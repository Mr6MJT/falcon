"""Orvex API: authoritative scan snapshot (REST) + live progress (WebSocket).

Reconnection model: the client GETs /scans/{id}/state (authoritative snapshot), then opens
the WebSocket which first re-sends the snapshot and thereafter streams throttled deltas.
Missing a delta is harmless — the next snapshot reconciles.

Auth: every request and the WS handshake require a valid JWT; the scan must belong to the
token's org, enforced with the RLS org-context session. Unauthenticated WS connections are
closed before accept.
"""

from __future__ import annotations

import asyncio
import os
import queue as _queue
import re
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from starlette.websockets import WebSocketState

from packages.core.auth import (
    AuthError,
    Principal,
    bearer_from_header,
    create_access_token,
    decode_token,
)
from packages.core.db import make_engine, make_session_factory, org_session
from packages.core.events import EventBus, InMemoryEventBus, channel_for
from packages.core.gate1 import Gate1Error, create_scan
from packages.core.models import (
    Aggressiveness,
    Authorization,
    AuthorizationType,
    Finding,
    FindingStatus,
    Membership,
    Program,
    Scan,
    ScopeRule,
    ScopeRuleAction,
    ScopeRuleKind,
    User,
)
from packages.core.passwords import verify_password
from packages.core.report import build_report, render_html, render_json, render_pdf
from packages.core.scope import ScopeRule as CoreScopeRule
from packages.core.scope import parse_scope_lines
from packages.core.snapshot import build_snapshot

WRITE_ROLES = frozenset({"admin", "operator"})


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return s or "program"


class ScopeRuleIn(BaseModel):
    kind: str
    action: str
    value: str


class AuthorizationIn(BaseModel):
    authorized_by: str
    authorization_type: str = "bug_bounty"
    evidence_ref: str | None = None
    expires_in_days: int = 90
    allows_active_testing: bool = False
    allows_automated_tools: bool = True
    program_rate_cap_rps: float | None = None


class ProgramIn(BaseModel):
    name: str
    platform: str | None = None
    program_url: str | None = None
    scope_rules: list[ScopeRuleIn] = Field(default_factory=list)
    # Free-text scope inputs (the bug-bounty syntax: *.d.ae, exact d.exchange, *end.api.d.com).
    scope_text: str | None = None
    out_of_scope_text: str | None = None
    authorization: AuthorizationIn | None = None


class ScanIn(BaseModel):
    program_id: str
    seeds: list[str]
    aggressiveness: str = "safe"
    active_probes: bool = False
    fuzzing: bool = False
    scan_mode: str = "connect"
    allow_internal: bool = False


class LoginIn(BaseModel):
    email: str
    password: str


class TriageIn(BaseModel):
    status: str


def _finding_out(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "type": f.type,
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "status": f.status.value,
        "cvss": f.cvss,
        "cve_id": f.cve_id,
        "cwe": f.cwe,
        "target": f.target,
        "evidence": f.evidence or {},
    }


def create_app(session_factory=None, bus: EventBus | None = None,
               jwt_secret: str | None = None, cors_origins: list[str] | None = None) -> FastAPI:
    app = FastAPI(title="Orvex API")
    app.state.session_factory = session_factory or make_session_factory(make_engine())
    app.state.bus = bus or InMemoryEventBus()
    app.state.jwt_secret = jwt_secret  # None => auth.py reads ORVEX_JWT_SECRET
    # Login needs to read a user's membership across orgs, which RLS hides. A privileged
    # auth engine (owner role) is used ONLY for that lookup; it falls back to the main factory.
    _auth_url = os.environ.get("ORVEX_AUTH_DATABASE_URL")
    app.state.auth_session_factory = (
        make_session_factory(make_engine(_auth_url)) if _auth_url else app.state.session_factory
    )

    # Optional Celery dispatch: when ORVEX_REDIS_URL is set, scan creation enqueues the worker
    # to actually execute the pipeline. Without it, scans are created but stay pending.
    app.state.enqueue_scan = None
    _redis_url = os.environ.get("ORVEX_REDIS_URL")
    if _redis_url:
        try:
            from celery import Celery

            _celery = Celery(broker=_redis_url)

            def _enqueue(scan_id: str, org_id: str) -> None:
                # The worker consumes recon/active/cpu/report (not the default 'celery' queue).
                _celery.send_task("orvex.start_scan", args=[scan_id, org_id], queue="recon")

            app.state.enqueue_scan = _enqueue
        except Exception:
            app.state.enqueue_scan = None

    origins = cors_origins or [
        o.strip() for o in os.environ.get("ORVEX_CORS_ORIGINS", "").split(",") if o.strip()
    ]
    if origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def principal_from_request(request: Request) -> Principal:
        token = bearer_from_header(request.headers.get("authorization"))
        if not token:
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            return decode_token(token, request.app.state.jwt_secret)
        except AuthError as e:
            raise HTTPException(status_code=401, detail=str(e)) from e

    def _load_scan_snapshot(app: FastAPI, principal: Principal, scan_id: str):
        """Return the snapshot iff the scan exists and belongs to the principal's org."""
        with org_session(app.state.session_factory, principal.org_id) as session:
            scan = session.get(Scan, scan_id)
            if scan is None or str(scan.org_id) != str(principal.org_id):
                return None
            return build_snapshot(session, scan_id)

    def require_write(principal: Principal) -> None:
        if principal.role not in WRITE_ROLES:
            raise HTTPException(status_code=403, detail="role may not perform writes")

    def _program_status(s, program_id, org_id) -> tuple[bool, bool, int]:
        """(scannable, allows_active_testing, scope_rule_count) for a program."""
        now = datetime.now(UTC)
        authzs = s.execute(
            select(Authorization).where(
                Authorization.program_id == program_id, Authorization.org_id == org_id
            )
        ).scalars().all()
        live = [a for a in authzs if a.is_live(now)]
        scope_count = s.execute(
            select(func.count()).select_from(ScopeRule).where(ScopeRule.program_id == program_id)
        ).scalar() or 0
        scannable = bool(live) and scope_count > 0
        return scannable, any(a.allows_active_testing for a in live), scope_count

    def _program_out(p: Program, status: tuple[bool, bool, int]) -> dict:
        scannable, active, scope_count = status
        return {
            "id": str(p.id), "name": p.name, "slug": p.slug,
            "platform": p.platform, "program_url": p.program_url,
            "allows_active_testing": active,
            "scannable": scannable,
            "scope_rule_count": scope_count,
        }

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.post("/auth/login")
    def login(body: LoginIn) -> dict:
        # users has no RLS, so the main (app-role) session can authenticate.
        with app.state.session_factory() as s:
            user = s.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
            if (user is None or not user.is_active
                    or not verify_password(body.password, user.password_hash)):
                raise HTTPException(status_code=401, detail="invalid email or password")
            user_id = user.id
        # membership (org + role) via the privileged auth session (RLS would hide it otherwise).
        with app.state.auth_session_factory() as s2:
            m = s2.execute(
                select(Membership).where(Membership.user_id == user_id)
            ).scalars().first()
            if m is None:
                raise HTTPException(status_code=403, detail="user has no org membership")
            org_id, role = str(m.org_id), m.role.value
        token = create_access_token(user_id=str(user_id), org_id=org_id, role=role,
                                    secret=app.state.jwt_secret)
        return {"token": token, "role": role, "org_id": org_id}

    @app.get("/programs")
    def list_programs(principal: Principal = Depends(principal_from_request)) -> list[dict]:
        with org_session(app.state.session_factory, principal.org_id) as s:
            rows = s.execute(select(Program).order_by(Program.created_at.desc())).scalars().all()
            return [_program_out(p, _program_status(s, p.id, principal.org_id)) for p in rows]

    @app.post("/programs", status_code=201)
    def create_program(
        body: ProgramIn, principal: Principal = Depends(principal_from_request)
    ) -> dict:
        require_write(principal)
        with org_session(app.state.session_factory, principal.org_id) as s:
            prog = Program(
                org_id=principal.org_id, name=body.name, slug=_slugify(body.name),
                platform=body.platform, program_url=body.program_url,
            )
            s.add(prog)
            s.flush()
            # Free-text scope inputs are parsed into rules (in addition to any explicit ones).
            rule_inputs = [(r.kind, r.action, r.value) for r in body.scope_rules]
            if body.scope_text or body.out_of_scope_text:
                for r in parse_scope_lines(body.scope_text or "", body.out_of_scope_text or ""):
                    rule_inputs.append((r["kind"], r["action"], r["value"]))
            for kind_s, action_s, value_s in rule_inputs:
                try:
                    kind, action = ScopeRuleKind(kind_s), ScopeRuleAction(action_s)
                    normalised = CoreScopeRule.make(kind_s, action_s, value_s)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"bad scope rule: {e}") from e
                s.add(ScopeRule(org_id=principal.org_id, program_id=prog.id,
                                kind=kind, action=action, value=normalised.value))
            if body.authorization:
                a = body.authorization
                try:
                    atype = AuthorizationType(a.authorization_type)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"bad authz type: {e}") from e
                s.add(Authorization(
                    org_id=principal.org_id, program_id=prog.id, authorized_by=a.authorized_by,
                    authorization_type=atype, evidence_ref=a.evidence_ref,
                    expires_at=datetime.now(UTC) + timedelta(days=a.expires_in_days),
                    allows_active_testing=a.allows_active_testing,
                    allows_automated_tools=a.allows_automated_tools,
                    program_rate_cap_rps=a.program_rate_cap_rps,
                ))
            s.flush()
            return _program_out(prog, _program_status(s, prog.id, principal.org_id))

    @app.post("/scans", status_code=201)
    def create_scan_endpoint(
        body: ScanIn, principal: Principal = Depends(principal_from_request)
    ) -> dict:
        require_write(principal)
        try:
            aggr = Aggressiveness(body.aggressiveness)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"bad aggressiveness: {e}") from e
        with org_session(app.state.session_factory, principal.org_id) as s:
            try:
                scan = create_scan(
                    s, org_id=principal.org_id, program_id=body.program_id, seeds=body.seeds,
                    aggressiveness=aggr, active_probes=body.active_probes, fuzzing=body.fuzzing,
                    scan_mode=body.scan_mode, allow_internal=body.allow_internal,
                )
            except Gate1Error as e:
                raise HTTPException(status_code=e.status_code, detail=e.detail) from e
            result = {
                "scan_id": str(scan.id), "status": scan.status.value,
                "scope_snapshot_hash": scan.scope_snapshot_hash,
            }
        # Enqueue execution AFTER the scan is committed (outside the txn).
        if app.state.enqueue_scan is not None:
            try:
                app.state.enqueue_scan(result["scan_id"], str(principal.org_id))
            except Exception:
                pass
        return result

    @app.get("/scans/{scan_id}/state")
    def scan_state(scan_id: str, principal: Principal = Depends(principal_from_request)) -> dict:
        snap = _load_scan_snapshot(app, principal, scan_id)
        if snap is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return snap

    @app.get("/scans")
    def list_scans(principal: Principal = Depends(principal_from_request),
                   limit: int = 100, offset: int = 0) -> dict:
        limit = max(1, min(limit, 200))
        with org_session(app.state.session_factory, principal.org_id) as s:
            total = s.execute(select(func.count()).select_from(Scan)).scalar() or 0
            rows = s.execute(
                select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
            ).scalars().all()
            progs = {
                p.id: p.name
                for p in s.execute(select(Program)).scalars().all()
            }

            def _fcount(scan_id) -> int:
                return s.execute(
                    select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
                ).scalar() or 0

            items = [{
                "id": str(sc.id), "program": progs.get(sc.program_id),
                "status": sc.status.value, "aggressiveness": sc.aggressiveness.value,
                "seeds": (sc.config or {}).get("seeds", []),
                "created_at": sc.created_at.isoformat() if sc.created_at else None,
                "finished_at": sc.finished_at.isoformat() if sc.finished_at else None,
                "findings": _fcount(sc.id),
            } for sc in rows]
            return {"items": items, "total": total}

    # Full drill-down: every discovered asset, per kind, paginated.
    from packages.core.models import (
        DNSRecord,
        HTTPEndpoint,
        Parameter,
        Secret,
        Service,
        Subdomain,
        Technology,
        TLSInfo,
    )

    def _jsonable(v):
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        val = getattr(v, "value", None)  # enum
        return val if val is not None else str(v)

    def _asset_rows(model, columns, s, scan_id, limit, offset):
        q = (select(model).where(model.scan_id == scan_id)
             .order_by(model.created_at.desc()).limit(limit).offset(offset))
        return [{c: _jsonable(getattr(r, c, None)) for c in columns}
                for r in s.execute(q).scalars().all()]

    ASSET_KINDS = {
        "subdomains": (Subdomain, ["hostname", "source", "in_scope"]),
        "dns": (DNSRecord, ["hostname", "record_type", "value"]),
        "services": (Service, ["ip", "port", "protocol", "service_name", "product", "version",
                               "hostname"]),
        "http_endpoints": (HTTPEndpoint, ["url", "status_code", "title", "content_length",
                                          "waf_vendor", "cdn"]),
        "parameters": (Parameter, ["url", "name", "method", "param_in", "reflected"]),
        "technologies": (Technology, ["url", "layer", "name", "version", "cpe"]),
        "tls": (TLSInfo, ["hostname", "port", "tls_version", "cert_issuer", "expired",
                          "weak_protocol"]),
        "secrets": (Secret, ["detector", "redacted_match", "location", "verified"]),
    }

    @app.get("/scans/{scan_id}/assets/{kind}")
    def list_assets(scan_id: str, kind: str,
                    principal: Principal = Depends(principal_from_request),
                    limit: int = 200, offset: int = 0) -> dict:
        if kind not in ASSET_KINDS:
            raise HTTPException(status_code=404, detail=f"unknown asset kind: {kind}")
        model, columns = ASSET_KINDS[kind]
        limit = max(1, min(limit, 1000))
        with org_session(app.state.session_factory, principal.org_id) as s:
            scan = s.get(Scan, scan_id)
            if scan is None or str(scan.org_id) != str(principal.org_id):
                raise HTTPException(status_code=404, detail="scan not found")
            total = s.execute(
                select(func.count()).select_from(model).where(model.scan_id == scan_id)
            ).scalar() or 0
            items = _asset_rows(model, columns, s, scan_id, limit, offset)
            return {"kind": kind, "columns": columns, "items": items, "total": total}

    @app.get("/scans/{scan_id}/findings")
    def list_findings(
        scan_id: str,
        principal: Principal = Depends(principal_from_request),
        severity: str | None = None,
        confidence: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        limit = max(1, min(limit, 500))
        with org_session(app.state.session_factory, principal.org_id) as s:
            scan = s.get(Scan, scan_id)
            if scan is None or str(scan.org_id) != str(principal.org_id):
                raise HTTPException(status_code=404, detail="scan not found")
            conds = [Finding.scan_id == scan_id]
            if severity:
                conds.append(Finding.severity == severity)
            if confidence:
                conds.append(Finding.confidence == confidence)
            if status:
                conds.append(Finding.status == status)
            total = s.execute(
                select(func.count()).select_from(Finding).where(*conds)
            ).scalar() or 0
            # Highest severity first, then most recently found.
            sev_rank = case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                else_=4,
            )
            rows = s.execute(
                select(Finding).where(*conds)
                .order_by(sev_rank.asc(), Finding.created_at.desc())
                .limit(limit).offset(offset)
            ).scalars().all()
            return {"items": [_finding_out(f) for f in rows], "total": total}

    def _load_report(principal: Principal, scan_id: str):
        with org_session(app.state.session_factory, principal.org_id) as s:
            scan = s.get(Scan, scan_id)
            if scan is None or str(scan.org_id) != str(principal.org_id):
                return None
            return build_report(s, scan_id)

    @app.get("/scans/{scan_id}/report")
    def report_json(scan_id: str,
                    principal: Principal = Depends(principal_from_request)) -> dict:
        rep = _load_report(principal, scan_id)
        if rep is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return rep

    @app.get("/scans/{scan_id}/report.html")
    def report_html(scan_id: str, principal: Principal = Depends(principal_from_request)):
        from fastapi.responses import HTMLResponse
        rep = _load_report(principal, scan_id)
        if rep is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return HTMLResponse(render_html(rep))

    @app.get("/scans/{scan_id}/report.json")
    def report_json_download(scan_id: str,
                             principal: Principal = Depends(principal_from_request)):
        from fastapi.responses import Response
        rep = _load_report(principal, scan_id)
        if rep is None:
            raise HTTPException(status_code=404, detail="scan not found")
        cd = f'attachment; filename="orvex-{scan_id}.json"'
        return Response(render_json(rep), media_type="application/json",
                        headers={"content-disposition": cd})

    @app.get("/scans/{scan_id}/report.pdf")
    def report_pdf(scan_id: str, principal: Principal = Depends(principal_from_request)):
        from fastapi.responses import Response
        rep = _load_report(principal, scan_id)
        if rep is None:
            raise HTTPException(status_code=404, detail="scan not found")
        pdf = render_pdf(render_html(rep))
        cd = f'attachment; filename="orvex-{scan_id}.pdf"'
        return Response(pdf, media_type="application/pdf",
                        headers={"content-disposition": cd})

    @app.patch("/findings/{finding_id}")
    def triage_finding(
        finding_id: str, body: TriageIn,
        principal: Principal = Depends(principal_from_request),
    ) -> dict:
        require_write(principal)
        try:
            new_status = FindingStatus(body.status)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"bad status: {e}") from e
        with org_session(app.state.session_factory, principal.org_id) as s:
            f = s.get(Finding, finding_id)
            if f is None or str(f.org_id) != str(principal.org_id):
                raise HTTPException(status_code=404, detail="finding not found")
            f.status = new_status
            s.flush()
            return _finding_out(f)

    @app.websocket("/scans/{scan_id}/events")
    async def scan_events(websocket: WebSocket, scan_id: str) -> None:
        # Token from Authorization header, ?token=, or the "bearer.<token>" subprotocol.
        token = bearer_from_header(websocket.headers.get("authorization"))
        chosen_subprotocol: str | None = None
        if not token:
            token = websocket.query_params.get("token")
        if not token:
            for proto in websocket.scope.get("subprotocols", []):
                if proto.startswith("bearer."):
                    token = proto.split(".", 1)[1]
                    chosen_subprotocol = proto  # must be echoed on accept for browsers
                    break
        if not token:
            await websocket.close(code=4401)  # unauthenticated
            return
        try:
            principal = decode_token(token, websocket.app.state.jwt_secret)
        except AuthError:
            await websocket.close(code=4401)
            return

        snap = await asyncio.to_thread(_load_scan_snapshot, websocket.app, principal, scan_id)
        if snap is None:
            await websocket.close(code=4403)  # not authorized for / no such scan in org
            return

        # Echo the offered subprotocol; browsers fail the connection otherwise.
        await websocket.accept(subprotocol=chosen_subprotocol)
        bus: EventBus = websocket.app.state.bus
        loop = asyncio.get_running_loop()
        # Subscribe BEFORE sending the snapshot so no delta emitted after the snapshot is
        # missed. (Deltas emitted before this point are covered by the snapshot itself.)
        with bus.subscribe(channel_for(scan_id)) as q:
            await websocket.send_json(snap)
            stop = False

            async def pump() -> None:
                # Poll with a short timeout so the executor thread never blocks long and
                # cancellation is prompt; emit a keepalive ping roughly every 20s idle.
                idle = 0
                while not stop:
                    try:
                        event = await loop.run_in_executor(None, q.get, True, 1.0)
                    except _queue.Empty:
                        idle += 1
                        if idle >= 20:
                            idle = 0
                            await websocket.send_json({"type": "ping"})
                        continue
                    if event is None:  # sentinel to unblock on shutdown
                        break
                    idle = 0
                    await websocket.send_json(event)

            async def watch_disconnect() -> None:
                try:
                    while True:
                        await websocket.receive_text()
                except Exception:
                    return

            pump_task = asyncio.create_task(pump())
            dc_task = asyncio.create_task(watch_disconnect())
            try:
                _, pending = await asyncio.wait(
                    {pump_task, dc_task}, return_when=asyncio.FIRST_COMPLETED
                )
                stop = True
                q.put_nowait(None)  # unblock a waiting get() at once
                for t in pending:
                    t.cancel()
            finally:
                if websocket.client_state != WebSocketState.DISCONNECTED:
                    await websocket.close()

    return app


app = None  # built lazily by ASGI servers via `app_factory`


def app_factory() -> FastAPI:
    """Production entrypoint: Redis bus when ORVEX_REDIS_URL is set, else in-memory."""
    bus: EventBus | None = None
    redis_url = os.environ.get("ORVEX_REDIS_URL")
    if redis_url:
        import redis as _redis

        from packages.core.events import RedisEventBus

        bus = RedisEventBus(_redis.Redis.from_url(redis_url))
    return create_app(bus=bus)
