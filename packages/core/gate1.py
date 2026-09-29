"""Gate 1 — the API-side admission check for creating a scan.

This is the first of the three scope/authorization gates (Gate 2 = per-task re-validation
in the pipeline; Gate 3 = the egress firewall). Gate 1 refuses a scan at creation time if:

  * no live authorization exists (missing / expired / revoked), or it forbids automated tools;
  * the requested aggressiveness/active/fuzzing exceeds what the authorization permits;
  * the scope is empty, or a seed is out of scope / a special (metadata/private) address;
  * the run exceeds hard caps (max root domains).

On success it FREEZES a scope snapshot hash onto the scan, so later stages validate against
exactly the scope that was authorized at creation, even if the program's rules change later.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Aggressiveness,
    Authorization,
    Program,
    Scan,
)
from .models import (
    ScopeRule as ScopeRuleRow,
)
from .pipeline import seed_stages
from .scope import ScopeRule, is_in_scope

MAX_ROOT_DOMAINS = 50


class Gate1Error(Exception):
    """Raised when a scan request is refused. ``status_code`` maps to an HTTP status."""

    def __init__(self, detail: str, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def compile_scope(rows: list[ScopeRuleRow]) -> list[ScopeRule]:
    """Turn DB scope rows into the core matcher's normalised rules."""
    return [ScopeRule.make(r.kind.value, r.action.value, r.value) for r in rows]


def scope_hash(rules: list[ScopeRule]) -> str:
    """Deterministic hash of the compiled scope (order-independent)."""
    canon = sorted(f"{r.kind.value}|{r.action.value}|{r.value}" for r in rules)
    return hashlib.sha256("\n".join(canon).encode()).hexdigest()


def _pick_live_authorization(
    session: Session, program_id, org_id, now: datetime
) -> Authorization:
    authzs = session.execute(
        select(Authorization).where(
            Authorization.program_id == program_id, Authorization.org_id == org_id
        )
    ).scalars().all()
    live = [a for a in authzs if a.is_live(now)]
    if not live:
        raise Gate1Error("no live authorization for this program", status_code=403)
    if not any(a.allows_automated_tools for a in live):
        raise Gate1Error("authorization forbids automated tools", status_code=403)
    # Prefer one that allows automated tools; among those, the latest-expiring.
    live = [a for a in live if a.allows_automated_tools]
    return max(live, key=lambda a: a.expires_at)


def _validate_modules(
    authz: Authorization, aggressiveness: Aggressiveness, active: bool, fuzzing: bool
) -> None:
    wants_sharp = active or fuzzing or aggressiveness in (
        Aggressiveness.NORMAL,
        Aggressiveness.AGGRESSIVE,
    )
    if wants_sharp and not authz.allows_active_testing:
        raise Gate1Error(
            "authorization does not permit active testing (active/fuzzing/normal+)",
            status_code=403,
        )


def _validate_seeds(seeds: list[str], rules: list[ScopeRule], allow_internal: bool) -> None:
    cleaned = [s.strip() for s in seeds if s.strip()]
    if not cleaned:
        raise Gate1Error("no seed domains provided", status_code=400)
    if len(cleaned) > MAX_ROOT_DOMAINS:
        raise Gate1Error(f"too many root domains (max {MAX_ROOT_DOMAINS})", status_code=400)
    if not any(r.action.value == "include" for r in rules):
        raise Gate1Error("scope has no include rules (default-deny would block all)", 400)
    for s in cleaned:
        d = is_in_scope(s, rules, allow_internal=allow_internal)
        if not d.allowed:
            raise Gate1Error(f"seed {s!r} is not in scope: {d.reason}", status_code=400)


def create_scan(
    session: Session,
    *,
    org_id,
    program_id,
    seeds: list[str],
    aggressiveness: Aggressiveness = Aggressiveness.SAFE,
    active_probes: bool = False,
    fuzzing: bool = False,
    scan_mode: str = "connect",
    allow_internal: bool = False,
    now: datetime | None = None,
) -> Scan:
    """Run Gate 1 and, if it passes, create the Scan (frozen scope hash) + seed its stages."""
    now = now or datetime.now(UTC)

    program = session.get(Program, program_id)
    if program is None or str(program.org_id) != str(org_id):
        raise Gate1Error("program not found", status_code=404)

    authz = _pick_live_authorization(session, program_id, org_id, now)
    _validate_modules(authz, aggressiveness, active_probes, fuzzing)

    rows = session.execute(
        select(ScopeRuleRow).where(ScopeRuleRow.program_id == program_id)
    ).scalars().all()
    compiled = compile_scope(rows)
    _validate_seeds(seeds, compiled, allow_internal)

    scan = Scan(
        org_id=org_id,
        program_id=program_id,
        authorization_id=authz.id,
        aggressiveness=aggressiveness,
        scan_mode=scan_mode,
        scope_snapshot_hash=scope_hash(compiled),
        config={
            "stages": {
                "subdomains": True, "dns": True, "httpx": True,
                "ports": True, "tls": True, "waf": True, "tech": True,
                "urls": True, "secrets": True, "findings": True,
                # Gated active modules — enabled only per the (authz-checked) request flags.
                "fuzzing": fuzzing,
                "active": active_probes,
                "login": active_probes,
                "idor": active_probes,
            },
            "seeds": [s.strip() for s in seeds if s.strip()],
            "active_probes": active_probes,
            "fuzzing": fuzzing,
            "allow_internal": allow_internal,
        },
    )
    session.add(scan)
    session.flush()
    seed_stages(session, scan)
    return scan
