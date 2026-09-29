"""Pipeline DAG + the ``advance_scan`` coordinator.

The pipeline is an explicit dependency graph persisted in ``scan_stages`` (DB is the
source of truth). ``advance_scan`` dispatches every stage whose deps are all DONE and
which is enabled in ``scan.config``; each stage upserts its results idempotently, marks
its row DONE, and advance is re-invoked. This gives resume-after-crash and partial
results for free: re-running advance on a half-finished scan simply continues from the
first not-yet-DONE ready stage.

Execution is decoupled from Celery on purpose. ``advance_scan`` takes a ``dispatch``
callable: in production it enqueues a Celery task per stage; in tests it runs the stage
inline. Either way the DB state transitions are identical and fully testable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Scan, ScanStage, StageStatus


@dataclass(frozen=True)
class StageDef:
    name: str
    deps: tuple[str, ...] = ()
    # Config key under scan.config["stages"] that enables this stage; None = always on.
    config_key: str | None = None
    # Celery queue the stage runs on (recon/active/cpu/report).
    queue: str = "recon"
    default_enabled: bool = True


# Recon spine. Passive (subdomains→dns→httpx) then fan-out to ports/tls/waf/tech, which all
# depend only on their inputs and can run concurrently once those are ready.
PIPELINE: tuple[StageDef, ...] = (
    StageDef("subdomains", deps=(), config_key="subdomains", queue="recon"),
    StageDef("dns", deps=("subdomains",), config_key="dns", queue="recon"),
    StageDef("httpx", deps=("dns",), config_key="httpx", queue="recon"),
    # Only runs against IPs EXPLICITLY in scope (never an IP just because a host resolves there).
    StageDef("ports", deps=("dns",), config_key="ports", queue="recon"),
    StageDef("tls", deps=("httpx",), config_key="tls", queue="recon"),
    StageDef("waf", deps=("httpx",), config_key="waf", queue="recon"),
    StageDef("tech", deps=("httpx",), config_key="tech", queue="recon"),
    # URL/endpoint discovery (crawl + historical) then secret detection over what's found.
    StageDef("urls", deps=("httpx",), config_key="urls", queue="recon"),
    StageDef("secrets", deps=("urls",), config_key="secrets", queue="recon"),
    # Findings: nuclei over discovered endpoints + tech; runs after tech + urls are known.
    StageDef("findings", deps=("tech", "urls"), config_key="findings", queue="cpu"),
    # --- Gated active modules (slice 13): OFF by default; enabled only when the scan is
    # configured for active testing, which Gate 1 permits only if the authorization allows it.
    StageDef("fuzzing", deps=("urls",), config_key="fuzzing",
             default_enabled=False, queue="active"),
    StageDef("active", deps=("urls",), config_key="active",
             default_enabled=False, queue="active"),
    StageDef("login", deps=("httpx",), config_key="login",
             default_enabled=False, queue="active"),
    StageDef("idor", deps=("urls",), config_key="idor",
             default_enabled=False, queue="active"),
)

PIPELINE_BY_NAME: dict[str, StageDef] = {s.name: s for s in PIPELINE}


def stage_enabled(scan: Scan, stage: StageDef) -> bool:
    if stage.config_key is None:
        return True
    stages_cfg = (scan.config or {}).get("stages", {})
    return bool(stages_cfg.get(stage.config_key, stage.default_enabled))


def seed_stages(session: Session, scan: Scan) -> list[ScanStage]:
    """Create one scan_stages row per pipeline stage (enabled → BLOCKED, else SKIPPED).

    Idempotent: existing rows for the scan are left untouched.
    """
    existing = {
        row.name
        for row in session.execute(
            select(ScanStage.name).where(ScanStage.scan_id == scan.id)
        ).all()
    }
    created: list[ScanStage] = []
    for sdef in PIPELINE:
        if sdef.name in existing:
            continue
        status = StageStatus.BLOCKED if stage_enabled(scan, sdef) else StageStatus.SKIPPED
        row = ScanStage(org_id=scan.org_id, scan_id=scan.id, name=sdef.name, status=status)
        session.add(row)
        created.append(row)
    session.flush()
    return created


def _stage_rows(session: Session, scan_id) -> dict[str, ScanStage]:
    rows = session.execute(select(ScanStage).where(ScanStage.scan_id == scan_id)).scalars().all()
    return {r.name: r for r in rows}


def ready_stages(session: Session, scan_id) -> list[ScanStage]:
    """Stages that are BLOCKED/READY and whose deps are all DONE (or SKIPPED)."""
    rows = _stage_rows(session, scan_id)
    out: list[ScanStage] = []
    for sdef in PIPELINE:
        row = rows.get(sdef.name)
        if row is None or row.status not in (StageStatus.BLOCKED, StageStatus.READY):
            continue
        deps_ok = all(
            rows.get(d) is not None
            and rows[d].status in (StageStatus.DONE, StageStatus.SKIPPED)
            for d in sdef.deps
        )
        if deps_ok:
            out.append(row)
    return out


def is_terminal(session: Session, scan_id) -> bool:
    """True when no stage can make further progress (all DONE/SKIPPED/FAILED)."""
    rows = _stage_rows(session, scan_id)
    if not rows:
        return True
    return all(
        r.status in (StageStatus.DONE, StageStatus.SKIPPED, StageStatus.FAILED)
        for r in rows.values()
    )


@dataclass
class AdvanceResult:
    dispatched: list[str] = field(default_factory=list)
    terminal: bool = False


def advance_scan(
    session: Session,
    scan_id,
    dispatch: Callable[[str], None],
) -> AdvanceResult:
    """Atomically claim ready stages and hand each to ``dispatch`` (Celery enqueue or inline).

    Each ready stage is claimed with ``UPDATE ... WHERE status='blocked'`` so that when several
    ``advance_scan`` tasks run concurrently (one fires after every stage completes), only ONE
    of them transitions a given stage — no stage is ever dispatched twice. ``dispatch`` runs
    the stage and re-invokes ``advance_scan`` on completion.
    """
    from sqlalchemy import update

    result = AdvanceResult()
    rows = _stage_rows(session, scan_id)
    # Snapshot statuses at entry so an inline dispatch that completes a stage within this call
    # doesn't cascade its dependants in the same call — they advance on the next invocation.
    status_at_entry = {name: r.status for name, r in rows.items()}
    for sdef in PIPELINE:
        row = rows.get(sdef.name)
        if row is None or status_at_entry.get(sdef.name) != StageStatus.BLOCKED:
            continue
        deps_ok = all(
            status_at_entry.get(d) in (StageStatus.DONE, StageStatus.SKIPPED)
            for d in sdef.deps
        )
        if not deps_ok:
            continue
        # Atomic claim: only the txn that flips BLOCKED->READY (rowcount 1) dispatches it.
        claimed = session.execute(
            update(ScanStage)
            .where(ScanStage.id == row.id, ScanStage.status == StageStatus.BLOCKED)
            .values(status=StageStatus.READY)
        ).rowcount
        if claimed:
            row.status = StageStatus.READY
            result.dispatched.append(sdef.name)
            dispatch(sdef.name)
    result.terminal = is_terminal(session, scan_id)
    return result
