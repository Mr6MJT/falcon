"""Stage executor + inline pipeline runner.

``execute_stage`` runs one stage, transitions its ``scan_stages`` row
(READY→RUNNING→DONE/FAILED), records counters, and is what both the inline runner and the
Celery task call. ``run_pipeline_inline`` drives the whole DAG synchronously via
``advance_scan`` with an inline dispatch — used for tests and a local "run now" path;
production swaps the dispatch for a Celery enqueue but reuses ``execute_stage`` unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Scan, ScanStage, ScanStatus, StageStatus
from .pipeline import advance_scan, is_terminal, seed_stages
from .stages import STAGE_FUNCS, Cancelled, StageContext


def _stage_row(session: Session, scan_id, name: str) -> ScanStage:
    return session.execute(
        select(ScanStage).where(ScanStage.scan_id == scan_id, ScanStage.name == name)
    ).scalar_one()


def execute_stage(session: Session, ctx: StageContext, name: str) -> dict:
    """Run stage ``name`` and update its row. Raises Cancelled to the caller to stop."""
    row = _stage_row(session, ctx.scan.id, name)
    func = STAGE_FUNCS.get(name)
    if func is None:
        row.status = StageStatus.SKIPPED
        session.flush()
        return {"skipped": "no implementation"}

    row.status = StageStatus.RUNNING
    session.flush()
    ctx.publisher.stage_started(name)
    try:
        stats = func(ctx)
    except Cancelled:
        row.status = StageStatus.FAILED
        row.error = "cancelled"
        session.flush()
        raise
    except Exception as e:  # a stage failure must not wedge the whole DAG
        row.status = StageStatus.FAILED
        row.error = f"{type(e).__name__}: {e}"[:2000]
        session.flush()
        ctx.audit({"event": "stage_failed", "stage": name, "error": row.error})
        return {"error": row.error}

    row.status = StageStatus.DONE
    total = sum(v for v in stats.values() if isinstance(v, int))
    row.total = total
    row.done = total
    session.flush()
    ctx.publisher.stage_progress(name, total, total)
    ctx.publisher.stage_done(name, stats)
    ctx.audit({"event": "stage_done", "stage": name, "stats": stats})
    return stats


def run_pipeline_inline(session: Session, ctx: StageContext) -> Scan:
    """Seed stages then drive the DAG to completion in-process. Honors cancellation."""
    scan: Scan = ctx.scan
    seed_stages(session, scan)
    scan.status = ScanStatus.RUNNING
    scan.started_at = scan.started_at or datetime.now(UTC)
    session.flush()
    ctx.publisher.scan_status(ScanStatus.RUNNING.value)

    def dispatch(name: str) -> None:
        execute_stage(session, ctx, name)

    try:
        # Keep advancing until no stage transitions to READY (fixed point / terminal).
        while True:
            if ctx.is_cancelled():
                raise Cancelled(f"scan {scan.id} cancelled")
            result = advance_scan(session, scan.id, dispatch)
            if not result.dispatched or result.terminal:
                break
    except Cancelled:
        scan.status = ScanStatus.CANCELLED
        scan.finished_at = datetime.now(UTC)
        session.flush()
        ctx.publisher.scan_status(ScanStatus.CANCELLED.value)
        ctx.audit({"event": "scan_cancelled", "scan_id": str(scan.id)})
        return scan

    rows = session.execute(
        select(ScanStage).where(ScanStage.scan_id == scan.id)
    ).scalars().all()
    any_failed = any(r.status == StageStatus.FAILED for r in rows)
    scan.status = ScanStatus.FAILED if any_failed else ScanStatus.COMPLETED
    scan.finished_at = datetime.now(UTC)
    session.flush()
    ctx.publisher.scan_status(scan.status.value)
    assert is_terminal(session, scan.id)
    return scan
