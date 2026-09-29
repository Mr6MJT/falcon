"""Celery tasks — the production dispatch that drives the DAG.

`advance_scan` marks ready stages and enqueues one `run_stage` task per stage; each task runs
the stage via the shared `execute_stage`, then re-queues `advance_scan`. This is the same
state machine the inline runner uses (packages/core/orchestrator), so behavior can't diverge.

`org_id` is threaded through every task so each opens its RLS-scoped session correctly (the
worker connects as the non-owner `orvex_app` role; without an org bound, RLS returns nothing).
`build_context` wires the real guard runner, the Redis cancel flag, and the Redis event
publisher — this is where the worker's egress actually happens, through Gate 3.
"""

from __future__ import annotations

import os

from celery import shared_task
from sqlalchemy import select

from packages.core.cancel import RedisCancelFlag
from packages.core.db import make_engine, make_session_factory, org_session
from packages.core.events import RedisEventBus, ScanEventPublisher
from packages.core.gate1 import compile_scope
from packages.core.models import Scan, ScopeRule
from packages.core.orchestrator import execute_stage
from packages.core.pipeline import advance_scan as _advance
from packages.core.pipeline import seed_stages
from packages.core.stages import StageContext

_session_factory = None
_bus = None
_cancel = None


def _redis():
    import redis
    return redis.Redis.from_url(os.environ.get("ORVEX_REDIS_URL", "redis://redis:6379/0"))


def _factory():
    global _session_factory, _bus, _cancel
    if _session_factory is None:
        _session_factory = make_session_factory(make_engine())
        r = _redis()
        _bus = RedisEventBus(r)
        _cancel = RedisCancelFlag(r)
    return _session_factory


def build_context(session, scan: Scan) -> StageContext:
    rows = session.execute(
        select(ScopeRule).where(ScopeRule.program_id == scan.program_id)
    ).scalars().all()
    cfg = scan.config or {}
    return StageContext(
        session=session,
        scan=scan,
        scope_rules=compile_scope(rows),
        roots=cfg.get("seeds", []),
        run=None,  # default guard runner → real engines through the egress gateway
        allow_internal=bool(cfg.get("allow_internal")),
        is_cancelled=lambda: _cancel.is_set(scan.id),
        publisher=ScanEventPublisher(_bus, scan.id),
    )


@shared_task(name="orvex.start_scan")
def start_scan(scan_id: str, org_id: str) -> None:
    with org_session(_factory(), org_id) as session:
        scan = session.get(Scan, scan_id)
        seed_stages(session, scan)
    advance_scan.delay(scan_id, org_id)


@shared_task(name="orvex.advance_scan")
def advance_scan(scan_id: str, org_id: str) -> list[str]:
    with org_session(_factory(), org_id) as session:
        result = _advance(
            session, scan_id, lambda name: run_stage.delay(scan_id, org_id, name)
        )
        return result.dispatched


@shared_task(name="orvex.stage.run", bind=True, max_retries=2)
def run_stage(self, scan_id: str, org_id: str, name: str) -> dict:
    with org_session(_factory(), org_id) as session:
        scan = session.get(Scan, scan_id)
        ctx = build_context(session, scan)
        stats = execute_stage(session, ctx, name)
    advance_scan.delay(scan_id, org_id)  # re-drive the DAG after each stage
    return stats
