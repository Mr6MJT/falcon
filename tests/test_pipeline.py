"""Slice 4 acceptance: passive pipeline end-to-end against the DB with a fake engine runner.

Proves: rows land in subdomains/dns_records/http_endpoints; stages advance to DONE and the
scan COMPLETES; a mid-run cancel halts remaining stages; a re-run creates no duplicates
(idempotent upserts); and a discovered out-of-scope host is stored but never fed onward
(Gate 2). No real binaries or network — the runner returns canned tool output.
"""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.guard import ToolResult
from packages.core.models import (
    Authorization,
    AuthorizationType,
    DNSRecord,
    HTTPEndpoint,
    Organization,
    Program,
    Scan,
    ScanStatus,
    StageStatus,
    Subdomain,
)
from packages.core.orchestrator import run_pipeline_inline
from packages.core.pipeline import PIPELINE
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import StageContext

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL",
    "postgresql+psycopg://postgres:orvex@localhost:5432/orvex",
)

SUBFINDER_OUT = "www.example.com\napi.example.com\nevil.attacker.net\n"
DNSX_OUT = (
    '{"host":"www.example.com","a":["93.184.216.34"]}\n'
    '{"host":"api.example.com","a":["93.184.216.35"]}\n'
)
HTTPX_OUT = (
    '{"url":"https://www.example.com","status_code":200,"title":"Home","content_length":123}\n'
    '{"url":"https://api.example.com","status_code":403,"title":"","content_length":10}\n'
)
TOOL_OUT = {"subfinder": SUBFINDER_OUT, "dnsx": DNSX_OUT, "httpx": HTTPX_OUT}


def _fake_runner(calls: list | None = None):
    def run(tool, targets, **kw):
        if calls is not None:
            calls.append((tool, list(targets)))
        return ToolResult(ok=True, returncode=0, stdout=TOOL_OUT.get(tool, ""),
                          stderr="", in_scope_targets=list(targets))
    return run


@pytest.fixture
def session():
    eng = create_engine(OWNER_URL, future=True)
    try:
        with eng.connect() as c:
            c.execute(select(1))
    except OperationalError:
        pytest.skip("Postgres not reachable")
    s = sessionmaker(bind=eng, future=True)()
    s.begin()
    yield s
    s.rollback()  # keep the DB clean; everything happens in one rolled-back txn
    s.close()


@pytest.fixture
def scan(session):
    org = Organization(name="t", slug=f"t-{uuid.uuid4().hex[:8]}")
    session.add(org)
    session.flush()
    prog = Program(org_id=org.id, name="p", slug=f"p-{uuid.uuid4().hex[:8]}")
    session.add(prog)
    session.flush()
    authz = Authorization(
        org_id=org.id, program_id=prog.id, authorized_by="me",
        authorization_type=AuthorizationType.BUG_BOUNTY,
        expires_at=datetime.now(UTC) + timedelta(days=30), allows_automated_tools=True,
    )
    session.add(authz)
    session.flush()
    sc = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id,
              config={"stages": {"subdomains": True, "dns": True, "httpx": True}})
    session.add(sc)
    session.flush()
    return sc


def _scope():
    return [
        ScopeRule.make(RuleKind.DOMAIN, RuleAction.INCLUDE, "example.com"),
        ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"),
    ]


def _ctx(session, scan, **kw):
    return StageContext(session=session, scan=scan, scope_rules=_scope(),
                        roots=["example.com"], run=_fake_runner(kw.pop("calls", None)), **kw)


def test_passive_pipeline_end_to_end(session, scan):
    run_pipeline_inline(session, _ctx(session, scan))

    assert scan.status == ScanStatus.COMPLETED
    subs = session.execute(
        select(Subdomain).where(Subdomain.scan_id == scan.id)
    ).scalars().all()
    names = {s.hostname: s.in_scope for s in subs}
    assert names["www.example.com"] is True
    assert names["api.example.com"] is True
    assert names["example.com"] is True
    assert names["evil.attacker.net"] is False  # discovered, out of scope

    dns_n = session.execute(
        select(func.count()).select_from(DNSRecord).where(DNSRecord.scan_id == scan.id)
    ).scalar()
    assert dns_n == 2
    ep_n = session.execute(
        select(func.count()).select_from(HTTPEndpoint).where(HTTPEndpoint.scan_id == scan.id)
    ).scalar()
    assert ep_n == 2


def test_gate2_out_of_scope_host_not_fed_onward(session, scan):
    calls: list = []
    run_pipeline_inline(session, _ctx(session, scan, calls=calls))
    dns_calls = [targets for (tool, targets) in calls if tool == "dnsx"]
    fed = {h for targets in dns_calls for h in targets}
    assert "evil.attacker.net" not in fed  # never handed to a downstream engine
    assert "www.example.com" in fed


def test_idempotent_rerun_no_duplicates(session, scan):
    run_pipeline_inline(session, _ctx(session, scan))
    n1 = session.execute(
        select(func.count()).select_from(Subdomain).where(Subdomain.scan_id == scan.id)
    ).scalar()
    # Re-run the same pipeline (resume/re-scan) — upserts must not duplicate.
    run_pipeline_inline(session, _ctx(session, scan))
    n2 = session.execute(
        select(func.count()).select_from(Subdomain).where(Subdomain.scan_id == scan.id)
    ).scalar()
    assert n1 == n2 == 4


def test_cancel_mid_run_halts_remaining_stages(session, scan):
    from packages.core.models import ScanStage

    def cancel_after_subdomains() -> bool:
        row = session.execute(
            select(ScanStage).where(ScanStage.scan_id == scan.id, ScanStage.name == "subdomains")
        ).scalar_one_or_none()
        return row is not None and row.status == StageStatus.DONE

    ctx = _ctx(session, scan)
    ctx.is_cancelled = cancel_after_subdomains
    run_pipeline_inline(session, ctx)

    assert scan.status == ScanStatus.CANCELLED
    # subdomains ran, dns/httpx did not.
    dns_n = session.execute(
        select(func.count()).select_from(DNSRecord).where(DNSRecord.scan_id == scan.id)
    ).scalar()
    assert dns_n == 0
    rows = {r.name: r.status for r in session.execute(
        select(ScanStage).where(ScanStage.scan_id == scan.id)
    ).scalars().all()}
    assert rows["subdomains"] == StageStatus.DONE
    assert rows["dns"] in (StageStatus.BLOCKED, StageStatus.READY)


def test_pipeline_stage_count_matches_definition(session, scan):
    run_pipeline_inline(session, _ctx(session, scan))
    from packages.core.models import ScanStage
    n = session.execute(
        select(func.count()).select_from(ScanStage).where(ScanStage.scan_id == scan.id)
    ).scalar()
    assert n == len(PIPELINE)
