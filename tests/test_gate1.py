"""Gate 1 admission checks for scan creation (against the DB, in a rolled-back txn)."""

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

from packages.core.gate1 import Gate1Error, create_scan, scope_hash
from packages.core.models import (
    Aggressiveness,
    Authorization,
    AuthorizationType,
    Organization,
    Program,
    ScanStage,
    ScopeRule,
    ScopeRuleAction,
    ScopeRuleKind,
)

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)


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
    s.rollback()
    s.close()


def _program(session, *, active=False, automated=True, expired=False, with_authz=True):
    org = Organization(name="t", slug=f"t-{uuid.uuid4().hex[:8]}")
    session.add(org)
    session.flush()
    prog = Program(org_id=org.id, name="p", slug=f"p-{uuid.uuid4().hex[:8]}")
    session.add(prog)
    session.flush()
    session.add_all([
        ScopeRule(org_id=org.id, program_id=prog.id, kind=ScopeRuleKind.DOMAIN,
                  action=ScopeRuleAction.INCLUDE, value="example.com"),
        ScopeRule(org_id=org.id, program_id=prog.id, kind=ScopeRuleKind.WILDCARD,
                  action=ScopeRuleAction.INCLUDE, value="example.com"),
    ])
    if with_authz:
        exp = datetime.now(UTC) + (timedelta(days=-1) if expired else timedelta(days=30))
        session.add(Authorization(
            org_id=org.id, program_id=prog.id, authorized_by="me",
            authorization_type=AuthorizationType.BUG_BOUNTY, expires_at=exp,
            allows_active_testing=active, allows_automated_tools=automated,
        ))
    session.flush()
    return org, prog


def test_create_scan_success_freezes_scope_and_seeds_stages(session):
    org, prog = _program(session)
    scan = create_scan(session, org_id=org.id, program_id=prog.id, seeds=["example.com"])
    assert scan.scope_snapshot_hash and len(scan.scope_snapshot_hash) == 64
    assert scan.config["seeds"] == ["example.com"]
    n = session.execute(
        select(func.count()).select_from(ScanStage).where(ScanStage.scan_id == scan.id)
    ).scalar()
    assert n >= 3  # stages seeded


def test_no_live_authorization_refused(session):
    org, prog = _program(session, with_authz=False)
    with pytest.raises(Gate1Error) as e:
        create_scan(session, org_id=org.id, program_id=prog.id, seeds=["example.com"])
    assert e.value.status_code == 403


def test_expired_authorization_refused(session):
    org, prog = _program(session, expired=True)
    with pytest.raises(Gate1Error) as e:
        create_scan(session, org_id=org.id, program_id=prog.id, seeds=["example.com"])
    assert e.value.status_code == 403


def test_active_testing_requires_permission(session):
    org, prog = _program(session, active=False)
    with pytest.raises(Gate1Error) as e:
        create_scan(session, org_id=org.id, program_id=prog.id, seeds=["example.com"],
                    aggressiveness=Aggressiveness.SAFE, active_probes=True)
    assert e.value.status_code == 403
    # With permission it succeeds.
    org2, prog2 = _program(session, active=True)
    scan = create_scan(session, org_id=org2.id, program_id=prog2.id, seeds=["example.com"],
                       active_probes=True)
    assert scan is not None


def test_out_of_scope_seed_refused(session):
    org, prog = _program(session)
    with pytest.raises(Gate1Error) as e:
        create_scan(session, org_id=org.id, program_id=prog.id, seeds=["evil.attacker.net"])
    assert e.value.status_code == 400


def test_empty_and_too_many_seeds_refused(session):
    org, prog = _program(session)
    with pytest.raises(Gate1Error):
        create_scan(session, org_id=org.id, program_id=prog.id, seeds=[])
    with pytest.raises(Gate1Error):
        create_scan(session, org_id=org.id, program_id=prog.id,
                    seeds=[f"h{i}.example.com" for i in range(51)])


def test_scope_hash_is_order_independent():
    from packages.core.scope import RuleAction, RuleKind
    from packages.core.scope import ScopeRule as CoreRule
    a = [CoreRule.make(RuleKind.DOMAIN, RuleAction.INCLUDE, "a.com"),
         CoreRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.a.com")]
    b = list(reversed(a))
    assert scope_hash(a) == scope_hash(b)
