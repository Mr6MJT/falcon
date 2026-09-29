"""Recon stages: ports/tls/waf/tech — parsers + DB population, incl. the IP-scope rule."""

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
    Service,
    Technology,
    TLSInfo,
)
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import (
    StageContext,
    parse_naabu,
    parse_tlsx,
    parse_wafw00f,
    run_ports,
    run_tech,
    run_tls,
    run_waf,
)

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)

NAABU_OUT = '{"ip":"1.1.1.1","port":443,"host":"api.example.com"}\n{"ip":"1.1.1.1","port":80}\n'
TLSX_OUT = (
    '{"host":"www.example.com","port":"443","tls_version":"tls1.0",'
    '"issuer_dn":"CN=Test","self_signed":false,"expired":false}\n'
)
WAFW00F_OUT = '[{"url":"https://www.example.com","detected":true,"firewall":"Cloudflare"}]'
TECH_OUT = '{"url":"https://www.example.com","tech":["Nginx","React"]}\n'


def _runner(mapping):
    def run(tool, targets, **kw):
        val = mapping.get(tool, "")
        return ToolResult(ok=True, returncode=0, stdout=val, stderr="",
                          in_scope_targets=list(targets))
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
    s.rollback()
    s.close()


@pytest.fixture
def scan(session):
    org = Organization(name="t", slug=f"t-{uuid.uuid4().hex[:8]}")
    session.add(org)
    session.flush()
    prog = Program(org_id=org.id, name="p", slug=f"p-{uuid.uuid4().hex[:8]}")
    session.add(prog)
    session.flush()
    authz = Authorization(org_id=org.id, program_id=prog.id, authorized_by="me",
                          authorization_type=AuthorizationType.BUG_BOUNTY,
                          expires_at=datetime.now(UTC) + timedelta(days=30))
    session.add(authz)
    session.flush()
    sc = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id, config={})
    session.add(sc)
    session.flush()
    return sc


def _ctx(session, scan, *, with_ip_scope: bool):
    rules = [
        ScopeRule.make(RuleKind.DOMAIN, RuleAction.INCLUDE, "example.com"),
        ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"),
    ]
    if with_ip_scope:
        rules.append(ScopeRule.make(RuleKind.IP, RuleAction.INCLUDE, "1.1.1.1"))
    return StageContext(session=session, scan=scan, scope_rules=rules,
                        roots=["example.com"],
                        run=_runner({"naabu": NAABU_OUT, "tlsx": TLSX_OUT,
                                     "wafw00f": WAFW00F_OUT, "httpx": TECH_OUT}))


def _seed_dns_and_endpoints(session, scan):
    session.add_all([
        DNSRecord(org_id=scan.org_id, scan_id=scan.id, hostname="www.example.com",
                  record_type="A", value="1.1.1.1"),
        HTTPEndpoint(org_id=scan.org_id, scan_id=scan.id, url="https://www.example.com",
                     status_code=200),
    ])
    session.flush()


def test_parsers():
    assert parse_naabu(NAABU_OUT) == [("1.1.1.1", 443, "api.example.com"), ("1.1.1.1", 80, None)]
    assert parse_tlsx(TLSX_OUT)[0]["tls_version"] == "tls1.0"
    assert parse_wafw00f(WAFW00F_OUT)[0]["firewall"] == "Cloudflare"


def test_ports_only_scans_in_scope_ips(session, scan):
    _seed_dns_and_endpoints(session, scan)
    # No IP scope rule: the resolved IP is NOT in scope -> naabu produces nothing.
    run_ports(_ctx(session, scan, with_ip_scope=False))
    n = session.execute(
        select(func.count()).select_from(Service).where(Service.scan_id == scan.id)
    ).scalar()
    assert n == 0


def test_ports_scans_when_ip_explicitly_in_scope(session, scan):
    _seed_dns_and_endpoints(session, scan)
    run_ports(_ctx(session, scan, with_ip_scope=True))
    n = session.execute(
        select(func.count()).select_from(Service).where(Service.scan_id == scan.id)
    ).scalar()
    assert n == 2  # 443 + 80


def test_tls_populates_and_flags_weak_protocol(session, scan):
    _seed_dns_and_endpoints(session, scan)
    run_tls(_ctx(session, scan, with_ip_scope=False))
    row = session.execute(
        select(TLSInfo).where(TLSInfo.scan_id == scan.id)
    ).scalar_one()
    assert row.hostname == "www.example.com"
    assert row.weak_protocol is True  # tls1.0


def test_waf_updates_endpoint_vendor(session, scan):
    _seed_dns_and_endpoints(session, scan)
    run_waf(_ctx(session, scan, with_ip_scope=False))
    ep = session.execute(
        select(HTTPEndpoint).where(HTTPEndpoint.scan_id == scan.id)
    ).scalar_one()
    assert ep.waf_vendor == "Cloudflare"


def test_tech_populates_and_is_idempotent(session, scan):
    _seed_dns_and_endpoints(session, scan)
    run_tech(_ctx(session, scan, with_ip_scope=False))
    run_tech(_ctx(session, scan, with_ip_scope=False))  # re-run: no dupes
    n = session.execute(
        select(func.count()).select_from(Technology).where(Technology.scan_id == scan.id)
    ).scalar()
    assert n == 2  # Nginx, React
