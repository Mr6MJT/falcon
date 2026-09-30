"""Writeup-driven stages: subdomain takeover + CORS misconfiguration.

Both are non-destructive detectors added from the public-writeup bug-class analysis. The
security-relevant assertions: confidence follows the honesty matrix (fingerprint/observation →
confirmed, dangling-only → candidate) and out-of-scope / non-reflecting hosts never produce
findings.
"""

import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core import stages as stages_mod
from packages.core.guard import ToolResult
from packages.core.models import (
    Authorization,
    AuthorizationType,
    Confidence,
    DNSRecord,
    Finding,
    Organization,
    Program,
    Scan,
    Subdomain,
)
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import CORS_PROBE_ORIGIN, StageContext, run_cors, run_takeover

OWNER_URL = "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"


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
    session.add(Subdomain(org_id=org.id, scan_id=sc.id, hostname="app.example.com",
                          in_scope=True))
    session.flush()
    return sc


def _ctx(session, scan):
    rules = [ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com")]
    return StageContext(session=session, scan=scan, scope_rules=rules, roots=["example.com"],
                        run=lambda *a, **k: ToolResult(ok=True, returncode=0, stdout="",
                                                       stderr="", in_scope_targets=[]))


def _stub_bodies(monkeypatch, mapping):
    monkeypatch.setattr(stages_mod, "_fetch_response_bodies",
                        lambda ctx, urls, **kw: dict(mapping))


def _findings(session, scan):
    return session.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()


# --- subdomain takeover -----------------------------------------------------
def test_takeover_confirmed_when_fingerprint_matches(session, scan, monkeypatch):
    session.add(DNSRecord(org_id=scan.org_id, scan_id=scan.id, hostname="app.example.com",
                          record_type="CNAME", value="victim.github.io"))
    session.flush()
    _stub_bodies(monkeypatch, {
        "https://app.example.com": "404: There isn't a GitHub Pages site here.",
    })
    stats = run_takeover(_ctx(session, scan))
    assert stats["confirmed"] == 1
    f = _findings(session, scan)[0]
    assert f.type == "subdomain_takeover"
    assert f.confidence == Confidence.CONFIRMED
    assert f.evidence["provider"] == "GitHub Pages"


def test_takeover_candidate_when_dangling_without_fingerprint(session, scan, monkeypatch):
    session.add(DNSRecord(org_id=scan.org_id, scan_id=scan.id, hostname="app.example.com",
                          record_type="CNAME", value="victim.github.io"))
    session.flush()
    _stub_bodies(monkeypatch, {"https://app.example.com": "<html>a normal live page</html>"})
    stats = run_takeover(_ctx(session, scan))
    assert stats["takeover_candidates"] == 1 and stats["confirmed"] == 0
    assert _findings(session, scan)[0].confidence == Confidence.CANDIDATE


def test_takeover_ignores_non_takeover_cname(session, scan, monkeypatch):
    session.add(DNSRecord(org_id=scan.org_id, scan_id=scan.id, hostname="app.example.com",
                          record_type="CNAME", value="app.example.com.cdn.cloudflare.net"))
    session.flush()
    called = {"n": 0}
    monkeypatch.setattr(stages_mod, "_fetch_response_bodies",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    stats = run_takeover(_ctx(session, scan))
    assert stats == {"takeover_candidates": 0, "confirmed": 0, "findings": 0}
    assert called["n"] == 0  # nothing to fetch, so no requests sent


# --- CORS -------------------------------------------------------------------
def _cors_response(acao, acac=None):
    lines = ["HTTP/1.1 200 OK", "Content-Type: application/json",
             f"Access-Control-Allow-Origin: {acao}"]
    if acac is not None:
        lines.append(f"Access-Control-Allow-Credentials: {acac}")
    return "\n".join(lines) + "\n\n{}"


def test_cors_confirmed_reflect_with_credentials(session, scan, monkeypatch):
    _stub_bodies(monkeypatch, {
        "https://app.example.com": _cors_response(CORS_PROBE_ORIGIN, "true"),
    })
    run_cors(_ctx(session, scan))
    f = _findings(session, scan)[0]
    assert f.type == "cors_reflect_credentials"
    assert f.confidence == Confidence.CONFIRMED
    assert f.evidence["allow_credentials"] is True


def test_cors_reflect_without_credentials_is_medium(session, scan, monkeypatch):
    _stub_bodies(monkeypatch, {"https://app.example.com": _cors_response(CORS_PROBE_ORIGIN)})
    run_cors(_ctx(session, scan))
    f = _findings(session, scan)[0]
    assert f.type == "misconfiguration"
    assert f.severity.value == "medium"


def test_cors_ignores_non_reflecting_origin(session, scan, monkeypatch):
    _stub_bodies(monkeypatch, {
        "https://app.example.com": _cors_response("https://trusted.example.com", "true"),
    })
    run_cors(_ctx(session, scan))
    assert _findings(session, scan) == []
