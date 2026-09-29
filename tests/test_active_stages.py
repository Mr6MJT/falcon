"""Slice 13: gated active modules — fuzzing, active probes, safe login, IDOR.

Safety assertions: these stages are OFF unless explicitly enabled; login attempts are requested
at the ≤5 cap; and XSS/SQLi/IDOR findings can NEVER be confirmed (reflection/heuristic only).
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
    Confidence,
    Finding,
    HTTPEndpoint,
    Organization,
    Program,
    Scan,
    Subdomain,
)
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import (
    StageContext,
    run_active,
    run_fuzzing,
    run_idor,
    run_login,
)

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)

FFUF_OUT = ('{"results":[{"url":"https://www.example.com/admin"},'
            '{"url":"https://evil.attacker.net/secret"}]}')  # 2nd is out of scope
PROBE_OUT = "\n".join([
    '{"kind":"xss","url":"https://www.example.com/s?q=1","param":"q","confirmed":true}',
    '{"kind":"sqli","url":"https://www.example.com/s?id=1","param":"id","confirmed":true}',
    '{"kind":"open_redirect","url":"https://www.example.com/r?u=x","param":"u","confirmed":true}',
    '{"kind":"ssrf","url":"https://www.example.com/f?url=x","param":"url","confirmed":false}',
])
LOGIN_OUT = "\n".join([
    '{"kind":"bruteforce_protection","url":"https://www.example.com/login","present":true}',
    '{"kind":"user_enum","url":"https://www.example.com/login","detected":true}',
    '{"kind":"default_creds","url":"https://www.example.com/login","accepted":false}',
])
IDOR_OUT = '{"url":"https://www.example.com/api/orders/1","param":"id"}'


def _rec(calls):
    out = {"ffuf": FFUF_OUT, "orvex-probe": PROBE_OUT, "login_probe": LOGIN_OUT,
           "orvex-idor": IDOR_OUT}

    def run(tool, targets, **kw):
        calls.append({"tool": tool, "kw": kw})
        return ToolResult(ok=True, returncode=0, stdout=out.get(tool, ""),
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
                          expires_at=datetime.now(UTC) + timedelta(days=30),
                          allows_active_testing=True)
    session.add(authz)
    session.flush()
    sc = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id, config={})
    session.add(sc)
    session.flush()
    session.add_all([
        HTTPEndpoint(org_id=org.id, scan_id=sc.id,
                     url="https://www.example.com/login", status_code=200),
        Subdomain(org_id=org.id, scan_id=sc.id, hostname="www.example.com", in_scope=True),
    ])
    session.flush()
    return sc


def _ctx(session, scan, calls=None):
    rules = [ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com")]
    return StageContext(session=session, scan=scan, scope_rules=rules, roots=["example.com"],
                        run=_rec(calls if calls is not None else []))


# --- opt-in gating ----------------------------------------------------------
def test_active_modules_skip_when_not_enabled(session, scan):
    # scan.config is empty -> every gated module refuses to run.
    assert run_fuzzing(_ctx(session, scan)) == {"skipped": "fuzzing not enabled"}
    assert run_active(_ctx(session, scan))["skipped"]
    assert run_login(_ctx(session, scan))["skipped"]
    assert run_idor(_ctx(session, scan))["skipped"]
    assert session.execute(
        select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)
    ).scalar() == 0


# --- fuzzing ----------------------------------------------------------------
def test_fuzzing_discovers_in_scope_only(session, scan, tmp_path, monkeypatch):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nsecret\n")
    monkeypatch.setenv("ORVEX_FUZZ_WORDLIST", str(wl))
    scan.config = {"fuzzing": True}
    session.flush()
    calls: list = []
    run_fuzzing(_ctx(session, scan, calls=calls))
    urls = session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == scan.id)
    ).scalars().all()
    assert "https://www.example.com/admin" in urls
    assert not any("attacker.net" in u for u in urls)  # out-of-scope dropped
    # ffuf is invoked per host with -u FUZZ + -w wordlist and no positional target.
    ffuf_calls = [c for c in calls if c["tool"] == "ffuf"]
    assert ffuf_calls and all(c["kw"].get("no_target_argv") for c in ffuf_calls)
    assert any("-u" in c["kw"].get("extra_args", []) for c in ffuf_calls)


def test_fuzzing_skips_without_wordlist(session, scan, monkeypatch):
    monkeypatch.delenv("ORVEX_FUZZ_WORDLIST", raising=False)
    scan.config = {"fuzzing": True}
    session.flush()
    assert run_fuzzing(_ctx(session, scan)) == {
        "skipped": "no wordlist configured (ORVEX_FUZZ_WORDLIST)"}


# --- active probes: honesty -------------------------------------------------
def test_active_probes_never_confirm_xss_or_sqli(session, scan):
    scan.config = {"active_probes": True}
    session.flush()
    run_active(_ctx(session, scan))
    rows = {r.type: r for r in session.execute(
        select(Finding).where(Finding.scan_id == scan.id)).scalars().all()}
    # Even though the probe output said confirmed:true, reflection-based XSS/SQLi stay candidate.
    assert rows["xss_candidate"].confidence == Confidence.CANDIDATE
    assert rows["sqli_candidate"].confidence == Confidence.CANDIDATE
    # Canary-proven open redirect may be confirmed; unproven SSRF stays candidate.
    assert rows["open_redirect_canary"].confidence == Confidence.CONFIRMED
    assert rows["ssrf_candidate"].confidence == Confidence.CANDIDATE


def test_active_probes_default_to_get_only(session, scan):
    scan.config = {"active_probes": True}
    session.flush()
    calls: list = []
    run_active(_ctx(session, scan, calls))
    probe = next(c for c in calls if c["tool"] == "orvex-probe")
    assert probe["kw"].get("extra_args") == ["--methods", "GET"]


# --- safe login testing -----------------------------------------------------
def test_login_requests_capped_attempts_and_asserts_presence_only(session, scan):
    scan.config = {"active_probes": True}
    session.flush()
    calls: list = []
    run_login(_ctx(session, scan, calls))
    login = next(c for c in calls if c["tool"] == "login_probe")
    assert login["kw"].get("attempts") == 5  # never more than 5 (guard also hard-caps)
    types = {r.type for r in session.execute(
        select(Finding).where(Finding.scan_id == scan.id)).scalars().all()}
    assert "bruteforce_protection_present" in types
    assert "user_enumeration" in types
    # "default_creds accepted:false" and absence-of-protection produce NO finding.
    assert "default_credentials_accepted" not in types


# --- IDOR: always candidate -------------------------------------------------
def test_idor_is_always_candidate(session, scan):
    scan.config = {"active_probes": True}
    session.flush()
    run_idor(_ctx(session, scan))
    row = session.execute(
        select(Finding).where(Finding.scan_id == scan.id, Finding.type == "idor")
    ).scalar_one()
    assert row.confidence == Confidence.CANDIDATE
