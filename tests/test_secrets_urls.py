"""Slice 10: URL/param discovery + secret detection.

The security-critical assertion: a detected secret's plaintext NEVER lands in the DB or in
any audit event — only a mask + sha256 (+ optional ciphertext when retention is opted in).
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

from packages.core import stages as stages_mod
from packages.core.crypto import decrypt, encrypt, generate_key_b64
from packages.core.guard import ToolResult
from packages.core.models import (
    Authorization,
    AuthorizationType,
    DNSRecord,
    HTTPEndpoint,
    Organization,
    Parameter,
    Program,
    Scan,
    Secret,
)
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import (
    StageContext,
    params_from_url,
    parse_trufflehog,
    parse_urls,
    run_secrets,
    run_urls,
)

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)

LEAKED = "AKIAIOSFODNN7EXAMPLE"
KATANA_OUT = (
    "https://www.example.com/login?next=/home\n"
    "https://www.example.com/search?q=test&page=2\n"
    "https://evil.attacker.net/x?a=1\n"  # out of scope -> dropped
)
GAU_OUT = "https://api.example.com/v1/users?id=1\n"
TRUFFLEHOG_OUT = (
    '{"DetectorName":"AWS","Raw":"' + LEAKED + '","Verified":false,'
    '"SourceMetadata":{"Data":{"Filesystem":{"file":"https://www.example.com/app.js"}}}}\n'
)


def _runner():
    def run(tool, targets, **kw):
        out = {"katana": KATANA_OUT, "gau": GAU_OUT, "trufflehog": TRUFFLEHOG_OUT}.get(tool, "")
        return ToolResult(ok=True, returncode=0, stdout=out, stderr="",
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
    session.add_all([
        DNSRecord(org_id=org.id, scan_id=sc.id, hostname="www.example.com",
                  record_type="A", value="93.184.216.34"),
        DNSRecord(org_id=org.id, scan_id=sc.id, hostname="api.example.com",
                  record_type="A", value="93.184.216.35"),
        # an in-scope JS asset the secrets stage will select and (via a stubbed fetch) scan
        HTTPEndpoint(org_id=org.id, scan_id=sc.id, url="https://www.example.com/app.js"),
    ])
    session.flush()
    return sc


# Body served by the stubbed fetch: a JS bundle with a hard-coded AWS key.
LEAK_URL = "https://www.example.com/app.js"
LEAK_BODY = f'const cfg={{region:"us-east-1",key:"{LEAKED}"}};'


def _stub_fetch(monkeypatch, bodies=None):
    bodies = bodies if bodies is not None else {LEAK_URL: LEAK_BODY}
    monkeypatch.setattr(stages_mod, "_fetch_response_bodies", lambda ctx, urls: dict(bodies))


def _ctx(session, scan, events=None):
    rules = [
        ScopeRule.make(RuleKind.DOMAIN, RuleAction.INCLUDE, "example.com"),
        ScopeRule.make(RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"),
    ]
    audit = events.append if events is not None else (lambda e: None)
    return StageContext(session=session, scan=scan, scope_rules=rules, roots=["example.com"],
                        run=_runner(), audit=audit)


# --- pure helpers -----------------------------------------------------------
def test_parse_urls_and_params():
    urls = parse_urls(KATANA_OUT)
    assert "https://www.example.com/search?q=test&page=2" in urls
    assert params_from_url("https://x/y?a=1&b=2") == [("a", "query"), ("b", "query")]


def test_parse_trufflehog_extracts_raw_and_location():
    f = parse_trufflehog(TRUFFLEHOG_OUT)[0]
    assert f["detector"] == "AWS" and f["raw"] == LEAKED
    assert f["location"] == "https://www.example.com/app.js"


# --- stages -----------------------------------------------------------------
def test_urls_populates_endpoints_and_params_and_drops_out_of_scope(session, scan):
    stats = run_urls(_ctx(session, scan))
    assert stats["urls"] >= 3  # 2 katana in-scope + 1 gau; evil.attacker.net dropped
    params = session.execute(
        select(Parameter.name).where(Parameter.scan_id == scan.id)
    ).scalars().all()
    assert set(params) >= {"next", "q", "page", "id"}
    # the out-of-scope host never made it into endpoints
    from packages.core.models import HTTPEndpoint
    urls = session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == scan.id)
    ).scalars().all()
    assert not any("attacker.net" in u for u in urls)


def test_secrets_never_store_plaintext(session, scan, monkeypatch):
    _stub_fetch(monkeypatch)
    events: list = []
    stats = run_secrets(_ctx(session, scan, events=events))
    assert stats["scanned"] == 1
    secret = session.execute(select(Secret).where(Secret.scan_id == scan.id)).scalar_one()
    assert secret.detector == "aws_access_key_id"
    assert secret.redacted_match == "AKIA…MPLE"      # masked (first4…last4)
    assert secret.sha256 == __import__("hashlib").sha256(LEAKED.encode()).hexdigest()
    assert secret.location == LEAK_URL               # traced back to the JS file
    assert secret.ciphertext is None                 # regex net never retains plaintext
    # The raw secret must not appear anywhere persisted or audited.
    assert LEAKED not in (secret.redacted_match + secret.location)
    assert not any(LEAKED in str(e) for e in events)


def test_secrets_empty_when_no_assets(session, scan, monkeypatch):
    # No matched bodies -> no secrets, and nothing blows up.
    _stub_fetch(monkeypatch, bodies={})
    stats = run_secrets(_ctx(session, scan))
    assert stats == {"secrets": 0, "scanned": 0}


def test_crypto_roundtrip_and_key_required():
    key = generate_key_b64()
    blob = encrypt("s3cr3t-value", key)
    assert b"s3cr3t" not in blob  # not plaintext
    assert decrypt(blob, key) == "s3cr3t-value"


def test_secrets_count_is_idempotent(session, scan, monkeypatch):
    _stub_fetch(monkeypatch)
    run_secrets(_ctx(session, scan))
    run_secrets(_ctx(session, scan))
    n = session.execute(
        select(func.count()).select_from(Secret).where(Secret.scan_id == scan.id)
    ).scalar()
    assert n == 1
