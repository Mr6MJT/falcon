"""E2E: real engines against a real local target. Regression net for the stdin/secrets/CORS
bugs that unit tests (with a mocked runner) could not catch."""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from packages.core.guard import run_tool
from packages.core.models import (
    Authorization,
    AuthorizationType,
    HTTPEndpoint,
    Organization,
    Program,
    Scan,
    Secret,
)
from packages.core.redact import redact
from packages.core.scope import RuleAction, RuleKind, ScopeRule
from packages.core.stages import (
    CORS_PROBE_ORIGIN,
    StageContext,
    _fetch_response_bodies,
    _response_header,
    run_secrets,
)
from tests.e2e.conftest import PLANTED_AWS, PLANTED_GOOGLE

pytestmark = pytest.mark.e2e

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)


def _iprules():
    return [ScopeRule.make(RuleKind.IP, RuleAction.INCLUDE, "127.0.0.1")]


def _ctx(session=None, scan=None):
    return StageContext(session=session, scan=scan, scope_rules=_iprules(), roots=[],
                        allow_internal=True)


# --- pipeline-plumbing regressions (no DB) ----------------------------------
def test_real_httpx_receives_targets_via_stdin(httpx_available, target_server):
    """THE stdin-bug regression: the real httpx binary must return a result for a target it can
    only have received over stdin (targets are never on argv)."""
    hostport, _base = target_server
    res = run_tool("httpx", [hostport], _iprules(), allow_internal=True, extra_args=["-silent"])
    assert res.ok, res.stderr
    assert "127.0.0.1" in res.stdout  # empty here == the argv-vs-stdin bug is back


def test_real_secret_scan_finds_planted_keys(httpx_available, target_server):
    """httpx fetches the JS body for real, and the detector finds the planted keys."""
    _hostport, base = target_server
    bodies = _fetch_response_bodies(_ctx(), [f"{base}/app.js"], match_codes=None)
    assert bodies, "httpx stored no response bodies"
    detectors = {ref.detector for blob in bodies.values() for ref in redact(blob)[1]}
    assert "aws_access_key_id" in detectors
    assert "google_api_key" in detectors
    # the raw secret is never returned by redact()
    assert all(PLANTED_AWS not in blob or "[REDACTED" in redact(blob)[0]
               for blob in bodies.values())


def test_real_cors_reflection_captured(httpx_available, target_server):
    """The Origin probe header is sent and the reflected CORS response headers are captured."""
    _hostport, base = target_server
    bodies = _fetch_response_bodies(_ctx(), [base],
                                    extra_httpx=["-H", f"Origin: {CORS_PROBE_ORIGIN}"],
                                    match_codes=None)
    blob = "\n".join(bodies.values())
    assert _response_header(blob, "Access-Control-Allow-Origin") == CORS_PROBE_ORIGIN
    assert (_response_header(blob, "Access-Control-Allow-Credentials") or "").lower() == "true"


# --- full secrets stage with the real engine + real DB ----------------------
@pytest.fixture
def db_session():
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


def test_secrets_stage_end_to_end(httpx_available, target_server, db_session):
    """run_secrets end to end: real httpx fetch -> detect -> Secret rows in the DB."""
    _hostport, base = target_server
    org = Organization(name="e2e", slug=f"e2e-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    db_session.flush()
    prog = Program(org_id=org.id, name="p", slug=f"p-{uuid.uuid4().hex[:8]}")
    db_session.add(prog)
    db_session.flush()
    authz = Authorization(org_id=org.id, program_id=prog.id, authorized_by="e2e",
                          authorization_type=AuthorizationType.BUG_BOUNTY,
                          expires_at=datetime.now(UTC) + timedelta(days=1))
    db_session.add(authz)
    db_session.flush()
    sc = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id, config={})
    db_session.add(sc)
    db_session.flush()
    db_session.add(HTTPEndpoint(org_id=org.id, scan_id=sc.id, url=f"{base}/app.js"))
    db_session.flush()

    stats = run_secrets(_ctx(db_session, sc))
    assert stats["scanned"] >= 1
    detectors = {
        r.detector for r in db_session.execute(
            select(Secret).where(Secret.scan_id == sc.id)
        ).scalars().all()
    }
    assert {"aws_access_key_id", "google_api_key"} <= detectors
    # persisted values are masked, never plaintext
    rows = db_session.execute(select(Secret).where(Secret.scan_id == sc.id)).scalars().all()
    assert all(PLANTED_AWS not in (r.redacted_match or "") for r in rows)
    assert all(PLANTED_GOOGLE not in (r.redacted_match or "") for r in rows)
