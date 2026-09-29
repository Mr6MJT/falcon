"""Reporting: build_report + HTML/JSON/PDF rendering, and the API endpoints."""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apps.api.main import create_app
from packages.core.auth import create_access_token
from packages.core.models import (
    Authorization,
    AuthorizationType,
    Confidence,
    Finding,
    Organization,
    Program,
    Scan,
    Secret,
    Severity,
    Technology,
)
from packages.core.report import build_report, render_html, render_json, render_pdf

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)
SECRET = "test-secret-key-at-least-32-bytes-long!!"
LEAKED = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def env():
    eng = create_engine(OWNER_URL, future=True)
    try:
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
    except OperationalError:
        pytest.skip("Postgres not reachable")
    sf = sessionmaker(bind=eng, future=True)
    org_id = uuid.uuid4()
    with sf() as s, s.begin():
        s.add(Organization(id=org_id, name="Acme", slug=f"a-{org_id.hex[:8]}"))
        prog = Program(org_id=org_id, name="Acme BB", slug=f"p-{org_id.hex[:8]}",
                       platform="hackerone")
        s.add(prog)
        s.flush()
        authz = Authorization(org_id=org_id, program_id=prog.id, authorized_by="me",
                              authorization_type=AuthorizationType.BUG_BOUNTY,
                              expires_at=datetime.now(UTC) + timedelta(days=30))
        s.add(authz)
        s.flush()
        scan = Scan(org_id=org_id, program_id=prog.id, authorization_id=authz.id,
                    scope_snapshot_hash="a" * 64, config={"seeds": ["example.com"]})
        s.add(scan)
        s.flush()
        scan_id = scan.id
        s.add_all([
            Finding(org_id=org_id, scan_id=scan_id, type="cve", title="Example RCE",
                    severity=Severity.CRITICAL, confidence=Confidence.CANDIDATE,
                    cve_id="CVE-2021-1", cvss=9.8, dedup_key="k1",
                    evidence={"request": "GET /", "response": "200 OK"}),
            Finding(org_id=org_id, scan_id=scan_id, type="tls_issue", title="TLS 1.0",
                    severity=Severity.LOW, confidence=Confidence.CONFIRMED, dedup_key="k2"),
            Technology(org_id=org_id, scan_id=scan_id, url="https://x", name="nginx",
                       version="1.18"),
            Secret(org_id=org_id, scan_id=scan_id, detector="AWS", redacted_match="AKIA…MPLE",
                   sha256="d" * 64, location="https://x/app.js", verified=False),
        ])
    app = create_app(session_factory=sf, jwt_secret=SECRET)
    client = TestClient(app)

    def token(role="operator"):
        return create_access_token(user_id=str(uuid.uuid4()), org_id=str(org_id),
                                   role=role, secret=SECRET)

    yield {"client": client, "sf": sf, "scan_id": scan_id, "org_id": org_id, "token": token}
    with sf() as s, s.begin():
        s.execute(text("DELETE FROM organizations WHERE id=:i"), {"i": org_id})


def _h(tok):
    return {"authorization": f"Bearer {tok}"}


def test_build_report_structure(env):
    with env["sf"]() as s:
        rep = build_report(s, env["scan_id"])
    assert rep["scan"]["program"] == "Acme BB"
    assert rep["summary"]["findings_total"] == 2
    assert rep["summary"]["by_confidence"]["confirmed"] == 1
    assert rep["summary"]["by_confidence"]["candidate"] == 1
    # critical finding first
    assert rep["findings"][0]["severity"] == "critical"
    assert rep["assets"]["secrets"][0]["mask"] == "AKIA…MPLE"


def test_report_never_leaks_plaintext_secret(env):
    with env["sf"]() as s:
        rep = build_report(s, env["scan_id"])
    html = render_html(rep)
    js = render_json(rep)
    assert LEAKED not in html and LEAKED not in js  # only the mask is present
    assert "AKIA…MPLE" in html


def test_render_html_marks_candidates(env):
    with env["sf"]() as s:
        rep = build_report(s, env["scan_id"])
    html = render_html(rep)
    assert "Orvex Recon" in html
    assert "requires manual verification" in html  # candidate caveat present
    assert "CVE-2021-1" in html


def test_render_pdf_produces_pdf(env):
    with env["sf"]() as s:
        rep = build_report(s, env["scan_id"])
    pdf = render_pdf(render_html(rep))
    assert pdf[:5] == b"%PDF-" and len(pdf) > 1000


def test_report_endpoints(env):
    c, tok = env["client"], env["token"]()
    rj = c.get(f"/scans/{env['scan_id']}/report", headers=_h(tok))
    assert rj.status_code == 200 and rj.json()["summary"]["findings_total"] == 2
    rh = c.get(f"/scans/{env['scan_id']}/report.html", headers=_h(tok))
    assert rh.status_code == 200 and "text/html" in rh.headers["content-type"]
    rpdf = c.get(f"/scans/{env['scan_id']}/report.pdf", headers=_h(tok))
    assert rpdf.status_code == 200 and rpdf.content[:5] == b"%PDF-"
    # auth required
    assert c.get(f"/scans/{env['scan_id']}/report").status_code == 401
