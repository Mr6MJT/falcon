"""Findings list + triage over HTTP."""

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
    Severity,
)

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"
)
SECRET = "test-secret-key-at-least-32-bytes-long!!"


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
        s.add(Organization(id=org_id, name="t", slug=f"t-{org_id.hex[:8]}"))
        prog = Program(org_id=org_id, name="p", slug=f"p-{org_id.hex[:8]}")
        s.add(prog)
        s.flush()
        authz = Authorization(org_id=org_id, program_id=prog.id, authorized_by="me",
                              authorization_type=AuthorizationType.BUG_BOUNTY,
                              expires_at=datetime.now(UTC) + timedelta(days=30))
        s.add(authz)
        s.flush()
        scan = Scan(org_id=org_id, program_id=prog.id, authorization_id=authz.id)
        s.add(scan)
        s.flush()
        scan_id = scan.id
        s.add_all([
            Finding(org_id=org_id, scan_id=scan_id, type="cve", title="RCE",
                    severity=Severity.CRITICAL, confidence=Confidence.CANDIDATE,
                    cve_id="CVE-2021-1", cvss=9.8, dedup_key="k1",
                    evidence={"request": "GET /", "response": "200 OK"}),
            Finding(org_id=org_id, scan_id=scan_id, type="tls_issue", title="TLS 1.0",
                    severity=Severity.LOW, confidence=Confidence.CONFIRMED, dedup_key="k2"),
        ])
    app = create_app(session_factory=sf, jwt_secret=SECRET)
    client = TestClient(app)

    def token(role="operator"):
        return create_access_token(user_id=str(uuid.uuid4()), org_id=str(org_id),
                                   role=role, secret=SECRET)

    yield {"client": client, "scan_id": scan_id, "org_id": org_id, "token": token}
    with sf() as s, s.begin():
        s.execute(text("DELETE FROM organizations WHERE id=:i"), {"i": org_id})


def _h(tok):
    return {"authorization": f"Bearer {tok}"}


def test_list_findings_sorted_and_with_evidence(env):
    r = env["client"].get(f"/scans/{env['scan_id']}/findings", headers=_h(env["token"]()))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    # critical first
    assert body["items"][0]["severity"] == "critical"
    assert body["items"][0]["cve_id"] == "CVE-2021-1"
    assert body["items"][0]["evidence"]["request"] == "GET /"


def test_list_findings_filter_by_confidence(env):
    r = env["client"].get(
        f"/scans/{env['scan_id']}/findings?confidence=confirmed", headers=_h(env["token"]())
    )
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["type"] == "tls_issue"


def test_triage_persists(env):
    lst = env["client"].get(f"/scans/{env['scan_id']}/findings", headers=_h(env["token"]())).json()
    fid = lst["items"][0]["id"]
    r = env["client"].patch(f"/findings/{fid}", json={"status": "false_positive"},
                            headers=_h(env["token"]()))
    assert r.status_code == 200 and r.json()["status"] == "false_positive"
    # re-fetch: persisted
    again = env["client"].get(
        f"/scans/{env['scan_id']}/findings", headers=_h(env["token"]())
    ).json()
    got = next(i for i in again["items"] if i["id"] == fid)
    assert got["status"] == "false_positive"


def test_triage_requires_write_role(env):
    lst = env["client"].get(f"/scans/{env['scan_id']}/findings", headers=_h(env["token"]())).json()
    fid = lst["items"][0]["id"]
    r = env["client"].patch(f"/findings/{fid}", json={"status": "resolved"},
                            headers=_h(env["token"]("viewer")))
    assert r.status_code == 403


def test_triage_bad_status_rejected(env):
    lst = env["client"].get(f"/scans/{env['scan_id']}/findings", headers=_h(env["token"]())).json()
    fid = lst["items"][0]["id"]
    r = env["client"].patch(f"/findings/{fid}", json={"status": "nonsense"},
                            headers=_h(env["token"]()))
    assert r.status_code == 400


def test_list_scans_and_assets(env):
    # seed one subdomain for the scan via the owner engine
    import os as _os

    from sqlalchemy import create_engine as _ce
    from sqlalchemy.orm import sessionmaker as _sm
    eng = _ce(_os.environ.get("ORVEX_TEST_OWNER_URL",
              "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"), future=True)
    from packages.core.models import Subdomain
    with _sm(bind=eng, future=True)() as s, s.begin():
        s.add(Subdomain(org_id=env["org_id"], scan_id=env["scan_id"],
                        hostname="www.example.com", in_scope=True))
    tok = env["token"]()
    r = env["client"].get("/scans", headers=_h(tok))
    assert r.status_code == 200
    assert any(sc["id"] == str(env["scan_id"]) for sc in r.json()["items"])
    a = env["client"].get(f"/scans/{env['scan_id']}/assets/subdomains", headers=_h(tok))
    assert a.status_code == 200
    body = a.json()
    assert body["kind"] == "subdomains" and body["total"] >= 1
    assert any(row["hostname"] == "www.example.com" for row in body["items"])
    # unknown kind rejected
    bad = env["client"].get(f"/scans/{env['scan_id']}/assets/bogus", headers=_h(tok))
    assert bad.status_code == 404
