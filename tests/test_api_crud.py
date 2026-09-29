"""API CRUD + scan-create (Gate 1) over HTTP."""

import os
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apps.api.main import create_app
from packages.core.auth import create_access_token
from packages.core.models import Organization

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
    app = create_app(session_factory=sf, jwt_secret=SECRET)
    client = TestClient(app)

    def token(role: str) -> str:
        return create_access_token(user_id=str(uuid.uuid4()), org_id=str(org_id),
                                   role=role, secret=SECRET)

    yield {"client": client, "org_id": org_id, "token": token}
    with sf() as s, s.begin():
        s.execute(text("DELETE FROM organizations WHERE id=:i"), {"i": org_id})


def _auth(tok: str) -> dict:
    return {"authorization": f"Bearer {tok}"}


def _make_program(env, *, active=False):
    body = {
        "name": "Acme BB",
        "platform": "hackerone",
        "scope_rules": [
            {"kind": "domain", "action": "include", "value": "example.com"},
            {"kind": "wildcard", "action": "include", "value": "*.example.com"},
        ],
        "authorization": {
            "authorized_by": "Security Team",
            "authorization_type": "bug_bounty",
            "allows_active_testing": active,
            "allows_automated_tools": True,
        },
    }
    r = env["client"].post("/programs", json=body, headers=_auth(env["token"]("operator")))
    assert r.status_code == 201, r.text
    return r.json()


def test_program_create_list_and_viewer_cannot_write(env):
    prog = _make_program(env)
    assert prog["slug"] == "acme-bb"
    r = env["client"].get("/programs", headers=_auth(env["token"]("viewer")))
    assert r.status_code == 200
    assert any(p["id"] == prog["id"] for p in r.json())
    # viewer may not create
    r2 = env["client"].post("/programs", json={"name": "x"}, headers=_auth(env["token"]("viewer")))
    assert r2.status_code == 403


def test_scan_create_success_and_freezes_scope(env):
    prog = _make_program(env)
    r = env["client"].post(
        "/scans",
        json={"program_id": prog["id"], "seeds": ["example.com", "api.example.com"]},
        headers=_auth(env["token"]("operator")),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert len(body["scope_snapshot_hash"]) == 64
    # snapshot endpoint now sees the scan + seeded stages
    st = env["client"].get(f"/scans/{body['scan_id']}/state", headers=_auth(env["token"]("viewer")))
    assert st.status_code == 200
    assert len(st.json()["stages"]) >= 3


def test_scan_create_rejects_out_of_scope_seed(env):
    prog = _make_program(env)
    r = env["client"].post(
        "/scans",
        json={"program_id": prog["id"], "seeds": ["evil.attacker.net"]},
        headers=_auth(env["token"]("operator")),
    )
    assert r.status_code == 400
    assert "not in scope" in r.text


def test_scan_create_rejects_active_without_permission(env):
    prog = _make_program(env, active=False)
    r = env["client"].post(
        "/scans",
        json={"program_id": prog["id"], "seeds": ["example.com"], "fuzzing": True},
        headers=_auth(env["token"]("operator")),
    )
    assert r.status_code == 403
    assert "active testing" in r.text
