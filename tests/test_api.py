"""API tests: snapshot auth/isolation + WebSocket (unauth rejected, snapshot + live delta).

Uses committed rows (the API opens its own sessions), cleaned up in teardown.
"""

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
from packages.core.events import InMemoryEventBus, channel_for
from packages.core.models import (
    Authorization,
    AuthorizationType,
    Organization,
    Program,
    Scan,
)

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL",
    "postgresql+psycopg://postgres:orvex@localhost:5432/orvex",
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

    bus = InMemoryEventBus()
    app = create_app(session_factory=sf, bus=bus, jwt_secret=SECRET)
    client = TestClient(app)
    token = create_access_token(user_id=str(uuid.uuid4()), org_id=str(org_id),
                                role="operator", secret=SECRET)
    yield {"client": client, "app": app, "bus": bus, "scan_id": scan_id,
           "org_id": org_id, "token": token}

    with sf() as s, s.begin():
        s.execute(text("DELETE FROM organizations WHERE id=:i"), {"i": org_id})


def test_state_requires_auth(env):
    r = env["client"].get(f"/scans/{env['scan_id']}/state")
    assert r.status_code == 401


def test_state_returns_snapshot(env):
    r = env["client"].get(
        f"/scans/{env['scan_id']}/state",
        headers={"authorization": f"Bearer {env['token']}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "snapshot"
    assert body["status"] == "pending"
    assert body["counts"]["subdomains"] == 0


def test_state_cross_org_is_404(env):
    other_token = create_access_token(user_id=str(uuid.uuid4()),
                                      org_id=str(uuid.uuid4()), role="operator", secret=SECRET)
    r = env["client"].get(
        f"/scans/{env['scan_id']}/state",
        headers={"authorization": f"Bearer {other_token}"},
    )
    assert r.status_code == 404


def test_ws_unauthenticated_rejected(env):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with env["client"].websocket_connect(f"/scans/{env['scan_id']}/events") as ws:
            ws.receive_json()


def test_ws_sends_snapshot_then_live_delta(env):
    url = f"/scans/{env['scan_id']}/events"
    headers = {"authorization": f"Bearer {env['token']}"}
    with env["client"].websocket_connect(url, headers=headers) as ws:
        first = ws.receive_json()
        assert first["type"] == "snapshot"
        # Publish a delta; the socket must forward it.
        env["bus"].publish(channel_for(env["scan_id"]),
                           {"type": "stage.started", "stage": "subdomains"})
        got = ws.receive_json()
        while got.get("type") == "ping":
            got = ws.receive_json()
        assert got["type"] == "stage.started"
        assert got["stage"] == "subdomains"
