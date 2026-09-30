"""Hash-chained audit trail: chain integrity, append ordering, and tamper detection."""

import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.audit import AuditSink, compute_entry_hash, verify_chain
from packages.core.models import (
    AuditLog,
    Authorization,
    AuthorizationType,
    Organization,
    Program,
    Scan,
)

OWNER_URL = "postgresql+psycopg://postgres:orvex@localhost:5432/orvex"


# --- pure hash logic --------------------------------------------------------
def test_entry_hash_is_deterministic_and_field_sensitive():
    base = compute_entry_hash(None, 1, "tool_spawn", {"tool": "httpx"})
    assert base == compute_entry_hash(None, 1, "tool_spawn", {"tool": "httpx"})
    assert base != compute_entry_hash("abc", 1, "tool_spawn", {"tool": "httpx"})  # prev
    assert base != compute_entry_hash(None, 2, "tool_spawn", {"tool": "httpx"})   # seq
    assert base != compute_entry_hash(None, 1, "tool_skipped", {"tool": "httpx"}) # event
    assert base != compute_entry_hash(None, 1, "tool_spawn", {"tool": "nuclei"})  # payload


# --- DB-backed chain --------------------------------------------------------
@pytest.fixture
def factory_and_scan():
    eng = create_engine(OWNER_URL, future=True)
    try:
        with eng.connect() as c:
            c.execute(select(1))
    except OperationalError:
        pytest.skip("Postgres not reachable")
    sf = sessionmaker(bind=eng, expire_on_commit=False, future=True)
    s = sf()
    org = Organization(name="a", slug=f"a-{uuid.uuid4().hex[:8]}")
    s.add(org)
    s.flush()
    prog = Program(org_id=org.id, name="p", slug=f"p-{uuid.uuid4().hex[:8]}")
    s.add(prog)
    s.flush()
    authz = Authorization(org_id=org.id, program_id=prog.id, authorized_by="me",
                          authorization_type=AuthorizationType.BUG_BOUNTY,
                          expires_at=datetime.now(UTC) + timedelta(days=1))
    s.add(authz)
    s.flush()
    sc = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id, config={})
    s.add(sc)
    s.commit()  # committed so the sink's own transactions can see it (and satisfy the FK)
    try:
        yield sf, org.id, sc.id
    finally:
        s.execute(delete(Scan).where(Scan.id == sc.id))  # cascades to audit_log
        s.execute(delete(Authorization).where(Authorization.id == authz.id))
        s.execute(delete(Program).where(Program.id == prog.id))
        s.execute(delete(Organization).where(Organization.id == org.id))
        s.commit()
        s.close()


def test_sink_appends_a_valid_chain(factory_and_scan):
    sf, org_id, scan_id = factory_and_scan
    sink = AuditSink(sf, org_id, scan_id)
    sink({"event": "scan_started"})
    sink({"event": "tool_spawn", "tool": "httpx", "targets": ["a.example.com"]})
    sink({"event": "target_dropped", "tool": "httpx", "target": "evil.net"})

    s = sf()
    rows = s.execute(
        select(AuditLog).where(AuditLog.scan_id == scan_id).order_by(AuditLog.seq)
    ).scalars().all()
    assert [r.seq for r in rows] == [1, 2, 3]
    assert rows[0].prev_hash is None
    assert rows[1].prev_hash == rows[0].entry_hash  # linked
    assert rows[2].prev_hash == rows[1].entry_hash
    assert verify_chain(s, scan_id) is True
    s.close()


def test_verify_chain_detects_tampering(factory_and_scan):
    sf, org_id, scan_id = factory_and_scan
    sink = AuditSink(sf, org_id, scan_id)
    sink({"event": "tool_spawn", "tool": "httpx"})
    sink({"event": "tool_spawn", "tool": "nuclei"})

    s = sf()
    assert verify_chain(s, scan_id) is True
    # Tamper: rewrite a payload in place without fixing the hash chain.
    s.execute(update(AuditLog).where(AuditLog.scan_id == scan_id, AuditLog.seq == 1)
              .values(payload={"tool": "MALICIOUS"}))
    s.commit()
    assert verify_chain(s, scan_id) is False
    s.close()
