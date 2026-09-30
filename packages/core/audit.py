"""Append-only, hash-chained audit trail — the legal record of what a scan did.

Every scope drop, tool spawn, rate wait and attempt cap flows through the ``audit`` callable
that the guard and stages already emit; this module is the sink that actually persists them.

Design:
  * Each event is written in ITS OWN committed transaction, so the trail survives a stage
    rollback (a failed stage's attempts still leave a record).
  * A per-scan Postgres advisory lock serialises sequence-number allocation, so the chain stays
    valid even when stages run concurrently across worker processes.
  * ``entry_hash = sha256(prev_hash | seq | event | canonical(payload))`` — tampering with any
    row (or reordering) breaks verification from that point on.
  * Payloads are already redacted by the guard before they reach here; no plaintext secret is
    ever written. Audit failures are swallowed (logged to stderr) — the trail must never be able
    to break a scan.
"""

from __future__ import annotations

import hashlib
import json
import sys

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from .db import org_session
from .models import AuditLog


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(prev_hash: str | None, seq: int, event: str, payload: dict) -> str:
    material = f"{prev_hash or ''}|{seq}|{event}|{_canonical(payload)}"
    return hashlib.sha256(material.encode()).hexdigest()


class AuditSink:
    """Callable audit sink: ``sink({"event": name, ...fields})`` appends one chained row."""

    def __init__(self, session_factory: sessionmaker, org_id, scan_id) -> None:
        self._sf = session_factory
        self.org_id = org_id
        self.scan_id = scan_id

    def __call__(self, event: dict) -> None:
        try:
            ev = dict(event)
            name = str(ev.pop("event", "event"))[:80]
            self._append(name, ev)
        except Exception as exc:  # the audit side-channel must never break a scan
            print(f"[orvex-audit] failed to record event: {exc}", file=sys.stderr)

    def _append(self, name: str, payload: dict) -> None:
        with org_session(self._sf, str(self.org_id)) as s:
            # Serialise seq allocation per scan so the chain is valid under concurrency.
            s.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(self.scan_id)})
            last = s.execute(
                select(AuditLog.seq, AuditLog.entry_hash)
                .where(AuditLog.scan_id == self.scan_id)
                .order_by(AuditLog.seq.desc())
                .limit(1)
            ).first()
            seq = (last[0] + 1) if last else 1
            prev = last[1] if last else None
            entry_hash = compute_entry_hash(prev, seq, name, payload)
            s.add(AuditLog(
                org_id=self.org_id, scan_id=self.scan_id, seq=seq,
                event=name, payload=payload, prev_hash=prev, entry_hash=entry_hash,
            ))


def verify_chain(session: Session, scan_id) -> bool:
    """Recompute a scan's chain end to end; True iff every link and sequence number is intact."""
    rows = session.execute(
        select(AuditLog).where(AuditLog.scan_id == scan_id).order_by(AuditLog.seq)
    ).scalars().all()
    prev = None
    for expected_seq, r in enumerate(rows, start=1):
        if r.seq != expected_seq or r.prev_hash != prev:
            return False
        if r.entry_hash != compute_entry_hash(prev, r.seq, r.event, r.payload):
            return False
        prev = r.entry_hash
    return True
