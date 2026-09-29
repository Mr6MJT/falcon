"""The honesty invariant: some finding types can never be marked 'confirmed'.

Enforced in two layers — the Python model (`Finding.__init__`) and a DB CheckConstraint.
This is a core promise of the tool: it never presents a heuristic guess (IDOR, access
control, injection candidates) as a confirmed bug.
"""

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.models import Confidence, Finding, Severity

OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL",
    "postgresql+psycopg://postgres:orvex@localhost:55432/orvex",
)


@pytest.mark.parametrize("bad_type", ["idor", "broken_access_control", "business_logic",
                                      "sqli_candidate", "xss_candidate"])
def test_candidate_capped_types_cannot_be_confirmed(bad_type):
    with pytest.raises(ValueError, match="candidate"):
        Finding(type=bad_type, title="x", severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED, dedup_key="k")


def test_unknown_type_cannot_be_confirmed():
    with pytest.raises(ValueError, match="CONFIRMABLE"):
        Finding(type="some_new_thing", title="x", severity=Severity.LOW,
                confidence=Confidence.CONFIRMED, dedup_key="k")


def test_confirmable_type_may_be_confirmed():
    f = Finding(type="open_port", title="22/tcp open", severity=Severity.INFO,
                confidence=Confidence.CONFIRMED, dedup_key="k")
    assert f.confidence == Confidence.CONFIRMED


def test_capped_types_allowed_as_candidate():
    f = Finding(type="idor", title="candidate idor", severity=Severity.MEDIUM,
                confidence=Confidence.CANDIDATE, dedup_key="k")
    assert f.confidence == Confidence.CANDIDATE


def test_db_check_constraint_present():
    """The DB backstop exists even if application code is bypassed."""
    eng = create_engine(OWNER_URL, future=True)
    try:
        with eng.connect() as c:
            row = c.execute(
                text("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                     "WHERE conname='ck_finding_candidate_cap'")
            ).scalar()
    except OperationalError:
        pytest.skip("Postgres not reachable")
    assert row is not None
    assert "confirmed" in row and "idor" in row
