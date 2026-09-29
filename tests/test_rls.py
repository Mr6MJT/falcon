"""RLS cross-org isolation — the tenancy safety test.

Connects as the non-superuser ``orvex_app`` role (RLS is enforced) and proves:
  * a session bound to org A sees only org A's rows,
  * a session with no org set sees nothing (fail-closed),
  * writing a row for another org is rejected by the WITH CHECK clause.

Requires a live Postgres with migrations applied. Set ORVEX_TEST_DB_URL to the app-role
DSN; the test skips (not fails) if the DB is unreachable, so the suite still runs where no
DB is provisioned. In CI a postgres service is provided and this test must pass.
"""

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

APP_URL = os.environ.get(
    "ORVEX_TEST_DB_URL",
    "postgresql+psycopg://orvex_app:orvex@localhost:55432/orvex",
)
OWNER_URL = os.environ.get(
    "ORVEX_TEST_OWNER_URL",
    "postgresql+psycopg://postgres:orvex@localhost:55432/orvex",
)


@pytest.fixture(scope="module")
def owner_engine():
    eng = create_engine(OWNER_URL, future=True)
    try:
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
    except OperationalError:
        pytest.skip("Postgres not reachable; skipping RLS test")
    return eng


@pytest.fixture(scope="module")
def app_engine():
    return create_engine(APP_URL, future=True)


@pytest.fixture
def two_orgs(owner_engine):
    """Seed two orgs as the owner (organizations has no RLS)."""
    a, b = uuid.uuid4(), uuid.uuid4()
    with owner_engine.begin() as c:
        for oid, slug in ((a, f"org-a-{a.hex[:8]}"), (b, f"org-b-{b.hex[:8]}")):
            c.execute(
                text("INSERT INTO organizations (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": oid, "n": slug, "s": slug},
            )
    yield a, b
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})


def _set_org(conn, org_id):
    conn.execute(text("SELECT set_config('app.current_org', :o, true)"),
                 {"o": str(org_id) if org_id else ""})


def _insert_program(conn, org_id, slug):
    conn.execute(
        text("INSERT INTO programs (id, org_id, name, slug) VALUES (:id,:o,:n,:s)"),
        {"id": uuid.uuid4(), "o": org_id, "n": slug, "s": slug},
    )


def test_rls_isolates_and_fails_closed(app_engine, two_orgs):
    org_a, org_b = two_orgs

    # Insert one program into each org, each in its own org-bound transaction.
    with app_engine.begin() as c:
        _set_org(c, org_a)
        _insert_program(c, org_a, "prog-a")
    with app_engine.begin() as c:
        _set_org(c, org_b)
        _insert_program(c, org_b, "prog-b")

    # Bound to A: sees only A.
    with app_engine.begin() as c:
        _set_org(c, org_a)
        rows = c.execute(text("SELECT slug FROM programs")).scalars().all()
        assert rows == ["prog-a"]

    # Bound to B: sees only B.
    with app_engine.begin() as c:
        _set_org(c, org_b)
        rows = c.execute(text("SELECT slug FROM programs")).scalars().all()
        assert rows == ["prog-b"]

    # No org set: fail-closed, zero rows.
    with app_engine.begin() as c:
        rows = c.execute(text("SELECT slug FROM programs")).scalars().all()
        assert rows == []


def test_rls_blocks_cross_org_write(app_engine, two_orgs):
    org_a, org_b = two_orgs
    # Bound to A, try to write a row tagged org B -> WITH CHECK must reject it.
    with pytest.raises((ProgrammingError, Exception)):
        with app_engine.begin() as c:
            _set_org(c, org_a)
            _insert_program(c, org_b, "smuggled")

    # Confirm nothing leaked in.
    with app_engine.begin() as c:
        _set_org(c, org_b)
        rows = c.execute(text("SELECT slug FROM programs WHERE slug='smuggled'")).scalars().all()
        assert rows == []
