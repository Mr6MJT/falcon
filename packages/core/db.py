"""Database engine, session, and the RLS org-context helper.

Row-Level Security is how one Orvex deployment stays safe to grow into multi-tenant
later: every tenant-scoped table carries ``org_id`` and a policy that filters on the
session setting ``app.current_org``. Application code must call :func:`set_org` (or use
:func:`org_session`) so the policy has an org to compare against; with no org set, the
policies match nothing and queries return zero rows (fail-closed).

The app connects as a NON-owner role (``orvex_app``) and tables use
``FORCE ROW LEVEL SECURITY``, so RLS applies even though migrations create the tables —
there is no "owner bypass" hole.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def database_url() -> str:
    return os.environ.get(
        "ORVEX_DATABASE_URL",
        "postgresql+psycopg://orvex_app:orvex@localhost:5432/orvex",
    )


def make_engine(url: str | None = None, **kw):
    return create_engine(url or database_url(), pool_pre_ping=True, future=True, **kw)


def make_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def set_org(session: Session, org_id: str | None) -> None:
    """Bind the current org for RLS on this session's transaction.

    Uses SET LOCAL so it is scoped to the current transaction and cannot leak to a
    later checkout of the same pooled connection. Passing None clears it (fail-closed).
    """
    if org_id is None:
        session.execute(text("RESET app.current_org"))
    else:
        # set_config(..., is_local=true) is parameterisable, unlike SET LOCAL.
        session.execute(
            text("SELECT set_config('app.current_org', :org, true)"),
            {"org": str(org_id)},
        )


@contextlib.contextmanager
def org_session(session_factory: sessionmaker[Session], org_id: str | None) -> Iterator[Session]:
    """Open a session, begin a txn, bind the org for RLS, and commit/rollback safely."""
    session = session_factory()
    try:
        with session.begin():
            set_org(session, org_id)
            yield session
    finally:
        session.close()
