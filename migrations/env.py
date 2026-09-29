"""Alembic environment for Orvex.

Migrations run as the DB owner (postgres); the application connects as the non-owner
``orvex_app`` role so RLS is enforced. ``target_metadata`` points at the models so
autogenerate + the CI drift check work.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.db import Base  # noqa: E402
from packages.core import models  # noqa: E402,F401  (import registers all tables)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Allow overriding the URL from the environment (CI / different ports).
if os.environ.get("ORVEX_ALEMBIC_URL"):
    config.set_main_option("sqlalchemy.url", os.environ["ORVEX_ALEMBIC_URL"])

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
