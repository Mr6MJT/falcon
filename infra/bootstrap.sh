#!/bin/sh
# One-shot deploy bootstrap: create the non-owner app role, run migrations (as owner),
# and seed the org + first admin. Safe to re-run (idempotent).
set -e

python - <<'PY'
import os
from sqlalchemy import create_engine, text
pw = os.environ.get("ORVEX_DB_PASSWORD", "orvex").replace("'", "''")
eng = create_engine(os.environ["ADMIN_DB_URL"], future=True, isolation_level="AUTOCOMMIT")
with eng.connect() as c:
    exists = c.execute(text("SELECT 1 FROM pg_roles WHERE rolname='orvex_app'")).first()
    if not exists:
        c.execute(text(f"CREATE ROLE orvex_app LOGIN PASSWORD '{pw}' NOSUPERUSER NOBYPASSRLS"))
        print("created role orvex_app")
    else:
        c.execute(text(f"ALTER ROLE orvex_app PASSWORD '{pw}'"))
        print("role orvex_app present (password synced)")
PY

echo "running migrations..."
ORVEX_ALEMBIC_URL="$ADMIN_DB_URL" alembic upgrade head

echo "seeding org + admin..."
ORVEX_DATABASE_URL="$ADMIN_DB_URL" python scripts/seed.py
echo "bootstrap done."
