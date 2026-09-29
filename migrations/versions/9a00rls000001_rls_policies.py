"""row-level security policies on all tenant tables

Enables and FORCEs RLS on every table carrying org_id, with a fail-closed policy:
a row is visible/writable only when its org_id equals the session setting
``app.current_org``. With the setting unset, current_setting(..., true) returns NULL,
``org_id = NULL`` is never true, and queries return/affect zero rows.

FORCE ROW LEVEL SECURITY makes the policy apply even to the table owner, so there is no
owner-bypass hole; the app additionally connects as the non-superuser ``orvex_app`` role.

Revision ID: 9a00rls000001
Revises: 922b6cbf2321
Create Date: 2026-09-29
"""
from alembic import op

revision = "9a00rls000001"
down_revision = "922b6cbf2321"
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "memberships", "programs", "scope_rules", "authorizations", "scans", "scan_stages",
    "subdomains", "dns_records", "services", "tls_info", "http_endpoints", "technologies",
    "parameters", "secrets", "technology_cves", "findings", "report_exports", "audit_log",
)

APP_ROLE = "orvex_app"


def upgrade() -> None:
    # Make sure the app role can touch the tables that already exist.
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    for t in TENANT_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {t} TO {APP_ROLE}")
    # Non-tenant tables the app still needs.
    for t in ("organizations", "users", "cves"):
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {t} TO {APP_ROLE}")

    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        # NULLIF(..., '') so an unset GUC (which reverts to '' after a txn, not NULL)
        # becomes NULL rather than raising on ''::uuid — org_id = NULL matches nothing,
        # i.e. fail-closed with zero rows and no error.
        op.execute(
            f"""
            CREATE POLICY {t}_org_isolation ON {t}
            USING (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
            WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
            """
        )


def downgrade() -> None:
    for t in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {t}_org_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
