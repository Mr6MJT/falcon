#!/usr/bin/env python3
"""Dev-only: seed a program + authorization + a scan, and print a JWT + scan_id.

For local end-to-end demos only. Uses the lab-safe example.com scope. Prints an operator
token for the seeded org so the web client can authenticate.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from packages.core.auth import create_access_token
from packages.core.gate1 import create_scan
from packages.core.models import (
    Aggressiveness,
    Authorization,
    AuthorizationType,
    Organization,
    Program,
    ScopeRule,
    ScopeRuleAction,
    ScopeRuleKind,
)


def main() -> int:
    url = os.environ["ORVEX_DATABASE_URL"]
    secret = os.environ["ORVEX_JWT_SECRET"]
    eng = create_engine(url, future=True)
    s = sessionmaker(bind=eng, future=True)()
    with s.begin():
        org = s.execute(
            select(Organization).where(Organization.slug == "orvex")
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="Orvex", slug="orvex")
            s.add(org)
            s.flush()
        prog = Program(org_id=org.id, name="Demo Program", slug=f"demo-{uuid.uuid4().hex[:6]}")
        s.add(prog)
        s.flush()
        s.add_all([
            ScopeRule(org_id=org.id, program_id=prog.id, kind=ScopeRuleKind.DOMAIN,
                      action=ScopeRuleAction.INCLUDE, value="example.com"),
            ScopeRule(org_id=org.id, program_id=prog.id, kind=ScopeRuleKind.WILDCARD,
                      action=ScopeRuleAction.INCLUDE, value="example.com"),
        ])
        s.add(Authorization(
            org_id=org.id, program_id=prog.id, authorized_by="Demo Security Team",
            authorization_type=AuthorizationType.BUG_BOUNTY,
            expires_at=datetime.now(UTC) + timedelta(days=90),
            allows_active_testing=True, allows_automated_tools=True,
        ))
        s.flush()
        scan = create_scan(s, org_id=org.id, program_id=prog.id,
                           seeds=["example.com"], aggressiveness=Aggressiveness.SAFE)
        token = create_access_token(user_id=str(uuid.uuid4()), org_id=str(org.id),
                                    role="operator", secret=secret)
        print(f"SCAN_ID={scan.id}")
        print(f"ORG_ID={org.id}")
        print(f"TOKEN={token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
