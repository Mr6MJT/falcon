#!/usr/bin/env python3
"""Seed the single Orvex org and its first admin (invite-based; no public signup).

Idempotent: safe to run repeatedly. The admin password is read from ORVEX_ADMIN_PASSWORD
(or generated and printed once). Password hashing here is stdlib PBKDF2 as a placeholder;
slice 6 swaps in the app's real hasher (argon2) — the stored format is namespaced so it
can be migrated.

Usage:
  ORVEX_DATABASE_URL=... ORVEX_ADMIN_EMAIL=admin@orvex.local python scripts/seed.py
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def main() -> int:
    url = os.environ.get(
        "ORVEX_DATABASE_URL",
        "postgresql+psycopg://postgres:orvex@localhost:55432/orvex",
    )
    org_name = os.environ.get("ORVEX_ORG_NAME", "Orvex")
    org_slug = os.environ.get("ORVEX_ORG_SLUG", "orvex")
    admin_email = os.environ.get("ORVEX_ADMIN_EMAIL", "admin@orvex.local")
    password = os.environ.get("ORVEX_ADMIN_PASSWORD")
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True

    eng = create_engine(url, future=True)
    with eng.begin() as c:
        org_id = c.execute(
            text("SELECT id FROM organizations WHERE slug=:s"), {"s": org_slug}
        ).scalar()
        if not org_id:
            org_id = uuid.uuid4()
            c.execute(
                text("INSERT INTO organizations (id,name,slug) VALUES (:i,:n,:s)"),
                {"i": org_id, "n": org_name, "s": org_slug},
            )
            print(f"created org {org_slug} ({org_id})")
        else:
            print(f"org {org_slug} already exists ({org_id})")

        user_id = c.execute(
            text("SELECT id FROM users WHERE email=:e"), {"e": admin_email}
        ).scalar()
        if not user_id:
            user_id = uuid.uuid4()
            c.execute(
                text("INSERT INTO users (id,email,full_name,password_hash,is_active) "
                     "VALUES (:i,:e,:f,:p,true)"),
                {"i": user_id, "e": admin_email, "f": "Admin", "p": hash_password(password)},
            )
            print(f"created admin user {admin_email} ({user_id})")
            if generated:
                print(f"\n  GENERATED ADMIN PASSWORD (shown once): {password}\n")
        else:
            print(f"admin user {admin_email} already exists ({user_id})")

        exists = c.execute(
            text("SELECT 1 FROM memberships WHERE org_id=:o AND user_id=:u"),
            {"o": org_id, "u": user_id},
        ).scalar()
        if not exists:
            c.execute(
                text("INSERT INTO memberships (id,org_id,user_id,role) "
                     "VALUES (:i,:o,:u,'admin')"),
                {"i": uuid.uuid4(), "o": org_id, "u": user_id},
            )
            print("granted admin membership")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
