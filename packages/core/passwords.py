"""Password hashing/verification (PBKDF2-SHA256), matching scripts/seed.py's stored format.

Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<dk_hex>``. Slice 6 can swap in argon2; the
namespaced prefix lets stored hashes be migrated.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 200_000


def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, dk_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
    except ValueError:
        return False
    return hmac.compare_digest(dk.hex(), dk_hex)
