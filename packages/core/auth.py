"""JWT auth helpers (HS256).

Tokens carry the subject (user id), the org, and the role — enough for the API to enforce
org isolation on every request and WebSocket handshake without a DB round-trip just to
authenticate. The secret comes from ORVEX_JWT_SECRET; there is no insecure default in
production (a missing secret raises).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

ALGORITHM = "HS256"


class AuthError(Exception):
    pass


def _secret() -> str:
    secret = os.environ.get("ORVEX_JWT_SECRET")
    if not secret:
        raise AuthError("ORVEX_JWT_SECRET is not set")
    return secret


@dataclass(frozen=True)
class Principal:
    user_id: str
    org_id: str
    role: str


def create_access_token(
    *, user_id: str, org_id: str, role: str,
    expires_in: timedelta = timedelta(hours=12), secret: str | None = None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_in).timestamp()),
    }
    return jwt.encode(payload, secret or _secret(), algorithm=ALGORITHM)


def decode_token(token: str, secret: str | None = None) -> Principal:
    try:
        payload = jwt.decode(token, secret or _secret(), algorithms=[ALGORITHM])
    except jwt.PyJWTError as e:
        raise AuthError(f"invalid token: {e}") from e
    try:
        return Principal(user_id=payload["sub"], org_id=payload["org"], role=payload["role"])
    except KeyError as e:
        raise AuthError(f"token missing claim: {e}") from e


def bearer_from_header(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None
