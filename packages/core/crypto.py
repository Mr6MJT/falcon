"""Envelope encryption for optional full-secret retention (AES-256-GCM).

Default policy is to NOT retain full secret values (store mask + sha256 only). When an
engagement opts in, the full value is encrypted here with a key from the environment
(``ORVEX_SECRET_KEY``, base64 of 32 bytes) and stored as ciphertext, to be auto-purged at
engagement end. The plaintext is never written to logs and only ever held transiently.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12


class CryptoError(Exception):
    pass


def _load_key(key_b64: str | None) -> bytes:
    raw = key_b64 or os.environ.get("ORVEX_SECRET_KEY")
    if not raw:
        raise CryptoError("ORVEX_SECRET_KEY is not set")
    try:
        key = base64.b64decode(raw)
    except Exception as e:
        raise CryptoError("ORVEX_SECRET_KEY is not valid base64") from e
    if len(key) != 32:
        raise CryptoError("ORVEX_SECRET_KEY must decode to 32 bytes (AES-256)")
    return key


def generate_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def encrypt(plaintext: str, key_b64: str | None = None) -> bytes:
    """Return nonce || ciphertext(+tag). Safe to store; useless without the key."""
    key = _load_key(key_b64)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt(blob: bytes, key_b64: str | None = None) -> str:
    key = _load_key(key_b64)
    if len(blob) <= _NONCE_LEN:
        raise CryptoError("ciphertext too short")
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
