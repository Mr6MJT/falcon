"""Secret redaction — runs over ALL engine stdout/stderr before it hits DB or logs.

Policy (from the safety spec): the tool never persists or logs a full secret. We keep
a mask (first4+last4), a sha256, the detector name, and the location. This module is the
enforcement point: even if a scanner prints a live key, it is masked before storage.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# High-signal patterns. This is a redaction net, not a detector of record (trufflehog
# is), so it favours recall: better to over-mask than to leak.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[posru]_[0-9A-Za-z]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    (
        "generic_bearer",
        re.compile(r"(?i)\b(?:bearer|token|secret|api[_-]?key)\s*[:=]\s*([^\s'\"]{12,})"),
    ),
]


@dataclass(frozen=True)
class SecretRef:
    detector: str
    mask: str  # e.g. "AKIA…J7QX"
    sha256: str


def mask_value(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "…" * len(v)
    return f"{v[:4]}…{v[-4:]}"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8", "surrogatepass")).hexdigest()


def redact(text: str) -> tuple[str, list[SecretRef]]:
    """Return (redacted_text, refs). Redacted text is safe to log/store.

    Refs carry only mask + sha256 + detector — never the plaintext. Callers that need
    to store a full value must route it through the (opt-in) envelope-encryption path,
    never through logs.
    """
    refs: list[SecretRef] = []
    out = text

    def _sub(detector: str, m: re.Match[str]) -> str:
        # If the pattern has a capture group, redact that; else the whole match.
        raw = m.group(1) if m.groups() else m.group(0)
        refs.append(SecretRef(detector=detector, mask=mask_value(raw), sha256=sha256_hex(raw)))
        return m.group(0).replace(raw, f"[REDACTED:{detector}:{mask_value(raw)}]")

    for detector, pat in _PATTERNS:
        out = pat.sub(lambda m, d=detector: _sub(d, m), out)
    return out, refs
