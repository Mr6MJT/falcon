"""Token-bucket rate limiting, keyed by eTLD+1, so Orvex never DoSes a target.

The bucket is the second half of "responsible by design": scope decides *whether*
we may touch a host, the rate limiter decides *how gently*. In production the state
lives in Redis (shared across workers); this module holds the pure algorithm plus an
in-memory backend used by tests and single-process runs. A Redis backend implements
the same ``TokenBucketBackend`` protocol.

Rate profiles (SAFE is the default; NORMAL/AGGRESSIVE are opt-in and only usable when
the program's authorization record permits and stays under its ``program_rate_cap_rps``):
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class RateProfile(str, Enum):
    SAFE = "safe"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


@dataclass(frozen=True)
class RateSpec:
    """Requests/sec and burst per host for a profile. Kept deliberately conservative."""

    rps: float
    burst: int
    max_concurrency: int


PROFILES: dict[RateProfile, RateSpec] = {
    RateProfile.SAFE: RateSpec(rps=5.0, burst=10, max_concurrency=10),
    RateProfile.NORMAL: RateSpec(rps=15.0, burst=25, max_concurrency=20),
    RateProfile.AGGRESSIVE: RateSpec(rps=40.0, burst=60, max_concurrency=40),
}


def effective_spec(profile: RateProfile, program_rate_cap_rps: float | None) -> RateSpec:
    """Clamp the chosen profile to the program's contractual cap. The cap always wins."""
    spec = PROFILES[profile]
    if program_rate_cap_rps is not None and program_rate_cap_rps < spec.rps:
        return RateSpec(
            rps=program_rate_cap_rps,
            burst=max(1, int(program_rate_cap_rps * 2)),
            max_concurrency=spec.max_concurrency,
        )
    return spec


class TokenBucketBackend(Protocol):
    def take(self, key: str, rps: float, burst: int, cost: float = 1.0) -> float:
        """Return 0.0 if a token was granted, else the seconds to wait before retry."""
        ...


class InMemoryTokenBucket:
    """Thread-safe local token bucket. One-process use and tests only."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def take(self, key: str, rps: float, burst: int, cost: float = 1.0) -> float:
        with self._lock:
            now = self._clock()
            tokens, last = self._state.get(key, (float(burst), now))
            tokens = min(float(burst), tokens + (now - last) * rps)
            if tokens >= cost:
                self._state[key] = (tokens - cost, now)
                return 0.0
            deficit = cost - tokens
            self._state[key] = (tokens, now)
            return deficit / rps if rps > 0 else float("inf")


def etld1_key(host: str) -> str:
    """Bucket key: eTLD+1 so all subdomains of one org share a budget.

    Uses a real PSL (``tldextract``) when installed; otherwise a conservative
    last-two-labels fallback. The fallback over-groups (e.g. treats ``co.uk`` as the
    registrable domain), which errs toward being *gentler*, never harsher.
    """
    host = host.strip().lower().rstrip(".")
    try:
        import tldextract  # type: ignore

        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
