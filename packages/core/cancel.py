"""Cooperative cancellation flag.

Production backs this with Redis key ``cancel:<scan_id>`` (set by the kill-switch, polled
by stages between chunks). Tests use the in-memory implementation. The guard's subprocess
wrapper handles hard termination (SIGTERM/SIGKILL of the process group); this flag is the
soft, cooperative layer that stops a stage from starting the next chunk or the next stage.
"""

from __future__ import annotations

from typing import Protocol


class CancelFlag(Protocol):
    def is_set(self, scan_id) -> bool: ...
    def set(self, scan_id) -> None: ...
    def clear(self, scan_id) -> None: ...


class InMemoryCancelFlag:
    def __init__(self) -> None:
        self._flags: set[str] = set()

    def is_set(self, scan_id) -> bool:
        return str(scan_id) in self._flags

    def set(self, scan_id) -> None:
        self._flags.add(str(scan_id))

    def clear(self, scan_id) -> None:
        self._flags.discard(str(scan_id))


class RedisCancelFlag:
    """Redis-backed flag. TTL so a stale flag self-clears after the max run duration."""

    def __init__(self, redis, ttl_seconds: int = 6 * 3600) -> None:
        self._r = redis
        self._ttl = ttl_seconds

    def _key(self, scan_id) -> str:
        return f"cancel:{scan_id}"

    def is_set(self, scan_id) -> bool:
        return bool(self._r.exists(self._key(scan_id)))

    def set(self, scan_id) -> None:
        self._r.set(self._key(scan_id), "1", ex=self._ttl)

    def clear(self, scan_id) -> None:
        self._r.delete(self._key(scan_id))
