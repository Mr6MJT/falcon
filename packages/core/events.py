"""Live-progress event bus + the throttled per-scan publisher.

Transport: Redis pub/sub in production (worker publishes, API subscribes across processes);
an in-memory, thread-safe bus for single-process runs and tests. Both expose the same
sync ``publish`` and a ``subscribe`` context manager yielding a queue the WebSocket drains.

What is streamed (deltas) is deliberately lossy + small: throttled stage progress (<=1/s per
stage), stage/scan milestones, and ``finding.created`` for severity >= medium. Detailed
rows (thousands of URLs) are NEVER streamed — clients page them over REST. Correctness on
reconnect comes from the authoritative snapshot (see snapshot.py), not from perfect
delivery, so dropping a throttled delta is always safe.
"""

from __future__ import annotations

import contextlib
import queue
import time
from collections import defaultdict
from collections.abc import Iterator
from typing import Any, Protocol

# Severity levels that are important enough to push as a live finding delta.
_STREAM_SEVERITIES = frozenset({"medium", "high", "critical"})


def channel_for(scan_id) -> str:
    return f"scan:{scan_id}:events"


class EventBus(Protocol):
    def publish(self, channel: str, event: dict[str, Any]) -> None: ...
    def subscribe(self, channel: str) -> contextlib.AbstractContextManager: ...


class InMemoryEventBus:
    """Thread-safe fanout. Each subscriber gets its own unbounded queue."""

    def __init__(self) -> None:
        self._subs: dict[str, set[queue.Queue]] = defaultdict(set)

    def publish(self, channel: str, event: dict[str, Any]) -> None:
        for q in list(self._subs.get(channel, ())):
            q.put_nowait(event)

    @contextlib.contextmanager
    def subscribe(self, channel: str) -> Iterator[queue.Queue]:
        q: queue.Queue = queue.Queue()
        self._subs[channel].add(q)
        try:
            yield q
        finally:
            self._subs[channel].discard(q)


class RedisEventBus:
    """Redis pub/sub transport. JSON-encodes events on the wire."""

    def __init__(self, redis) -> None:
        self._r = redis

    def publish(self, channel: str, event: dict[str, Any]) -> None:
        import json

        self._r.publish(channel, json.dumps(event, default=str))

    @contextlib.contextmanager
    def subscribe(self, channel: str) -> Iterator[queue.Queue]:
        import json
        import threading

        q: queue.Queue = queue.Queue()
        pubsub = self._r.pubsub()
        pubsub.subscribe(channel)
        stop = threading.Event()

        def _pump() -> None:
            try:
                for msg in pubsub.listen():
                    if stop.is_set():
                        break
                    if msg.get("type") == "message":
                        with contextlib.suppress(Exception):
                            q.put_nowait(json.loads(msg["data"]))
            except Exception:
                # Expected when the subscription is torn down (socket closed on WS close).
                return

        t = threading.Thread(target=_pump, daemon=True)
        t.start()
        try:
            yield q
        finally:
            stop.set()
            with contextlib.suppress(Exception):
                pubsub.close()


class ScanEventPublisher:
    """Emits scan events, throttling per-stage progress to <=1 per ``min_interval`` seconds.

    Milestones (stage started/done, scan status, findings) are never throttled.
    """

    def __init__(self, bus: EventBus, scan_id, *, min_interval: float = 1.0,
                 clock=time.monotonic) -> None:
        self._bus = bus
        self._scan_id = scan_id
        self._channel = channel_for(scan_id)
        self._min_interval = min_interval
        self._clock = clock
        self._last_progress: dict[str, float] = {}

    def _emit(self, event: dict[str, Any]) -> None:
        event.setdefault("scan_id", str(self._scan_id))
        event.setdefault("ts", time.time())
        self._bus.publish(self._channel, event)

    def stage_started(self, stage: str) -> None:
        self._emit({"type": "stage.started", "stage": stage})

    def stage_progress(self, stage: str, done: int, total: int) -> bool:
        """Throttled. Returns True if the delta was emitted, False if dropped."""
        now = self._clock()
        last = self._last_progress.get(stage)
        if last is not None and (now - last) < self._min_interval:
            return False
        self._last_progress[stage] = now
        self._emit({"type": "stage.progress", "stage": stage, "done": done, "total": total})
        return True

    def stage_done(self, stage: str, stats: dict | None = None) -> None:
        self._emit({"type": "stage.done", "stage": stage, "stats": stats or {}})

    def scan_status(self, status: str) -> None:
        self._emit({"type": "scan.status", "status": status})

    def finding_created(self, *, finding_id, ftype: str, severity: str,
                        confidence: str, title: str) -> None:
        # Only stream findings at or above medium severity; the rest are paged over REST.
        if str(severity).lower() not in _STREAM_SEVERITIES:
            return
        self._emit({
            "type": "finding.created", "finding_id": str(finding_id),
            "finding_type": ftype, "severity": severity,
            "confidence": confidence, "title": title,
        })


class NullPublisher:
    """No-op publisher for runs that don't need live events (e.g. some tests)."""

    def stage_started(self, *a, **k): ...
    def stage_progress(self, *a, **k): return False
    def stage_done(self, *a, **k): ...
    def scan_status(self, *a, **k): ...
    def finding_created(self, *a, **k): ...
