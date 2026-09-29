"""Event bus + throttled publisher (no DB, no network)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.events import (
    InMemoryEventBus,
    ScanEventPublisher,
    channel_for,
)


def test_bus_delivers_to_subscribers():
    bus = InMemoryEventBus()
    with bus.subscribe("c1") as q:
        bus.publish("c1", {"type": "x"})
        bus.publish("c2", {"type": "y"})  # different channel, ignored
        assert q.get_nowait() == {"type": "x"}
        assert q.empty()


def test_progress_is_throttled_but_milestones_are_not():
    bus = InMemoryEventBus()
    t = {"now": 100.0}
    pub = ScanEventPublisher(bus, "s1", min_interval=1.0, clock=lambda: t["now"])
    ch = channel_for("s1")
    with bus.subscribe(ch) as q:
        assert pub.stage_progress("dns", 1, 10) is True   # first always emits
        assert pub.stage_progress("dns", 2, 10) is False  # <1s later: dropped
        t["now"] += 1.5
        assert pub.stage_progress("dns", 5, 10) is True   # enough time passed
        # milestones bypass the throttle entirely
        pub.stage_started("dns")
        pub.stage_done("dns", {"records": 5})
        pub.scan_status("completed")
        types = []
        while not q.empty():
            types.append(q.get_nowait()["type"])
    assert types == [
        "stage.progress", "stage.progress",
        "stage.started", "stage.done", "scan.status",
    ]


def test_finding_created_only_streams_medium_and_up():
    bus = InMemoryEventBus()
    pub = ScanEventPublisher(bus, "s1")
    with bus.subscribe(channel_for("s1")) as q:
        pub.finding_created(finding_id="1", ftype="tls_issue", severity="low",
                            confidence="confirmed", title="low sev")
        assert q.empty()  # low severity is not streamed
        pub.finding_created(finding_id="2", ftype="cve_active_confirmed", severity="high",
                            confidence="confirmed", title="high sev")
        evt = q.get_nowait()
    assert evt["type"] == "finding.created"
    assert evt["severity"] == "high"
