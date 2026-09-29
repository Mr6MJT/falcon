"""Authoritative scan-state snapshot.

The client GETs this on every (re)connect, then subscribes to deltas. Because the snapshot
is the source of truth and is cheap to recompute, a reconnecting client always reconciles
correctly even if it missed throttled deltas while disconnected.

Only summary counts are included — never the detailed rows (URLs, params, etc.), which are
paged over REST. Keeps the payload small and the WebSocket a control/progress channel.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    Finding,
    HTTPEndpoint,
    Parameter,
    Scan,
    ScanStage,
    Secret,
    Service,
    Subdomain,
    Technology,
    TLSInfo,
)


def build_snapshot(session: Session, scan_id) -> dict[str, Any] | None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        return None

    stages = session.execute(
        select(ScanStage).where(ScanStage.scan_id == scan_id)
    ).scalars().all()

    def _count(model) -> int:
        return session.execute(
            select(func.count()).select_from(model).where(model.scan_id == scan_id)
        ).scalar() or 0

    # Findings summary by severity (small, useful for the header/severity scale).
    sev_rows = session.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    ).all()
    findings_by_severity = {str(sev.value if hasattr(sev, "value") else sev): n
                            for sev, n in sev_rows}

    return {
        "type": "snapshot",
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "aggressiveness": scan.aggressiveness.value,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "stages": [
            {"name": s.name, "status": s.status.value, "done": s.done, "total": s.total,
             "error": s.error}
            for s in sorted(stages, key=lambda r: r.name)
        ],
        "counts": {
            "subdomains": _count(Subdomain),
            "services": _count(Service),
            "http_endpoints": _count(HTTPEndpoint),
            "tls": _count(TLSInfo),
            "technologies": _count(Technology),
            "parameters": _count(Parameter),
            "secrets": _count(Secret),
            "findings": _count(Finding),
        },
        "findings_by_severity": findings_by_severity,
    }
