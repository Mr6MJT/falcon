#!/usr/bin/env python3
"""Dev-only: run the passive pipeline for a scan, publishing live events to Redis.

Simulates the engines with canned output (no real binaries), but drives the REAL pipeline
and publishes REAL events through the Redis bus — so a browser watching the scan view sees
live stage progress. Small sleeps make the progression visible.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis as _redis
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from packages.core.events import RedisEventBus, ScanEventPublisher
from packages.core.gate1 import compile_scope
from packages.core.guard import ToolResult
from packages.core.models import Scan, ScopeRule
from packages.core.orchestrator import run_pipeline_inline
from packages.core.stages import StageContext

CANNED = {
    "subfinder": "www.example.com\napi.example.com\nblog.example.com\n",
    "dnsx": ('{"host":"www.example.com","a":["93.184.216.34"]}\n'
             '{"host":"api.example.com","a":["93.184.216.35"]}\n'
             '{"host":"blog.example.com","a":["93.184.216.36"]}\n'),
    "httpx": ('{"url":"https://www.example.com","status_code":200,"title":"Home","content_length":120}\n'
              '{"url":"https://api.example.com","status_code":403,"title":"","content_length":9}\n'
              '{"url":"https://blog.example.com","status_code":200,"title":"Blog","content_length":88}\n'),
    "httpx_tech": ('{"url":"https://www.example.com","tech":["Nginx","React"]}\n'
                   '{"url":"https://blog.example.com","tech":["WordPress","PHP"]}\n'),
    "tlsx": ('{"host":"www.example.com","port":"443","tls_version":"tls1.2","issuer_dn":"CN=R3"}\n'
             '{"host":"api.example.com","port":"443","tls_version":"tls1.0","issuer_dn":"CN=R3"}\n'),
    "wafw00f": '[{"url":"https://www.example.com","detected":true,"firewall":"Cloudflare"}]',
    "nuclei": (
        '{"template-id":"git-config","info":{"name":"Git Config Exposure","severity":"high",'
        '"tags":["exposure","config"]},"matched-at":"https://www.example.com/.git/config"}\n'
        '{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical",'
        '"tags":["cve"],"classification":{"cve-id":["CVE-2021-1234"],"cvss-score":9.8}},'
        '"matched-at":"https://api.example.com/"}\n'
    ),
}


def main() -> int:
    scan_id = os.environ["SCAN_ID"]
    url = os.environ["ORVEX_DATABASE_URL"]
    r = _redis.Redis.from_url(os.environ["ORVEX_REDIS_URL"])
    bus = RedisEventBus(r)

    eng = create_engine(url, future=True)
    s = sessionmaker(bind=eng, future=True)()

    def runner(tool, targets, **kw):
        time.sleep(1.5)  # make progress visible in the UI
        # The tech stage calls httpx with -td; return tech output in that case.
        key = tool
        if tool == "httpx" and "-td" in (kw.get("extra_args") or []):
            key = "httpx_tech"
        return ToolResult(ok=True, returncode=0, stdout=CANNED.get(key, ""),
                          stderr="", in_scope_targets=list(targets))

    with s.begin():
        scan = s.get(Scan, scan_id)
        rows = s.execute(
            select(ScopeRule).where(ScopeRule.program_id == scan.program_id)
        ).scalars().all()
        ctx = StageContext(
            session=s, scan=scan, scope_rules=compile_scope(rows),
            roots=scan.config.get("seeds", []), run=runner,
            publisher=ScanEventPublisher(bus, scan_id, min_interval=0.0),
        )
        run_pipeline_inline(s, ctx)
    print("pipeline finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
