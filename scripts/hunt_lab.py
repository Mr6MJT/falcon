#!/usr/bin/env python3
"""Run Orvex against the self-hosted OWASP Juice Shop lab (authorized target only).

This drives the tool's OWN machinery — the scope guard, rate limiter, real engines, and the
honest findings classifier — against http://localhost:3000, then stores + prints findings the
way an operator triaging a scan would see them. Never point this at a third-party host.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from packages.core import guard
from packages.core.findings import finding_from_nuclei
from packages.core.models import (
    Authorization,
    AuthorizationType,
    Finding,
    HTTPEndpoint,
    Organization,
    Program,
    Scan,
    ScopeRule,
    ScopeRuleAction,
    ScopeRuleKind,
    Technology,
)
from packages.core.scope import RuleAction, RuleKind
from packages.core.scope import ScopeRule as CoreRule
from packages.core.stages import parse_tech, parse_urls

TARGET = os.environ.get("HUNT_TARGET", "http://localhost:3000")
DB = os.environ.get("ORVEX_DATABASE_URL", "postgresql+psycopg://postgres:orvex@localhost:5432/orvex")

# Scope: the lab only. allow_internal=True is the lab flag (localhost is otherwise refused).
RULES = [
    CoreRule.make(RuleKind.DOMAIN, RuleAction.INCLUDE, "localhost"),
    CoreRule.make(RuleKind.IP, RuleAction.INCLUDE, "127.0.0.1"),
]
AUDIT = []


def audit(e):
    AUDIT.append(e)


def run(tool, targets, **kw):
    return guard.run_tool(tool, targets, RULES, allow_internal=True, audit=audit, **kw)


def main() -> int:
    eng = create_engine(DB, future=True)
    s = sessionmaker(bind=eng, future=True)()
    with s.begin():
        org = Organization(name="Lab", slug=f"lab-{uuid.uuid4().hex[:6]}")
        s.add(org)
        s.flush()
        prog = Program(org_id=org.id, name="Juice Shop (lab)", slug=f"juice-{uuid.uuid4().hex[:6]}")
        s.add(prog)
        s.flush()
        for r in RULES:
            s.add(ScopeRule(org_id=org.id, program_id=prog.id,
                            kind=ScopeRuleKind(r.kind.value),
                            action=ScopeRuleAction(r.action.value), value=r.value))
        authz = Authorization(org_id=org.id, program_id=prog.id,
                              authorized_by="Self (owned lab)",
                              authorization_type=AuthorizationType.INTERNAL,
                              expires_at=datetime.now(UTC) + timedelta(days=1),
                              allows_active_testing=True, allows_automated_tools=True)
        s.add(authz)
        s.flush()
        scan = Scan(org_id=org.id, program_id=prog.id, authorization_id=authz.id,
                    scope_snapshot_hash="lab", config={"seeds": ["localhost"]})
        s.add(scan)
        s.flush()
        scan_id, org_id = scan.id, org.id

    print(f"== Orvex hunt against {TARGET} (authorized lab) ==\n")

    # 1) httpx: liveness + title + tech
    print("[*] httpx (liveness + tech)...")
    res = run("httpx", [TARGET], extra_args=["-json", "-td", "-silent", "-title", "-tech-detect"])
    print("   ", res.stdout.strip()[:300] or res.stderr.strip()[:300])
    techs = parse_tech(res.stdout)
    with s.begin():
        for url, name in techs:
            s.add(Technology(org_id=org_id, scan_id=scan_id, url=url, name=name, version=""))
    print(f"    technologies: {sorted({t for _, t in techs})}")

    # 2) katana: crawl for URLs/endpoints
    print("\n[*] katana (crawl)...")
    res = run("katana", [TARGET], extra_args=["-jc", "-silent", "-d", "2"], timeout_s=180)
    urls = parse_urls(res.stdout)
    with s.begin():
        for u in sorted(set(urls))[:200]:
            s.add(HTTPEndpoint(org_id=org_id, scan_id=scan_id, url=u))
    print(f"    crawled URLs: {len(set(urls))} (showing 8) -> {sorted(set(urls))[:8]}")

    # 3) nuclei: findings (allow-tags / deny dos,intrusive,fuzz,bruteforce)
    print("\n[*] nuclei (findings)...")
    tags = ("cve,exposures,misconfiguration,tech,ssl,takeover,"
            "panel,login,config,backup,logs,disclosure")
    res = run("nuclei", [TARGET], timeout_s=600, extra_args=[
        "-tags", tags,
        "-etags", "dos,intrusive,fuzz,fuzzing,brute-force,bruteforce",
        "-json", "-silent",
    ])
    n = 0
    with s.begin():
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            import json
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = finding_from_nuclei(obj)
            if not row:
                continue
            row["org_id"] = org_id
            row["scan_id"] = scan_id
            try:
                s.add(Finding(**row))
                n += 1
            except ValueError as e:
                print("    honesty guard blocked:", e)
    print(f"    findings stored: {n}")

    # Report
    print("\n== Findings (as an operator would triage) ==")
    rows = s.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(rows, key=lambda r: order.get(r.severity.value, 9)):
        cve = f" [{f.cve_id}]" if f.cve_id else ""
        print(f"  {f.severity.value.upper():8} {f.confidence.value:9} "
              f"{f.type:24} {f.title[:60]}{cve}")
    print(f"\n  total findings: {len(rows)}")
    print(f"  audit events: {len(AUDIT)} (scope checks, rate waits, spawns)")
    print(f"\n  scan_id={scan_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
