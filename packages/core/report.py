"""Report generation — assemble a scan into HTML (house style), PDF, and JSON.

The report is built from the DB (findings + asset summaries) and is honest by construction:
confirmed and candidate findings are separated, candidates carry a "manual review" caveat, and
secrets appear only as masks. PDF is rendered from the same HTML via WeasyPrint (pure-Python,
no headless browser / subprocess), so it never touches the exec choke point.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    Finding,
    HTTPEndpoint,
    Parameter,
    Program,
    Scan,
    Secret,
    Service,
    Subdomain,
    Technology,
    TLSInfo,
)

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#b91c1c", "high": "#c2410c", "medium": "#b45309",
    "low": "#0369a1", "info": "#475569",
}


def build_report(session: Session, scan_id) -> dict[str, Any] | None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        return None
    program = session.get(Program, scan.program_id)

    def _count(model) -> int:
        return session.execute(
            select(func.count()).select_from(model).where(model.scan_id == scan_id)
        ).scalar() or 0

    findings = session.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    ).scalars().all()

    by_sev: dict[str, int] = {s: 0 for s in SEV_ORDER}
    by_conf: dict[str, int] = {"confirmed": 0, "candidate": 0, "informational": 0}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_conf[f.confidence.value] = by_conf.get(f.confidence.value, 0) + 1

    def _finding(f: Finding) -> dict:
        return {
            "type": f.type, "title": f.title, "severity": f.severity.value,
            "confidence": f.confidence.value, "status": f.status.value,
            "cvss": f.cvss, "cve_id": f.cve_id, "cwe": f.cwe, "target": f.target,
            "evidence": f.evidence or {},
        }

    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    findings_sorted = sorted(findings, key=lambda f: rank.get(f.severity.value, 9))

    subs = session.execute(
        select(Subdomain.hostname, Subdomain.in_scope)
        .where(Subdomain.scan_id == scan_id).limit(1000)
    ).all()
    services = session.execute(
        select(Service.ip, Service.port, Service.service_name, Service.product, Service.version)
        .where(Service.scan_id == scan_id).limit(1000)
    ).all()
    techs = session.execute(
        select(Technology.name, Technology.version).where(Technology.scan_id == scan_id)
        .distinct().limit(1000)
    ).all()
    secrets = session.execute(
        select(Secret.detector, Secret.redacted_match, Secret.location, Secret.verified)
        .where(Secret.scan_id == scan_id).limit(1000)
    ).all()

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "scan": {
            "id": str(scan.id),
            "program": program.name if program else None,
            "platform": program.platform if program else None,
            "status": scan.status.value,
            "aggressiveness": scan.aggressiveness.value,
            "scan_mode": scan.scan_mode,
            "scope_snapshot_hash": scan.scope_snapshot_hash,
            "seeds": (scan.config or {}).get("seeds", []),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        },
        "summary": {
            "findings_total": len(findings),
            "by_severity": by_sev,
            "by_confidence": by_conf,
            "assets": {
                "subdomains": _count(Subdomain), "services": _count(Service),
                "http_endpoints": _count(HTTPEndpoint), "tls": _count(TLSInfo),
                "technologies": _count(Technology), "parameters": _count(Parameter),
                "secrets": _count(Secret),
            },
        },
        "findings": [_finding(f) for f in findings_sorted],
        "assets": {
            "subdomains": [{"hostname": h, "in_scope": bool(i)} for h, i in subs],
            "services": [
                {"ip": str(ip), "port": p, "service": sn, "product": pr, "version": v}
                for ip, p, sn, pr, v in services
            ],
            "technologies": [{"name": n, "version": v} for n, v in techs],
            "secrets": [
                {"detector": d, "mask": m, "location": loc, "verified": bool(ver)}
                for d, m, loc, ver in secrets
            ],
        },
    }


def render_json(report: dict) -> str:
    import json
    return json.dumps(report, indent=2, default=str)


def _sev_pill(sev: str) -> str:
    return (f'<span class="pill" style="background:{SEV_COLOR.get(sev, "#475569")}">'
            f'{escape(sev.upper())}</span>')


def render_html(report: dict) -> str:
    scan = report["scan"]
    summ = report["summary"]
    sev_cells = "".join(
        f'<div class="stat"><div class="num" style="color:{SEV_COLOR[s]}">'
        f'{summ["by_severity"].get(s, 0)}</div><div class="lbl">{s}</div></div>'
        for s in SEV_ORDER
    )
    asset_cells = "".join(
        f'<div class="stat"><div class="num">{v}</div><div class="lbl">{escape(k)}</div></div>'
        for k, v in summ["assets"].items()
    )

    def finding_block(f: dict) -> str:
        cand = f["confidence"] == "candidate"
        meta = []
        if f.get("cve_id"):
            meta.append(f'CVE: {escape(str(f["cve_id"]))}')
        if f.get("cvss") is not None:
            meta.append(f'CVSS: {escape(str(f["cvss"]))}')
        if f.get("cwe"):
            meta.append(f'CWE: {escape(str(f["cwe"]))}')
        if f.get("target"):
            meta.append(f'Target: {escape(str(f["target"]))}')
        ev = f.get("evidence") or {}
        ev_html = ""
        for key in ("request", "response"):
            if ev.get(key):
                ev_html += (f'<div class="evlabel">{key}</div>'
                            f'<pre>{escape(str(ev[key])[:2000])}</pre>')
        caveat = ('<div class="caveat">Candidate — requires manual verification. '
                  'Not a confirmed vulnerability.</div>' if cand else "")
        return (
            f'<div class="finding {"candidate" if cand else "confirmed"}">'
            f'<div class="fhead">{_sev_pill(f["severity"])}'
            f'<span class="conf {"c-cand" if cand else "c-conf"}">{escape(f["confidence"])}</span>'
            f'<span class="ftype">{escape(f["type"])}</span>'
            f'<span class="fstatus">{escape(f["status"])}</span></div>'
            f'<div class="ftitle">{escape(f["title"])}</div>'
            f'<div class="fmeta">{" &middot; ".join(meta)}</div>'
            f'{caveat}{ev_html}</div>'
        )

    findings_html = "".join(finding_block(f) for f in report["findings"]) or \
        '<p class="muted">No findings recorded for this scan.</p>'

    tech_rows = "".join(
        f'<tr><td>{escape(t["name"])}</td><td>{escape(t.get("version") or "")}</td></tr>'
        for t in report["assets"]["technologies"][:50]
    )
    secret_rows = "".join(
        f'<tr><td>{escape(s["detector"])}</td><td class="mono">{escape(s["mask"])}</td>'
        f'<td>{escape(s["location"])}</td><td>{"yes" if s["verified"] else "no"}</td></tr>'
        for s in report["assets"]["secrets"][:100]
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Orvex Report — {escape(scan.get("program") or scan["id"])}</title>
<style>
  @page {{ size: A4; margin: 18mm 14mm; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 13px/1.5 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         color: #0f172a; background: #fff; margin: 0; padding: 24px; }}
  h1 {{ font-size: 22px; margin: 0 0 2px; }}
  h2 {{ font-size: 15px; margin: 28px 0 10px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }}
  .sub {{ color: #64748b; font-size: 12px; }}
  .grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin: 10px 0; }}
  .grid.assets {{ grid-template-columns: repeat(7, 1fr); }}
  .stat {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px; text-align: center; }}
  .num {{ font-size: 20px; font-weight: 700; }}
  .lbl {{ font-size: 10px; text-transform: uppercase; color: #64748b; letter-spacing: .04em; }}
  .pill {{ color: #fff; font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px; }}
  .finding {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 12px; margin: 8px 0;
             page-break-inside: avoid; }}
  .finding.candidate {{ border-style: dashed; }}
  .fhead {{ display: flex; align-items: center; gap: 8px; }}
  .conf {{ font-size: 10px; text-transform: uppercase; padding: 1px 6px; border-radius: 4px; }}
  .c-conf {{ background: #dcfce7; color: #166534; }}
  .c-cand {{ background: #fff7ed; color: #9a3412; border: 1px dashed #fdba74; }}
  .ftype {{ font-family: ui-monospace, monospace; font-size: 11px; color: #475569; }}
  .fstatus {{ margin-left: auto; font-size: 11px; color: #64748b; }}
  .ftitle {{ font-weight: 600; margin: 6px 0 2px; }}
  .fmeta {{ font-size: 11px; color: #64748b; }}
  .caveat {{ background: #fff7ed; color: #9a3412; font-size: 11px; padding: 5px 8px;
            border-radius: 6px; margin: 6px 0; }}
  .evlabel {{ font-size: 10px; text-transform: uppercase; color: #64748b; margin-top: 6px; }}
  pre {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px;
        font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th, td {{ text-align: left; padding: 5px 8px; border-bottom: 1px solid #eef2f7; }}
  .mono {{ font-family: ui-monospace, monospace; }}
  .muted {{ color: #94a3b8; }}
  .foot {{ margin-top: 28px; padding-top: 10px; border-top: 1px solid #e2e8f0;
          font-size: 10px; color: #94a3b8; }}
</style></head>
<body>
  <h1>Orvex Recon — Scan Report</h1>
  <div class="sub">{escape(scan.get("program") or "")} &middot; {escape(scan.get("platform") or "internal")}
    &middot; status: {escape(scan["status"])} &middot; generated {escape(report["generated_at"][:19])}</div>

  <h2>Summary</h2>
  <div class="grid">{sev_cells}</div>
  <div class="grid assets">{asset_cells}</div>
  <div class="sub">Findings by confidence — confirmed: {summ["by_confidence"].get("confirmed", 0)},
    candidate: {summ["by_confidence"].get("candidate", 0)},
    informational: {summ["by_confidence"].get("informational", 0)}.
    Candidates require manual verification before submission.</div>

  <h2>Scope &amp; authorization</h2>
  <div class="sub">Seeds: {escape(", ".join(scan.get("seeds") or []) or "—")}<br>
    Scope snapshot: <span class="mono">{escape(str(scan.get("scope_snapshot_hash") or "—"))}</span><br>
    Mode: {escape(scan.get("scan_mode") or "")} &middot; aggressiveness: {escape(scan.get("aggressiveness") or "")}</div>

  <h2>Findings ({summ["findings_total"]})</h2>
  {findings_html}

  <h2>Technologies</h2>
  <table><thead><tr><th>Name</th><th>Version</th></tr></thead><tbody>{tech_rows or '<tr><td class="muted" colspan=2>none</td></tr>'}</tbody></table>

  <h2>Secrets (masked)</h2>
  <table><thead><tr><th>Detector</th><th>Mask</th><th>Location</th><th>Verified</th></tr></thead>
    <tbody>{secret_rows or '<tr><td class="muted" colspan=4>none</td></tr>'}</tbody></table>

  <div class="foot">Generated by Orvex Recon for authorized testing only. This report may
    contain heuristic "candidate" findings that are not confirmed vulnerabilities; verify
    manually and follow the program's disclosure rules before submission.</div>
</body></html>"""


def render_pdf(html: str) -> bytes:
    """Render report HTML to PDF via WeasyPrint (no subprocess / headless browser)."""
    import weasyprint
    return weasyprint.HTML(string=html).write_pdf()
