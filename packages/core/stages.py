"""Passive-recon stage implementations: subdomains -> dns -> httpx.

Each stage:
  * runs its engine through ``guard.run_tool`` (scope + rate + redaction happen there),
  * re-validates every discovered asset against the frozen scope (Gate 2) before it is
    used as input to a later stage — out-of-scope assets are stored but flagged
    ``in_scope=False`` ("Discovered, not tested") and never fed onward,
  * upserts results idempotently (ON CONFLICT), so a re-run produces no duplicates,
  * checks a cooperative cancel flag between chunks.

Parsing targets the tools' JSON/line output; tests feed matching canned output through an
injected runner, so no real binary or network is needed to exercise the logic.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from .events import NullPublisher
from .findings import SEVERITY_CVSS, finding_from_nuclei, make_dedup_key, severity_from
from .guard import ToolResult, run_tool
from .models import (
    CVE,
    Confidence,
    DNSRecord,
    Finding,
    HTTPEndpoint,
    Parameter,
    Secret,
    Service,
    Subdomain,
    Technology,
    TLSInfo,
)
from .ratelimit import RateProfile
from .redact import redact
from .scope import ScopeRule, is_in_scope


class Cancelled(RuntimeError):
    """Raised inside a stage when the scan's cancel flag is set."""


@dataclass
class StageContext:
    session: Session
    scan: object  # models.Scan (avoid import cycle at type level)
    scope_rules: list[ScopeRule]
    roots: list[str]  # program seed/root domains
    run: Callable[..., ToolResult] | None = None  # injectable; defaults to a guard runner
    profile: RateProfile = RateProfile.SAFE
    allow_internal: bool = False
    is_cancelled: Callable[[], bool] = field(default=lambda: False)
    audit: Callable[[dict], None] = field(default=lambda e: None)
    publisher: object = field(default_factory=NullPublisher)  # events.ScanEventPublisher

    def runner(self):
        if self.run is not None:
            return self.run

        def _default(tool: str, targets: list[str], **extra) -> ToolResult:
            return run_tool(
                tool, targets, self.scope_rules,
                profile=self.profile, allow_internal=self.allow_internal,
                audit=self.audit, **extra,
            )

        return _default

    def check_cancel(self) -> None:
        if self.is_cancelled():
            raise Cancelled(f"scan {getattr(self.scan, 'id', '?')} cancelled")


def chunked(seq: Iterable[str], size: int) -> Iterator[list[str]]:
    buf: list[str] = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


# --------------------------------------------------------------------------- parsers
def parse_subfinder(stdout: str) -> list[str]:
    """subfinder -silent: one hostname per line."""
    out: list[str] = []
    for line in stdout.splitlines():
        h = line.strip().lower()
        if h and " " not in h and "." in h:
            out.append(h)
    return out


def parse_dnsx(stdout: str) -> list[tuple[str, str, str]]:
    """dnsx -json: {"host","a":[],"aaaa":[],"cname":[]} -> (host, rtype, value) tuples."""
    records: list[tuple[str, str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (obj.get("host") or "").strip().lower()
        if not host:
            continue
        for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname")):
            for val in obj.get(key, []) or []:
                records.append((host, rtype, str(val).strip().lower()))
    return records


def parse_httpx(stdout: str) -> list[dict]:
    """httpx -json: one JSON object per probed URL."""
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _jsonl(stdout: str) -> list[dict]:
    rows: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def parse_naabu(stdout: str) -> list[tuple[str, int, str | None]]:
    """naabu -json: {"ip","port","host"} -> (ip, port, host)."""
    out: list[tuple[str, int, str | None]] = []
    for obj in _jsonl(stdout):
        ip = (obj.get("ip") or "").strip()
        port = obj.get("port")
        if ip and isinstance(port, int):
            out.append((ip, port, obj.get("host")))
    return out


def parse_tlsx(stdout: str) -> list[dict]:
    """tlsx -json: TLS metadata per host:port."""
    return _jsonl(stdout)


def parse_wafw00f(stdout: str) -> list[dict]:
    """wafw00f -f json: a JSON array of {url, detected, firewall, ...}."""
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return _jsonl(stdout)  # tolerate JSONL too
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)]


def parse_tech(stdout: str) -> list[tuple[str, str]]:
    """httpx -td -json: {"url","tech":[...]} -> (url, tech_name)."""
    out: list[tuple[str, str]] = []
    for obj in _jsonl(stdout):
        url = (obj.get("url") or "").strip()
        for name in obj.get("tech", []) or []:
            if url and name:
                out.append((url, str(name)))
    return out


def parse_urls(stdout: str) -> list[str]:
    """katana/gau: one URL per line (katana can also emit JSON with an 'endpoint' field)."""
    out: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                url = obj.get("endpoint") or obj.get("url") or ""
            except json.JSONDecodeError:
                url = ""
        else:
            url = line
        url = url.strip()
        if url.startswith(("http://", "https://")):
            out.append(url)
    return out


def params_from_url(url: str) -> list[tuple[str, str]]:
    """Extract (name, 'query') pairs from a URL's query string."""
    try:
        q = urlparse(url).query
    except ValueError:
        return []
    return [(name, "query") for name, _ in parse_qsl(q, keep_blank_values=True)]


def parse_trufflehog(stdout: str) -> list[dict]:
    """trufflehog --json: one finding per line.

    Fields used: DetectorName, Raw (the secret), Verified, SourceMetadata (location).
    The Raw value is handled transiently to compute a mask + sha256 and is never stored
    or logged in the clear.
    """
    out: list[dict] = []
    for obj in _jsonl(stdout):
        raw = obj.get("Raw") or obj.get("raw") or ""
        if not raw:
            continue
        detector = obj.get("DetectorName") or obj.get("detector_name") or "unknown"
        verified = bool(obj.get("Verified") or obj.get("verified"))
        # Best-effort location out of trufflehog's nested SourceMetadata.
        location = ""
        meta = obj.get("SourceMetadata") or {}
        data = meta.get("Data") if isinstance(meta, dict) else None
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, dict):
                    location = v.get("link") or v.get("file") or v.get("uri") or location
        out.append({"detector": str(detector), "raw": str(raw),
                    "verified": verified, "location": location or "unknown"})
    return out


# --------------------------------------------------------------------------- upserts
def _upsert(session: Session, model, rows: list[dict], index_elements: list[str],
            update_cols: list[str] | None) -> int:
    if not rows:
        return 0
    stmt = pg_insert(model).values(rows)
    if update_cols:
        stmt = stmt.on_conflict_do_update(
            index_elements=index_elements,
            set_={c: getattr(stmt.excluded, c) for c in update_cols},
        )
    else:
        stmt = stmt.on_conflict_do_nothing(index_elements=index_elements)
    session.execute(stmt)
    return len(rows)


# --------------------------------------------------------------------------- stages
def run_subdomains(ctx: StageContext) -> dict:
    """subfinder over the program roots -> upsert Subdomain rows (Gate-2 scope re-check)."""
    ctx.check_cancel()
    run = ctx.runner()
    # Only enumerate roots that are themselves in scope.
    extra = ["-silent"]
    # Optional provider API keys (SecurityTrails, Shodan, VirusTotal, GitHub, …) dramatically
    # widen passive discovery. Point ORVEX_SUBFINDER_CONFIG at a provider-config.yaml to enable
    # them and use every configured source; without it subfinder still uses the free sources.
    pc = os.environ.get("ORVEX_SUBFINDER_CONFIG")
    if pc:
        extra += ["-pc", pc, "-all"]
    res = run("subfinder", ctx.roots, extra_args=extra)
    hosts = parse_subfinder(res.stdout)
    # Always include the roots themselves as discovered hosts.
    hosts = sorted(set(hosts) | {h.lower() for h in ctx.roots})

    rows = []
    in_scope_count = 0
    for h in hosts:
        decision = is_in_scope(h, ctx.scope_rules, allow_internal=ctx.allow_internal)
        if not decision.allowed:
            ctx.audit({"event": "discovered_out_of_scope", "stage": "subdomains",
                       "host": h, "reason": decision.reason})
        in_scope_count += 1 if decision.allowed else 0
        rows.append({
            "org_id": ctx.scan.org_id, "scan_id": ctx.scan.id,
            "hostname": h, "source": "subfinder", "in_scope": decision.allowed,
        })
    n = _upsert(ctx.session, Subdomain, rows, ["scan_id", "hostname"],
                update_cols=["source", "in_scope"])
    return {"discovered": n, "in_scope": in_scope_count}


def _in_scope_subdomains(ctx: StageContext) -> list[str]:
    q = select(Subdomain.hostname).where(
        Subdomain.scan_id == ctx.scan.id, Subdomain.in_scope.is_(True)
    )
    return list(ctx.session.execute(q).scalars().all())


def run_dns(ctx: StageContext) -> dict:
    """dnsx over in-scope subdomains -> upsert DNSRecord rows; detect which resolve."""
    run = ctx.runner()
    hosts = _in_scope_subdomains(ctx)
    total_records = 0
    for chunk in chunked(hosts, 500):
        ctx.check_cancel()
        res = run("dnsx", chunk, extra_args=["-json", "-a", "-aaaa", "-cname", "-silent"])
        recs = parse_dnsx(res.stdout)
        rows = [
            {"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id,
             "hostname": h, "record_type": rt, "value": v}
            for (h, rt, v) in recs
        ]
        total_records += _upsert(
            ctx.session, DNSRecord, rows,
            ["scan_id", "hostname", "record_type", "value"], update_cols=None,
        )
    return {"records": total_records}


def _resolved_hosts(ctx: StageContext) -> list[str]:
    """Hosts with an A/AAAA record — the 'live' set httpx probes."""
    q = (
        select(DNSRecord.hostname)
        .where(DNSRecord.scan_id == ctx.scan.id, DNSRecord.record_type.in_(("A", "AAAA")))
        .distinct()
    )
    return list(ctx.session.execute(q).scalars().all())


def run_httpx(ctx: StageContext) -> dict:
    """httpx over resolved hosts -> upsert HTTPEndpoint rows."""
    run = ctx.runner()
    hosts = _resolved_hosts(ctx)
    total = 0
    for chunk in chunked(hosts, 300):
        ctx.check_cancel()
        res = run("httpx", chunk,
                  extra_args=["-json", "-silent", "-title", "-content-length"])
        rows = []
        for obj in parse_httpx(res.stdout):
            url = (obj.get("url") or "").strip()
            if not url:
                continue
            rows.append({
                "org_id": ctx.scan.org_id, "scan_id": ctx.scan.id, "url": url,
                "status_code": obj.get("status_code"),
                "title": (obj.get("title") or None),
                "content_length": obj.get("content_length"),
                "waf_vendor": obj.get("waf") or None,
                "cdn": obj.get("cdn_name") or None,
            })
        total += _upsert(
            ctx.session, HTTPEndpoint, rows, ["scan_id", "url"],
            update_cols=["status_code", "title", "content_length", "waf_vendor", "cdn"],
        )
    return {"endpoints": total}


def _scanned_ip_targets(ctx: StageContext) -> list[str]:
    """IPs from A/AAAA records that are EXPLICITLY in scope (ip/cidr rule).

    A host resolving to an IP never authorises scanning that IP — only ip/cidr scope rules
    do. This is what stops us port-scanning shared CDN / co-tenant infrastructure.
    """
    ips = ctx.session.execute(
        select(DNSRecord.value)
        .where(DNSRecord.scan_id == ctx.scan.id, DNSRecord.record_type.in_(("A", "AAAA")))
        .distinct()
    ).scalars().all()
    kept: list[str] = []
    for ip in ips:
        if is_in_scope(ip, ctx.scope_rules, allow_internal=ctx.allow_internal).allowed:
            kept.append(ip)
        else:
            ctx.audit({"event": "ip_out_of_scope", "stage": "ports", "ip": ip})
    return kept


def run_ports(ctx: StageContext) -> dict:
    """naabu over IPs explicitly in scope -> upsert Service rows."""
    run = ctx.runner()
    ips = _scanned_ip_targets(ctx)
    total = 0
    for chunk in chunked(ips, 100):
        ctx.check_cancel()
        res = run("naabu", chunk, extra_args=["-json", "-silent"])
        rows = [
            {"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id, "ip": ip,
             "hostname": host, "port": port, "protocol": "tcp"}
            for (ip, port, host) in parse_naabu(res.stdout)
        ]
        total += _upsert(ctx.session, Service, rows,
                         ["scan_id", "ip", "port", "protocol"],
                         update_cols=["hostname"])
    return {"services": total}


def run_tls(ctx: StageContext) -> dict:
    """tlsx over resolved hosts -> upsert TLSInfo rows."""
    run = ctx.runner()
    hosts = _resolved_hosts(ctx)
    total = 0
    for chunk in chunked(hosts, 300):
        ctx.check_cancel()
        res = run("tlsx", chunk, extra_args=["-json", "-silent"])
        rows = []
        for o in parse_tlsx(res.stdout):
            host = (o.get("host") or "").strip().lower()
            if not host:
                continue
            try:
                port = int(o.get("port", 443))
            except (TypeError, ValueError):
                port = 443
            rows.append({
                "org_id": ctx.scan.org_id, "scan_id": ctx.scan.id, "hostname": host,
                "port": port, "tls_version": o.get("tls_version"),
                "cert_issuer": o.get("issuer_dn"), "cert_subject": o.get("subject_dn"),
                "self_signed": o.get("self_signed"), "expired": o.get("expired"),
                "weak_protocol": _is_weak_tls(o.get("tls_version")),
            })
        total += _upsert(ctx.session, TLSInfo, rows, ["scan_id", "hostname", "port"],
                         update_cols=["tls_version", "cert_issuer", "cert_subject",
                                      "self_signed", "expired", "weak_protocol"])
    return {"tls_info": total}


def _is_weak_tls(version: str | None) -> bool | None:
    if not version:
        return None
    v = version.lower().replace(" ", "")
    return v in ("ssl3", "sslv3", "tls1", "tls1.0", "tls10", "tls1.1", "tls11")


def run_waf(ctx: StageContext) -> dict:
    """wafw00f over endpoints -> update HTTPEndpoint.waf_vendor."""
    run = ctx.runner()
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id)
    ).scalars().all())
    total = 0
    for chunk in chunked(urls, 200):
        ctx.check_cancel()
        res = run("wafw00f", chunk)
        rows = []
        for o in parse_wafw00f(res.stdout):
            url = (o.get("url") or "").strip()
            vendor = o.get("firewall") if o.get("detected") else None
            if url and vendor and vendor.lower() not in ("none", "generic"):
                rows.append({"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id,
                             "url": url, "waf_vendor": vendor})
        total += _upsert(ctx.session, HTTPEndpoint, rows, ["scan_id", "url"],
                         update_cols=["waf_vendor"])
    return {"waf": total}


def run_tech(ctx: StageContext) -> dict:
    """httpx tech-detect over endpoints -> upsert Technology rows."""
    run = ctx.runner()
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id)
    ).scalars().all())
    total = 0
    for chunk in chunked(urls, 200):
        ctx.check_cancel()
        res = run("httpx", chunk, extra_args=["-td", "-json"])
        rows = [
            # version="" (not NULL) so the (scan_id,url,name,version) unique key dedupes on
            # re-run — Postgres treats NULLs as distinct, which would allow duplicates.
            {"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id, "url": url,
             "name": name, "version": ""}
            for (url, name) in parse_tech(res.stdout)
        ]
        total += _upsert(ctx.session, Technology, rows,
                         ["scan_id", "url", "name", "version"], update_cols=None)
    return {"technologies": total}


def run_urls(ctx: StageContext) -> dict:
    """katana (crawl) + gau (historical) over in-scope hosts -> http_endpoints + parameters.

    Every discovered URL is re-checked against scope (Gate 2); out-of-scope URLs are dropped.
    Query-string parameters are extracted into the parameters table.
    """
    run = ctx.runner()
    hosts = _resolved_hosts(ctx) or _in_scope_subdomains(ctx)
    seen: set[str] = set()
    ep_rows: list[dict] = []
    param_rows: list[dict] = []
    for chunk in chunked(hosts, 100):
        ctx.check_cancel()
        for tool in ("katana", "gau"):
            extra = ["-silent"] if tool == "katana" else []
            res = run(tool, chunk, extra_args=extra)
            for url in parse_urls(res.stdout):
                host = urlparse(url).hostname or ""
                if not host or not is_in_scope(host, ctx.scope_rules,
                                               allow_internal=ctx.allow_internal).allowed:
                    ctx.audit({"event": "url_out_of_scope", "stage": "urls", "host": host})
                    continue
                if url not in seen:
                    seen.add(url)
                    ep_rows.append({"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id,
                                    "url": url})
                for name, loc in params_from_url(url):
                    param_rows.append({"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id,
                                       "url": url, "name": name, "method": "GET",
                                       "param_in": loc})
    n_urls = _upsert(ctx.session, HTTPEndpoint, ep_rows, ["scan_id", "url"], update_cols=None)
    n_params = _upsert(ctx.session, Parameter, param_rows,
                       ["scan_id", "url", "name", "method"], update_cols=None)
    return {"urls": n_urls, "parameters": n_params}


# Asset suffixes most likely to carry hard-coded secrets; JS bundles above all.
_SECRET_SCAN_SUFFIXES = (
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".json", ".map",
    ".env", ".txt", ".yml", ".yaml", ".config", ".xml",
)
_MAX_SECRET_TARGETS = 800


def _secret_scan_urls(ctx: StageContext) -> list[str]:
    """In-scope endpoint URLs worth fetching for secret scanning: JS/JSON/config assets first,
    then a bounded number of HTML pages (inline scripts leak too)."""
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id).distinct()
    ).scalars().all())
    assets, pages = [], []
    for u in urls:
        path = urlparse(u).path.lower()
        (assets if path.endswith(_SECRET_SCAN_SUFFIXES) else pages).append(u)
    return (assets + pages)[:_MAX_SECRET_TARGETS]


def _parse_httpx_srd_index(index_path: str) -> dict[str, str]:
    """Map each stored-response file path -> its source URL, from httpx -srd's index.txt."""
    mapping: dict[str, str] = {}
    try:
        with open(index_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.strip().split(" ", 2)
                if len(parts) >= 2:
                    mapping[parts[0]] = parts[1]
    except OSError:
        pass
    return mapping


def _fetch_response_bodies(ctx: StageContext, urls: list[str]) -> dict[str, str]:
    """Fetch each URL's body with the scoped httpx engine and return {source_url: body}.

    httpx (-srd) writes each response to <tmp>/response/<host>/<hash>.txt plus an index.txt
    mapping file->URL; we read them back and delete the temp dir. Separated from run_secrets so
    the disk side-effect can be stubbed in tests.
    """
    run = ctx.runner()
    bodies: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="orvex-secrets-") as td:
        for chunk in chunked(urls, 200):
            ctx.check_cancel()
            run("httpx", chunk, extra_args=["-silent", "-srd", td, "-timeout", "15",
                                            "-mc", "200,201,203,206"])
        index = _parse_httpx_srd_index(os.path.join(td, "response", "index.txt"))
        for root, _dirs, files in os.walk(td):
            for fn in files:
                if fn == "index.txt":
                    continue
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        bodies[index.get(fpath, fpath)] = fh.read()
                except OSError:
                    continue
    return bodies


def run_secrets(ctx: StageContext) -> dict:
    """Fetch in-scope JS/JSON/config assets and scan their bodies for hard-coded secrets.

    The old approach handed bare hostnames to trufflehog, which does nothing without a source
    subcommand — so it never looked at any content and always returned 0. This fetches response
    bodies with the (scoped, rate-limited) httpx engine, then scans them in pure Python with the
    high-signal detector net. Only a mask + sha256 + location are stored; the plaintext is never
    persisted or logged.
    """
    urls = _secret_scan_urls(ctx)
    if not urls:
        return {"secrets": 0, "scanned": 0}
    bodies = _fetch_response_bodies(ctx, urls)
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for location, body in bodies.items():
        _redacted, refs = redact(body)
        for ref in refs:
            key = (ref.sha256, location)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "org_id": ctx.scan.org_id, "scan_id": ctx.scan.id,
                "detector": ref.detector, "redacted_match": ref.mask,
                "sha256": ref.sha256, "location": location,
                "verified": False, "ciphertext": None,
            })
    n = _upsert(ctx.session, Secret, rows, ["scan_id", "sha256", "location"], update_cols=None)
    return {"secrets": n, "scanned": len(bodies)}


# nuclei template policy: allow reliably-automatable, non-destructive template classes;
# deny anything that can DoS/brute/fuzz. Self-hosted interactsh, no headless/code.
NUCLEI_ALLOW_TAGS = (
    "cve,exposures,misconfiguration,tech,ssl,dns,takeover,panel,login,config,backup,logs,disclosure"
)
NUCLEI_DENY_ETAGS = "dos,intrusive,fuzz,fuzzing,brute-force,bruteforce"


def _publish_finding(ctx: StageContext, row: dict) -> None:
    pub = ctx.publisher
    fc = getattr(pub, "finding_created", None)
    if fc:
        fc(finding_id=row.get("dedup_key", ""), ftype=row["type"],
           severity=row["severity"].value, confidence=row["confidence"].value,
           title=row["title"])


def run_findings(ctx: StageContext) -> dict:
    """nuclei over endpoints -> typed/deduped findings; also builds the CVE catalog.

    Confidence follows the honesty matrix (findings.classify_nuclei): CVE templates are
    candidate, matcher-based detections are confirmed. Re-runs never duplicate (dedup_key).
    """
    run = ctx.runner()
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id)
    ).scalars().all())
    finding_rows: list[dict] = []
    cve_rows: dict[str, dict] = {}
    seen_keys: set[str] = set()
    for chunk in chunked(urls, 200):
        ctx.check_cancel()
        res = run("nuclei", chunk,
                  extra_args=["-tags", NUCLEI_ALLOW_TAGS, "-etags", NUCLEI_DENY_ETAGS,
                              "-json", "-silent"])
        for obj in _jsonl(res.stdout):
            row = finding_from_nuclei(obj)
            if row is None or row["dedup_key"] in seen_keys:
                continue
            seen_keys.add(row["dedup_key"])
            row["org_id"] = ctx.scan.org_id
            row["scan_id"] = ctx.scan.id
            finding_rows.append(row)
            if row.get("cve_id"):
                cve_rows[row["cve_id"]] = {
                    "cve_id": row["cve_id"], "cvss_score": row.get("cvss"),
                    "severity": row["severity"], "summary": row["title"],
                }

    # CVE catalog (global, keyed by cve_id) — enriches reporting; ON CONFLICT keeps latest.
    if cve_rows:
        _upsert(ctx.session, CVE, list(cve_rows.values()), ["cve_id"],
                update_cols=["cvss_score", "severity", "summary"])

    n = _upsert(ctx.session, Finding, finding_rows, ["scan_id", "dedup_key"], update_cols=None)
    for row in finding_rows:
        _publish_finding(ctx, row)
    return {"findings": n}


# ============================ gated active modules (slice 13) ============================
# These run ONLY when the scan is configured for active testing (which Gate 1 permits only
# when the authorization record allows it). All are non-destructive by default; sharp finding
# classes are hard-capped at candidate by the model + DB.
MAX_LOGIN_ATTEMPTS = 5


def _config_flag(ctx: StageContext, key: str) -> bool:
    return bool((getattr(ctx.scan, "config", {}) or {}).get(key))


def _insert_findings(ctx: StageContext, rows: list[dict]) -> int:
    for r in rows:
        r.setdefault("org_id", ctx.scan.org_id)
        r.setdefault("scan_id", ctx.scan.id)
        r.setdefault("cvss", SEVERITY_CVSS.get(r["severity"]))
    n = _upsert(ctx.session, Finding, rows, ["scan_id", "dedup_key"], update_cols=None)
    fc = getattr(ctx.publisher, "finding_created", None)
    if fc:
        for r in rows:
            fc(finding_id=r["dedup_key"], ftype=r["type"], severity=r["severity"].value,
               confidence=r["confidence"].value, title=r["title"])
    return n


def _classify_probe(kind: str, confirmed: bool) -> tuple[str, Confidence]:
    """Map a probe result to (type, confidence). Reflection/boolean-diff only → candidate.

    Only OAST/canary-proven open-redirect and SSRF may be confirmed; XSS and SQLi from a
    reflection or boolean-diff signal are ALWAYS candidate (we never claim execution).
    """
    k = kind.lower()
    if k == "xss":
        return "xss_candidate", Confidence.CANDIDATE
    if k == "sqli":
        return "sqli_candidate", Confidence.CANDIDATE
    if k == "open_redirect":
        return ("open_redirect_canary", Confidence.CONFIRMED) if confirmed \
            else ("open_redirect_candidate", Confidence.CANDIDATE)
    if k == "ssrf":
        return ("ssrf_oast_callback", Confidence.CONFIRMED) if confirmed \
            else ("ssrf_candidate", Confidence.CANDIDATE)
    return "injection_candidate", Confidence.CANDIDATE


def parse_ffuf(stdout: str) -> list[str]:
    """ffuf output: `-json` newline-delimited records ({url,input,status}), a single JSON object
    with 'results':[{url}], or one URL per line."""
    stdout = stdout.strip()
    if not stdout:
        return []
    urls: list[str] = []
    # Whole-document JSON ({results:[...]}) first.
    try:
        obj = json.loads(stdout)
        for r in obj.get("results", []):
            u = r.get("url") or ""
            if u:
                urls.append(u)
        if urls:
            return urls
    except json.JSONDecodeError:
        pass
    # Newline-delimited JSON records (ffuf -json).
    for rec in _jsonl(stdout):
        u = rec.get("url") or ""
        if u:
            urls.append(u)
    if urls:
        return urls
    return parse_urls(stdout)


# Directory/content fuzzing needs a wordlist. There is no general content-discovery list in the
# image, so fuzzing is opt-in AND requires ORVEX_FUZZ_WORDLIST to point at one (e.g. a SecLists
# file mounted into the worker). Without it the stage skips loudly instead of silently doing
# nothing — which is how the old implementation (ffuf with no -u/-w) always behaved.
_FUZZ_MATCH_CODES = "200,204,301,302,307,401,403,405"


def run_fuzzing(ctx: StageContext) -> dict:
    """ffuf content discovery (opt-in). One `-u https://host/FUZZ` run per in-scope host, GET,
    rate-limited, non-destructive. Discovered paths are re-checked against scope and stored."""
    if not _config_flag(ctx, "fuzzing"):
        return {"skipped": "fuzzing not enabled"}
    wordlist = os.environ.get("ORVEX_FUZZ_WORDLIST", "")
    if not wordlist or not os.path.isfile(wordlist):
        ctx.audit({"event": "fuzzing_skipped", "reason": "no wordlist (set ORVEX_FUZZ_WORDLIST)"})
        return {"skipped": "no wordlist configured (ORVEX_FUZZ_WORDLIST)"}
    run = ctx.runner()
    hosts = _resolved_hosts(ctx) or _in_scope_subdomains(ctx)
    rows: list[dict] = []
    seen: set[str] = set()
    for host in hosts:
        ctx.check_cancel()
        # The target goes in -u (not argv); the guard still scope-validates & rate-limits `host`.
        res = run("ffuf", [host], no_target_argv=True, extra_args=[
            "-u", f"https://{host}/FUZZ", "-w", wordlist,
            "-mc", _FUZZ_MATCH_CODES, "-json", "-s",
        ])
        for url in parse_ffuf(res.stdout):
            h = urlparse(url).hostname or ""
            if not h or not is_in_scope(h, ctx.scope_rules,
                                        allow_internal=ctx.allow_internal).allowed:
                continue
            if url not in seen:
                seen.add(url)
                rows.append({"org_id": ctx.scan.org_id, "scan_id": ctx.scan.id, "url": url})
    n = _upsert(ctx.session, HTTPEndpoint, rows, ["scan_id", "url"], update_cols=None)
    return {"fuzzed_endpoints": n}


def run_active(ctx: StageContext) -> dict:
    """Canary-based active probes (opt-in). Candidate findings only (never confirmed XSS/SQLi)."""
    if not _config_flag(ctx, "active_probes"):
        return {"skipped": "active probes not enabled"}
    run = ctx.runner()
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id)
    ).scalars().all())
    rows: list[dict] = []
    for chunk in chunked(urls, 100):
        ctx.check_cancel()
        # State-changing methods are opt-in; default is GET/idempotent only.
        extra = [] if _config_flag(ctx, "allow_state_changing") else ["--methods", "GET"]
        res = run("orvex-probe", chunk, extra_args=extra)
        for o in _jsonl(res.stdout):
            kind = o.get("kind", "")
            ftype, confidence = _classify_probe(kind, bool(o.get("confirmed")))
            target = o.get("url", "")
            rows.append({
                "type": ftype, "title": o.get("title") or f"{kind} candidate at {target}",
                "severity": severity_from(o.get("severity") or "medium"),
                "confidence": confidence, "target": target,
                "evidence": {k: v for k, v in o.items() if k != "raw"},
                "dedup_key": make_dedup_key("probe", kind, target, o.get("param", "")),
            })
    return {"findings": _insert_findings(ctx, rows)}


def run_login(ctx: StageContext) -> dict:
    """Safe login testing (opt-in): brute-force-protection-EXISTS + user-enum, ≤5 attempts.

    The guard hard-caps attempts to 5 regardless of what we request. We assert presence of
    protection, never its absence.
    """
    if not _config_flag(ctx, "active_probes"):
        return {"skipped": "login testing not enabled"}
    run = ctx.runner()
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id)
    ).scalars().all())
    rows: list[dict] = []
    for chunk in chunked(urls, 50):
        ctx.check_cancel()
        # attempts is also hard-capped by the guard (see TOOL_PROFILES['login_probe']).
        res = run("login_probe", chunk, attempts=MAX_LOGIN_ATTEMPTS)
        for o in _jsonl(res.stdout):
            kind = o.get("kind", "")
            target = o.get("url", "")
            if kind == "bruteforce_protection" and o.get("present"):
                ftype, title = "bruteforce_protection_present", "Brute-force protection present"
            elif kind == "user_enum" and o.get("detected"):
                ftype, title = "user_enumeration", "Username enumeration"
            elif kind == "default_creds" and o.get("accepted"):
                ftype, title = "default_credentials_accepted", "Default credentials accepted"
            else:
                continue  # e.g. "protection not observed in 5 attempts" is NOT a finding
            rows.append({
                "type": ftype, "title": title,
                "severity": severity_from(o.get("severity") or "medium"),
                "confidence": Confidence.CONFIRMED, "target": target,
                "evidence": {k: v for k, v in o.items()
                             if k not in ("raw", "password", "credential")},
                "dedup_key": make_dedup_key("login", kind, target),
            })
    return {"findings": _insert_findings(ctx, rows)}


def run_idor(ctx: StageContext) -> dict:
    """IDOR differential testing (opt-in, two sessions). ALWAYS candidate (never confirmed)."""
    if not _config_flag(ctx, "active_probes"):
        return {"skipped": "idor testing not enabled"}
    run = ctx.runner()
    urls = list(ctx.session.execute(
        select(HTTPEndpoint.url).where(HTTPEndpoint.scan_id == ctx.scan.id)
    ).scalars().all())
    rows: list[dict] = []
    for chunk in chunked(urls, 100):
        ctx.check_cancel()
        res = run("orvex-idor", chunk)
        for o in _jsonl(res.stdout):
            target = o.get("url", "")
            rows.append({
                "type": "idor",  # hard-capped at candidate by model + DB
                "title": o.get("title") or f"IDOR candidate at {target}",
                "severity": severity_from(o.get("severity") or "medium"),
                "confidence": Confidence.CANDIDATE, "target": target,
                "evidence": {k: v for k, v in o.items() if k != "raw"},
                "dedup_key": make_dedup_key("idor", target, o.get("param", "")),
            })
    return {"findings": _insert_findings(ctx, rows)}


STAGE_FUNCS: dict[str, Callable[[StageContext], dict]] = {
    "subdomains": run_subdomains,
    "dns": run_dns,
    "httpx": run_httpx,
    "ports": run_ports,
    "tls": run_tls,
    "waf": run_waf,
    "tech": run_tech,
    "urls": run_urls,
    "secrets": run_secrets,
    "findings": run_findings,
    "fuzzing": run_fuzzing,
    "active": run_active,
    "login": run_login,
    "idor": run_idor,
}
