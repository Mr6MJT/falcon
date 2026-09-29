"""Turn nuclei output into typed, honestly-labelled findings.

The honesty matrix (from the safety spec) lives here as a pure function so it is unit-tested
independently of the DB:

  * CVE templates are version/banner-based → **candidate** by default (we don't assert a CVE
    is exploitable just because a version matched). type="cve".
  * Matcher-based detections (the template matched real response content) — TLS issues,
    missing headers, exposures, misconfigurations, disclosures, exposed panels, subdomain
    takeover, accepted default creds — are reliably automatable → **confirmed**.
  * Anything we can't place confidently → candidate.

CVSS: taken from nuclei's classification when present; otherwise a fixed severity→score map
(real CVSS is only claimed for type=cve when nuclei provides it).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .models import Confidence, Severity

# Fixed severity→CVSS for our own (non-CVE) findings.
SEVERITY_CVSS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.1,
    Severity.MEDIUM: 5.3,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.1,
}

_SEVERITY_BY_NAME = {s.value: s for s in Severity}

# Confirmed matcher-based categories → our finding type (must be in models.CONFIRMABLE_TYPES).
_CONFIRMED_TAG_TYPE: list[tuple[frozenset[str], str]] = [
    (frozenset({"ssl", "tls"}), "tls_issue"),
    (frozenset({"missing-headers", "headers", "http-headers"}), "missing_security_header"),
    (frozenset({"default-login", "default-logins"}), "default_credentials_accepted"),
    (frozenset({"takeover"}), "subdomain_takeover"),
    (frozenset({"panel", "login", "exposed-panel"}), "exposed_panel"),
    (frozenset({"exposure", "exposures"}), "exposure"),
    (frozenset({"misconfig", "misconfiguration"}), "misconfiguration"),
    (frozenset({"disclosure", "logs", "backup", "config"}), "disclosure"),
]


def severity_from(name: str | None) -> Severity:
    return _SEVERITY_BY_NAME.get((name or "").lower(), Severity.INFO)


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value) if value else None


def classify_nuclei(info: dict, tags: list[str]) -> tuple[str, Confidence]:
    """Return (finding_type, confidence) for a nuclei finding.

    ``info`` is the nuclei ``info`` block; ``tags`` its normalised tag list.
    """
    classification = info.get("classification") or {}
    cve_id = _first(classification.get("cve-id") or classification.get("cve_id"))
    tagset = {t.strip().lower() for t in tags}

    # CVE templates: candidate (version/banner-based) unless clearly an active check.
    if cve_id or "cve" in tagset:
        return "cve", Confidence.CANDIDATE

    for wanted, ftype in _CONFIRMED_TAG_TYPE:
        if tagset & wanted:
            return ftype, Confidence.CONFIRMED

    # Unknown category: keep it honest — candidate.
    return "known_vulnerability", Confidence.CANDIDATE


def make_dedup_key(*parts: str) -> str:
    """Stable dedup key from any set of identifying parts (keeps re-runs idempotent)."""
    return hashlib.sha256("|".join(p or "" for p in parts).encode()).hexdigest()[:40]


def _dedup_key(template_id: str, matched_at: str, ftype: str) -> str:
    return make_dedup_key(template_id, matched_at, ftype)


def finding_from_nuclei(obj: dict) -> dict | None:
    """Map one nuclei JSON result to a findings-row dict, or None if unusable."""
    template_id = obj.get("template-id") or obj.get("templateID") or ""
    info = obj.get("info") or {}
    if not template_id and not info:
        return None
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t for t in tags.split(",") if t]

    ftype, confidence = classify_nuclei(info, tags)
    severity = severity_from(info.get("severity"))
    classification = info.get("classification") or {}
    cvss = classification.get("cvss-score") or classification.get("cvss_score")
    if cvss is None:
        cvss = SEVERITY_CVSS[severity]
    cve_id = _first(classification.get("cve-id") or classification.get("cve_id"))
    cwe = _first(classification.get("cwe-id") or classification.get("cwe_id"))
    matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""

    evidence = {
        "template_id": template_id,
        "matcher_name": obj.get("matcher-name") or obj.get("matcher_name"),
        "matched_at": matched_at,
        "request": obj.get("request"),
        "response": obj.get("response"),
        "curl_command": obj.get("curl-command"),
    }
    evidence = {k: v for k, v in evidence.items() if v is not None}

    return {
        "type": ftype,
        "title": info.get("name") or template_id or ftype,
        "severity": severity,
        "confidence": confidence,
        "cvss": float(cvss) if cvss is not None else None,
        "cve_id": cve_id,
        "cwe": cwe,
        "target": matched_at,
        "evidence": evidence,
        "dedup_key": _dedup_key(template_id, matched_at, ftype),
    }
