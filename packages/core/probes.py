"""Probe logic for the custom engines (orvex-probe / orvex-login-probe / orvex-idor).

These are the canary-based active checks. The *logic* lives here (pure, testable via an
injected ``fetch``), and the CLI wrappers in ``engines/`` are thin adapters that plug in a
real HTTP client. Everything here is non-destructive and GET/idempotent by default; the only
state-changing behaviour is the safe login test, which is capped and synthetic.

A ``fetch`` is ``Callable[[str, str | None], Response]`` where Response is
``(status:int, headers:dict[str,str], body:str)``. ``method`` defaults to GET.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

Response = tuple[int, dict, str]
Fetch = Callable[..., Response]

REDIRECT_PARAMS = {"url", "next", "redirect", "return", "returnurl", "dest", "destination",
                   "continue", "u", "r"}
SSRF_PARAMS = {"url", "uri", "path", "dest", "callback", "target", "feed", "site", "host"}


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(parts._replace(query=urlencode(q)))


def _params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def probe_xss(url: str, fetch: Fetch) -> list[dict]:
    """Reflection-only XSS: a unique canary reflected UNENCODED → candidate (never confirmed)."""
    out: list[dict] = []
    for p in _params(url):
        canary = f"orvx{secrets.token_hex(4)}<b>"
        test = _with_param(url, p, canary)
        _, _, body = fetch(test)
        if canary in body:  # reflected without HTML-encoding the '<'
            out.append({"kind": "xss", "url": url, "param": p, "confirmed": False,
                        "severity": "medium",
                        "evidence": {"canary": canary, "reflected_unencoded": True}})
    return out


def _similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def probe_sqli(url: str, fetch: Fetch) -> list[dict]:
    """Boolean-difference SQLi heuristic: TRUE payload resembles baseline, FALSE differs.

    No UNION/stacked/DDL, no data extraction. Candidate only.
    """
    out: list[dict] = []
    for p in _params(url):
        _, _, base = fetch(url)
        _, _, t = fetch(_with_param(url, p, "1' AND '1'='1"))
        _, _, f = fetch(_with_param(url, p, "1' AND '1'='2"))
        # TRUE close to baseline, FALSE clearly different → suggests boolean SQLi.
        if _similar(base, t) > 0.95 and _similar(base, f) < 0.9 and _similar(t, f) < 0.9:
            out.append({"kind": "sqli", "url": url, "param": p, "confirmed": False,
                        "severity": "high",
                        "evidence": {"true_sim": round(_similar(base, t), 3),
                                     "false_sim": round(_similar(base, f), 3)}})
    return out


def probe_open_redirect(url: str, fetch: Fetch) -> list[dict]:
    """Canary in a redirect param appearing in the Location header → CONFIRMED (canary-proven)."""
    out: list[dict] = []
    canary = f"https://orvex-canary-{secrets.token_hex(4)}.example"
    for p in _params(url):
        if p.lower() not in REDIRECT_PARAMS:
            continue
        status, headers, _ = fetch(_with_param(url, p, canary))
        loc = headers.get("location") or headers.get("Location") or ""
        if 300 <= status < 400 and canary in loc:
            out.append({"kind": "open_redirect", "url": url, "param": p, "confirmed": True,
                        "severity": "medium",
                        "evidence": {"canary": canary, "location": loc, "status": status}})
    return out


def probe_ssrf(
    url: str, fetch: Fetch, oast_confirm: Callable[[str], bool] | None = None
) -> list[dict]:
    """SSRF: only CONFIRMED with an out-of-band callback; otherwise a candidate on suspect params.

    ``oast_confirm(token)`` returns True if our self-hosted OAST server saw a callback. Without
    an OAST server, findings stay candidate — we never chase 169.254.169.254 / internal targets.
    """
    out: list[dict] = []
    for p in _params(url):
        if p.lower() not in SSRF_PARAMS:
            continue
        token = secrets.token_hex(6)
        canary = f"https://orvex-oast-{token}.example"
        fetch(_with_param(url, p, canary))
        confirmed = bool(oast_confirm and oast_confirm(token))
        out.append({"kind": "ssrf", "url": url, "param": p, "confirmed": confirmed,
                    "severity": "high" if confirmed else "medium",
                    "evidence": {"token": token, "oast": confirmed}})
    return out


def probe_url(url: str, fetch: Fetch, oast_confirm=None) -> list[dict]:
    findings: list[dict] = []
    findings += probe_open_redirect(url, fetch)
    findings += probe_xss(url, fetch)
    findings += probe_sqli(url, fetch)
    findings += probe_ssrf(url, fetch, oast_confirm)
    return findings


# --------------------------------------------------------------------------- safe login
def login_bruteforce_protection(login_url: str, fetch: Fetch, *, max_attempts: int = 5) -> dict:
    """Assert protection EXISTS. Sends up to `max_attempts` (hard-capped at 5) synthetic
    logins and looks for 429 / lockout / CAPTCHA / throttle. Never asserts absence."""
    attempts = min(max_attempts, 5)
    synthetic = f"orvex-synthetic-{secrets.token_hex(3)}@example.test"
    for _ in range(attempts):
        status, headers, body = fetch(login_url, "POST")
        blob = (str(status) + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
                + " " + body[:500]).lower()
        if (status == 429 or "captcha" in blob or "locked" in blob or "too many" in blob
                or "rate limit" in blob or "retry-after" in headers):
            return {"kind": "bruteforce_protection", "url": login_url, "present": True,
                    "severity": "info", "evidence": {"signal_status": status,
                                                     "account": synthetic}}
    # No signal in <=5 attempts → NOT a finding ("not observed", never "absent").
    return {"kind": "bruteforce_protection", "url": login_url, "present": False}


def login_user_enumeration(login_url: str, fetch: Fetch, *, real_account: str) -> dict:
    """User enumeration: compare a random-nonexistent account vs an operator-owned real one."""
    nonexistent = f"orvex-nope-{secrets.token_hex(4)}@example.test"
    s1, _, b1 = fetch(_with_param(login_url, "username", nonexistent), "POST")
    s2, _, b2 = fetch(_with_param(login_url, "username", real_account), "POST")
    differs = s1 != s2 or _similar(b1, b2) < 0.9 or abs(len(b1) - len(b2)) > 40
    return {"kind": "user_enum", "url": login_url, "detected": bool(differs),
            "severity": "low",
            "evidence": {"status_diff": s1 != s2, "len_diff": abs(len(b1) - len(b2))}}


# --------------------------------------------------------------------------- IDOR
def idor_differential(url: str, fetch_a: Fetch, fetch_b: Fetch) -> list[dict]:
    """Two-session differential: if session B can read a resource that returns the same object
    as session A (200 + high similarity), flag an IDOR CANDIDATE. Never confirmed."""
    out: list[dict] = []
    sa, _, ba = fetch_a(url)
    sb, _, bb = fetch_b(url)
    if sa == 200 and sb == 200 and _similar(ba, bb) > 0.9 and len(ba) > 0:
        out.append({"kind": "idor", "url": url, "confirmed": False, "severity": "medium",
                    "evidence": {"both_200": True, "similarity": round(_similar(ba, bb), 3)}})
    return out
