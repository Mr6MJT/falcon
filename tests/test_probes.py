"""Probe logic (pure, via a fake fetcher). No DB, no network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.probes import (
    idor_differential,
    login_bruteforce_protection,
    login_user_enumeration,
    probe_open_redirect,
    probe_sqli,
    probe_xss,
)


def fetch_factory(handler):
    def fetch(url, method="GET"):
        return handler(url, method)
    return fetch


def test_xss_reflection_is_candidate_not_confirmed():
    def h(url, method):
        # reflect the injected value verbatim
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(url).query)
        val = q.get("q", [""])[0]
        return 200, {}, f"<div>{val}</div>"
    out = probe_xss("http://x/s?q=1", fetch_factory(h))
    assert len(out) == 1
    assert out[0]["kind"] == "xss" and out[0]["confirmed"] is False


def test_xss_not_flagged_when_encoded():
    def h(url, method):
        return 200, {}, "<div>&lt;b&gt;</div>"  # encoded, canary '<b>' not present raw
    assert probe_xss("http://x/s?q=1", fetch_factory(h)) == []


def test_sqli_boolean_diff_candidate():
    def h(url, method):
        from urllib.parse import parse_qs, urlparse
        val = parse_qs(urlparse(url).query).get("id", [""])[0]
        if "'1'='2" in val:  # FALSE payload (decoded) → different response
            return 200, {}, "no results found"
        return 200, {}, "here are your 20 results ...."  # baseline/TRUE → same
    out = probe_sqli("http://x/s?id=1", fetch_factory(h))
    assert out and out[0]["kind"] == "sqli" and out[0]["confirmed"] is False


def test_open_redirect_confirmed_only_via_location():
    canary_seen = {}

    def h(url, method):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(url).query)
        target = q.get("next", [""])[0]
        canary_seen["v"] = target
        return 302, {"location": target}, ""  # echoes canary into Location
    out = probe_open_redirect("http://x/go?next=orig", fetch_factory(h))
    assert out and out[0]["confirmed"] is True and out[0]["kind"] == "open_redirect"


def test_open_redirect_not_confirmed_without_location():
    def h(url, method):
        return 200, {}, "ok"  # no redirect, no Location
    assert probe_open_redirect("http://x/go?next=orig", fetch_factory(h)) == []


def test_login_bruteforce_protection_presence_only():
    def with_protection(url, method):
        return 429, {"retry-after": "30"}, "too many requests"

    def no_signal(url, method):
        return 200, {}, "invalid credentials"

    r1 = login_bruteforce_protection("http://x/login", fetch_factory(with_protection))
    assert r1["present"] is True
    r2 = login_bruteforce_protection("http://x/login", fetch_factory(no_signal))
    assert r2["present"] is False  # "not observed" — never asserts absence as a finding


def test_login_bruteforce_capped_at_five():
    calls = {"n": 0}

    def counter(url, method):
        calls["n"] += 1
        return 200, {}, "nope"
    login_bruteforce_protection("http://x/login", fetch_factory(counter), max_attempts=100)
    assert calls["n"] == 5  # hard cap


def test_user_enum_detects_difference():
    def h(url, method):
        if "nope" in url:
            return 404, {}, "no such user"
        return 200, {}, "wrong password for this account"
    r = login_user_enumeration("http://x/login", fetch_factory(h), real_account="admin@x")
    assert r["detected"] is True


def test_idor_is_candidate_only():
    def a(url, method):
        return 200, {}, "order #1 for alice, total $50"

    def b(url, method):
        return 200, {}, "order #1 for alice, total $50"  # B sees A's object
    out = idor_differential("http://x/api/orders/1", fetch_factory(a), fetch_factory(b))
    assert out and out[0]["kind"] == "idor" and out[0]["confirmed"] is False
