"""Scope-rejection tests — the security-critical suite. CI gates on these.

If any of these ever fail, the tool can touch something it must not. Treat a
failure here as a release blocker, never as a flaky test to be skipped.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.scope import (
    RuleAction,
    RuleKind,
    ScopeRule,
    is_in_scope,
)


def _rules(*specs):
    return [ScopeRule.make(k, a, v) for (k, a, v) in specs]


WILDCARD_EXAMPLE = _rules((RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"))
APEX_AND_WILDCARD = _rules(
    (RuleKind.DOMAIN, RuleAction.INCLUDE, "example.com"),
    (RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"),
)


# --- wildcards anchor on label boundaries -----------------------------------
@pytest.mark.parametrize(
    "host,expected",
    [
        ("app.example.com", True),
        ("a.b.example.com", True),
        ("example.com", False),  # apex is NOT covered by *.example.com
        ("evilexample.com", False),  # no label boundary
        ("example.com.attacker.net", False),  # classic suffix trick
        ("evil-example.com.attacker.net", False),  # from the spec
        ("notexample.com", False),
    ],
)
def test_wildcard_label_boundary(host, expected):
    assert is_in_scope(host, WILDCARD_EXAMPLE).allowed is expected


def test_apex_needs_its_own_rule():
    assert is_in_scope("example.com", APEX_AND_WILDCARD).allowed is True
    assert is_in_scope("x.example.com", APEX_AND_WILDCARD).allowed is True


# --- IDN / punycode homographs ----------------------------------------------
def test_idn_homograph_rejected():
    # "раypal" using Cyrillic а/р must not match ASCII paypal.
    rules = _rules((RuleKind.DOMAIN, RuleAction.INCLUDE, "paypal.com"))
    assert is_in_scope("раypal.com", rules).allowed is False


def test_idn_scope_matches_its_own_punycode():
    # An in-scope IDN host matches whether given as unicode or as its xn-- form.
    rules = _rules((RuleKind.DOMAIN, RuleAction.INCLUDE, "bücher.example"))
    assert is_in_scope("bücher.example", rules).allowed is True
    assert is_in_scope("xn--bcher-kva.example", rules).allowed is True


# --- trailing dot normalisation ---------------------------------------------
def test_trailing_dot_is_normalised():
    assert is_in_scope("app.example.com.", WILDCARD_EXAMPLE).allowed is True
    assert is_in_scope("EXAMPLE.com", APEX_AND_WILDCARD).allowed is True


# --- deny wins ---------------------------------------------------------------
def test_exclude_overrides_include():
    rules = _rules(
        (RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"),
        (RuleKind.DOMAIN, RuleAction.EXCLUDE, "secret.example.com"),
    )
    assert is_in_scope("secret.example.com", rules).allowed is False
    assert is_in_scope("public.example.com", rules).allowed is True


def test_default_deny_with_no_rules():
    assert is_in_scope("anything.com", []).allowed is False


# --- metadata / private / loopback IPs --------------------------------------
@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",  # cloud metadata
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "0.0.0.0",
        "::1",
        "fd00:ec2::254",
    ],
)
def test_special_ips_rejected_even_if_ruled_in(ip):
    # Even an explicit include rule cannot pull a metadata/private IP into scope
    # while internal testing is off.
    rules = _rules((RuleKind.IP, RuleAction.INCLUDE, ip))
    assert is_in_scope(ip, rules).allowed is False


def test_internal_flag_allows_lab_only():
    rules = _rules((RuleKind.IP, RuleAction.INCLUDE, "127.0.0.1"))
    assert is_in_scope("127.0.0.1", rules, allow_internal=True).allowed is True


# --- hostname != resolved IP -------------------------------------------------
def test_in_scope_host_does_not_authorise_an_ip():
    # example.com is in scope as a host, but a raw IP is only in scope via ip/cidr.
    rules = _rules((RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"))
    assert is_in_scope("93.184.216.34", rules).allowed is False


def test_explicit_ip_and_cidr_in_scope():
    # Genuinely public IPs. (RFC 5737 doc ranges like 203.0.113.0/24 are reserved and
    # are correctly refused by the special-IP guard — see the test below.)
    rules = _rules(
        (RuleKind.CIDR, RuleAction.INCLUDE, "93.184.216.0/24"),
        (RuleKind.IP, RuleAction.INCLUDE, "1.1.1.1"),
    )
    assert is_in_scope("93.184.216.34", rules).allowed is True
    assert is_in_scope("1.1.1.1", rules).allowed is True
    assert is_in_scope("93.184.217.1", rules).allowed is False


def test_reserved_doc_ranges_refused_even_if_ruled_in():
    # Documentation/reserved ranges must never be scanned, rule or no rule.
    rules = _rules((RuleKind.CIDR, RuleAction.INCLUDE, "203.0.113.0/24"))
    assert is_in_scope("203.0.113.55", rules).allowed is False


# --- junk / malformed input --------------------------------------------------
@pytest.mark.parametrize("bad", ["", "   ", "http://", "..", " a b .com"])
def test_malformed_targets_rejected(bad):
    assert is_in_scope(bad, WILDCARD_EXAMPLE).allowed is False


# --- partial-label glob wildcards + scope parsing (user-requested syntax) ---------------
def test_glob_wildcard_label_suffix():
    rules = _rules((RuleKind.WILDCARD, RuleAction.INCLUDE, "*end.api.deriv.com"))
    assert is_in_scope("frontend.api.deriv.com", rules).allowed is True
    assert is_in_scope("backend.api.deriv.com", rules).allowed is True
    assert is_in_scope("api.deriv.com", rules).allowed is False          # apex not matched
    assert is_in_scope("other.api.deriv.com", rules).allowed is False    # label doesn't end 'end'
    assert is_in_scope("frontend.deriv.com", rules).allowed is False     # different base


def test_exact_domain_excludes_subdomains():
    rules = _rules((RuleKind.DOMAIN, RuleAction.INCLUDE, "deriv.exchange"))
    assert is_in_scope("deriv.exchange", rules).allowed is True
    assert is_in_scope("www.deriv.exchange", rules).allowed is False     # no subdomains


def test_parse_scope_lines_all_forms():
    from packages.core.scope import parse_scope_lines
    rules = parse_scope_lines(
        include_text="*.deriv.ae\nderiv.exchange\n*end.api.deriv.com",
        exclude_text="admin.deriv.ae",
    )
    got = {(r["kind"], r["action"], r["value"]) for r in rules}
    assert ("wildcard", "include", "deriv.ae") in got          # *.deriv.ae -> base
    assert ("domain", "include", "deriv.exchange") in got      # exact
    assert ("wildcard", "include", "*end.api.deriv.com") in got  # glob kept
    assert ("domain", "exclude", "admin.deriv.ae") in got      # out-of-scope


def test_parsed_scope_enforced_end_to_end():
    from packages.core.scope import ScopeRule as SR
    from packages.core.scope import parse_scope_lines
    compiled = [SR.make(r["kind"], r["action"], r["value"])
                for r in parse_scope_lines("*.deriv.ae\nderiv.exchange\n*end.api.deriv.com",
                                           "admin.deriv.ae")]
    assert is_in_scope("shop.deriv.ae", compiled).allowed is True        # subdomain in scope
    assert is_in_scope("admin.deriv.ae", compiled).allowed is False      # excluded (deny wins)
    assert is_in_scope("deriv.exchange", compiled).allowed is True
    assert is_in_scope("www.deriv.exchange", compiled).allowed is False  # exact only
    assert is_in_scope("backend.api.deriv.com", compiled).allowed is True
    assert is_in_scope("cdn.api.deriv.com", compiled).allowed is False   # doesn't end 'end'
