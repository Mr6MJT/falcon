"""Gate 3 allow-list resolution (pure; injected resolver)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.core.egress import resolve_allowlist
from packages.core.scope import RuleAction, RuleKind, ScopeRule


def _rules(*specs):
    return [ScopeRule.make(k, a, v) for (k, a, v) in specs]


def test_ip_and_cidr_rules_pass_through():
    rules = _rules(
        (RuleKind.IP, RuleAction.INCLUDE, "203.0.113.5"),
        (RuleKind.CIDR, RuleAction.INCLUDE, "198.51.100.0/24"),
    )
    v4, _ = resolve_allowlist(rules, resolver=lambda h: [])
    assert "203.0.113.5/32" in v4
    assert "198.51.100.0/24" in v4


def test_domains_resolve_to_ips():
    rules = _rules((RuleKind.WILDCARD, RuleAction.INCLUDE, "*.example.com"))
    v4, v6 = resolve_allowlist(rules, resolver=lambda h: ["93.184.216.34", "2606:2800::1"])
    assert "93.184.216.34/32" in v4
    assert "2606:2800::1/128" in v6


def test_excluded_rules_are_not_added():
    rules = _rules(
        (RuleKind.IP, RuleAction.INCLUDE, "203.0.113.5"),
        (RuleKind.IP, RuleAction.EXCLUDE, "203.0.113.9"),
    )
    v4, _ = resolve_allowlist(rules, resolver=lambda h: [])
    assert "203.0.113.5/32" in v4
    assert "203.0.113.9/32" not in v4


def test_write_allowlist(tmp_path):
    from packages.core.egress import write_allowlist
    v4p, v6p = tmp_path / "a4", tmp_path / "a6"
    write_allowlist(["1.2.3.4/32"], [], v4_path=str(v4p), v6_path=str(v6p))
    assert v4p.read_text().strip() == "1.2.3.4/32"
