"""Scope enforcement — the single source of truth for what Orvex is allowed to touch.

Design invariants (do not weaken any of these without security-auditor review):

  * DEFAULT DENY. A target is out of scope unless a matching *include* rule says
    otherwise and no *exclude* rule matches it.
  * DENY WINS. If any exclude rule matches, the target is out of scope, full stop,
    even if an include rule also matches.
  * WILDCARDS ANCHOR ON LABEL BOUNDARIES. ``*.example.com`` matches ``a.example.com``
    and ``a.b.example.com`` but NOT ``example.com`` itself and NOT ``evilexample.com``.
  * HOSTNAME != RESOLVED IP. A hostname being in scope never puts its resolved IP in
    scope. Port/host scanners run against IPs/CIDRs only when those IPs are *explicitly*
    listed as ip/cidr include rules. (Avoids scanning shared CDN / co-tenant infra.)
  * IDN / PUNYCODE NORMALISED. Every hostname is IDNA-encoded before comparison so a
    Unicode homograph cannot slip past an ASCII rule.
  * METADATA / PRIVATE / LOOPBACK IPS REJECTED unless an explicit internal-testing flag
    is set on the call (used only for the local lab).

There is exactly one public entry point, :func:`is_in_scope`. Callers must not
reimplement any of this logic.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

# Cloud/link-local metadata endpoints and other addresses that must never be
# scanned regardless of what a scope rule says, unless internal testing is on.
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure IMDS
        ipaddress.ip_address("100.100.100.200"),  # Alibaba metadata
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDSv2 over IPv6
    }
)


class RuleKind(str, Enum):
    DOMAIN = "domain"  # exact host, e.g. example.com
    WILDCARD = "wildcard"  # *.example.com (subdomains only, not the apex)
    IP = "ip"  # single IP address
    CIDR = "cidr"  # IP range, e.g. 203.0.113.0/24
    URL = "url"  # a specific URL host (host portion is matched as a domain)


class RuleAction(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


@dataclass(frozen=True)
class ScopeRule:
    kind: RuleKind
    action: RuleAction
    value: str  # normalised at construction time via ScopeRule.make()

    @staticmethod
    def make(kind: RuleKind | str, action: RuleAction | str, value: str) -> ScopeRule:
        kind = RuleKind(kind)
        action = RuleAction(action)
        return ScopeRule(kind=kind, action=action, value=_normalise_rule_value(kind, value))


class TargetKind(str, Enum):
    HOST = "host"  # a DNS name — only matched by domain/wildcard/url rules
    IP = "ip"  # an IP literal — only matched by ip/cidr rules


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str  # human-readable, goes straight into the audit log


class ScopeError(ValueError):
    """Raised when a value cannot even be parsed into a target (e.g. junk input)."""


def normalise_host(host: str) -> str:
    """Lower-case, strip a single trailing dot, and IDNA-encode to punycode.

    Raises ScopeError on anything that is not a usable hostname. This is what
    defeats IDN homograph tricks: a Cyrillic look-alike of "paypal.com" becomes its
    distinct xn-- (punycode) form here and will not match an ASCII "paypal.com" rule.
    """
    if not host or not host.strip():
        raise ScopeError("empty host")
    h = host.strip().lower().rstrip(".")
    if not h:
        raise ScopeError("empty host after normalisation")
    # Reject embedded whitespace / control chars outright.
    if any(c.isspace() for c in h):
        raise ScopeError(f"host contains whitespace: {host!r}")
    try:
        # encode() applies IDNA (punycode) per label; decode back to str for comparison.
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as e:
        # idna codec rejects empty labels, over-long labels, etc.
        raise ScopeError(f"host is not a valid IDNA hostname: {host!r}") from e
    return h


def classify_target(raw: str) -> tuple[TargetKind, str]:
    """Turn a raw target string into (kind, normalised value).

    An IP literal becomes TargetKind.IP; everything else is treated as a hostname.
    """
    if not raw or not raw.strip():
        raise ScopeError("empty target")
    candidate = raw.strip()
    # Strip a scheme/path if a URL was passed, keeping only the host[:port] authority.
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0]
    # Drop a userinfo@ prefix if present.
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    # Strip a trailing :port (but keep bracketed IPv6 intact).
    if candidate.startswith("["):
        host_part = candidate[1 : candidate.index("]")] if "]" in candidate else candidate[1:]
    elif candidate.count(":") == 1:
        host_part = candidate.rsplit(":", 1)[0]
    else:
        host_part = candidate

    try:
        ip = ipaddress.ip_address(host_part)
        return TargetKind.IP, str(ip)
    except ValueError:
        return TargetKind.HOST, normalise_host(host_part)


def _normalise_rule_value(kind: RuleKind, value: str) -> str:
    if kind in (RuleKind.DOMAIN, RuleKind.URL):
        _, host = classify_target(value)
        return host
    if kind == RuleKind.WILDCARD:
        v = value.strip().lower().rstrip(".")
        if "*" not in v:
            return normalise_host(v)  # bare base: match all subdomains of it
        if v.startswith("*.") and "*" not in v[2:]:
            return normalise_host(v[2:])  # "*.base" -> store base (all subdomains)
        # A partial-label glob like "*end.api.deriv.com": keep the pattern as-is (validated).
        if any(c.isspace() for c in v) or "/" in v:
            raise ScopeError(f"invalid wildcard pattern: {value!r}")
        return v
    if kind == RuleKind.IP:
        return str(ipaddress.ip_address(value.strip()))
    if kind == RuleKind.CIDR:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    raise ScopeError(f"unknown rule kind: {kind}")


def _host_matches_domain(host: str, rule_value: str) -> bool:
    return host == rule_value


def _host_matches_wildcard(host: str, base: str) -> bool:
    # Two forms:
    #   * a bare base ("deriv.ae", from "*.deriv.ae") matches all subdomains, any depth, but
    #     NOT the apex itself — label-boundary anchored ("evil"+base fails).
    #   * a partial-label glob ("*end.api.deriv.com") matches hosts where "*" stands in for one
    #     label's characters (no dot-crossing): frontend/backend.api.deriv.com match, apex does not.
    if "*" in base:
        pattern = re.escape(base).replace(r"\*", "[^.]*")
        return re.fullmatch(pattern, host) is not None
    return host != base and host.endswith("." + base)


def _ip_matches_cidr(ip: ipaddress._BaseAddress, network: str) -> bool:
    try:
        return ip in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def _is_special_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip in _METADATA_IPS
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def classify_scope_token(token: str) -> tuple[str, str]:
    """Classify one scope token into (kind, normalised_value).

    Understood forms (as bug-bounty programs express scope):
      * ``deriv.exchange``          -> domain  (exact host, NO subdomains)
      * ``*.deriv.ae``              -> wildcard (all subdomains, any depth)
      * ``*end.api.deriv.com``      -> wildcard (partial-label glob; label ends with 'end')
      * ``203.0.113.7`` / ``/24``   -> ip / cidr
      * ``https://x.deriv.com/y``   -> url (host portion)
    """
    t = token.strip().lower()
    if "/" in t and "://" not in t:
        try:
            return "cidr", str(ipaddress.ip_network(t, strict=False))
        except ValueError:
            pass
    try:
        return "ip", str(ipaddress.ip_address(t))
    except ValueError:
        pass
    if "://" in t:
        kind = "url"
    elif "*" in t:
        kind = "wildcard"
    else:
        kind = "domain"
    return kind, ScopeRule.make(kind, "include", t).value


def parse_scope_lines(include_text: str, exclude_text: str = "") -> list[dict]:
    """Parse free-text in-scope / out-of-scope inputs into rule dicts {kind, action, value}.

    Lines may hold several whitespace/comma-separated tokens; ``#`` starts a comment. Bad
    tokens are skipped rather than failing the whole input.
    """
    rules: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for action, text in (("include", include_text), ("exclude", exclude_text)):
        for line in (text or "").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            for tok in re.split(r"[\s,;]+", line):
                if not tok:
                    continue
                try:
                    kind, value = classify_scope_token(tok)
                except (ScopeError, ValueError):
                    continue
                key = (kind, action, value)
                if key in seen:
                    continue
                seen.add(key)
                rules.append({"kind": kind, "action": action, "value": value})
    return rules


def is_in_scope(
    raw_target: str,
    rules: Iterable[ScopeRule],
    *,
    allow_internal: bool = False,
) -> ScopeDecision:
    """The one and only scope check. Returns an auditable decision.

    ``allow_internal=True`` is set ONLY for the local lab (Juice Shop). In every
    real engagement it stays False, so metadata/private/loopback targets are refused
    even if a rule tries to include them.
    """
    try:
        kind, value = classify_target(raw_target)
    except ScopeError as e:
        return ScopeDecision(False, f"unparseable target {raw_target!r}: {e}")

    rules = list(rules)

    if kind == TargetKind.IP:
        ip = ipaddress.ip_address(value)
        if not allow_internal and _is_special_ip(ip):
            return ScopeDecision(
                False, f"refused special/metadata/private IP {value} (internal testing off)"
            )
        # deny wins
        for r in rules:
            if r.action != RuleAction.EXCLUDE:
                continue
            if r.kind == RuleKind.IP and ip == ipaddress.ip_address(r.value):
                return ScopeDecision(False, f"IP {value} excluded by rule {r.value}")
            if r.kind == RuleKind.CIDR and _ip_matches_cidr(ip, r.value):
                return ScopeDecision(False, f"IP {value} excluded by CIDR {r.value}")
        for r in rules:
            if r.action != RuleAction.INCLUDE:
                continue
            if r.kind == RuleKind.IP and ip == ipaddress.ip_address(r.value):
                return ScopeDecision(True, f"IP {value} explicitly in scope (ip rule)")
            if r.kind == RuleKind.CIDR and _ip_matches_cidr(ip, r.value):
                return ScopeDecision(True, f"IP {value} in scope via CIDR {r.value}")
        return ScopeDecision(False, f"IP {value} not covered by any include rule (default deny)")

    # kind == HOST
    host = value
    for r in rules:
        if r.action != RuleAction.EXCLUDE:
            continue
        if r.kind in (RuleKind.DOMAIN, RuleKind.URL) and _host_matches_domain(host, r.value):
            return ScopeDecision(False, f"host {host} excluded by rule {r.value}")
        if r.kind == RuleKind.WILDCARD and _host_matches_wildcard(host, r.value):
            return ScopeDecision(False, f"host {host} excluded by wildcard *.{r.value}")
    for r in rules:
        if r.action != RuleAction.INCLUDE:
            continue
        if r.kind in (RuleKind.DOMAIN, RuleKind.URL) and _host_matches_domain(host, r.value):
            return ScopeDecision(True, f"host {host} in scope (exact rule)")
        if r.kind == RuleKind.WILDCARD and _host_matches_wildcard(host, r.value):
            return ScopeDecision(True, f"host {host} in scope via wildcard *.{r.value}")
    return ScopeDecision(False, f"host {host} not covered by any include rule (default deny)")
