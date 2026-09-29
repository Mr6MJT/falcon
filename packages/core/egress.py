"""Gate 3 helper — resolve the frozen scope to IPs and write the egress allow-list files.

The egress gateway (infra/egress) hot-reloads these files into its nftables allow sets. This
is the app side of Gate 3: it translates the scope (domains/CIDRs/IPs) into concrete
destination IPs the worker is permitted to reach for this run. Everything else is DROPed in
the kernel, independently of any app-level check.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable

from .scope import RuleKind, ScopeRule


def resolve_allowlist(rules: Iterable[ScopeRule], *, resolver=None) -> tuple[list[str], list[str]]:
    """Return (ipv4_cidrs, ipv6_cidrs) the worker may egress to for this run.

    IPs/CIDRs from ip/cidr include rules are used directly. Domain/wildcard include rules are
    resolved to A/AAAA records (a domain being in scope authorises reaching the IPs it resolves
    to, for HTTP recon). Excluded rules are never added. `resolver` is injectable for testing.
    """
    resolve = resolver or _default_resolver
    v4: set[str] = set()
    v6: set[str] = set()
    includes = [r for r in rules if r.action.value == "include"]
    for r in includes:
        if r.kind == RuleKind.IP:
            (_v6_add if ":" in r.value else _v4_add)(r.value + _mask(r.value), v4, v6)
        elif r.kind == RuleKind.CIDR:
            (_v6_add if ":" in r.value else _v4_add)(r.value, v4, v6)
        elif r.kind in (RuleKind.DOMAIN, RuleKind.WILDCARD, RuleKind.URL):
            for ip in resolve(r.value):
                (_v6_add if ":" in ip else _v4_add)(ip + _host_mask(ip), v4, v6)
    return sorted(v4), sorted(v6)


def _mask(ip: str) -> str:
    return "" if "/" in ip else _host_mask(ip)


def _host_mask(ip: str) -> str:
    return "/128" if ":" in ip else "/32"


def _v4_add(cidr: str, v4: set, v6: set) -> None:
    try:
        v4.add(str(ipaddress.ip_network(cidr, strict=False)))
    except ValueError:
        pass


def _v6_add(cidr: str, v4: set, v6: set) -> None:
    try:
        v6.add(str(ipaddress.ip_network(cidr, strict=False)))
    except ValueError:
        pass


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


def write_allowlist(v4: list[str], v6: list[str], *, v4_path: str, v6_path: str) -> None:
    with open(v4_path, "w") as f:
        f.write("\n".join(v4) + "\n")
    with open(v6_path, "w") as f:
        f.write("\n".join(v6) + "\n")
