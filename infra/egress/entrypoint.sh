#!/bin/sh
# Gate 3 — the un-bypassable egress firewall.
#
# The worker network (orvex-egress) is a Docker network with NO internet route. This gateway
# is the worker's default route; it forwards + NATs traffic to the internet ONLY for
# destination IPs that are on the per-run allow-list, and DROPs everything else. Even if every
# app-level scope check (Gate 1 / Gate 2) had a bug, a packet still cannot reach an off-scope
# host — this is the kernel-level backstop that defeats DNS rebinding / redirect-to-internal.
#
# The allow-list is programmed per run by the app resolving in-scope domains/CIDRs to IPs and
# writing them (one per line) to $ALLOW_V4 / $ALLOW_V6, which we hot-reload into nft sets.
#
# Requires: NET_ADMIN, and the worker started with its default route via this container.

set -eu

ALLOW_V4="${ORVEX_ALLOW_V4:-/run/orvex/allow.v4}"
ALLOW_V6="${ORVEX_ALLOW_V6:-/run/orvex/allow.v6}"
EXT_IF="${ORVEX_EXT_IF:-eth0}"          # interface facing the internet
mkdir -p "$(dirname "$ALLOW_V4")"
: > "$ALLOW_V4"; : > "$ALLOW_V6"

echo 1 > /proc/sys/net/ipv4/ip_forward || true
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

# Base ruleset: default-DROP forward, allow established + allow-listed destinations, NAT out.
nft -f - <<'NFT'
flush ruleset
table inet orvex {
  set allow4 { type ipv4_addr; flags interval; }
  set allow6 { type ipv6_addr; flags interval; }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ip  daddr @allow4 accept
    ip6 daddr @allow6 accept
    # Never let the worker reach cloud metadata / link-local / private ranges.
    ip  daddr { 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } drop
    log prefix "orvex-egress-drop " drop
  }
}
table ip orvex_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    ip daddr @allow4 oifname "IFACE" masquerade
  }
}
NFT
# substitute the external interface name into the NAT rule
nft delete table ip orvex_nat 2>/dev/null || true
nft add table ip orvex_nat
nft add chain ip orvex_nat postrouting '{ type nat hook postrouting priority 100; policy accept; }'
nft add rule ip orvex_nat postrouting ip daddr @orvex_nat_placeholder oifname "$EXT_IF" masquerade 2>/dev/null || \
  nft add rule ip orvex_nat postrouting oifname "$EXT_IF" ip daddr != 0.0.0.0 masquerade

reload_sets() {
  # Replace the allow sets from the files (atomic per set).
  v4="$(grep -E '^[0-9.]+(/[0-9]+)?$' "$ALLOW_V4" 2>/dev/null | paste -sd, - || true)"
  v6="$(grep -E '^[0-9a-fA-F:]+(/[0-9]+)?$' "$ALLOW_V6" 2>/dev/null | paste -sd, - || true)"
  nft flush set inet orvex allow4 2>/dev/null || true
  nft flush set inet orvex allow6 2>/dev/null || true
  [ -n "$v4" ] && nft add element inet orvex allow4 "{ $v4 }" 2>/dev/null || true
  [ -n "$v6" ] && nft add element inet orvex allow6 "{ $v6 }" 2>/dev/null || true
}

echo "[gate3] egress firewall up (default DROP). Watching $ALLOW_V4 / $ALLOW_V6"
reload_sets
# Hot-reload the allow-list whenever the files change.
LAST=""
while true; do
  CUR="$(cat "$ALLOW_V4" "$ALLOW_V6" 2>/dev/null | sha256sum || true)"
  if [ "$CUR" != "$LAST" ]; then reload_sets; LAST="$CUR"; echo "[gate3] allow-list reloaded"; fi
  sleep 3
done
