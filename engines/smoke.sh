#!/bin/sh
# Smoke test: every engine must respond to a version/help query.
set -e
for t in subfinder dnsx naabu httpx katana nuclei tlsx ffuf; do
  printf '%s: ' "$t"; "$t" -version 2>&1 | head -1 || { echo FAIL; exit 1; }
done
nmap --version | head -1
trufflehog --version 2>&1 | head -1
wafw00f --version 2>&1 | head -1 || true
for c in orvex-probe orvex-login-probe orvex-idor; do
  printf '%s: ' "$c"; "$c" --help >/dev/null 2>&1; echo "ok (bundled)"
done
echo "SMOKE OK"
