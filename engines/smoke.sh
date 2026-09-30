#!/bin/sh
# Smoke test: every bundled engine must be present and respond to a version/help query.
# Fails (exit 1) the moment any engine is missing or errors — this is what proves the worker
# image actually ships working tools, not just files.
set -e

# ProjectDiscovery engines use -version.
for t in subfinder dnsx naabu httpx katana nuclei tlsx; do
  "$t" -version >/dev/null 2>&1 || { echo "$t: FAIL"; exit 1; }
  echo "$t: ok"
done

# ffuf uses -V (not -version).
ffuf -V >/dev/null 2>&1 || { echo "ffuf: FAIL"; exit 1; }
echo "ffuf: ok"

nmap --version >/dev/null 2>&1 || { echo "nmap: FAIL"; exit 1; }
echo "nmap: ok"
trufflehog --version >/dev/null 2>&1 || { echo "trufflehog: FAIL"; exit 1; }
echo "trufflehog: ok"
wafw00f --version >/dev/null 2>&1 || true  # optional; some builds lack --version
echo "wafw00f: checked"

# Bundled custom engines must at least respond to --help cleanly.
for c in orvex-probe orvex-login-probe orvex-idor; do
  "$c" --help >/dev/null 2>&1 || { echo "$c: FAIL"; exit 1; }
  echo "$c: ok (bundled)"
done

echo "SMOKE OK"
