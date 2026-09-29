#!/bin/sh
# fetch_pd.sh <repo> <name> <version> — download a pinned ProjectDiscovery binary and
# verify it against the release's published checksums.txt before installing.
#
# ProjectDiscovery's checksums file naming is inconsistent across tools, so we try the known
# patterns until one resolves, then verify the zip against it.
set -eu
repo="$1"; name="$2"; ver="$3"
base="https://github.com/${repo}/releases/download/v${ver}"
zip="${name}_${ver}_linux_amd64.zip"
cd /tmp
curl -fsSLO "${base}/${zip}"

sums=""
for cand in "${name}_${ver}_checksums.txt" "${name}-${ver}-checksums.txt" "${name}-checksums.txt"; do
    if curl -fsSLo "checksums.txt" "${base}/${cand}"; then sums="checksums.txt"; break; fi
done
[ -n "${sums}" ] || { echo "no checksums file found for ${name} ${ver}" >&2; exit 22; }

# Verify: the line for our zip must match. (grep the filename, then sha256sum -c.)
grep " ${zip}\$" "${sums}" | sha256sum -c -
unzip -o "${zip}" "${name}"
install -m 0755 "${name}" "/usr/local/bin/${name}"
rm -f "/tmp/${zip}" "/tmp/checksums.txt" "/tmp/${name}"
echo "installed ${name} ${ver} (sha256-verified)"
