#!/usr/bin/env bash
# test/listfeeds_test.sh — registry generation, per-kind refresh/parse, lookup.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"          # for _ip_in_cidr_file (cidr lookups)
source "${ROOT}/lib/providers/listfeeds.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-lf.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_CURL=1
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Mock curl: emit $FEED_DATA.
FEED_DATA=""
curl() { printf '%s' "$FEED_DATA"; }

# (a) registry generates a provider + refresh fn for every feed name.
for n in firehol_level1 cins dshield blocklist_de et_compromised greensnow; do
  declare -F "provider_${n}" >/dev/null && declare -F "provider_${n}_refresh" >/dev/null \
    && PASS=$((PASS+1)) || { echo "FAIL gen ${n}"; FAIL=$((FAIL+1)); }
done

# (b) ip-kind feed (cins): parse strips comments, lookup hit returns tier score 95.
FEED_DATA=$'1.2.3.4\n5.6.7.8\n# comment line\n'
_listfeed_refresh cins
check cins-lines "$(grep -c . "$STATE_DIR/feeds/cins.txt")" "2"
out="$(provider_cins 1.2.3.4)"
check cins-score "$(printf '%s' "$out" | cut -f1)" "95"
check cins-name  "$(printf '%s' "$out" | cut -f3)" "cins"
provider_cins 9.9.9.9 >/dev/null 2>&1 && { echo "FAIL cins-miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# (c) cidr-kind feed (firehol_level1): membership match, score 95.
FEED_DATA=$'1.10.16.0/20\n0.0.0.0/8\n'
_listfeed_refresh firehol_level1
check fh-score "$(provider_firehol_level1 1.10.16.5 | cut -f1)" "95"
provider_firehol_level1 8.8.8.8 >/dev/null 2>&1 && { echo "FAIL fh-miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# (d) dshield-kind: 'start end prefixlen ...' -> start/prefixlen CIDR, score 95.
FEED_DATA=$'69.5.169.0\t69.5.169.255\t24\t303\tOMNIS\tUS\n'
_listfeed_refresh dshield
check ds-cidr "$(cat "$STATE_DIR/feeds/dshield.cidr")" "69.5.169.0/24"
check ds-score "$(provider_dshield 69.5.169.5 | cut -f1)" "95"

# (e) tier scores: blocklist.de=80, greensnow=70.
FEED_DATA=$'1.1.1.1\n'; _listfeed_refresh blocklist_de
check bde-score "$(provider_blocklist_de 1.1.1.1 | cut -f1)" "80"
FEED_DATA=$'2.2.2.2\n'; _listfeed_refresh greensnow
check gs-score "$(provider_greensnow 2.2.2.2 | cut -f1)" "70"

# (f) missing feed file -> no-data.
rm -f "$STATE_DIR/feeds/et_compromised.txt"
provider_et_compromised 1.2.3.4 >/dev/null 2>&1 && { echo "FAIL et-nofile"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
