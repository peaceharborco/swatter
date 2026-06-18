#!/usr/bin/env bash
# test/abuseipdb_blocklist_test.sh — opt-in daily blocklist: refresh + lookup.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/providers/abuseipdb_blocklist.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-abl.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_CURL=1; ABUSEIPDB_KEY="testkey"; ABUSEIPDB_BLOCKLIST_CONFIDENCE=90
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

FEED_DATA=$'1.2.3.4\n5.6.7.8\n'
curl() { printf '%s' "$FEED_DATA"; }

provider_abuseipdb_blocklist_refresh
check abl-lines "$(grep -c . "$STATE_DIR/feeds/abuseipdb_blocklist.txt")" "2"
check abl-score "$(provider_abuseipdb_blocklist 1.2.3.4 | cut -f1)" "90"
check abl-name  "$(provider_abuseipdb_blocklist 1.2.3.4 | cut -f3)" "abuseipdb_blocklist"
provider_abuseipdb_blocklist 9.9.9.9 >/dev/null 2>&1 && { echo "FAIL abl-miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# No key -> refresh no-ops (no fetch, no file), lookup no-data.
rm -f "$STATE_DIR/feeds/abuseipdb_blocklist.txt"
ABUSEIPDB_KEY=""
provider_abuseipdb_blocklist_refresh >/dev/null 2>&1
[[ -f "$STATE_DIR/feeds/abuseipdb_blocklist.txt" ]] && { echo "FAIL abl-nokey-file"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
provider_abuseipdb_blocklist 1.2.3.4 >/dev/null 2>&1 && { echo "FAIL abl-nokey-lookup"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
