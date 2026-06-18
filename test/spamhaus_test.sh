#!/usr/bin/env bash
# test/spamhaus_test.sh — EDROP removed: a single drop.txt fetch populates the feed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/providers/spamhaus.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sh.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_CURL=1
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Mock curl: count calls; emit drop.txt-format lines.
CURL_CALLS=0
curl() { CURL_CALLS=$((CURL_CALLS+1)); printf '%s' $'1.10.16.0/20 ; SBL256894\n2.56.0.0/24 ; SBL999\n'; }

provider_spamhaus_refresh
check sh-single-fetch "$CURL_CALLS" "1"
check sh-cidrs "$(grep -c . "$STATE_DIR/feeds/spamhaus.cidr")" "2"
check sh-lookup "$(provider_spamhaus 1.10.16.5 | cut -f1)" "100"
# no SPAMHAUS_EDROP_URL variable should remain
[[ -z "${SPAMHAUS_EDROP_URL:-}" ]] && PASS=$((PASS+1)) || { echo "FAIL sh-edrop-var-gone"; FAIL=$((FAIL+1)); }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
