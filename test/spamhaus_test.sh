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

# A POISONED feed (0.0.0.0/0 present) is rejected; the last-good file survives so a
# MITM'd drop.txt can't score every visitor 100 and mass-ban innocents.
curl() { printf '%s' $'0.0.0.0/0 ; SBLX\n5.5.5.0/24 ; SBLY\n'; }
provider_spamhaus_refresh; check sh-poison-rejected "$?" "1"
check sh-poison-kept-lastgood "$(grep -c . "$STATE_DIR/feeds/spamhaus.cidr")" "2"
check sh-poison-no-zero       "$(grep -c '0.0.0.0/0' "$STATE_DIR/feeds/spamhaus.cidr")" "0"

# swatter_intel_cidr_feed_ok unit checks.
ok() { local g; if printf '%s' "$1" | swatter_intel_cidr_feed_ok; then g=ok; else g=no; fi; check "$2" "$g" "$3"; }
ok $'1.2.3.0/24\n10.0.0.0/9\n' feedok-good        ok
ok $'1.2.3.4\n'               feedok-bare-ip      ok
ok $'2001:db8::/32\n'         feedok-v6-ok        ok
ok $'0.0.0.0/0\n'             feedok-slash0       no
ok $'10.0.0.0/6\n'           feedok-broad-v4     no
ok $'2001:db8::/8\n'         feedok-broad-v6     no
ok $'<html>error</html>\n'   feedok-html         no
ok ''                        feedok-empty        no

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
