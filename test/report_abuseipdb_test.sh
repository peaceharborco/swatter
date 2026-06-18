#!/usr/bin/env bash
# test/report_abuseipdb_test.sh — opt-in gate, category map, dedup, background POST.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report_abuseipdb.sh"
PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rep.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
SWATTER_HAVE_CURL=1; ABUSEIPDB_KEY="k"; ABUSEIPDB_REPORT_TTL=900
POSTS="$STATE_DIR/posts"; : > "$POSTS"
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
curl() { printf '%s\n' "$*" >> "$POSTS"; return 0; }

EV='{"decisive_rule":"high_badpath_repeat","honeypot":0}'

# Off by default (ABUSEIPDB_REPORT unset/false) -> no POST, no marker.
swatter_abuseipdb_report 1.2.3.4 "$EV" "brute"; wait 2>/dev/null
[[ -s "$POSTS" ]] && { echo "FAIL off-no-post"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# Enabled -> background POST with mapped categories (brute -> 18,21); marker written synchronously.
ABUSEIPDB_REPORT="true"
swatter_abuseipdb_report 1.2.3.4 "$EV" "brute"
[[ -f "$STATE_DIR/reported/1.2.3.4" ]] && PASS=$((PASS+1)) || { echo "FAIL marker"; FAIL=$((FAIL+1)); }
wait 2>/dev/null   # let the backgrounded curl finish
grep -q "categories=18,21" "$POSTS" && PASS=$((PASS+1)) || { echo "FAIL cats"; FAIL=$((FAIL+1)); }

# Dedup: a second call within TTL does not POST again.
: > "$POSTS"
swatter_abuseipdb_report 1.2.3.4 "$EV" "brute"; wait 2>/dev/null
[[ -s "$POSTS" ]] && { echo "FAIL dedup"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# Category map for honeypot -> 21,19.
EV2='{"decisive_rule":"honeypot","honeypot":1}'
swatter_abuseipdb_report 9.9.9.9 "$EV2" "trap"; wait 2>/dev/null
grep -q "categories=21,19" "$POSTS" && PASS=$((PASS+1)) || { echo "FAIL cats-honeypot"; FAIL=$((FAIL+1)); }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
