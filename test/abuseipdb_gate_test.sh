#!/usr/bin/env bash
# test/abuseipdb_gate_test.sh — ABUSEIPDB_REPORT_MIN_ACTION gates outbound reports:
# default 'perm' reports only high-confidence perm bans (never a first-seen temp or
# a swarm-corroborated temp); 'temp' reports both. The reporter is stubbed to
# record calls; the real store + _swatter_apply_plane run.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/score.sh"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-abgate.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce; DIRECT_BACKEND=csf; TTL_LADDER="3600 21600 86400 259200"
MAX_BLOCKS_PER_RUN=100; _SW_TOTAL_BLOCKS=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
swatter_store_init

swatter_is_never_block()      { return 1; }
swatter_cf_manages_plane()    { return 0; }
swatter_block_direct_temp()   { return 0; }
swatter_block_direct_perm()   { return 0; }
swatter_store_sighting_clear(){ :; }
_swatter_audit()              { :; }
REPORTED="$STATE_DIR/reported"; : > "$REPORTED"
swatter_abuseipdb_report()    { echo "$1" >> "$REPORTED"; }

# Default (perm): a TEMP block does NOT report; a PERM block DOES.
: > "$REPORTED"; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 1.1.1.1 DIRECT temp 3600 r "" 1 91 '{}' 0
check default-temp-noreport "$(grep -c '1.1.1.1' "$REPORTED")" "0"
_SW_TOTAL_BLOCKS=0
_swatter_apply_plane 2.2.2.2 DIRECT perm 0 r "" 1 95 '{}' 0
check default-perm-reports  "$(grep -c '2.2.2.2' "$REPORTED")" "1"

# min=temp: a TEMP block DOES report (opt-in to the old behavior).
: > "$REPORTED"; _SW_TOTAL_BLOCKS=0
ABUSEIPDB_REPORT_MIN_ACTION=temp _swatter_apply_plane 3.3.3.3 DIRECT temp 3600 r "" 1 91 '{}' 0
check tempmode-temp-reports "$(grep -c '3.3.3.3' "$REPORTED")" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
