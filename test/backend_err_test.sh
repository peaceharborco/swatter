#!/usr/bin/env bash
# test/backend_err_test.sh — a `failed` CF block records the captured backend
# error as a structured evidence.backend_err (diagnosability), the rest of the
# evidence is preserved, and a later SUCCESS carries no stale error (no bleed).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block_cf.sh"
source "${ROOT}/lib/score.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP (no jq)"; echo "Total: 0 passed, 0 failed"; exit 0; }
PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL $n: want='$w' got='$g'"; FAIL=$((FAIL+1)); fi; }

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-be.XXXXXX")"; trap 'rm -rf "$LOG_DIR"' EXIT
SWATTER_HAVE_JQ=1; SWATTER_MODE="enforce"; MAX_BLOCKS_PER_RUN=100
_SW_TOTAL_BLOCKS=0; SWATTER_RUN_BREAKER=0; SWATTER_RUN_ACTED=0; CF_MODE="direct"; DIRECT_BACKEND="csf"

swatter_store_sighting_clear() { :; }; swatter_store_record() { :; }; swatter_abuseipdb_report() { :; }
swatter_is_never_block()  { return 1; }        # not exempt
swatter_classify()        { echo "CF"; }       # -> cloudflare plane (non-DIRECT)
swatter_cf_manages_plane(){ return 0; }
# A CF block that fails and captures a (fake) API error, like the real path.
swatter_cf_block() { SWATTER_LAST_BACKEND_ERR="cloudflare 429 too many requests"; return 1; }

: > "$LOG_DIR/decisions.jsonl"
_swatter_execute_block 9.9.9.9 temp 3600 91 "probed secret files" '{"badpath_cat":"CRITICAL"}' 0 0 x.com 1
rec="$(tail -1 "$LOG_DIR/decisions.jsonl")"
check action-failed "$(printf '%s' "$rec" | jq -r '.action')" "failed"
check backend-err   "$(printf '%s' "$rec" | jq -r '.evidence.backend_err')" "cloudflare 429 too many requests"
check ev-preserved  "$(printf '%s' "$rec" | jq -r '.evidence.badpath_cat')" "CRITICAL"

# No cross-IP bleed: a SUCCESSFUL block right after must not carry a backend_err.
swatter_cf_block() { return 0; }               # success; does not set the global
_SW_TOTAL_BLOCKS=0
_swatter_execute_block 8.8.8.8 temp 3600 91 "r" '{}' 0 0 x.com 1
rec2="$(tail -1 "$LOG_DIR/decisions.jsonl")"
check success-not-failed "$(printf '%s' "$rec2" | jq -r '.action')" "temp"
check success-no-bleed   "$(printf '%s' "$rec2" | jq -r '.evidence.backend_err // "none"')" "none"

# Cross-PLANE bleed: CF failure on IP1, then a DIRECT/CSF failure on IP2 — IP2's
# failed record must NOT inherit IP1's cause (per-IP clear runs before dispatch;
# the direct plane sets no cause).
swatter_block_direct_temp() { return 1; }; swatter_block_direct_perm() { return 1; }
swatter_cf_block() { SWATTER_LAST_BACKEND_ERR="ip1 cf error"; return 1; }
swatter_classify() { echo "CF"; };   _SW_TOTAL_BLOCKS=0
_swatter_execute_block 1.1.1.1 temp 3600 91 r '{}' 0 0 x.com 1     # IP1 CF fail (sets global)
swatter_classify() { echo "DIRECT"; }; _SW_TOTAL_BLOCKS=0
_swatter_execute_block 2.2.2.2 temp 3600 91 r '{}' 0 0 "" 1        # IP2 CSF fail (sets nothing)
rec3="$(tail -1 "$LOG_DIR/decisions.jsonl")"
check csf-channel          "$(printf '%s' "$rec3" | jq -r '.channel')" "csf"
check cross-plane-no-bleed "$(printf '%s' "$rec3" | jq -r '.evidence.backend_err // "none"')" "none"

# Direct/CSF failure WITH a captured cause is recorded too (channel-agnostic slot).
swatter_block_direct_temp() { SWATTER_LAST_BACKEND_ERR="csf -td failed: deny list full"; return 1; }
swatter_classify() { echo "DIRECT"; }; _SW_TOTAL_BLOCKS=0
_swatter_execute_block 3.3.3.3 temp 3600 91 r '{}' 0 0 "" 1
rec4="$(tail -1 "$LOG_DIR/decisions.jsonl")"
check direct-channel        "$(printf '%s' "$rec4" | jq -r '.channel')" "csf"
check direct-cause-recorded "$(printf '%s' "$rec4" | jq -r '.evidence.backend_err')" "csf -td failed: deny list full"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
