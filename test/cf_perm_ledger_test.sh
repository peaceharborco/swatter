#!/usr/bin/env bash
# test/cf_perm_ledger_test.sh — a Cloudflare-plane 'perm' is TTL-emulated (swept at
# ~3d), so it must be recorded in plane_blocks as a TEMP with that real lifetime,
# not a never-expiring perm — else is_perm_on(cloudflare) stays true forever and a
# returning offender is never re-blocked after the CF rule is swept.
# Exercises the real _swatter_apply_plane with the firewall backends stubbed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-cfperm.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce; DIRECT_BACKEND=csf; TTL_LADDER="3600 21600 86400 259200"
_SW_TOTAL_BLOCKS=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0; MAX_BLOCKS_PER_RUN=100
swatter_store_init

# Stub only the firewall backends + side effects; keep the REAL store + ledger.
swatter_is_never_block() { return 1; }
swatter_cf_manages_plane() { return 0; }
swatter_cf_block() { return 0; }
swatter_block_direct_perm() { return 0; }
swatter_block_direct_temp() { return 0; }
swatter_store_sighting_clear() { :; }
swatter_abuseipdb_report() { :; }
_swatter_audit() { :; }

# VIA_CF perm -> ledger must be a TEMP (expiring), NOT a perm.
_swatter_apply_plane 1.2.3.4 VIA_CF perm 0 "cf perm" "x.com" 1 91 '{}' 91
check cf-perm-not-perm   "$(swatter_store_is_perm_on 1.2.3.4 cloudflare && echo yes || echo no)" "no"
check cf-perm-active-now "$(swatter_store_active_on  1.2.3.4 cloudflare && echo yes || echo no)" "yes"
# ...and its expiry is ~the ladder max (3d), not 0.
exp="$(sqlite3 "$(_swatter_db)" "SELECT expires_at FROM plane_blocks WHERE ip='1.2.3.4' AND plane='cloudflare';")"
now="$(swatter_now)"
check cf-perm-expires-future "$([[ "$exp" -gt "$now" ]] && echo yes || echo no)" "yes"

# DIRECT perm -> genuine perm (never expires).
_swatter_apply_plane 5.6.7.8 DIRECT perm 0 "csf perm" "" 1 91 '{}' 91
check direct-perm-is-perm "$(swatter_store_is_perm_on 5.6.7.8 csf && echo yes || echo no)" "yes"
dexp="$(sqlite3 "$(_swatter_db)" "SELECT expires_at FROM plane_blocks WHERE ip='5.6.7.8' AND plane='csf';")"
check direct-perm-exp-zero "$dexp" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
