#!/usr/bin/env bash
# test/cf_perm_ledger_test.sh — a Cloudflare-plane 'perm' is TTL-emulated (swept at
# ~3d), so it is recorded in plane_blocks as an EXPIRING perm: is_perm_on holds
# while the edge rule is live (so _swatter_perm_gate noops instead of re-applying
# a plane-upgrade every scan — the v2.9.0 upgrade-storm bug), and lapses at expiry
# so a returning offender is re-blocked after the sweep.
# Exercises the real _swatter_apply_plane with the firewall backends stubbed.
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

# VIA_CF perm -> ledger is an EXPIRING perm: perm while live, expiry ~ladder max.
_swatter_apply_plane 1.2.3.4 VIA_CF perm 0 "cf perm" "x.com" 1 91 '{}' 91
check cf-perm-is-perm-live "$(swatter_store_is_perm_on 1.2.3.4 cloudflare && echo yes || echo no)" "yes"
check cf-perm-active-now   "$(swatter_store_active_on  1.2.3.4 cloudflare && echo yes || echo no)" "yes"
kind="$(sqlite3 "$(_swatter_db)" "SELECT kind FROM plane_blocks WHERE ip='1.2.3.4' AND plane='cloudflare';")"
exp="$(sqlite3 "$(_swatter_db)" "SELECT expires_at FROM plane_blocks WHERE ip='1.2.3.4' AND plane='cloudflare';")"
now="$(swatter_now)"
check cf-perm-kind "$kind" "perm"
check cf-perm-expires-future "$([[ "$exp" -gt "$now" ]] && echo yes || echo no)" "yes"

# ...and once the expiry passes (rule swept at the edge), it is neither perm nor
# active — the gate falls through and a returning offender is re-blocked.
sqlite3 "$(_swatter_db)" "UPDATE plane_blocks SET expires_at=$(( now - 10 )) WHERE ip='1.2.3.4';"
check cf-perm-lapsed-notperm "$(swatter_store_is_perm_on 1.2.3.4 cloudflare && echo yes || echo no)" "no"
check cf-perm-lapsed-inactive "$(swatter_store_active_on 1.2.3.4 cloudflare && echo yes || echo no)" "no"

# DIRECT perm -> genuine perm (never expires; exp stays 0, always perm/active).
_swatter_apply_plane 5.6.7.8 DIRECT perm 0 "csf perm" "" 1 91 '{}' 91
check direct-perm-is-perm "$(swatter_store_is_perm_on 5.6.7.8 csf && echo yes || echo no)" "yes"
dexp="$(sqlite3 "$(_swatter_db)" "SELECT expires_at FROM plane_blocks WHERE ip='5.6.7.8' AND plane='csf';")"
check direct-perm-exp-zero "$dexp" "0"
check direct-perm-active "$(swatter_store_active_on 5.6.7.8 csf && echo yes || echo no)" "yes"

# A true perm can never be downgraded/shortened by a later temp on the same plane.
swatter_store_plane_set 5.6.7.8 csf temp 3600
dexp2="$(sqlite3 "$(_swatter_db)" "SELECT kind||' '||expires_at FROM plane_blocks WHERE ip='5.6.7.8' AND plane='csf';")"
check true-perm-sticky "$dexp2" "perm 0"

# --- THE UPGRADE-STORM REGRESSION (v2.9.0) ----------------------------------
# A CF-emulated perm used to be recorded kind='temp', so is_perm_on(cloudflare)
# was permanently false and _swatter_perm_gate re-applied a "plane-upgrade" perm
# on EVERY scan, burning MAX_BLOCKS_PER_RUN. Now: while the edge rule is live the
# gate must NOOP; after expiry it must fall through/backfill (re-block).
APPLY="${STATE_DIR}/apply"; : > "$APPLY"

# Seed a CF-emulated perm exactly as an enforced scan records one.
swatter_store_record 9.9.8.7 perm cloudflare 259200 95 "score=95" 0
swatter_store_plane_set 9.9.8.7 cloudflare perm 259200

# Subshell so the apply stub never shadows the real function at file scope
# (shellcheck SC2218) and needs no restore afterwards.
(
    _swatter_apply_plane() { printf '%s %s %s %s\n' "$1" "$2" "$3" "${11:-$3}" >> "$APPLY"; return 0; }
    # Live: 5 consecutive gate calls -> 5 noops, ZERO applies.
    for _ in 1 2 3 4 5; do
        _swatter_perm_gate 9.9.8.7 VIA_CF cloudflare 95 r '{}' 0 "x.com" 1 >/dev/null
    done
    # Expired (edge rule swept): the gate must RE-BLOCK (backfill), not noop.
    sqlite3 "$(_swatter_db)" "UPDATE plane_blocks SET expires_at=$(( now - 10 )) WHERE ip='9.9.8.7';"
    _swatter_perm_gate 9.9.8.7 VIA_CF cloudflare 95 r '{}' 0 "x.com" 1 >/dev/null
)
# 5 live calls produced zero applies; the 1 post-expiry call re-blocked.
check storm-noop-noapply "$(grep -c -v '^9.9.8.7 VIA_CF perm plane-upgrade$' "$APPLY")" "0"
check storm-expired-reblocks "$(grep -c '^9.9.8.7 VIA_CF perm plane-upgrade' "$APPLY")" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
