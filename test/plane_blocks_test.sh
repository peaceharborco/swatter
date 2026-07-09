#!/usr/bin/env bash
# test/plane_blocks_test.sh — per-plane block state: perm/temp, expiry, upsert,
# plane independence, clear-on-unblock, flatfile no-op.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-plane.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=7
swatter_store_init
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
rc() { "$@" && echo yes || echo no; }

db="$STATE_DIR/swatter.db"

# perm row: is_perm_on true, active_on true.
swatter_store_plane_set 1.1.1.1 cloudflare perm 0
check perm-is_perm    "$(rc swatter_store_is_perm_on 1.1.1.1 cloudflare)" "yes"
check perm-active     "$(rc swatter_store_active_on  1.1.1.1 cloudflare)" "yes"

# temp unexpired: is_perm_on FALSE, active_on TRUE.
swatter_store_plane_set 2.2.2.2 csf temp 3600
check temp-not_perm   "$(rc swatter_store_is_perm_on 2.2.2.2 csf)" "no"
check temp-active     "$(rc swatter_store_active_on  2.2.2.2 csf)" "yes"

# temp expired (forced past expires_at via direct INSERT): active_on FALSE.
now=$(swatter_now)
sqlite3 "$db" "INSERT INTO plane_blocks(ip,plane,kind,expires_at) VALUES('3.3.3.3','csf','temp',$((now-100)));"
check expired-not_perm "$(rc swatter_store_is_perm_on 3.3.3.3 csf)" "no"
check expired-inactive "$(rc swatter_store_active_on  3.3.3.3 csf)" "no"

# perm supersedes temp on same (ip,plane) upsert.
swatter_store_plane_set 4.4.4.4 csf temp 3600
check upsert-temp-first "$(rc swatter_store_is_perm_on 4.4.4.4 csf)" "no"
swatter_store_plane_set 4.4.4.4 csf perm 0
check upsert-now-perm   "$(rc swatter_store_is_perm_on 4.4.4.4 csf)" "yes"
check upsert-exp-zero    "$(sqlite3 "$db" "SELECT expires_at FROM plane_blocks WHERE ip='4.4.4.4' AND plane='csf';")" "0"
# a later temp does NOT downgrade a perm.
swatter_store_plane_set 4.4.4.4 csf temp 3600
check upsert-stay-perm  "$(rc swatter_store_is_perm_on 4.4.4.4 csf)" "yes"

# later temp extends expiry (max).
swatter_store_plane_set 7.7.7.7 csf temp 100
e1="$(sqlite3 "$db" "SELECT expires_at FROM plane_blocks WHERE ip='7.7.7.7' AND plane='csf';")"
swatter_store_plane_set 7.7.7.7 csf temp 100000
e2="$(sqlite3 "$db" "SELECT expires_at FROM plane_blocks WHERE ip='7.7.7.7' AND plane='csf';")"
check temp-extends "$([[ "$e2" -gt "$e1" ]] && echo yes || echo no)" "yes"

# distinct planes independent.
swatter_store_plane_set 5.5.5.5 csf perm 0
swatter_store_plane_set 5.5.5.5 cloudflare temp 3600
check plane-indep-csf-perm  "$(rc swatter_store_is_perm_on 5.5.5.5 csf)" "yes"
check plane-indep-cf-temp   "$(rc swatter_store_is_perm_on 5.5.5.5 cloudflare)" "no"
check plane-indep-cf-active "$(rc swatter_store_active_on  5.5.5.5 cloudflare)" "yes"
check plane-indep-ipset-none "$(rc swatter_store_active_on 5.5.5.5 ipset)" "no"

# plane_clear removes all rows for the ip (simulates unblock).
swatter_store_plane_set 6.6.6.6 csf perm 0
swatter_store_plane_set 6.6.6.6 cloudflare temp 3600
swatter_store_unblock 6.6.6.6
check unblock-clears-csf "$(rc swatter_store_active_on 6.6.6.6 csf)" "no"
check unblock-clears-cf  "$(rc swatter_store_active_on 6.6.6.6 cloudflare)" "no"
check unblock-clears-cnt "$(sqlite3 "$db" "SELECT COUNT(*) FROM plane_blocks WHERE ip='6.6.6.6';")" "0"

# flatfile store: predicates non-zero, plane_set a no-op (no crash).
STORE=flatfile
check flat-set-noop     "$(rc swatter_store_plane_set 8.8.8.8 csf perm 0)" "yes"
check flat-is_perm-off  "$(rc swatter_store_is_perm_on 8.8.8.8 csf)" "no"
check flat-active-off   "$(rc swatter_store_active_on  8.8.8.8 csf)" "no"
check flat-clear-noop   "$(rc swatter_store_plane_clear 8.8.8.8)" "yes"
STORE=sqlite

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
