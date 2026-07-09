#!/usr/bin/env bash
# test/plane_wiring_test.sh — scan-loop wiring: _swatter_perm_gate (per-plane noop
# / channel-upgrade / dual-plane heal / legacy backfill) and _swatter_maybe_dual_plane.
# Unit-level: real sqlite store, _swatter_apply_plane + _swatter_audit stubbed to
# record calls. Run: bash test/plane_wiring_test.sh
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-wiring.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce; DIRECT_BACKEND=csf; REPEAT_WINDOW_DAYS=7
INTEL_HARDBLOCK_MIN=100; DUAL_PLANE_HARD_INTEL=true
swatter_store_init

# Stubs: record calls, don't touch a firewall. The stub does NOT write plane_blocks
# (the gate queries real state before calling apply, so unit isolation holds).
APPLY="${STATE_DIR}/apply"; AUDIT="${STATE_DIR}/audit"; : > "$APPLY"; : > "$AUDIT"
# _swatter_apply_plane <ip> <plane> <action> <ttl> <reason> ... [audit_action(11)]
_swatter_apply_plane() { printf '%s %s %s %s\n' "$1" "$2" "$3" "${11:-$3}" >> "$APPLY"; return 0; }
_swatter_audit() { printf '%s %s\n' "$1" "$3" >> "$AUDIT"; }   # ip action
reset() { : > "$APPLY"; : > "$AUDIT"; }
# helper: mark an IP perm on a plane exactly as an enforced block would (offenders.perm + plane row)
seed_perm() { swatter_store_record "$1" perm "$2" 0 91 seed 0; swatter_store_plane_set "$1" "$2" perm 0; }

# ---- _swatter_perm_gate ----------------------------------------------------
# args: <ip> <plane> <want_ch> <folded> <reason> <ev> <rep> <top_vhost> <healthy>

# 1. Not perm anywhere -> falls through (rc 1), no audit, no apply.
reset; _swatter_perm_gate 1.1.1.1 DIRECT csf 91 r '{}' 91 "" 1; check gate-fresh-rc "$?" "1"
check gate-fresh-noapply "$(grep -c . "$APPLY")" "0"; check gate-fresh-noaudit "$(grep -c . "$AUDIT")" "0"

# 2. Perm on the WANT plane, not hard-intel -> noop-perm, rc 0, no apply.
reset; seed_perm 2.2.2.2 csf
_swatter_perm_gate 2.2.2.2 DIRECT csf 91 r '{}' 91 "" 1; check gate-noop-rc "$?" "0"
check gate-noop-audit "$(grep -c '^2.2.2.2 noop-perm' "$AUDIT")" "1"; check gate-noop-noapply "$(grep -c . "$APPLY")" "0"

# 3. Perm on the OTHER plane + new evidence here -> UPGRADE onto this plane.
reset; seed_perm 3.3.3.3 cloudflare
_swatter_perm_gate 3.3.3.3 DIRECT csf 91 r '{}' 91 "" 1; check gate-upgrade-rc "$?" "0"
check gate-upgrade-apply "$(grep -c '^3.3.3.3 DIRECT perm plane-upgrade' "$APPLY")" "1"

# 4. LIVE TEMP on the want plane must NOT noop (B1 guard) -> falls through to ladder.
reset; swatter_store_record 4.4.4.4 temp csf 3600 91 seed 0; swatter_store_plane_set 4.4.4.4 csf temp 3600
_swatter_perm_gate 4.4.4.4 DIRECT csf 91 r '{}' 91 "" 1; check gate-temp-falls-through "$?" "1"
check gate-temp-noaudit "$(grep -c 'noop-perm' "$AUDIT")" "0"

# 5. HARD-INTEL perm on want plane but NOT the other -> heal the missing plane (dual).
reset; seed_perm 5.5.5.5 csf
_swatter_perm_gate 5.5.5.5 DIRECT csf 100 r '{}' 100 "" 1; check gate-heal-rc "$?" "0"
check gate-heal-apply "$(grep -c '^5.5.5.5 VIA_CF perm dual-plane' "$APPLY")" "1"
check gate-heal-noaudit "$(grep -c 'noop-perm' "$AUDIT")" "0"

# 6. HARD-INTEL perm on BOTH planes -> noop (nothing to heal).
reset; seed_perm 5.6.7.8 csf; seed_perm 5.6.7.8 cloudflare
_swatter_perm_gate 5.6.7.8 DIRECT csf 100 r '{}' 100 "" 1
check gate-covered-noop "$(grep -c '^5.6.7.8 noop-perm' "$AUDIT")" "1"; check gate-covered-noapply "$(grep -c . "$APPLY")" "0"

# 7. LEGACY: offenders.perm=1 but NO plane row -> backfill this plane + dual (hard).
reset; swatter_store_record 9.1.1.1 perm csf 0 100 "imported" 0   # perm without plane_set
_swatter_perm_gate 9.1.1.1 DIRECT csf 100 r '{}' 100 "" 1; check gate-legacy-rc "$?" "0"
check gate-legacy-upgrade "$(grep -c '^9.1.1.1 DIRECT perm plane-upgrade' "$APPLY")" "1"
check gate-legacy-dual "$(grep -c '^9.1.1.1 VIA_CF perm dual-plane' "$APPLY")" "1"

# 8. REPORT mode: a perm IP (from a prior enforced run) gets a quiet GLOBAL noop,
#    never a per-plane upgrade (report mode can't write plane_blocks). M1 guard.
#    (A dry-run perm no longer sets offenders.perm at all — store fix — so the
#    phantom-perm upgrade loop is impossible; here we seed an enforced perm.)
reset; SD_R="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rep.XXXXXX")"
( STATE_DIR="$SD_R"; STORE=sqlite; SWATTER_MODE=report; swatter_store_init
  swatter_store_record 9.2.2.2 perm csf 0 100 seed 0    # enforced perm -> offenders.perm=1, no plane row
  _swatter_perm_gate 9.2.2.2 DIRECT csf 100 r '{}' 100 "" 1; echo "rc=$?" > "$SD_R/rc" )
check gate-report-noop-audit "$(grep -c '^9.2.2.2 noop-perm' "$AUDIT")" "1"
check gate-report-noapply "$(grep -c . "$APPLY")" "0"; check gate-report-rc "$(cat "$SD_R/rc")" "rc=0"
rm -rf "$SD_R"

# 9. Flatfile store: no per-plane ledger -> global-perm noop preserved.
reset; SD2="$(mktemp -d "${TMPDIR:-/tmp}/swatter-flat.XXXXXX")"
( STATE_DIR="$SD2"; STORE=flatfile; swatter_store_init
  swatter_store_record 6.6.6.6 perm csf 0 91 seed 0
  _swatter_perm_gate 6.6.6.6 DIRECT csf 91 r '{}' 91 "" 1; echo "rc=$?" > "$SD2/r1"
  _swatter_perm_gate 7.7.7.7 DIRECT csf 91 r '{}' 91 "" 1; echo "rc=$?" > "$SD2/r2" )
check gate-flat-perm-noop "$(cat "$SD2/r1")" "rc=0"; check gate-flat-fresh-through "$(cat "$SD2/r2")" "rc=1"
rm -rf "$SD2"

# ---- _swatter_maybe_dual_plane ---------------------------------------------
# args: <ip> <plane> <action> <folded> <reason> <ev> <rep> <top_vhost> <healthy>

# 10. Hard-intel perm -> second plane (DIRECT -> VIA_CF), fired regardless of primary DID.
reset; _swatter_maybe_dual_plane 8.8.8.8 DIRECT perm 100 r '{}' 100 "" 1
check dual-fires "$(grep -c '^8.8.8.8 VIA_CF perm dual-plane' "$APPLY")" "1"

# 11. Symmetric: primary VIA_CF -> second plane DIRECT.
reset; _swatter_maybe_dual_plane 8.8.4.4 VIA_CF perm 100 r '{}' 100 "" 1
check dual-symmetric "$(grep -c '^8.8.4.4 DIRECT perm dual-plane' "$APPLY")" "1"

# 12. rep below the hard-intel floor -> no dual plane.
reset; _swatter_maybe_dual_plane 9.9.9.9 DIRECT perm 99 r '{}' 99 "" 1
check dual-low-rep "$(grep -c . "$APPLY")" "0"

# 13. temp action -> no dual plane (only fresh perms).
reset; _swatter_maybe_dual_plane 9.9.9.8 DIRECT temp 100 r '{}' 100 "" 1
check dual-temp "$(grep -c . "$APPLY")" "0"

# 14. feature disabled -> no dual plane.
reset; DUAL_PLANE_HARD_INTEL=false
_swatter_maybe_dual_plane 9.9.9.6 DIRECT perm 100 r '{}' 100 "" 1
check dual-disabled "$(grep -c . "$APPLY")" "0"
DUAL_PLANE_HARD_INTEL=true

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
