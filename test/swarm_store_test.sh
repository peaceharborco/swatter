#!/usr/bin/env bash
# test/swarm_store_test.sh — swatter_store_perm_ips_since: delta of confirmed perm bans.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

run_suite() {   # $1 = sqlite|flatfile
    STORE="$1"
    STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sst.XXXXXX")"
    swatter_store_init
    # Fixed clock per record so the cursor math is deterministic.
    swatter_now() { echo "$FAKE_NOW"; }
    FAKE_NOW=1000; swatter_store_record 1.1.1.1 perm csf 0 90 "old ban" 0        # before cursor
    FAKE_NOW=2000; swatter_store_record 2.2.2.2 perm csf 0 90 "new ban" 0        # after cursor
    FAKE_NOW=2100; swatter_store_record 3.3.3.3 perm csf 0 90 "dry ban" 1        # dry-run: excluded
    FAKE_NOW=2200; swatter_store_record 4.4.4.4 temp csf 3600 75 "temp" 0        # temp: excluded
    FAKE_NOW=2300; swatter_store_record 5.5.5.5 perm csf 0 90 "unbanned later" 0
    FAKE_NOW=2400; swatter_store_record 5.5.5.5 unblock csf 0 0 "manual" 0       # unblocked: excluded
    if [[ "$STORE" == "sqlite" ]]; then
        _sql "UPDATE offenders SET perm=0 WHERE ip='5.5.5.5';"                   # unblock clears perm state
    fi
    local out; out="$(swatter_store_perm_ips_since 1500)"
    check "${STORE}-only-new" "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" "2.2.2.2 "
    check "${STORE}-ts"       "$(printf '%s\n' "$out" | cut -f2)" "2000"
    check "${STORE}-since0-includes-old" "$(swatter_store_perm_ips_since 0 | cut -f1 | grep -c .)" "2"
    unset -f swatter_now
    rm -rf "$STATE_DIR"
}

run_suite flatfile
if command -v sqlite3 >/dev/null 2>&1; then SWATTER_HAVE_SQLITE=1; run_suite sqlite; fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
