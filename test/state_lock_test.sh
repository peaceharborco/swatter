#!/usr/bin/env bash
# test/state_lock_test.sh — swatter_with_state_lock: waived is a no-op, a free lock
# is acquired, and a lock held by another open file description blocks (mutual
# exclusion with the scan). Each acquire runs in a subshell so its fd 9 is scoped.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
rc_class() { [[ "$1" -eq 0 ]] && echo zero || echo nonzero; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-lock.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT

# waived -> no-op success (never touches flock)
( SWATTER_NO_LOCK=1; swatter_with_state_lock 1 ); check waived-noop "$(rc_class $?)" "zero"

# free lock -> acquired (rc 0). On a box without flock this is also a no-op success.
( swatter_with_state_lock 1 ); check free-acquire "$(rc_class $?)" "zero"

if command -v flock >/dev/null 2>&1; then
    # Hold the lock on a SEPARATE open file description (fd 8). flock treats each
    # open() independently, so a second acquire (fd 9) must block even in-process.
    exec 8>"${STATE_DIR}/.lock"; flock -n 8 || { echo "FAIL setup: could not seed lock"; FAIL=$((FAIL+1)); }
    ( swatter_with_state_lock 1 ) 2>/dev/null; check excl-blocks "$(rc_class $?)" "nonzero"
    exec 8>&-   # release
    ( swatter_with_state_lock 1 ); check excl-frees "$(rc_class $?)" "zero"
else
    echo "(flock absent — exclusion checks skipped)"
fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
