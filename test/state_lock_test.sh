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

# Regression: swatter_with_state_lock used to open fd 9 via a bare `exec
# 9>lock 2>/dev/null` — an exec with no command word applies ALL its
# redirections to the current shell PERMANENTLY, so that unbraced 2>/dev/null
# silently killed fd 2 for the rest of the process, not just for that one open
# attempt. Every log_* call issued after a successful lock acquisition (by
# unblock, import-bans, rollback-ladder, and the scan's own lock path) went
# dark with no error to notice. Confirm a log_* call after acquiring still
# reaches stderr. Wrapped in its own $(...) subshell so the acquired fd 9 is
# scoped like the other cases above.
out="$( { swatter_with_state_lock 1; log_warn "post-lock stderr probe"; } 2>&1 )"
case "$out" in
    *"post-lock stderr probe"*) PASS=$((PASS+1)) ;;
    *) echo "FAIL post-lock-stderr-survives: got '${out}'"; FAIL=$((FAIL+1)) ;;
esac

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
