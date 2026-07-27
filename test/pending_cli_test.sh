#!/usr/bin/env bash
# test/pending_cli_test.sh — `swatter pending` lists and drains queued intents.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# lib/common.sh:225 does an unconditional `STATE_DIR="/var/lib/swatter"` default
# assignment, which clobbers any STATE_DIR already exported/set the instant this
# process (or a `bin/swatter` subprocess) sources it. So: source common.sh FIRST
# (matching test/pending_retry_test.sh), THEN set STATE_DIR — and for the
# subprocess below, thread it through a SWATTER_CONF file (matching
# test/cli_test.sh, test/rollback_ladder_test.sh) since a bare env export is a
# no-op there too.
source "${ROOT}/lib/common.sh"; source "${ROOT}/lib/store_sqlite.sh"

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-pend.XXXXXX")"
SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-pend-conf.XXXXXX")"
trap 'rm -rf "$STATE_DIR" "$SWATTER_CONF"' EXIT
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$STATE_DIR"
EOF

STORE=sqlite; swatter_store_init
db="$STATE_DIR/swatter.db"
now="$(swatter_now)"
q() { sqlite3 "$db" "$1"; }
ins() { sqlite3 "$db" "INSERT INTO pending_blocks(ip,plane,action,ttl,reason,first_failed,last_attempt,attempts)
                       VALUES('$1','DIRECT','$2',0,'$3',${now},${now},1);"; }
ins 10.0.0.1 perm 'score=91 intel=spamhaus'
ins 10.0.0.2 perm 'honeypot /wp-config.bak'
ins 10.0.0.3 temp 'score=75'

# Invoke the REAL command as a subprocess — this is a CLI test, so simulating
# the drain with raw SQL would assert nothing about `swatter pending`.
sw() { STORE=sqlite SWATTER_CONF="$SWATTER_CONF" \
       bash "${ROOT}/bin/swatter" pending "$@" 2>&1; }

check lists-all-rows "$(sw | grep -cE '^10\.0\.0\.')" "3"

# --dry-run reports what it would clear and changes nothing.
check dry-run-reports "$(sw --drain-perms --dry-run | grep -c 'would clear 2')" "1"
check dry-run-kept    "$(q "SELECT COUNT(*) FROM pending_blocks;")" "3"

# --drain-perms clears perm intents only, leaving temps queued. Happy path:
# full count reported, rc=0.
drain_out="$(sw --drain-perms)"; drain_rc=$?
check drain-reports      "$(printf '%s' "$drain_out" | grep -c 'cleared 2')" "1"
check drain-exit-zero    "$drain_rc" "0"
check drained-perms-gone "$(q "SELECT COUNT(*) FROM pending_blocks WHERE action='perm';")" "0"
check drained-temp-kept  "$(q "SELECT COUNT(*) FROM pending_blocks WHERE action='temp';")" "1"

# --- Partial-failure path: swatter_store_pending_clear failing mid-drain must
# NOT be reported as a complete success (coordinator review finding). Shadow
# `sqlite3` on PATH with a wrapper that fails ONLY the DELETE for one specific
# IP (simulating a locked/busy DB — plausible during a concurrent */5 retry
# scan, exactly when this command gets run) and passes every other call
# through to the real binary untouched.
REAL_SQLITE3="$(command -v sqlite3)"
FAKEBIN="$(mktemp -d "${TMPDIR:-/tmp}/swatter-pend-fakebin.XXXXXX")"
cat > "$FAKEBIN/sqlite3" <<EOF
#!/usr/bin/env bash
sql="\${@: -1}"
case "\$sql" in
  *"DELETE FROM pending_blocks"*"ip='10.0.0.9'"*)
    echo "Error: database is locked" >&2
    exit 5
    ;;
esac
exec "$REAL_SQLITE3" "\$@"
EOF
chmod +x "$FAKEBIN/sqlite3"

ins 10.0.0.8 perm 'score=95'
ins 10.0.0.9 perm 'score=96'
fail_out="$(PATH="$FAKEBIN:$PATH" sw --drain-perms)"; fail_rc=$?
check partial-count-reported "$(printf '%s' "$fail_out" | grep -c 'cleared 1 of 2')" "1"
check partial-failure-visible "$(printf '%s' "$fail_out" | grep -c 'FAILED')" "1"
check partial-exit-nonzero "$([[ "$fail_rc" -ne 0 ]] && echo yes || echo no)" "yes"
check partial-failed-row-kept    "$(q "SELECT COUNT(*) FROM pending_blocks WHERE ip='10.0.0.9';")" "1"
check partial-succeeded-row-gone "$(q "SELECT COUNT(*) FROM pending_blocks WHERE ip='10.0.0.8';")" "0"
rm -rf "$FAKEBIN"

# Empty queue is reported, not an error.
sqlite3 "$db" "DELETE FROM pending_blocks;"
check empty-queue "$(sw | grep -c 'queue is empty')" "1"

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
