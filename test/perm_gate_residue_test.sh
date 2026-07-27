#!/usr/bin/env bash
# test/perm_gate_residue_test.sh — the legacy perm backfill needs enforced
# evidence in the ledger, not just the offenders.perm rollup flag.
#
# Before 15aad86 a DRY-RUN perm set that flag exactly as it inflated temp_count,
# and the rollup is never recomputed. _swatter_perm_gate's third branch turns
# the flag into a real permanent ban when no plane_blocks row exists — so on a
# host that ran report mode before enforce, a ghost that was never banned gets
# permed on sight, skipping the ladder and the CRITICAL-single bar entirely.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"
# STATE_DIR must be set AFTER sourcing common.sh: common.sh unconditionally
# assigns STATE_DIR="/var/lib/swatter" (line ~225), so setting it earlier (and
# exporting it) gets clobbered — matches the convention in plane_blocks_test.sh
# and its siblings.
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-residue.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce
swatter_store_init
db="$STATE_DIR/swatter.db"
APPLIED="$STATE_DIR/applied.log"

# Stub the side effects; the gate's own branch logic stays real.
_swatter_apply_plane() { printf '%s\n' "$1" >> "$APPLIED"; }
_swatter_maybe_dual_plane() { :; }
_swatter_audit() { :; }

now="$(swatter_now)"
rollup() {  # <ip> <perm_flag>
  sqlite3 "$db" "INSERT OR REPLACE INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
                 VALUES('$1',${now},${now},93,1,0,$2,'x','csf');"
}
enforced_perm() {  # <ip>
  sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
                 VALUES('$1',${now},'perm','csf',0,93,'real perm',0);"
}
dry_perm() {  # <ip>
  sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
                 VALUES('$1',${now},'perm','csf',0,93,'dry perm',1);"
}
# Returns 0 (handled) or 1 (fall through to the ladder). No plane_blocks rows
# are ever seeded, so every case lands on the third branch under test.
gate() { : > "$APPLIED"; _swatter_perm_gate "$1" DIRECT csf 93 "r" '{}' 0 "v" 1; echo "$?"; }
# grep -c on a no-match file still prints "0" AND exits 1, so a naive
# `grep -c . "$APPLIED" || echo 0` double-prints "0\n0" for the empty case.
# Count lines directly instead; wc -l always exits 0.
applied() { wc -l < "$APPLIED" 2>/dev/null | tr -d ' '; }

# Residue: rollup says perm, ledger has only a DRY-RUN perm. Must NOT backfill.
rollup 10.0.0.1 1; dry_perm 10.0.0.1
check residue-falls-through "$(gate 10.0.0.1)" "1"
check residue-no-ban        "$(applied)"       "0"

# A real legacy import: rollup perm + an enforced perm row. Must still backfill.
rollup 10.0.0.2 1; enforced_perm 10.0.0.2
check legacy-handled "$(gate 10.0.0.2)" "0"
check legacy-backfills "$(applied)"     "1"

# Flag cleared by an operator unblock: never backfills, evidence or not.
rollup 10.0.0.3 0; enforced_perm 10.0.0.3
check unblocked-falls-through "$(gate 10.0.0.3)" "1"
check unblocked-no-ban        "$(applied)"       "0"

# --- Fail-closed guard on the helper's OWN error path ---
#
# The three cases above all assume swatter_store_has_enforced_perm's query
# SUCCEEDS and returns a real count. That's not the only way offenders.perm=1
# can meet a ghost: the ledger query itself can fail outright (missing
# 'actions' table, corrupt db, lock timeout) — and _sqlq returns empty stdout
# on any such failure. A naive `[[ "$n" != "0" ]]` reads that empty string as
# "yes, evidence found", silently reopening the exact ghost-ban bug this file
# exists to close. These two cases assert what happens when the query can't
# run at all, not just when it runs and returns zero.

# Missing 'actions' table: offenders.perm=1 survives (its own table is
# untouched by the DROP), but the ledger query the gate depends on cannot
# run. Must fall through, not backfill.
rollup 10.0.0.4 1
sqlite3 "$db" "DROP TABLE actions;"
check missing-table-falls-through "$(gate 10.0.0.4)" "1"
check missing-table-no-ban        "$(applied)"       "0"
# Restore the schema before anything else runs against this db.
# CREATE TABLE IF NOT EXISTS is idempotent — leaves the offenders rows
# already seeded (including 10.0.0.1-3 above) untouched.
swatter_store_init >/dev/null 2>&1

# Absent db file entirely (e.g. a rename/lock window). Exercises the
# helper's OTHER guard (`[[ -e "$(_swatter_db)" ]] || return 1`) — a
# different line than the missing-table case above. Tested directly against
# the helper rather than through the full gate: swatter_store_is_perm (the
# other half of the gate's conjunct) ALSO queries this same absent db and
# happens to fail closed on its own, so driving this through the gate would
# only prove is_perm's guard works, not has_enforced_perm's — the two would
# be indistinguishable from the gate's return code alone.
rollup 10.0.0.5 1
mv "$db" "${db}.hidden"
absent_db_rc="$(swatter_store_has_enforced_perm 10.0.0.5; echo $?)"
mv "${db}.hidden" "$db"
check absent-db-fails-closed "$absent_db_rc" "1"

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
