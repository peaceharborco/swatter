#!/usr/bin/env bash
# test/persist_test.sh — sightings: distinct-bucket counting, dedup, clear, sweep.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-persist.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=7
swatter_store_init
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# swatter_now is real time; bucket=3600. Two adds in the same hour = ONE bucket.
swatter_store_sighting_add 1.2.3.4 55 3600
swatter_store_sighting_add 1.2.3.4 60 3600
check same-bucket-dedup "$(swatter_store_sighting_buckets 1.2.3.4 3)" "1"

# sqlite errors must SURFACE (bounded warn on stderr, rc propagated) instead of
# vanishing into 2>/dev/null — a locked/unwritable DB silently diverging the
# ledger from the firewall is undiagnosable. stdout stays clean for parsers.
_sqlerr="$STATE_DIR/sqlerr"
STATE_DIR_SAVE="$STATE_DIR"; STATE_DIR="/nonexistent-swatter-db-dir"
out="$(_sql "SELECT 1;" 2>"$_sqlerr")"; rc=$?
STATE_DIR="$STATE_DIR_SAVE"
check sql-fail-rc "$([[ $rc -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check sql-fail-stdout-clean "$out" ""
grep -q "sqlite error" "$_sqlerr" && PASS=$((PASS+1)) || { echo "FAIL sql-fail-warn"; FAIL=$((FAIL+1)); }
check sql-ok-stdout "$(_sql "SELECT 42;" 2>/dev/null)" "42"

# Inject 5 older distinct buckets directly, all within 3 days -> 6 total.
db="$STATE_DIR/swatter.db"
now=$(swatter_now)
for k in 1 2 3 4 5; do
  b=$(( (now - k*7200) / 3600 ))
  sqlite3 "$db" "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts) VALUES('1.2.3.4',$b,1,55,$((now-k*7200)));"
done
check six-buckets "$(swatter_store_sighting_buckets 1.2.3.4 3)" "6"

# Clear removes them all.
swatter_store_sighting_clear 1.2.3.4
check cleared "$(swatter_store_sighting_buckets 1.2.3.4 3)" "0"

# Sweep drops rows older than the window.
oldb=$(( (now - 10*86400) / 3600 ))
sqlite3 "$db" "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts) VALUES('9.9.9.9',$oldb,1,55,$((now-10*86400)));"
swatter_store_sighting_sweep 3
check swept "$(swatter_store_sighting_buckets 9.9.9.9 30)" "0"

# Counts.
swatter_store_record 5.5.5.5 temp csf 3600 80 "r" 0
swatter_store_record 6.6.6.6 perm csf 0 95 "r" 0
counts="$(swatter_store_counts)"
check temp-count "$(printf '%s' "$counts" | cut -f1)" "1"
check perm-count "$(printf '%s' "$counts" | cut -f2)" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
