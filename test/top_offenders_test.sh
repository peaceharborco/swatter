#!/usr/bin/env bash
# test/top_offenders_test.sh — `swatter top`'s OFFN/TEMP columns must report
# ENFORCED activity only, computed from the actions ledger.
#
# The offenders rollup carries no dry_run dimension: total_offenses counts every
# record (report-mode detections, and operator unblocks, included), and while
# temp_count stopped counting dry-run temps in 15aad86, that fix was not
# retroactive — a rollup counter written before it is inflated forever. Both
# made `top` disagree with the ladder, which counts `actions WHERE dry_run=0`.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-top.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=7
swatter_store_init
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

db="$STATE_DIR/swatter.db"

# Column n of the `top` row for an IP. Fields: ip score offn temp perm channel label
col() { swatter_store_top_offenders 100 | awk -F'\t' -v ip="$1" -v c="$2" '$1==ip {print $c; found=1} END{if(!found) print "MISSING"}'; }
offn() { col "$1" 3; }
temp() { col "$1" 4; }

# --- 1. report-mode records must not inflate either column ------------------
# Three dry-run detections, nothing enforced: the IP is known to the ledger but
# has never been acted on.
swatter_store_record 10.0.0.1 temp csf 3600 80 "dry temp" 1
swatter_store_record 10.0.0.1 temp csf 3600 85 "dry temp" 1
swatter_store_record 10.0.0.1 perm csf 0    95 "dry perm" 1
check dry-only-offn "$(offn 10.0.0.1)" "0"
check dry-only-temp "$(temp 10.0.0.1)" "0"
# still listed — the detection happened, and the score is a detection property
check dry-only-listed "$(col 10.0.0.1 2)" "95"

# --- 2. enforced records are counted ----------------------------------------
swatter_store_record 10.0.0.2 temp csf 3600 80 "real temp" 0
swatter_store_record 10.0.0.2 temp csf 3600 82 "real temp" 0
swatter_store_record 10.0.0.2 perm csf 0    91 "real perm" 0
check enforced-offn "$(offn 10.0.0.2)" "3"
check enforced-temp "$(temp 10.0.0.2)" "2"

# --- 3. mixed: only the enforced half counts --------------------------------
swatter_store_record 10.0.0.3 temp csf 3600 70 "dry temp"  1
swatter_store_record 10.0.0.3 temp csf 3600 75 "real temp" 0
check mixed-offn "$(offn 10.0.0.3)" "1"
check mixed-temp "$(temp 10.0.0.3)" "1"

# --- 4. historical residue: a pre-fix rollup must not be believed ------------
# Simulates a cds1 row written before 15aad86, when dry-run temps bumped
# temp_count. The rollup says 9 temps / 99 offenses; the ledger says the only
# enforced action was one temp. The ledger wins.
now="$(swatter_now)"
sqlite3 "$db" "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
               VALUES('10.0.0.4',${now},${now},88,99,9,0,'stale rollup','csf');"
sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
               VALUES('10.0.0.4',${now},'temp','csf',3600,88,'real temp',0);"
sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
               VALUES('10.0.0.4',${now},'temp','csf',3600,88,'dry temp',1);"
check residue-offn "$(offn 10.0.0.4)" "1"
check residue-temp "$(temp 10.0.0.4)" "1"

# --- 5. an operator unblock is not an offense --------------------------------
# swatter_store_unblock writes an `unblock` action row; the old rollup counted it
# as a +1 offense, so correcting a false positive made the IP look worse.
swatter_store_record 10.0.0.5 temp csf 3600 80 "real temp" 0
swatter_store_unblock 10.0.0.5
check unblock-offn "$(offn 10.0.0.5)" "1"
check unblock-temp "$(temp 10.0.0.5)" "1"

# --- 6. the PERM column still comes from the rollup --------------------------
# It is dry-run guarded already AND carries the operator reset (unblock sets
# perm=0), which a raw ledger count would lose.
swatter_store_record 10.0.0.6 perm csf 0 92 "real perm" 0
check perm-flag "$(col 10.0.0.6 5)" "1"
swatter_store_unblock 10.0.0.6
check perm-flag-after-unblock "$(col 10.0.0.6 5)" "0"

# --- 6b. PERM residue: a pre-fix rollup flag needs enforced evidence ---------
# Before 15aad86 a DRY-RUN perm set perm=1 in the rollup exactly as it inflated
# temp_count. Trusting the flag alone would render PERM=1 alongside OFFN=0 — a
# permanent-ban flag on an IP that was never actually banned.
sqlite3 "$db" "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
               VALUES('10.0.0.7',${now},${now},93,5,0,1,'stale perm flag','csf');"
sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
               VALUES('10.0.0.7',${now},'perm','csf',0,93,'dry perm',1);"
check perm-residue-flag "$(col 10.0.0.7 5)" "0"
check perm-residue-offn "$(offn 10.0.0.7)" "0"

# --- 6c. TEMP is a LIFETIME count and deliberately NOT the ladder's number ----
# Documented divergence, asserted so it cannot drift into an accidental claim of
# parity. The ladder is windowed and resets at an unblock; TEMP is neither.
REPEAT_WINDOW_DAYS=7
old=$(( now - 30*86400 ))
sqlite3 "$db" "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
               VALUES('10.0.0.8',${old},${old},77,0,0,0,'old temp','csf');"
sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
               VALUES('10.0.0.8',${old},'temp','csf',3600,77,'old temp',0);"
check lifetime-temp-counts-old "$(temp 10.0.0.8)" "1"
check ladder-window-excludes   "$(swatter_store_recent_temp_count 10.0.0.8)" "0"
# and after an unblock: TEMP keeps the history, the ladder resets to 0.
check lifetime-temp-after-unblock "$(temp 10.0.0.5)" "1"
check ladder-watermark-resets     "$(swatter_store_recent_temp_count 10.0.0.5)" "0"

# --- 7. shape and limit ------------------------------------------------------
check field-count "$(swatter_store_top_offenders 100 | awk -F'\t' 'NR==1{print NF}')" "7"
check limit-honored "$(swatter_store_top_offenders 2 | grep -c .)" "2"
# highest worst_score first — 10.0.0.1's dry-run 95 outranks 10.0.0.6's 92
check order-desc "$(swatter_store_top_offenders 1 | cut -f1)" "10.0.0.1"

# --- 8. flatfile branch unaffected ------------------------------------------
# It tails the raw jsonl and has no rollup at all, so this fix does not touch it.
STORE=flatfile
printf '{"ts":1,"ip":"10.9.9.9","action":"temp","dry_run":0}\n' > "${STATE_DIR}/ledger.jsonl"
out="$(swatter_store_top_offenders 5)"; rc=$?
check flat-rc    "$rc" "0"
check flat-lines "$(printf '%s' "$out" | grep -c '10.9.9.9')" "1"
STORE=sqlite

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
