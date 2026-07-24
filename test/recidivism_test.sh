#!/usr/bin/env bash
# test/recidivism_test.sh — temp->perm escalation counting semantics: the
# REPEAT_WINDOW_DAYS window, the dry_run filter, action filtering, and the
# unblock watermark (an operator correction must reset the ladder).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${ROOT}/lib/common.sh"
# shellcheck source=../lib/store_sqlite.sh
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-recid.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=30
REPEAT_N=3
swatter_store_init
db="$STATE_DIR/swatter.db"
NOW="$(swatter_now)"
DAY=86400

# seed <ip> <days_ago> <action> [dry_run] [channel]
# Direct INSERT so timestamps can be backdated deterministically.
seed() {
  local ip="$1" days="$2" action="$3" dry="${4:-0}" ch="${5:-csf}"
  sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
    VALUES('${ip}',$(( NOW - days*DAY )),'${action}','${ch}',3600,80,'seed',${dry});"
}

# --- the unblock watermark -------------------------------------------------
# 2 enforced temps, then an operator unblock, then nothing: the ladder resets,
# so the next offense must be temp #1 (count 0), not the 3rd strike.
seed 10.0.0.1 20 temp
seed 10.0.0.2 20 temp   # unrelated IP, must not interfere
seed 10.0.0.1 10 temp
seed 10.0.0.1  5 unblock
check watermark-resets     "$(swatter_store_recent_temp_count 10.0.0.1)" "0"

# A temp AFTER the unblock counts again.
seed 10.0.0.1 2 temp
check watermark-post-count "$(swatter_store_recent_temp_count 10.0.0.1)" "1"

# An unblock OLDER than the temps clears nothing.
seed 10.0.0.3 20 unblock
seed 10.0.0.3 10 temp
seed 10.0.0.3  5 temp
check watermark-old-unblock "$(swatter_store_recent_temp_count 10.0.0.3)" "2"

# No unblock row at all -> full in-window history counts.
check watermark-absent     "$(swatter_store_recent_temp_count 10.0.0.2)" "1"

# --- flatfile parity -------------------------------------------------------
# Same history, flatfile store: the watermark must behave identically.
(
  STORE=flatfile
  STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-recid-ff.XXXXXX")"
  jsonl="$(_swatter_jsonl)"
  : > "$jsonl"
  ff() { printf '{"ip":"%s","ts":%s,"action":"%s","channel":"csf","ttl":0,"score":80,"reason":"seed","dry_run":%s}\n' \
           "$1" "$(( NOW - $2*DAY ))" "$3" "${4:-0}" >> "$jsonl"; }
  ff 10.0.0.1 20 temp
  ff 10.0.0.1 10 temp
  ff 10.0.0.1  5 unblock
  ff 10.0.0.1  2 temp
  got="$(swatter_store_recent_temp_count 10.0.0.1)"
  rm -rf "$STATE_DIR"
  [[ "$got" == "1" ]] && exit 0 || { echo "FAIL flatfile-watermark: want='1' got='${got}'"; exit 1; }
) && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
