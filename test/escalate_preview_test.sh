#!/usr/bin/env bash
# test/escalate_preview_test.sh — offline escalation preview: correct candidate
# selection, and the read-only guarantees that make it safe to run on prod.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-prev.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_N=3; REPEAT_WINDOW_DAYS=30
swatter_store_init
db="$STATE_DIR/swatter.db"; NOW="$(swatter_now)"; DAY=86400
seed() { sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('$1',$(( NOW - $2*DAY )),'$3','csf',3600,80,'seed',${4:-0});"; }

# Escalates at 30d (3 temps in-window), not at 7d.
seed 10.1.0.1 25 temp; seed 10.1.0.1 12 temp; seed 10.1.0.1 1 temp
# Only 2 in-window. The decider counts the PENDING offense — `(( prior + 1 >=
# thresh ))` in lib/score.sh — so 2 PRIOR temps at REPEAT_N=3 means the very
# next offense is a permanent ban. This IP is the whole reason the preview
# exists; a `HAVING c >= REPEAT_N` bar omitted exactly this row, handing the
# operator a clean list one offense before the ladder fired.
seed 10.1.0.2 25 temp; seed 10.1.0.2 1 temp
# 3 temps but one is dry_run=1 -> only 2 enforced -> still a candidate, but as
# 2 (report-mode temps never count toward the ladder).
seed 10.1.0.3 25 temp; seed 10.1.0.3 12 temp 1; seed 10.1.0.3 1 temp
# 3 temps but unblocked after the first two -> watermark drops them, leaving 1
# -> below REPEAT_N-1 -> not a candidate.
seed 10.1.0.4 25 temp; seed 10.1.0.4 20 temp; seed 10.1.0.4 15 unblock; seed 10.1.0.4 1 temp
# A single in-window temp -> 1 prior, next offense is only its 2nd -> excluded.
seed 10.1.0.5 3 temp

out="$(REPEAT_WINDOW_DAYS=30 swatter_escalate_preview 30)"
check prev-includes    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="10.1.0.1"{print $2}')" "3"
check prev-includes-at-bar "$(printf '%s\n' "$out" | awk -F'\t' '$1=="10.1.0.1"{print $4}')" "at-bar"
# The off-by-one regression guard: REPEAT_N-1 priors MUST be listed, marked as
# one-away, because the pending offense is what tips them over.
check prev-incl-oneaway     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="10.1.0.2"{print $2}')" "2"
check prev-oneaway-status   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="10.1.0.2"{print $4}')" "one-away"
check prev-dryrun-not-counted "$(printf '%s\n' "$out" | awk -F'\t' '$1=="10.1.0.3"{print $2}')" "2"
check prev-excl-unblk  "$(printf '%s\n' "$out" | grep -c '^10\.1\.0\.4' || true)" "0"
check prev-excl-one    "$(printf '%s\n' "$out" | grep -c '^10\.1\.0\.5' || true)" "0"
check prev-7d-empty    "$(REPEAT_WINDOW_DAYS=7 swatter_escalate_preview 7 | grep -c . || true)" "0"

# REPEAT_N=1 degenerates the bar to 0, which must mean "any IP with an enforced
# in-window temp" — not a SQL error and not an empty list.
n1="$(REPEAT_N=1 REPEAT_WINDOW_DAYS=30 swatter_escalate_preview 30)"
check prev-n1-includes-single "$(printf '%s\n' "$n1" | awk -F'\t' '$1=="10.1.0.5"{print $2}')" "1"
check prev-n1-status          "$(printf '%s\n' "$n1" | awk -F'\t' '$1=="10.1.0.5"{print $4}')" "at-bar"

# Read-only: no cursor file created, ledger row count unchanged.
before="$(sqlite3 "$db" 'SELECT COUNT(*) FROM actions;')"
swatter_escalate_preview 30 >/dev/null
after="$(sqlite3 "$db" 'SELECT COUNT(*) FROM actions;')"
check prev-readonly-rows "$after" "$before"
check prev-no-cursor     "$([[ -e "${STATE_DIR}/cursors.tsv" ]] && echo yes || echo no)" "no"

# Read-only, part 2: on a NEVER-SCANNED host (no swatter.db yet at all), the
# preview must not be the thing that plants the DB file — sqlite3 creates the
# file just by opening a connection, even for a SELECT that then fails on a
# missing table. Run in a subshell so this doesn't disturb the outer STATE_DIR.
FRESH_STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-prev-fresh.XXXXXX")"
( STATE_DIR="$FRESH_STATE_DIR"; swatter_escalate_preview 30 >/dev/null 2>&1 )
fresh_rc=$?
check prev-nodb-rc      "$([[ $fresh_rc -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check prev-nodb-nofile  "$([[ -e "${FRESH_STATE_DIR}/swatter.db" ]] && echo yes || echo no)" "no"
rm -rf "$FRESH_STATE_DIR"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
