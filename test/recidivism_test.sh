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

# --- _swatter_ev_stamp -----------------------------------------------------
# shellcheck source=../lib/score.sh
source "${ROOT}/lib/score.sh"
SWATTER_HAVE_JQ=0
command -v jq >/dev/null 2>&1 && SWATTER_HAVE_JQ=1

if (( SWATTER_HAVE_JQ )); then
  # Merges as a JSON NUMBER (not a string) into real scorer-shaped evidence.
  ev='{"sub":{"rate":10},"reqs":5,"decisive_rule":"scanner_profile"}'
  got="$(_swatter_ev_stamp "$ev" recidivism 3)"
  check stamp-number      "$(printf '%s' "$got" | jq -r '.recidivism')" "3"
  check stamp-is-number   "$(printf '%s' "$got" | jq -r '.recidivism|type')" "number"
  check stamp-keeps-rule  "$(printf '%s' "$got" | jq -r '.decisive_rule')" "scanner_profile"
  check stamp-valid-json  "$(printf '%s' "$got" | jq -e . >/dev/null 2>&1 && echo ok)" "ok"
  # Invalid input JSON must pass through untouched, never empty.
  check stamp-bad-json    "$(_swatter_ev_stamp 'not json' recidivism 3)" "not json"
  # Non-integer value refused; evidence returned unchanged.
  check stamp-bad-value   "$(_swatter_ev_stamp "$ev" recidivism "3.0")" "$ev"
  check stamp-empty-value "$(_swatter_ev_stamp "$ev" recidivism "")" "$ev"
fi
# Empty evidence must not produce empty output (that would corrupt the JSONL).
# With jq available, "" normalizes to {} and the merge still succeeds, so the
# correct (non-empty, non-failure) result is the merged object; without jq
# there's no merge attempt, so the normalized placeholder {} is returned as-is.
if (( SWATTER_HAVE_JQ )); then
  check stamp-empty-ev  "$(_swatter_ev_stamp "" recidivism 3)" '{"recidivism":3}'
else
  check stamp-empty-ev  "$(_swatter_ev_stamp "" recidivism 3)" "{}"
fi
# No-jq path returns the original untouched.
check stamp-nojq      "$(SWATTER_HAVE_JQ=0 _swatter_ev_stamp '{"a":1}' recidivism 3)" '{"a":1}'

# --- CRITICAL-single gate --------------------------------------------------
# A one-request CRITICAL probe is already a temp (score.awk floors it at 90 and
# bypasses MIN_REQS). Three such singles must NOT be enough for a permanent ban;
# a fourth is. Multi-signal offenders still escalate at REPEAT_N.
check crit-gate-default "${REPEAT_N_CRITICAL_SINGLE}" "4"
check crit-all-raises  "$(_swatter_recid_threshold 1)" "4"   # all-critical -> 4
check crit-mixed-normal "$(_swatter_recid_threshold 0)" "3"  # any non-critical -> REPEAT_N

# swatter_store_temps_all_critical_single reads the LEDGER (not the firewall
# comment, which lib/block_csf.sh truncates to 120 chars) so it always sees the
# full reason string.
SINCE_CRIT="$(( NOW - REPEAT_WINDOW_DAYS*DAY ))"
seed_reason() { # ip days_ago reason
  local ip="$1" days="$2" reason="$3"
  sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
    VALUES('${ip}',$(( NOW - days*DAY )),'temp','csf',3600,91,'${reason}',0);"
}

# Zero temps in window: must report 0 ("all critical"), not misreport an empty
# set as all-critical.
check crit-zero-temps "$(swatter_store_temps_all_critical_single 10.0.9.1 "$SINCE_CRIT")" "0"

# Two prior CRITICAL-single temps: the 3rd offense computed against them must
# NOT reach perm (threshold is raised to REPEAT_N_CRITICAL_SINGLE=4).
seed_reason 10.0.9.2 6 "score=91 rule=critical_badpath"
seed_reason 10.0.9.2 5 "score=91 rule=critical_badpath"
allcrit="$(swatter_store_temps_all_critical_single 10.0.9.2 "$SINCE_CRIT")"
prior="$(swatter_store_recent_temp_count 10.0.9.2)"
thresh="$(_swatter_recid_threshold "$allcrit")"
check crit-2prior-allcrit  "$allcrit" "1"
check crit-3rd-no-perm     "$(( prior + 1 >= thresh ? 1 : 0 ))" "0"

# Record that 3rd single (now 3 prior, all critical): the 4th offense DOES perm.
seed_reason 10.0.9.2 4 "score=91 rule=critical_badpath"
allcrit="$(swatter_store_temps_all_critical_single 10.0.9.2 "$SINCE_CRIT")"
prior="$(swatter_store_recent_temp_count 10.0.9.2)"
thresh="$(_swatter_recid_threshold "$allcrit")"
check crit-3prior-allcrit  "$allcrit" "1"
check crit-4th-perms       "$(( prior + 1 >= thresh ? 1 : 0 ))" "1"

# Two prior temps, one of them multi-signal (not a CRITICAL single): the 3rd
# offense still perms at the normal REPEAT_N=3 — this offender is unaffected
# by the gate.
seed_reason 10.0.9.3 6 "score=91 rule=critical_badpath"
seed_reason 10.0.9.3 5 "score=85 rule=scanner_profile"
allcrit="$(swatter_store_temps_all_critical_single 10.0.9.3 "$SINCE_CRIT")"
prior="$(swatter_store_recent_temp_count 10.0.9.3)"
thresh="$(_swatter_recid_threshold "$allcrit")"
check crit-mixed-not-allcrit "$allcrit" "0"
check crit-mixed-perms-at-3  "$(( prior + 1 >= thresh ? 1 : 0 ))" "1"

# --- operator-unblock watermark (mirrors the watermark tests at the top of
# this file, applied to the NEW function) -----------------------------------
# 2 stale pre-correction temps (later unblocked by the operator: one of them
# multi-signal), then 2 genuine post-unblock CRITICAL singles. The gate must
# judge on POST-unblock history only, exactly like swatter_store_recent_temp_
# count already does for `prior` — otherwise the stale multi-signal temp keeps
# dragging allcrit to 0 forever, the threshold never raises back to
# REPEAT_N_CRITICAL_SINGLE, and the IP perm-bans on its 3rd post-correction
# CRITICAL-single offense: the exact premature-perm scenario this task exists
# to prevent, reached through the operator-correction path the watermark
# exists to protect.
seed_reason 10.0.9.4 20 "score=91 rule=critical_badpath"
seed_reason 10.0.9.4 19 "score=85 rule=scanner_profile"
sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('10.0.9.4',$(( NOW - 15*DAY )),'unblock','none',0,0,'manual unblock',0);"
seed_reason 10.0.9.4 10 "score=91 rule=critical_badpath"
seed_reason 10.0.9.4  5 "score=91 rule=critical_badpath"
allcrit="$(swatter_store_temps_all_critical_single 10.0.9.4 "$SINCE_CRIT")"
prior="$(swatter_store_recent_temp_count 10.0.9.4)"
thresh="$(_swatter_recid_threshold "$allcrit")"
check watermark-crit-prior   "$prior" "2"
check watermark-crit-allcrit "$allcrit" "1"
check watermark-crit-no-perm "$(( prior + 1 >= thresh ? 1 : 0 ))" "0"

# --- flatfile: the gate is inert, and must SAY so -------------------------
# Returning 0 on flatfile is not a safe refusal: allcrit=0 means the threshold
# falls back to REPEAT_N, i.e. the store without the gate bans SOONER than the
# store with it. Silent degradation toward more banning is the one thing this
# must not do, so the flatfile path warns instead of answering quietly.
_ffwarn="${STATE_DIR}/critwarn.txt"
STORE=flatfile swatter_store_temps_all_critical_single 10.0.9.2 "$SINCE_CRIT" \
    >"${STATE_DIR}/critout.txt" 2>"$_ffwarn"
check flatfile-crit-warns "$(grep -c 'INERT on STORE=flatfile' "$_ffwarn" || true)" "1"
check flatfile-crit-zero  "$(cat "${STATE_DIR}/critout.txt")" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
