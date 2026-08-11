#!/usr/bin/env bash
# test/perm_rate_alert_test.sh — the perm-rate tripwire: ladder-only counting,
# threshold trip, and an alert key that cannot hide a multi-hour incident.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/score.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

check perm-alert-run-default "${PERM_RATE_ALERT_PER_RUN}" "5"
check perm-alert-day-default "${PERM_RATE_ALERT_PER_DAY}" "15"

# The alert key must vary by hour. A static key would be suppressed by
# _notify_ratelimited for ALERT_REPEAT_TTL (6h by default), silencing exactly
# the multi-hour burst the tripwire exists to catch.
k1="$(_swatter_perm_rate_key 1000000000)"
k2="$(_swatter_perm_rate_key 1000003600)"   # +1h
k3="$(_swatter_perm_rate_key 1000000060)"   # +1m, same hour
check perm-key-differs-hour "$([[ "$k1" != "$k2" ]] && echo yes || echo no)" "yes"
check perm-key-stable-hour  "$([[ "$k1" == "$k3" ]] && echo yes || echo no)" "yes"

# ---------------------------------------------------------------------------
# The remaining sections need real sqlite: they exercise SWATTER_RUN_PERMS'
# gating, the end-of-scan threshold trip (spying on swatter_notify), and the
# new swatter_store_perm_count_since query directly.
# ---------------------------------------------------------------------------
HAVE_SQLITE=0
command -v sqlite3 >/dev/null 2>&1 && HAVE_SQLITE=1

if (( HAVE_SQLITE )); then
    source "${ROOT}/lib/store_sqlite.sh"
    source "${ROOT}/lib/metrics.sh"

    CLEANUP_DIRS=()
    # shellcheck disable=SC2064
    trap 'rm -rf "${CLEANUP_DIRS[@]}"' EXIT
    newdir() { local d; d="$(mktemp -d "${TMPDIR:-/tmp}/swatter-permrate.XXXXXX")"; CLEANUP_DIRS+=("$d"); printf '%s' "$d"; }

    # -----------------------------------------------------------------------
    # Part 2: counter gating — direct _swatter_apply_plane calls, backends
    # stubbed. Proves SWATTER_RUN_PERMS increments on a primary, enforce-mode,
    # ladder perm ONLY: not a dual-plane/plane-upgrade second leg (distinct
    # audit_action), not a temp, not a report-mode "success".
    # -----------------------------------------------------------------------
    STATE_DIR="$(newdir)"; LOG_DIR="${STATE_DIR}/log"; mkdir -p "$LOG_DIR"
    STORE=sqlite
    swatter_store_init

    swatter_is_never_block()    { return 1; }   # never exempt
    swatter_block_direct_perm() { return 0; }   # backend "success"
    swatter_block_direct_temp() { return 0; }
    swatter_cf_manages_plane()  { return 1; }   # unused below (DIRECT plane only)
    swatter_abuseipdb_report()  { :; }          # lib/report_abuseipdb.sh not sourced here

    _SW_TOTAL_BLOCKS=0; SWATTER_RUN_WATCHED=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
    SWATTER_RUN_PERMS=0
    SWATTER_MODE="enforce"

    # Primary ladder perm: action=perm, audit_action defaults to action ->
    # increments.
    _swatter_apply_plane 203.0.113.10 DIRECT perm 0 "r" "" 1 100 '{"k":1}' 0
    check counter-primary-perm-incr "${SWATTER_RUN_PERMS}" "1"

    # Dual-plane second leg for a DIFFERENT ip: audit_action="dual-plane" !=
    # action -> must NOT increment (this is exactly the double-count a
    # dual-plane/plane-upgrade leg would otherwise cause for one IP).
    _swatter_apply_plane 203.0.113.11 DIRECT perm 0 "r" "" 1 100 '{"k":1}' 0 "dual-plane"
    check counter-dualplane-leg-no-incr "${SWATTER_RUN_PERMS}" "1"

    # Plane-upgrade leg: same exclusion, distinct audit_action.
    _swatter_apply_plane 203.0.113.12 DIRECT perm 0 "r" "" 1 100 '{"k":1}' 0 "plane-upgrade"
    check counter-planeupgrade-leg-no-incr "${SWATTER_RUN_PERMS}" "1"

    # A temp action -> must NOT increment.
    _swatter_apply_plane 203.0.113.13 DIRECT temp 3600 "r" "" 1 100 '{"k":1}' 0
    check counter-temp-no-incr "${SWATTER_RUN_PERMS}" "1"

    # Report mode: same primary-perm shape (action=perm, audit_action=action),
    # stubbed backend still returns rc=0 — mirroring the REAL
    # swatter_block_direct_perm/swatter_cf_block's own dry-run early-return
    # (lib/block_csf.sh:22-25, lib/block_cf.sh:363-366), which also answers
    # rc=0 without touching the firewall. did=1 either way; only the
    # SWATTER_MODE==enforce guard may stop the count from incrementing here.
    SWATTER_MODE="report"
    _swatter_apply_plane 203.0.113.14 DIRECT perm 0 "r" "" 1 100 '{"k":1}' 0
    check counter-reportmode-no-incr "${SWATTER_RUN_PERMS}" "1"
    SWATTER_MODE="enforce"

    # -----------------------------------------------------------------------
    # Part 3: threshold boundary + notify spy — real swatter_scan, honeypot
    # evidence (guaranteed instant perm, skips the repeat-count ladder) drives
    # SWATTER_RUN_PERMS across several distinct IPs in ONE run. swatter_notify
    # is stubbed to record its args so the test asserts the alert actually
    # fired (subject + hour-bucketed key), not merely that a comparison was
    # true.
    # -----------------------------------------------------------------------
    swatter_failclosed_active() { return 1; }   # healthy
    swatter_build_direct_set()  { :; }
    swatter_cf_sweep_expired()  { :; }
    swatter_intel_available()   { return 0; }
    swatter_intel_score()       { printf '0\t\t0\n'; }   # neutral: rep=0, no suppress
    swatter_classify()          { echo "DIRECT"; }

    honeypot_lines() {   # honeypot_lines <n> -> n distinct scored TSV rows
        local n="$1" i lines=""
        for ((i = 1; i <= n; i++)); do
            [[ -n "$lines" ]] && lines+=$'\n'
            lines+="203.0.$((120 + i)).1"$'\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
        done
        printf '%s' "$lines"
    }
    feed_multi() { FEED_LINES="$1"; _swatter_run_scorer() { printf '%s\n' "$FEED_LINES"; }; }

    setup_scan_case() {
        STATE_DIR="$(newdir)"; LOG_DIR="${STATE_DIR}/log"; mkdir -p "$LOG_DIR"
        STORE=sqlite; SWATTER_MODE="enforce"
        SWATTER_NOW_EPOCH=1700000000   # frozen clock: hour-key comparisons can't flake
        SCORE_WATCH=50; SCORE_TEMP=70
        TTL_LADDER="3600 21600 86400"; REPEAT_N=3; REPEAT_WINDOW_DAYS=7; CRITICAL_TTL_FLOOR=86400
        MAX_BLOCKS_PER_RUN=25; MAX_CSF_DENIES_PER_RUN=10; W_REPUTATION=14
        ASN_SIGNAL_ENABLE="false"; PERSIST_ENABLE="false"
        METRICS_FILE=""; CF_MODE="off"; DIRECT_WEB_PORTS=""
        PERM_RATE_ALERT_PER_RUN=5
        PERM_RATE_ALERT_PER_DAY=999   # isolate the per-run arm for this section
        NOTIFY_LOG="${STATE_DIR}/notify.log"; : > "$NOTIFY_LOG"
        swatter_notify() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$NOTIFY_LOG"; }
        swatter_store_init
    }

    # 4 perms this run: below PERM_RATE_ALERT_PER_RUN=5 -> no trip.
    setup_scan_case
    feed_multi "$(honeypot_lines 4)"
    swatter_scan >/dev/null 2>&1
    check perm-rate-4-counter  "${SWATTER_RUN_PERMS}" "4"
    check perm-rate-4-no-trip  "$(grep -c 'perm-rate tripwire' "$NOTIFY_LOG" || true)" "0"

    # 5 perms this run: AT PERM_RATE_ALERT_PER_RUN=5 -> trips exactly at the
    # boundary (proves >=, not >, and not an off-by-one that would need a 6th).
    setup_scan_case
    feed_multi "$(honeypot_lines 5)"
    swatter_scan >/dev/null 2>&1
    check perm-rate-5-counter "${SWATTER_RUN_PERMS}" "5"
    check perm-rate-5-trips   "$(grep -c 'perm-rate tripwire' "$NOTIFY_LOG" || true)" "1"
    # The alert that fired used the hour-bucketed key (the reason a static key
    # would have been wrong: it would go silent for ALERT_REPEAT_TTL while the
    # backlog kept growing).
    check perm-rate-5-key "$(tail -1 "$NOTIFY_LOG" | cut -f3)" "$(_swatter_perm_rate_key)"

    # -----------------------------------------------------------------------
    # Part 4: swatter_store_perm_count_since — ts>since cutoff, dry_run=0
    # filter, flatfile-returns-0 asymmetry, no-phantom-DB guard. Same seeding
    # pattern as test/rollback_ladder_test.sh's swatter_ladder_perms_since
    # coverage.
    # -----------------------------------------------------------------------
    STATE_DIR="$(newdir)"; STORE=sqlite
    swatter_store_init
    db="${STATE_DIR}/swatter.db"; NOW="$(swatter_now)"; DAY=86400
    seed_action() {   # seed_action <ip> <days_ago> <action> <dry_run>
        sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
          VALUES('$1',$(( NOW - $2 * DAY )),'$3','csf',0,91,'seed',$4);"
    }
    seed_action 10.9.0.1 1 perm 0   # inside window, enforced perm  -> counts
    seed_action 10.9.0.2 2 perm 0   # inside window, enforced perm  -> counts
    seed_action 10.9.0.3 9 perm 0   # OUTSIDE the since cutoff      -> excluded
    seed_action 10.9.0.4 1 perm 1   # dry_run=1 (report/preview)    -> excluded
    seed_action 10.9.0.5 1 temp 0   # not a perm                    -> excluded

    since=$(( NOW - 5 * DAY ))
    check permcount-cutoff-and-dryrun "$(swatter_store_perm_count_since "$since")" "2"

    # Flatfile asymmetry: same DB present, STORE=flatfile -> always 0.
    STORE=flatfile
    check permcount-flatfile-zero "$(swatter_store_perm_count_since "$since")" "0"
    STORE=sqlite

    # Non-numeric since -> 0, not an error.
    check permcount-bad-since "$(swatter_store_perm_count_since notaninteger)" "0"

    # No-phantom-DB guard: a never-scanned STATE_DIR must not get a swatter.db
    # planted merely by querying (mirrors swatter_ladder_perms_since's guard).
    NODB_DIR="$(newdir)"
    ( STATE_DIR="$NODB_DIR"; swatter_store_perm_count_since "$since" >/dev/null 2>&1 )
    check permcount-no-phantom-db "$( [[ -e "${NODB_DIR}/swatter.db" ]] && echo present || echo absent )" "absent"

    # -----------------------------------------------------------------------
    # Part 5: the escalation ladder END TO END, through swatter_scan.
    #
    # Everything else that covers the ladder (test/recidivism_test.sh) computes
    # `$(( prior + 1 >= thresh ))` IN THE TEST — it re-implements the production
    # conditional instead of driving it, so lib/score.sh's own decision line is
    # never executed by the suite. Part 3 above does drive swatter_scan, but with
    # honeypot evidence, which takes the instant-perm path and never reaches the
    # ladder branch at all. Result: mutating the ladder's central decision to
    # `(( prior >= thresh ))`, or deleting the `rule=` stamp that the whole
    # CRITICAL-single gate matches on, left the ENTIRE suite green.
    #
    # These cases feed NON-honeypot scored lines through the real scan and
    # assert the recorded decision.
    # -----------------------------------------------------------------------
    HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1
    SWATTER_HAVE_JQ="$HAVE_JQ"

    scored_line() {   # scored_line <ip> <decisive_rule> [extra_ev_fields]
        printf '%s\t91\t12\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"%s","honeypot":0,"top_vhost":"example.test"%s}' \
            "$1" "$2" "${3:-}"
    }
    seed_temp() {     # seed_temp <ip> <days_ago> <reason>
        sqlite3 "${STATE_DIR}/swatter.db" \
            "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
             VALUES('$1',$(( $(swatter_now) - $2 * 86400 )),'temp','csf',3600,91,'$3',0);"
    }
    dec_for() {       # dec_for <ip> <action> -> count of matching decision records
        grep -F "\"ip\":\"$1\"" "${LOG_DIR}/decisions.jsonl" 2>/dev/null \
            | grep -Fc "\"action\":\"$2\"" || true
    }

    # Case A: REPEAT_N-1 = 2 prior enforced temps, then one fresh non-honeypot
    # offense over SCORE_TEMP -> PERM, because the decider counts the PENDING
    # offense. This is the case `(( prior >= thresh ))` gets wrong.
    setup_scan_case
    seed_temp 198.51.100.7 2 'score=91 rule=scanner_profile'
    seed_temp 198.51.100.7 1 'score=91 rule=scanner_profile'
    feed_multi "$(scored_line 198.51.100.7 scanner_profile)"
    swatter_scan >/dev/null 2>&1
    check ladder-2prior-perms   "$(dec_for 198.51.100.7 perm)" "1"
    check ladder-2prior-no-temp "$(dec_for 198.51.100.7 temp)" "0"
    # The perm explains itself: prior(2) + this offense = 3, over REPEAT_WINDOW_DAYS=7.
    check ladder-2prior-reason \
        "$(grep -Fc 'recidivism=3/7d' "${LOG_DIR}/decisions.jsonl" || true)" "1"
    if (( HAVE_JQ )); then
        check ladder-2prior-evidence \
            "$(grep -Fc '"recidivism":3' "${LOG_DIR}/decisions.jsonl" || true)" "1"
    fi

    # Case B (sibling): 1 prior temp -> still a TEMP, not a perm. Guards the
    # other direction, so "always perm" can't pass Case A.
    setup_scan_case
    seed_temp 198.51.100.8 1 'score=91 rule=scanner_profile'
    feed_multi "$(scored_line 198.51.100.8 scanner_profile)"
    swatter_scan >/dev/null 2>&1
    check ladder-1prior-temps    "$(dec_for 198.51.100.8 temp)" "1"
    check ladder-1prior-no-perm  "$(dec_for 198.51.100.8 perm)" "0"
    check ladder-1prior-no-recid \
        "$(grep -Fc 'recidivism=' "${LOG_DIR}/decisions.jsonl" || true)" "0"

    # Case C: the CRITICAL-single gate, driven end to end. The temps are written
    # BY THE SCAN (not seeded by hand), so the gate only holds if score.sh
    # actually stamps `rule=<decisive_rule>` into the reason it records — that
    # stamp is the sole producer of the "critical_badpath" substring
    # swatter_store_temps_all_critical_single matches on. Delete it and allcrit
    # is permanently 0, the threshold silently drops back to REPEAT_N, and the
    # 3rd offense below perms instead of getting its 3rd temp.
    setup_scan_case
    crit_ev=',"badpath_cat":"CRITICAL"'
    feed_multi "$(scored_line 198.51.100.9 critical_badpath "$crit_ev")"
    swatter_scan >/dev/null 2>&1   # offense 1 -> temp
    swatter_scan >/dev/null 2>&1   # offense 2 -> temp
    swatter_scan >/dev/null 2>&1   # offense 3 -> temp (bar raised to 4), NOT perm
    check critgate-3rd-still-temp "$(dec_for 198.51.100.9 temp)" "3"
    check critgate-3rd-no-perm    "$(dec_for 198.51.100.9 perm)" "0"
    swatter_scan >/dev/null 2>&1   # offense 4 -> perm at REPEAT_N_CRITICAL_SINGLE
    check critgate-4th-perms      "$(dec_for 198.51.100.9 perm)" "1"
    check critgate-4th-reason \
        "$(grep -Fc 'recidivism=4/7d crit-single' "${LOG_DIR}/decisions.jsonl" || true)" "1"
else
    echo "SKIP counter-gating/threshold/store-query sections (no sqlite3)"
fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
