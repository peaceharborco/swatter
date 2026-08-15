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

# The alert key is bucketed by SEVERITY, not by wall clock.
#
# It was keyed on the hour, which defeated _notify_ratelimited entirely: every
# hour minted a new key, so a _pday count that stays over the threshold — and a
# trailing-24h count necessarily does — re-alerted once an hour for a full day.
# Measured on cds1 2026-08-15: four texts, 10:55/11:00/12:00/13:00, the first
# two five minutes apart because the run straddled an hour boundary.
#
# Keying on the band means a steady incident is ONE alert (then governed by
# ALERT_REPEAT_TTL), while a genuinely worsening one still re-alerts the moment
# it crosses another full threshold's worth. Louder on escalation, silent on
# repetition — the fail direction the alerting plane requires.
PERM_RATE_ALERT_PER_RUN=5
PERM_RATE_ALERT_PER_DAY=70

# Same severity -> same key, no matter how much wall time passes.
kA="$(_swatter_perm_rate_key 0 73)"
kB="$(_swatter_perm_rate_key 0 99)"    # still band 1 (70..139)
check perm-key-stable-in-band "$([[ "$kA" == "$kB" ]] && echo yes || echo no)" "yes"

# Crossing another full threshold's worth -> new key -> alerts again.
kC="$(_swatter_perm_rate_key 0 140)"   # band 2
check perm-key-escalates "$([[ "$kA" != "$kC" ]] && echo yes || echo no)" "yes"

# The per-run arm escalates independently of the per-day arm.
kD="$(_swatter_perm_rate_key 5 73)"
check perm-key-run-arm-independent "$([[ "$kA" != "$kD" ]] && echo yes || echo no)" "yes"

# The key must NOT depend on the clock — that was the whole defect.
SWATTER_NOW_EPOCH=1000000000; kE="$(_swatter_perm_rate_key 0 73)"
SWATTER_NOW_EPOCH=1000090000; kF="$(_swatter_perm_rate_key 0 73)"   # +25h
unset SWATTER_NOW_EPOCH
check perm-key-clock-independent "$([[ "$kE" == "$kF" ]] && echo yes || echo no)" "yes"

# Non-numeric args must not reach an arithmetic context (lib/common.sh assigns
# defaults unconditionally, so a conf typo can arrive here) and must fail LOUD:
# an unreadable severity gets its own key rather than colliding with a quiet one.
check perm-key-nonnumeric-safe "$(_swatter_perm_rate_key notanumber 73)" "perm_rate.unreadable"
check perm-key-nonnumeric-thresh "$(PERM_RATE_ALERT_PER_DAY=oops _swatter_perm_rate_key 0 73)" "perm_rate.unreadable"

# --- the high-water ratchet -------------------------------------------------
# The pure band above re-alerts on the way DOWN (140 -> 100 is d2 -> d1, a new
# key, which _notify_ratelimited reads as a new incident). _swatter_perm_rate_hw_key
# ratchets, so only worsening mints a new key.
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-hw.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT

check hw-first        "$(_swatter_perm_rate_hw_key 0 140)" "perm_rate.r0.d2"
check hw-decay-holds  "$(_swatter_perm_rate_hw_key 0 100)" "perm_rate.r0.d2"   # improving -> same key
check hw-decay-holds2 "$(_swatter_perm_rate_hw_key 0 71)"  "perm_rate.r0.d2"
check hw-escalates    "$(_swatter_perm_rate_hw_key 0 210)" "perm_rate.r0.d3"   # worse -> new key
check hw-run-arm      "$(_swatter_perm_rate_hw_key 5 210)" "perm_rate.r1.d3"
check hw-run-decay    "$(_swatter_perm_rate_hw_key 0 210)" "perm_rate.r1.d3"   # run arm ratchets too

# A corrupt high-water file must not abort or wedge the key at a bogus band.
printf 'garbage\n' > "$(_swatter_perm_rate_hw_file)"
check hw-corrupt-file "$(_swatter_perm_rate_hw_key 0 140)" "perm_rate.r0.d2"

# Unreadable severity is passed through untouched, not ratcheted.
check hw-unreadable "$(_swatter_perm_rate_hw_key notanumber 73)" "perm_rate.unreadable"

# A directory where the state file should be must not hang or abort the scan.
rm -f "$(_swatter_perm_rate_hw_file)"; mkdir -p "$(_swatter_perm_rate_hw_file)"
check hw-dir-at-path "$(_swatter_perm_rate_hw_key 0 140)" "perm_rate.r0.d2"
rmdir "$(_swatter_perm_rate_hw_file)" 2>/dev/null || rm -rf "$(_swatter_perm_rate_hw_file)"

# An empty STATE_DIR must degrade to the pure band, never build a path at /.
check hw-no-statedir "$(STATE_DIR="" _swatter_perm_rate_hw_key 0 140)" "perm_rate.r0.d2"
rm -rf "$STATE_DIR"; trap - EXIT

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
    # The alert that fired carries the SEVERITY-BAND key, built from the real
    # counts: 5 perms this run over PERM_RATE_ALERT_PER_RUN=5 is band r1, and
    # the day arm is isolated to 0 here by PERM_RATE_ALERT_PER_DAY=999.
    # Asserting the literal (not a re-call of the helper) means a helper that
    # silently returned a constant could not pass this.
    check perm-rate-5-key "$(tail -1 "$NOTIFY_LOG" | cut -f3)" "perm_rate.r1.d0"

    # A SECOND scan at the same severity must NOT mint a new key — that is the
    # repetition the hour bucket could not suppress.
    prev_key="$(tail -1 "$NOTIFY_LOG" | cut -f3)"
    feed_multi "$(honeypot_lines 5)"
    swatter_scan >/dev/null 2>&1
    check perm-rate-repeat-same-key "$(tail -1 "$NOTIFY_LOG" | cut -f3)" "$prev_key"

    # -----------------------------------------------------------------------
    # Call-site wiring, end to end through swatter_scan. The helper tests above
    # pin the HELPERS; reviewers proved you could revert every call-site
    # contract (use the pure key instead of the ratchet, drop the _unreadable
    # trip, delete the high-water clear) with the suite still green. These
    # drive swatter_scan and assert what the operator actually receives.
    # -----------------------------------------------------------------------

    # (i) DECAY through the real scan: cross into d2, then decay to d1 while
    # still over threshold. One key, not two — no page on the way down.
    setup_scan_case
    PERM_RATE_ALERT_PER_RUN=999      # isolate the DAY arm
    PERM_RATE_ALERT_PER_DAY=10
    seed_day() {   # seed_day <n> — n distinct IPs with an enforced perm, now
        local n="$1" i
        for ((i = 1; i <= n; i++)); do
            sqlite3 "${STATE_DIR}/swatter.db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
              VALUES('10.20.$(( i / 250 )).$(( i % 250 ))',$(swatter_now),'perm','csf',0,91,'seed',0);"
        done
    }
    feed_multi ""                    # no new offenders; the ledger drives the day arm
    seed_day 25                      # 25 >= 10 -> band d2
    swatter_scan >/dev/null 2>&1
    k_hi="$(tail -1 "$NOTIFY_LOG" | cut -f3)"
    check e2e-decay-first-key "$k_hi" "perm_rate.r0.d2"
    # Now decay: rewrite the ledger to 15 distinct IPs (still >= 10 -> band d1).
    sqlite3 "${STATE_DIR}/swatter.db" "DELETE FROM actions;"
    seed_day 15
    swatter_scan >/dev/null 2>&1
    check e2e-decay-no-new-key "$(tail -1 "$NOTIFY_LOG" | cut -f3)" "$k_hi"
    check e2e-decay-band-file-present \
        "$([[ -f "${STATE_DIR}/perm_rate.band" ]] && echo yes || echo no)" "yes"

    # (ii) The high-water is CLEARED once nothing trips, so the next wave is
    # judged fresh instead of being suppressed by an old peak.
    sqlite3 "${STATE_DIR}/swatter.db" "DELETE FROM actions;"
    swatter_scan >/dev/null 2>&1     # 0 perms, under both arms
    check e2e-clear-band-file \
        "$([[ -e "${STATE_DIR}/perm_rate.band" ]] && echo present || echo absent)" "absent"

    # (iii) An UNREADABLE ledger must page, and must keep ratcheting on the run
    # arm — a blind day arm may not also disarm the arm that can still see.
    setup_scan_case
    PERM_RATE_ALERT_PER_RUN=5
    PERM_RATE_ALERT_PER_DAY=10
    swatter_store_perm_count_since() { echo UNREADABLE; }   # post-init read failure
    feed_multi "$(honeypot_lines 5)"
    swatter_scan >/dev/null 2>&1
    check e2e-unreadable-pages \
        "$(grep -c 'perm-rate tripwire' "$NOTIFY_LOG" || true)" "1"
    check e2e-unreadable-key "$(tail -1 "$NOTIFY_LOG" | cut -f3)" "perm_rate.unreadable.r1.d0"
    check e2e-unreadable-body-says-so \
        "$(tail -1 "$NOTIFY_LOG" | grep -c 'UNREADABLE' || true)" "1"
    # (iv) The case that isolates the _unreadable arm: NOTHING else trips.
    # 1 perm this run (< 5) and a day arm that cannot be read. Without the
    # _unreadable term in the trip condition this is silent — an alarm that has
    # gone blind reporting a quiet day, which is the whole defect.
    setup_scan_case
    PERM_RATE_ALERT_PER_RUN=5
    PERM_RATE_ALERT_PER_DAY=10
    swatter_store_perm_count_since() { echo UNREADABLE; }
    feed_multi "$(honeypot_lines 1)"
    swatter_scan >/dev/null 2>&1
    check e2e-unreadable-alone-counter "${SWATTER_RUN_PERMS}" "1"
    check e2e-unreadable-alone-pages \
        "$(grep -c 'perm-rate tripwire' "$NOTIFY_LOG" || true)" "1"
    unset -f swatter_store_perm_count_since
    source "${ROOT}/lib/store_sqlite.sh"

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

    # -----------------------------------------------------------------------
    # The two ways this counter over-reported on real data. Every seed above is
    # one IP with one row, so neither shape was reachable by the suite; on cds1
    # 2026-08-15 the pair inflated a true 30 into 73 and tripped a 70/day
    # tripwire that the honest number never came close to.
    # -----------------------------------------------------------------------

    seed_action_ch() {   # seed_action_ch <ip> <days_ago> <channel> <ttl>
        sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
          VALUES('$1',$(( NOW - $2 * DAY )),'perm','$3',$4,91,'seed',0);"
    }

    # (a) A Cloudflare perm MUST COUNT. Its ttl is rewritten to the ladder max,
    # so it is not a never-expiring row — but it IS the ladder's perm decision,
    # and on a CF-fronted host it is the only form most of them take. Filtering
    # on ttl=0 here pinned this arm near 0 (and at exactly 0 on an all-proxied
    # host), which is an alarm that cannot fire. The run arm counts CF primaries
    # too, so excluding them here would also make the two numbers in one SMS
    # mean different things.
    STATE_DIR="$(newdir)"; swatter_store_init; db="${STATE_DIR}/swatter.db"
    seed_action_ch 10.9.1.1 1 csf        0        # direct perm
    seed_action_ch 10.9.1.2 1 cloudflare 259200   # CF perm -> STILL COUNTS
    check permcount-counts-cf-perm "$(swatter_store_perm_count_since "$since")" "2"

    # (b) One IP blocked on BOTH planes writes one row per plane, same second.
    # The per-run counter already guards this (lib/score.sh's audit_action
    # check, with a comment naming the exact hazard); the day counter did not.
    STATE_DIR="$(newdir)"; swatter_store_init; db="${STATE_DIR}/swatter.db"
    seed_action_ch 10.9.2.1 1 csf        0        # same IP, direct plane
    seed_action_ch 10.9.2.1 1 cloudflare 259200   # same IP, edge plane
    check permcount-dualplane-counts-ip-once "$(swatter_store_perm_count_since "$since")" "1"

    # (b2) The shape that isolates DISTINCT from any ttl predicate: ONE IP, TWO
    # rows, BOTH ttl=0. Reviewers proved (b) alone passes with DISTINCT reverted,
    # because the ttl values differed and a ttl filter did the collapsing.
    STATE_DIR="$(newdir)"; swatter_store_init; db="${STATE_DIR}/swatter.db"
    seed_action_ch 10.9.5.1 1 csf   0
    seed_action_ch 10.9.5.1 1 ipset 0
    check permcount-distinct-isolates "$(swatter_store_perm_count_since "$since")" "1"

    # (c) The same IP re-permed later in the window is still one banned IP.
    # (653 distinct IPs across 662 all-time perm rows on cds1 — this happens.)
    STATE_DIR="$(newdir)"; swatter_store_init; db="${STATE_DIR}/swatter.db"
    seed_action_ch 10.9.3.1 3 csf 0
    seed_action_ch 10.9.3.1 1 csf 0
    check permcount-repeat-perm-counts-once "$(swatter_store_perm_count_since "$since")" "1"

    # Guard the other direction: distinct IPs must still each count, or the fix
    # would trade an over-report for an under-report and blunt the alarm.
    STATE_DIR="$(newdir)"; swatter_store_init; db="${STATE_DIR}/swatter.db"
    seed_action_ch 10.9.4.1 1 csf 0
    seed_action_ch 10.9.4.2 1 csf 0
    seed_action_ch 10.9.4.3 1 csf 0
    check permcount-distinct-ips-all-count "$(swatter_store_perm_count_since "$since")" "3"

    STATE_DIR="$(newdir)"; swatter_store_init; db="${STATE_DIR}/swatter.db"
    seed_action 10.9.0.1 1 perm 0
    seed_action 10.9.0.2 2 perm 0

    # Flatfile asymmetry: same DB present, STORE=flatfile -> always 0.
    STORE=flatfile
    check permcount-flatfile-zero "$(swatter_store_perm_count_since "$since")" "0"
    STORE=sqlite

    # Non-numeric since -> 0, not an error.
    check permcount-bad-since "$(swatter_store_perm_count_since notaninteger)" "0"

    # A ledger that EXISTS but cannot be read must report UNREADABLE, never 0 —
    # 0 is "quiet day", and the day arm is the only thing watching a slow
    # accumulation. Corrupt the DB file in place to force _sqlq to fail.
    STATE_DIR="$(newdir)"; STORE=sqlite; swatter_store_init
    printf 'not a sqlite database at all' > "${STATE_DIR}/swatter.db"
    check permcount-unreadable-is-loud "$(swatter_store_perm_count_since "$since")" "UNREADABLE"

    # ...but a flatfile host or a never-scanned host has no ledger to read and is
    # honestly 0. Absence of data is not a failed read.
    STORE=flatfile
    check permcount-flatfile-not-unreadable "$(swatter_store_perm_count_since "$since")" "0"
    STORE=sqlite

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
