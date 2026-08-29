#!/usr/bin/env bash
# test/scan_wire_test.sh — swatter_scan routing: suppress->exempt, honeypot->perm,
# asn boost, persistence escalation. Firewall + classify + intel are stubbed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

# Load real modules under test.
source "${ROOT}/lib/store_sqlite.sh"
# allowlist.sh for the CIDR primitives the shared-egress veto matches through
# (_cidr_overlaps_file). swatter_is_never_block is stubbed below, after this.
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/metrics.sh"
source "${ROOT}/lib/score.sh"

PASS=0; FAIL=0
STORE=sqlite; SWATTER_MODE="enforce"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-wire.XXXXXX")"
LOG_DIR="$STATE_DIR/log"; mkdir -p "$LOG_DIR"
trap 'rm -rf "$STATE_DIR"' EXIT
# thresholds + caps + weights
SCORE_WATCH=50; SCORE_TEMP=70
TTL_LADDER="3600 21600 86400"; REPEAT_N=3; REPEAT_WINDOW_DAYS=7; CRITICAL_TTL_FLOOR=86400
MAX_BLOCKS_PER_RUN=25; MAX_CSF_DENIES_PER_RUN=10; W_REPUTATION=14
ASN_SIGNAL_ENABLE="true"; W_ASN=12; HOSTING_ASNS_FILE="$STATE_DIR/hosting.txt"
printf '16276 # OVH\n' > "$HOSTING_ASNS_FILE"
PERSIST_ENABLE="true"; PERSIST_N=3; PERSIST_WINDOW_DAYS=3; PERSIST_BUCKET_SECONDS=3600
METRICS_FILE=""; CF_MODE="off"; DIRECT_WEB_PORTS=""
swatter_store_init

# --- stubs ---
swatter_failclosed_active() { return 1; }     # healthy
swatter_build_direct_set()  { :; }
swatter_cf_sweep_expired()  { :; }
swatter_ingest()            { :; }            # parsed stream comes from the scorer override
swatter_intel_available()   { return 0; }     # intel reachable; default score is neutral (0\t\t0)
swatter_intel_score()       { printf '0\t\t0\n'; }   # neutral unless a case re-defines it
swatter_classify()          { echo "DIRECT"; }   # everything direct -> CSF
swatter_is_never_block()    { return 1; }
swatter_cf_manages_plane()  { return 1; }
LAST_CSF=""
# Stub the backends _swatter_execute_block ACTUALLY calls (swatter_block_direct_*
# for the DIRECT plane, swatter_cf_block for VIA_CF) — block.sh is not sourced
# here. BLOCK_RC flips success(0) vs failure(1) so the did=0 (failed-block) audit
# path can be exercised. (Previously only swatter_csf_* were stubbed, leaving the
# direct fns undefined -> did=0 in every case; the perm checks passed only because
# the buggy unconditional audit logged the action regardless of block success.)
BLOCK_RC=0
swatter_block_direct_temp() { LAST_CSF="temp $1 $2"; return "$BLOCK_RC"; }
swatter_block_direct_perm() { LAST_CSF="perm $1"; return "$BLOCK_RC"; }
swatter_csf_temp() { LAST_CSF="temp $1 $2"; return 0; }
swatter_csf_perm() { LAST_CSF="perm $1"; return 0; }
swatter_cf_block() { return "$BLOCK_RC"; }
swatter_notify()   { :; }
# ASN: 1.2.3.4 is OVH; resolve mock via asn.sh's resolver -> stub the resolver.
swatter_asn_resolve() { [[ "$1" == "1.2.3.4" ]] && echo 16276; return 0; }

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
last_action()  { tail -1 "$LOG_DIR/decisions.jsonl" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p'; }
last_channel() { tail -1 "$LOG_DIR/decisions.jsonl" | sed -n 's/.*"channel":"\([^"]*\)".*/\1/p'; }

# Helper: feed one synthetic scored line by overriding _swatter_run_scorer.
# FEED_LINE is global so the override closure resolves it under `set -u` when
# _swatter_run_scorer is invoked later inside swatter_scan (dynamic scope).
feed() { FEED_LINE="$1"; _swatter_run_scorer() { printf '%s\n' "$FEED_LINE"; }; }

# 1) honeypot evidence -> perm regardless of low score.
feed $'8.8.4.4\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_intel_score() { printf '0\t\t0\n'; }
swatter_scan >/dev/null 2>&1
check honeypot-perm "$(last_action)" "perm"

# 2) suppress flag -> exempt even with a high score.
feed $'9.9.9.9\t95\t40\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"high_badpath_repeat","honeypot":0,"top_vhost":"x.com"}'
swatter_intel_score() { printf '95\triot:google\t1\n'; }     # suppress=1
swatter_scan >/dev/null 2>&1
check suppress-exempt "$(last_action)" "exempt"

# 3) ASN boost: behavioral 64 (< TEMP 70) + OVH + attack-shaped -> boosted to temp.
feed $'1.2.3.4\t64\t30\t{"sub":{"burst":0},"novhost":0,"hibad_fail":12,"decisive_rule":"","honeypot":0,"top_vhost":"x.com"}'
swatter_intel_score() { printf '0\t\t0\n'; }
swatter_scan >/dev/null 2>&1
check asn-boost-temp "$(last_action)" "temp"

# 4) Same IP/score but NOT hosting (5.5.5.5) -> stays watch.
swatter_asn_resolve() { return 1; }
feed $'5.5.5.5\t64\t30\t{"sub":{"burst":0},"novhost":0,"hibad_fail":12,"decisive_rule":"","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check no-asn-watch "$(last_action)" "watch"

# 5) HONEYPOT_OVERRIDES_SUPPRESS: suppressed IP that hits a honeypot.
#    Default/false -> suppression wins (exempt). True -> honeypot wins (perm).
swatter_asn_resolve() { return 1; }   # don't matter here; keep ASN off for this IP
feed $'7.7.7.7\t10\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_intel_score() { printf '0\triot:google\t1\n'; }   # suppress=1
HONEYPOT_OVERRIDES_SUPPRESS="false"
swatter_scan >/dev/null 2>&1
check honeypot-suppress-default-exempt "$(last_action)" "exempt"

unset HONEYPOT_OVERRIDES_SUPPRESS
feed $'7.7.7.7\t10\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check honeypot-suppress-unset-exempt "$(last_action)" "exempt"

HONEYPOT_OVERRIDES_SUPPRESS="true"
feed $'7.7.7.7\t10\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check honeypot-suppress-override-perm "$(last_action)" "perm"
unset HONEYPOT_OVERRIDES_SUPPRESS

# 8) Block backend SUCCEEDS (did=1): the real action is audited and the offender
#    is marked perm (so the next run short-circuits to noop-perm).
BLOCK_RC=0
swatter_intel_score() { printf '0\t\t0\n'; }
feed $'3.3.3.3\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check block-ok-audits-perm "$(last_action)" "perm"
if swatter_store_is_perm "3.3.3.3"; then check block-ok-sets-perm "set" "set"; else check block-ok-sets-perm "unset" "set"; fi

# 9) Block backend FAILS (did=0): audit the truth ("failed"), NOT the intended
#    action, and DON'T mark the offender perm — so the duplicate-perm loop where a
#    failed CF/CSF block was logged as a successful block can't recur.
BLOCK_RC=1
feed $'4.4.4.4\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check block-fail-audits-failed "$(last_action)" "failed"
if swatter_store_is_perm "4.4.4.4"; then check block-fail-no-perm "set" "unset"; else check block-fail-no-perm "unset" "unset"; fi
BLOCK_RC=0

# 10) VIA_CF plane, backend FAILS (rc=1): the EXACT prod failure mode (52.138.3.29
#     went via Cloudflare). Earlier cases route DIRECT; this proves the failed-audit
#     fix covers the cloudflare plane too — audit "failed" on channel=cloudflare,
#     perm unset.
swatter_classify()         { echo "VIA_CF"; }
swatter_cf_manages_plane() { return 0; }
BLOCK_RC=1
swatter_intel_score() { printf '0\t\t0\n'; }
feed $'5.6.7.8\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check viacf-fail-audits-failed "$(last_action)" "failed"
check viacf-fail-channel "$(last_channel)" "cloudflare"
if swatter_store_is_perm "5.6.7.8"; then check viacf-fail-no-perm "set" "unset"; else check viacf-fail-no-perm "unset" "unset"; fi

# 11) temp action (score>=TEMP, repeat-count not yet met) with backend FAIL ->
#     "failed", NOT "temp" (the non-perm half of the fix).
swatter_classify()         { echo "DIRECT"; }
swatter_cf_manages_plane() { return 1; }
BLOCK_RC=1
feed $'9.8.7.6\t82\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"scanner_profile","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check temp-fail-audits-failed "$(last_action)" "failed"
# and the failed temp left NO temp record in the store (not just the right label).
check temp-fail-no-store "$(swatter_store_recent_temp_count 9.8.7.6)" "0"

# 12) Backend hits its per-run cap (rc=2): a deliberate throttle, NOT a backend
#     error -> "skipped-cap" (mirrors the MAX_BLOCKS_PER_RUN skip), not "failed".
BLOCK_RC=2
feed $'11.11.11.11\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check cap-audits-skipped-cap "$(last_action)" "skipped-cap"

# 13) VIA_CF deterministic precondition (rc=3, e.g. vhost not in CF map / no token):
#     a config skip we'll never satisfy by retrying -> "skipped-config", not "failed"
#     (so a misconfig doesn't masquerade as a transient backend error forever).
swatter_classify()         { echo "VIA_CF"; }
swatter_cf_manages_plane() { return 0; }
BLOCK_RC=3
feed $'12.12.12.12\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check cfprecond-audits-skipped-config "$(last_action)" "skipped-config"
check cfprecond-channel "$(last_channel)" "cloudflare"
if swatter_store_is_perm "12.12.12.12"; then check cfprecond-no-perm "set" "unset"; else check cfprecond-no-perm "unset" "unset"; fi

# 14) VIA_CF with no nameable target vhost this window (rc=4): data-dependent, may
#     resolve next scan -> "skipped-novhost", distinct from the permanent
#     "skipped-config" so a transient evidence shape isn't read as a misconfig.
BLOCK_RC=4
feed $'13.13.13.13\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check novhost-audits-skipped-novhost "$(last_action)" "skipped-novhost"
check novhost-channel "$(last_channel)" "cloudflare"
if swatter_store_is_perm "13.13.13.13"; then check novhost-no-perm "set" "unset"; else check novhost-no-perm "unset" "unset"; fi

BLOCK_RC=0
swatter_classify()         { echo "DIRECT"; }
swatter_cf_manages_plane() { return 1; }

# 15) Malformed IP tokens that pass score.awk's loose charset gate (bounded to
#     [0-9A-Fa-f:.] but not validity) must NEVER reach a firewall backend. The
#     block path applies the strict validator itself — the last line of defense.
for badip in "999.999.999.999" "::::" "deadbe:ef::0:12345"; do
    LAST_CSF=""
    feed "$badip"$'\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
    swatter_scan >/dev/null 2>&1
    check "malformed-ip-no-backend(${badip})" "${LAST_CSF}" ""
    # ...and the skip is AUDITED (observability parity with the never-block path),
    # not just dropped with a log line.
    check "malformed-ip-audited(${badip})" "$(last_action)" "skipped-invalid"
done

# 16) ...and a valid attacker IP in the same run still gets blocked (the gate
#     rejects garbage, not traffic).
LAST_CSF=""
feed $'203.0.113.99\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>&1
check valid-ip-still-blocked "${LAST_CSF}" "perm 203.0.113.99"

# 18) FAIL-CLOSED on the DIRECT plane (the load-bearing invariant): a DIRECT
#     offender with healthy=0 (stale/missing CF ranges) must NOT reach the csf/
#     ipset backend, and the skip is audited 'skipped-failclosed'. Exercises
#     _swatter_apply_plane directly so the gate is proven independent of scan flow.
LAST_CSF=""; _SW_TOTAL_BLOCKS=0
: > "$LOG_DIR/decisions.jsonl"
_swatter_apply_plane 198.51.100.7 DIRECT perm 0 "r" "" 0 100 '{"k":1}' 0
check failclosed-no-backend "${LAST_CSF}" ""
check failclosed-audited "$(last_action)" "skipped-failclosed"

# 19) MAX_BLOCKS_PER_RUN circuit breaker: at the cap, an actionable call is skipped
#     BEFORE any backend call, audited 'skipped-cap', and SWATTER_RUN_BREAKER latches 1.
LAST_CSF=""; SWATTER_RUN_BREAKER=0; _SW_TOTAL_BLOCKS="$MAX_BLOCKS_PER_RUN"
: > "$LOG_DIR/decisions.jsonl"
_swatter_apply_plane 198.51.100.8 DIRECT perm 0 "r" "" 1 100 '{"k":1}' 0
check cap-breaker-no-backend "${LAST_CSF}" ""
check cap-breaker-audited "$(last_action)" "skipped-cap"
check cap-breaker-flag "${SWATTER_RUN_BREAKER}" "1"
_SW_TOTAL_BLOCKS=0

# 17) _swatter_audit backstop: a reason carrying a backslash and a double-quote
#     must still yield a parseable JSON line (the record layer neutralizes them
#     even if some future reason source isn't pre-sanitized).
if command -v jq >/dev/null 2>&1; then
    : > "$LOG_DIR/decisions.jsonl"
    _swatter_audit '203.0.113.7' 90 temp csf 3600 'intel=mal\ware "x"' '{"k":1}' 0
    if jq -e . "$LOG_DIR/decisions.jsonl" >/dev/null 2>&1; then
        check audit-json-valid "valid" "valid"
    else
        check audit-json-valid "invalid" "valid"
    fi
    check audit-json-oneline "$(wc -l < "$LOG_DIR/decisions.jsonl" | tr -d ' ')" "1"

    # The ip field is sanitized at the record layer too (parity with reason), so
    # even a hostile ip token can't break the JSON line — defense in depth for any
    # future path into _swatter_audit that bypasses the charset-safe scorer.
    : > "$LOG_DIR/decisions.jsonl"
    _swatter_audit 'evil"ip\x' 90 temp csf 3600 'r' '{"k":1}' 0
    if jq -e . "$LOG_DIR/decisions.jsonl" >/dev/null 2>&1; then
        check audit-json-hostile-ip-valid "valid" "valid"
    else
        check audit-json-hostile-ip-valid "invalid" "valid"
    fi
fi

# 20) Shared-egress caps are RUN-scoped and visible. A too-wide-but-valid CIDR
#     line mass-caps perms while emitting only per-IP warnings, so the count has
#     to reach the scan-complete line — and it has to be reset like every other
#     run counter, or a long-lived shell (tests, `swatter scan` twice) reports a
#     stale total forever.
SHARED_EGRESS_ENABLE="true"
SHARED_EGRESS_CIDR_FILE="$STATE_DIR/se.cidr"
SHARED_EGRESS_ASNS_FILE="$STATE_DIR/se-asns.txt"
printf '104.28.0.0/16 # WARP\n' > "$SHARED_EGRESS_CIDR_FILE"; : > "$SHARED_EGRESS_ASNS_FILE"
_SW_SHARED_CIDR_OK=""
SWATTER_RUN_SHARED_CAPS=99          # stale value from a previous run
LAST_CSF=""
feed $'104.28.44.44\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
# NOT $( ): swatter_scan sets the run counters, and a command substitution
# would run it in a subshell where every one of them dies with the child.
swatter_scan >/dev/null 2>"$STATE_DIR/scan1.log"; scanlog="$(cat "$STATE_DIR/scan1.log")"
check shared-cap-counted "${SWATTER_RUN_SHARED_CAPS}" "1"
check shared-cap-backend "${LAST_CSF%% *}" "temp"
case "$scanlog" in *"scan complete:"*"1 shared-egress perm-capped"*) PASS=$((PASS+1));;
  *) echo "FAIL shared-cap-in-scan-log: $(printf '%s\n' "$scanlog" | grep 'scan complete')"; FAIL=$((FAIL+1));; esac
# A run with no cap resets to 0 and leaves the log line's normal shape alone.
feed $'203.0.113.98\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_scan >/dev/null 2>"$STATE_DIR/scan2.log"; scanlog2="$(cat "$STATE_DIR/scan2.log")"
check shared-cap-reset "${SWATTER_RUN_SHARED_CAPS}" "0"
case "$scanlog2" in *"shared-egress perm-capped"*) echo "FAIL shared-cap-quiet-when-zero"; FAIL=$((FAIL+1));;
  *) PASS=$((PASS+1));; esac
# ...and the counter reaches the metrics exposition too.
check shared-cap-metric "$(SWATTER_RUN_SHARED_CAPS=4 swatter_metrics_emit | grep '^swatter_scan_shared_caps ')" "swatter_scan_shared_caps 4"
SHARED_EGRESS_ENABLE="false"

# 21) srcset_flood is WATCH-ONLY. The awk cap and the folded>=SCORE_TEMP cap
#     are not enough: the WATCH band accrues persist sightings with no rule
#     filter, and PERSIST_N buckets in PERSIST_WINDOW_DAYS is a real temp
#     (dry_run=0) that feeds the recidivism ladder. Deleting the rule filter
#     on that path must fail the persist cases below; deleting the fold cap
#     must fail the >=SCORE_TEMP case.
seed_older_sightings() {
    local ip="$1" n="$2" now k b
    now="$(swatter_now)"
    for (( k=1; k<=n; k++ )); do
        b=$(( (now - k * 7200) / 3600 ))
        sqlite3 "$STATE_DIR/swatter.db" \
            "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts) VALUES('${ip}',${b},1,50,$((now - k * 7200)));"
    done
}

_SW_TOTAL_BLOCKS=0
BLOCK_RC=0
ASN_SIGNAL_ENABLE="false"
swatter_intel_score() { printf '0\t\t0\n'; }
swatter_classify() { echo "DIRECT"; }
swatter_cf_manages_plane() { return 1; }

# Control: persist still temps any OTHER watch-band rule. The filter is
# rule-specific, not a persist disable.
LAST_CSF=""
: > "$LOG_DIR/decisions.jsonl"
seed_older_sightings "198.51.100.21" 2
feed $'198.51.100.21\t50\t20\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"scanner_profile","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check persist-other-rule-still-temps "$(last_action)" "temp"

LAST_CSF=""
: > "$LOG_DIR/decisions.jsonl"
seed_older_sightings "198.51.100.22" 2
feed $'198.51.100.22\t50\t500\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"srcset_flood","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check srcset-flood-persist-stays-watch "$(last_action)" "watch"
check srcset-flood-persist-no-backend "${LAST_CSF}" ""
check srcset-flood-persist-no-temp-row "$(swatter_store_recent_temp_count 198.51.100.22)" "0"
check srcset-flood-no-sighting-accrual "$(swatter_store_sighting_buckets 198.51.100.22 3)" "2"

# Folded >= SCORE_TEMP with the watch-only rule (reputation/ASN fold, or an
# operator raising SCORE_WATCH) must still not temp — that is the cap at
# lib/score.sh, and it was previously untested.
LAST_CSF=""
: > "$LOG_DIR/decisions.jsonl"
feed $'198.51.100.23\t80\t500\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"srcset_flood","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check srcset-flood-cap-stays-watch "$(last_action)" "watch"
check srcset-flood-cap-no-backend "${LAST_CSF}" ""

LAST_CSF=""
: > "$LOG_DIR/decisions.jsonl"
seed_older_sightings "198.51.100.24" 2
feed $'198.51.100.24\t80\t500\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"srcset_flood","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check srcset-flood-capped-persist-stays-watch "$(last_action)" "watch"
check srcset-flood-capped-persist-no-backend "${LAST_CSF}" ""

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
