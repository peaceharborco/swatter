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
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/metrics.sh"
source "${ROOT}/lib/score.sh"

PASS=0; FAIL=0
STORE=sqlite; SWATTER_MODE="enforce"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-wire.XXXXXX")"
LOG_DIR="$STATE_DIR/log"; mkdir -p "$LOG_DIR"
trap 'rm -rf "$STATE_DIR"' EXIT
# thresholds + caps + weights
SCORE_WATCH=50; SCORE_TEMP=70; SCORE_PERM=85
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
last_action() { tail -1 "$LOG_DIR/decisions.jsonl" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p'; }

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

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
