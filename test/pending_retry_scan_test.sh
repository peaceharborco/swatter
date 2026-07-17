#!/usr/bin/env bash
# test/pending_retry_scan_test.sh — the durable-retry drain fires INSIDE the real
# swatter_scan, not just when _swatter_retry_pending is called directly. Scan 1
# fails a block (queues the intent); scan 2 ingests ZERO offenders — the aged-out
# case the seed bug dropped forever — yet the block still lands off the queue.
# Guards the swatter_scan wiring (drain call + `healthy` in scope). Mirrors the
# scan_wire_test harness: firewall + ingest + scorer stubbed, real store + scan.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/metrics.sh"
source "${ROOT}/lib/score.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STORE=sqlite; SWATTER_MODE=enforce
# Mirror prod dep detection (bin/swatter sets this before scanning) so the drain's
# jq-gated retry:1 evidence merge runs when jq is available.
SWATTER_HAVE_JQ="$(command -v jq >/dev/null 2>&1 && echo 1 || echo 0)"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-prs.XXXXXX")"; LOG_DIR="$STATE_DIR/log"; mkdir -p "$LOG_DIR"
trap 'rm -rf "$STATE_DIR"' EXIT
SCORE_WATCH=50; SCORE_TEMP=70; TTL_LADDER="3600 21600 86400"; REPEAT_N=3; REPEAT_WINDOW_DAYS=7
CRITICAL_TTL_FLOOR=86400; MAX_BLOCKS_PER_RUN=25; MAX_CSF_DENIES_PER_RUN=10; W_REPUTATION=14
PERSIST_ENABLE=false; METRICS_FILE=""; CF_MODE="off"; DIRECT_WEB_PORTS=""; ASN_SIGNAL_ENABLE=false
swatter_store_init

swatter_failclosed_active() { return 1; }
swatter_build_direct_set()  { :; }
swatter_cf_sweep_expired()  { :; }
swatter_ingest()            { :; }
swatter_intel_available()   { return 1; }
swatter_classify()          { echo "DIRECT"; }
swatter_is_never_block()    { return 1; }
swatter_cf_manages_plane()  { return 1; }
swatter_notify()            { :; }
BLOCK_RC=0
swatter_block_direct_temp() { return "$BLOCK_RC"; }
swatter_block_direct_perm() { return "$BLOCK_RC"; }
feed() { FEED_LINE="$1"; _swatter_run_scorer() { printf '%s\n' "$FEED_LINE"; }; }
DB="$(_swatter_db)"
pend()    { sqlite3 "$DB" "SELECT COUNT(*) FROM pending_blocks;"; }
active()  { swatter_store_active_on 203.0.113.9 csf && echo yes || echo no; }
lastact() { tail -1 "$LOG_DIR/decisions.jsonl" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p'; }

# Scan 1: offender present, backend DOWN -> failed + queued, nothing blocked.
BLOCK_RC=1
feed $'203.0.113.9\t95\t40\t{"novhost":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check scan1-failed    "$(lastact)" "failed"
check scan1-queued    "$(pend)"    "1"
check scan1-notblocked "$(active)" "no"

# Scan 2: ingest yields NO offenders (aged out), backend RECOVERED -> the in-scan
# drain re-drives the queued block with no fresh evidence. The retried primary
# block records the REAL action (so the digest counts it), marked evidence.retry=1.
BLOCK_RC=0
feed ''
swatter_scan >/dev/null 2>&1
check scan2-real-action "$(lastact)" "temp"
[[ "$SWATTER_HAVE_JQ" == "1" ]] && \
  check scan2-retry-mark "$(tail -1 "$LOG_DIR/decisions.jsonl" | grep -c '"retry":1')" "1"
check scan2-dequeued    "$(pend)"    "0"
check scan2-blocked     "$(active)"  "yes"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
