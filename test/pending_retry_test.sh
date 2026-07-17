#!/usr/bin/env bash
# test/pending_retry_test.sh — durable retry of a `failed` block.
#
# THE seed-bug regression. Ingest is cursor-based (lib/ingest.sh): a log line is
# scored by exactly one scan and never re-read, so a `failed` block used to be
# re-driven ONLY if the offender kept producing fresh evidence. A single-burst
# offender whose CF/CSF block hit a transient backend error was silently, never
# blocked. These tests drive the block path with NO re-ingested evidence — the
# retry must come purely from the durable pending_blocks queue.
#
# Exercises the real _swatter_apply_plane + _swatter_retry_pending against the
# real store, with only the firewall backends + external side effects stubbed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-pending.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce; DIRECT_BACKEND=csf; TTL_LADDER="3600 21600 86400 259200"
MAX_BLOCKS_PER_RUN=100
_SW_TOTAL_BLOCKS=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
swatter_store_init

# Stub only the firewall backends + external side effects; keep the REAL store.
swatter_is_never_block()      { return 1; }
swatter_cf_manages_plane()    { return 0; }
swatter_store_sighting_clear(){ :; }
swatter_abuseipdb_report()    { :; }
_swatter_audit()              { :; }
# Toggle backend outcome per-test.
CF_RC=1
swatter_cf_block()          { [[ "$CF_RC" == "0" ]] || SWATTER_LAST_BACKEND_ERR="cf 503 transient"; return "$CF_RC"; }
swatter_block_direct_temp() { return "${DIRECT_RC:-0}"; }
swatter_block_direct_perm() { return "${DIRECT_RC:-0}"; }

DB="$(_swatter_db)"
pcount() { sqlite3 "$DB" "SELECT COUNT(*) FROM pending_blocks WHERE ip='$1'${2:+ AND plane='$2'};" 2>/dev/null; }

# --- A. a `failed` CF block ENQUEUES a durable pending row, blocks nothing ----
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.7 VIA_CF temp 3600 "score=91" "x.com" 1 91 '{"e":1}' 91
check A-enqueued        "$(pcount 9.9.8.7 VIA_CF)" "1"
check A-not-blocked     "$(swatter_store_active_on 9.9.8.7 cloudflare && echo yes || echo no)" "no"
check A-attempts1       "$(sqlite3 "$DB" "SELECT attempts FROM pending_blocks WHERE ip='9.9.8.7';")" "1"

# --- B. THE regression: drain re-drives it with NO fresh evidence -------------
# Backend recovers; the retry runs purely off the queue (no scan, no ingest).
CF_RC=0; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1
check B-blocked-now     "$(swatter_store_active_on 9.9.8.7 cloudflare && echo yes || echo no)" "yes"
check B-queue-cleared   "$(pcount 9.9.8.7)" "0"

# --- C. repeated failure BUMPS attempts (keeps the row, backs off) ------------
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.6 VIA_CF temp 3600 "score=80" "x.com" 1 80 '{}' 80
check C-attempts1       "$(sqlite3 "$DB" "SELECT attempts FROM pending_blocks WHERE ip='9.9.8.6';")" "1"
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1
check C-attempts2       "$(sqlite3 "$DB" "SELECT attempts FROM pending_blocks WHERE ip='9.9.8.6';")" "2"
check C-still-queued    "$(pcount 9.9.8.6)" "1"

# --- D. max-attempts reaps the row (unsatisfiable intent self-limits) ---------
PENDING_RETRY_MAX_ATTEMPTS=2 _SW_TOTAL_BLOCKS=0 CF_RC=1 _swatter_retry_pending 1
check D-reaped-attempts "$(pcount 9.9.8.6)" "0"

# --- E. max-age reaps the row -------------------------------------------------
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.5 VIA_CF temp 3600 "score=80" "x.com" 1 80 '{}' 80
now="$(swatter_now)"
sqlite3 "$DB" "UPDATE pending_blocks SET first_failed=$(( now - 200000 )) WHERE ip='9.9.8.5';"
PENDING_RETRY_MAX_AGE_HOURS=24 _SW_TOTAL_BLOCKS=0 CF_RC=1 _swatter_retry_pending 1
check E-reaped-age       "$(pcount 9.9.8.5)" "0"

# --- F. operator `unblock` cancels a queued retry -----------------------------
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.4 VIA_CF temp 3600 "score=80" "x.com" 1 80 '{}' 80
check F-queued-before    "$(pcount 9.9.8.4)" "1"
swatter_block_direct_unblock() { return 0; }; swatter_cf_unblock() { return 0; }
swatter_store_unblock 9.9.8.4
check F-cleared-after     "$(pcount 9.9.8.4)" "0"

# --- G. an IP allow-listed AFTER queueing is dropped, never re-blocked --------
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.3 VIA_CF temp 3600 "score=80" "x.com" 1 80 '{}' 80
swatter_is_never_block() { return 0; }        # now exempt
CF_RC=0; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1
check G-dropped-exempt    "$(pcount 9.9.8.3)" "0"
check G-not-blocked       "$(swatter_store_active_on 9.9.8.3 cloudflare && echo yes || echo no)" "no"
swatter_is_never_block() { return 1; }        # restore

# --- H. a row already covered on its plane (later scan won) clears, no dup ----
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.2 VIA_CF temp 3600 "score=80" "x.com" 1 80 '{}' 80
swatter_store_plane_set 9.9.8.2 cloudflare perm 259200   # a fresh scan blocked it
CF_RC=0; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1
check H-cleared-covered   "$(pcount 9.9.8.2)" "0"

# --- I. a SUCCESSFUL block never enqueues anything ----------------------------
CF_RC=0; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.8.1 VIA_CF temp 3600 "score=95" "x.com" 1 95 '{}' 95
check I-no-queue-on-ok     "$(pcount 9.9.8.1)" "0"
check I-blocked            "$(swatter_store_active_on 9.9.8.1 cloudflare && echo yes || echo no)" "yes"

# --- K. a live TEMP must NOT clear a queued PERM (Blocker #1 regression) -------
# A perm escalation that failed while a prior temp is still live must keep
# retrying the perm — clearing it on the temp's coverage would silently drop the
# escalation once the temp expires (the exact bug shape the fix closes).
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.7.1 VIA_CF perm 0 "score=99" "x.com" 1 99 '{}' 99   # perm fails -> queued
swatter_store_plane_set 9.9.7.1 cloudflare temp 3600                          # a live TEMP covers the plane
check K-perm-queued        "$(sqlite3 "$DB" "SELECT action FROM pending_blocks WHERE ip='9.9.7.1';")" "perm"
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1                                                      # backend still down
check K-perm-not-cleared   "$(pcount 9.9.7.1)" "1"                            # live temp did NOT clear it
check K-not-perm-yet       "$(swatter_store_is_perm_on 9.9.7.1 cloudflare && echo yes || echo no)" "no"
CF_RC=0; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1                                                      # backend recovers
check K-perm-landed        "$(swatter_store_is_perm_on 9.9.7.1 cloudflare && echo yes || echo no)" "yes"
check K-perm-dequeued      "$(pcount 9.9.7.1)" "0"

# --- L. a live TEMP DOES clear a queued TEMP (coverage matches intent) ---------
CF_RC=1; _SW_TOTAL_BLOCKS=0
_swatter_apply_plane 9.9.7.2 VIA_CF temp 3600 "score=80" "x.com" 1 80 '{}' 80
swatter_store_plane_set 9.9.7.2 cloudflare temp 3600
CF_RC=0; _SW_TOTAL_BLOCKS=0
_swatter_retry_pending 1
check L-temp-cleared       "$(pcount 9.9.7.2)" "0"

# --- M. per-run retry cap leaves headroom (drains at most MAX_PER_RUN) ---------
CF_RC=1
for n in 1 2 3 4 5; do _SW_TOTAL_BLOCKS=0; _swatter_apply_plane 10.0.0.$n VIA_CF temp 3600 "s" "x.com" 1 80 '{}' 80; done
before="$(sqlite3 "$DB" "SELECT COUNT(*) FROM pending_blocks WHERE ip LIKE '10.0.0.%';")"
# With cap=2 and backend still down, only 2 rows get a (failed) re-attempt -> attempts=2;
# the rest stay at attempts=1, untouched.
PENDING_RETRY_MAX_PER_RUN=2 _SW_TOTAL_BLOCKS=0 CF_RC=1 _swatter_retry_pending 1
bumped="$(sqlite3 "$DB" "SELECT COUNT(*) FROM pending_blocks WHERE ip LIKE '10.0.0.%' AND attempts>=2;")"
check M-cap-before5        "$before" "5"
check M-cap-bumped2        "$bumped" "2"

# --- J. flatfile mode: pending helpers no-op cleanly (no error, no rows) ------
( STORE=flatfile
  swatter_store_pending_set 1.2.3.4 VIA_CF temp 3600 r x.com 80 80 '{}' temp
  check J-flatfile-list-empty "$(swatter_store_pending_list | wc -l | tr -d ' ')" "0"
)

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
