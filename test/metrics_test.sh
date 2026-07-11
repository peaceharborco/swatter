#!/usr/bin/env bash
# test/metrics_test.sh — exposition format + atomic write + empty-disables.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/metrics.sh"

PASS=0; FAIL=0
STORE=flatfile
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-metrics.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
SWATTER_VERSION="1.3.0"; SWATTER_MODE="enforce"
SWATTER_RUN_WATCHED=3; SWATTER_RUN_ACTED=1; SWATTER_RUN_BREAKER=0
swatter_store_init
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

out="$(swatter_metrics_emit)"
case "$out" in *'# TYPE swatter_build_info gauge'*) PASS=$((PASS+1));; *) echo "FAIL has-type"; FAIL=$((FAIL+1));; esac
case "$out" in *'swatter_build_info{version="1.3.0"} 1'*) PASS=$((PASS+1));; *) echo "FAIL build-info"; FAIL=$((FAIL+1));; esac
case "$out" in *'swatter_scan_watched 3'*) PASS=$((PASS+1));; *) echo "FAIL watched"; FAIL=$((FAIL+1));; esac
case "$out" in *'swatter_mode{mode="enforce"} 1'*) PASS=$((PASS+1));; *) echo "FAIL mode"; FAIL=$((FAIL+1));; esac
case "$out" in *'# HELP swatter_intel_quota_used'*) PASS=$((PASS+1));; *) echo "FAIL quota-help"; FAIL=$((FAIL+1));; esac
check quota-type-once "$(printf '%s\n' "$out" | grep -c '^# TYPE swatter_intel_quota_used')" "1"

# Atomic write produces a readable file.
swatter_metrics_write "$STATE_DIR/swatter.prom"
[[ -s "$STATE_DIR/swatter.prom" ]] && PASS=$((PASS+1)) || { echo "FAIL wrote-file"; FAIL=$((FAIL+1)); }

# Empty METRICS_FILE disables: returns 0, writes nothing, warns nothing.
# (An explicit "" arg falls back to $METRICS_FILE per ${1:-...}, so disabling
# is expressed via the config var, matching how swatter.conf does it.)
METRICS_FILE="" swatter_metrics_write; check empty-rc "$?" "0"

# Missing dir warns + skips: returns 0 and creates no file at the bad path.
warn1="$(swatter_metrics_write "$STATE_DIR/nope/swatter.prom" 2>&1 >/dev/null)"; check missingdir-rc "$?" "0"
[[ ! -e "$STATE_DIR/nope/swatter.prom" ]] && PASS=$((PASS+1)) || { echo "FAIL missingdir-nofile"; FAIL=$((FAIL+1)); }
check missingdir-warned "$(printf '%s' "$warn1" | grep -c 'missing or unwritable')" "1"

# Warn-once persists ACROSS processes (each */5 scan is a fresh shell): the
# stamp file suppresses the repeat warning, and a later writable dir clears it.
stamp_count() { find "$STATE_DIR" -maxdepth 1 -name '.metrics-warned.*' | grep -c .; }
warn2="$(swatter_metrics_write "$STATE_DIR/nope/swatter.prom" 2>&1 >/dev/null)"
check missingdir-warn-once "$(printf '%s' "$warn2" | grep -c 'missing or unwritable')" "0"
check warn-stamp-set "$(stamp_count)" "1"
# A DIFFERENT bad dir is a different outage: keyed stamp -> warns independently.
warn2b="$(swatter_metrics_write "$STATE_DIR/other/swatter.prom" 2>&1 >/dev/null)"
check otherdir-warns "$(printf '%s' "$warn2b" | grep -c 'missing or unwritable')" "1"
check warn-stamp-two "$(stamp_count)" "2"
swatter_metrics_write "$STATE_DIR/swatter.prom"   # writable dir -> ITS stamp cleared (others keyed, untouched)
warn3="$(swatter_metrics_write "$STATE_DIR/nope/swatter.prom" 2>&1 >/dev/null)"
check missingdir-still-suppressed "$(printf '%s' "$warn3" | grep -c 'missing or unwritable')" "0"
# Simulate the bad dir being fixed then breaking again: clear its stamp the way
# a successful write to THAT dir would, and confirm it re-warns.
mkdir -p "$STATE_DIR/nope"; swatter_metrics_write "$STATE_DIR/nope/swatter.prom"
check fixed-dir-writes "$([[ -s "$STATE_DIR/nope/swatter.prom" ]] && echo yes || echo no)" "yes"
rm -rf "$STATE_DIR/nope"
warn4="$(swatter_metrics_write "$STATE_DIR/nope/swatter.prom" 2>&1 >/dev/null)"
check missingdir-rewarn "$(printf '%s' "$warn4" | grep -c 'missing or unwritable')" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
