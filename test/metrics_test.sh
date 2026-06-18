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

# Empty path disables: returns 0 and writes nothing.
swatter_metrics_write ""; check empty-rc "$?" "0"

# Missing dir warns + skips: returns 0 and creates no file at the bad path.
swatter_metrics_write "$STATE_DIR/nope/swatter.prom" 2>/dev/null; check missingdir-rc "$?" "0"
[[ ! -e "$STATE_DIR/nope/swatter.prom" ]] && PASS=$((PASS+1)) || { echo "FAIL missingdir-nofile"; FAIL=$((FAIL+1)); }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
