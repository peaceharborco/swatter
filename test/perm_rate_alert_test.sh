#!/usr/bin/env bash
# test/perm_rate_alert_test.sh — the perm-rate tripwire: ladder-only counting,
# threshold trip, and an alert key that cannot hide a multi-hour incident.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
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

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
