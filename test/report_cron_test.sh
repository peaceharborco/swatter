#!/usr/bin/env bash
# test/report_cron_test.sh — install.sh generates the report cron line from config.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/install/install.sh" --source-only 2>/dev/null || true   # load funcs without running main
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

TMPL="${ROOT}/install/swatter.cron"
out="$(_swatter_render_cron "$TMPL" "0 4" "")"
check no-tz-line   "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=')" "0"
check report-utc   "$(printf '%s\n' "$out" | grep -c '^0 4 \* \* \* root .*swatter report')" "1"
out="$(_swatter_render_cron "$TMPL" "0 4" "America/Los_Angeles")"
check tz-line      "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=America/Los_Angeles')" "1"
check report-after-tz "$(printf '%s\n' "$out" | awk '/^CRON_TZ=/{tz=NR} /swatter report/{r=NR} END{print (tz<r)?"ok":"bad"}')" "ok"
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
