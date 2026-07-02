#!/usr/bin/env bash
# test/report_cron_test.sh — install.sh renders the nightly report cron into its
# OWN file (/etc/cron.d/swatter-report) so CRON_TZ scopes to the report only (a
# bare CRON_TZ in the shared cron would also shift the 5-min scan). The report
# line redirects to a log so a failed send is never silently discarded.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/install/install.sh" --source-only 2>/dev/null || true   # load funcs without running main
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# No timezone -> no CRON_TZ line; report line present with the log redirect + MAILTO.
out="$(_swatter_report_cron_file "0 4" "")"
check no-tz-line       "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=')" "0"
check report-line      "$(printf '%s\n' "$out" | grep -Ec '^0 4 \* \* \* root .*swatter report')" "1"
check mailto-line      "$(printf '%s\n' "$out" | grep -c '^MAILTO=')" "1"
check redirect-present "$(printf '%s\n' "$out" | grep -c 'report.log 2>&1')" "1"

# Timezone set -> CRON_TZ=<tz>, and it must precede the report line (so it applies).
out="$(_swatter_report_cron_file "0 4" "America/Los_Angeles")"
check tz-line          "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=America/Los_Angeles')" "1"
check tz-before-report "$(printf '%s\n' "$out" | awk '/^CRON_TZ=/{tz=NR} /swatter report/{r=NR} END{print (tz<r)?"ok":"bad"}')" "ok"
check redirect-present-tz "$(printf '%s\n' "$out" | grep -c 'report.log 2>&1')" "1"

# The shared template (/etc/cron.d/swatter) must NOT carry the report line — it
# lives only in the dedicated file now.
check tmpl-no-report   "$(grep -c 'swatter report' "${ROOT}/install/swatter.cron")" "0"

# Regression (2026-07-01): install.sh runs in its own shell and never sources
# swatter.conf, so rendering from "${REPORT_CRON_TZ:-}" read empty env vars and
# every upgrade regenerated the cron WITHOUT the operator's CRON_TZ (report
# fired 04:00 UTC = 21:00 PDT). The render must read the LIVE conf file.
conf="$(mktemp "${TMPDIR:-/tmp}/swatter-conf.XXXXXX")"
printf 'REPORT_CRON="30 5"\nREPORT_CRON_TZ="America/Los_Angeles"\n' > "$conf"
out="$(_swatter_report_cron_from_conf "$conf")"
check conf-tz          "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=America/Los_Angeles')" "1"
check conf-schedule    "$(printf '%s\n' "$out" | grep -Ec '^30 5 \* \* \* root .*swatter report')" "1"
rm -f "$conf"

# Conf absent (fresh box edge) -> defaults: 0 4, no CRON_TZ line.
out="$(_swatter_report_cron_from_conf "/nonexistent/swatter.conf")"
check conf-missing-default "$(printf '%s\n' "$out" | grep -Ec '^0 4 \* \* \* root .*swatter report')" "1"
check conf-missing-no-tz   "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=')" "0"

# _install_local must render via the conf-reading path (one-line call so this
# guard can see it), never from install.sh's own environment again.
check install-renders-from-conf "$(grep -c '_swatter_report_cron_from_conf /etc/swatter/swatter.conf > /etc/cron.d/swatter-report' "${ROOT}/install/install.sh")" "1"
check install-no-env-render     "$(grep -c '_swatter_report_cron_file "\${REPORT_CRON' "${ROOT}/install/install.sh")" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
