#!/usr/bin/env bash
# test/config_defaults_test.sh — new keys have safe built-in defaults.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/origin_lock.sh"   # for _ol_mode default guard
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
check asn-default       "${ASN_SIGNAL_ENABLE}" "false"
check wasn-default      "${W_ASN}" "12"
check persist-default   "${PERSIST_ENABLE}" "true"
check persist-n         "${PERSIST_N}" "6"
check bucket-default    "${PERSIST_BUCKET_SECONDS}" "3600"
check gn-quota-default  "${GREYNOISE_DAILY_QUOTA}" "100"
check intel-has-gn      "$(case " ${INTEL_PROVIDERS} " in *' greynoise '*) echo yes;; *) echo no;; esac)" "yes"
check httpbl-empty      "${HTTPBL_KEY}" ""
check metrics-nonempty  "$([[ -n "${METRICS_FILE}" ]] && echo yes || echo no)" "yes"
check honeypot-override "${HONEYPOT_OVERRIDES_SUPPRESS}" "false"
check persist-window    "${PERSIST_WINDOW_DAYS}" "3"
check hosting-nonempty  "$([[ -n "${HOSTING_ASNS_FILE}" ]] && echo yes || echo no)" "yes"
check intel-has-firehol "$(case " ${INTEL_PROVIDERS} " in *' firehol_level1 '*) echo yes;; *) echo no;; esac)" "yes"
check intel-has-dshield "$(case " ${INTEL_PROVIDERS} " in *' dshield '*) echo yes;; *) echo no;; esac)" "yes"
check intel-has-blde    "$(case " ${INTEL_PROVIDERS} " in *' blocklist_de '*) echo yes;; *) echo no;; esac)" "yes"
check abl-conf-default   "${ABUSEIPDB_BLOCKLIST_CONFIDENCE}" "90"
# abuseipdb_blocklist is OPT-IN: must NOT be in the default list.
check abl-optin "$(case " ${INTEL_PROVIDERS} " in *' abuseipdb_blocklist '*) echo in;; *) echo out;; esac)" "out"
check direct-backend-default "${DIRECT_BACKEND}" "csf"
# origin-lock ships inert: with ORIGIN_LOCK unset the resolved mode must be "off"
# (guards the "present but not armed unless the operator runs apply" claim).
unset ORIGIN_LOCK 2>/dev/null || true
check origin-lock-default     "$(_ol_mode)" "off"
check alert-repeat-default   "${ALERT_REPEAT_TTL}" "21600"
check abuse-report-default   "${ABUSEIPDB_REPORT}" "false"
check abuse-report-ttl       "${ABUSEIPDB_REPORT_TTL}" "900"
check webhook-fmt-default    "${ALERT_WEBHOOK_FORMAT}" "auto"
check report-cron-default     "${REPORT_CRON}" "0 4"
check report-cron-tz-default  "${REPORT_CRON_TZ}" ""
check ol-digest-default       "${ORIGIN_LOCK_DIGEST}" "auto"
check ol-log-default          "${ORIGIN_LOCK_LOG}" ""
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
