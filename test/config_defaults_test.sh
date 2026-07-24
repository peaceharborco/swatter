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
# From-header display name must NOT contain parentheses: RFC 5322 treats "(...)"
# as a comment that mail clients strip, so "Swatter (host)" shows as just
# "Swatter". Brackets display verbatim. Guards against regressing to parens.
check fromname-no-parens "$(case "${REPORT_FROM_NAME}" in *'('*|*')'*) echo bad;; *) echo ok;; esac)" "ok"
check fromname-brackets  "$(case "${REPORT_FROM_NAME}" in 'Swatter ['*']') echo ok;; *) echo no;; esac)" "ok"
# SMS grade-alert defaults: OFF out of the box, sensible trigger grades + dedup.
check fatal-scanner-set   "$([[ -n "${ERROR_FATAL_SCANNER}" ]] && echo yes || echo no)" "yes"
check fatal-scanner-reps  "${ERROR_FATAL_SCANNER_REPEATS}" "3"
check alert-sms-off      "${ALERT_SMS_METHOD}" ""
check alert-sms-grades   "${ALERT_SMS_GRADES}" "RED"
check alert-sms-dedup    "${ALERT_SMS_DEDUP_HOURS}" "6"
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

# --- escalation knob defaults + validation ---------------------------------
check repeat-n-default   "${REPEAT_N}" "3"
check repeat-window-def  "${REPEAT_WINDOW_DAYS}" "7"
check repeat-n-crit-default "${REPEAT_N_CRITICAL_SINGLE}" "4"

# Validation runs at the END of swatter_load_config, after the conf is sourced,
# so an operator typo cannot bypass it. An empty REPEAT_N is the dangerous one:
# unvalidated it makes (( prior+1 >= REPEAT_N )) true on the FIRST offense, so
# every IP is permanently banned. Each case must fall back to the shipped value.
_vconf="$(mktemp "${TMPDIR:-/tmp}/swatter-vconf.XXXXXX")"
trap 'rm -f "$_vconf"' EXIT

vcheck() { # vcheck <name> <conf-line> <var> <want>
  local name="$1" line="$2" var="$3" want="$4"
  printf '%s\n' "$line" > "$_vconf"
  ( SWATTER_CONF="$_vconf"; swatter_load_config >/dev/null 2>&1
    printf '%s' "${!var}" ) > "${_vconf}.out"
  check "$name" "$(cat "${_vconf}.out")" "$want"
}

vcheck repeat-n-empty     'REPEAT_N=""'                REPEAT_N            "3"
vcheck repeat-n-alpha     'REPEAT_N="abc"'             REPEAT_N            "3"
vcheck repeat-n-zero      'REPEAT_N=0'                 REPEAT_N            "3"
vcheck repeat-n-huge      'REPEAT_N=999'               REPEAT_N            "3"
vcheck repeat-n-valid     'REPEAT_N=4'                 REPEAT_N            "4"
vcheck window-empty       'REPEAT_WINDOW_DAYS=""'      REPEAT_WINDOW_DAYS  "7"
vcheck window-suffix      'REPEAT_WINDOW_DAYS="30d"'   REPEAT_WINDOW_DAYS  "7"
vcheck window-over-cap    'REPEAT_WINDOW_DAYS=365'     REPEAT_WINDOW_DAYS  "7"
vcheck window-valid       'REPEAT_WINDOW_DAYS=30'      REPEAT_WINDOW_DAYS  "30"
# Leading-zero numerals must be normalized to decimal, not left as octal-ish
# strings: bash `(( ))` parses "020"/"030" as octal (16/24), so the stored
# value must be the canonical decimal form the fix reassigns, proving the
# `10#` normalization ran rather than just accepting the raw string.
vcheck repeat-n-padded    'REPEAT_N="020"'             REPEAT_N            "20"
vcheck window-padded      'REPEAT_WINDOW_DAYS="030"'   REPEAT_WINDOW_DAYS  "30"

# REPEAT_N_CRITICAL_SINGLE: same footgun class — it flows unguarded into
# lib/score.sh's `(( prior + 1 >= thresh ))`. A non-numeric typo is the
# dangerous one: unvalidated, bash arithmetic treats it as 0, so an IP perms
# on its 2nd CRITICAL-single offense (worse than pre-gate behavior).
vcheck repeat-n-crit-empty  'REPEAT_N_CRITICAL_SINGLE=""'    REPEAT_N_CRITICAL_SINGLE "4"
vcheck repeat-n-crit-alpha  'REPEAT_N_CRITICAL_SINGLE="abc"' REPEAT_N_CRITICAL_SINGLE "4"
vcheck repeat-n-crit-zero   'REPEAT_N_CRITICAL_SINGLE=0'     REPEAT_N_CRITICAL_SINGLE "4"
vcheck repeat-n-crit-huge   'REPEAT_N_CRITICAL_SINGLE=999'   REPEAT_N_CRITICAL_SINGLE "4"
vcheck repeat-n-crit-valid  'REPEAT_N_CRITICAL_SINGLE=5'     REPEAT_N_CRITICAL_SINGLE "5"
vcheck repeat-n-crit-padded 'REPEAT_N_CRITICAL_SINGLE="020"' REPEAT_N_CRITICAL_SINGLE "20"

# ...and bounds alone don't protect it: the knob only ever RAISES the bar, so a
# value BELOW REPEAT_N inverts the gate it exists to be. REPEAT_N_CRITICAL_
# SINGLE=1 (a plausible misreading as "+1 more") passes 1-20 validation and
# perms an all-CRITICAL-single IP on its 2nd offense. Must clamp up to REPEAT_N.
vcheck crit-clamp-below     'REPEAT_N_CRITICAL_SINGLE=1'     REPEAT_N_CRITICAL_SINGLE "3"
vcheck crit-clamp-equal     'REPEAT_N_CRITICAL_SINGLE=3'     REPEAT_N_CRITICAL_SINGLE "3"
# Clamp must run AFTER both knobs are validated/normalized, so it compares the
# operator's REPEAT_N — not the built-in default — and the octal-normalized form.
vcheck crit-clamp-vs-conf-n $'REPEAT_N=6\nREPEAT_N_CRITICAL_SINGLE=4' REPEAT_N_CRITICAL_SINGLE "6"
vcheck crit-clamp-padded-n  $'REPEAT_N="010"\nREPEAT_N_CRITICAL_SINGLE=4' REPEAT_N_CRITICAL_SINGLE "10"
# An invalid value falls back to 4, which is still >= a default REPEAT_N=3 —
# but with REPEAT_N=6 the fallback itself must be clamped, not shipped as-is.
vcheck crit-clamp-fallback  $'REPEAT_N=6\nREPEAT_N_CRITICAL_SINGLE="abc"' REPEAT_N_CRITICAL_SINGLE "6"

# --- perm-rate tripwire knobs ----------------------------------------------
# Unvalidated these are the same footgun class, on the one channel that beats
# the 24h digest. Empty is the loud one: `(( 0 >= "" ))` is TRUE, so the
# tripwire fires every run with zero perms placed and, because the alert key is
# hour-bucketed, keeps firing hourly until the operator mutes the channel.
# Non-numeric is the silent one: under `set -u` the arithmetic aborts the shell
# INSIDE swatter_scan, so every */5 cron run dies before swatter_swarm_publish.
check perm-alert-run-default2 "${PERM_RATE_ALERT_PER_RUN}" "5"
check perm-alert-day-default2 "${PERM_RATE_ALERT_PER_DAY}" "15"
vcheck perm-run-empty     'PERM_RATE_ALERT_PER_RUN=""'      PERM_RATE_ALERT_PER_RUN "5"
vcheck perm-run-alpha     'PERM_RATE_ALERT_PER_RUN="abc"'   PERM_RATE_ALERT_PER_RUN "5"
vcheck perm-run-zero      'PERM_RATE_ALERT_PER_RUN=0'       PERM_RATE_ALERT_PER_RUN "5"
vcheck perm-run-huge      'PERM_RATE_ALERT_PER_RUN=100000'  PERM_RATE_ALERT_PER_RUN "5"
vcheck perm-run-padded    'PERM_RATE_ALERT_PER_RUN="020"'   PERM_RATE_ALERT_PER_RUN "20"
vcheck perm-run-valid     'PERM_RATE_ALERT_PER_RUN=3'       PERM_RATE_ALERT_PER_RUN "3"
vcheck perm-day-empty     'PERM_RATE_ALERT_PER_DAY=""'      PERM_RATE_ALERT_PER_DAY "15"
vcheck perm-day-alpha     'PERM_RATE_ALERT_PER_DAY="abc"'   PERM_RATE_ALERT_PER_DAY "15"
vcheck perm-day-zero      'PERM_RATE_ALERT_PER_DAY=0'       PERM_RATE_ALERT_PER_DAY "15"
vcheck perm-day-huge      'PERM_RATE_ALERT_PER_DAY=100000'  PERM_RATE_ALERT_PER_DAY "15"
vcheck perm-day-padded    'PERM_RATE_ALERT_PER_DAY="030"'   PERM_RATE_ALERT_PER_DAY "30"
vcheck perm-day-valid     'PERM_RATE_ALERT_PER_DAY=40'      PERM_RATE_ALERT_PER_DAY "40"
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
