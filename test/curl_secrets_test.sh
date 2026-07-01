#!/usr/bin/env bash
# test/curl_secrets_test.sh — secrets must never ride in curl argv.
# /proc/<pid>/cmdline is world-readable: on a shared box any local user running
# `ps` during a scan would see the raw CF bearer token / API keys / Twilio auth.
# Every credentialed curl call site must pass the secret via a 0600 config file
# (`curl -K <file>`) instead. The mock curl records its argv AND the -K file
# contents, so we can assert the secret reached curl without touching argv.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block_cf.sh"
source "${ROOT}/lib/mailer.sh"
source "${ROOT}/lib/alerts.sh"
source "${ROOT}/lib/notify.sh"
source "${ROOT}/lib/report_abuseipdb.sh"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-secr.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
LOG="$TMP/curl.log"; : > "$LOG"
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
# argv must NOT contain the secret; the -K config file MUST.
argv_clean() { local n="$1" secret="$2"
  if grep -F "ARGS:" "$LOG" | grep -qF "$secret"; then echo "FAIL ${n}-argv-leak"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi; }
cfg_has() { local n="$1" pat="$2"
  if grep -qF "$pat" "$LOG"; then PASS=$((PASS+1)); else echo "FAIL ${n}-cfg-missing: '${pat}'"; FAIL=$((FAIL+1)); fi; }

# Mock curl: log argv, dump any -K config file, emit MOCK_STDOUT.
curl() {
    local a prev="" cfg=""
    for a in "$@"; do [[ "$prev" == "-K" ]] && cfg="$a"; prev="$a"; done
    printf 'ARGS: %s\n' "$*" >> "$LOG"
    [[ -n "$cfg" && -r "$cfg" ]] && cat "$cfg" >> "$LOG"
    printf '%s' "${MOCK_STDOUT:-}"
    return "${MOCK_RC:-0}"
}

SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=1

# 1) Cloudflare API bearer token.
: > "$LOG"; MOCK_STDOUT='{"success":true}'
_cf_api "CFSECRETTOKEN" GET "/zones" >/dev/null
argv_clean cf "CFSECRETTOKEN"
cfg_has cf 'header = "Authorization: Bearer CFSECRETTOKEN"'

# 2) SendGrid key.
: > "$LOG"; MOCK_STDOUT="202"
REPORT_FROM="s@x"; REPORT_FROM_NAME="Swatter"
SENDGRID_KEY_FILE="$TMP/sg.key"; printf 'SGSECRETKEY\n' > "$SENDGRID_KEY_FILE"
_mailer_sendgrid "ops@x" "s" "b" >/dev/null 2>&1
argv_clean sendgrid "SGSECRETKEY"
cfg_has sendgrid 'header = "Authorization: Bearer SGSECRETKEY"'

# 3) Brevo key.
: > "$LOG"; MOCK_STDOUT="201"
BREVO_KEY_FILE=""; BREVO_API_KEY="BREVOSECRET"
_mailer_brevo "ops@x" "s" "b" >/dev/null 2>&1
argv_clean brevo "BREVOSECRET"
cfg_has brevo 'header = "api-key: BREVOSECRET"'

# 4) Twilio (alerts.sh) SID:token basic auth.
: > "$LOG"; MOCK_STDOUT="201"
TWILIO_SID="AC123"; TWILIO_FROM="+15550001111"
TWILIO_TOKEN_FILE="$TMP/tw.tok"; printf 'TWSECRETTOK\n' > "$TWILIO_TOKEN_FILE"
_alert_sms_twilio "+15552223333" "hi" >/dev/null 2>&1
argv_clean alerts-twilio "TWSECRETTOK"
cfg_has alerts-twilio 'user = "AC123:TWSECRETTOK"'

# 5) Twilio (notify.sh) basic auth.
: > "$LOG"; MOCK_STDOUT=""
ALERT_SMS_TO="+15552223333"
_notify_sms "subj" "body" >/dev/null 2>&1
argv_clean notify-twilio "TWSECRETTOK"
cfg_has notify-twilio 'user = "AC123:TWSECRETTOK"'

# 6) AbuseIPDB key header (backgrounded POST).
: > "$LOG"; MOCK_STDOUT=""
STATE_DIR="$TMP"; SWATTER_MODE="enforce"
ABUSEIPDB_REPORT="true"; ABUSEIPDB_KEY="ABUSESECRET"; ABUSEIPDB_REPORT_TTL=900
swatter_abuseipdb_report 1.2.3.4 '{"decisive_rule":"honeypot"}' "trap" >/dev/null 2>&1
wait 2>/dev/null
argv_clean abuseipdb "ABUSESECRET"
cfg_has abuseipdb 'header = "Key: ABUSESECRET"'

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
