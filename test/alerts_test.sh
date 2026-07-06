#!/usr/bin/env bash
# test/alerts_test.sh — SMS grade-alert trigger logic: which grades fire, the
# grades-config, dedup window, --test bypass, message content, fail-soft. The
# actual sender (swatter_send_sms) is stubbed to record calls — no network.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh" 2>/dev/null
source "${ROOT}/lib/alerts.sh"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-alerts.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
has()   { local n="$1" pat="$2"; if grep -qF -e "$pat" "$SENT"; then PASS=$((PASS+1)); else echo "FAIL ${n}: '${pat}' not sent"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$TMP"; SENT="$TMP/sent"; : > "$SENT"
# Record every send instead of hitting Twilio; SMS_RC controls the return code.
swatter_send_sms() { printf 'TO=%s BODY=%s\n' "$1" "$2" >> "$SENT"; return "${SMS_RC:-0}"; }
swatter_now() { echo "${NOW:-1000000}"; }
nsent() { wc -l < "$SENT" | tr -d ' '; }

# baseline config: twilio on, destination set, default trigger "RED"
ALERT_SMS_METHOD="twilio"; ALERT_SMS_TO="+15550001111"; ALERT_SMS_GRADES="RED"; ALERT_SMS_DEDUP_HOURS=6
REPORT_TRIAGE_HINT="/server-logs"
RPT_GRADE_WORD="x"; RPT_GRADE_SUB="sub"; RPT_RECO="Run /server-logs now."

# 1. method off -> never sends, even at RED
: > "$SENT"; ALERT_SMS_METHOD=""; RPT_GRADE=RED; swatter_alert_on_grade; check off-no-send "$(nsent)" "0"
ALERT_SMS_METHOD="twilio"
# 2. no destination -> off
: > "$SENT"; ALERT_SMS_TO=""; RPT_GRADE=RED; swatter_alert_on_grade; check no-dest "$(nsent)" "0"
ALERT_SMS_TO="+15550001111"

# 3. GREEN/YELLOW -> no send (only RED by default)
: > "$SENT"; rm -f "$TMP/last-sms-alert"
for g in GREEN YELLOW; do RPT_GRADE=$g; swatter_alert_on_grade; done
check no-send-below-red "$(nsent)" "0"

# 4. RED -> send
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=RED; swatter_alert_on_grade; check send-red "$(nsent)" "1"
has msg-host    "Swatter"
has msg-status  "Status RED"
has msg-icon    "🔴"
has msg-hint    "/server-logs"

# 4b. icon source: an explicit RPT_GRADE_ICON is used verbatim; an empty one falls
# back to deriving the lamp from the status word (both branches of the fallback).
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=RED RPT_GRADE_ICON="🟢" swatter_alert_on_grade
has msg-icon-explicit "🟢"    # primary path honors the provided icon (even if mismatched)
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=RED RPT_GRADE_ICON="" swatter_alert_on_grade
has msg-icon-fallback "🔴"    # empty icon -> derived from the RED status word

# 5. custom trigger set can include YELLOW
: > "$SENT"; rm -f "$TMP/last-sms-alert"; ALERT_SMS_GRADES="YELLOW RED"; RPT_GRADE=YELLOW; swatter_alert_on_grade; check custom-yellow "$(nsent)" "1"

# 6. dedup: same status within window suppressed; different status allowed; after window allowed
: > "$SENT"; rm -f "$TMP/last-sms-alert"; NOW=1000000
RPT_GRADE=RED; swatter_alert_on_grade               # 1st: sends
RPT_GRADE=RED; swatter_alert_on_grade               # dup within window: suppressed
check dedup-same "$(nsent)" "1"
RPT_GRADE=YELLOW; swatter_alert_on_grade            # different status: sends
check dedup-diff-status "$(nsent)" "2"
NOW=$(( 1000000 + 7*3600 )); RPT_GRADE=YELLOW; swatter_alert_on_grade   # past 6h window: sends
check dedup-after-window "$(nsent)" "3"
ALERT_SMS_GRADES="RED"

# 7. --test sends regardless of status, with [TEST], bypassing dedup
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=GREEN
swatter_alert_on_grade --test; swatter_alert_on_grade --test   # both send (no dedup)
check test-sends-twice "$(nsent)" "2"
has test-prefix "[TEST]"

# 8. fail-soft: sender returns nonzero -> alert function still returns 0
: > "$SENT"; rm -f "$TMP/last-sms-alert"; SMS_RC=1; RPT_GRADE=RED
swatter_alert_on_grade; check failsoft-rc "$?" "0"; SMS_RC=0

# 9. swatter_send_sms dispatch: method "" is a no-op success (restore real fn)
unset -f swatter_send_sms; source "${ROOT}/lib/alerts.sh"
ALERT_SMS_METHOD=""; swatter_send_sms "+1555" "hi"; check dispatch-off "$?" "0"

# 10. Twilio sender key: a phone number -> From=, a Messaging Service SID (MG…) ->
#     MessagingServiceSid=. Stub curl (echo args, return a 2xx code).
CURLLOG="$TMP/curl"; : > "$CURLLOG"
curl() { printf '%s\n' "$*" >> "$CURLLOG"; echo "201"; }
SWATTER_HAVE_CURL=1; TWILIO_SID="ACtest"; TWILIO_TOKEN_FILE="$TMP/tok"; echo "s3cret" > "$TWILIO_TOKEN_FILE"
TWILIO_FROM="+15559999999"; _alert_sms_twilio "+15550001111" "hi"
check twilio-from-number "$(grep -c 'From=+15559999999' "$CURLLOG")" "1"
: > "$CURLLOG"; TWILIO_FROM="MG0123456789abcdef"; _alert_sms_twilio "+15550001111" "hi"
check twilio-msgsvc  "$(grep -c 'MessagingServiceSid=MG0123456789abcdef' "$CURLLOG")" "1"
check twilio-no-from "$(grep -c ' From=MG' "$CURLLOG")" "0"

# 11. Twilio failure logs the response BODY (the actionable cause), bounded and
#     token-redacted — "HTTP 401" alone is undiagnosable.
ERR="$TMP/twerr"
curl() { printf '%s\n' "$*" >> "$CURLLOG"; printf '{"code": 20003, "message": "Authentication Error - invalid username s3cret"}\n401'; }
TWILIO_FROM="+15559999999"
_alert_sms_twilio "+15550001111" "hi" 2> "$ERR"; check twilio-fail-rc "$?" "1"
check twilio-fail-code "$(grep -c 'HTTP 401' "$ERR")" "1"
check twilio-fail-body "$(grep -c 'Authentication Error' "$ERR")" "1"
check twilio-fail-redacted "$(grep -c 's3cret' "$ERR")" "0"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
