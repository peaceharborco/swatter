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

# baseline config: twilio on, destination set, default grades "D F"
ALERT_SMS_METHOD="twilio"; ALERT_SMS_TO="+15550001111"; ALERT_SMS_GRADES="D F"; ALERT_SMS_DEDUP_HOURS=6
REPORT_TRIAGE_HINT="/server-logs"
RPT_GRADE_WORD="x"; RPT_GRADE_SUB="sub"; RPT_RECO="Run /server-logs now."

# 1. method off -> never sends, even at F
: > "$SENT"; ALERT_SMS_METHOD=""; RPT_GRADE=F; swatter_alert_on_grade; check off-no-send "$(nsent)" "0"
ALERT_SMS_METHOD="twilio"
# 2. no destination -> off
: > "$SENT"; ALERT_SMS_TO=""; RPT_GRADE=F; swatter_alert_on_grade; check no-dest "$(nsent)" "0"
ALERT_SMS_TO="+15550001111"

# 3. grade B/C/A -> no send (only D/F by default)
: > "$SENT"; rm -f "$TMP/last-sms-alert"
for g in A B C; do RPT_GRADE=$g; swatter_alert_on_grade; done
check no-send-below-D "$(nsent)" "0"

# 4. grade D and F -> send
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=D; swatter_alert_on_grade; check send-D "$(nsent)" "1"
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=F; swatter_alert_on_grade; check send-F "$(nsent)" "1"
has msg-host    "Swatter"
has msg-grade   "Grade F"
has msg-hint    "/server-logs"

# 5. custom grades include C
: > "$SENT"; rm -f "$TMP/last-sms-alert"; ALERT_SMS_GRADES="C D F"; RPT_GRADE=C; swatter_alert_on_grade; check custom-grade-C "$(nsent)" "1"
ALERT_SMS_GRADES="D F"

# 6. dedup: same grade within window suppressed; new grade allowed; after window allowed
: > "$SENT"; rm -f "$TMP/last-sms-alert"; NOW=1000000
RPT_GRADE=F; swatter_alert_on_grade                 # 1st: sends
RPT_GRADE=F; swatter_alert_on_grade                 # dup within window: suppressed
check dedup-same "$(nsent)" "1"
RPT_GRADE=D; swatter_alert_on_grade                 # different grade: sends
check dedup-diff-grade "$(nsent)" "2"
NOW=$(( 1000000 + 7*3600 )); RPT_GRADE=D; swatter_alert_on_grade   # past 6h window: sends
check dedup-after-window "$(nsent)" "3"

# 7. --test sends regardless of grade, with [TEST], bypassing dedup
: > "$SENT"; rm -f "$TMP/last-sms-alert"; RPT_GRADE=A
swatter_alert_on_grade --test; swatter_alert_on_grade --test   # both send (no dedup)
check test-sends-twice "$(nsent)" "2"
has test-prefix "[TEST]"

# 8. fail-soft: sender returns nonzero -> alert function still returns 0
: > "$SENT"; rm -f "$TMP/last-sms-alert"; SMS_RC=1; RPT_GRADE=F
swatter_alert_on_grade; check failsoft-rc "$?" "0"; SMS_RC=0

# 9. swatter_send_sms dispatch: method "" is a no-op success (restore real fn)
unset -f swatter_send_sms; source "${ROOT}/lib/alerts.sh"
ALERT_SMS_METHOD=""; swatter_send_sms "+1555" "hi"; check dispatch-off "$?" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
