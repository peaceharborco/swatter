#!/usr/bin/env bash
# test/notify_test.sh — multi-channel fan-out, independence, rate-limit, webhook fmt.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/notify.sh"
PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-ntf.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
SWATTER_HAVE_CURL=1; ALERT_REPEAT_TTL=21600
WEB="$STATE_DIR/web"; SMS="$STATE_DIR/sms"; MAILED="$STATE_DIR/mailed"
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Mock the channel sinks.
swatter_send_email() { printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$MAILED"; return 0; }
# curl is used by SMS (twilio) and webhook; route by URL.
curl() { local url="${*: -1}"; case "$url" in *twilio*) printf '%s\n' "$*" >> "$SMS";; *) printf '%s\n' "$*" >> "$WEB";; esac; return 0; }

# Configure SendGrid email + Twilio SMS + a Slack webhook.
ALERT_EMAIL="ops@example.com"
ALERT_SMS_TO="+15550001111"; TWILIO_SID="ACxxx"; TWILIO_FROM="+15550002222"
TWILIO_TOKEN_FILE="$STATE_DIR/tw.key"; printf 'tok\n' > "$TWILIO_TOKEN_FILE"
ALERT_WEBHOOK_URL="https://hooks.slack.com/services/X"; ALERT_WEBHOOK_FORMAT="auto"

swatter_notify "circuit breaker tripped" "reached cap" "circuit_breaker"
[[ -s "$MAILED" ]] && PASS=$((PASS+1)) || { echo "FAIL email-fired"; FAIL=$((FAIL+1)); }
[[ -s "$SMS" ]] && PASS=$((PASS+1)) || { echo "FAIL sms-fired"; FAIL=$((FAIL+1)); }
# slack auto-format -> payload contains "text".
grep -q '"text"' "$WEB" && PASS=$((PASS+1)) || { echo "FAIL webhook-slack-fmt"; FAIL=$((FAIL+1)); }

# Rate-limit: a second keyed call within TTL is suppressed (no new email).
before="$(wc -l < "$MAILED")"
swatter_notify "circuit breaker tripped" "again" "circuit_breaker"
after="$(wc -l < "$MAILED")"
check ratelimit "$before" "$after"

# A failing channel does not abort the others: make webhook curl fail, email still fires.
: > "$MAILED"
curl() { local url="${*: -1}"; case "$url" in *twilio*) return 0;; *) return 7;; esac; }
swatter_notify "fail closed" "denies disabled" "fail_closed"
[[ -s "$MAILED" ]] && PASS=$((PASS+1)) || { echo "FAIL email-after-webhook-fail"; FAIL=$((FAIL+1)); }

# Unkeyed alert always fires (not rate-limited).
: > "$MAILED"; swatter_notify "manual test" "x"; swatter_notify "manual test" "x"
check unkeyed-always "$(wc -l < "$MAILED" | tr -d ' ')" "2"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
