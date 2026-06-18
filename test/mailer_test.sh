#!/usr/bin/env bash
# test/mailer_test.sh — shared email sender dispatch + recipient parameterization.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/mailer.sh"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-mail.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
CURL_BODY="$TMP/curl"; : > "$CURL_BODY"
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=1
REPORT_FROM="swatter@x"; REPORT_FROM_NAME="Swatter"
SENDGRID_KEY_FILE="$TMP/sg.key"; printf 'SG.testkey\n' > "$SENDGRID_KEY_FILE"
has() { local n="$1" pat="$2"; if grep -qF "$pat" "$CURL_BODY"; then PASS=$((PASS+1)); else echo "FAIL ${n}: '${pat}' not seen"; FAIL=$((FAIL+1)); fi; }

# Mock curl: record args + stdin (the JSON payload), return HTTP 202.
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; cat >> "$CURL_BODY" 2>/dev/null; echo "202"; }

REPORT_METHOD="sendgrid"
swatter_send_email "ops@example.com" "subj-line" "body-line"
has sg-endpoint "api.sendgrid.com"
has sg-recipient "ops@example.com"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
