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

check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
ERR="$TMP/err"

# Failure diagnosability: a non-2xx logs the provider's error BODY (bounded),
# not just "HTTP 403" — the body says WHY (bad key, unverified sender, ...).
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; printf '{"errors":[{"message":"maximum credits exceeded"}]}\n403'; }
_mailer_sendgrid "ops@example.com" "s" "b" 2> "$ERR"; check sg-fail-rc "$?" "1"
check sg-fail-code "$(grep -c 'HTTP 403' "$ERR")" "1"
check sg-fail-body "$(grep -c 'maximum credits exceeded' "$ERR")" "1"

# ...and the API key is redacted if a body ever echoes it.
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; printf 'bad key SG.testkey rejected\n401'; }
_mailer_sendgrid "ops@example.com" "s" "b" 2> "$ERR"
check sg-fail-redacted "$(grep -c 'SG.testkey' "$ERR")" "0"

# Brevo failure carries the body too.
BREVO_KEY_FILE=""; BREVO_API_KEY="brevo-key"
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; printf '{"code":"unauthorized","message":"Key not found"}\n401'; }
_mailer_brevo "ops@example.com" "s" "b" 2> "$ERR"; check brevo-fail-rc "$?" "1"
check brevo-fail-code "$(grep -c 'HTTP 401' "$ERR")" "1"
check brevo-fail-body "$(grep -c 'Key not found' "$ERR")" "1"

# Success paths still parse the trailing status code correctly.
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; printf '\n202'; }
_mailer_sendgrid "ops@example.com" "s" "b" 2>/dev/null; check sg-ok-rc "$?" "0"
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; printf '{"messageId":"x"}\n201'; }
_mailer_brevo "ops@example.com" "s" "b" 2>/dev/null; check brevo-ok-rc "$?" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
