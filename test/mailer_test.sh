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

# Mock curl: record args (the JSON payload arrives via --data, an ARG — never
# stdin; a `cat` here blocks forever on an inherited open stdin). Return 202.
curl() { printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"; echo "202"; }

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

# Cloudflare: only a reply naming the mail delivered or queued counts as sent.
CF_MAIL_ACCOUNT_ID="0123456789abcdef0123456789abcdef"
CF_MAIL_TOKEN_FILE="$TMP/cf.token"; printf 'CFMAILTOKEN\n' > "$CF_MAIL_TOKEN_FILE"
REPORT_METHOD="cloudflare"
cf_reply() { CF_REPLY="$1"; CF_CODE="$2"; }
curl() {
    printf 'ARGS: %s\n' "$*" >> "$CURL_BODY"
    local a; for a in "$@"; do [[ "$a" == @* ]] && { cat "${a#@}" >> "$CURL_BODY"; printf '\n' >> "$CURL_BODY"; }; done
    printf '%s\n%s' "$CF_REPLY" "$CF_CODE"
}
: > "$CURL_BODY"
cf_reply '{"success":true,"result":{"delivered":["ops@example.com"],"queued":[],"permanent_bounces":[]}}' 200
swatter_send_email "ops@example.com" "subj" "body" "<p>h</p>" 2>/dev/null; check cf-delivered-rc "$?" "0"
has cf-endpoint "accounts/0123456789abcdef0123456789abcdef/email/sending/send"
has cf-to '"to":"ops@example.com"'
has cf-from '"from":{"address":"swatter@x","name":"Swatter"}'
has cf-text '"text":"body"'
has cf-html '"html":"<p>h</p>"'
check cf-token-not-on-argv "$(grep -c 'CFMAILTOKEN' "$CURL_BODY")" "0"
cf_reply '{"success":true,"result":{"delivered":[],"queued":["ops@example.com"],"permanent_bounces":[]}}' 200
BIG="$(head -c 1200000 /dev/zero | tr '\0' 'x')"; : > "$CURL_BODY"; export TMPDIR="$TMP"
_mailer_cloudflare "ops@example.com" "s" "$BIG" "<p>$BIG</p>" 2>/dev/null; check cf-large-digest-rc "$?" "0"
check cf-large-digest-carried "$(grep -c "\"text\":\"$(printf '%s' "$BIG" | head -c 1000)" "$CURL_BODY")" "1"
check cf-work-dir-removed "$(ls -d "$TMP"/swatter-mail.* 2>/dev/null | wc -l | tr -d ' ')" "0"
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-queued-rc "$?" "0"
cf_reply '{"success":true,"result":{"delivered":[],"queued":[],"permanent_bounces":[]}}' 200
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-nothing-sent-rc "$?" "1"
cf_reply '{"success":true,"result":{"delivered":["a@x"],"queued":[],"permanent_bounces":["b@x"]}}' 200
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-bounce-rc "$?" "1"
cf_reply '{"success":false,"errors":[{"message":"sender denied"}]}' 200
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-success-false-rc "$?" "1"
cf_reply '{"errors":[{"message":"bad CFMAILTOKEN value"}]}' 401
_mailer_cloudflare "ops@example.com" "s" "b" 2> "$ERR"; check cf-401-rc "$?" "1"
check cf-401-code "$(grep -c 'HTTP 401' "$ERR")" "1"
check cf-401-redacted "$(grep -c 'CFMAILTOKEN' "$ERR")" "0"
cf_reply '{"success":true,"result":{"delivered":["a@x"]}}' 200
CF_MAIL_ACCOUNT_ID="0123456789ABCDEF0123456789ABCDEF"
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-uppercase-account-rc "$?" "0"
CF_MAIL_ACCOUNT_ID='bad/../path'
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-bad-account-rc "$?" "1"
CF_MAIL_ACCOUNT_ID="0123456789abcdef0123456789abcdef"
: > "$CF_MAIL_TOKEN_FILE"
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-empty-token-rc "$?" "1"
CF_MAIL_TOKEN_FILE="$TMP/none"
_mailer_cloudflare "ops@example.com" "s" "b" 2>/dev/null; check cf-missing-token-rc "$?" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
