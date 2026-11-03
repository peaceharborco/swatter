#!/usr/bin/env bash
# lib/mailer.sh — shared email sender (sendmail | sendgrid | brevo | cloudflare).
#
# swatter_send_email <to> <subject> <body> [html] — dispatch on REPORT_METHOD.
# Extracted from report.sh so the nightly digest and ops alerts share one path.

swatter_send_email() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    case "${REPORT_METHOD:-sendmail}" in
        sendgrid) _mailer_sendgrid "$to" "$subject" "$body" "$html" ;;
        brevo)    _mailer_brevo    "$to" "$subject" "$body" "$html" ;;
        cloudflare) _mailer_cloudflare "$to" "$subject" "$body" "$html" ;;
        *)        _mailer_sendmail "$to" "$subject" "$body" "$html" ;;
    esac
}

# Brevo (formerly Sendinblue) transactional email API v3. Key from BREVO_KEY_FILE
# (preferred) or BREVO_API_KEY. The common choice for hosts whose sending IP
# isn't an authorized sender for the From domain and who already use Brevo.
_mailer_brevo() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "brevo needs curl+jq"; return 1; }
    local key=""
    if [[ -n "${BREVO_KEY_FILE}" && -r "${BREVO_KEY_FILE}" ]]; then key="$(cat "${BREVO_KEY_FILE}")"
    elif [[ -n "${BREVO_API_KEY}" ]]; then key="${BREVO_API_KEY}"; fi
    [[ -n "$key" ]] || { log_error "brevo: no BREVO_KEY_FILE/BREVO_API_KEY"; return 1; }
    local payload code
    payload="$(jq -nc --arg to "${to}" --arg from "${REPORT_FROM}" \
        --arg fromname "${REPORT_FROM_NAME}" --arg subj "${subject}" --arg body "${body}" --arg html "${html}" '{
        sender:{email:$from,name:$fromname},
        to:[{email:$to}],
        subject:$subj,
        htmlContent:(if $html=="" then null else $html end),
        textContent:$body
    } | with_entries(select(.value != null))')"
    # API key via -K config file, never argv (visible in `ps` on a shared box).
    local cfg resp
    cfg="$(swatter_curl_cfg "header = \"api-key: ${key}\"")" || { log_error "brevo: cannot create curl config"; return 1; }
    # Keep the response BODY: on failure it carries the actionable cause (bad
    # key, unverified sender, ...) that a bare "HTTP 401" hides. The EXIT/INT/TERM
    # trap lives in the command-substitution subshell, so it scrubs the token cfg
    # even if curl is interrupted, without clobbering any caller trap.
    resp="$(trap 'rm -f "$cfg"' EXIT INT TERM
        curl -sS --max-time 15 -X POST "https://api.brevo.com/v3/smtp/email" \
        -K "$cfg" -H "Content-Type: application/json" -H "Accept: application/json" \
        --data "$payload" -w '\n%{http_code}' 2>&1)"
    rm -f "$cfg"
    code="${resp##*$'\n'}"; local body="${resp%"${code}"}"; body="${body%$'\n'}"
    if [[ "$code" == "201" || "$code" == "202" ]]; then log_info "report sent to ${to} via Brevo (${code})"; return 0; fi
    body="${body//${key}/***}"
    log_error "Brevo send failed (HTTP ${code:-000})${body:+: $(printf '%s' "$body" | tr '\n' ' ' | cut -c1-200)}"; return 1
}

_mailer_sendmail() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    if have sendmail || [[ -x /usr/sbin/sendmail ]]; then
        local sm; sm="$(command -v sendmail || echo /usr/sbin/sendmail)"
        if [[ -n "$html" ]]; then
            # multipart/alternative: text + html.
            local b; b="swatter-$(swatter_now)-bnd"
            { printf 'To: %s\nFrom: %s <%s>\nSubject: %s\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary="%s"\n\n' \
                "${to}" "${REPORT_FROM_NAME}" "${REPORT_FROM}" "${subject}" "$b"
              printf -- '--%s\nContent-Type: text/plain; charset=UTF-8\n\n%s\n\n' "$b" "$body"
              printf -- '--%s\nContent-Type: text/html; charset=UTF-8\n\n%s\n\n' "$b" "$html"
              printf -- '--%s--\n' "$b"; } | "$sm" -t 2>/dev/null \
              && { log_info "report sent to ${to} via sendmail (html)"; return 0; }
        else
            { printf 'To: %s\nFrom: %s <%s>\nSubject: %s\nContent-Type: text/plain; charset=UTF-8\n\n' \
                "${to}" "${REPORT_FROM_NAME}" "${REPORT_FROM}" "${subject}"
              printf '%s\n' "$body"; } | "$sm" -t 2>/dev/null \
              && { log_info "report sent to ${to} via sendmail"; return 0; }
        fi
    elif have mail; then
        printf '%s\n' "$body" | mail -s "$subject" "${to}" 2>/dev/null \
          && { log_info "report sent to ${to} via mail"; return 0; }
    fi
    log_error "no MTA available (sendmail/mail) to send the report"; return 1
}

# Cloudflare Email Sending REST API. The token needs Email Sending: Edit, and
# REPORT_FROM's domain must be onboarded on CF_MAIL_ACCOUNT_ID. A 200 can still
# mean the mail went nowhere, so the reply has to name it delivered or queued.
_mailer_cloudflare() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "cloudflare mail needs curl+jq"; return 1; }
    [[ "${CF_MAIL_ACCOUNT_ID:-}" =~ ^[0-9a-fA-F]{32}$ ]] || { log_error "cloudflare mail: CF_MAIL_ACCOUNT_ID must be a 32-character account id"; return 1; }
    [[ -r "${CF_MAIL_TOKEN_FILE:-}" ]] || { log_error "cloudflare mail: token not readable: ${CF_MAIL_TOKEN_FILE:-unset}"; return 1; }
    local key code
    key="$(tr -d "[:space:]" < "${CF_MAIL_TOKEN_FILE}")"
    [[ -n "$key" ]] || { log_error "cloudflare mail: token file is empty: ${CF_MAIL_TOKEN_FILE}"; return 1; }
    # The body travels through files: Linux caps one argument at 128 KiB, and a
    # large digest passed as an argument would never reach jq or curl.
    local work
    work="$(mktemp -d "${TMPDIR:-/tmp}/swatter-mail.XXXXXX")" || { log_error "cloudflare mail: cannot create a work directory"; return 1; }
    printf '%s' "$body" > "$work/text"
    printf '%s' "$html" > "$work/html"
    if ! jq -nc --arg to "${to}" --arg from "${REPORT_FROM}" \
        --arg fromname "${REPORT_FROM_NAME}" --arg subj "${subject}" \
        --rawfile body "$work/text" --rawfile html "$work/html" '{
        to:$to,
        from:{address:$from,name:$fromname},
        subject:$subj,
        text:$body
    } + (if $html=="" then {} else {html:$html} end)' > "$work/payload"; then
        rm -rf "$work"
        log_error "cloudflare mail: could not build the message"; return 1
    fi
    local cfg resp
    cfg="$(swatter_curl_cfg "header = \"Authorization: Bearer ${key}\"")" || { rm -rf "$work"; log_error "cloudflare mail: cannot create curl config"; return 1; }
    resp="$(trap 'rm -f "$cfg"; rm -rf "$work"' EXIT INT TERM
        curl -sS --max-time 30 -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_MAIL_ACCOUNT_ID}/email/sending/send" \
        -K "$cfg" -H "Content-Type: application/json" \
        --data-binary "@${work}/payload" -w '\n%{http_code}' 2>&1)"
    rm -f "$cfg"; rm -rf "$work"
    code="${resp##*$'\n'}"; local reply="${resp%"${code}"}"; reply="${reply%$'\n'}"
    if [[ "$code" == "200" ]] && jq -e '.success == true
            and ((.result.permanent_bounces // []) | length == 0)
            and (((.result.delivered // []) + (.result.queued // [])) | length > 0)' <<<"$reply" >/dev/null 2>&1; then
        log_info "report sent to ${to} via Cloudflare"; return 0
    fi
    reply="${reply//${key}/***}"
    log_error "Cloudflare send failed (HTTP ${code:-000})${reply:+: $(printf '%s' "$reply" | tr '\n' ' ' | cut -c1-200)}"; return 1
}

_mailer_sendgrid() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "sendgrid needs curl+jq"; return 1; }
    [[ -r "${SENDGRID_KEY_FILE}" ]] || { log_error "SendGrid key not readable: ${SENDGRID_KEY_FILE}"; return 1; }
    local key payload code
    key="$(tr -d "[:space:]" < "${SENDGRID_KEY_FILE}")"   # a CRLF key file put "\r" on the wire -> 401
    # SendGrid requires text/plain before text/html in the content array.
    payload="$(jq -nc --arg to "${to}" --arg from "${REPORT_FROM}" \
        --arg fromname "${REPORT_FROM_NAME}" --arg subj "${subject}" --arg body "${body}" --arg html "${html}" '{
        personalizations:[{to:[{email:$to}]}],
        from:{email:$from,name:$fromname},
        subject:$subj,
        content:( [{type:"text/plain",value:$body}] + (if $html=="" then [] else [{type:"text/html",value:$html}] end) )
    }')"
    # API key via -K config file, never argv (visible in `ps` on a shared box).
    local cfg resp
    cfg="$(swatter_curl_cfg "header = \"Authorization: Bearer ${key}\"")" || { log_error "sendgrid: cannot create curl config"; return 1; }
    # Keep the response BODY: on failure it carries the actionable cause (bad
    # key, unverified sender, ...) that a bare "HTTP 403" hides. The EXIT/INT/TERM
    # trap lives in the command-substitution subshell, so it scrubs the token cfg
    # even if curl is interrupted, without clobbering any caller trap.
    resp="$(trap 'rm -f "$cfg"' EXIT INT TERM
        curl -sS --max-time 15 -X POST "https://api.sendgrid.com/v3/mail/send" \
        -K "$cfg" -H "Content-Type: application/json" \
        --data "$payload" -w '\n%{http_code}' 2>&1)"
    rm -f "$cfg"
    code="${resp##*$'\n'}"; local body="${resp%"${code}"}"; body="${body%$'\n'}"
    if [[ "$code" == "202" ]]; then log_info "report sent to ${to} via SendGrid (202)"; return 0; fi
    body="${body//${key}/***}"
    log_error "SendGrid send failed (HTTP ${code:-000})${body:+: $(printf '%s' "$body" | tr '\n' ' ' | cut -c1-200)}"; return 1
}
