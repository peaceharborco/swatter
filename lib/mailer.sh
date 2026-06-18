#!/usr/bin/env bash
# lib/mailer.sh — shared email sender (sendmail | sendgrid | brevo).
#
# swatter_send_email <to> <subject> <body> [html] — dispatch on REPORT_METHOD.
# Extracted from report.sh so the nightly digest and ops alerts share one path.

swatter_send_email() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    case "${REPORT_METHOD:-sendmail}" in
        sendgrid) _mailer_sendgrid "$to" "$subject" "$body" "$html" ;;
        brevo)    _mailer_brevo    "$to" "$subject" "$body" "$html" ;;
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
    code="$(curl -sS --max-time 15 -X POST "https://api.brevo.com/v3/smtp/email" \
        -H "api-key: ${key}" -H "Content-Type: application/json" -H "Accept: application/json" \
        --data "$payload" -o /dev/null -w '%{http_code}')"
    if [[ "$code" == "201" || "$code" == "202" ]]; then log_info "report sent to ${to} via Brevo (${code})"; return 0; fi
    log_error "Brevo send failed (HTTP ${code})"; return 1
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

_mailer_sendgrid() {
    local to="$1" subject="$2" body="$3" html="${4:-}"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "sendgrid needs curl+jq"; return 1; }
    [[ -r "${SENDGRID_KEY_FILE}" ]] || { log_error "SendGrid key not readable: ${SENDGRID_KEY_FILE}"; return 1; }
    local key payload code
    key="$(cat "${SENDGRID_KEY_FILE}")"
    # SendGrid requires text/plain before text/html in the content array.
    payload="$(jq -nc --arg to "${to}" --arg from "${REPORT_FROM}" \
        --arg fromname "${REPORT_FROM_NAME}" --arg subj "${subject}" --arg body "${body}" --arg html "${html}" '{
        personalizations:[{to:[{email:$to}]}],
        from:{email:$from,name:$fromname},
        subject:$subj,
        content:( [{type:"text/plain",value:$body}] + (if $html=="" then [] else [{type:"text/html",value:$html}] end) )
    }')"
    code="$(curl -sS --max-time 15 -X POST "https://api.sendgrid.com/v3/mail/send" \
        -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" \
        --data "$payload" -o /dev/null -w '%{http_code}')"
    if [[ "$code" == "202" ]]; then log_info "report sent to ${to} via SendGrid (202)"; return 0; fi
    log_error "SendGrid send failed (HTTP ${code})"; return 1
}
