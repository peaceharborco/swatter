#!/usr/bin/env bash
# lib/report.sh — nightly email digest of offenses and actions.
#
# Reads the structured decision log (decisions.jsonl), filters to a window
# (default 24h), groups what happened by ACTION (perm/temp/exempt/skipped/watch),
# by OFFENSE (decisive rule + bad-path category), and by CHANNEL (csf/cloudflare),
# then emails a compact digest. Stays silent when the window had no activity
# unless --test is given.
#
# Delivery is method-pluggable for portability:
#   sendmail (default) — pipe to the local MTA (/usr/sbin/sendmail or `mail`)
#   sendgrid           — POST the SendGrid v3 API (for hosts whose IP can't send
#                        direct-to-MX for the From domain); needs SENDGRID_KEY_FILE
#
# Requires jq for the grouped digest; without it, falls back to a flat count.

# Convert "24h"/"7d"/"90m" to seconds.
_report_window_secs() {
    local w="$1" n unit
    n="${w%[hdm]}"; unit="${w##*[0-9]}"
    [[ "$n" =~ ^[0-9]+$ ]] || { echo 86400; return; }
    case "$unit" in
        h) echo $(( n * 3600 )) ;;
        d) echo $(( n * 86400 )) ;;
        m) echo $(( n * 60 )) ;;
        *) echo 86400 ;;
    esac
}

# Build the plain-text digest body on stdout. Sets globals used for the subject:
#   RPT_ACTED RPT_PERM RPT_TEMP RPT_CF RPT_CSF RPT_EXEMPT RPT_WATCH
swatter_report_build() {
    local window="$1" cutoff
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    local log="${LOG_DIR}/decisions.jsonl"

    RPT_ACTED=0 RPT_PERM=0 RPT_TEMP=0 RPT_CF=0 RPT_CSF=0 RPT_EXEMPT=0 RPT_WATCH=0
    ERR_TOTAL=0 ERR_FATAL=0 ERR_GENUINE=0 ERR_NOISE=0

    # The error-triage section runs first so its counters are set for the subject
    # even when the abuse log is empty. Captured to a temp, emitted after the
    # abuse digest below.
    local errsection="" errfile=""
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && declare -F swatter_errors_section >/dev/null; then
        # Redirection (not $(...)) so the ERR_* counters persist in this shell.
        errfile="$(mktemp "${TMPDIR:-/tmp}/swatter-errsec.XXXXXX")"
        swatter_errors_section "$window" > "$errfile"
        errsection="$(cat "$errfile")"
        rm -f "$errfile"
    fi

    echo "Swatter nightly digest — $(hostname -f 2>/dev/null || hostname)"
    echo "Window: last ${window}  (mode: ${SWATTER_MODE})"
    echo
    echo "========================  BAD ACTORS  ==========================="
    echo
    _report_emit_abuse "$window" "$cutoff" "$log"

    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        echo
        echo "========================  SERVER ERRORS  ========================"
        echo
        printf '%s\n' "$errsection"
    fi

    echo
    echo "------------------------------------------------------------------"
    echo "Full evidence:  swatter why <ip>      Abuse log: ${log}"
    [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && echo "Error triage:   swatter report --test   (or /server-logs equivalent)"
}

# The abuse (bad-actor) digest body.
_report_emit_abuse() {
    local window="$1" cutoff="$2" log="$3"

    if [[ ! -r "$log" ]]; then
        echo "No abuse decision log at ${log}."
        return 0
    fi
    if [[ "${SWATTER_HAVE_JQ}" -ne 1 ]]; then
        # Degraded: flat counts via grep.
        local n; n="$(awk -F'"ts":' 'NF>1{split($2,a,","); if (a[1]+0 >= '"$cutoff"') c++} END{print c+0}' "$log")"
        echo "Swatter activity in last ${window}: ${n} decisions (install jq for the grouped digest)."
        RPT_ACTED="$n"
        return 0
    fi

    # All in-window records.
    local recs; recs="$(jq -c "select(.ts >= ${cutoff})" "$log" 2>/dev/null)"
    [[ -n "$recs" ]] || { echo "No Swatter activity in the last ${window} — quiet."; return 0; }

    RPT_PERM=$(printf '%s\n'   "$recs" | jq -rc 'select(.action=="perm")'   | grep -c . || true)
    RPT_TEMP=$(printf '%s\n'   "$recs" | jq -rc 'select(.action=="temp")'   | grep -c . || true)
    RPT_EXEMPT=$(printf '%s\n' "$recs" | jq -rc 'select(.action=="exempt")' | grep -c . || true)
    RPT_WATCH=$(printf '%s\n'  "$recs" | jq -rc 'select(.action=="watch")'  | grep -c . || true)
    RPT_CF=$(printf '%s\n'     "$recs" | jq -rc 'select(.channel=="cloudflare" and (.action=="temp" or .action=="perm"))' | grep -c . || true)
    RPT_CSF=$(printf '%s\n'    "$recs" | jq -rc 'select(.channel=="csf" and (.action=="temp" or .action=="perm"))' | grep -c . || true)
    RPT_ACTED=$(( RPT_PERM + RPT_TEMP ))

    {
        echo "Actions taken"
        echo "-------------"
        printf '  %-22s %s\n' "permanent blocks:" "${RPT_PERM}"
        printf '  %-22s %s\n' "temporary blocks:" "${RPT_TEMP}"
        printf '  %-22s %s\n' "  via CSF (direct):" "${RPT_CSF}"
        printf '  %-22s %s\n' "  via Cloudflare:"   "${RPT_CF}"
        printf '  %-22s %s\n' "exempted (allowlist):" "${RPT_EXEMPT}"
        printf '  %-22s %s\n' "watched (no action):" "${RPT_WATCH}"
        echo

        echo "By offense type (acted only)"
        echo "----------------------------"
        printf '%s\n' "$recs" \
            | jq -rc 'select(.action=="temp" or .action=="perm") | (.evidence.decisive_rule // "unspecified")' \
            | sort | uniq -c | sort -rn \
            | awk '{printf "  %-26s %s\n", $2, $1}'
        echo

        echo "By bad-path category (acted only)"
        echo "---------------------------------"
        printf '%s\n' "$recs" \
            | jq -rc 'select(.action=="temp" or .action=="perm") | (.evidence.badpath_cat // "" | if .=="" then "(behavioral)" else . end)' \
            | sort | uniq -c | sort -rn \
            | awk '{printf "  %-26s %s\n", $2, $1}'
        echo

        if (( RPT_ACTED > 0 )); then
            echo "Blocks (newest first)"
            echo "---------------------"
            printf '%-16s %5s %-12s %-20s %-10s %s\n' "IP" "SCORE" "ACTION" "RULE" "CHANNEL" "TTL"
            printf '%s\n' "$recs" \
                | jq -rc 'select(.action=="temp" or .action=="perm")
                          | [.ip,(.score|tostring),.action,(.evidence.decisive_rule // "-"),.channel,(.ttl|tostring)] | @tsv' \
                | tail -100 \
                | awk -F'\t' '{printf "%-16s %5s %-12s %-20s %-10s %s\n",$1,$2,$3,$4,$5,$6}'
            echo
        fi

        if (( RPT_EXEMPT > 0 )); then
            echo "Exemptions (allowlist hits that scored high — review if unexpected)"
            echo "------------------------------------------------------------------"
            printf '%s\n' "$recs" \
                | jq -rc 'select(.action=="exempt") | [.ip,(.score|tostring),.reason] | @tsv' \
                | sort -u \
                | awk -F'\t' '{printf "  %-16s score=%-4s %s\n",$1,$2,$3}'
            echo
        fi
    }
}

# Minimal HTML escape for embedding the plain-text detail in <pre>.
_report_html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# Render a styled HTML digest from the globals (summary pills) + the plain-text
# body (detail, in a monospace block). $1 = plain-text body. Emits HTML on stdout.
# Inline styles + table layout for email-client compatibility.
_report_render_html() {
    local body="$1"
    local host; host="$(hostname -f 2>/dev/null || hostname)"
    local escaped; escaped="$(printf '%s' "$body" | _report_html_escape)"

    local pill='display:inline-block;margin:0 8px 8px 0;padding:6px 12px;border-radius:6px;font-size:13px;font-weight:600;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif'
    local pre='background:#0d1117;color:#c9d1d9;border-radius:8px;padding:16px;overflow-x:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word'

    _pill() { # value label bg fg
        (( $1 > 0 )) || [[ "$4" == "always" ]] || { return; }
        printf '<span style="%s;background:%s;color:%s">%s&nbsp;%s</span>' "$pill" "$2" "$3" "$1" "$5"
    }

    {
        printf '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:760px;margin:0 auto;color:#24292e">'
        printf '<h2 style="margin:0 0 2px;font-size:20px">🪰 Swatter nightly digest</h2>'
        printf '<p style="margin:0 0 14px;color:#586069;font-size:13px">%s &middot; last %s &middot; mode: <b>%s</b></p>' \
            "$(printf '%s' "$host" | _report_html_escape)" "${REPORT_WINDOW}" "${SWATTER_MODE}"

        printf '<div style="margin-bottom:6px">'
        _pill "${RPT_PERM:-0}"  "#ffeef0" "#b31d28" 0 "permanent"
        _pill "${RPT_TEMP:-0}"  "#fff5b1" "#735c0f" 0 "temporary"
        _pill "${RPT_CSF:-0}"   "#dbedff" "#0349b4" 0 "via&nbsp;CSF"
        _pill "${RPT_CF:-0}"    "#ffead7" "#9a4d00" 0 "via&nbsp;Cloudflare"
        _pill "${RPT_WATCH:-0}" "#eaecef" "#444d56" 0 "watched"
        if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
            _pill "${ERR_FATAL:-0}"   "#ffeef0" "#b31d28" 0 "FATAL"
            _pill "${ERR_GENUINE:-0}" "#fff5b1" "#735c0f" 0 "server&nbsp;errors"
        fi
        printf '</div>'

        printf '<pre style="%s">%s</pre>' "$pre" "$escaped"
        printf '<p style="margin:14px 0 0;color:#959da5;font-size:12px">Swatter &middot; <code>swatter why &lt;ip&gt;</code> for evidence &middot; <code>swatter unblock &lt;ip&gt;</code> to reverse</p>'
        printf '</div>'
    }
}

# Deliver the digest. $1 subject $2 text-body $3 html-body
_report_send() {
    local subject="$1" body="$2" html="$3"
    case "${REPORT_METHOD}" in
        sendgrid) _report_send_sendgrid "$subject" "$body" "$html" ;;
        brevo)    _report_send_brevo    "$subject" "$body" "$html" ;;
        *)        _report_send_sendmail "$subject" "$body" "$html" ;;
    esac
}

# Brevo (formerly Sendinblue) transactional email API v3. Key from BREVO_KEY_FILE
# (preferred) or BREVO_API_KEY. The common choice for hosts whose sending IP
# isn't an authorized sender for the From domain and who already use Brevo.
_report_send_brevo() {
    local subject="$1" body="$2" html="${3:-}"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "brevo needs curl+jq"; return 1; }
    local key=""
    if [[ -n "${BREVO_KEY_FILE}" && -r "${BREVO_KEY_FILE}" ]]; then key="$(cat "${BREVO_KEY_FILE}")"
    elif [[ -n "${BREVO_API_KEY}" ]]; then key="${BREVO_API_KEY}"; fi
    [[ -n "$key" ]] || { log_error "brevo: no BREVO_KEY_FILE/BREVO_API_KEY"; return 1; }
    local payload code
    payload="$(jq -nc --arg to "${REPORT_EMAIL}" --arg from "${REPORT_FROM}" \
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
    if [[ "$code" == "201" || "$code" == "202" ]]; then log_info "report sent to ${REPORT_EMAIL} via Brevo (${code})"; return 0; fi
    log_error "Brevo send failed (HTTP ${code})"; return 1
}

_report_send_sendmail() {
    local subject="$1" body="$2" html="${3:-}"
    if have sendmail || [[ -x /usr/sbin/sendmail ]]; then
        local sm; sm="$(command -v sendmail || echo /usr/sbin/sendmail)"
        if [[ -n "$html" ]]; then
            # multipart/alternative: text + html.
            local b; b="swatter-$(swatter_now)-bnd"
            { printf 'To: %s\nFrom: %s <%s>\nSubject: %s\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary="%s"\n\n' \
                "${REPORT_EMAIL}" "${REPORT_FROM_NAME}" "${REPORT_FROM}" "${subject}" "$b"
              printf -- '--%s\nContent-Type: text/plain; charset=UTF-8\n\n%s\n\n' "$b" "$body"
              printf -- '--%s\nContent-Type: text/html; charset=UTF-8\n\n%s\n\n' "$b" "$html"
              printf -- '--%s--\n' "$b"; } | "$sm" -t 2>/dev/null \
              && { log_info "report sent to ${REPORT_EMAIL} via sendmail (html)"; return 0; }
        else
            { printf 'To: %s\nFrom: %s <%s>\nSubject: %s\nContent-Type: text/plain; charset=UTF-8\n\n' \
                "${REPORT_EMAIL}" "${REPORT_FROM_NAME}" "${REPORT_FROM}" "${subject}"
              printf '%s\n' "$body"; } | "$sm" -t 2>/dev/null \
              && { log_info "report sent to ${REPORT_EMAIL} via sendmail"; return 0; }
        fi
    elif have mail; then
        printf '%s\n' "$body" | mail -s "$subject" "${REPORT_EMAIL}" 2>/dev/null \
          && { log_info "report sent to ${REPORT_EMAIL} via mail"; return 0; }
    fi
    log_error "no MTA available (sendmail/mail) to send the report"; return 1
}

_report_send_sendgrid() {
    local subject="$1" body="$2" html="${3:-}"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "sendgrid needs curl+jq"; return 1; }
    [[ -r "${SENDGRID_KEY_FILE}" ]] || { log_error "SendGrid key not readable: ${SENDGRID_KEY_FILE}"; return 1; }
    local key payload code
    key="$(cat "${SENDGRID_KEY_FILE}")"
    # SendGrid requires text/plain before text/html in the content array.
    payload="$(jq -nc --arg to "${REPORT_EMAIL}" --arg from "${REPORT_FROM}" \
        --arg fromname "${REPORT_FROM_NAME}" --arg subj "${subject}" --arg body "${body}" --arg html "${html}" '{
        personalizations:[{to:[{email:$to}]}],
        from:{email:$from,name:$fromname},
        subject:$subj,
        content:( [{type:"text/plain",value:$body}] + (if $html=="" then [] else [{type:"text/html",value:$html}] end) )
    }')"
    code="$(curl -sS --max-time 15 -X POST "https://api.sendgrid.com/v3/mail/send" \
        -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" \
        --data "$payload" -o /dev/null -w '%{http_code}')"
    if [[ "$code" == "202" ]]; then log_info "report sent to ${REPORT_EMAIL} via SendGrid (202)"; return 0; fi
    log_error "SendGrid send failed (HTTP ${code})"; return 1
}

# Entry point: swatter report [WINDOW] [--test]
swatter_report() {
    local window="${REPORT_WINDOW:-24h}" test_mode=0 arg
    for arg in "$@"; do
        case "$arg" in
            --test) test_mode=1 ;;
            [0-9]*h|[0-9]*d|[0-9]*m) window="$arg" ;;
        esac
    done
    [[ -n "${REPORT_EMAIL}" ]] || { log_warn "REPORT_EMAIL unset; nothing to send"; return 0; }

    # Build into a temp file via redirection (NOT $(...)), so the RPT_* counters
    # the builder sets persist in this shell — a command substitution would run
    # the builder in a subshell and lose them.
    local bodyfile; bodyfile="$(mktemp "${TMPDIR:-/tmp}/swatter-report.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -f '$bodyfile'" RETURN
    swatter_report_build "$window" > "$bodyfile"
    local body; body="$(cat "$bodyfile")"

    # Stay silent only when BOTH planes are quiet (no actions, no exemptions, no
    # genuine server errors) — unless --test.
    local err_genuine="${ERR_GENUINE:-0}" err_fatal="${ERR_FATAL:-0}"
    if (( ! test_mode )) && (( RPT_ACTED == 0 && RPT_EXEMPT == 0 && err_genuine == 0 )); then
        log_info "report: quiet window (${window}); not sending"
        return 0
    fi

    # Subject summarizes both planes.
    local host subject parts=""
    host="$(hostname -s 2>/dev/null || hostname)"
    if (( RPT_PERM > 0 )); then parts="${RPT_PERM} perm + ${RPT_TEMP} temp block(s)"
    elif (( RPT_ACTED > 0 )); then parts="${RPT_ACTED} block(s)"
    elif (( RPT_EXEMPT > 0 )); then parts="${RPT_EXEMPT} exemption(s)"; fi
    if (( err_genuine > 0 )); then
        local errpart="${err_genuine} server error(s)"
        (( err_fatal > 0 )) && errpart="${err_fatal} FATAL + ${err_genuine} error(s)"
        parts="${parts:+${parts} + }${errpart}"
    fi
    [[ -n "$parts" ]] || parts="all quiet"
    subject="[Swatter] ${parts} in ${window} — ${host}"
    (( test_mode )) && subject="[TEST] ${subject}"

    local html; html="$(_report_render_html "$body")"
    _report_send "$subject" "$body" "$html"
}
