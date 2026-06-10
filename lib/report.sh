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

    if [[ ! -r "$log" ]]; then
        echo "No decision log at ${log}."
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

    local mode; mode="$(printf '%s\n' "$recs" | jq -r '.mode' | tail -1)"

    {
        echo "Swatter nightly digest — $(hostname -f 2>/dev/null || hostname)"
        echo "Window: last ${window}  (mode: ${mode})"
        echo
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

        echo "------------------------------------------------------------------"
        echo "Full evidence:  swatter why <ip>      Live log: ${log}"
    }
}

# Deliver the digest. $1 subject $2 body $3 html(optional)
_report_send() {
    local subject="$1" body="$2"
    case "${REPORT_METHOD}" in
        sendgrid) _report_send_sendgrid "$subject" "$body" ;;
        *)        _report_send_sendmail "$subject" "$body" ;;
    esac
}

_report_send_sendmail() {
    local subject="$1" body="$2"
    if have sendmail || [[ -x /usr/sbin/sendmail ]]; then
        local sm; sm="$(command -v sendmail || echo /usr/sbin/sendmail)"
        { printf 'To: %s\nFrom: %s <%s>\nSubject: %s\nContent-Type: text/plain; charset=UTF-8\n\n' \
            "${REPORT_EMAIL}" "${REPORT_FROM_NAME}" "${REPORT_FROM}" "${subject}"
          printf '%s\n' "$body"; } | "$sm" -t 2>/dev/null \
          && { log_info "report sent to ${REPORT_EMAIL} via sendmail"; return 0; }
    elif have mail; then
        printf '%s\n' "$body" | mail -s "$subject" "${REPORT_EMAIL}" 2>/dev/null \
          && { log_info "report sent to ${REPORT_EMAIL} via mail"; return 0; }
    fi
    log_error "no MTA available (sendmail/mail) to send the report"; return 1
}

_report_send_sendgrid() {
    local subject="$1" body="$2"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_error "sendgrid needs curl+jq"; return 1; }
    [[ -r "${SENDGRID_KEY_FILE}" ]] || { log_error "SendGrid key not readable: ${SENDGRID_KEY_FILE}"; return 1; }
    local key payload code
    key="$(cat "${SENDGRID_KEY_FILE}")"
    payload="$(jq -nc --arg to "${REPORT_EMAIL}" --arg from "${REPORT_FROM}" \
        --arg fromname "${REPORT_FROM_NAME}" --arg subj "${subject}" --arg body "${body}" '{
        personalizations:[{to:[{email:$to}]}],
        from:{email:$from,name:$fromname},
        subject:$subj,
        content:[{type:"text/plain",value:$body}]
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

    local body; body="$(swatter_report_build "$window")"

    # Stay silent on a quiet window unless --test.
    if (( ! test_mode )) && (( RPT_ACTED == 0 && RPT_EXEMPT == 0 )); then
        log_info "report: quiet window (${window}); not sending"
        return 0
    fi

    local host subject
    host="$(hostname -s 2>/dev/null || hostname)"
    if (( RPT_PERM > 0 )); then
        subject="[Swatter] ${RPT_PERM} perm + ${RPT_TEMP} temp block(s) in ${window} — ${host}"
    elif (( RPT_ACTED > 0 )); then
        subject="[Swatter] ${RPT_ACTED} block(s) in ${window} — ${host}"
    else
        subject="[Swatter] ${RPT_EXEMPT} allowlist exemption(s) in ${window} — ${host}"
    fi
    (( test_mode )) && subject="[TEST] ${subject}"

    _report_send "$subject" "$body"
}
