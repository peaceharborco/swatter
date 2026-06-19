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

# Plain-English labels for decisive-rule identifiers, for the digest only —
# decisions.jsonl and `swatter why` keep the raw identifier for the audit trail.
# Unknown/future rules fall through and display as-is.
_RPT_RULE_LABELS='{
  "critical_badpath":    "probed secret/exploit files",
  "high_badpath_repeat": "brute-forced a sensitive page",
  "scanner_profile":     "vulnerability scanning",
  "error_burst":         "error-response burst (fuzzing)",
  "request_flood":       "request flood",
  "unspecified":         "combined suspicious signals"
}'

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
#   RPT_ACTED RPT_PERM RPT_TEMP RPT_CF RPT_DIRECT RPT_EXEMPT RPT_WATCH
swatter_report_build() {
    local window="$1" cutoff
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    local log="${LOG_DIR}/decisions.jsonl"

    RPT_ACTED=0 RPT_PERM=0 RPT_TEMP=0 RPT_CF=0 RPT_DIRECT=0 RPT_EXEMPT=0 RPT_WATCH=0
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
    [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && echo "Error triage:   swatter report --test"
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
    RPT_DIRECT=$(printf '%s\n' "$recs" | jq -rc 'select((.channel=="csf" or .channel=="ipset") and (.action=="temp" or .action=="perm"))' | grep -c . || true)
    RPT_ACTED=$(( RPT_PERM + RPT_TEMP ))

    {
        echo "Actions taken"
        echo "-------------"
        printf '  %-22s %s\n' "permanent blocks:" "${RPT_PERM}"
        printf '  %-22s %s\n' "temporary blocks:" "${RPT_TEMP}"
        printf '  %-22s %s\n' "  direct (CSF/ipset):" "${RPT_DIRECT}"
        printf '  %-22s %s\n' "  via Cloudflare:"   "${RPT_CF}"
        printf '  %-22s %s\n' "exempted (allowlist):" "${RPT_EXEMPT}"
        printf '  %-22s %s\n' "watched (no action):" "${RPT_WATCH}"
        echo

        echo "By offense type (acted only)"
        echo "----------------------------"
        printf '%s\n' "$recs" \
            | jq -rc --argjson L "$_RPT_RULE_LABELS" \
                'select(.action=="temp" or .action=="perm")
                 | (.evidence.decisive_rule // "unspecified") as $r | ($L[$r] // $r)' \
            | sort | uniq -c | sort -rn \
            | awk '{c=$1; sub(/^ *[0-9]+ /,""); printf "  %-30s %s\n", $0, c}'
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
            printf '%-16s %5s %-12s %-30s %-10s %s\n' "IP" "SCORE" "ACTION" "WHY" "CHANNEL" "TTL"
            printf '%s\n' "$recs" \
                | jq -rc --argjson L "$_RPT_RULE_LABELS" \
                         'select(.action=="temp" or .action=="perm")
                          | (.evidence.decisive_rule // "unspecified") as $r
                          | [.ip,(.score|tostring),.action,($L[$r] // $r),.channel,(.ttl|tostring)] | @tsv' \
                | tail -100 \
                | awk -F'\t' '{printf "%-16s %5s %-12s %-30s %-10s %s\n",$1,$2,$3,$4,$5,$6}'
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
        _pill "${RPT_DIRECT:-0}"   "#dbedff" "#0349b4" 0 "direct"
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
    local subject="$1" body="$2" html="${3:-}"
    swatter_send_email "${REPORT_EMAIL}" "$subject" "$body" "$html"
}

# Entry point: swatter report [WINDOW] [--test|--print]
# --print writes the digest body to stdout and sends nothing — for operators
# (and automation) who want the email's content on demand.
swatter_report() {
    local window="${REPORT_WINDOW:-24h}" test_mode=0 print_mode=0 arg
    for arg in "$@"; do
        case "$arg" in
            --test) test_mode=1 ;;
            --print) print_mode=1 ;;
            [0-9]*h|[0-9]*d|[0-9]*m) window="$arg" ;;
        esac
    done
    if (( print_mode )); then
        swatter_report_build "$window"
        return 0
    fi
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
