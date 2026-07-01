#!/usr/bin/env bash
# lib/report.sh — nightly email digest of offenses and actions.
#
# Reads the structured decision log (decisions.jsonl), filters to a window
# (default 24h), groups what happened by ACTION, by OFFENSE (decisive rule +
# bad-path category), and by CHANNEL (csf/cloudflare), then emails a compact
# digest. Stays silent when the window had no activity unless --test is given.
#
# Only perm/temp count toward the block tallies (exact-matched below). The other
# actions are observability, not blocks: exempt, watch, noop-perm, skipped-cap,
# skipped-config, skipped-novhost, skipped-cf-plane, skipped-failclosed, and
# failed (a backend error — deliberately NOT counted as an enforced block).
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
    OL_HITS=0 OL_IPS=0 OL_P80=0 OL_P443=0 OL_MODE="" OL_TOP_ROWS=""

    # Gather origin-lock + errors via redirection (NOT $(...)) so the OL_* / ERR_*
    # counters they set persist in this shell — a command substitution would run
    # the builder in a subshell and lose them.
    local olfile="" errsec="" errfile=""
    if [[ "${ORIGIN_LOCK_DIGEST:-auto}" != "off" ]]; then
        olfile="$(mktemp "${TMPDIR:-/tmp}/swatter-olsec.XXXXXX")"
        swatter_originlock_section "$window" > "$olfile"
    fi
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && declare -F swatter_errors_section >/dev/null; then
        errfile="$(mktemp "${TMPDIR:-/tmp}/swatter-errsec.XXXXXX")"
        swatter_errors_section "$window" > "$errfile"
        errsec="$(cat "$errfile")"
        rm -f "$errfile"
    fi

    echo "Swatter Nightly Report — $(hostname -f 2>/dev/null || hostname)"
    echo "Window: last ${window}  (mode: ${SWATTER_MODE})"
    echo
    echo "========================  Bad Actors  ==========================="
    echo
    _report_emit_abuse "$window" "$cutoff" "$log"

    if _ol_digest_should_render "${OL_HITS:-0}"; then
        echo
        echo "========================  Origin-Lock  =========================="
        echo
        cat "$olfile"
    fi
    rm -f "$olfile"

    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        echo
        echo "========================  Server Errors  ========================"
        echo
        printf '%s\n' "$errsec"
    fi

    echo
    echo "------------------------------------------------------------------"
    echo "On the server:"
    echo "  swatter why <ip>      — see why an IP was flagged"
    echo "  swatter unblock <ip>  — lift a block"
    echo "Abuse log: ${log}"
    echo
    echo "Swatter · a Peace Harbor Studios project — https://studios.peaceharbor.com"
    echo "GitHub: https://github.com/peaceharborco/swatter"
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
        echo "Actions Taken"
        echo "-------------"
        printf '  %-22s %s\n' "permanent blocks:" "${RPT_PERM}"
        printf '  %-22s %s\n' "temporary blocks:" "${RPT_TEMP}"
        printf '  %-22s %s\n' "  direct (CSF/ipset):" "${RPT_DIRECT}"
        printf '  %-22s %s\n' "  via Cloudflare:"   "${RPT_CF}"
        printf '  %-22s %s\n' "exempted (allowlist):" "${RPT_EXEMPT}"
        printf '  %-22s %s\n' "watched (no action):" "${RPT_WATCH}"
        echo

        echo "By Offense Type"
        echo "---------------"
        printf '%s\n' "$recs" \
            | jq -rc --argjson L "$_RPT_RULE_LABELS" \
                'select(.action=="temp" or .action=="perm")
                 | (.evidence.decisive_rule // "unspecified") as $r | ($L[$r] // $r)' \
            | sort | uniq -c | sort -rn \
            | awk '{c=$1; sub(/^ *[0-9]+ /,""); printf "  %-30s %s\n", $0, c}'
        echo

        echo "By Bad-Path Category"
        echo "--------------------"
        printf '%s\n' "$recs" \
            | jq -rc 'select(.action=="temp" or .action=="perm") | (.evidence.badpath_cat // "" | if .=="" then "(behavioral)" else . end)' \
            | sort | uniq -c | sort -rn \
            | awk '{printf "  %-26s %s\n", $2, $1}'
        echo

        if (( RPT_ACTED > 0 )); then
            echo "Blocks (Newest First)"
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
            echo "Exemptions"
            echo "----------"
            printf '%s\n' "$recs" \
                | jq -rc 'select(.action=="exempt") | [.ip,(.score|tostring),.reason] | @tsv' \
                | sort -u \
                | awk -F'\t' '{printf "  %-16s score=%-4s %s\n",$1,$2,$3}'
            echo
        fi
    }
}

# Render Direction-B structured HTML from globals. $1 = plain-text body (unused;
# kept for call-site compatibility). Emits HTML on stdout.
# Inline styles + tables only (email-client safe). No <pre> dump.
_report_render_html() {
    local _unused_body="$1"   # text body no longer embedded; kept for call-site compat
    local host; host="$(hostname -f 2>/dev/null || hostname)"
    local v level summary; v="$(_report_verdict)"; level="${v%%$'\t'*}"; summary="${v#*$'\t'}"
    local vbar vbg
    case "$level" in
        red)   vbar="#b31d28"; vbg="#fff5f5" ;;
        amber) vbar="#9a4d00"; vbg="#fffbea" ;;
        *)     vbar="#1a7f37"; vbg="#f0fff4" ;;
    esac
    local esc; esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

    _tile() { # value label bg border fg
        (( ${1:-0} > 0 )) || return 0
        printf '<div style="flex:1;min-width:80px;text-align:center;background:%s;border:1px solid %s;border-radius:8px;padding:8px 4px"><div style="font-size:20px;font-weight:800;color:%s">%s</div><div style="font-size:10px;color:#586069">%s</div></div>' "$3" "$4" "$5" "$1" "$2"
    }
    _sechead() { printf '<div style="font-size:14px;font-weight:700;color:#24292e;border-bottom:2px solid #eaecef;padding-bottom:5px;margin:14px 0 9px">%s</div>' "$1"; }

    printf '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;border:1px solid #e1e4e8;border-radius:10px;overflow:hidden;color:#24292e">'
    printf '<div style="background:#24292e;color:#fff;padding:14px 18px"><div style="font-size:17px;font-weight:700">🪰 Swatter Nightly Report</div><div style="font-size:12px;color:#b1b8c0;margin-top:2px">%s · last %s · mode: <b style="color:#fff">%s</b></div></div>' \
        "$(printf '%s' "$host" | esc)" "${REPORT_WINDOW:-24h}" "${SWATTER_MODE:-report}"
    printf '<div class="verdict-%s" style="padding:12px 18px;border-left:4px solid %s;background:%s;font-size:13px">%s</div>' \
        "$level" "$vbar" "$vbg" "$(printf '%s' "$summary" | esc)"

    printf '<div style="display:flex;flex-wrap:wrap;gap:8px;padding:14px 18px 6px">'
    _tile "${RPT_PERM:-0}"  "Permanent"      "#fff5f5" "#ffd7d7" "#b31d28"
    _tile "${RPT_TEMP:-0}"  "Temporary"      "#fffbea" "#f5e6a8" "#735c0f"
    _tile "${RPT_CF:-0}"    "Via Cloudflare" "#fff5ec" "#ffd9b8" "#9a4d00"
    _ol_digest_should_render "${OL_HITS:-0}" && _tile "${OL_HITS:-0}" "Origin-Lock" "#faf7ff" "#e6d8ff" "#8957e5"
    [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && _tile "${ERR_GENUINE:-0}" "Server Errors" "#f6f8fa" "#e1e4e8" "#444d56"
    printf '</div>'

    # Bad Actors (always)
    printf '<div style="padding:0 18px">'
    _sechead "🛡️ Bad Actors"
    printf '<div style="font-size:12px;color:#444d56">Permanent <b>%s</b> · Temporary <b>%s</b> · Via Cloudflare <b>%s</b> · Exempted <b>%s</b></div>' \
        "${RPT_PERM:-0}" "${RPT_TEMP:-0}" "${RPT_CF:-0}" "${RPT_EXEMPT:-0}"
    printf '</div>'

    # Origin-Lock (gated)
    if _ol_digest_should_render "${OL_HITS:-0}"; then
        printf '<div style="padding:0 18px">'
        _sechead "🔒 Origin-Lock"
        printf '<div style="font-size:12px;color:#444d56"><b>%s</b> direct-to-origin hits dropped · %s IPs · :80 %s · :443 %s · mode %s</div>' \
            "${OL_HITS:-0}" "${OL_IPS:-0}" "${OL_P80:-0}" "${OL_P443:-0}" "$(printf '%s' "${OL_MODE}" | esc)"
        printf '<table style="width:100%%;border-collapse:collapse;font-size:12px;margin-top:6px"><thead><tr style="color:#586069;font-size:11px;text-align:left"><th style="padding:3px 6px">Source IP</th><th style="padding:3px 6px">Hits</th><th style="padding:3px 6px">Tag</th></tr></thead><tbody>'
        printf '%s' "$OL_TOP_ROWS" | while IFS=$'\t' read -r ip n tag; do
            [[ -n "$ip" ]] || continue
            printf '<tr style="border-top:1px solid #ece3fb"><td style="padding:4px 6px;font-family:ui-monospace,Menlo,monospace">%s</td><td style="padding:4px 6px">%s</td><td style="padding:4px 6px">%s</td></tr>' \
                "$(printf '%s' "$ip" | esc)" "$n" "$(printf '%s' "$tag" | esc)"
        done
        printf '</tbody></table></div>'
    fi

    # Server Errors (gated)
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        printf '<div style="padding:0 18px">'
        _sechead "🩺 Server Errors"
        printf '<div style="font-size:12px;color:#444d56"><b>%s Genuine</b> · %s FATAL</div>' "${ERR_GENUINE:-0}" "${ERR_FATAL:-0}"
        printf '</div>'
    fi

    printf '<div style="padding:14px 18px 4px;color:#959da5;font-size:11px">On the server: <code>swatter why &lt;ip&gt;</code> — why an IP was flagged · <code>swatter unblock &lt;ip&gt;</code> — lift a block</div>'
    printf '<div style="padding:10px 18px 16px;border-top:1px solid #eaecef;color:#8b949e;font-size:11px;text-align:center">🪰 Swatter · a <a href="https://studios.peaceharbor.com" style="color:#C48A2E;text-decoration:none;font-weight:600">Peace Harbor Studios</a> project · <a href="https://github.com/peaceharborco/swatter" style="color:#C48A2E;text-decoration:none">GitHub</a></div>'
    printf '</div>'
}

# Deliver the digest. $1 subject $2 text-body $3 html-body
_report_send() {
    local subject="$1" body="$2" html="${3:-}"
    swatter_send_email "${REPORT_EMAIL}" "$subject" "$body" "$html"
}

# Worst-plane-wins severity. Echoes "LEVEL<TAB>SUMMARY" (LEVEL: green|amber|red).
_report_verdict() {
    local level="green" lead="healthy"
    if   (( ${ERR_FATAL:-0}   > 0 )); then level="red";   lead="⚠ ${ERR_FATAL} FATAL"
    elif (( ${ERR_GENUINE:-0} > 0 )); then level="amber"; lead="⚠ ${ERR_GENUINE} server error(s)"
    fi
    local tail="${RPT_ACTED:-0} blocked"
    (( ${OL_HITS:-0} > 0 )) && tail="${tail} · ${OL_HITS} origin-lock"
    [[ "$level" == "green" ]] && tail="${tail}, ${ERR_FATAL:-0} FATAL"
    printf '%s\t%s · %s' "$level" "$lead" "$tail"
}

# Echoes "Report <YYYY-MM-DD> - <summary>" (UTC run date).
_report_subject() {
    local d; d="$(date -u -d "@$(swatter_now)" +%F 2>/dev/null || date -u -r "$(swatter_now)" +%F)"
    local v; v="$(_report_verdict)"
    printf 'Report %s - %s' "$d" "${v#*$'\t'}"
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
    local subject; subject="$(_report_subject "$window")"
    (( test_mode )) && subject="[TEST] ${subject}"

    local html; html="$(_report_render_html "$body")"
    _report_send "$subject" "$body" "$html"
}
