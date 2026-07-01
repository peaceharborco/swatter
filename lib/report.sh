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

    RPT_ACTED=0 RPT_PERM=0 RPT_TEMP=0 RPT_CF=0 RPT_DIRECT=0 RPT_EXEMPT=0 RPT_WATCH=0 RPT_FAILED=0 RPT_FAIL_CAUSE=""
    ERR_TOTAL=0 ERR_FATAL=0 ERR_GENUINE=0 ERR_NOISE=0
    OL_HITS=0 OL_IPS=0 OL_P80=0 OL_P443=0 OL_MODE="" OL_TOP_ROWS=""

    # Gather ALL THREE planes first (via redirection so their RPT_*/OL_*/ERR_*
    # counters persist in this shell — a command substitution would run in a
    # subshell and lose them). The grade needs every plane, so it can't be computed
    # until they're all in.
    local olfile="" errsec="" errfile="" abusefile
    abusefile="$(mktemp "${TMPDIR:-/tmp}/swatter-abuse.XXXXXX")"
    _report_emit_abuse "$window" "$cutoff" "$log" > "$abusefile"
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

    _report_grade   # sets RPT_GRADE / RPT_GRADE_WORD / RPT_GRADE_HEADLINE / RPT_GRADE_SUB / RPT_RECO

    echo "Swatter Nightly Report — $(hostname -f 2>/dev/null || hostname)"
    echo "Window: last ${window}  (mode: ${SWATTER_MODE})"
    echo
    echo "GRADE ${RPT_GRADE} — ${RPT_GRADE_WORD}:  ${RPT_GRADE_HEADLINE}"
    echo "${RPT_GRADE_SUB}"
    echo "-> ${RPT_RECO}"
    echo
    echo "========================  Bad Actors  ==========================="
    echo
    _report_summary_actors
    echo
    cat "$abusefile"
    rm -f "$abusefile"

    if _ol_digest_should_render "${OL_HITS:-0}"; then
        echo
        echo "========================  Origin-Lock  =========================="
        echo
        _report_summary_origin
        echo
        cat "$olfile"
    fi
    rm -f "$olfile"

    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        echo
        echo "========================  Server Errors  ========================"
        echo
        _report_summary_errors
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

    # Capture the top 1-2 offense labels (for the plain-language summary). Globals
    # persist because the builder runs emit-abuse via redirection, not a subshell.
    local _offlist
    _offlist="$(printf '%s\n' "$recs" \
        | jq -rc --argjson L "$_RPT_RULE_LABELS" \
            'select(.action=="temp" or .action=="perm")
             | (.evidence.decisive_rule // "unspecified") as $r | ($L[$r] // $r)' \
        | sort | uniq -c | sort -rn | sed -E 's/^ *[0-9]+ +//')"
    RPT_OFF1="$(printf '%s\n' "$_offlist" | sed -n 1p)"
    RPT_OFF2="$(printf '%s\n' "$_offlist" | sed -n 2p)"

    # Backend failures (block_failed) + their dominant cause, from the captured
    # evidence.backend_err. These self-heal (next scan retries), so they inform
    # but never escalate the grade — just make a silent 41/day legible.
    RPT_FAILED=$(printf '%s\n' "$recs" | jq -rc 'select(.action=="failed")' | grep -c . || true)
    RPT_FAIL_CAUSE="$(printf '%s\n' "$recs" \
        | jq -r 'select(.action=="failed") | .evidence.backend_err // empty' \
        | sort | uniq -c | sort -rn | sed -E 's/^ *[0-9]+ +//' | sed -n 1p)"

    {
        echo "Actions Taken"
        echo "-------------"
        printf '  %-22s %s\n' "permanent blocks:" "${RPT_PERM}"
        printf '  %-22s %s\n' "temporary blocks:" "${RPT_TEMP}"
        printf '  %-22s %s\n' "  direct (CSF/ipset):" "${RPT_DIRECT}"
        printf '  %-22s %s\n' "  via Cloudflare:"   "${RPT_CF}"
        printf '  %-22s %s\n' "exempted (allowlist):" "${RPT_EXEMPT}"
        printf '  %-22s %s\n' "watched (no action):" "${RPT_WATCH}"
        (( RPT_FAILED > 0 )) && printf '  %-22s %s\n' "backend-failed:" "${RPT_FAILED}${RPT_FAIL_CAUSE:+  (top: ${RPT_FAIL_CAUSE})}  — retried next scan"
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
    local _unused_body="${1:-}"   # kept for call-site compat
    _report_grade                 # ensure grade + summary globals are populated
    local host; host="$(hostname -f 2>/dev/null || hostname)"
    local esc; esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
    # Title-case the first letter (bash 3.2-safe — no ${x^}).
    local _tc; _tc() { local s="$1"; [[ -z "$s" ]] && return 0; printf '%s%s' "$(printf '%s' "${s:0:1}" | tr 'a-z' 'A-Z')" "${s:1}"; }

    local gbg gbd gfg
    case "${RPT_GRADE_LEVEL:-green}" in
        red)   gbg="#fdecea"; gbd="#f0b4ab"; gfg="#c0392b" ;;
        amber) gbg="#fff8ec"; gbd="#eccf8f"; gfg="#B26A00" ;;
        *)     gbg="#eef8f1"; gbd="#a9d9ba"; gfg="#1f8a4c" ;;
    esac

    # Recommendation — the triage hint (if any) is shown as type-this code, never a link.
    local reco; reco="$(printf '%s' "${RPT_RECO}" | esc)"
    if [[ -n "${REPORT_TRIAGE_HINT:-}" ]]; then
        local he; he="$(printf '%s' "${REPORT_TRIAGE_HINT}" | esc)"
        reco="$(printf '%s' "$reco" | sed "s|${he}|<code style=\"font-family:ui-monospace,Menlo,monospace;background:#f6ecd6;color:#8a5200;padding:2px 7px;border-radius:5px;font-weight:700\">&</code>|g")"
    fi

    printf '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:640px;margin:0 auto;background:#fff;border:1px solid #e3e7ec;border-radius:14px;overflow:hidden;color:#1b1f24">'

    # Header
    printf '<table width="100%%" style="border-bottom:1px solid #eef1f4"><tr><td style="padding:14px 22px;font-size:14px;font-weight:700">🪰 Swatter Nightly Report</td><td style="padding:14px 22px;font-size:11px;color:#545d69;text-align:right">%s · %s · %s</td></tr></table>' \
        "$(printf '%s' "$host" | esc)" "${REPORT_WINDOW:-24h}" "$(_tc "${SWATTER_MODE:-report}")"

    # Grade hero
    printf '<table><tr><td style="padding:22px 0 8px 22px;vertical-align:top;width:88px">'
    printf '<div style="width:88px;height:88px;border-radius:16px;background:%s;border:2px solid %s;text-align:center;padding-top:14px;box-sizing:border-box"><div style="font-size:40px;font-weight:800;color:%s;line-height:1">%s</div><div style="font-size:9px;font-weight:700;letter-spacing:1px;color:%s;text-transform:uppercase;margin-top:4px">%s</div></div>' \
        "$gbg" "$gbd" "$gfg" "${RPT_GRADE}" "$gfg" "$(printf '%s' "${RPT_GRADE_WORD}" | esc)"
    printf '</td><td style="padding:22px 22px 8px 18px;vertical-align:top">'
    printf '<div style="font-size:16px;font-weight:700;color:#1b1f24">%s</div><div style="font-size:13px;color:#545d69;margin-top:4px;line-height:1.55">%s</div><div style="font-size:12.5px;color:%s;margin-top:10px;line-height:1.5"><b>&rarr;</b> %s</div>' \
        "$(printf '%s' "${RPT_GRADE_HEADLINE}" | esc)" "$(printf '%s' "${RPT_GRADE_SUB}" | esc)" "$gfg" "$reco"
    printf '</td></tr></table>'

    # Grade legend
    printf '<div style="padding:0 22px 16px;font-size:10px;color:#545d69;letter-spacing:.3px">A All Clear · B Review · C Investigate · D Act Now · F Fatal / Outage</div>'

    # Bad Actors
    local bf=""
    if (( ${RPT_FAILED:-0} > 0 )); then
        bf=" · <span style=\"color:#B26A00;font-weight:600\">${RPT_FAILED} backend-failed</span>$( [[ -n "${RPT_FAIL_CAUSE:-}" ]] && printf ' <span style="color:#545d69">(top: %s — retried next scan)</span>' "$(printf '%s' "${RPT_FAIL_CAUSE}" | esc)" )"
    fi
    printf '<div style="padding:16px 22px;border-top:1px solid #eef1f4;border-left:3px solid #c0392b"><table width="100%%"><tr><td style="font-size:14px;font-weight:800">🛡️ Bad Actors</td><td style="font-size:22px;font-weight:800;color:#c0392b;text-align:right">%s</td></tr></table><div style="font-size:13px;color:#1b1f24;margin-top:5px;line-height:1.55">%s</div><div style="font-size:12px;color:#545d69;margin-top:6px">%s Permanent · %s Temporary · %s Via Cloudflare · %s At Server · %s Exempted%s</div></div>' \
        "${RPT_ACTED:-0}" "$(_report_summary_actors | esc)" "${RPT_PERM:-0}" "${RPT_TEMP:-0}" "${RPT_CF:-0}" "${RPT_DIRECT:-0}" "${RPT_EXEMPT:-0}" "$bf"

    # Origin-Lock (gated)
    if _ol_digest_should_render "${OL_HITS:-0}"; then
        printf '<div style="padding:16px 22px;border-top:1px solid #eef1f4;border-left:3px solid #2a6b7c"><table width="100%%"><tr><td style="font-size:14px;font-weight:800">🔒 Origin-Lock <span style="font-size:11px;font-weight:600;color:#545d69">· Mode %s</span></td><td style="font-size:22px;font-weight:800;color:#2a6b7c;text-align:right">%s</td></tr></table><div style="font-size:13px;color:#1b1f24;margin-top:5px;line-height:1.55">%s</div><div style="font-size:12px;color:#545d69;margin-top:6px">%s IPs · :443 %s · :80 %s</div>' \
            "$(_tc "${OL_MODE}")" "${OL_HITS:-0}" "$(_report_summary_origin | esc)" "${OL_IPS:-0}" "${OL_P443:-0}" "${OL_P80:-0}"
        printf '<table style="width:100%%;border-collapse:collapse;font-size:12px;margin-top:8px"><thead><tr style="color:#545d69;font-size:10px;text-align:left;text-transform:uppercase;letter-spacing:.4px"><th style="padding:4px 6px 4px 0">Source IP</th><th style="padding:4px 6px;text-align:right">Hits</th><th style="padding:4px 0 4px 6px;text-align:right">Verdict</th></tr></thead><tbody>'
        printf '%s' "$OL_TOP_ROWS" | while IFS=$'\t' read -r ip n tag; do
            [[ -n "$ip" ]] || continue
            local tc="#545d69"; [[ "$tag" == attacker* ]] && tc="#c0392b"
            printf '<tr style="border-top:1px solid #eef1f4"><td style="padding:5px 6px 5px 0;font-family:ui-monospace,Menlo,monospace">%s</td><td style="padding:5px 6px;text-align:right;font-variant-numeric:tabular-nums">%s</td><td style="padding:5px 0 5px 6px;text-align:right;color:%s;font-weight:600">%s</td></tr>' \
                "$(printf '%s' "$ip" | esc)" "$n" "$tc" "$(_tc "$(printf '%s' "$tag" | esc)")"
        done
        printf '</tbody></table></div>'
    fi

    # Server Errors (gated)
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        local efc="#1f8a4c"; (( ${ERR_FATAL:-0} > 0 )) && efc="#c0392b"
        printf '<div style="padding:16px 22px;border-top:1px solid #eef1f4;border-left:3px solid #c9d0d8"><table width="100%%"><tr><td style="font-size:14px;font-weight:800">🩺 Server Errors</td><td style="font-size:22px;font-weight:800;color:#545d69;text-align:right">%s</td></tr></table><div style="font-size:13px;color:#1b1f24;margin-top:5px;line-height:1.55">%s</div><div style="font-size:12px;color:#545d69;margin-top:6px"><b style="color:#545d69">%s</b> Non-Fatal · <b style="color:%s">%s</b> Fatal</div></div>' \
            "${ERR_GENUINE:-0}" "$(_report_summary_errors | esc)" "${ERR_GENUINE:-0}" "$efc" "${ERR_FATAL:-0}"
    fi

    # Footer
    printf '<div style="padding:16px 22px 6px;color:#545d69;font-size:11px;border-top:1px solid #eef1f4">On The Server: <code style="color:#545d69">swatter why &lt;ip&gt;</code> — <i>Why An IP Was Flagged</i> · <code style="color:#545d69">swatter unblock &lt;ip&gt;</code> — <i>Lift A Block</i></div>'
    printf '<div style="padding:10px 22px 16px;color:#545d69;font-size:11px;text-align:center">🪰 Swatter · a <a href="https://studios.peaceharbor.com" style="color:#C48A2E;text-decoration:none;font-weight:600">Peace Harbor Studios</a> project · <a href="https://github.com/peaceharborco/swatter" style="color:#C48A2E;text-decoration:none">GitHub</a></div>'
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

# Report-card grade (A–F) + recommendation. Worst signal wins. Sets the RPT_GRADE*
# / RPT_RECO globals both renderers read. The grade decides whether the report
# tells the operator to run their triage command (REPORT_TRIAGE_HINT).
_report_grade() {
    local f="${ERR_FATAL:-0}" e="${ERR_GENUINE:-0}" b="${RPT_ACTED:-0}" ol="${OL_HITS:-0}"
    local win="${REPORT_WINDOW:-24h}" hint="${REPORT_TRIAGE_HINT:-}"
    local dE="${REPORT_GRADE_D_ERRORS:-300}" cE="${REPORT_GRADE_C_ERRORS:-100}"

    # Worst signal wins. Blocks never escalate past B — they're Swatter working.
    if   (( f > 0 ));  then RPT_GRADE=F; RPT_GRADE_WORD="Fatal";       RPT_GRADE_LEVEL=red
    elif (( e >= dE )); then RPT_GRADE=D; RPT_GRADE_WORD="Act Now";     RPT_GRADE_LEVEL=red
    elif (( e >= cE )); then RPT_GRADE=C; RPT_GRADE_WORD="Investigate"; RPT_GRADE_LEVEL=amber
    elif (( b > 0 || e > 0 || ol > 0 )); then RPT_GRADE=B; RPT_GRADE_WORD="Review"; RPT_GRADE_LEVEL=amber
    else                RPT_GRADE=A; RPT_GRADE_WORD="All Clear";   RPT_GRADE_LEVEL=green
    fi

    local es; es="$( (( e == 1 )) || echo s )"    # pluralizers
    local bs; bs="$( (( b == 1 )) || echo s )"
    local fs; fs="$( (( f == 1 )) || echo s )"
    local recap="${e} non-fatal error${es} and ${b} block${bs} in the last ${win}."
    case "$RPT_GRADE" in
        A) RPT_GRADE_HEADLINE="All Clear — Nothing To Do";       RPT_GRADE_SUB="A quiet ${win}: no errors and nothing that needed action." ;;
        B) RPT_GRADE_HEADLINE="Worth A Look — Nothing's On Fire"; RPT_GRADE_SUB="${recap} No fatal errors, no outage." ;;
        C) RPT_GRADE_HEADLINE="Worth Investigating";              RPT_GRADE_SUB="${recap} No fatal errors, but the volume is above routine." ;;
        D) RPT_GRADE_HEADLINE="Needs Attention";                  RPT_GRADE_SUB="${recap} A high error count — check it before it escalates." ;;
        F) RPT_GRADE_HEADLINE="Action Needed";                    RPT_GRADE_SUB="${f} fatal error${fs} — a service or app may be down." ;;
    esac

    case "$RPT_GRADE" in
        A) RPT_RECO="No action needed." ;;
        B) [[ -n "$hint" ]] && RPT_RECO="Skim the sections below; run ${hint} if anything stands out." || RPT_RECO="Skim the sections below when you have a moment." ;;
        C) [[ -n "$hint" ]] && RPT_RECO="Run ${hint} to triage." || RPT_RECO="Review the sections below to triage." ;;
        D) [[ -n "$hint" ]] && RPT_RECO="Run ${hint} now to triage." || RPT_RECO="Investigate now." ;;
        F) [[ -n "$hint" ]] && RPT_RECO="Run ${hint} now — ${f} fatal error${fs}." || RPT_RECO="Investigate the ${f} fatal error${fs} now." ;;
    esac
}

# Plain-language one-liners per section, composed from the counters. Sentence case.
_report_summary_actors() {
    (( ${RPT_ACTED:-0} > 0 )) || { echo "No blocks this window — quiet."; return 0; }
    local off=""
    [[ -n "${RPT_OFF1:-}" ]] && off=" — mostly ${RPT_OFF1}"
    [[ -n "${RPT_OFF1:-}" && -n "${RPT_OFF2:-}" ]] && off="${off} and ${RPT_OFF2}"
    local spared=""
    if (( ${RPT_EXEMPT:-0} > 0 )); then
        local xs; xs="$( (( RPT_EXEMPT == 1 )) || echo s )"
        spared=" ${RPT_EXEMPT} trusted IP${xs} were spared."
    fi
    echo "Automated attackers${off}. ${RPT_CF:-0} stopped at Cloudflare's edge, ${RPT_DIRECT:-0} blocked at the server.${spared}"
}
_report_summary_origin() {
    local disp="all dropped at the firewall before reaching a site"
    [[ "${OL_MODE:-}" == log* ]] && disp="logged in dry-run mode — not yet enforced"
    echo "Bots hitting the raw server IP to bypass Cloudflare — a mix of known attackers and unclassified scanners, ${disp}."
}
_report_summary_errors() {
    local f="${ERR_FATAL:-0}" e="${ERR_GENUINE:-0}"
    if (( f > 0 )); then
        local fs; fs="$( (( f == 1 )) || echo s )"
        echo "${f} fatal error${fs} — a service or app crashed; investigate now. ${e} non-fatal alongside."
    elif (( e > 0 )); then
        echo "Mostly scanner-induced proxy noise and rejected probes the server handled cleanly. No crashes or outages."
    else
        echo "No server errors this window."
    fi
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

    # Second channel: SMS on a severe grade (D/F by default). Fail-soft — never
    # blocks the email. --test forces a [TEST] SMS so Twilio setup can be verified.
    if declare -F swatter_alert_on_grade >/dev/null; then
        if (( test_mode )); then swatter_alert_on_grade --test; else swatter_alert_on_grade; fi
    fi
}
