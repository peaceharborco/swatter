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
    SWARM_FEED_N=0 SWARM_STALE=0 SWARM_PREBLOCKED=0 SWARM_CONTRIB=0 SWARM_LAST_PUB="none" SWARM_COUNTS_OK=1

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
    local swfile=""
    if _swarm_enabled; then
        swfile="$(mktemp "${TMPDIR:-/tmp}/swatter-swsec.XXXXXX")"
        swatter_swarm_section "$window" "$cutoff" "$log" > "$swfile"
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

    if _swarm_enabled; then
        echo
        echo "========================  Swarm  ================================"
        echo
        _report_summary_swarm
        [[ -s "$swfile" ]] && cat "$swfile"
    fi
    rm -f "$swfile"

    echo
    echo "------------------------------------------------------------------"
    echo "On the server:"
    echo "  swatter why <ip>      — see why an IP was flagged"
    echo "  swatter unblock <ip>  — lift a block"
    echo "Abuse log: ${log}"
    echo
    echo "Swatter — https://github.com/peaceharborco/swatter"
    echo "Peace Harbor Studios — a division of Peace Harbor Companies"
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

# Render structured HTML from globals. $1 = plain-text body (unused; kept for
# call-site compatibility). Emits HTML on stdout.
#
# Canonical Peace Harbor system-email template (peaceharbor repo:
# brand/email-template.md, owner-approved 2026-07-02): stacked STUDIOS lockup
# on cream, Title Caps headings, table layout for mail-client safety, slate
# #4A5568 as the muted floor, inline styles only.
#
# Operators running their own Swatter may replace the header logo:
#   REPORT_LOGO_URL  — https URL of your logo (shown 360px wide, scales down)
#   REPORT_LOGO_ALT  — its alt text
# The footer branding is part of the project and is not configurable.
_report_render_html() {
    local _unused_body="${1:-}"   # kept for call-site compat
    _report_grade                 # ensure grade + summary globals are populated
    local host; host="$(hostname -f 2>/dev/null || hostname)"
    local esc; esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
    # Title-case the first letter (bash 3.2-safe — no ${x^}).
    local _tc; _tc() { local s="$1"; [[ -z "$s" ]] && return 0; printf '%s%s' "$(printf '%s' "${s:0:1}" | tr 'a-z' 'A-Z')" "${s:1}"; }

    local logo="${REPORT_LOGO_URL:-https://assets.peaceharbor.com/email/ph-lockup-stacked-studios-email-720w-v2.png}"
    local logo_alt="${REPORT_LOGO_ALT:-Peace Harbor Studios}"

    # Brand tokens (brand/email-template.md).
    local f_h='font-family:Sora,Helvetica,Arial,sans-serif'
    local f_b='font-family:Manrope,Helvetica,Arial,sans-serif'
    local pine='#1E3A2F' slate='#4A5568' ink='#1A1814' cream='#F4F0E8'
    local bdr='#E3DCCB' panel='#FBF9F4' ember='#8C3B2E' lake='#2A5A6B'
    local h3="${f_h};font-weight:600;font-size:14.5px;color:${pine};"

    # Grade badge/tile colors: Info / Warn / Critical per the template.
    local gbg gfg
    case "${RPT_GRADE_LEVEL:-green}" in
        red)   gbg="#F3E4E0"; gfg="$ember" ;;
        amber) gbg="#F7EBD4"; gfg="#7A5313" ;;
        *)     gbg="$cream";  gfg="$pine" ;;
    esac

    # Recommendation — the triage hint (if any) is shown as type-this code, never a link.
    local reco; reco="$(printf '%s' "${RPT_RECO}" | esc)"
    if [[ -n "${REPORT_TRIAGE_HINT:-}" ]]; then
        local he; he="$(printf '%s' "${REPORT_TRIAGE_HINT}" | esc)"
        # Neutralize sed metacharacters (incl. the | delimiter) in the pattern so
        # an unusual hint can't corrupt the substitution.
        local he_pat; he_pat="$(printf '%s' "$he" | sed 's/[][\\.*^$|&]/\\&/g')"
        reco="$(printf '%s' "$reco" | sed "s|${he_pat}|<code style=\"font-family:ui-monospace,Menlo,monospace;background:#F7EBD4;color:#7A5313;padding:2px 7px;border-radius:5px;font-weight:700\">&</code>|g")"
    fi

    printf '<div style="margin:0;padding:28px 16px;background:%s;">' "$cream"
    printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0"><tr><td align="center">'
    printf '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%%;background:#ffffff;border:1px solid %s;border-radius:10px;">' "$bdr"

    # Header — stacked lockup on the cream field, brass rule.
    printf '<tr><td align="center" style="background:%s;padding:24px 28px 18px;border-bottom:3px solid #4A5568;border-radius:10px 10px 0 0;">' "$cream"
    printf '<img src="%s" alt="%s" width="360" style="display:block;width:360px;max-width:80%%;height:auto;">' \
        "$(printf '%s' "$logo" | esc)" "$(printf '%s' "$logo_alt" | esc)"
    printf '</td></tr>'

    # Title block: grade badge -> title -> meta line.
    printf '<tr><td align="center" style="padding:22px 28px 4px;%s;">' "$f_b"
    printf '<span style="display:inline-block;%s;font-size:11px;font-weight:700;border-radius:4px;padding:3px 9px;background:%s;color:%s;border:1px solid %s;">Grade %s &middot; %s</span>' \
        "$f_h" "$gbg" "$gfg" "$bdr" "${RPT_GRADE}" "$(printf '%s' "${RPT_GRADE_WORD}" | esc)"
    printf '<p style="%s;font-weight:600;font-size:19px;color:%s;margin:10px 0 4px;">Swatter Nightly Report</p>' "$f_h" "$ink"
    printf '<p style="font-size:13px;color:%s;margin:0;">%s &middot; Last %s &middot; Mode %s</p>' \
        "$slate" "$(printf '%s' "$host" | esc)" "$(printf '%s' "${REPORT_WINDOW:-24h}" | esc)" "$(printf '%s' "$(_tc "${SWATTER_MODE:-report}")" | esc)"
    printf '</td></tr>'

    # Body.
    printf '<tr><td style="padding:14px 28px 24px;%s;font-size:15px;line-height:1.6;color:%s;">' "$f_b" "$ink"

    # Grade hero: letter tile + headline / sub / recommendation.
    printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0"><tr>'
    printf '<td width="88" style="vertical-align:top;"><div style="width:88px;height:88px;border-radius:10px;background:%s;border:1px solid %s;text-align:center;padding-top:14px;box-sizing:border-box;"><div style="%s;font-size:40px;font-weight:700;color:%s;line-height:1;">%s</div><div style="%s;font-size:11.5px;font-weight:700;color:%s;margin-top:4px;">%s</div></div></td>' \
        "$gbg" "$bdr" "$f_h" "$gfg" "${RPT_GRADE}" "$f_h" "$gfg" "$(printf '%s' "${RPT_GRADE_WORD}" | esc)"
    printf '<td style="vertical-align:top;padding-left:18px;">'
    printf '<div style="%s;font-weight:600;font-size:16px;color:%s;">%s</div><div style="font-size:13px;color:%s;margin-top:4px;line-height:1.55;">%s</div><div style="font-size:13px;color:%s;margin-top:10px;line-height:1.5;"><b>&rarr;</b> %s</div>' \
        "$f_h" "$ink" "$(printf '%s' "${RPT_GRADE_HEADLINE}" | esc)" "$slate" "$(printf '%s' "${RPT_GRADE_SUB}" | esc)" "$gfg" "$reco"
    printf '</td></tr></table>'
    printf '<p style="font-size:11.5px;color:%s;margin:12px 0 0;">A All Clear &middot; B Review &middot; C Investigate &middot; D Act Now &middot; F Fatal / Outage</p>' "$slate"

    # Bad Actors.
    local bf=""
    if (( ${RPT_FAILED:-0} > 0 )); then
        bf=" &middot; <span style=\"color:#7A5313;font-weight:600;\">${RPT_FAILED} backend-failed</span>$( [[ -n "${RPT_FAIL_CAUSE:-}" ]] && printf ' <span style="color:%s;">(top: %s &mdash; retried next scan)</span>' "$slate" "$(printf '%s' "${RPT_FAIL_CAUSE}" | esc)" )"
    fi
    printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;border-top:1px solid %s;"><tr><td style="padding-top:14px;%s">Bad Actors</td><td style="padding-top:14px;%s;font-weight:700;font-size:20px;color:%s;text-align:right;">%s</td></tr></table>' \
        "$bdr" "$h3" "$f_h" "$pine" "${RPT_ACTED:-0}"
    printf '<div style="font-size:13px;color:%s;margin-top:5px;line-height:1.55;">%s</div><div style="font-size:12px;color:%s;margin-top:6px;">%s Permanent &middot; %s Temporary &middot; %s Via Cloudflare &middot; %s At Server &middot; %s Exempted%s</div>' \
        "$ink" "$(_report_summary_actors | esc)" "$slate" "${RPT_PERM:-0}" "${RPT_TEMP:-0}" "${RPT_CF:-0}" "${RPT_DIRECT:-0}" "${RPT_EXEMPT:-0}" "$bf"

    # Origin-Lock (gated).
    if _ol_digest_should_render "${OL_HITS:-0}"; then
        printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;border-top:1px solid %s;"><tr><td style="padding-top:14px;%s">Origin-Lock <span style="font-size:12px;color:%s;font-weight:600;">&middot; Mode %s</span></td><td style="padding-top:14px;%s;font-weight:700;font-size:20px;color:%s;text-align:right;">%s</td></tr></table>' \
            "$bdr" "$h3" "$slate" "$(printf '%s' "$(_tc "${OL_MODE}")" | esc)" "$f_h" "$pine" "${OL_HITS:-0}"
        printf '<div style="font-size:13px;color:%s;margin-top:5px;line-height:1.55;">%s</div><div style="font-size:12px;color:%s;margin-top:6px;">%s IPs &middot; :443 %s &middot; :80 %s</div>' \
            "$ink" "$(_report_summary_origin | esc)" "$slate" "${OL_IPS:-0}" "${OL_P443:-0}" "${OL_P80:-0}"
        printf '<table style="width:100%%;border-collapse:collapse;font-size:12px;margin-top:8px;"><thead><tr style="color:%s;font-size:11.5px;text-align:left;"><th style="padding:4px 6px 4px 0;%s;font-weight:600;">Source IP</th><th style="padding:4px 6px;text-align:right;%s;font-weight:600;">Hits</th><th style="padding:4px 0 4px 6px;text-align:right;%s;font-weight:600;">Verdict</th></tr></thead><tbody>' \
            "$slate" "$f_h" "$f_h" "$f_h"
        printf '%s' "$OL_TOP_ROWS" | while IFS=$'\t' read -r ip n tag; do
            [[ -n "$ip" ]] || continue
            local tc="$slate"; [[ "$tag" == attacker* ]] && tc="$ember"
            printf '<tr style="border-top:1px solid %s;"><td style="padding:5px 6px 5px 0;font-family:ui-monospace,Menlo,monospace;">%s</td><td style="padding:5px 6px;text-align:right;font-variant-numeric:tabular-nums;">%s</td><td style="padding:5px 0 5px 6px;text-align:right;color:%s;font-weight:600;">%s</td></tr>' \
                "$bdr" "$(printf '%s' "$ip" | esc)" "$n" "$tc" "$(_tc "$(printf '%s' "$tag" | esc)")"
        done
        printf '</tbody></table>'
    fi

    # Server Errors (gated).
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        local efc="$pine"; (( ${ERR_FATAL:-0} > 0 )) && efc="$ember"
        printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;border-top:1px solid %s;"><tr><td style="padding-top:14px;%s">Server Errors</td><td style="padding-top:14px;%s;font-weight:700;font-size:20px;color:%s;text-align:right;">%s</td></tr></table>' \
            "$bdr" "$h3" "$f_h" "$efc" "${ERR_GENUINE:-0}"
        printf '<div style="font-size:13px;color:%s;margin-top:5px;line-height:1.55;">%s</div><div style="font-size:12px;color:%s;margin-top:6px;"><b>%s</b> Non-Fatal &middot; <b style="color:%s;">%s</b> Fatal</div>' \
            "$ink" "$(_report_summary_errors | esc)" "$slate" "${ERR_GENUINE:-0}" "$efc" "${ERR_FATAL:-0}"
    fi

    # Swarm (gated) — informational; headline = fleet IPs consumed, summary sub-line.
    if _swarm_enabled; then
        printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;border-top:1px solid %s;"><tr><td style="padding-top:14px;%s">Swarm</td><td style="padding-top:14px;%s;font-weight:700;font-size:20px;color:%s;text-align:right;">%s</td></tr></table>' \
            "$bdr" "$h3" "$f_h" "$pine" "${SWARM_FEED_N:-0}"
        printf '<div style="font-size:13px;color:%s;margin-top:5px;line-height:1.55;">%s</div>' \
            "$ink" "$(_report_summary_swarm | esc)"
        (( ${SWARM_STALE:-0} )) && printf '<div style="font-size:12px;color:%s;margin-top:6px;">Feed stale &mdash; shown for information only.</div>' "$ember"
    fi

    # Help line.
    printf '<p style="font-size:12px;color:%s;margin:18px 0 0;">On The Server: <code style="font-family:ui-monospace,Menlo,monospace;background:%s;padding:1px 5px;border-radius:4px;">swatter why &lt;ip&gt;</code> &mdash; <i>Why An IP Was Flagged</i> &middot; <code style="font-family:ui-monospace,Menlo,monospace;background:%s;padding:1px 5px;border-radius:4px;">swatter unblock &lt;ip&gt;</code> &mdash; <i>Lift A Block</i></p>' \
        "$slate" "$panel" "$panel"
    printf '</td></tr>'

    # Footer — system identity + the division-identity lockup line (permanent).
    printf '<tr><td style="background:%s;border-top:1px solid %s;padding:14px 28px 16px;%s;font-size:12px;color:%s;line-height:1.6;border-radius:0 0 10px 10px;">' \
        "$panel" "$bdr" "$f_b" "$slate"
    printf '<b style="color:%s;font-weight:600;">Swatter</b> on %s &middot; <a href="https://github.com/peaceharborco/swatter" style="color:%s;text-decoration:underline;">GitHub</a><br>' \
        "$ink" "$(printf '%s' "$host" | esc)" "$lake"
    printf '<a href="https://studios.peaceharbor.com" style="color:%s;text-decoration:underline;">Peace Harbor Studios</a> &mdash; a division of <a href="https://peaceharbor.com" style="color:%s;text-decoration:underline;">Peace Harbor Companies</a>' "$lake" "$lake"
    printf '</td></tr></table></td></tr></table></div>'
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
# Swarm plane (informational — never escalates the grade, never breaks silence).
# Reads only local swarm state; no hub call at report time. Content-only like
# swatter_originlock_section: sets SWARM_* globals + emits the stale note (if any);
# _report_summary_swarm prints the one-liner in the render step. $2/$3 optional so
# standalone callers get sane defaults.
swatter_swarm_section() {
    _swarm_enabled || return 0
    local window="${1:-${REPORT_WINDOW:-24h}}" cutoff="${2:-}" log="${3:-${LOG_DIR}/decisions.jsonl}"
    [[ -n "$cutoff" ]] || cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    local feed="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    local plog="${STATE_DIR}/swarm.publish.log" cur="${STATE_DIR}/swarm.publish.cursor"
    local now; now="$(swatter_now)"

    # Intel received: feed size + staleness. Staleness = the OLDER of swarm.txt
    # and swarm.meta.json (the sweep skips on stale META, so a fresh feed alone
    # is not "fresh"). stat_mtime is the repo's portable mtime helper.
    SWARM_FEED_N=0; [[ -s "$feed" ]] && SWARM_FEED_N="$(grep -c . "$feed" 2>/dev/null)"
    SWARM_STALE=0
    local f m oldest=0
    for f in "$feed" "$meta"; do
        [[ -s "$f" ]] || continue
        m="$(stat_mtime "$f" 2>/dev/null || echo "$now")"
        (( m < now )) || continue          # future mtime (test stubs a past now) => treat as fresh
        (( now - m > oldest )) && oldest=$(( now - m ))
    done
    (( oldest > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )) && SWARM_STALE=1

    # The two JSON-derived counts require jq. Without it, flag them unavailable
    # rather than silently showing 0 (feed size + staleness still render).
    SWARM_PREBLOCKED=0 SWARM_CONTRIB=0 SWARM_COUNTS_OK=1
    if [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
        # Corroborated pre-blocks in-window. Match evidence.swarm (stamped on
        # EVERY dispatched row), NOT .reason (prefixed on novhost/failed paths).
        [[ -s "$log" ]] && SWARM_PREBLOCKED="$(jq -c "select(.ts >= ${cutoff} and (.evidence.swarm == true))" "$log" 2>/dev/null | grep -c . )"
        # Contribution made in-window (sum of counts from the publish audit).
        [[ -s "$plog" ]] && SWARM_CONTRIB="$(jq -s "map(select(.ts >= ${cutoff}))|map(.count)|add // 0" "$plog" 2>/dev/null)"
        [[ -n "$SWARM_CONTRIB" ]] || SWARM_CONTRIB=0   # empty jq output => 0
    else
        SWARM_COUNTS_OK=0
    fi
    SWARM_LAST_PUB="none"; [[ -s "$cur" ]] && SWARM_LAST_PUB="$(tr -d '[:space:]' < "$cur")"

    # Body: an amber note only when stale (information only — grade is unaffected).
    (( ${SWARM_STALE:-0} )) && echo "  NOTE: feed stale (> ${SWARM_MAX_AGE_DAYS:-3}d) — shown for information only; the report grade is unaffected."
}

_report_summary_swarm() {
    if (( ${SWARM_COUNTS_OK:-1} )); then
        printf 'Consuming %s fleet IP(s) · %s pre-blocked (corroborated) · %s contributed this window' \
            "${SWARM_FEED_N:-0}" "${SWARM_PREBLOCKED:-0}" "${SWARM_CONTRIB:-0}"
    else
        printf 'Consuming %s fleet IP(s) · pre-block/contribution counts unavailable (jq not installed)' \
            "${SWARM_FEED_N:-0}"
    fi
    # Last contribution, when we have ever published — portable epoch->date.
    if [[ "${SWARM_LAST_PUB:-none}" != "none" ]]; then
        local when; when="$(date -u -d "@${SWARM_LAST_PUB}" '+%Y-%m-%d' 2>/dev/null || date -u -r "${SWARM_LAST_PUB}" '+%Y-%m-%d' 2>/dev/null)"
        [[ -n "$when" ]] && printf ' · last contributed %s' "$when"
    fi
    printf '.\n'
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
