#!/usr/bin/env bash
# lib/mail_campaigns.sh — SMTP AUTH campaign digest (report-time, visibility only).
#
# Parses Exim `dovecot_login authenticator failed` over the digest window,
# groups by verbatim set_id, and emits a "Mail Campaigns" section. Never
# blocks, never writes decisions.jsonl, never talks to CSF/CF/AbuseIPDB.

_MAILCAMP_DEFAULT_PATH="/var/log/exim_mainlog"

_mailcamp_path() {
    if [[ -n "${EXIM_MAINLOG}" ]]; then printf '%s' "${EXIM_MAINLOG}"
    else printf '%s' "$_MAILCAMP_DEFAULT_PATH"; fi
}

_mailcamp_explicit() { [[ -n "${EXIM_MAINLOG}" ]]; }

_mailcamp_should_run() {
    case "${MAIL_CAMPAIGN_DIGEST:-auto}" in
        off) return 1 ;;
        on)  return 0 ;;
        *)
            _mailcamp_explicit && return 0
            [[ -e "$(_mailcamp_path)" ]] && return 0
            return 1
            ;;
    esac
}

_mailcamp_emit_unreadable() {
    local why="$1"
    MAILCAMP_OK=0
    MAILCAMP_N=0
    MAILCAMP_FAILS=0
    MAILCAMP_IPS=0
    printf 'UNREADABLE: cannot read %s (%s)\n' "$(_mailcamp_path)" "$why"
}

# Select the live log (always, if we are running) plus rotations whose mtime
# is >= cutoff. Uses stat_mtime from common.sh (GNU/BSD).
_mailcamp_select_files() {
    local path="$1" cutoff="$2"
    local dir base f mt
    dir="$(dirname -- "$path")"
    base="$(basename -- "$path")"
    printf '%s\n' "$path"
    for f in "$dir"/"$base"-* "$dir"/"$base".*; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$path" ]] && continue
        mt="$(stat_mtime "$f")" || continue
        [[ "$mt" =~ ^[0-9]+$ ]] || continue
        (( mt >= cutoff )) || continue
        printf '%s\n' "$f"
    done
}

_mailcamp_parse() {
    local cutoff="$1"
    # Connecting IP = [addr]:port: immediately before 535. set_id is after 535,
    # so a forged [ip]:port inside set_id cannot win. HELO parentheticals have
    # no :port: 535. LC_ALL=C; clear TZ so common.sh's TZ=UTC does not shift
    # host-local Exim stamps (v2.15.0 class).
    ( unset TZ; LC_ALL=C gawk -v cutoff="$cutoff" '
        {
            if (substr($0,5,1) != "-" || substr($0,8,1) != "-" || substr($0,11,1) != " ") next
            ts = substr($0, 1, 19)
            Y = substr(ts,1,4)+0; Mo = substr(ts,6,2)+0; D = substr(ts,9,2)+0
            h = substr(ts,12,2)+0; mi = substr(ts,15,2)+0; s = substr(ts,18,2)+0
            ep = mktime(sprintf("%04d %02d %02d %02d %02d %02d", Y, Mo, D, h, mi, s))
            if (ep < cutoff) next
            if (index($0, "dovecot_login authenticator failed") == 0) next
            p535 = index($0, ": 535")
            if (p535 == 0) p535 = index($0, ":535")
            if (p535 == 0) next
            head = substr($0, 1, p535)
            ip = ""
            rest = head
            while (match(rest, /\[[0-9A-Fa-f:.]+\]:[0-9]+:/)) {
                ip = substr(rest, RSTART, RLENGTH)
                rest = substr(rest, RSTART + RLENGTH)
            }
            if (ip == "") next
            sub(/^\[/, "", ip)
            sub(/\]:[0-9]+:$/, "", ip)
            tail = substr($0, p535)
            if (match(tail, /\(set_id=/) == 0) next
            id = substr(tail, RSTART + 8)
            sub(/\).*$/, "", id)
            if (id == "") next
            print ip "\t" id
        }
    ' )
}

swatter_mail_campaigns_section() {
    local window="$1" cutoff path
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    path="$(_mailcamp_path)"
    MAILCAMP_OK=1 MAILCAMP_N=0 MAILCAMP_FAILS=0 MAILCAMP_IPS=0

    local files f
    files="$(_mailcamp_select_files "$path" "$cutoff")"
    local parsed; parsed="$(mktemp "${TMPDIR:-/tmp}/swatter-mc.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -f '$parsed'" RETURN

    local any=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if [[ "$f" == "$path" && ! -e "$f" ]]; then
            _mailcamp_emit_unreadable "missing"
            return 0
        fi
        if [[ ! -r "$f" ]]; then
            _mailcamp_emit_unreadable "unreadable: ${f}"
            return 0
        fi
        any=1
        if [[ "$f" == *.gz ]]; then
            gzip -dc -- "$f" 2>/dev/null | _mailcamp_parse "$cutoff" >> "$parsed" || {
                _mailcamp_emit_unreadable "gzip failed: ${f}"; return 0; }
        else
            _mailcamp_parse "$cutoff" < "$f" >> "$parsed"
        fi
    done <<< "$files"

    if (( ! any )) && [[ ! -e "$path" ]]; then
        _mailcamp_emit_unreadable "missing"
        return 0
    fi

    local min="${MAIL_CAMPAIGN_MIN_IPS:-5}" cap="${MAIL_CAMPAIGN_LIST_CAP:-20}"
    local summary
    # Identity is everything after the first tab (set_id may itself contain tabs).
    summary="$(LC_ALL=C gawk -F '\t' -v min="$min" -v cap="$cap" '
        NF >= 2 {
            ip=$1
            id = substr($0, index($0, "\t") + 1)
            fails[id]++; ipn[id SUBSEP ip]++; seenip[ip]=1; n++
        }
        END {
            print n+0, length(seenip)+0
            for (id in fails) {
                d = 0; ones = 0
                for (k in ipn) {
                    split(k, a, SUBSEP)
                    if (a[1] != id) continue
                    d++
                    if (ipn[k] == 1) ones++
                }
                if (d >= min) printf "%d\t%d\t%d\t%s\n", d, fails[id], ones, id
            }
        }
    ' "$parsed")"

    local totals campaigns
    totals="$(printf '%s\n' "$summary" | sed -n '1p')"
    MAILCAMP_FAILS="${totals%% *}"
    MAILCAMP_IPS="${totals#* }"
    [[ "$MAILCAMP_FAILS" =~ ^[0-9]+$ ]] || MAILCAMP_FAILS=0
    [[ "$MAILCAMP_IPS" =~ ^[0-9]+$ ]] || MAILCAMP_IPS=0

    campaigns="$(printf '%s\n' "$summary" | sed '1d' | sort -t$'\t' -k1,1nr -k2,2nr)"
    MAILCAMP_N=0
    [[ -n "$campaigns" ]] && MAILCAMP_N="$(printf '%s\n' "$campaigns" | grep -c . || true)"

    if (( MAILCAMP_N == 0 )); then
        printf 'No SMTP AUTH campaigns this window.\n'
        return 0
    fi

    printf 'Mail Campaigns\n'
    echo "--------------"
    printf '  %s campaigns  ·  %s fails  ·  %s distinct IPs\n\n' "$MAILCAMP_N" "$MAILCAMP_FAILS" "$MAILCAMP_IPS"
    printf '  %-40s %5s %6s %8s\n' "mailbox" "ips" "fails" "1-per-IP"
    local shown=0 d fails ones id pct
    while IFS=$'\t' read -r d fails ones id; do
        [[ -n "$id" ]] || continue
        if (( shown >= cap )); then
            printf '  + %s more campaigns\n' "$(( MAILCAMP_N - shown ))"
            break
        fi
        pct=0
        (( fails > 0 )) && pct=$(( (ones * 100 + fails/2) / fails ))
        printf '  %-40s %5s %6s %7s%%\n' "$id" "$d" "$fails" "$pct"
        shown=$(( shown + 1 ))
    done <<< "$campaigns"
}
