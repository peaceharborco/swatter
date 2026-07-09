#!/usr/bin/env bash
# lib/errors.sh — server error-log triage for the nightly digest.
#
# Swatter doesn't just swat bad actors; it can also surface genuine server
# breakage. This module scans the last <window> of the server's error logs,
# normalizes them to one format, drops known high-volume noise, groups what
# remains by signature, and returns a compact "Server errors" section that the
# nightly report folds in alongside the abuse digest.
#
# Two sources of truth:
#   - ERROR_DIGEST_LOG set & readable  -> read that pre-consolidated log
#     (lines: "[YYYY-MM-DD HH:MM:SS] [LEVEL] [source/id] message", UTC). This
#     reuses an existing aggregator (e.g. an hourly error-log feed).
#   - otherwise -> aggregate live from raw Apache/PHP-FPM/MySQL/per-site logs.
#
# No persistent state: a once-nightly digest just scans the window directly.

# Emit consolidated "[ts] [LEVEL] [src] msg" lines within the window to stdout.
_errors_consolidated() {
    local cutoff="$1"

    if [[ -n "${ERROR_DIGEST_LOG}" && -r "${ERROR_DIGEST_LOG}" ]]; then
        # Pre-consolidated UTC log: fixed-width ISO timestamp -> lexical compare.
        local cut_human; cut_human="$(date -u -d "@${cutoff}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -r "${cutoff}" '+%Y-%m-%d %H:%M:%S')"
        awk -v c="$cut_human" '/^\[[0-9-]{10} [0-9:]{8}\]/ { if (substr($0,2,19) >= c) print }' "${ERROR_DIGEST_LOG}"
        return 0
    fi

    # Live aggregation from raw sources.
    _errors_collect_apache "$cutoff"
    _errors_collect_php    "$cutoff"
    _errors_collect_fpm    "$cutoff"
    _errors_collect_mysql  "$cutoff"
}

# Shared awk month map + emitter, prepended to each collector.
_ERR_AWKLIB='
BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",_mn," "); for(_i=1;_i<=12;_i++) mon[_mn[_i]]=_i }
function emit(epoch,level,src,msg){ gsub(/[ \t\r\n]+/," ",msg); sub(/^ /,"",msg); sub(/ $/,"",msg);
  printf "[%s] [%s] [%s] %s\n", strftime("%Y-%m-%d %H:%M:%S",epoch,1), level, src, msg }
'

# Apache global error_log: [Mon Jun 01 20:34:05.368594 2026] [mod:sev] [pid] msg
_errors_collect_apache() {
    local cutoff="$1" f="${ERROR_LOG}"
    [[ -n "$f" && -s "$f" ]] || return 0
    # Apache stamps its error_log in the host's local time; mktime must interpret
    # the broken-down fields in that same zone. common.sh exports TZ=UTC process-
    # wide, so a bare gawk would STILL read the stamps as UTC — unset TZ for this
    # invocation only (subshell-scoped) so mktime uses /etc/localtime. emit()
    # normalizes to UTC on output.
    ( unset TZ; gawk -v cutoff="$cutoff" "${_ERR_AWKLIB}"'
        {
            if (substr($0,1,1) != "[") next
            c=index($0,"]"); if(c==0) next
            tstok=substr($0,2,c-2); rest=substr($0,c+1); sub(/^[ \t]+/,"",rest)
            if (substr(rest,1,1)!="[") next
            c2=index(rest,"]"); if(c2==0) next
            tag=substr(rest,2,c2-2); after=substr(rest,c2+1)
            colon=index(tag,":"); if(colon==0) next
            module=substr(tag,1,colon-1); sev=substr(tag,colon+1)
            if (module=="security2") next
            if (sev=="error") level="ERROR"
            else if (sev=="crit"||sev=="alert"||sev=="emerg") level="FATAL"
            else if (sev=="warn") level="WARN"
            else next
            host=""; hi=index($0,"[hostname \"")
            if(hi>0){ t=substr($0,hi+11); q=index(t,"\""); if(q>0) host=substr(t,1,q-1) }
            np=split(tstok,p," "); if(np<5) next
            m=mon[p[2]]; if(m=="") next
            sub(/\.[0-9]+$/,"",p[4]); split(p[4],tt,":")
            epoch=mktime(p[5]" "m" "p[3]" "tt[1]" "tt[2]" "tt[3]" 0")
            if(epoch<0||epoch<cutoff) next
            srcid=(host=="")?"apache":"apache/" host
            emit(epoch,level,srcid,after)
        }' "$f" ) 2>/dev/null
}

# Per-site PHP error_log: [01-Jun-2026 20:01:10 UTC] PHP Fatal error: ...
_errors_collect_php() {
    local cutoff="$1" f acct
    [[ -n "${ERROR_PHP_HOME_GLOB}" ]] || return 0
    while IFS= read -r f; do
        [[ -s "$f" ]] || continue
        acct="${f#"${ERROR_PHP_HOME_GLOB}"/}"; acct="${acct%%/*}"; [[ -n "$acct" ]] || acct="unknown"
        TZ=UTC gawk -v cutoff="$cutoff" -v srcid="php/${acct}" "${_ERR_AWKLIB}"'
            {
                if(substr($0,1,1)!="[") next
                c=index($0,"]"); if(c==0) next
                ts=substr($0,2,c-2); sub(/ +UTC$/,"",ts); rest=substr($0,c+1); sub(/^[ \t]+/,"",rest)
                if(rest ~ /^PHP (Fatal|Parse) error/) level="FATAL"
                else if(rest ~ /^PHP (Warning|Deprecated|Notice)/) level="WARN"
                else next
                n=split(ts,a,/[-: ]/); if(n<6) next
                m=mon[a[2]]; if(m=="") next
                epoch=mktime(a[3]" "m" "a[1]" "a[4]" "a[5]" "a[6]" 0")
                if(epoch<0||epoch<cutoff) next
                emit(epoch,level,srcid,rest)
            }' "$f" 2>/dev/null
    done < <(find "${ERROR_PHP_HOME_GLOB}" -maxdepth 5 -name error_log -type f -not -path '*/virtfs/*' 2>/dev/null)
}

# PHP-FPM: [01-Jun-2026 20:27:14] WARNING: [pool name] ...
_errors_collect_fpm() {
    local cutoff="$1" f phpver
    for f in ${ERROR_FPM_GLOB}; do
        [[ -s "$f" ]] || continue
        phpver="$(printf '%s' "$f" | sed -n 's#.*/ea-php\([0-9][0-9]*\)/.*#php\1#p')"; [[ -n "$phpver" ]] || phpver="php"
        # PHP-FPM stamps its log in the host's local time (no zone suffix).
        # unset TZ (subshell-scoped) so mktime uses /etc/localtime — a bare gawk
        # would inherit the process-wide TZ=UTC from common.sh and mis-window.
        ( unset TZ; gawk -v cutoff="$cutoff" -v phpver="$phpver" "${_ERR_AWKLIB}"'
            {
                if(substr($0,1,1)!="[") next
                c=index($0,"]"); if(c==0) next
                ts=substr($0,2,c-2); rest=substr($0,c+1); sub(/^[ \t]+/,"",rest)
                if(rest ~ /^ERROR:/) level="ERROR"
                else if(rest ~ /^WARNING:/) level="WARN"
                else next
                sub(/^[A-Z]+:[ \t]*/,"",rest)
                pool=""; if(rest ~ /^\[pool /){ pc=index(rest,"]"); if(pc>0){ pool=substr(rest,7,pc-7); rest=substr(rest,pc+1); sub(/^[ \t]+/,"",rest) } }
                n=split(ts,a,/[-: ]/); if(n<6) next
                m=mon[a[2]]; if(m=="") next
                epoch=mktime(a[3]" "m" "a[1]" "a[4]" "a[5]" "a[6]" 0")
                if(epoch<0||epoch<cutoff) next
                srcid=(pool=="")?"fpm/" phpver : "fpm/" phpver ":" pool
                emit(epoch,level,srcid,rest)
            }' "$f" ) 2>/dev/null
    done
}

# MySQL/MariaDB: 2026-06-01 19:58:50 221659 [Warning] ...
_errors_collect_mysql() {
    local cutoff="$1" f
    for f in ${ERROR_MYSQL_GLOB}; do
        [[ -s "$f" ]] || continue
        # MariaDB stamps its .err in the host's local time. unset TZ (subshell-
        # scoped) so mktime uses /etc/localtime instead of the process-wide
        # TZ=UTC from common.sh. emit() re-normalizes to UTC.
        ( unset TZ; gawk -v cutoff="$cutoff" "${_ERR_AWKLIB}"'
            {
                if($0 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] /) next
                ts=substr($0,1,19); rest=substr($0,20)
                if(index(rest,"[ERROR]")) level="ERROR"
                else if(index(rest,"[Warning]")) level="WARN"
                else next
                split(ts,a,/[-: ]/)
                epoch=mktime(a[1]" "a[2]" "a[3]" "a[4]" "a[5]" "a[6]" 0")
                if(epoch<0||epoch<cutoff) next
                emit(epoch,level,"mysql",rest)
            }' "$f" ) 2>/dev/null
    done
}

# The known-noise filter is a user-tunable extended regex fed to `grep -Ev`.
# An empty value makes `grep -Ev ""` match (and thus invert away) every line,
# and a malformed regex makes grep exit 2 — either way the genuine-error count
# silently collapses to zero and real breakage is hidden. Validate once at load:
# reject empty and probe-compile the pattern, falling back to a safe default.
_ERR_NOISE_DEFAULT='prefetch request body failed|error reading status line from remote server|invalid URI path|Invalid method in request|no compatible SSL setup for policy|client denied by server configuration|Error dispatching request to'
_errors_validate_noise() {
    # Empty OR whitespace-only: `grep -Ev ""` (or an all-space pattern) inverts
    # away every line, zeroing the genuine-error count. Treat both as empty.
    if [[ -z "${ERROR_NOISE//[[:space:]]/}" ]]; then
        log_warn "errors: ERROR_NOISE is empty; using built-in noise default"
        ERROR_NOISE="$_ERR_NOISE_DEFAULT"
        return
    fi
    local rc=0
    printf '' | grep -Eq "${ERROR_NOISE}" 2>/dev/null || rc=$?
    if (( rc == 2 )); then
        log_warn "errors: ERROR_NOISE is not a valid regex; using built-in noise default"
        ERROR_NOISE="$_ERR_NOISE_DEFAULT"
    fi
}
_errors_validate_noise

# Build the "Server errors" digest section on stdout, and set globals:
#   ERR_TOTAL ERR_FATAL ERR_GENUINE ERR_NOISE
swatter_errors_section() {
    local window="$1" cutoff
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    ERR_TOTAL=0 ERR_FATAL=0 ERR_GENUINE=0 ERR_NOISE=0

    local stream; stream="$(_errors_consolidated "$cutoff")"
    [[ -n "$stream" ]] || { echo "Server errors: none in the last ${window}."; return 0; }

    # FATAL/ERROR only (WARN is de-emphasized noise for a nightly digest).
    local win genuine fatal
    win="$(printf '%s\n' "$stream" | grep -E '\] \[(FATAL|ERROR)\]' || true)"
    ERR_TOTAL=$(printf '%s\n' "$win" | grep -c . || true)
    # grep -Ev exit codes: 0 = kept lines, 1 = no lines kept (all noise),
    # 2 = regex error. Only 2 is a failure; treat it as "filter nothing" so a
    # broken pattern can never zero out (hide) genuine errors.
    local grc=0
    genuine="$(printf '%s\n' "$win" | grep -Ev "${ERROR_NOISE}")" || grc=$?
    if (( grc == 2 )); then
        log_warn "errors: ERROR_NOISE regex failed at filter time; counting all as genuine"
        genuine="$win"
    fi
    ERR_GENUINE=$(printf '%s\n' "$genuine" | grep -c . || true)
    fatal="$(printf '%s\n' "$win" | grep -E '\] \[FATAL\]' || true)"
    ERR_FATAL=$(printf '%s\n' "$fatal" | grep -c . || true)
    ERR_NOISE=$(( ERR_TOTAL - ERR_GENUINE ))

    {
        echo "Non-fatal: ${ERR_GENUINE}  ·  Fatal: ${ERR_FATAL}  ·  filtered as known noise: ${ERR_NOISE}"
        echo
        if (( ERR_GENUINE > 0 )); then
            echo "Issue signatures (count x normalized error):"
            # Strip volatile bits so identical errors collapse.
            printf '%s\n' "$genuine" | sed -E '
                s/^\[[0-9-]{10} [0-9:]{8}\] //;
                s/\[pid [0-9]+(:tid [0-9]+)?\]//g;
                s/\[client [0-9a-f.:]+\]//g;
                s/\[remote [0-9a-f.:]+\]//g;
                s/from [0-9.]+ ?(\(\))?//g;
                s#/[a-f0-9]{40}\.sock:[0-9]+#/<sock>#g;
                s/\([a-z0-9.-]+\.[a-z]{2,}\)//g;
                s/, referer: \S+//g;
                s/[?&](password|passwd|key|token|secret|auth)=[^& ]+//gI;
                s/=[A-Za-z0-9/+=]{24,}//g;
                s/[[:space:]]+/ /g;
              ' | sort | uniq -c | sort -rn | head -25 \
              | awk '{n=$1; $1=""; sub(/^ /,""); printf "  %4d x  %s\n", n, $0}'
            echo
        fi
        if (( ERR_FATAL > 0 )); then
            echo "FATAL entries (verbatim):"
            printf '%s\n' "$fatal" | head -25 | sed 's/^/  /'
            echo
        fi
    }
}
