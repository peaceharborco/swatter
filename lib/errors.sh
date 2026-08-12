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
        # Collapse runs of whitespace in the MESSAGE exactly as the live emit does
        # (see emit() in _ERR_AWKLIB). Raw PHP writes "PHP Fatal error:" with two
        # spaces, so without this the same error yields a different signature on
        # each feed: it matches no pattern here, and depth/breadth counting cannot
        # collapse the two forms together.
        local cut_human; cut_human="$(date -u -d "@${cutoff}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -r "${cutoff}" '+%Y-%m-%d %H:%M:%S')"
        awk -v c="$cut_human" '/^\[[0-9-]{10} [0-9:]{8}\]/ {
                if (substr($0,2,19) < c) next
                head=substr($0,1,21); msg=substr($0,22)
                gsub(/[ \t\r]+/," ",msg); sub(/ $/,"",msg)
                print head msg
            }' "${ERROR_DIGEST_LOG}"
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

# Fatal classifier: a fatal whose message matches ERROR_FATAL_SCANNER, whose
# signature repeats fewer than ERROR_FATAL_SCANNER_REPEATS times in the window
# and which spans fewer than ERROR_FATAL_FANOUT_ACCOUNTS accounts is
# scanner-induced — an isolated one-off crash — not an outage. Real breakage of
# the same shape (a broken plugin, a half-deployed theme) repeats on every page
# view, or lands on every account at once, and crosses one of the thresholds.
# This is a match-POSITIVE classifier, so the failure modes invert relative to
# ERROR_NOISE: an empty pattern would match every line and classify every fatal
# as scanner-induced (a real outage graded green). Empty or invalid falls back
# to the built-in default; to disable the classifier entirely, set
# ERROR_FATAL_SCANNER_REPEATS to 0 or 1 — no signature count is below either, so
# every matching fatal then counts as genuine. Both are kept as the RED-safe
# direction and are never clamped upward. Note REPEATS governs DEPTH only;
# ERROR_FATAL_FANOUT_ACCOUNTS governs breadth across accounts.
_ERR_FATAL_SCANNER_DEFAULT='PHP Fatal error: Uncaught Error: (Call to undefined function|Undefined constant)'
# Veto on top of the classifier: a fatal whose message matches
# ERROR_FATAL_SCANNER_EXCLUDE can never be scanner-induced, however few times it
# repeats. The classifier's whole premise is a bot executing a PHP file over
# HTTP, so a frame naming a known local CLI entrypoint (wp-cli.phar under
# /usr/local/bin) disproves it outright — that fatal came from tooling on the box, and
# filing it as bot noise both hides our own breakage and pads the scanner count.
# Same failure modes as ERROR_FATAL_SCANNER, and handled the same way: an empty
# pattern would match every line and veto every classification, so empty or
# invalid falls back to the built-in default. To disable the veto, set it to
# '^$' — a fatal signature is never empty, so it can never match.
#
# Deliberately NOT a bare 'phar://': the veto's claim is "this ran locally", and
# only a known local entrypoint proves that. A bot CAN induce a phar:// frame
# (phar deserialization probes), so such a fatal is left to the classifier's own
# terms rather than pulled out of the scanner class by a path prefix — under the
# default knobs a one-off lands in the SCANNER count, which is where an
# unattributed remote fatal belongs. Pinned by `veto-bare-phar` in
# test/errors_test.sh. (The veto only ever moves fatals toward genuine; it can
# never hide one.)
#
# Fallback direction is deliberate: empty or invalid falls back to the built-in
# default (an active veto), NOT to '^$'. At apply time an empty pattern is the
# RED-heaviest outcome — an empty regex matches every line, so `!~ ex` is false
# for all of them and every fatal counts genuine — while '^$' is the lightest.
# The shipping default is the middle and the predictable one: a typo'd veto keeps
# shipping behaviour instead of silently swinging the digest to either extreme.
_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT='phar:///usr/local/bin/|/usr/local/bin/wp-cli|wp-cli\.phar'

# Both patterns are validated with grep -E AND with awk, because awk is what
# actually applies them (`sigof[i] ~ re`). The two dialects disagree: patterns
# like '$^' and '(?i)x' are grep-legal yet rejected by some awks, and an awk
# regex syntax error aborts the whole classification, emptying `marked` — the
# caller then counts every fatal as genuine. That direction is RED-safe, but it
# silently voids the scanner class, so catch it here at config time instead.
# Which patterns fall in that gap is a property of the local awk — not a fixed
# list, and not even stable across versions of one awk: BSD awk (macOS) rejects
# both of those, gawk 5.4 rejects '(?i)x' but accepts '$^', and gawk 5.2 (what
# CI runs) accepts both. That is fine — the probe below runs the SAME awk that
# will apply the pattern, so it is correct on every host without knowing the
# dialect. (Do not re-pin a hardcoded "always illegal" list in the tests;
# test/errors_test.sh asserts the dialect-agnostic invariant instead.)
# The awk probe passes the pattern through ENVIRON, exactly as the classifier
# does — `-v` would escape-process operator backslashes and validate a different
# string than the one applied.
_errors_regex_ok() {
    local rc=0
    printf '' | grep -Eq "$1" 2>/dev/null || rc=$?
    (( rc == 2 )) && return 1
    SWATTER_RE_CHK="$1" awk 'BEGIN { r = ("x" ~ ENVIRON["SWATTER_RE_CHK"]) }' </dev/null 2>/dev/null
}
_errors_validate_fatal_scanner() {
    if [[ -z "${ERROR_FATAL_SCANNER//[[:space:]]/}" ]]; then
        log_warn "errors: ERROR_FATAL_SCANNER is empty; using built-in default (set ERROR_FATAL_SCANNER_REPEATS=1 to disable the classifier)"
        ERROR_FATAL_SCANNER="$_ERR_FATAL_SCANNER_DEFAULT"
    elif ! _errors_regex_ok "$ERROR_FATAL_SCANNER"; then
        log_warn "errors: ERROR_FATAL_SCANNER is not a valid regex in both grep -E and awk; using built-in default"
        ERROR_FATAL_SCANNER="$_ERR_FATAL_SCANNER_DEFAULT"
    fi
    if [[ -z "${ERROR_FATAL_SCANNER_EXCLUDE//[[:space:]]/}" ]]; then
        log_warn "errors: ERROR_FATAL_SCANNER_EXCLUDE is empty; using built-in default (set it to '^\$' to disable the veto)"
        ERROR_FATAL_SCANNER_EXCLUDE="$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
    elif ! _errors_regex_ok "$ERROR_FATAL_SCANNER_EXCLUDE"; then
        log_warn "errors: ERROR_FATAL_SCANNER_EXCLUDE is not a valid regex in both grep -E and awk; using built-in default"
        ERROR_FATAL_SCANNER_EXCLUDE="$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
    fi
    # 0 and 1 both disable the classifier (no signature count is < them), which
    # is the RED-safe direction — never clamp them upward. The width bound is not
    # cosmetic: a value too large to ever be reached reads as "configured" but
    # behaves as "gate off", silently, in the direction that hides an outage. Six
    # digits is far past any real window on one host, so anything wider is a typo
    # or a paste accident and falls back to the default WITH a warning.
    case "${ERROR_FATAL_SCANNER_REPEATS:-}" in
        *[!0-9]*|''|??????*)
            log_warn "errors: ERROR_FATAL_SCANNER_REPEATS='${ERROR_FATAL_SCANNER_REPEATS:-}' is not an integer of 0-99999; using 3"
            ERROR_FATAL_SCANNER_REPEATS=3 ;;
    esac
    # Same discipline as REPEATS: a non-negative integer or the built-in default,
    # never clamped upward. Fan-out is always >= 1, so a threshold of 0 would make
    # `fan < fanmin` false for every line and void the WHOLE scanner class rather
    # than just this gate — the apply site special-cases 0 as "breadth gate off"
    # instead. 1 is legal and means every matching fatal counts genuine.
    # Same width bound as REPEATS, and it bites harder here: a 25-digit threshold
    # is never reached by any account count, so the breadth gate is off and every
    # cross-account cluster grades green again — the exact defect this gate exists
    # to close, re-opened by a config typo that today passes validation silently.
    case "${ERROR_FATAL_FANOUT_ACCOUNTS:-}" in
        *[!0-9]*|''|??????*)
            log_warn "errors: ERROR_FATAL_FANOUT_ACCOUNTS='${ERROR_FATAL_FANOUT_ACCOUNTS:-}' is not an integer of 0-99999; using 4"
            ERROR_FATAL_FANOUT_ACCOUNTS=4 ;;
    esac
    # Same discipline, and here it is not merely tidiness. This value lands in an
    # arithmetic context, where bash RE-RESOLVES a non-numeric string as a
    # variable name: under the `set -u` that bin/swatter runs with, a typo like
    # ERROR_CORROBORATE_MAX_SPAN=1h aborts the whole report — no digest body, no
    # grade, no RED SMS — on precisely the night there are genuine fatals to
    # corroborate. A crafted value can also execute a command through an array
    # subscript. Digits only, always.
    case "${ERROR_CORROBORATE_MAX_SPAN:-}" in
        *[!0-9]*|''|???????*)
            log_warn "errors: ERROR_CORROBORATE_MAX_SPAN='${ERROR_CORROBORATE_MAX_SPAN:-}' is not an integer of 0-999999; using 3600"
            ERROR_CORROBORATE_MAX_SPAN=3600 ;;
    esac
    # An unrecognized boolean disables corroboration silently, which looks exactly
    # like a quiet night. Say so rather than fail mute.
    case "${ERROR_CORROBORATE_ENABLE:-true}" in
        true|false) ;;
        *) log_warn "errors: ERROR_CORROBORATE_ENABLE='${ERROR_CORROBORATE_ENABLE}' is not true|false; treating as false (no 🔥, no evidence line)"
           ERROR_CORROBORATE_ENABLE=false ;;
    esac
}
_errors_validate_fatal_scanner

# "YYYY-MM-DD HH:MM:SS" (UTC, the digest-feed stamp) -> epoch. GNU date and BSD
# date parse it with different flags and the suite runs on both; a failure prints
# nothing, which the caller treats as "no window".
_errors_epoch_of() {
    local h="$1"
    date -u -d "$h" '+%s' 2>/dev/null \
        || date -u -j -f '%Y-%m-%d %H:%M:%S' "$h" '+%s' 2>/dev/null \
        || true
}

# Ask the affected accounts' own access logs who received the failures, and turn
# the answer into ERR_CORR_VERDICT + a one-line operator note. Sets:
#   visitor — an outside client with a real user agent got a failure. The only
#             verdict that escalates the status.
#   self    — every failure went to the server talking to itself (wp-cron, a
#             loopback REST call). Broken, but nobody was waiting.
#   scanner — every failure went to a bot.
#   none    — the logs covered the window and held no failure at all.
#   wide    — the signature recurred across a span too long to correlate against.
#             Declining is the honest answer: measured on the reference host,
#             clusters spanning 6-19h collect a few unrelated failures from any
#             ordinary day, and calling that corroboration is just noise wearing
#             a verdict.
#   ""      — could not look (no window, no readable log covering it, disabled).
# Never downgrades anything. The note states what was observed, never a cause.
_errors_corroborate() {
    ERR_CORR_VERDICT="" ERR_CORR_NOTE=""
    [[ "${ERROR_CORROBORATE_ENABLE:-true}" == "true" ]] || return 0
    declare -F swatter_corroborate >/dev/null || return 0
    (( ERR_FATAL_GENUINE > 0 )) || return 0
    (( ERR_CORR_AFTER > 0 )) || return 0
    [[ -n "$ERR_CORR_ACCTS" ]] || return 0

    local span=$(( ERR_CORR_BEFORE - ERR_CORR_AFTER ))
    local cap="${ERROR_CORROBORATE_MAX_SPAN:-3600}"
    if (( span > cap )); then
        ERR_CORR_VERDICT="wide"
        ERR_CORR_NOTE="(this signature recurred over $(( span / 3600 ))h — too long a span to tell a shared failure from ordinary daily errors, so no correlation was attempted.)"
        return 0
    fi

    # The server's own addresses are what make a loopback request recognizable.
    # Derived once here rather than configured, so a host that changes IP does
    # not silently start reading its own wp-cron traffic as customers.
    [[ -n "${SERVER_IPS:-}" ]] || SERVER_IPS="$(hostname -I 2>/dev/null || true)"
    # The scanner arm reads swatter's OWN ledger — it already knows who the bots
    # are. Via a file, never a command line: the ledger runs to thousands of
    # addresses and macOS caps argv far below Linux.
    local _banf=""
    if [[ -z "${CORR_BANNED_FILE:-}" ]] && command -v sqlite3 >/dev/null 2>&1 \
       && [[ -r "${STATE_DIR:-/var/lib/swatter}/swatter.db" ]]; then
        _banf="$(mktemp "${TMPDIR:-/tmp}/swatter-corrban.XXXXXX" 2>/dev/null)" || _banf=""
        if [[ -n "$_banf" ]]; then
            sqlite3 "${STATE_DIR:-/var/lib/swatter}/swatter.db" \
                'select ip from offenders;' > "$_banf" 2>/dev/null || : > "$_banf"
            CORR_BANNED_FILE="$_banf"
        fi
    fi

    swatter_corroborate "$ERR_CORR_AFTER" "$ERR_CORR_BEFORE" "$ERR_CORR_ACCTS" || {
        ERR_CORR_VERDICT=""; [[ -n "$_banf" ]] && { rm -f "$_banf"; CORR_BANNED_FILE=""; }; return 0; }
    [[ -n "$_banf" ]] && { rm -f "$_banf"; CORR_BANNED_FILE=""; }
    ERR_CORR_VERDICT="$CORR_VERDICT"
    # Always state the actual split. An earlier version summarised the winning
    # arm as "all N", which was wrong the first time it met real data: a cluster
    # of 4 loopback failures plus 1 bot probe reported "all 5 went to the server
    # itself". Counts cannot be wrong the way a summary can.
    local n="${CORR_5XX_TOTAL:-0}"
    local split="${n} served failure(s) here: ${CORR_5XX_VISITOR:-0} to outside clients, ${CORR_5XX_SELF:-0} to the server itself (wp-cron or a loopback call), ${CORR_5XX_SCANNER:-0} to known bots, ${CORR_5XX_NOUA:-0} with no user agent"
    # Absence may only be asserted about accounts actually read. One readable log
    # says nothing about three whose archives rotated away unread, and a sentence
    # claiming otherwise is the soft-suppression the design forbids.
    local seen="${CORR_ACCTS_SEEN:-0}" asked="${CORR_ACCTS_ASKED:-0}"
    local partial=""
    (( seen < asked )) && partial=" Only ${seen} of ${asked} accounts' logs could be read, so this is not the whole picture."
    case "$ERR_CORR_VERDICT" in
        visitor) ERR_CORR_NOTE="(${split}. Someone outside saw this.${partial})" ;;
        # "no user agent" is a bot signal, not proof of one: a curl-based API
        # client or a stripped agent arrives bare too. Report it, claim nothing.
        noua)    ERR_CORR_NOTE="(${split}. The ones with no user agent cannot be told apart from a customer's API client — treat this as unresolved, not as nobody.${partial})" ;;
        self|scanner)
                 if (( seen < asked )); then
                     ERR_CORR_NOTE="(${split}.${partial})"
                 else
                     ERR_CORR_NOTE="(${split}. No outside client saw one.)"
                 fi ;;
        none)    if (( seen < asked )); then
                     ERR_CORR_NOTE="(no served failure found, but only ${seen} of ${asked} accounts' logs could be read for this window.)"
                 else
                     ERR_CORR_NOTE="(these accounts' logs cover the window and show no served failure at all — the crash may never have reached a request.)"
                 fi ;;
    esac
    return 0
}

# Build the "Server errors" digest section on stdout, and set globals:
#   ERR_TOTAL ERR_FATAL ERR_FATAL_GENUINE ERR_FATAL_SCANNER ERR_GENUINE ERR_NOISE
#   ERR_FATAL_FANOUT_MAX
#   ERR_CORR_AFTER ERR_CORR_BEFORE ERR_CORR_ACCTS — the span and accounts of the
#     WIDEST genuine signature, for the corroboration lookup. 0/0/"" = no window.
swatter_errors_section() {
    local window="$1" cutoff
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    ERR_TOTAL=0 ERR_FATAL=0 ERR_FATAL_GENUINE=0 ERR_FATAL_SCANNER=0 ERR_GENUINE=0 ERR_NOISE=0
    ERR_FATAL_FANOUT_MAX=0
    ERR_CORR_AFTER=0 ERR_CORR_BEFORE=0 ERR_CORR_ACCTS=""
    ERR_CORR_VERDICT="" ERR_CORR_NOTE=""

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

    # Split fatals into genuine vs scanner-induced. Signature = the line with
    # its timestamp stripped — PHP fatal messages are stable (file:line, no
    # pids/clients), so identical crashes collapse and real breakage crosses
    # the repeat gate. If classification produces nothing despite fatals being
    # present, count every fatal as genuine — fail toward RED, never green.
    # (Both patterns are now validated against awk as well as grep -E at config
    # time, so an awk-illegal pattern no longer reaches this point; the guard
    # stays as defense-in-depth for a runtime override that skipped validation,
    # which would otherwise just empty `marked`.) The regex rides in via ENVIRON,
    # not -v, so awk never escape-processes operator-supplied backslashes —
    # `environ-not-dashv` in test/errors_test.sh pins that. Do not "simplify" it.
    local fatal_genuine="" fatal_scanner=""
    if (( ERR_FATAL > 0 )); then
        local marked
        marked="$(printf '%s\n' "$fatal" \
            | SWATTER_FS_RE="${ERROR_FATAL_SCANNER}" \
              SWATTER_FS_EX="${ERROR_FATAL_SCANNER_EXCLUDE}" \
            awk -v reps="${ERROR_FATAL_SCANNER_REPEATS:-3}" \
                -v fanmin="${ERROR_FATAL_FANOUT_ACCOUNTS:-4}" '
                { sig=$0; sub(/^\[[0-9-]+ [0-9:]+\] /,"",sig)
                  line[NR]=$0; sigof[NR]=sig; cnt[sig]++

                  # Sanitized copy for KEY MATERIAL ONLY: account identity and
                  # the normalized signature below. sig itself (already used
                  # above for depth via cnt[], and used below in END for
                  # re/ex) stays exactly what the operator log line produced.
                  # That split is what keeps this gate a strict narrowing of
                  # the pre-fanout one -- mutating sig before cnt/re/ex would
                  # let a stray byte flip a line that never matched the
                  # scanner pattern into one that does, moving it toward
                  # scanner instead of only ever away from it.
                  ksig=sig

                  # \034 (SUBSEP) hygiene: the composite fan-out key below is
                  # "nsig SUBSEP key". A literal \034 byte surviving into nsig
                  # or key injects an extra separator into that composite, and
                  # since neither side is length-prefixed, that extra byte can
                  # slice one logical (nsig,key) pair away from the bucket its
                  # sibling rows land in -- fragmenting one account group into
                  # two fan[] entries (verified by fanout-subsep-no-merge; it
                  # is not, as the mechanism was once described, two accounts
                  # merging into one key). Either direction only LOWERS
                  # fan-out, the unsafe direction for the scanner conjunct, so
                  # strip it before anything keys on it. Stripping only ksig --
                  # never sig -- means neither nsig nor key can contain \034
                  # afterward, so "nsig SUBSEP key" carries exactly one SUBSEP
                  # byte and the composite mapping stays injective.
                  gsub(/\034/,"",ksig); gsub(/\003/,"",ksig)

                  # cPanel virtfs jails re-nest a normal /home[0-9]*/<acct>/...
                  # path one level down, as
                  # /home[0-9]*/virtfs/<acct>/home[0-9]*/<acct>/.... Left
                  # alone this defeats the gate two ways at once: tier 2 below
                  # would read the literal shared string "virtfs" as the
                  # account -- the same collapse "unknown" is rejected for --
                  # and the nsig gsub further down scans left-to-right and
                  # non-overlapping, so it consumes the virtfs wrapper and
                  # resumes past it, leaving the inner /home/<acct>/ segment
                  # un-normalized. That second failure hits even a line with a
                  # correct [php/<acct>] tag, since nsig normalization does
                  # not depend on which tier supplied acct. Unwrap the jail
                  # before either tier 2 or nsig sees the path; a no-op on
                  # non-virtfs lines.
                  gsub(/\/home[0-9]*\/virtfs\/[^\/]+/, "", ksig)

                  # --- account identity, three tiers ---
                  # 1. a php/<acct> source tag, which only _errors_collect_php
                  #    emits. Reject the literal "unknown": that is the collector
                  #    fallback (see _errors_collect_php) and is SHARED by every
                  #    account whose path strip failed, so trusting it would
                  #    collapse them all into one and hide the very fan-out we
                  #    are counting.
                  #    The whole src field is kept, not just the account after
                  #    "php/": a feed that stamps a CONSTANT or wrong account
                  #    (php/webuser on every line) would otherwise collapse the
                  #    whole fleet onto one key. Non-php tags (apache vhost, fpm
                  #    pool) are per-site too, so they carry identity as well.
                  atag=""
                  if (substr(ksig,1,1)=="[") {
                      p=index(ksig,"] [")
                      if (p>0) { rest=substr(ksig,p+3); q=index(rest,"]")
                                 if (q>0) { src=substr(rest,1,q-1); sl=index(src,"/")
                                            if (!(sl>0 && substr(src,sl+1)=="unknown")) atag=src } }
                  }
                  # 2. the /home<N>/<acct>/ path (virtfs wrapper already
                  #    stripped above), read INDEPENDENTLY of the tag rather than
                  #    as a fallback for it.
                  apath=""
                  if (match(ksig, /\/home[0-9]*\/[^\/]+\//)) {
                      seg=substr(ksig,RSTART,RLENGTH)
                      sub(/^\/home[0-9]*\//,"",seg); sub(/\/$/,"",seg)
                      if (seg!="") apath=seg
                  }
                  # 3. Identity is the PAIR, so two rows share an account only
                  #    when tag AND path agree. Deflating fan-out then takes
                  #    control of both, and disagreement can only ADD distinct
                  #    accounts -- the RED-safe direction. An empty component
                  #    borrows the other so rows from one feed do not split off
                  #    from another feed for the same account. Neither -> a key
                  #    unique to this line: an unattributable fatal contributes
                  #    to fan-out and can never suppress the gate.
                  if (atag=="" && apath=="") key = "\001" NR
                  else key = "\002" (atag=="" ? apath : atag) "\003" (apath=="" ? atag : apath)

                  # The cPanel account NAME, for the corroboration lookup only --
                  # never for keying. The /home path segment IS the account; a
                  # php/<acct> tag is too. An apache vhost or an fpm pool is not,
                  # so those contribute no name and the lookup just sees fewer
                  # accounts than the fan-out counted. Deliberate: a name we
                  # cannot resolve to a home directory would send the log reader
                  # hunting for a path that does not exist.
                  aname = apath
                  if (aname=="" && substr(atag,1,4)=="php/") aname = substr(atag,5)
                  anameof[NR] = aname

                  # --- account-normalized signature, for BREADTH only ---
                  # /home[0-9]* not /home: cPanel uses /home2, /home3 as extra
                  # mount roots, and ERROR_DIGEST_LOG is an external feed that can
                  # carry any path. With /home alone the account stays embedded in
                  # nsig, no two accounts ever share one, and breadth is inert.
                  nsig=ksig
                  gsub(/\/home[0-9]*\/[^\/]+\//, "/home<N>/<A>/", nsig)
                  sub(/^\[[A-Z]+\] \[[^]]+\]/, "[L] [<SRC>]", nsig)
                  nsigof[NR]=nsig
                  if (!((nsig SUBSEP key) in seen)) { seen[nsig SUBSEP key]=1; fan[nsig]++ }
                }
                END { re=ENVIRON["SWATTER_FS_RE"]; ex=ENVIRON["SWATTER_FS_EX"]
                      for (i=1;i<=NR;i++) {
                          # DEPTH is cnt on the RAW signature and re/ex match the
                          # RAW signature; only BREADTH uses the sanitized,
                          # account-normalized nsig. That split is what makes
                          # this gate a strict narrowing of the old one --
                          # every conjunct can only move a fatal toward
                          # genuine, so this can never introduce a new false
                          # green. Do NOT rekey cnt onto nsig, and do NOT feed
                          # ksig/nsig into cnt, re, or ex above.
                          # fanmin <= 0 disables the breadth gate: fan is always
                          # >= 1, so a bare `fan < fanmin` would be false for
                          # every line and void the whole scanner class instead.
                          s = (sigof[i] ~ re && cnt[sigof[i]] < reps && sigof[i] !~ ex \
                               && (fanmin <= 0 || fan[nsigof[i]] < fanmin))
                          print (s ? "S" : "G") "\t" fan[nsigof[i]] "\t" line[i]

                          # Corroboration window, GENUINE rows only. Tracked PER
                          # SIGNATURE, never across the whole genuine set: two
                          # unrelated fatals at 02:00 and 22:00 would otherwise
                          # hand the log reader a 20-hour window, which any
                          # ordinary days worth of 5xx corroborates. Measured
                          # spans of real clusters here run 16-19 hours, so this
                          # is the common case, not the corner.
                          if (!s) {
                              ts = substr(line[i],2,19)
                              g = nsigof[i]
                              if (!(g in gmin) || ts < gmin[g]) gmin[g] = ts
                              if (!(g in gmax) || ts > gmax[g]) gmax[g] = ts
                              an = anameof[i]
                              if (an != "" && !((g SUBSEP an) in gseen)) {
                                  gseen[g SUBSEP an] = 1
                                  gacct[g] = (g in gacct) ? gacct[g] "," an : an
                              }
                          }
                      }
                      # The widest-fanout genuine signature is the cluster worth
                      # corroborating. Ties break on the lexically smallest nsig
                      # so the choice is reproducible run to run rather than
                      # dependent on awk hash order.
                      best=""; bestfan=-1
                      for (g in gmin) {
                          f = fan[g]
                          if (f > bestfan || (f == bestfan && g < best)) { bestfan=f; best=g }
                      }
                      # "#" can never begin a marked row (those start S or G), so
                      # the ^G / ^S consumers and cut -f3- below never see this.
                      if (best != "")
                          printf "#CORR\t%d\t%s\t%s\t%s\n", bestfan, gmin[best], gmax[best], (best in gacct ? gacct[best] : "")
                    }')"
        if [[ -z "$marked" ]]; then
            log_warn "errors: fatal classification failed; counting all fatals as genuine"
            fatal_genuine="$fatal"
        else
            fatal_genuine="$(printf '%s\n' "$marked" | grep '^G' | cut -f3- || true)"
            fatal_scanner="$(printf '%s\n' "$marked" | grep '^S' | cut -f3- || true)"

            # Widest cross-account spread among the GENUINE fatals. Drives the
            # body label below so an operator can tell "one signature across many
            # accounts" (breadth) from "one account failing repeatedly" (depth) —
            # the two now grade the same and need different responses.
            local _fmax
            _fmax="$(printf '%s\n' "$marked" | grep '^G' | cut -f2 | sort -rn | head -1)"
            [[ "$_fmax" =~ ^[0-9]+$ ]] && ERR_FATAL_FANOUT_MAX="$_fmax"

            # Corroboration window for the widest genuine signature. Exported RAW
            # (unpadded): these are observations, and the pad is policy belonging
            # to whoever reads the access logs. Any parse failure leaves the
            # globals at 0/empty, which every consumer must read as "no window" —
            # never as "a window starting at the epoch".
            local _corr; _corr="$(printf '%s\n' "$marked" | grep '^#CORR' | head -1 || true)"
            if [[ -n "$_corr" ]]; then
                local _cmin _cmax
                _cmin="$(printf '%s' "$_corr" | cut -f3)"
                _cmax="$(printf '%s' "$_corr" | cut -f4)"
                ERR_CORR_ACCTS="$(printf '%s' "$_corr" | cut -f5)"
                ERR_CORR_AFTER="$(_errors_epoch_of "$_cmin")"
                ERR_CORR_BEFORE="$(_errors_epoch_of "$_cmax")"
                if [[ ! "$ERR_CORR_AFTER" =~ ^[0-9]+$ || ! "$ERR_CORR_BEFORE" =~ ^[0-9]+$ ]]; then
                    ERR_CORR_AFTER=0; ERR_CORR_BEFORE=0; ERR_CORR_ACCTS=""
                fi
            fi
        fi
    fi
    ERR_FATAL_GENUINE=$(printf '%s\n' "$fatal_genuine" | grep -c . || true)
    ERR_FATAL_SCANNER=$(( ERR_FATAL - ERR_FATAL_GENUINE ))
    _errors_corroborate

    local fshow="Fatal: ${ERR_FATAL}"
    (( ERR_FATAL_SCANNER > 0 )) && fshow="Fatal: ${ERR_FATAL_GENUINE} genuine · ${ERR_FATAL_SCANNER} scanner-induced"
    {
        echo "Non-fatal: ${ERR_GENUINE}  ·  ${fshow}  ·  filtered as known noise: ${ERR_NOISE}"
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
        if (( ERR_FATAL_GENUINE > 0 )); then
            echo "FATAL entries (verbatim):"
            if (( ERR_FATAL_FANOUT_MAX >= 2 )); then
                echo "  (one signature spans across ${ERR_FATAL_FANOUT_MAX} accounts — reported whether a bot swept the"
                echo "   sites or a deploy broke them; those are indistinguishable in this log.)"
            fi
            [[ -n "$ERR_CORR_NOTE" ]] && echo "  ${ERR_CORR_NOTE}"
            printf '%s\n' "$fatal_genuine" | head -25 | sed 's/^/  /'
            echo
        fi
        if (( ERR_FATAL_SCANNER > 0 )); then
            echo "Scanner-induced FATALs (under both the repeat and account-spread gates — no outage signal):"
            printf '%s\n' "$fatal_scanner" | head -25 | sed 's/^/  /'
            echo
        fi
    }
}
