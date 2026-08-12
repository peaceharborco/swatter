#!/usr/bin/env bash
# lib/corroborate.sh — did the accounts that fataled actually SERVE failures, and
# to whom?
#
# The errors plane can tell you that one signature crashed on N accounts. It
# cannot tell you whether a human was waiting on any of them, because a PHP error
# log records that a request fataled and never who asked. Three situations produce
# the same cluster and need different responses:
#
#   - a real visitor got a broken page          -> an outage
#   - a scanner poked a file that crashed       -> noise
#   - wp-cron / a loopback REST call crashed    -> broken, but nobody was waiting
#
# So read the affected accounts' OWN access logs for the window the cluster
# occupied, and classify each 5xx by who received it. The per-account plane is
# load-bearing: the host-wide picture cannot answer a per-account question. On the
# reference host netdata's web_log tails only /var/log/apache2/access_log and
# never the per-vhost *-ssl_log files, which is why it reported zero 5xx for a
# cluster whose four accounts had each served one.
#
# Reports observations, never a cause. "No 5xx found" is not "nobody saw it" —
# headers-already-sent yields a blank 200, a plugin can catch a fatal and render
# 200, and an edge cache can serve a healthy copy over a dead origin. The caller
# must fail toward the louder reading, never quieter (see the design's §2).
#
# Globals set by swatter_corroborate:
#   CORR_5XX_TOTAL CORR_5XX_VISITOR CORR_5XX_SELF CORR_5XX_SCANNER
#   CORR_5XX_ACCTS   distinct accounts that served at least one 5xx
#   CORR_VERDICT     visitor | self | scanner | none | unknown
# rc 0 = the logs were read. rc 1 = they were NOT, and every count is meaningless.

# cPanel layout. Overridable so the suite can build a fake one.
: "${CORR_USERDOMAINS:=/etc/userdomains}"
: "${CORR_DOMLOG_DIR:=/etc/apache2/logs/domlogs}"
: "${CORR_HOME_ROOT:=/home}"
# Padding either side of the cluster span. The span is exported raw by the errors
# plane; how much slack to allow is policy and lives here.
: "${CORR_PAD_SECS:=120}"
# Space-separated IPs that mean "the server talking to itself". Loopback is always
# treated as self in addition to these.
: "${SERVER_IPS:=}"
# Space-separated IPs swatter has blocked, for the scanner arm. The caller fills
# this from the ledger; empty just means the scanner arm never fires, which is
# the safe direction (an unrecognized scanner reads as a visitor -> louder).
: "${CORR_BANNED_IPS:=}"
# ...or a FILE of them, one per line, which is how production supplies it: the
# ledger holds thousands of addresses and a command line is the wrong place for
# that much data (macOS caps argv far lower than Linux). The file wins when both
# are set. Read inside awk, never expanded by the shell.
: "${CORR_BANNED_FILE:=}"

# _corr_domains_for <acct> — the domains that belong to an account, one per line.
# /etc/userdomains is "domain: user"; the leading "*: nobody" wildcard is not a
# domain and must never match.
_corr_domains_for() {
    local acct="$1"
    [[ -r "$CORR_USERDOMAINS" ]] || return 1
    awk -v a="$acct" -F': *' '$1 != "*" && $2 == a { print $1 }' "$CORR_USERDOMAINS"
}

# _corr_day_keys <after> <before> — the Apache DAY prefixes ("25/Jun/2026") a window
# touches. Used for the coverage guard, not for matching.
_corr_day_keys() {
    local a="$1" b="$2" t
    for (( t = a - a % 86400; t <= b; t += 86400 )); do
        date -u -d "@$t" '+%d/%b/%Y' 2>/dev/null || date -u -r "$t" '+%d/%b/%Y' 2>/dev/null
    done
}

# _corr_month_tags <after> <before> — the "Mon-YYYY" tags cPanel names its monthly
# archives with, for a window that may straddle a month boundary.
_corr_month_tags() {
    local a="$1" b="$2" t
    for (( t = a; t <= b + 86400; t += 86400 )); do
        date -u -d "@$t" '+%b-%Y' 2>/dev/null || date -u -r "$t" '+%b-%Y' 2>/dev/null
    done | sort -u
}

# _corr_minute_keys <after> <before> — the Apache time prefixes ("25/Jun/2026:09:05")
# covering a window, one per line. Matching by precomputed minute key keeps the
# scan to a fixed-string grep and avoids mktime(), which BSD awk does not have and
# the suite must run under.
_corr_minute_keys() {
    local a="$1" b="$2" t n=0
    # A pathological window must not generate an unbounded pattern list; 3000
    # minutes is two days, far past any real digest window.
    for (( t = a - a % 60; t <= b; t += 60 )); do
        (( ++n > 3000 )) && return 1
        date -u -d "@$t" '+%d/%b/%Y:%H:%M' 2>/dev/null || date -u -r "$t" '+%d/%b/%Y:%H:%M' 2>/dev/null
    done
}

# swatter_corroborate <after_epoch> <before_epoch> <acct-csv>
swatter_corroborate() {
    local after="$1" before="$2" accts="$3"
    CORR_5XX_TOTAL=0 CORR_5XX_VISITOR=0 CORR_5XX_SELF=0 CORR_5XX_SCANNER=0
    CORR_5XX_ACCTS=0 CORR_VERDICT="unknown"

    [[ "$after" =~ ^[0-9]+$ && "$before" =~ ^[0-9]+$ ]] || return 1
    (( after > 0 && before >= after )) || return 1
    [[ -n "$accts" ]] || return 1
    [[ -r "$CORR_USERDOMAINS" ]] || return 1

    local pad="${CORR_PAD_SECS:-120}"
    local keys; keys="$(_corr_minute_keys "$(( after - pad ))" "$(( before + pad ))")" || return 1
    [[ -n "$keys" ]] || return 1

    # Scan PER ACCOUNT rather than over one merged list. It keeps "which accounts
    # served a failure" exact, and it sidesteps parsing grep's filename prefix
    # back off every line — which is the kind of detail that silently misreads a
    # field and reclassifies traffic.
    local acct dom f looked=0 covered=0 out c k
    local oldifs="$IFS"
    while IFS= read -r acct; do
        [[ -n "$acct" ]] || continue
        local -a logs=() gzlogs=()
        while read -r dom; do
            [[ -n "$dom" ]] || continue
            # Access logs only. -bytes_log is a byte-count ledger, not requests.
            for f in "${CORR_DOMLOG_DIR}/${dom}" "${CORR_DOMLOG_DIR}/${dom}-ssl_log"; do
                [[ -r "$f" ]] && logs+=("$f")
            done
            # cPanel rotates the live domlog into the account's own monthly
            # archive. A digest that runs after rotation, or any look at an older
            # window, finds the live file holding only today — so the archive is
            # not an optimization, it is the difference between reading the
            # window and quietly reporting nothing about it.
            local tag
            while read -r tag; do
                [[ -n "$tag" ]] || continue
                for f in "${CORR_HOME_ROOT}/${acct}/logs/${dom}-ssl_log-${tag}.gz" \
                         "${CORR_HOME_ROOT}/${acct}/logs/${dom}-${tag}.gz"; do
                    [[ -r "$f" ]] && gzlogs+=("$f")
                done
            done < <(_corr_month_tags "$(( after - pad ))" "$(( before + pad ))")
        done < <(_corr_domains_for "$acct")
        (( ${#logs[@]} + ${#gzlogs[@]} )) || continue
        looked=1

        # Everything below is data, never code: no eval, no expansion of a log
        # field, and a line that does not parse is skipped rather than guessed at.
        out="$( { (( ${#logs[@]} ))   && cat -- "${logs[@]}" 2>/dev/null
                  (( ${#gzlogs[@]} )) && gzip -dc -- "${gzlogs[@]}" 2>/dev/null
                  true; } \
            | LC_ALL=C grep -hF -f <(printf '%s\n' "$keys") 2>/dev/null \
            | awk -v selfips="${SERVER_IPS:-} 127.0.0.1 ::1" -v banned="${CORR_BANNED_IPS:-}" \
                  -v banfile="${CORR_BANNED_FILE:-}" '
                BEGIN { n=split(selfips,s," "); for(i=1;i<=n;i++) self[s[i]]=1
                        if (banfile != "") { while ((getline ln < banfile) > 0) { gsub(/[ \t\r]/,"",ln); if (ln!="") ban[ln]=1 }
                                             close(banfile) }
                        else { n=split(banned,b," "); for(i=1;i<=n;i++) ban[b[i]]=1 } }
                {
                  ip=$1
                  # Combined format: the request is quoted and may contain spaces,
                  # so find the closing quote instead of trusting a field offset.
                  rq=index($0,"\""); if (rq==0) next
                  rest=substr($0,rq+1); rq2=index(rest,"\""); if (rq2==0) next
                  req=substr(rest,1,rq2-1); tail=substr(rest,rq2+1)
                  split(tail,T," "); st=T[1]
                  if (st !~ /^5[0-9][0-9]$/) next
                  # UA is the last quoted field on the line.
                  ua=""; lq=0
                  for (i=length(tail); i>1; i--) if (substr(tail,i,1)=="\"") { lq=i; break }
                  if (lq>1) { pre=0
                              for (i=lq-1; i>0; i--) if (substr(tail,i,1)=="\"") { pre=i; break }
                              if (pre>0) ua=substr(tail,pre+1,lq-pre-1) }
                  # Self before scanner before visitor. An unrecognized client
                  # falls through to visitor, which is the louder reading.
                  #
                  # The empty-UA arm is the one place this deliberately chooses
                  # the QUIETER reading, so it needs its evidence stated: on the
                  # reference host the only failures that reached this arm were
                  # "GET /wp-admin/setup-config.php" 500 with UA "-", from two
                  # IPs not in the ledger — a probe for an unconfigured
                  # WordPress, landing mid-cluster and reading as a customer.
                  # No browser omits a user-agent. A real outage still surfaces
                  # here, because the humans hitting it do send one.
                  cls="visitor"
                  if (ip in self)                cls="self"
                  else if (ua ~ /WordPress\//)   cls="self"
                  else if (req ~ /wp-cron\.php/) cls="self"
                  else if (ip in ban)            cls="scanner"
                  else if (ua == "" || ua == "-") cls="scanner"
                  print cls
                }' | sort | uniq -c)" || true

        local had=0
        while read -r c k; do
            [[ -n "$k" ]] || continue
            case "$k" in
                visitor) CORR_5XX_VISITOR=$(( CORR_5XX_VISITOR + c )); had=1 ;;
                self)    CORR_5XX_SELF=$((    CORR_5XX_SELF    + c )); had=1 ;;
                scanner) CORR_5XX_SCANNER=$(( CORR_5XX_SCANNER + c )); had=1 ;;
            esac
        done <<< "$out"
        (( had )) && CORR_5XX_ACCTS=$(( CORR_5XX_ACCTS + 1 ))

        # Coverage: did these sources contain ANY request on the days the window
        # touches? A live domlog that has rotated is perfectly readable and holds
        # only today, so without this check an old window reads as "looked, found
        # no failures" when nothing covering it was ever opened. Silence from an
        # unread log is the quiet direction, and quiet is the direction that
        # loses an outage.
        if (( ! covered )); then
            { (( ${#logs[@]} ))   && cat -- "${logs[@]}" 2>/dev/null
              (( ${#gzlogs[@]} )) && gzip -dc -- "${gzlogs[@]}" 2>/dev/null
              true; } \
            | LC_ALL=C grep -qF -f <(_corr_day_keys "$(( after - pad ))" "$(( before + pad ))") 2>/dev/null \
            && covered=1
        fi
    done < <(printf '%s\n' "$accts" | tr ',' '\n')   # trailing newline: read drops an unterminated last field
    IFS="$oldifs"

    (( looked )) || return 1
    (( covered )) || return 1
    CORR_5XX_TOTAL=$(( CORR_5XX_VISITOR + CORR_5XX_SELF + CORR_5XX_SCANNER ))

    # A single outside client failing beside a hundred cron failures is still an
    # outage for that client, so the visitor arm wins outright — it is never
    # averaged against the others.
    if   (( CORR_5XX_VISITOR > 0 )); then CORR_VERDICT="visitor"
    elif (( CORR_5XX_SELF    > 0 )); then CORR_VERDICT="self"
    elif (( CORR_5XX_SCANNER > 0 )); then CORR_VERDICT="scanner"
    else                                  CORR_VERDICT="none"
    fi
    return 0
}
