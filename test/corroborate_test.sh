#!/usr/bin/env bash
# test/corroborate_test.sh — outage corroboration: read the affected accounts' own
# access logs for the fatal window and classify WHO received each failure.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/corroborate.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/swatter-corrt.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# A fake cPanel layout: userdomains maps domain -> account, and each account's
# logs live under the domlogs dir by DOMAIN name.
CORR_USERDOMAINS="${WORK}/userdomains"
CORR_DOMLOG_DIR="${WORK}/domlogs"
CORR_HOME_ROOT="${WORK}/home"
mkdir -p "$CORR_DOMLOG_DIR" "$CORR_HOME_ROOT"
cat > "$CORR_USERDOMAINS" <<'EOF'
*: nobody
alpha.example: acctA
alpha-extra.example: acctA
beta.example: acctB
gamma.example: acctC
EOF
SERVER_IPS="203.0.113.10"

# Window: 2026-06-25 09:00:00 .. 09:30:00 UTC, as the classifier exports it.
W_AFTER="$(date -u -d '2026-06-25 09:00:00' '+%s' 2>/dev/null || date -u -j -f '%Y-%m-%d %H:%M:%S' '2026-06-25 09:00:00' '+%s')"
W_BEFORE="$(date -u -d '2026-06-25 09:30:00' '+%s' 2>/dev/null || date -u -j -f '%Y-%m-%d %H:%M:%S' '2026-06-25 09:30:00' '+%s')"

# Apache stamps logs in the host's LOCAL zone and the code builds its match keys
# the same way, so fixtures must too — otherwise this suite only passes on a UTC
# machine and silently stops exercising the timezone handling anywhere else.
_lts() { ( unset TZ; date -d "@$1" '+%d/%b/%Y:%H:%M:%S' 2>/dev/null || date -r "$1" '+%d/%b/%Y:%H:%M:%S' 2>/dev/null ); }

# Log line helper: <file> <ip> <time> <request> <status> [ua]
_log() { local f="$1" ip="$2" t="$3" req="$4" st="$5" ua="${6:-Mozilla/5.0 (X11; Linux x86_64) Chrome/120}"
  printf '%s - - [%s +0000] "%s" %s 512 "-" "%s"\n' "$ip" "$t" "$req" "$st" "$ua" >> "$f"; }

_reset() { rm -f "${CORR_DOMLOG_DIR}"/* 2>/dev/null; : ; }

# --- a visitor-shaped failure: remote client, browser UA, ordinary page -------
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+300)))" "GET /about-us/ HTTP/2.0" 500
_log "${CORR_DOMLOG_DIR}/beta.example-ssl_log"  198.51.100.8 "$(_lts $((W_AFTER+360)))" "GET /shop/ HTTP/2.0" 503
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA,acctB"
check visitor-total    "$CORR_5XX_TOTAL"   "2"
check visitor-count    "$CORR_5XX_VISITOR" "2"
check visitor-self     "$CORR_5XX_SELF"    "0"
check visitor-scanner  "$CORR_5XX_SCANNER" "0"
check visitor-accts    "$CORR_5XX_ACCTS"   "2"
check visitor-verdict  "$CORR_VERDICT"     "visitor"

# --- the Jetpack shape: WordPress talking to itself --------------------------
# This is the real cds1 cluster: wp-cron -> loopback -> jetpack sync -> 503.
# It is a served failure, but no outside client ever saw it.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 203.0.113.10 "$(_lts $((W_AFTER+300)))" \
     "POST /wp-json/jetpack/v4/sync/spawn-sync HTTP/1.1" 503 "WordPress/6.5; https://alpha.example"
_log "${CORR_DOMLOG_DIR}/beta.example-ssl_log"  127.0.0.1    "$(_lts $((W_AFTER+360)))" \
     "GET /wp-cron.php?doing_wp_cron HTTP/1.1" 503 "WordPress/6.5; https://beta.example"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA,acctB"
check self-total     "$CORR_5XX_TOTAL"   "2"
check self-count     "$CORR_5XX_SELF"    "2"
check self-visitor   "$CORR_5XX_VISITOR" "0"
check self-verdict   "$CORR_VERDICT"     "self"

# A remote IP can still be self-shaped: a loopback UA or a cron path is the
# signal, not just the address (some hosts route wp-cron through the edge).
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.9 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-cron.php?doing_wp_cron=1 HTTP/1.1" 500 "WordPress/6.5; https://alpha.example"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check self-remote-ua "$CORR_5XX_SELF" "1"

# --- a scanner: an IP swatter already blocked --------------------------------
_reset
CORR_BANNED_IPS="198.51.100.66 198.51.100.67"
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.66 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-admin/includes/admin.php HTTP/1.1" 500 "curl/8.4.0"
_log "${CORR_DOMLOG_DIR}/beta.example-ssl_log"  198.51.100.67 "$(_lts $((W_AFTER+360)))" \
     "GET /.env HTTP/1.1" 500 "python-requests/2.31"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA,acctB"
check scanner-count   "$CORR_5XX_SCANNER" "2"
check scanner-visitor "$CORR_5XX_VISITOR" "0"
check scanner-verdict "$CORR_VERDICT"     "scanner"
CORR_BANNED_IPS=""

# --- an empty user-agent is a probe, not a customer --------------------------
# Measured on the reference host: the ONLY failures reaching the visitor arm in a
# real cluster were "GET /wp-admin/setup-config.php" 500 with UA "-", from IPs
# not in the ledger. No browser omits a user-agent. This is the one arm that
# deliberately chooses the quieter reading, so it is pinned explicitly.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.44 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-admin/setup-config.php HTTP/2.0" 500 "-"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check emptyua-bucket  "$CORR_5XX_NOUA"    "1"
check emptyua-scanner "$CORR_5XX_SCANNER" "0"
check emptyua-visitor "$CORR_5XX_VISITOR" "0"
# NOT "scanner": an absent UA is a strong bot signal but a curl-based API client
# or a stripped agent arrives bare too, and calling those "a bot" would let a
# real customer-facing outage be reported as nobody having seen it.
check emptyua-verdict "$CORR_VERDICT"     "noua"
# ...but a browser-shaped client on the same path is still a visitor: the UA is
# the signal, not the path.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.44 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-admin/setup-config.php HTTP/2.0" 500 "Mozilla/5.0 (Macintosh) Safari/605"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check browserua-visitor "$CORR_5XX_VISITOR" "1"

# --- wp-cron.php by PATH alone is not "the server talking to itself" ---------
# External schedulers (EasyCron, cron-job.org) and remote probes hit that path.
# Calling their failures self-inflicted would hide a 5xx served to a paying
# integration. It counts as self only from our own address or a WordPress UA.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.55 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-cron.php?doing_wp_cron HTTP/1.1" 500 "EasyCron/1.0"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check extcron-visitor "$CORR_5XX_VISITOR" "1"
check extcron-self    "$CORR_5XX_SELF"    "0"

# --- absence is only claimed about accounts actually READ ---------------------
# acctA has a readable log; acctC's is missing entirely. One readable log does
# not license a statement about the other, so the caller must see seen<asked.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 203.0.113.10 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-cron.php HTTP/1.1" 503 "WordPress/6.5"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA,acctC"
check partial-asked "$CORR_ACCTS_ASKED" "2"
check partial-seen  "$CORR_ACCTS_SEEN"  "1"

# --- mixed: one real visitor among background noise escalates ----------------
# The visitor arm is what 🔥 keys on, so a single outside client failing beside
# ten cron failures must NOT be averaged away.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 203.0.113.10 "$(_lts $((W_AFTER+300)))" \
     "GET /wp-cron.php HTTP/1.1" 503 "WordPress/6.5"
_log "${CORR_DOMLOG_DIR}/beta.example-ssl_log"  198.51.100.7 "$(_lts $((W_AFTER+360)))" \
     "GET /pricing/ HTTP/2.0" 500
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA,acctB"
check mixed-visitor "$CORR_5XX_VISITOR" "1"
check mixed-self    "$CORR_5XX_SELF"    "1"
check mixed-verdict "$CORR_VERDICT"     "visitor"

# --- window boundaries are respected -----------------------------------------
# A pad is applied, so just-outside means outside the PADDED window. 09:00 minus
# 10 minutes is outside any sane pad; 09:31 is inside a 120s pad.
_reset
CORR_PAD_SECS=120
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER-600)))" "GET /a/ HTTP/2.0" 500
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_BEFORE+60)))" "GET /b/ HTTP/2.0" 500
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+10800)))" "GET /c/ HTTP/2.0" 500
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check window-pad-in    "$CORR_5XX_TOTAL" "1"

# --- non-5xx and other accounts' logs are never counted ----------------------
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+300)))" "GET /ok/ HTTP/2.0" 200
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+301)))" "GET /nf/ HTTP/2.0" 404
_log "${CORR_DOMLOG_DIR}/gamma.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+300)))" "GET /x/ HTTP/2.0" 500
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check ignores-2xx-4xx    "$CORR_5XX_TOTAL" "0"
check ignores-other-acct "$CORR_VERDICT"   "none"

# --- both plain and ssl logs for an account are read -------------------------
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example"          198.51.100.7 "$(_lts $((W_AFTER+300)))" "GET /p/ HTTP/1.1" 500
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log"  198.51.100.7 "$(_lts $((W_AFTER+360)))" "GET /s/ HTTP/2.0" 500
_log "${CORR_DOMLOG_DIR}/alpha-extra.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+420)))" "GET /e/ HTTP/2.0" 500
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check reads-all-logs "$CORR_5XX_TOTAL" "3"
# -bytes_log is not an access log and must never be parsed
_log "${CORR_DOMLOG_DIR}/alpha.example-bytes_log" 198.51.100.7 "25/Jun/2026:09:08:00" "GET /z/ HTTP/2.0" 500
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check skips-bytes-log "$CORR_5XX_TOTAL" "3"

# --- failure modes must be distinguishable from "found nothing" --------------
# rc 1 = could not look; rc 0 with totals 0 = looked and found nothing. A caller
# that conflates them would print "no failures" when it never read a byte.
_reset
swatter_corroborate "$W_AFTER" "$W_BEFORE" ""; rc=$?
check no-accts-rc      "$rc" "1"
check no-accts-verdict "$CORR_VERDICT" "unknown"
swatter_corroborate 0 0 "acctA"; rc=$?
check no-window-rc "$rc" "1"
CORR_USERDOMAINS="${WORK}/does-not-exist"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"; rc=$?
check no-map-rc      "$rc" "1"
check no-map-verdict "$CORR_VERDICT" "unknown"
CORR_USERDOMAINS="${WORK}/userdomains"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "ghostacct"; rc=$?
check unknown-acct-rc "$rc" "1"
# A readable log that does not COVER the window is not evidence of absence. A
# rotated domlog is perfectly readable and holds only today, so without this the
# oldest windows would all read "looked, found no failures" having never seen a
# line from that day.
_reset
: > "${CORR_DOMLOG_DIR}/alpha.example-ssl_log"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"; rc=$?
check no-coverage-rc      "$rc" "1"
check no-coverage-verdict "$CORR_VERDICT" "unknown"
# Same, but the log holds only traffic from a different day.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+86700)))" "GET /a/ HTTP/2.0" 500
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"; rc=$?
check wrong-day-rc "$rc" "1"
# Whereas traffic IN the window with no failures is a real, reportable "none".
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+300)))" "GET /a/ HTTP/2.0" 200
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"; rc=$?
check covered-none-rc      "$rc" "0"
check covered-none-verdict "$CORR_VERDICT" "none"

# --- the window is read out of the monthly archive once the domlog rotates ----
# cPanel moves the live log into the account's own <domain>-ssl_log-Mon-YYYY.gz.
# The nightly digest can run after that rotation, and every historical look does.
_reset
mkdir -p "${CORR_HOME_ROOT}/acctA/logs"
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+4000000)))" "GET /today/ HTTP/2.0" 200
_arch="${CORR_HOME_ROOT}/acctA/logs/alpha.example-ssl_log-$( ( unset TZ; date -d "@${W_AFTER}" +%b-%Y 2>/dev/null || date -r "${W_AFTER}" +%b-%Y ) )"
_log "$_arch" 198.51.100.7 "$(_lts $((W_AFTER+300)))" "GET /rotated/ HTTP/2.0" 500
_log "$_arch" 203.0.113.10 "$(_lts $((W_AFTER+360)))" "GET /wp-cron.php HTTP/1.1" 503
gzip -f "$_arch"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"; rc=$?
check archive-rc      "$rc" "0"
check archive-total   "$CORR_5XX_TOTAL"   "2"
check archive-visitor "$CORR_5XX_VISITOR" "1"
check archive-self    "$CORR_5XX_SELF"    "1"
check archive-verdict "$CORR_VERDICT"     "visitor"
rm -rf "${CORR_HOME_ROOT}/acctA"

# --- a hostile log line cannot break the reader ------------------------------
# Log fields are attacker-influenced (UA, path). Nothing may be evaluated, and a
# malformed line must be skipped rather than counted or crash the parse.
_reset
printf '%s\n' 'not a log line at all' >> "${CORR_DOMLOG_DIR}/alpha.example-ssl_log"
printf '%s - - [%s +0000] "GET /$(touch ${WORK}/pwned) HTTP/2.0" 500 1 "-" "`id`"\n' \
  198.51.100.7 "$(_lts $((W_AFTER+300)))" >> "${CORR_DOMLOG_DIR}/alpha.example-ssl_log"
swatter_corroborate "$W_AFTER" "$W_BEFORE" "acctA"
check hostile-counted "$CORR_5XX_TOTAL" "1"
check hostile-no-exec "$([[ -e "${WORK}/pwned" ]] && echo pwned || echo safe)" "safe"

# --- end to end: the errors plane calls this and renders the evidence line ----
# Wires the real classifier to the real lookup over a fake cPanel layout, so the
# whole path is exercised rather than the two halves separately.
source "${ROOT}/lib/report.sh"; source "${ROOT}/lib/errors.sh"
swatter_now() { echo 1782396000; }   # 2026-06-25 12:00:00 UTC
ERROR_DIGEST_LOG="${WORK}/digest.log"
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
FAN='PHP Fatal error: Uncaught Error: Call to undefined function shared_helper()'
_reset
# Four accounts crash inside one hour; two of them served the failure to a real
# browser. That is the shape 🔥 exists for.
{ echo "[2026-06-25 09:00:00] [FATAL] [php/acctA] ${FAN} in /home/acctA/public_html/x.php:8"
  echo "[2026-06-25 09:10:00] [FATAL] [php/acctB] ${FAN} in /home/acctB/public_html/x.php:8"
  echo "[2026-06-25 09:20:00] [FATAL] [php/acctC] ${FAN} in /home/acctC/public_html/x.php:8"
  echo "[2026-06-25 09:30:00] [FATAL] [php/acctD] ${FAN} in /home/acctD/public_html/x.php:8"
} > "$ERROR_DIGEST_LOG"
cat >> "$CORR_USERDOMAINS" <<'EOF'
delta.example: acctD
EOF
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.7 "$(_lts $((W_AFTER+5)))" "GET /a/ HTTP/2.0" 500
_log "${CORR_DOMLOG_DIR}/beta.example-ssl_log"  198.51.100.8 "$(_lts $((W_AFTER+605)))" "GET /b/ HTTP/2.0" 500
swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
check e2e-genuine  "$ERR_FATAL_GENUINE" "4"
check e2e-verdict  "$ERR_CORR_VERDICT"  "visitor"
check e2e-note     "$(printf '%s' "$SECTION" | grep -c 'to outside clients')" "1"
# The note must report the actual SPLIT, never summarise the winning arm as
# "all N" — that was wrong the first time it met real data (4 loopback failures
# plus 1 bot probe reported "all 5 went to the server itself").
check e2e-note-split "$(printf '%s' "$SECTION" | grep -c '2 to outside clients, 0 to the server itself')" "1"
# ...and the same cluster with only loopback failures does NOT read as visitor.
_reset
_log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 203.0.113.10 "$(_lts $((W_AFTER+5)))" \
     "GET /wp-cron.php HTTP/1.1" 503 "WordPress/6.5"
swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
check e2e-self-verdict "$ERR_CORR_VERDICT" "self"
# Only 2 of the 4 clustered accounts have readable logs here, so the note must
# NOT assert "No outside client saw one" — it says how much it actually read.
check e2e-self-note    "$(printf '%s' "$SECTION" | grep -c 'not the whole picture')" "1"
# A mixed cluster reports both arms honestly rather than claiming "all".
_log "${CORR_DOMLOG_DIR}/beta.example-ssl_log" 198.51.100.90 "$(_lts $((W_AFTER+605)))" \
     "GET /wp-admin/setup-config.php HTTP/2.0" 500 "-"
swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
# A bare-UA failure alongside the loopback ones is unresolved, not "nobody".
check e2e-mixed-verdict "$ERR_CORR_VERDICT" "noua"
check e2e-mixed-split   "$(printf '%s' "$SECTION" | grep -c '1 with no user agent')" "1"
check e2e-mixed-noclaim "$(printf '%s' "$SECTION" | grep -c 'treat this as unresolved, not as nobody')" "1"
# --- "known bot" means blocked for HOSTILE behaviour, not "ever blocked" -------
# Reference host, 2026-10-02: a site administrator, logged in, hit a plugin crash
# and the digest said "served to known bots — no outside client saw one". Their
# address was in the ledger for three request_flood blocks, all false positives
# on wp-admin page loads. The list used to be `select ip from offenders`.
if command -v sqlite3 >/dev/null 2>&1; then
    HDB="${WORK}/state/swatter.db"; mkdir -p "${WORK}/state"
    sqlite3 "$HDB" "CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, ts INTEGER,
        action TEXT, channel TEXT, ttl INTEGER, score INTEGER, reason TEXT, dry_run INTEGER);
        CREATE TABLE offenders(ip TEXT PRIMARY KEY);"
    _act() {  # <ip> <ts> <action> <reason> [dry_run]
        sqlite3 "$HDB" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
            VALUES('$1',$2,'$3','cloudflare',3600,75,'$4',${5:-0});
            INSERT OR IGNORE INTO offenders(ip) VALUES('$1');"; }
    H_SINCE=$(( W_AFTER - 2592000 ))
    # The measured case: request_flood only, three times, the last one a "perm".
    _act 198.51.100.20 $((W_AFTER-800000)) temp "score=75 rule=request_flood"
    _act 198.51.100.20 $((W_AFTER-600000)) temp "score=75 rule=request_flood"
    _act 198.51.100.20 $((W_AFTER-500000)) perm "score=75 rule=request_flood recidivism=3/30d"
    # Other non-hostile histories: the other volume rule, a secondary leg of a
    # volume rule, and a blended score with no decisive rule at all.
    _act 198.51.100.21 $((W_AFTER-1000))   temp "score=75 rule=error_burst"
    _act 198.51.100.22 $((W_AFTER-1000))   perm "plane-upgrade score=75 rule=request_flood"
    _act 198.51.100.23 $((W_AFTER-1000))   temp "score=72"
    # Hostile, one per rule, in the reason shapes the scan actually writes.
    _act 198.51.100.30 $((W_AFTER-1000))   temp "score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath"
    _act 198.51.100.31 $((W_AFTER-1000))   temp "score=82 rule=high_badpath_repeat"
    _act 198.51.100.32 $((W_AFTER-1000))   temp "low_and_slow_persist buckets=6 score=55 rule=scanner_profile"
    _act 198.51.100.33 $((W_AFTER-1000))   perm "honeypot score=100 rule=honeypot"
    # Blocked AFTER the window: the normal order for a scanner that crashed a page.
    _act 198.51.100.34 $((W_BEFORE+300))   temp "score=90 rule=critical_badpath"
    # Report mode writes every row as a dry run; it still identifies the scanner.
    _act 198.51.100.35 $((W_AFTER-1000))   temp "score=90 rule=critical_badpath" 1
    # Too old: one second outside the 30 days, and one second inside.
    _act 198.51.100.40 $((H_SINCE-1))      temp "score=90 rule=critical_badpath"
    _act 198.51.100.41 $((H_SINCE))        temp "score=90 rule=critical_badpath"
    # The operator took the block back: not a bot. Re-blocked afterwards: is one.
    _act 198.51.100.50 $((W_AFTER-5000))   temp "score=78 rule=scanner_profile"
    _act 198.51.100.50 $((W_AFTER-4000))   unblock "manual unblock"
    _act 198.51.100.51 $((W_AFTER-5000))   unblock "manual unblock"
    _act 198.51.100.51 $((W_AFTER-4000))   temp "score=78 rule=scanner_profile"
    # Hostile, but 40 days before the window: the caller's 30-day lookback drops
    # it. Used end to end below, where that number actually lives.
    _act 198.51.100.42 $((W_AFTER-3456000)) temp "score=90 rule=critical_badpath"
    # Hostile once, then a volume block after it: the hostile row still stands.
    _act 198.51.100.52 $((W_AFTER-5000))   temp "score=90 rule=critical_badpath"
    _act 198.51.100.52 $((W_AFTER-4000))   temp "score=75 rule=request_flood"

    HOSTILE="$(_errors_hostile_ips "$HDB" "$H_SINCE" | sort | tr '\n' ' ')"
    check hostile-list "$HOSTILE" \
        "198.51.100.30 198.51.100.31 198.51.100.32 198.51.100.33 198.51.100.34 198.51.100.35 198.51.100.41 198.51.100.51 198.51.100.52 "
    # A <since> that is not a number is refused rather than spliced into SQL.
    # The payload is a complete statement followed by a comment, so it WOULD run
    # if spliced; a fragment only produces a syntax error and proves nothing.
    cp "$HDB" "${HDB}.inj"
    _errors_hostile_ips "${HDB}.inj" "0; DROP TABLE actions; --" >/dev/null 2>&1; rc=$?
    check hostile-bad-since-rc "$rc" "1"
    check hostile-bad-since-noexec "$(sqlite3 "${HDB}.inj" 'select count(*) > 0 from actions;' 2>/dev/null)" "1"
    # A database that cannot be read is an error, never an empty answer.
    _errors_hostile_ips "${WORK}/state/absent.db" "$H_SINCE" >/dev/null 2>&1; rc=$?
    check hostile-nodb-rc "$([[ "$rc" -ne 0 ]] && echo nonzero || echo zero)" "nonzero"

    # End to end, through the real digest path. Same four-account crash; the only
    # served failure went to a logged-in browser whose address has the
    # request_flood history above. It must read as an outside client.
    _SAVED_STATE_DIR="${STATE_DIR:-}"; STATE_DIR="${WORK}/state"
    { echo "[2026-06-25 09:00:00] [FATAL] [php/acctA] ${FAN} in /home/acctA/public_html/x.php:8"
      echo "[2026-06-25 09:10:00] [FATAL] [php/acctB] ${FAN} in /home/acctB/public_html/x.php:8"
      echo "[2026-06-25 09:20:00] [FATAL] [php/acctC] ${FAN} in /home/acctC/public_html/x.php:8"
      echo "[2026-06-25 09:30:00] [FATAL] [php/acctD] ${FAN} in /home/acctD/public_html/x.php:8"
    } > "$ERROR_DIGEST_LOG"
    _reset
    _log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.20 "$(_lts $((W_AFTER+5)))" \
         "POST /wp-admin/admin-ajax.php?action=sign HTTP/2.0" 500
    swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
    check e2e-flooder-verdict "$ERR_CORR_VERDICT" "visitor"
    check e2e-flooder-note    "$(printf '%s' "$SECTION" | grep -c '1 to outside clients, 0 to the server itself (wp-cron or a loopback call), 0 to known bots')" "1"
    # The same request from an address blocked for a secret-file probe is a bot.
    _reset
    _log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.30 "$(_lts $((W_AFTER+5)))" \
         "POST /wp-admin/admin-ajax.php?action=sign HTTP/2.0" 500
    swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
    check e2e-hostile-verdict "$ERR_CORR_VERDICT" "scanner"
    check e2e-hostile-note    "$(printf '%s' "$SECTION" | grep -c '0 to outside clients, 0 to the server itself (wp-cron or a loopback call), 1 to known bots')" "1"
    # ...and from one whose hostile block is 40 days old, an outside client again.
    _reset
    _log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.42 "$(_lts $((W_AFTER+5)))" \
         "POST /wp-admin/admin-ajax.php?action=sign HTTP/2.0" 500
    swatter_errors_section 24h > "${WORK}/sec.out"
    check e2e-stale-hostile-verdict "$ERR_CORR_VERDICT" "visitor"
    # A ledger query that dies part-way must not leave a partial list behind: the
    # addresses it did print would be called bots on the strength of a failed
    # read. Here the stand-in names the hostile address and then fails.
    sqlite3() { echo 198.51.100.30; return 1; }
    _reset
    _log "${CORR_DOMLOG_DIR}/alpha.example-ssl_log" 198.51.100.30 "$(_lts $((W_AFTER+5)))" \
         "POST /wp-admin/admin-ajax.php?action=sign HTTP/2.0" 500
    swatter_errors_section 24h > "${WORK}/sec.out"
    check e2e-failed-query-verdict "$ERR_CORR_VERDICT" "visitor"
    unset -f sqlite3
    # The temp file holding the list never outlives the lookup.
    check e2e-no-tempfile-left "$(ls "${TMPDIR:-/tmp}"/swatter-corrban.* 2>/dev/null | wc -l | tr -d ' ')" "0"
    STATE_DIR="$_SAVED_STATE_DIR"
else
    echo "SKIP hostile-ledger cases: sqlite3 not installed"
fi

# A signature sprawling past the span cap declines to correlate at all.
{ echo "[2026-06-25 00:05:00] [FATAL] [php/acctA] ${FAN} in /home/acctA/public_html/x.php:8"
  echo "[2026-06-25 03:05:00] [FATAL] [php/acctB] ${FAN} in /home/acctB/public_html/x.php:8"
  echo "[2026-06-25 06:05:00] [FATAL] [php/acctC] ${FAN} in /home/acctC/public_html/x.php:8"
  echo "[2026-06-25 09:05:00] [FATAL] [php/acctD] ${FAN} in /home/acctD/public_html/x.php:8"
} > "$ERROR_DIGEST_LOG"
swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
check e2e-wide-verdict "$ERR_CORR_VERDICT" "wide"
check e2e-wide-note    "$(printf '%s' "$SECTION" | grep -c 'too long a span')" "1"
# Turning it off leaves no verdict and no line — and never touches the counts.
ERROR_CORROBORATE_ENABLE=false
swatter_errors_section 24h > "${WORK}/sec.out"; SECTION="$(cat "${WORK}/sec.out")"
check e2e-off-verdict "$ERR_CORR_VERDICT" ""
check e2e-off-note    "$(printf '%s' "$SECTION" | grep -c 'too long a span')" "0"
check e2e-off-genuine "$ERR_FATAL_GENUINE" "4"
ERROR_CORROBORATE_ENABLE=true

echo "corroborate_test: PASS=${PASS} FAIL=${FAIL}"
(( FAIL == 0 ))
