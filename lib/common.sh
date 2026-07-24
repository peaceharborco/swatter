#!/usr/bin/env bash
# lib/common.sh — Swatter shared runtime: config, logging, locking, helpers.
#
# Sourced by bin/swatter and every other lib. Defines SWATTER_LIB_DIR and the
# defaults for every tunable, loads the operator config over them, and provides
# the logging/lock primitives the rest of the tool relies on.
#
# Conventions mirror the house style: `set -uo pipefail` (NOT -e — one failing
# source must not abort the run), TZ=UTC everywhere, a single now_epoch capture,
# and a flock re-exec so only one Swatter run touches state at a time.

# Resolve our own location so libs can find siblings regardless of cwd.
SWATTER_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SWATTER_ROOT_DIR="$(cd -- "${SWATTER_LIB_DIR}/.." && pwd)"
export SWATTER_LIB_DIR SWATTER_ROOT_DIR

export TZ=UTC

# ---------------------------------------------------------------------------
# Backend block return-code protocol — the single source of truth shared by the
# block_*.sh backends (producers) and _swatter_execute_block in score.sh
# (consumer). A backend's exit status tells the scorer how to audit a non-block:
#   OK      (0) block placed (or idempotent dup / dry-run)  -> real perm/temp
#   CAP     (2) per-run deny cap hit (deliberate throttle)   -> skipped-cap
#   CONFIG  (3) deterministic config gap (unmapped vhost /   -> skipped-config
#               missing token; never satisfied by retrying)
#   NOVHOST (4) no nameable target vhost in THIS window      -> skipped-novhost
#               (data-dependent; may resolve next scan — not a config error)
#   1 / other   genuine backend error (API/csf/ipset/tooling)-> failed
SWATTER_RC_CAP=2
SWATTER_RC_CONFIG=3
SWATTER_RC_NOVHOST=4

# ---------------------------------------------------------------------------
# Built-in defaults. The config file overrides any of these.
# ---------------------------------------------------------------------------
: "${SWATTER_CONF:=/etc/swatter/swatter.conf}"

SWATTER_MODE="report"
WINDOW_SECONDS=600
MIN_REQS=15
LOG_LEVEL="info"

DOMLOGS_GLOB="/etc/apache2/logs/domlogs/*"
ACCESS_LOG="/etc/apache2/logs/access_log"
ERROR_LOG="/etc/apache2/logs/error_log"
LFD_LOG="/var/log/lfd.log"
SEED_BYTES=5242880
MAX_BYTES_PER_FILE=209715200

# Local web ports whose live, non-Cloudflare sockets count as direct-to-origin
# evidence: a confirmed offender connecting here is bypassing Cloudflare, so it
# belongs on the CSF plane, not the (useless) CF challenge plane. Empty string
# disables the signal; an absent key in the config inherits this default.
DIRECT_WEB_PORTS="80 443"

: "${DIRECT_BACKEND:=csf}"
: "${IPSET_SAVE_FILE:=/etc/swatter/ipset.save}"

# Alert channels (all optional; Swatter runs fine with none configured).
: "${ALERT_EMAIL:=}"
: "${ALERT_SMS_TO:=}"
: "${TWILIO_SID:=}"
: "${TWILIO_FROM:=}"
: "${TWILIO_TOKEN_FILE:=}"
: "${ALERT_WEBHOOK_URL:=}"
: "${ALERT_WEBHOOK_FORMAT:=auto}"
: "${ALERT_REPEAT_TTL:=21600}"

# Outbound AbuseIPDB reporting (opt-in).
: "${ABUSEIPDB_REPORT:=false}"
: "${ABUSEIPDB_REPORT_TTL:=900}"
# Minimum action that triggers an AbuseIPDB report: 'perm' (default — only
# high-confidence repeat-offender / hard-intel bans, so a scoring false-positive or
# a swarm-corroborated temp is never reported as outbound reputational harm) or
# 'temp' (report first-seen temps too — the pre-2.9.4 behavior).
: "${ABUSEIPDB_REPORT_MIN_ACTION:=perm}"

SCORE_WATCH=50
SCORE_TEMP=70

W_RATE=18
W_ERR_RATIO=16
W_ERR_BURST=12
W_FANOUT=12
W_BADPATH=22
W_UA=6
W_POST_FLOOD=8
W_NOVHOST=6
W_REPUTATION=14
RATE_SAT=8

TTL_LADDER="3600 21600 86400 259200"
REPEAT_N=3
REPEAT_WINDOW_DAYS=7
CRITICAL_TTL_FLOOR=86400

MAX_BLOCKS_PER_RUN=25
MAX_CSF_DENIES_PER_RUN=10
ALLOWLIST_MAX_AGE_DAYS=7

# Durable retry of a block that hit a transient backend error (CF API 5xx/timeout,
# csf/ipset command failure). The intent is queued (sqlite pending_blocks) and
# re-driven each scan independent of whether the offender reappears in the log —
# without this a single-burst offender's failed block is silently, permanently
# dropped (ingest is cursor-based). An intent that never lands self-reaps after
# MAX_ATTEMPTS re-attempts or MAX_AGE_HOURS, whichever first. On a */5 cron, 12
# attempts ≈ 1h of retries; 24h is the hard ceiling.
PENDING_RETRY_MAX_ATTEMPTS=12
PENDING_RETRY_MAX_AGE_HOURS=24
# Cap durable retries re-driven per scan so a large queue (mass-outage recovery)
# can't consume the whole MAX_BLOCKS_PER_RUN budget and starve this scan's fresh
# offenders. Keep it below MAX_BLOCKS_PER_RUN; excess rows wait for the next scan.
PENDING_RETRY_MAX_PER_RUN=10

# Dual-plane hard-intel blocking: an IP whose threat-intel reputation is at or
# above INTEL_HARDBLOCK_MIN (Spamhaus DROP / AbuseIPDB emit 100) is never a
# legitimate visitor, so a fresh PERM block is applied on BOTH planes — the
# Cloudflare edge (proxied traffic) AND CSF (direct-to-origin on any port,
# incl. cPanel service ports). never_block + fail-closed still gate the CSF leg,
# so a CF edge range can never be CSF-denied. Set false to keep single-plane.
DUAL_PLANE_HARD_INTEL=true
INTEL_HARDBLOCK_MIN=100

OPERATOR_IPS=""
OPERATOR_ALLOW_FILE="/etc/swatter/allow.cidr"
MONITORING_RANGES_FILE="/etc/swatter/monitoring.cidr"
VERIFY_GOOD_CRAWLERS="true"
CLOUDFLARE_IPS_FILE="/etc/swatter/cloudflare.cidr"

CF_MODE="auto"
# Safe default: a false positive solves a challenge instead of being locked out.
# Must match the documented default in swatter.example.conf.
CF_ACTION="managed_challenge"
# Where a Cloudflare-plane rule lands. "zone" (default, backward-compatible) is
# smallest-blast-radius and needs only a zone-scoped token, but a scanner that
# rotates target vhosts is only challenged on the first zone it hit. "account"
# rules every CF account in the creds file at once (needs an account-scoped
# token) so the block matches Swatter's per-IP ledger. Must match the documented
# default in swatter.example.conf.
CF_SCOPE="zone"
CF_RULE_PREFIX="swatter"
CF_CREDS_FILE="/etc/swatter/cloudflare.creds"
CF_DOMAINS_MAP="/etc/swatter/cf-domains.map"
# Web-server config files CF auto-detection greps for a mod_remoteip /
# CF-Connecting-IP block (a "behind Cloudflare" signal). cPanel/EA-Apache paths.
SWATTER_HTTPD_CF_GLOB="/etc/apache2/conf.d/*.conf /etc/apache2/conf.modules.d/*.conf /usr/local/apache/conf/includes/*.conf"

: "${INTEL_PROVIDERS:=ipsum spamhaus abuseipdb greynoise projecthoneypot firehol_level1 blocklist_de cins greensnow dshield et_compromised}"
# Reject an intel CIDR feed (Spamhaus/listfeeds) whose entries are broader than
# these prefixes — poison/MITM guard against a 0.0.0.0/0-style line scoring every
# visitor as hard-intel. Legit DROP netblocks are /9 or smaller, so /8 v4 / /16 v6
# only catches abuse. See swatter_intel_cidr_feed_ok.
INTEL_FEED_MIN_PREFIX4=8
INTEL_FEED_MIN_PREFIX6=16
: "${ABUSEIPDB_BLOCKLIST_CONFIDENCE:=90}"
ABUSEIPDB_KEY=""
ABUSEIPDB_DAILY_QUOTA=1000
: "${GREYNOISE_KEY:=}"
: "${GREYNOISE_DAILY_QUOTA:=100}"
: "${HTTPBL_KEY:=}"
# File-based alternatives to the inline keys above (0400, like SENDGRID_KEY_FILE /
# the Twilio / swarm tokens) so an operator can keep API keys OUT of swatter.conf.
# If set + readable, the file wins over the inline value. Resolved in
# swatter_load_config; the key never leaves a shell var (never exported).
: "${ABUSEIPDB_KEY_FILE:=}"
: "${GREYNOISE_KEY_FILE:=}"
: "${HTTPBL_KEY_FILE:=}"
: "${ASN_SIGNAL_ENABLE:=false}"
: "${HOSTING_ASNS_FILE:=/etc/swatter/hosting-asns.txt}"
: "${W_ASN:=12}"
: "${HONEYPOT_PATHS_FILE:=/etc/swatter/honeypot.paths}"
: "${HONEYPOT_OVERRIDES_SUPPRESS:=false}"
: "${PERSIST_ENABLE:=true}"
: "${PERSIST_N:=6}"
: "${PERSIST_WINDOW_DAYS:=3}"
: "${PERSIST_BUCKET_SECONDS:=3600}"
: "${METRICS_FILE:=/var/lib/node_exporter/textfile_collector/swatter.prom}"

# --- Swarm (fleet reputation sharing; subsystem 2 host side; ALL inert by default)
# Consume additionally requires adding `swarm` to INTEL_PROVIDERS.
: "${SWARM_ENABLE:=false}"
: "${SWARM_HUB_URL:=}"
: "${SWARM_WRITE_TOKEN_FILE:=/etc/swatter/swarm.write.token}"
: "${SWARM_READ_TOKEN_FILE:=/etc/swatter/swarm.read.token}"
: "${SWARM_ENROLL_TOKEN_FILE:=}"
# Per-host write token, issued by the hub at `swatter swarm enroll` and stored 0600
# HERE (not operator-managed). Preferred over the shared SWARM_WRITE_TOKEN_FILE for
# publish/purge once present — binds this box's writes to its own identity. Empty =
# resolve to ${STATE_DIR}/swarm.host_token at use time (STATE_DIR isn't known yet
# here; mirrors swarm.host_id).
: "${SWARM_HOST_TOKEN_FILE:=}"
: "${SWARM_PUBLISH:=true}"
: "${SWARM_ACTION:=boost}"
: "${SWARM_MIN_CORROBORATION:=2}"
: "${SWARM_BASE_SCORE:=70}"
: "${SWARM_ALLOW_FILE:=/etc/swatter/swarm.allow.cidr}"
: "${SWARM_MAX_AGE_DAYS:=3}"

INTEL_CACHE_TTL=86400

STORE="sqlite"
STATE_DIR="/var/lib/swatter"
LOG_DIR="/var/log/swatter"
NOTIFY_EMAIL=""

# Nightly report + delivery. Defaulted here so referencing them under `set -u`
# never aborts on a trimmed/older config.
REPORT_EMAIL=""
REPORT_WINDOW="24h"
REPORT_FROM="swatter@localhost"
# Display name on the From header. Templated with the server's FQDN so a multi-box
# fleet self-labels (e.g. "Swatter [cds1.example.com]") with no per-host edit. The
# subject line is computed per-report (see _report_subject) — not configurable.
# NOTE: brackets, not parentheses — in an email From header RFC 5322 treats "(...)"
# as a COMMENT that clients strip, so "Swatter (host)" would display as just
# "Swatter". Brackets are not comment delimiters and display verbatim.
REPORT_FROM_NAME="Swatter [$(hostname -f 2>/dev/null || hostname)]"
REPORT_METHOD="sendmail"          # sendmail | sendgrid | brevo
SENDGRID_KEY_FILE=""
BREVO_API_KEY=""
BREVO_KEY_FILE=""
# Header logo on the HTML report. Blank = the Peace Harbor Studios lockup;
# operators may point these at their own company logo (the footer branding is
# part of the project and is not configurable).
REPORT_LOGO_URL=""
REPORT_LOGO_ALT=""
# Triage-command hint shown in the recommendation line on a non-clean report
# (e.g. "/server-logs" for an operator who has that tool). Blank = generic wording
# ("Review the sections below") so the public default suggests nothing bespoke.
REPORT_TRIAGE_HINT=""
# Status thresholds (traffic light GREEN/YELLOW/RED). Tunable per host. RED = any
# GENUINE fatal error — fatals classified scanner-induced by ERROR_FATAL_SCANNER
# (below) don't trip it. Only ELEVATED non-fatal error volume turns the status
# YELLOW — routine noise and a high block count stay GREEN (blocks mean Swatter
# is doing its job, not a problem). The two thresholds keep their historical names.
REPORT_GRADE_D_ERRORS=300         # >= this many non-fatal errors -> YELLOW "act now" wording (error flood)
REPORT_GRADE_C_ERRORS=100         # >= this many non-fatal errors -> YELLOW (elevated, investigate)

# SMS alert on a RED status — a SECOND channel alongside the email (the email
# always sends too). OFF by default. Fail-soft: never blocks the report.
ALERT_SMS_METHOD=""               # "twilio" to enable; "" = off
ALERT_SMS_GRADES="RED"            # statuses that trigger an SMS (GREEN/YELLOW/RED)
ALERT_SMS_TO=""                   # destination number, E.164 (+15551234567)
ALERT_SMS_DEDUP_HOURS=6           # suppress a duplicate same-status text within N hours
TWILIO_SID=""                     # Twilio Account SID
TWILIO_TOKEN_FILE=""              # path to a file holding the auth token (mode 0400)
TWILIO_FROM=""                    # Twilio sender number, E.164

# Server error-log triage section (bundled error digest).
ERROR_DIGEST_ENABLE="false"
ERROR_DIGEST_LOG=""               # pre-consolidated log; empty = aggregate live

# Origin-lock digest plane (nightly report). auto = render when the window has
# ORIGIN-LOCK: hits (works for the standalone csfpre.sh lock AND the inline lock);
# on = always; off = never. ORIGIN_LOCK_LOG empty = /var/log/messages* (Debian: syslog).
ORIGIN_LOCK_DIGEST="auto"
ORIGIN_LOCK_LOG=""

# Nightly report schedule. install.sh writes /etc/cron.d/swatter from these.
# REPORT_CRON is "minute hour". REPORT_CRON_TZ is the delivery timezone (IANA);
# empty = the server clock (UTC on a normal server). Set it to deliver at a true
# local wall-clock hour, DST-aware via cron's CRON_TZ.
REPORT_CRON="0 4"
REPORT_CRON_TZ=""

ERROR_FPM_GLOB="/opt/cpanel/ea-php8*/root/usr/var/log/php-fpm/error.log"
ERROR_MYSQL_GLOB="/var/lib/mysql/*.err"
ERROR_PHP_HOME_GLOB="/home"
ERROR_NOISE="prefetch request body failed|error reading status line from remote server|invalid URI path|Invalid method in request|no compatible SSL setup for policy|client denied by server configuration|Error dispatching request to"

# Fatals matching this pattern that repeat fewer than REPEATS times in the
# window are scanner-induced (a bot executing a PHP file directly, outside the
# app bootstrap) and do not trip RED — real breakage of the same shape repeats
# on every page view and crosses the threshold. TRADE-OFF: a genuine one-off
# fatal of this shape on a near-zero-traffic site rides below the threshold
# until it repeats; set REPEATS=1 to disable the classifier if that trade is
# wrong for the box.
ERROR_FATAL_SCANNER='PHP Fatal error: Uncaught Error: (Call to undefined function|Undefined constant)'
ERROR_FATAL_SCANNER_REPEATS=3

# The bad-path table ships with the repo by default; installs relocate it.
BADPATHS_CONF="${BADPATHS_CONF:-${SWATTER_ROOT_DIR}/config/badpaths.conf}"

# ---------------------------------------------------------------------------
# Load operator config (if present). Sourced, so it is plain shell.
# ---------------------------------------------------------------------------
swatter_load_config() {
    if [[ -f "${SWATTER_CONF}" ]]; then
        # shellcheck disable=SC1090
        source "${SWATTER_CONF}"
    fi
    # Resolve file-based API keys AFTER the conf load: a *_KEY_FILE (0400) keeps the
    # key out of the 0600 conf. File wins over the inline value; the key stays a
    # plain shell var (never exported into the environment). A single trailing
    # newline is stripped (the common `echo key > file` form).
    local _kv _kf _kval
    for _kv in ABUSEIPDB_KEY GREYNOISE_KEY HTTPBL_KEY; do
        _kf="${_kv}_FILE"
        # Only override the inline key from a REGULAR, readable file that yields a
        # NON-EMPTY value — an empty file, a directory (which is `-r`), or a failed
        # read must keep the inline key, never blank it. Strip all whitespace so a
        # CRLF / trailing-newline key file can't 401 the provider.
        if [[ -n "${!_kf:-}" && -f "${!_kf}" && -r "${!_kf}" ]]; then
            _kval="$(tr -d '[:space:]' < "${!_kf}" 2>/dev/null)"
            [[ -n "$_kval" ]] && printf -v "$_kv" '%s' "$_kval"
        fi
    done
    # Installed bad-path table takes precedence over the repo copy if present.
    if [[ -f /etc/swatter/badpaths.conf ]]; then
        BADPATHS_CONF=/etc/swatter/badpaths.conf
    fi

    # Escalation knobs are interpolated straight into bash arithmetic
    # (lib/score.sh's `prior + 1 >= REPEAT_N`, lib/store_sqlite.sh's window
    # subtraction), where a malformed value fails SILENTLY and in opposite
    # directions: an empty REPEAT_WINDOW_DAYS yields a 0-day window (escalation
    # never fires — fail-safe), but an empty REPEAT_N makes (( 1 >= 0 )) true, so
    # EVERY first offense becomes a permanent ban. Validate here — the end of the
    # conf load — so an operator typo cannot bypass it, and both the sqlite and
    # flatfile counting paths are covered (they read the same globals).
    # A leading-zero numeral (e.g. "020") passes the ^[0-9]+$ regex but bash's
    # `(( ))` parses it as OCTAL, not decimal — "020" is 16, "030" is 24, and
    # "089"/"099" outright throw "value too great for base" (invalid octal
    # digit), which would abort the bounds check with no log_warn and let the
    # raw string through. Force base-10 with `10#` for the bounds check AND
    # reassign the canonical decimal value, so no downstream plain `(( ))`
    # (lib/score.sh, lib/store_sqlite.sh) ever re-parses a leading-zero string.
    local _n
    _n="${REPEAT_N:-}"
    if [[ "$_n" =~ ^[0-9]+$ ]] && (( 10#$_n >= 1 && 10#$_n <= 20 )); then
        REPEAT_N=$(( 10#$_n ))
    else
        log_warn "REPEAT_N='${_n}' invalid (want integer 1-20); using 3"
        REPEAT_N=3
    fi
    _n="${REPEAT_WINDOW_DAYS:-}"
    if [[ "$_n" =~ ^[0-9]+$ ]] && (( 10#$_n >= 1 && 10#$_n <= 90 )); then
        REPEAT_WINDOW_DAYS=$(( 10#$_n ))
    else
        log_warn "REPEAT_WINDOW_DAYS='${_n}' invalid (want integer 1-90); using 7"
        REPEAT_WINDOW_DAYS=7
    fi
}

# ---------------------------------------------------------------------------
# Logging. Numeric levels gate output; everything goes to stderr so cron with
# MAILTO="" discards it while interactive runs stay observable. The structured
# decision log is separate (see lib/score.sh / decisions.jsonl).
# ---------------------------------------------------------------------------
_loglevel_num() {
    case "$1" in
        debug) echo 10 ;; info) echo 20 ;; warn) echo 30 ;; error) echo 40 ;;
        *) echo 20 ;;
    esac
}
ts() { date -u '+%Y-%m-%d %H:%M:%S'; }
_log() {
    local lvl="$1"; shift
    local want cur
    want="$(_loglevel_num "$lvl")"
    cur="$(_loglevel_num "${LOG_LEVEL}")"
    (( want < cur )) && return 0
    printf '[%s] [%s] %s\n' "$(ts)" "${lvl^^}" "$*" >&2
}
log_debug() { _log debug "$@"; }
log_info()  { _log info  "$@"; }
log_warn()  { _log warn  "$@"; }
log_error() { _log error "$@"; }
die()       { log_error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Input sanitization / validation helpers. Used to keep CLI safe and to
# guarantee that values interpolated into shell/SQL/grep are harmless.
# The IP/CIDR regex is intentionally identical to the one previously only in
# cmd_allow so behavior is unchanged for valid inputs.
# ---------------------------------------------------------------------------
# Structural IPv6 validity (no prefix): hex/colon charset, at most one '::',
# groups of 1-4 hex digits, exactly 8 groups uncompressed / at most 7 with '::'.
# A trailing embedded IPv4 (e.g. ::ffff:192.0.2.1) is a legit textual form — the
# dotted quad counts as the final TWO 16-bit groups, so its bound is one lower.
# Self-contained so common.sh stays dependency-free.
_swatter_valid_ipv6() {
    local a="${1,,}" L="" R="" g n v4groups=0
    # Split off a trailing dotted-quad tail, validate it as an IPv4 (octets
    # 0-255), and treat it as two hex groups for the group-count bounds.
    if [[ "$a" == *.* ]]; then
        local tail="${a##*:}" head="${a%:*}"
        [[ "$a" == *:* ]] || return 1
        [[ "$tail" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || return 1
        a="${head}:0"      # placeholder single group; we add 2 to the count below
        v4groups=2
    fi
    [[ "$a" =~ ^[0-9a-f:]+$ ]] || return 1
    if [[ "$a" == *::* ]]; then
        [[ "$a" == *:::* || "${a#*::}" == *::* ]] && return 1   # ':::' / two '::'
        L="${a%%::*}"; R="${a#*::}"
    else
        [[ "$a" == :* || "$a" == *: ]] && return 1   # bare edge colon needs '::'
        L="$a"
    fi
    local -a lg=() rg=()
    IFS=: read -ra lg <<<"$L"; IFS=: read -ra rg <<<"$R"
    for g in ${lg[@]+"${lg[@]}"} ${rg[@]+"${rg[@]}"}; do
        [[ "$g" =~ ^[0-9a-f]{1,4}$ ]] || return 1
    done
    # -1 for the "0" placeholder that stood in for the v4 tail, +2 for the quad.
    n=$(( ${#lg[@]} + ${#rg[@]} - (v4groups > 0 ? 1 : 0) + v4groups ))
    if [[ "$a" == *::* ]]; then (( n <= 7 )); else (( n == 8 )); fi
}

# Non-fatal predicate: 0 if the value is a REAL IP or CIDR — v4 octets bounded
# 0-255, v6 structurally valid, prefix lengths bounded per family. This is the
# authoritative gate: score.awk's charset pre-filter is deliberately loose (it
# only guarantees no shell-meaningful bytes), so the block path and store layer
# rely on THIS to keep garbage tokens away from csf/ipset/CF. Internal paths
# use it and degrade gracefully — a malformed token parsed out of a log line
# must never kill a run.
swatter_is_valid_ip_or_cidr() {
    local ip="${1:-}" addr plen=""
    [[ -n "$ip" ]] || return 1
    addr="${ip%%/*}"
    if [[ "$ip" == */* ]]; then
        plen="${ip#*/}"
        [[ "$ip" == "${addr}/${plen}" && -n "$addr" ]] || return 1   # exactly one '/'
    fi
    if [[ "$addr" == *:* ]]; then
        _swatter_valid_ipv6 "$addr" || return 1
        [[ -z "$plen" ]] || [[ "$plen" =~ ^([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$ ]] || return 1
    else
        [[ "$addr" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || return 1
        [[ -z "$plen" ]] || [[ "$plen" =~ ^([0-9]|[12][0-9]|3[0-2])$ ]] || return 1
    fi
    return 0
}

# A syntactically-valid IP/CIDR that is CATASTROPHIC as a block target: a /0
# prefix (denies the whole internet) or an unspecified address (0.0.0.0 / ::).
# The general validator stays permissive because it also gates allow-lists,
# never-block CIDR files, and feed downloads where these forms are harmless — so
# the "never block this" call belongs at the block SINKS, not in the validator.
# 0 (true) = unsafe, do not block.
_swatter_is_unsafe_block_target() {
    local t="${1:-}" addr
    addr="${t%%/*}"
    [[ "$t" == */* && "${t#*/}" == "0" ]] && return 0   # /0 = entire internet
    case "$addr" in
        0.0.0.0|::|0:0:0:0:0:0:0:0) return 0 ;;          # unspecified address
    esac
    return 1
}

# Fatal wrapper for CLI entry points (why/unblock/allow), where the value came
# from the operator and a bad one should abort with a usage error.
swatter_validate_ip_or_cidr() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || die "IP or CIDR required"
    swatter_is_valid_ip_or_cidr "$ip" || die "not an IP or CIDR: ${ip}"
}

# Validate a downloaded range list (stdin): at least one line, and EVERY
# non-blank line a valid IP/CIDR. Guards feed installs against a 200 whose body
# is an HTML error page / captive portal — critical for cloudflare.cidr, which
# gates the never-block set (a poisoned file could let a CF edge be CSF-denied).
swatter_cidr_list_ok() {
    local line n=0
    # `|| [[ -n "$line" ]]` so a final line WITHOUT a trailing newline is still
    # validated — otherwise a poisoned last line (captive-portal HTML with no
    # closing newline) would be silently DROPPED and the list would falsely pass.
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"; line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        swatter_is_valid_ip_or_cidr "$line" || return 1
        n=$(( n + 1 ))
    done
    (( n > 0 ))
}

# Stricter validator for a downloaded INTEL CIDR feed (Spamhaus DROP, listfeeds
# cidr/dshield): stdin must be non-empty and EVERY line a valid IP/CIDR that is
# NOT dangerously broad. An intel match scores the IP as hard-intel and blocks it,
# so a poisoned / MITM'd feed line like 0.0.0.0/0 — or a huge ISP block — would
# score every visitor 100 and mass-ban innocents. Rejects the WHOLE feed (return 1)
# on any invalid or over-broad line so refresh keeps the last-good file. Floors are
# configurable; defaults reject anything broader than a /8 (v4) or /16 (v6) — legit
# DROP netblocks are /9 and smaller, so this only catches poison.
swatter_intel_cidr_feed_ok() {
    local line n=0 addr plen o1 min4="${INTEL_FEED_MIN_PREFIX4:-8}" min6="${INTEL_FEED_MIN_PREFIX6:-16}"
    [[ "$min4" =~ ^[0-9]+$ ]] || min4=8
    [[ "$min6" =~ ^[0-9]+$ ]] || min6=16
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"; line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        swatter_is_valid_ip_or_cidr "$line" || return 1
        if [[ "$line" == */* ]]; then
            addr="${line%%/*}"; plen="${line#*/}"
            [[ "$plen" =~ ^[0-9]+$ ]] || return 1
            (( plen == 0 )) && return 1   # /0 or ::/0 matches EVERY visitor — poison
            # The width floor only guards GLOBAL-UNICAST space, where real visitors
            # live. Bogon / multicast / reserved supernets are broad but can never be
            # a real visitor's source, so a legit feed legitimately ships them (e.g.
            # firehol_level1 includes 224.0.0.0/3) — don't reject the feed over them.
            # v4 global unicast ~ first octet 1-223; v6 global unicast = 2000::/3.
            if [[ "$addr" == *:* ]]; then
                case "$addr" in [23]*) (( plen < min6 )) && return 1 ;; esac
            else
                o1="${addr%%.*}"
                [[ "$o1" =~ ^[0-9]+$ ]] && (( o1 >= 1 && o1 <= 223 )) && (( plen < min4 )) && return 1
            fi
        fi
        n=$(( n + 1 ))
    done
    (( n > 0 ))
}

# ---------------------------------------------------------------------------
# Dependency checks. Hard deps abort; optional deps just disable a feature.
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# Portable stat (GNU `-c` on Linux, BSD `-f` on macOS/FreeBSD).
stat_inode() { stat -c %i "$1" 2>/dev/null || stat -f %i "$1" 2>/dev/null; }
stat_size()  { stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null; }
stat_mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null; }

swatter_check_deps() {
    local missing=()
    have gawk || missing+=(gawk)
    # flock guards against overlapping cron runs; only required when locking is
    # enabled (it is by default). SWATTER_NO_LOCK=1 waives both the lock and the
    # requirement (used by tests / single-shot invocations).
    if [[ "${SWATTER_NO_LOCK:-}" != "1" ]]; then
        have flock || missing+=(flock)
    fi
    if (( ${#missing[@]} )); then
        die "missing required dependencies: ${missing[*]}"
    fi
    # Optional — record availability for callers to branch on.
    SWATTER_HAVE_JQ=0;      have jq      && SWATTER_HAVE_JQ=1
    SWATTER_HAVE_CURL=0;    have curl    && SWATTER_HAVE_CURL=1
    SWATTER_HAVE_SQLITE=0;  have sqlite3 && SWATTER_HAVE_SQLITE=1
    SWATTER_HAVE_CSF=0;     have csf     && SWATTER_HAVE_CSF=1
    if have ipset && have iptables; then SWATTER_HAVE_IPSET=1; else SWATTER_HAVE_IPSET=0; fi
    SWATTER_HAVE_IP6TABLES=0; have ip6tables && SWATTER_HAVE_IP6TABLES=1   # gates IPv6 ipset DROP rule
    export SWATTER_HAVE_JQ SWATTER_HAVE_CURL SWATTER_HAVE_SQLITE SWATTER_HAVE_CSF SWATTER_HAVE_IPSET SWATTER_HAVE_IP6TABLES
    # DNS client for the DNS-based lookups (http:BL, Team Cymru ASN). Optional.
    if have dig; then SWATTER_HAVE_DNS=1; SWATTER_DNS_TOOL="dig"
    elif have host; then SWATTER_HAVE_DNS=1; SWATTER_DNS_TOOL="host"
    elif have nslookup; then SWATTER_HAVE_DNS=1; SWATTER_DNS_TOOL="nslookup"
    else SWATTER_HAVE_DNS=0; SWATTER_DNS_TOOL=""; fi
    export SWATTER_HAVE_DNS SWATTER_DNS_TOOL
    # Fall back to flatfile if sqlite was requested but is unavailable.
    if [[ "${STORE}" == "sqlite" && "${SWATTER_HAVE_SQLITE}" -eq 0 ]]; then
        log_warn "sqlite3 not found; falling back to flatfile store"
        STORE="flatfile"
    fi
}

# _swatter_dns_a <hostname> : echo the first A-record dotted-quad, or nothing.
_swatter_dns_a() {
    local name="$1"
    case "${SWATTER_DNS_TOOL}" in
        dig)      dig +short +time=3 +tries=1 A "$name" 2>/dev/null | awk '/^[0-9]+\./{print; exit}' ;;
        host)     host -W 3 -t A "$name" 2>/dev/null | awk '/has address/{print $NF; exit}' ;;
        nslookup) nslookup -type=A "$name" 2>/dev/null | awk '/^Address: /{print $2; exit}' ;;
    esac
}

# _swatter_dns_txt <hostname> : echo the first TXT record (quotes stripped), or nothing.
_swatter_dns_txt() {
    local name="$1"
    case "${SWATTER_DNS_TOOL}" in
        dig)      dig +short +time=3 +tries=1 TXT "$name" 2>/dev/null | head -1 | sed 's/^"//; s/"$//' ;;
        host)     host -W 3 -t TXT "$name" 2>/dev/null | sed -n 's/.*descriptive text "\(.*\)"$/\1/p' | head -1 ;;
        nslookup) nslookup -type=TXT "$name" 2>/dev/null | sed -n 's/.*text = "\(.*\)"$/\1/p' | head -1 ;;
    esac
}

# ---------------------------------------------------------------------------
# State/dir bootstrap. Idempotent; safe every run.
# ---------------------------------------------------------------------------
swatter_init_dirs() {
    local d
    for d in "${STATE_DIR}" "${STATE_DIR}/intel" "${STATE_DIR}/feeds" "${LOG_DIR}"; do
        [[ -d "$d" ]] || mkdir -p "$d" 2>/dev/null || die "cannot create $d"
    done
    chmod 0750 "${STATE_DIR}" "${LOG_DIR}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Single-run lock via flock re-exec. Call once, early, from the entrypoint.
# Honors SWATTER_NO_LOCK=1 for tests.
# ---------------------------------------------------------------------------
swatter_acquire_lock() {
    [[ "${SWATTER_NO_LOCK:-}" == "1" ]] && return 0
    local lock="${STATE_DIR}/.lock"
    if [[ "${SWATTER_LOCK_HELD:-}" != "1" ]]; then
        exec env SWATTER_LOCK_HELD=1 flock -n "${lock}" "${SWATTER_ENTRYPOINT}" "${SWATTER_ARGV[@]}"
        exit 0   # only reached if the lock was already held
    fi
}

# Blocking state lock for a mutating operator command (unblock, import-bans, the
# swarm sweep) so it cannot race the */5 scan on cf-rules.tsv / the sqlite ledger /
# the firewall. Takes the SAME lock file the scan's non-blocking flock re-exec
# uses, so the two are mutually exclusive. Blocks up to <wait>s (default 30) for a
# running scan to finish; RETURNS non-zero if it still can't get the lock so the
# caller decides whether to die (operator mutation) or skip (opt-in sweep). No-op
# (rc 0) if SWATTER_NO_LOCK=1 or flock is unavailable (e.g. a macOS dev box — tests
# run single-threaded). Uses a fixed fd (9), held until the process exits, for bash
# 3.2 portability (no dynamic {fd} assignment).
swatter_with_state_lock() {
    [[ "${SWATTER_NO_LOCK:-}" == "1" ]] && return 0
    have flock || return 0
    local wait="${1:-30}"; [[ "$wait" =~ ^[0-9]+$ ]] || wait=30
    exec 9>"${STATE_DIR}/.lock" 2>/dev/null || return 0
    flock -w "$wait" 9
}

# now_epoch is captured once per process and reused everywhere.
swatter_now() { printf '%s' "${SWATTER_NOW_EPOCH:-$(date -u +%s)}"; }

# ---------------------------------------------------------------------------
# Secret-safe curl. Credential-bearing options (header = "...", user = "...")
# go into a 0600 config file consumed via `curl -K <file>`, never into argv:
# /proc/<pid>/cmdline is world-readable, so on a shared box any local user
# running `ps` during a scan would see the raw bearer token / API key.
# Echoes the file path; the CALLER must rm -f it right after the curl returns.
# Values must not contain double-quotes (tokens/keys never do).
#   cfg="$(swatter_curl_cfg 'header = "Authorization: Bearer TOK"')" || return 1
# ---------------------------------------------------------------------------
swatter_curl_cfg() {
    local f line dir="${STATE_DIR:-}/.curlcfg"
    # Keep the secret-bearing cfg under STATE_DIR (0750 root:root), NOT world-shared
    # /tmp — a leftover from a mid-request SIGKILL (which no EXIT trap can catch)
    # would otherwise be a 0600 file readable by anyone who can list /tmp on a shared
    # box. Stale orphans here are swept by swatter_state_gc. Fall back to TMPDIR only
    # if STATE_DIR is unusable (early/no-state contexts).
    if [[ -n "${STATE_DIR:-}" ]] && mkdir -p "$dir" 2>/dev/null && chmod 0700 "$dir" 2>/dev/null && [[ -w "$dir" ]]; then
        f="$(mktemp "${dir}/curl.XXXXXX")" || return 1
    else
        f="$(mktemp "${TMPDIR:-/tmp}/swatter-curl.XXXXXX")" || return 1
    fi
    chmod 0600 "$f" 2>/dev/null
    for line in "$@"; do printf '%s\n' "$line" >> "$f"; done
    printf '%s' "$f"
}

# Sweep stale on-disk state a long-running box accretes: orphaned curl cfg files
# (from a SIGKILL mid-request), and per-IP intel + crawler cache entries older than
# their TTL. Bounded find over STATE_DIR; safe to call every refresh-feeds (daily).
# Never touches live files (age-gated), so it can't race a concurrent run's writes.
swatter_state_gc() {
    [[ -n "${STATE_DIR:-}" && -d "${STATE_DIR}" ]] || return 0
    # Orphaned curl cfg files (each caller rm's its own; only a SIGKILL leaves one) —
    # anything older than a day is definitely dead.
    [[ -d "${STATE_DIR}/.curlcfg" && ! -L "${STATE_DIR}/.curlcfg" ]] && find "${STATE_DIR}/.curlcfg" -type f -mtime +1 -delete 2>/dev/null
    # Per-IP intel + crawler cache: one file per IP, never GC'd before. Drop entries
    # untouched for longer than the cache would ever be honoured (max of the intel
    # TTLs, +1 day slack), so the working set stays bounded without evicting live ones.
    local maxttl="${INTEL_CACHE_TTL:-86400}"
    [[ "${INTEL_FAIL_TTL:-0}"  =~ ^[0-9]+$ ]] && (( INTEL_FAIL_TTL  > maxttl )) && maxttl="${INTEL_FAIL_TTL}"
    local days=$(( maxttl / 86400 + 1 ))
    [[ -d "${STATE_DIR}/intel" && ! -L "${STATE_DIR}/intel" ]] && find "${STATE_DIR}/intel" -type f -mtime "+${days}" -delete 2>/dev/null
    return 0
}
