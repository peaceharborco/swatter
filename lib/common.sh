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

SCORE_WATCH=50
SCORE_TEMP=70
SCORE_PERM=85

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

OPERATOR_IPS=""
OPERATOR_ALLOW_FILE="/etc/swatter/allow.cidr"
MONITORING_RANGES_FILE="/etc/swatter/monitoring.cidr"
VERIFY_GOOD_CRAWLERS="true"
CLOUDFLARE_IPS_FILE="/etc/swatter/cloudflare.cidr"

CF_MODE="auto"
# Safe default: a false positive solves a challenge instead of being locked out.
# Must match the documented default in swatter.example.conf.
CF_ACTION="managed_challenge"
CF_RULE_PREFIX="swatter"
CF_CREDS_FILE="/etc/swatter/cloudflare.creds"
CF_DOMAINS_MAP="/etc/swatter/cf-domains.map"
# Web-server config files CF auto-detection greps for a mod_remoteip /
# CF-Connecting-IP block (a "behind Cloudflare" signal). cPanel/EA-Apache paths.
SWATTER_HTTPD_CF_GLOB="/etc/apache2/conf.d/*.conf /etc/apache2/conf.modules.d/*.conf /usr/local/apache/conf/includes/*.conf"

INTEL_PROVIDERS="ipsum spamhaus abuseipdb"
ABUSEIPDB_KEY=""
ABUSEIPDB_DAILY_QUOTA=1000
GREYNOISE_KEY=""
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
REPORT_FROM_NAME="Swatter"
REPORT_METHOD="sendmail"          # sendmail | sendgrid | brevo
SENDGRID_KEY_FILE=""
BREVO_API_KEY=""
BREVO_KEY_FILE=""

# Server error-log triage section (bundled /server-logs digest).
ERROR_DIGEST_ENABLE="false"
ERROR_DIGEST_LOG=""               # pre-consolidated log; empty = aggregate live
ERROR_FPM_GLOB="/opt/cpanel/ea-php8*/root/usr/var/log/php-fpm/error.log"
ERROR_MYSQL_GLOB="/var/lib/mysql/*.err"
ERROR_PHP_HOME_GLOB="/home"
ERROR_NOISE="prefetch request body failed|error reading status line from remote server|invalid URI path|Invalid method in request|no compatible SSL setup for policy|client denied by server configuration|Error dispatching request to"

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
    # Installed bad-path table takes precedence over the repo copy if present.
    if [[ -f /etc/swatter/badpaths.conf ]]; then
        BADPATHS_CONF=/etc/swatter/badpaths.conf
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
# Non-fatal predicate: 0 if the value looks like an IP or CIDR. Internal
# paths (store layer, sweeps) use this and degrade gracefully — a malformed
# token parsed out of a log line must never kill a run.
swatter_is_valid_ip_or_cidr() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || return 1
    # v4: optional /0-32 ; v6: optional /0-128 (loose on full v6 syntax but sufficient and much stricter on prefix len than original)
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/([0-9]|[12][0-9]|3[0-2]))?$ ]] && return 0
    [[ "$ip" =~ ^[0-9A-Fa-f:]+(/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$ ]] && return 0
    return 1
}

# Fatal wrapper for CLI entry points (why/unblock/allow), where the value came
# from the operator and a bad one should abort with a usage error.
swatter_validate_ip_or_cidr() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || die "IP or CIDR required"
    swatter_is_valid_ip_or_cidr "$ip" || die "not an IP or CIDR: ${ip}"
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
    export SWATTER_HAVE_JQ SWATTER_HAVE_CURL SWATTER_HAVE_SQLITE SWATTER_HAVE_CSF
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

# now_epoch is captured once per process and reused everywhere.
swatter_now() { printf '%s' "${SWATTER_NOW_EPOCH:-$(date -u +%s)}"; }
