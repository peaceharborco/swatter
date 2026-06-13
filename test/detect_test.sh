#!/usr/bin/env bash
# test/detect_test.sh — Cloudflare auto-detection + fail-closed gating.
#
# Covers the "either/or" support: Swatter must work on a box that is NOT behind
# Cloudflare. No network, no root, no firewall. The DNS resolver is dependency-
# injected (we override _swatter_resolve_host), and every other signal reads a
# fixture file under a temp dir. Run: bash test/detect_test.sh

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"

# shellcheck source=../lib/common.sh
source "${ROOT}/lib/common.sh"
# shellcheck source=../lib/allowlist.sh
source "${ROOT}/lib/allowlist.sh"
# shellcheck source=../lib/classify.sh
source "${ROOT}/lib/classify.sh"

PASS=0; FAIL=0
ok()   { printf 'PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf 'FAIL  %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
assert_eq() { [[ "$2" == "$3" ]] && ok "$1" || bad "$1" "got '$2' want '$3'"; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/swatter-detect.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# A real Cloudflare IPv4 range + an address inside it, and a non-CF address.
CF_RANGE="173.245.48.0/20"
CF_IP="173.245.48.5"
NONCF_IP="203.0.113.7"

# Fresh CF range list (mtime = now, so swatter_allowlist_healthy passes).
ranges="$tmp/cloudflare.cidr"
printf '%s\n' "$CF_RANGE" > "$ranges"

# Reset all detection-input config to empty/neutral before each case so signals
# don't leak between tests. A fresh per-case dir is wiped each time; the caller
# then populates only the files a given signal needs.
reset_inputs() {
    rm -rf "$tmp/case"; mkdir -p "$tmp/case/httpd" "$tmp/case/domlogs"
    CF_DOMAINS_MAP="$tmp/case/domains.map";  : > "$CF_DOMAINS_MAP"
    CF_CREDS_FILE="$tmp/case/creds";         : > "$CF_CREDS_FILE"
    SWATTER_HTTPD_CF_GLOB="$tmp/case/httpd/*.conf"
    LFD_LOG="$tmp/case/lfd.log";             : > "$LFD_LOG"
    DOMLOGS_GLOB="$tmp/case/domlogs/*"
    CLOUDFLARE_IPS_FILE="$ranges"
    STATE_DIR="$tmp/state"; mkdir -p "$STATE_DIR"
    # Default resolver: everything fails to resolve (no signal).
    _swatter_resolve_host() { :; }
}

verdict_of() { swatter_compute_cf_verdict | cut -f1; }

# --- compute_cf_verdict: operator config is definitive -----------------------
reset_inputs
printf 'example.com\tacctA\n' > "$CF_DOMAINS_MAP"
assert_eq "domains-map-present -> behind" "$(verdict_of)" "behind"

reset_inputs
printf 'acctA\ttoken123\n' > "$CF_CREDS_FILE"
assert_eq "creds-present -> behind" "$(verdict_of)" "behind"

# A map with only comments/blank lines is NOT a signal.
reset_inputs
printf '# header only\n\n' > "$CF_DOMAINS_MAP"
assert_eq "empty-map -> not behind via op-config" "$(verdict_of)" "uncertain"

# --- compute_cf_verdict: web-server config references Cloudflare -------------
reset_inputs
mkdir -p "$tmp/case/httpd"
printf 'RemoteIPHeader CF-Connecting-IP\n' > "$tmp/case/httpd/remoteip.conf"
assert_eq "httpd-cf-config -> behind" "$(verdict_of)" "behind"

# --- compute_cf_verdict: inbound socket in a CF range (lfd) ------------------
reset_inputs
printf 'Jun 13 10:00:00 host lfd[1]: connection from %s\n' "$CF_IP" > "$LFD_LOG"
assert_eq "lfd-socket-in-cf-range -> behind" "$(verdict_of)" "behind"

reset_inputs
printf 'Jun 13 10:00:00 host lfd[1]: connection from %s\n' "$NONCF_IP" > "$LFD_LOG"
assert_eq "lfd-socket-not-cf -> uncertain" "$(verdict_of)" "uncertain"

# --- compute_cf_verdict: DNS of the box's own vhosts -------------------------
# A vhost that resolves into a CF range => behind.
reset_inputs
mkdir -p "$tmp/case/domlogs"
: > "$tmp/case/domlogs/proxied.com"
_swatter_resolve_host() { [[ "$1" == "proxied.com" ]] && printf '%s\n' "$CF_IP"; }
assert_eq "vhost-resolves-to-cf -> behind" "$(verdict_of)" "behind"

# Vhosts that resolve, none to CF => not-behind (the consequential conclusion).
reset_inputs
mkdir -p "$tmp/case/domlogs"
: > "$tmp/case/domlogs/origin.com"
: > "$tmp/case/domlogs/origin.com-ssl_log"   # ssl sibling collapses to one host
_swatter_resolve_host() { printf '%s\n' "$NONCF_IP"; }
assert_eq "vhosts-resolve-no-cf -> not-behind" "$(verdict_of)" "not-behind"

# Nothing resolves and no other signal => uncertain (safe).
reset_inputs
mkdir -p "$tmp/case/domlogs"
: > "$tmp/case/domlogs/unknown.com"
assert_eq "no-resolution -> uncertain" "$(verdict_of)" "uncertain"

# --- swatter_cf_in_use honors CF_MODE + cached verdict -----------------------
reset_inputs
CF_MODE="off";    swatter_cf_in_use && bad "off -> not in use" "returned in-use" || ok "off -> not in use"
CF_MODE="direct"; swatter_cf_in_use && ok "direct+ranges -> in use" || bad "direct+ranges -> in use" "returned not-in-use"

# auto reads the cached verdict.
CF_MODE="auto"
printf 'not-behind\t0\tdns\n' > "$STATE_DIR/cf-detect"
swatter_cf_in_use && bad "auto+not-behind -> not in use" "returned in-use" || ok "auto+not-behind -> not in use"
printf 'behind\t0\tmap\n' > "$STATE_DIR/cf-detect"
swatter_cf_in_use && ok "auto+behind -> in use" || bad "auto+behind -> in use" "returned not-in-use"
rm -f "$STATE_DIR/cf-detect"
swatter_cf_in_use && ok "auto+no-verdict+ranges -> in use (safe)" || bad "auto+no-verdict -> in use" "returned not-in-use"

# --- fail-closed only engages when Cloudflare is in use ----------------------
# direct mode + missing ranges => fail closed (regression guard for the outage
# safety property).
reset_inputs
CF_MODE="direct"; CLOUDFLARE_IPS_FILE="$tmp/missing.cidr"
swatter_failclosed_active && ok "direct+missing-ranges -> fail closed" || bad "direct+missing -> fail closed" "not active"
# direct mode + fresh ranges => not fail closed.
CLOUDFLARE_IPS_FILE="$ranges"
swatter_failclosed_active && bad "direct+fresh -> not fail closed" "active" || ok "direct+fresh -> not fail closed"
# off mode + missing ranges => NOT fail closed (the bug we are fixing: a non-CF
# box must still issue CSF denies).
CF_MODE="off"; CLOUDFLARE_IPS_FILE="$tmp/missing.cidr"
swatter_failclosed_active && bad "off+missing -> not fail closed" "active (would block nothing)" || ok "off+missing -> not fail closed"

# --- swatter_cf_manages_plane: when does Swatter actively run the CF plane? ----
# direct always manages (it skips per-offender if a token is missing, as today).
reset_inputs
CF_MODE="direct"; swatter_cf_manages_plane && ok "direct -> manages plane" || bad "direct -> manages" "no"
CF_MODE="skip";   swatter_cf_manages_plane && bad "skip -> no manage" "yes" || ok "skip -> does not manage"
CF_MODE="off";    swatter_cf_manages_plane && bad "off -> no manage" "yes"  || ok "off -> does not manage"

# auto only manages when it detected a CF-fronted box AND has creds+map to act.
CF_MODE="auto"
printf 'behind\t0\tmap\n' > "$STATE_DIR/cf-detect"
swatter_cf_manages_plane && bad "auto+behind+no-creds -> no manage" "yes" || ok "auto+behind+no-creds -> does not manage (skip-like)"
printf 'acctA\ttoken\n'        > "$CF_CREDS_FILE"
printf 'example.com\tacctA\n'  > "$CF_DOMAINS_MAP"
swatter_cf_manages_plane && ok "auto+behind+creds -> manages plane" || bad "auto+behind+creds -> manages" "no"
printf 'not-behind\t0\tdns\n' > "$STATE_DIR/cf-detect"
swatter_cf_manages_plane && bad "auto+not-behind -> no manage" "yes" || ok "auto+not-behind -> does not manage"

echo
echo "detect: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
