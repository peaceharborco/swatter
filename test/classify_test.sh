#!/usr/bin/env bash
# test/classify_test.sh — plane classification + direct-socket (CF-bypass) evidence.
#
# Covers the direct-socket signal: a confirmed offender with a live TCP
# connection to a local web port (:80/:443) from a NON-Cloudflare peer is
# hitting the origin directly (bypassing CF), so it must classify DIRECT (CSF
# deny), not VIA_CF (an ineffective managed_challenge). The socket-snapshot
# helper (_swatter_websocket_peers) is dependency-injected; no network, no root,
# no firewall. Run: bash test/classify_test.sh

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

tmp="$(mktemp -d "${TMPDIR:-/tmp}/swatter-classify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# A real Cloudflare IPv4 range + an edge address inside it, and a direct attacker.
CF_RANGE="173.245.48.0/20"
CF_IP="173.245.48.5"      # a Cloudflare edge socket
NONCF_IP="203.0.113.7"    # a direct-to-origin attacker

ranges="$tmp/cloudflare.cidr"
printf '%s\n' "$CF_RANGE" > "$ranges"

# Reset to a CF-fronted box with fresh ranges and no live sockets before each case.
reset_inputs() {
    rm -rf "$tmp/case"; mkdir -p "$tmp/case"
    CF_MODE="direct"
    CLOUDFLARE_IPS_FILE="$ranges"
    LFD_LOG="$tmp/case/lfd.log"; : > "$LFD_LOG"
    DIRECT_WEB_PORTS="80 443"
    STATE_DIR="$tmp/state"; mkdir -p "$STATE_DIR"
    unset SWATTER_DIRECT_SET
    # Default: no live web sockets (override per-case to inject peers).
    _swatter_websocket_peers() { :; }
}

# Build the direct set (consuming the injected sockets) then classify.
classify_after_build() {
    local ip="$1" novhost="${2:-0}"
    swatter_build_direct_set
    swatter_classify "$ip" "$novhost"
}

# 1. A non-CF peer on a web port, healthy ranges -> DIRECT.
reset_inputs
_swatter_websocket_peers() { printf '%s\n' "$NONCF_IP"; }
assert_eq "non-cf web socket -> DIRECT" "$(classify_after_build "$NONCF_IP" 0)" "DIRECT"

# 2. A Cloudflare edge peer on a web port is filtered out (never CSF the proxy).
reset_inputs
_swatter_websocket_peers() { printf '%s\n' "$CF_IP"; }
assert_eq "cf-edge web socket -> filtered -> VIA_CF" "$(classify_after_build "$CF_IP" 0)" "VIA_CF"

# 3. Regression (2026-06-14 xmlrpc/plugscrub): valid-Host offender (novhost=0),
#    no cPanel-port hit, but a live non-CF web socket -> DIRECT.
reset_inputs
_swatter_websocket_peers() { printf '%s\n' "$NONCF_IP"; }
assert_eq "valid-host direct flood -> DIRECT (regression)" "$(classify_after_build "$NONCF_IP" 0)" "DIRECT"

# 4. Stale ranges -> can't tell a CF edge from a direct peer -> do NOT fold web
#    peers -> VIA_CF. (CSF denies are already fail-closed-suppressed this run.)
reset_inputs
stale="$tmp/case/stale.cidr"; printf '%s\n' "$CF_RANGE" > "$stale"
touch -d "30 days ago" "$stale" 2>/dev/null || touch -t 202001010000 "$stale"
CLOUDFLARE_IPS_FILE="$stale"
_swatter_websocket_peers() { printf '%s\n' "$NONCF_IP"; }
assert_eq "stale ranges -> web peers not folded -> VIA_CF" "$(classify_after_build "$NONCF_IP" 0)" "VIA_CF"

# 5. Kill switch: empty DIRECT_WEB_PORTS disables the signal -> VIA_CF.
reset_inputs
DIRECT_WEB_PORTS=""
_swatter_websocket_peers() { printf '%s\n' "$NONCF_IP"; }
assert_eq "empty DIRECT_WEB_PORTS -> signal off -> VIA_CF" "$(classify_after_build "$NONCF_IP" 0)" "VIA_CF"

# 6. No live sockets (e.g. ss absent / attack ended) -> no-op -> VIA_CF.
reset_inputs
assert_eq "no live sockets -> no-op -> VIA_CF" "$(classify_after_build "$NONCF_IP" 0)" "VIA_CF"

# 7. Existing signal still works: novhost>0 -> DIRECT (regression guard).
reset_inputs
assert_eq "novhost>0 -> DIRECT (existing signal)" "$(classify_after_build "$NONCF_IP" 6)" "DIRECT"

# 8. Default when DIRECT_WEB_PORTS is unset is "80 443" (the signal is on).
reset_inputs
unset DIRECT_WEB_PORTS
( source "${ROOT}/lib/common.sh"; [[ "${DIRECT_WEB_PORTS:-UNSET}" == "80 443" ]] ) \
    && ok "unset DIRECT_WEB_PORTS defaults to '80 443'" \
    || bad "unset DIRECT_WEB_PORTS defaults to '80 443'" "default not applied"

echo
echo "classify: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
