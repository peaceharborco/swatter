#!/usr/bin/env bash
# test/allowlist_test.sh — the never-CSF-a-CF-edge safety net, exercised against
# the REAL swatter_is_never_block (allowlist.sh sourced UNMODIFIED, not stubbed).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/allowlist.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# never_block <ip> -> "rc:reason". rc=0 means never-block (with reason on stdout).
never_block() {
  local out rc
  out="$(swatter_is_never_block "$1")"; rc=$?
  printf '%s:%s' "$rc" "$out"
}

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-allowlist.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT

# Deliberately point the live CF file at a path that does not exist: the builtin
# fallback range MUST still protect the edge (README safety promise).
CLOUDFLARE_IPS_FILE="${STATE_DIR}/no-such-cf-file"
OPERATOR_ALLOW_FILE="${STATE_DIR}/no-such-op-allow"
MONITORING_RANGES_FILE="${STATE_DIR}/no-such-mon"
OPERATOR_IPS=""
VERIFY_GOOD_CRAWLERS=false
# Neutralize csf.allow discovery so a stray /etc/csf/csf.allow can't sway results.
SWATTER_CSF_ALLOW_FILE="${STATE_DIR}/empty-csf-allow"; : > "$SWATTER_CSF_ALLOW_FILE"

# --- Cloudflare edge via the compiled-in fallback, NO live file present -------
# 173.245.48.0/20 is the first fallback v4 range.
check cf-fallback-v4 "$(never_block 173.245.48.9)"  "0:cloudflare-range(builtin)"
# 104.16.0.0/13 fallback range.
check cf-fallback-v4b "$(never_block 104.16.1.1)"   "0:cloudflare-range(builtin)"
# 2400:cb00::/32 fallback v6 range.
check cf-fallback-v6 "$(never_block 2400:cb00::1)"  "0:cloudflare-range(builtin)"

# --- Loopback / private / link-local ------------------------------------------
check priv-10        "$(never_block 10.1.2.3)"      "0:local/private"
check priv-loopback  "$(never_block 127.0.0.1)"     "0:local/private"
check priv-v6-loop   "$(never_block ::1)"           "0:local/private"
check priv-linklocal "$(never_block fe80::1)"       "0:local/private"

# --- Operator IP (config inline list) -----------------------------------------
OPERATOR_IPS="203.0.113.50"
check operator-ip "$(never_block 203.0.113.50)" "0:operator-ip"
OPERATOR_IPS=""

# --- csf.allow membership -----------------------------------------------------
printf '198.51.100.7\n' > "$SWATTER_CSF_ALLOW_FILE"
check csf-allow "$(never_block 198.51.100.7)" "0:csf.allow"
: > "$SWATTER_CSF_ALLOW_FILE"

# --- Plain attacker IP: NOT allowlisted, must be blockable (rc=1, no reason) ---
check attacker "$(never_block 203.0.113.7)" "1:"

# --- _cidr_overlaps_file: the two-way test used wherever a CIDR TOKEN can be an
# enforcement target. Containment (_ip_in_cidr_file) answers "is this host in
# that range"; overlap answers "would banning this token touch that range",
# which is the question a prefix target actually poses.
ov="${STATE_DIR}/overlap.cidr"
printf '104.28.0.0/16 # WARP\n2001:db8:1::/48\n198.51.100.0/24\n' > "$ov"
ovl() { _cidr_overlaps_file "$1" "$ov" && echo yes || echo no; }
check ov-host-in        "$(ovl 104.28.1.1)"        "yes"
check ov-host-out       "$(ovl 192.0.2.1)"         "no"
check ov-equal          "$(ovl 104.28.0.0/16)"     "yes"
check ov-narrower       "$(ovl 104.28.7.0/24)"     "yes"
check ov-wider          "$(ovl 104.0.0.0/8)"       "yes"
check ov-adjacent       "$(ovl 104.29.0.0/16)"     "no"
check ov-slash32        "$(ovl 104.28.1.1/32)"     "yes"
check ov-disjoint-cidr  "$(ovl 192.0.2.0/24)"      "no"
check ov-v6-narrower    "$(ovl 2001:db8:1:2::/64)" "yes"
check ov-v6-wider       "$(ovl 2001:db8::/32)"     "yes"
check ov-v6-disjoint    "$(ovl 2001:db8:9::/48)"   "no"
check ov-v6-host        "$(ovl 2001:db8:1::5)"     "yes"
# Cross-family lines are skipped, not misread: a v4 token must not match a v6
# entry and vice versa.
check ov-v4-token-vs-v6 "$(ovl 32.1.13.184/30)"    "no"
check ov-missing-file   "$(_cidr_overlaps_file 104.28.1.1 "${STATE_DIR}/nope" && echo yes || echo no)" "no"

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]
