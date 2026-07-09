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

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]
