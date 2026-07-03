#!/usr/bin/env bash
# test/swarm_test.sh — host-side swarm core: gate, host_id, token cfg helper.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swarm.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
STORE="flatfile"; SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0; INTEL_CACHE_TTL=86400

# --- gate: disabled by default, and disabled => publish is a silent no-op
SWARM_ENABLE="false"; SWARM_HUB_URL=""
_swarm_enabled && { echo "FAIL gate-default-off"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
SWARM_ENABLE="true"
_swarm_enabled && { echo "FAIL gate-needs-url"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
SWARM_HUB_URL="https://hub.example"
_swarm_enabled && PASS=$((PASS+1)) || { echo "FAIL gate-on"; FAIL=$((FAIL+1)); }

# disabled => no curl ever (mock counts calls)
CURL_CALLS=0
curl() { CURL_CALLS=$((CURL_CALLS+1)); return 0; }
SWARM_ENABLE="false"
swatter_swarm_publish; check pub-disabled-nocurl "$CURL_CALLS" "0"
SWARM_ENABLE="true"

# --- host_id: created once, 32 hex, 0600, stable
id1="$(swatter_swarm_host_id)"; id2="$(swatter_swarm_host_id)"
check hostid-stable "$id1" "$id2"
[[ "$id1" =~ ^[0-9a-f]{32}$ ]] && PASS=$((PASS+1)) || { echo "FAIL hostid-hex: '$id1'"; FAIL=$((FAIL+1)); }
check hostid-perms "$(stat -c %a "${STATE_DIR}/swarm.host_id" 2>/dev/null || stat -f %Lp "${STATE_DIR}/swarm.host_id")" "600"

# --- token->cfg helper: missing file fails, real file lands token in cfg not argv
check tokcfg-missing "$(_swarm_curl_cfg_token "${STATE_DIR}/nope" >/dev/null 2>&1; echo $?)" "1"
printf 'sekret-token-123' > "${STATE_DIR}/tok"; chmod 0400 "${STATE_DIR}/tok"
cfg="$(_swarm_curl_cfg_token "${STATE_DIR}/tok")"
grep -q 'Authorization: Bearer sekret-token-123' "$cfg" && PASS=$((PASS+1)) || { echo "FAIL tokcfg-content"; FAIL=$((FAIL+1)); }
rm -f "$cfg"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
