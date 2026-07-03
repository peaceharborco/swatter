#!/usr/bin/env bash
# test/swarm_consume_test.sh — swarm feed consume: install/empty-clears/keep-last-good.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swc.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_READ_TOKEN_FILE="${STATE_DIR}/read.tok"; printf 'read-tok' > "$SWARM_READ_TOKEN_FILE"
FEED="${STATE_DIR}/feeds/swarm.txt"; META="${STATE_DIR}/feeds/swarm.meta.json"

# curl mock: honors -o <file> / -D <file>; prints $CURL_CODE (-w); body from $CURL_BODY.
CURL_CALLS=0; CURL_BODY=""; CURL_CODE="200"; CURL_HDRS=""; CURL_RC=0
curl() {
    CURL_CALLS=$((CURL_CALLS+1))
    local prev="" a out="" dfile=""
    for a in "$@"; do
        [[ "$prev" == "-o" ]] && out="$a"
        [[ "$prev" == "-D" ]] && dfile="$a"
        prev="$a"
    done
    [[ -n "$out"  ]] && printf '%s' "$CURL_BODY" > "$out"
    [[ -n "$dfile" ]] && printf '%s' "$CURL_HDRS" > "$dfile"
    printf '%s' "$CURL_CODE"
    return "$CURL_RC"
}

# 1) good bare feed installs
CURL_BODY=$'203.0.113.7\n198.51.100.0/24\n'; CURL_CODE="200"
provider_swarm_refresh 2>/dev/null; check inst-rc "$?" "0"
check inst-lines "$(grep -c . "$FEED")" "2"

# 2) transport failure keeps last-good
CURL_CODE=""; CURL_RC=7
provider_swarm_refresh 2>/dev/null; check fail-rc "$?" "1"
check fail-kept "$(grep -c . "$FEED")" "2"
CURL_RC=0

# 3) non-200 keeps last-good
CURL_CODE="500"
provider_swarm_refresh 2>/dev/null; check n200-rc "$?" "1"
check n200-kept "$(grep -c . "$FEED")" "2"

# 4) poisoned body (HTML) rejected, last-good kept
CURL_BODY=$'<html>error</html>\n'; CURL_CODE="200"
provider_swarm_refresh 2>/dev/null; check poison-rc "$?" "1"
check poison-kept "$(grep -c . "$FEED")" "2"

# 5) FROZEN OBLIGATION 1: valid EMPTY 200 CLEARS the feed (not keep-last-good)
CURL_BODY=""; CURL_CODE="200"
provider_swarm_refresh 2>/dev/null; check empty-rc "$?" "0"
check empty-cleared "$(grep -c . "$FEED" || true)" "0"

# 6) truncation header warns (message reaches stderr)
CURL_BODY=$'203.0.113.7\n'; CURL_HDRS=$'HTTP/2 200\r\nx-swarm-truncated: true\r\n'
warn="$(provider_swarm_refresh 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -qi 'truncat' && PASS=$((PASS+1)) || { echo "FAIL trunc-warn"; FAIL=$((FAIL+1)); }
CURL_HDRS=""

# 7) sidecar failure INVALIDATES prior meta (fresh-or-absent; jq boxes only)
if command -v jq >/dev/null 2>&1; then
    SWATTER_HAVE_JQ=1
    printf '[{"ip":"203.0.113.7","host_count":9}]' > "$META"   # stale prior meta
    CURL_BODY=$'203.0.113.7\n'
    # bare fetch 200 OK, but the json fetch (2nd call) returns garbage:
    _CALL=0
    curl() {
        _CALL=$(( _CALL + 1 ))
        local prev="" a out=""
        for a in "$@"; do [[ "$prev" == "-o" ]] && out="$a"; prev="$a"; done
        if (( _CALL == 1 )); then [[ -n "$out" ]] && printf '203.0.113.7\n' > "$out"; printf '200'
        else [[ -n "$out" ]] && printf 'not json' > "$out"; printf '200'; fi
        return 0
    }
    provider_swarm_refresh 2>/dev/null; check sidecar-fail-rc "$?" "0"
    [[ ! -e "$META" ]] && PASS=$((PASS+1)) || { echo "FAIL sidecar-fail-meta-invalidated"; FAIL=$((FAIL+1)); }
    SWATTER_HAVE_JQ=0
fi

# 8) disabled => rc 0 and NO curl call
CURL_CALLS=0
curl() { CURL_CALLS=$((CURL_CALLS+1)); return 0; }
SWARM_ENABLE="false"
provider_swarm_refresh 2>/dev/null; check disabled-rc "$?" "0"
check disabled-nocurl "$CURL_CALLS" "0"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
