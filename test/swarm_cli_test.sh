#!/usr/bin/env bash
# test/swarm_cli_test.sh — swatter swarm enroll/status/disable/purge.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swcli.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${STATE_DIR}/intel/swarm" "${LOG_DIR}"
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
INTEL_PROVIDERS="ipsum"
SWARM_ENROLL_TOKEN_FILE="${STATE_DIR}/enroll.tok"; printf 'enroll-tok' > "$SWARM_ENROLL_TOKEN_FILE"
SWARM_WRITE_TOKEN_FILE="${STATE_DIR}/write.tok";   printf 'write-tok'  > "$SWARM_WRITE_TOKEN_FILE"
SWARM_READ_TOKEN_FILE="${STATE_DIR}/read.tok";     printf 'read-tok'   > "$SWARM_READ_TOKEN_FILE"

POSTS="${STATE_DIR}/posts"; : > "$POSTS"
CURL_RESP=""; CURL_CODE="200"
curl() {
    local prev="" a out="" data="" url=""
    for a in "$@"; do
        [[ "$prev" == "-o" ]] && out="$a"
        [[ "$prev" == "--data-binary" ]] && data="$a"
        prev="$a"; url="$a"
    done
    printf 'URL=%s\n' "$url" >> "$POSTS"
    [[ -n "$data" ]] && cat "${data#@}" >> "$POSTS" && printf '\n' >> "$POSTS"
    [[ -n "$out" ]] && printf '%s' "$CURL_RESP" > "$out"
    printf '%s' "$CURL_CODE"
    return 0
}

# --- enroll happy path: POSTs /register with host_id + SANITIZED label, and
#     PERSISTS the per-host token the hub returns (0600), never printing it.
HTOK="${STATE_DIR}/swarm.host_token"
hid="$(swatter_swarm_host_id)"
TOK64="$(printf 'a%.0s' {1..64})"   # a 64-char hex-ish token
CURL_RESP="{\"enrolled\":\"${hid}\",\"rotated\":false,\"token\":\"${TOK64}\"}"
hostname() { printf 'host"with\\evil\nbytes.example.com'; }   # hostile hostname
out="$(cmd_swarm enroll </dev/null 2>&1)"; check enroll-rc "$?" "0"
check enroll-url "$(grep -c 'URL=https://hub.example/register' "$POSTS")" "1"
check enroll-hostid "$(grep -c "\"host_id\":\"${hid}\"" "$POSTS")" "1"
# label was sanitized to [A-Za-z0-9._-]: no quote/backslash/newline in payload
grep -q 'hostwithevilbytes.example.com' "$POSTS" && PASS=$((PASS+1)) || { echo "FAIL enroll-label-sanitized"; FAIL=$((FAIL+1)); }
check enroll-token-stored   "$(tr -d '[:space:]' < "$HTOK" 2>/dev/null)" "$TOK64"
check enroll-token-mode     "$(stat -c '%a' "$HTOK" 2>/dev/null || stat -f '%Lp' "$HTOK" 2>/dev/null)" "600"
printf '%s' "$out" | grep -q "$TOK64" && { echo "FAIL enroll-token-not-printed"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# --- _swarm_write_token_file prefers the per-host token when present, else falls
#     back to the shared write token (so publish/purge bind to this box's identity).
_wtf_saved="${SWARM_WRITE_TOKEN_FILE:-}"
SWARM_WRITE_TOKEN_FILE="${STATE_DIR}/wtok"; printf 'wtok' > "$SWARM_WRITE_TOKEN_FILE"
check wtf-prefers-host   "$(_swarm_write_token_file)" "$HTOK"
_htok_bak="$(cat "$HTOK")"; rm -f "$HTOK"
check wtf-fallback-write "$(_swarm_write_token_file)" "$SWARM_WRITE_TOKEN_FILE"
printf '%s' "$_htok_bak" > "$HTOK"; SWARM_WRITE_TOKEN_FILE="$_wtf_saved"

# --- plain re-enroll with NO token in the response (hub: already tokened) keeps
#     the existing token file and still succeeds.
CURL_RESP="{\"enrolled\":\"${hid}\",\"rotated\":false}"
cmd_swarm enroll </dev/null >/dev/null 2>&1; check reenroll-notoken-rc "$?" "0"
check reenroll-keeps-token "$(tr -d '[:space:]' < "$HTOK" 2>/dev/null)" "$TOK64"

# --- --rotate: the hub issues a new token; it replaces the stored one.
TOK64B="$(printf 'b%.0s' {1..64})"
CURL_RESP="{\"enrolled\":\"${hid}\",\"rotated\":true,\"token\":\"${TOK64B}\"}"
cmd_swarm enroll --rotate </dev/null >/dev/null 2>&1; check enroll-rotate-rc "$?" "0"
check enroll-rotate-flag  "$(grep -c '"rotate":true' "$POSTS")" "1"
check enroll-rotate-token "$(tr -d '[:space:]' < "$HTOK" 2>/dev/null)" "$TOK64B"

# --- no token in response AND no local token file -> hard fail (lockout guard).
rm -f "$HTOK"
CURL_RESP="{\"enrolled\":\"${hid}\",\"rotated\":false}"
cmd_swarm enroll </dev/null >/dev/null 2>&1; check enroll-notoken-lockout-rc "$?" "1"
# restore a token for the later publish/purge tests (they prefer it).
CURL_RESP="{\"enrolled\":\"${hid}\",\"rotated\":false,\"token\":\"${TOK64}\"}"
cmd_swarm enroll </dev/null >/dev/null 2>&1
unset -f hostname

# --- enroll without token file -> rc 1
SWARM_ENROLL_TOKEN_FILE="${STATE_DIR}/missing.tok"
cmd_swarm enroll </dev/null >/dev/null 2>&1; check enroll-notok-rc "$?" "1"
SWARM_ENROLL_TOKEN_FILE="${STATE_DIR}/enroll.tok"

# --- status runs clean with stdin closed, mentions the hub, and warns about
#     the missing INTEL_PROVIDERS wiring (consume would be dead)
out="$(cmd_swarm status </dev/null 2>&1)"; check status-rc "$?" "0"
printf '%s' "$out" | grep -q 'hub.example' && PASS=$((PASS+1)) || { echo "FAIL status-hub"; FAIL=$((FAIL+1)); }
printf '%s' "$out" | grep -q 'INTEL_PROVIDERS' && PASS=$((PASS+1)) || { echo "FAIL status-intel-warn"; FAIL=$((FAIL+1)); }
INTEL_PROVIDERS="ipsum swarm"
out="$(cmd_swarm status </dev/null 2>&1)"
printf '%s' "$out" | grep -q 'INTEL_PROVIDERS' && { echo "FAIL status-intel-ok-nowarn"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# --- disable removes feed + meta + intel cache + cursor
printf '1.2.3.4\n' > "${STATE_DIR}/feeds/swarm.txt"
printf '[]' > "${STATE_DIR}/feeds/swarm.meta.json"
printf '100' > "${STATE_DIR}/swarm.publish.cursor"
printf 'cached' > "${STATE_DIR}/intel/swarm/1.2.3.4"
cmd_swarm disable </dev/null >/dev/null 2>&1; check disable-rc "$?" "0"
[[ ! -e "${STATE_DIR}/feeds/swarm.txt" && ! -e "${STATE_DIR}/feeds/swarm.meta.json" \
   && ! -e "${STATE_DIR}/swarm.publish.cursor" && ! -e "${STATE_DIR}/intel/swarm/1.2.3.4" ]] \
    && PASS=$((PASS+1)) || { echo "FAIL disable-clean"; FAIL=$((FAIL+1)); }

# --- purge: stdin closed + no --yes -> rc 3, NO request sent
: > "$POSTS"
cmd_swarm purge </dev/null >/dev/null 2>&1; check purge-noconfirm-rc "$?" "3"
check purge-noconfirm-sent "$(grep -c 'URL=' "$POSTS" || true)" "0"

# --- purge --yes POSTs /purge with the write token's host_id
CURL_RESP='{"purged_sightings":4,"purged_offenders":2}'
cmd_swarm purge --yes </dev/null >/dev/null 2>&1; check purge-rc "$?" "0"
check purge-url "$(grep -c 'URL=https://hub.example/purge' "$POSTS")" "1"

# --- unknown verb -> rc 2
cmd_swarm bogus </dev/null >/dev/null 2>&1; check unknown-rc "$?" "2"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
