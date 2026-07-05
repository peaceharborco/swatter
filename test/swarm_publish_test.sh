#!/usr/bin/env bash
# test/swarm_publish_test.sh — publish: delta, filters, cursor-over-sent-only, chunking, enrolled:false.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swp.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
STORE="flatfile"; swatter_store_init
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0; SWATTER_MODE="enforce"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"; SWARM_PUBLISH="true"
SWARM_WRITE_TOKEN_FILE="${STATE_DIR}/write.tok"; printf 'write-tok' > "$SWARM_WRITE_TOKEN_FILE"
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; printf '9.9.9.9\n' > "$SWARM_ALLOW_FILE"
CURSOR="${STATE_DIR}/swarm.publish.cursor"

# never-block stub: 10.0.0.0/8 is "operator-allow"
swatter_is_never_block() { [[ "$1" == 10.* ]] && { echo operator-allow; return 0; }; return 1; }

# curl mock: capture each POST payload (--data-binary @file), reply $CURL_RESP via -o, code via -w.
POSTS="${STATE_DIR}/posts"; : > "$POSTS"
CURL_RESP='{"accepted":1,"rejected":0,"enrolled":true}'; CURL_CODE="200"
curl() {
    local prev="" a out="" data=""
    for a in "$@"; do
        [[ "$prev" == "-o" ]] && out="$a"
        [[ "$prev" == "--data-binary" ]] && data="$a"
        prev="$a"
    done
    [[ -n "$data" ]] && cat "${data#@}" >> "$POSTS" && printf '\n' >> "$POSTS"
    [[ -n "$out" ]] && printf '%s' "$CURL_RESP" > "$out"
    printf '%s' "$CURL_CODE"
    return 0
}

# Seed the ledger: 2 good bans, 1 never-block, 1 fleet-allow — the FILTERED
# rows carry the HIGHEST timestamps, so the cursor test below proves filtered
# rows do NOT consume the cursor.
swatter_now() { echo 5000; }
swatter_store_record 203.0.113.7 perm csf 0 90 "ban a" 0
swatter_store_record 198.51.100.9 perm csf 0 90 "ban b" 0
unset -f swatter_now
swatter_now() { echo 5600; }
swatter_store_record 10.1.2.3 perm csf 0 90 "never-block leak test" 0
swatter_store_record 9.9.9.9 perm csf 0 90 "fleet-allow leak test" 0
unset -f swatter_now

# 1) publishes only the filtered delta; cursor = max ts of SENT rows (5000, not 5600)
swatter_swarm_publish 2>/dev/null; check pub-rc "$?" "0"
check pub-has-a "$(grep -c '203.0.113.7' "$POSTS")" "1"
check pub-has-b "$(grep -c '198.51.100.9' "$POSTS")" "1"
check pub-no-neverblock "$(grep -c '10.1.2.3' "$POSTS")" "0"
check pub-no-fleetallow "$(grep -c '"9.9.9.9"' "$POSTS")" "0"
check pub-hostid "$(grep -c "\"host_id\":\"$(swatter_swarm_host_id)\"" "$POSTS")" "1"
check cursor-sent-only "$(cat "$CURSOR")" "5000"

# 2) idempotent for SENT rows: re-run re-reads the filtered rows (cursor 5000 <
#    their ts 5600) but sends nothing new
: > "$POSTS"
swatter_swarm_publish 2>/dev/null
check pub-idempotent "$(grep -c '"host_id"' "$POSTS" || true)" "0"

# 3) failure keeps cursor (new ban, hub 500)
swatter_now() { echo 6000; }; swatter_store_record 203.0.113.99 perm csf 0 90 "ban c" 0; unset -f swatter_now
CURL_CODE="500"
swatter_swarm_publish 2>/dev/null; check fail-rc "$?" "1"
check fail-cursor-kept "$(cat "$CURSOR")" "5000"

# 4) enrolled:false warns + keeps cursor (retry after enroll)
CURL_CODE="200"; CURL_RESP='{"accepted":0,"rejected":1,"enrolled":false}'
warn="$(swatter_swarm_publish 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -q 'swarm enroll' && PASS=$((PASS+1)) || { echo "FAIL enroll-warn"; FAIL=$((FAIL+1)); }
check enroll-cursor-kept "$(cat "$CURSOR")" "5000"

# 5) rejected>0 with enrolled:true is WARNED (validator drift) but advances
CURL_RESP='{"accepted":0,"rejected":1,"enrolled":true}'
warn="$(swatter_swarm_publish 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -qi 'reject' && PASS=$((PASS+1)) || { echo "FAIL rejected-warn"; FAIL=$((FAIL+1)); }
check rejected-cursor-advanced "$(cat "$CURSOR")" "6000"

# 5b) 200 with an EMPTY/garbled body (no enrolled:true ack) keeps cursor
swatter_now() { echo 6500; }; swatter_store_record 203.0.113.101 perm csf 0 90 "ban d" 0; unset -f swatter_now
CURL_RESP=''
warn="$(swatter_swarm_publish 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -qi 'ack' && PASS=$((PASS+1)) || { echo "FAIL noack-warn"; FAIL=$((FAIL+1)); }
check noack-cursor-kept "$(cat "$CURSOR")" "6000"
CURL_RESP='{"accepted":1,"rejected":0,"enrolled":true}'
swatter_swarm_publish 2>/dev/null   # drain ban d so later cases start clean
check noack-retry-advances "$(cat "$CURSOR")" "6500"

# 6) report mode publishes nothing
CURL_RESP='{"accepted":1,"rejected":0,"enrolled":true}'; : > "$POSTS"; SWATTER_MODE="report"
swatter_swarm_publish 2>/dev/null
check reportmode-silent "$(grep -c . "$POSTS" || true)" "0"
SWATTER_MODE="enforce"

# 7) chunking: 501 fresh bans -> 2 POSTs
rm -f "$CURSOR"; : > "$POSTS"; : > "$(_swatter_jsonl)"
swatter_now() { echo 7000; }
for i in $(seq 1 501); do
    swatter_store_record "172.16.$(( i / 256 )).$(( i % 256 ))" perm csf 0 90 "bulk" 0
done
unset -f swatter_now
swatter_swarm_publish 2>/dev/null
check chunk-posts "$(grep -c '"host_id"' "$POSTS")" "2"

# 8) the publish audit line: exists, counts sent IPs, and stamps PUBLISH time
#    (swatter_now at publish), NOT the ledger max_ts of the sent rows.
#    Case 7 wiped the ledger (: > jsonl) and left the cursor at 7000, so seed one
#    fresh ban above the cursor at an OLD ledger ts, then publish LATER.
PUBLOG="${STATE_DIR}/swarm.publish.log"; rm -f "$PUBLOG"; : > "$POSTS"
swatter_now() { echo 7200; }   # ledger ts of the new ban (> cursor 7000 => sent)
swatter_store_record 203.0.113.200 perm csf 0 90 "ban audit" 0
unset -f swatter_now
swatter_now() { echo 9999; }   # publish wall-clock — LATER than any ledger ts
swatter_swarm_publish 2>/dev/null
unset -f swatter_now
check pub-audit-exists     "$( [[ -s "$PUBLOG" ]] && echo yes || echo no )" "yes"
check pub-audit-count      "$(tail -1 "$PUBLOG" | grep -c '"count":1')"     "1"
check pub-audit-ts-publish "$(tail -1 "$PUBLOG" | grep -c '"ts":9999')"     "1"
check pub-audit-not-maxts  "$(tail -1 "$PUBLOG" | grep -c '"ts":7200')"     "0"

unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
