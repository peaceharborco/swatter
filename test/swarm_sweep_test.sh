#!/usr/bin/env bash
# test/swarm_sweep_test.sh — corroborated-block: threshold, routing through the gate choke.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"

command -v jq >/dev/null 2>&1 || { echo "Total: 0 passed, 0 failed (jq missing — sweep is jq-gated; skipping)"; exit 0; }

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sws.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
STORE="flatfile"; swatter_store_init
SWATTER_HAVE_JQ=1; SWATTER_MODE="enforce"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_ACTION="corroborated-block"; SWARM_MIN_CORROBORATION=2; SWARM_BASE_SCORE=70; SWARM_MAX_AGE_DAYS=3
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; printf '5.5.5.5\n' > "$SWARM_ALLOW_FILE"
META="${STATE_DIR}/feeds/swarm.meta.json"

# The sweep must route EVERY block through the gate choke — stub records calls.
# score.sh is NOT sourced here (it drags the whole scan surface), so stub its
# two helpers the sweep uses (Grok review: v1 forgot _swatter_pick_ttl).
BLOCKS="${STATE_DIR}/blocks"; : > "$BLOCKS"
_swatter_execute_block() { printf '%s %s %s %s\n' "$1" "$2" "$3" "$5" >> "$BLOCKS"; return 0; }
_swatter_pick_ttl() { echo 3600; }
swatter_failclosed_active() { return 1; }   # healthy

cat > "$META" <<'EOF'
[
 {"ip":"1.2.3.4","host_count":3,"category":null,"expires":99},
 {"ip":"2.3.4.5","host_count":1,"category":null,"expires":99},
 {"ip":"5.5.5.5","host_count":5,"category":null,"expires":99}
]
EOF
touch "$META"

swatter_swarm_sweep 2>/dev/null; check sweep-rc "$?" "0"
check sweep-corroborated "$(grep -c '^1.2.3.4 temp' "$BLOCKS")" "1"     # hc=3 >= 2 -> temp block
check sweep-below-threshold "$(grep -c '^2.3.4.5' "$BLOCKS")" "0"       # hc=1 < 2 -> untouched
check sweep-fleet-allow "$(grep -c '^5.5.5.5' "$BLOCKS")" "0"           # canary never swept
check sweep-reason "$(grep -c 'swarm-corroborated hosts=3' "$BLOCKS")" "1"

# already-perm IPs are skipped (no churn)
swatter_now() { echo 100; }; swatter_store_record 1.2.3.4 perm csf 0 90 "already" 0
# Restore the real clock (unset -f would ERASE the common.sh definition — the
# override replaced it — leaving the sweep's staleness math with an empty now).
swatter_now() { printf '%s' "${SWATTER_NOW_EPOCH:-$(date -u +%s)}"; }
: > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-skips-perm "$(grep -c . "$BLOCKS" || true)" "0"

# stale meta -> sweep skipped
printf '[{"ip":"7.7.7.7","host_count":9}]' > "$META"
touch -d '@1000' "$META" 2>/dev/null || touch -t 202001010000 "$META"
: > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-stale-noop "$(grep -c . "$BLOCKS" || true)" "0"

# boost mode: sweep is a no-op
SWARM_ACTION="boost"; : > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-boost-noop "$(grep -c . "$BLOCKS" || true)" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
