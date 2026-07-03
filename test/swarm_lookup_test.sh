#!/usr/bin/env bash
# test/swarm_lookup_test.sh — provider_swarm: hit/miss, CIDR, scaling, stale, fleet-allow, fold.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/score.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swl.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_BASE_SCORE=70; SWARM_MAX_AGE_DAYS=3; INTEL_CACHE_TTL=86400; SWATTER_HAVE_JQ=0
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; : > "$SWARM_ALLOW_FILE"
FEED="${STATE_DIR}/feeds/swarm.txt"; META="${STATE_DIR}/feeds/swarm.meta.json"

printf '203.0.113.7\n198.51.100.0/24\n' > "$FEED"

# exact-IP hit at base score
check hit "$(provider_swarm 203.0.113.7 | cut -f1)" "70"
check hit-label "$(provider_swarm 203.0.113.7 | cut -f3)" "hosts=1"
# CIDR containment hit
check cidr-hit "$(provider_swarm 198.51.100.99 | cut -f1)" "70"
# miss
provider_swarm 8.8.8.8 >/dev/null 2>&1 && { echo "FAIL miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

if command -v jq >/dev/null 2>&1; then
    SWATTER_HAVE_JQ=1
    # host_count scaling via meta
    printf '[{"ip":"203.0.113.7","host_count":3,"category":null,"expires":99}]' > "$META"
    check scaled "$(provider_swarm 203.0.113.7 | cut -f1)" "100"   # 70 + 15*2 = 100 (capped)
    check scaled-label "$(provider_swarm 203.0.113.7 | cut -f3)" "hosts=3"
    # LOCKED DECISION: a CIDR-contained IP stays at base even when the CIDR row
    # is corroborated — meta is keyed by the CIDR string (conservative).
    printf '[{"ip":"198.51.100.0/24","host_count":3,"category":null,"expires":99}]' > "$META"
    check cidr-conservative "$(provider_swarm 198.51.100.99 | cut -f1)" "70"
    SWATTER_HAVE_JQ=0; rm -f "$META"
fi

# fleet-allow: never boosted
printf '203.0.113.7\n' > "$SWARM_ALLOW_FILE"
provider_swarm 203.0.113.7 >/dev/null 2>&1 && { echo "FAIL fleet-allow"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
: > "$SWARM_ALLOW_FILE"

# stale feed -> signal absent
touch -d '@1000' "$FEED" 2>/dev/null || touch -t 202001010000 "$FEED"
provider_swarm 203.0.113.7 >/dev/null 2>&1 && { echo "FAIL stale"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# --- spec §11 boost-fold proof (W_REPUTATION path, lib/score.sh):
# a local-clean box (behavioral 5) + swarm 70 must stay FAR below SCORE_TEMP;
# a local near-miss (behavioral 68) + swarm 85 must tip over it.
W_REPUTATION=14; SCORE_TEMP=70
low="$(_swatter_fold_reputation 5 70)"
(( low < 70 )) && PASS=$((PASS+1)) || { echo "FAIL fold-clean-not-tipped: $low"; FAIL=$((FAIL+1)); }
high="$(_swatter_fold_reputation 68 85)"
(( high >= 70 )) && PASS=$((PASS+1)) || { echo "FAIL fold-nearmiss-tipped: $high"; FAIL=$((FAIL+1)); }
# fold can only RAISE, never lower a strong behavioral score
raised="$(_swatter_fold_reputation 95 10)"
(( raised >= 95 )) && PASS=$((PASS+1)) || { echo "FAIL fold-never-lowers: $raised"; FAIL=$((FAIL+1)); }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
