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
INTEL_PROVIDERS="swarm"   # sweep gates on active consume (pre-ship review)
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_ACTION="corroborated-block"; SWARM_MIN_CORROBORATION=2; SWARM_BASE_SCORE=70; SWARM_MAX_AGE_DAYS=3
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; printf '5.5.5.5\n' > "$SWARM_ALLOW_FILE"
META="${STATE_DIR}/feeds/swarm.meta.json"

# The sweep must route EVERY block through the gate choke — stub records calls.
# score.sh is NOT sourced here (it drags the whole scan surface), so stub the
# helpers the sweep uses. The sweep forces the DIRECT plane, so the stub records
# ip/plane/action/reason ($1/$2/$3/$5 of _swatter_apply_plane).
BLOCKS="${STATE_DIR}/blocks"; : > "$BLOCKS"
_swatter_apply_plane() { printf '%s %s %s %s\n' "$1" "$2" "$3" "$5" >> "$BLOCKS"; return 0; }
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
check sweep-corroborated "$(grep -c '^1.2.3.4 DIRECT temp' "$BLOCKS")" "1"  # hc=3 >= 2 -> DIRECT temp block
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

# non-numeric SWARM_MAX_AGE_DAYS must NOT silently disable the sweep: a bareword
# would evaluate to 0 in arithmetic and make every fresh meta look stale. It must
# fall back to the default bound and still block a corroborated IP.
cat > "$META" <<'EOF'
[{"ip":"4.4.4.4","host_count":3,"category":null,"expires":99}]
EOF
touch "$META"
: > "$BLOCKS"
SWARM_MAX_AGE_DAYS="abc" swatter_swarm_sweep 2>/dev/null
check sweep-bad-maxage-fresh "$(grep -c '^4.4.4.4 DIRECT temp' "$BLOCKS")" "1"

# boost mode: sweep is a no-op
SWARM_ACTION="boost"; : > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-boost-noop "$(grep -c . "$BLOCKS" || true)" "0"

# consume INACTIVE (swarm removed from INTEL_PROVIDERS): lingering fresh meta
# must NOT keep proactively blocking (pre-ship review)
SWARM_ACTION="corroborated-block"; INTEL_PROVIDERS="ipsum"
printf '[{"ip":"8.8.4.4","host_count":9,"category":null,"expires":99}]' > "$META"
touch "$META"
: > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-consume-inactive "$(grep -c . "$BLOCKS" || true)" "0"
INTEL_PROVIDERS="swarm"

# --- sqlite skip path (production default) ---------------------------------
# The sqlite branch skips on DIRECT-plane coverage (active_on), NOT global perm,
# so a CF-perm-ONLY IP must still be swept (gets its DIRECT/CSF deny), while an
# IP already covered on the DIRECT plane is skipped.
if command -v sqlite3 >/dev/null 2>&1; then
    SD_SQL="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sws-sql.XXXXXX")"; mkdir -p "$SD_SQL/feeds"
    ( STATE_DIR="$SD_SQL"; STORE=sqlite; DIRECT_BACKEND=csf; swatter_store_init
      META_SQL="${SD_SQL}/feeds/swarm.meta.json"
      # 1.2.3.4 = perm on cloudflare ONLY -> must fall through and get DIRECT temp.
      swatter_store_record 1.2.3.4 perm cloudflare 0 90 seed 0; swatter_store_plane_set 1.2.3.4 cloudflare perm 0
      # 9.9.9.9 = already perm on the DIRECT plane -> must be skipped.
      swatter_store_record 9.9.9.9 perm csf 0 90 seed 0; swatter_store_plane_set 9.9.9.9 csf perm 0
      : > "$BLOCKS"
      printf '[{"ip":"1.2.3.4","host_count":3,"category":null,"expires":99},{"ip":"9.9.9.9","host_count":3,"category":null,"expires":99}]' > "$META_SQL"; touch "$META_SQL"
      swatter_swarm_sweep 2>/dev/null
      grep -c '^1.2.3.4 DIRECT temp' "$BLOCKS" > "$SD_SQL/cf_only"
      grep -c '^9.9.9.9' "$BLOCKS" > "$SD_SQL/direct_perm" )
    check sqlite-cf-perm-only-swept "$(cat "$SD_SQL/cf_only")" "1"   # CF-perm-only -> DIRECT temp added
    check sqlite-direct-perm-skipped "$(cat "$SD_SQL/direct_perm")" "0"  # already DIRECT-perm -> skipped
    rm -rf "$SD_SQL"
fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
