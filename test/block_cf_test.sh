#!/usr/bin/env bash
# test/block_cf_test.sh — swatter_cf_block return-code contract (the 2.1.2/2.1.3
# protocol score.sh depends on). Pins which preconditions are deterministic config
# gaps (SWATTER_RC_CONFIG=3), which are "no nameable vhost this window"
# (SWATTER_RC_NOVHOST=4), and which are genuine failures (1) — so a future edit
# that flips one back can't pass CI silently. CF API + creds are stubbed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block_cf.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP (no jq)"; echo "Total: 0 passed, 0 failed"; exit 0; }
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-cfblk.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
CF_MODE="direct"; CF_ACTION="block"; CF_RULE_PREFIX="swatter"
SWATTER_HAVE_JQ=1; SWATTER_HAVE_CURL=1
# Drive the maps/zone/api directly instead of reading creds files off disk.
declare -A _CF_ACCT_OF_DOMAIN _CF_TOKEN
_cf_load() { :; }
swatter_cf_manages_plane() { return 0; }
_cf_zone_id() { printf 'zone123'; return 0; }       # default: resolves
_cf_api()     { printf '%s' "${_CF_API_RESP:-}"; }  # default: empty -> error

# 1) empty vhost -> NOVHOST(4): no nameable target this window, not a config gap.
SWATTER_MODE="enforce"
swatter_cf_block 1.2.3.4 3600 r ""; check empty-vhost-novhost "$?" "$SWATTER_RC_NOVHOST"

# 2) vhost present but NOT in CF_DOMAINS_MAP -> CONFIG(3).
swatter_cf_block 1.2.3.4 3600 r notmapped.com; check unmapped-config "$?" "$SWATTER_RC_CONFIG"

# 3) mapped vhost but no token for the account -> CONFIG(3).
_CF_ACCT_OF_DOMAIN[x.com]="acctA"
swatter_cf_block 1.2.3.4 3600 r x.com; check notoken-config "$?" "$SWATTER_RC_CONFIG"

# token present from here on.
_CF_TOKEN[acctA]="tok"

# 4) report/dry-run -> 0 (no API touched).
SWATTER_MODE="report"
swatter_cf_block 1.2.3.4 3600 r x.com; check dryrun-ok "$?" "0"

# 5) enforce, missing jq/curl -> genuine failure (1).
SWATTER_MODE="enforce"; SWATTER_HAVE_JQ=0
swatter_cf_block 1.2.3.4 3600 r x.com; check nojq-failed "$?" "1"
SWATTER_HAVE_JQ=1

# 6) zone resolve fails -> genuine failure (1).
_cf_zone_id() { return 1; }
swatter_cf_block 1.2.3.4 3600 r x.com; check zonefail-failed "$?" "1"
_cf_zone_id() { printf 'zone123'; return 0; }

# 7) API says success -> 0.
_CF_API_RESP='{"success":true,"result":{"id":"rule1"}}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-ok "$?" "0"

# 8) API duplicate ("already exists") -> treated as success (0).
_CF_API_RESP='{"success":false,"errors":[{"message":"firewallaccessrules.api.duplicate_of_existing already exists"}]}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-dup-ok "$?" "0"

# 9) API genuine error -> failure (1).
_CF_API_RESP='{"success":false,"errors":[{"message":"boom"}]}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-error-failed "$?" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
