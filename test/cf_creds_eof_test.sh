#!/usr/bin/env bash
# test/cf_creds_eof_test.sh — _cf_load loads the LAST creds/domains line even when
# the file has no trailing newline (a missing `read` EOF guard silently dropped the
# last account/domain — e.g. a one-line creds file added by hand).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block_cf.sh"
PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-cfcreds.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT

# Both files end WITHOUT a trailing newline on the last line (printf, no \n).
CF_CREDS_FILE="$STATE_DIR/creds";  printf 'acctA\ttokA\nacctB\ttokB'  > "$CF_CREDS_FILE"
CF_DOMAINS_MAP="$STATE_DIR/map";   printf 'a.com\tacctA\nb.com\tacctB' > "$CF_DOMAINS_MAP"

declare -A _CF_TOKEN _CF_ACCT_OF_DOMAIN
_CF_LOADED=0
_cf_load

check creds-first "${_CF_TOKEN[acctA]:-MISSING}"          "tokA"
check creds-last  "${_CF_TOKEN[acctB]:-MISSING}"          "tokB"    # dropped before the fix
check dom-first   "${_CF_ACCT_OF_DOMAIN[a.com]:-MISSING}" "acctA"
check dom-last    "${_CF_ACCT_OF_DOMAIN[b.com]:-MISSING}" "acctB"   # dropped before the fix

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
