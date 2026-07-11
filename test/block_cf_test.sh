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

# 0) defense-in-depth: a malformed IP is refused before ANY plane logic / API,
#    so no caller can push garbage into a Cloudflare access rule.
SWATTER_MODE="enforce"
_api_hits=0; _cf_api() { _api_hits=$((_api_hits+1)); printf '%s' "${_CF_API_RESP:-}"; }
swatter_cf_block "999.999.999.999" 3600 r x.com; check cf-malformed-rc "$?" "1"
swatter_cf_block "::::" 3600 r x.com >/dev/null 2>&1; check cf-malformed2-rc "$?" "1"
# Unsafe targets (/0, unspecified) are refused before any API call too.
swatter_cf_block "0.0.0.0/0" 3600 r x.com >/dev/null 2>&1; check cf-unsafe-rc "$?" "1"
swatter_cf_block "::" 3600 r x.com >/dev/null 2>&1; check cf-unsafe2-rc "$?" "1"
check cf-malformed-no-api "$_api_hits" "0"
_cf_api() { printf '%s' "${_CF_API_RESP:-}"; }   # restore

# 1) empty vhost -> NOVHOST(4): no nameable target this window, not a config gap.
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

# 5) enforce, missing jq/curl -> genuine failure (1) WITH a cause.
SWATTER_MODE="enforce"; SWATTER_HAVE_JQ=0
swatter_cf_block 1.2.3.4 3600 r x.com; check nojq-failed "$?" "1"
check nojq-cause "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'jq/curl unavailable')" "1"
SWATTER_HAVE_JQ=1

# 6) zone resolve fails -> genuine failure (1) WITH a cause.
_cf_zone_id() { return 1; }
swatter_cf_block 1.2.3.4 3600 r x.com; check zonefail-failed "$?" "1"
check zonefail-cause "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'zone unresolved')" "1"
_cf_zone_id() { printf 'zone123'; return 0; }

# 7) API says success -> 0.
_CF_API_RESP='{"success":true,"result":{"id":"rule1"}}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-ok "$?" "0"

# 8) API duplicate ("already exists") -> treated as success (0).
_CF_API_RESP='{"success":false,"errors":[{"message":"rule already exists"}]}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-dup-ok "$?" "0"

# 8b) REAL prod duplicate shape: code 10009, message is the bare error slug with
#     no "already exists" text. Must be idempotent-success, not `failed` — this
#     exact shape looped retries + starved perm escalation before the fix.
_CF_API_RESP='{"success":false,"errors":[{"code":10009,"message":"firewallaccessrules.api.duplicate_of_existing"}]}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-dup-10009-ok "$?" "0"

# 8c) code 10009 alone (no message) is still a duplicate -> success (0).
_CF_API_RESP='{"success":false,"errors":[{"code":10009}]}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-dup-codeonly-ok "$?" "0"

# 9) API genuine error -> failure (1), and the error is CAPTURED for diagnosability.
_CF_API_RESP='{"success":false,"errors":[{"message":"boom"}]}'
swatter_cf_block 1.2.3.4 3600 r x.com; check api-error-failed "$?" "1"
check backend-err-captured "$([[ -n "${SWATTER_LAST_BACKEND_ERR:-}" ]] && echo set || echo empty)" "set"
check backend-err-has-msg  "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR}" | grep -c boom)" "1"
# ...and cleared on the next successful attempt (no cross-IP bleed).
_CF_API_RESP='{"success":true,"result":{"id":"rule9"}}'
swatter_cf_block 1.2.3.4 3600 r x.com >/dev/null
check backend-err-cleared "$([[ -z "${SWATTER_LAST_BACKEND_ERR:-}" ]] && echo empty || echo set)" "empty"
# SECRET SAFETY: even if an error body echoed the bearer token, it must be redacted
# out of the captured cause (never reaches decisions.jsonl).
_CF_TOKEN[acctA]="SUPERSECRETTOKEN12345"
_CF_API_RESP='{"success":false,"errors":[{"message":"auth failed for token SUPERSECRETTOKEN12345 xyz"}]}'
swatter_cf_block 1.2.3.4 3600 r x.com >/dev/null
check backend-err-no-token "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR}" | grep -c SUPERSECRETTOKEN)" "0"
check backend-err-masked   "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR}" | grep -c '[*][*][*]')" "1"
_CF_TOKEN[acctA]="tok"
_CF_API_RESP='{"success":false,"errors":[{"message":"boom"}]}'   # restore for later cases

# ---- CF_SCOPE=account contract -------------------------------------------
# Account scope rules every account at once; the vhost is irrelevant, so the
# zone-path NOVHOST/CONFIG-by-domain gates do not apply. Account resolution is
# stubbed so we drive _CF_TOKEN_OF_ACCTID directly.
CF_SCOPE="account"
declare -A _CF_TOKEN_OF_ACCTID
_cf_load_accounts() { [[ "${#_CF_TOKEN_OF_ACCTID[@]}" -gt 0 ]]; }
SWATTER_MODE="enforce"

# A) genuinely no creds (empty token map) -> CONFIG(3): deterministic config gap.
declare -A _CF_TOKEN_SAVE; for k in "${!_CF_TOKEN[@]}"; do _CF_TOKEN_SAVE[$k]="${_CF_TOKEN[$k]}"; done
_CF_TOKEN=(); _CF_TOKEN_OF_ACCTID=()
swatter_cf_block 1.2.3.4 3600 r ""; check acct-nocreds-config "$?" "$SWATTER_RC_CONFIG"
for k in "${!_CF_TOKEN_SAVE[@]}"; do _CF_TOKEN[$k]="${_CF_TOKEN_SAVE[$k]}"; done

# B) creds present but 0 accounts resolve (API down / token lacks account read)
#    -> retryable failure(1), NOT config — a blip must not permanently skip.
_CF_TOKEN_OF_ACCTID=()
swatter_cf_block 1.2.3.4 3600 r ""; check acct-resolvefail-failed "$?" "1"

# two accounts resolve from here on.
_CF_TOKEN_OF_ACCTID[acct1]="tok1"; _CF_TOKEN_OF_ACCTID[acct2]="tok2"

# C) account scope needs NO vhost -> empty vhost still acts (dry-run here) -> 0.
SWATTER_MODE="report"
swatter_cf_block 1.2.3.4 3600 r ""; check acct-novhost-ok "$?" "0"

# D) enforce, missing jq -> genuine failure (1).
SWATTER_MODE="enforce"; SWATTER_HAVE_JQ=0
swatter_cf_block 1.2.3.4 3600 r ""; check acct-nojq-failed "$?" "1"
SWATTER_HAVE_JQ=1

# E) every account POST succeeds -> 0.
_CF_API_RESP='{"success":true,"result":{"id":"rule1"}}'
swatter_cf_block 1.2.3.4 3600 r ""; check acct-ok "$?" "0"

# F) duplicate on every account (real prod shape: code 10009, bare slug message)
#    -> treated as success (0).
_CF_API_RESP='{"success":false,"errors":[{"code":10009,"message":"firewallaccessrules.api.duplicate_of_existing"}]}'
swatter_cf_block 1.2.3.4 3600 r ""; check acct-dup-ok "$?" "0"

# G) every account errors -> failure (1).
_CF_API_RESP='{"success":false,"errors":[{"message":"boom"}]}'
swatter_cf_block 1.2.3.4 3600 r ""; check acct-allfail-failed "$?" "1"

# H) PARTIAL success (acct1 ok, acct2 errors) -> failure(1): the ledger must NOT
#    mark the IP handled, so the next run retries every account (succeeded ones
#    dup-OK). Returning 0 here would re-open the roaming gap on the failed account.
_cf_api() { case "$3" in */accounts/acct1/*) printf '%s' '{"success":true,"result":{"id":"r1"}}';; *) printf '%s' '{"success":false,"errors":[{"message":"boom"}]}';; esac; }
swatter_cf_block 1.2.3.4 3600 r ""; check acct-partial-failed "$?" "1"
_cf_api() { printf '%s' "${_CF_API_RESP:-}"; }   # restore default stub
CF_SCOPE="zone"

# ---- cf-rules.tsv backward-compat parse ----------------------------------
# A legacy 4-field zone row (written by an older Swatter) must still parse so it
# keeps sweeping/unblocking; the new 5-field scoped row carries explicit scope.
_cf_parse_ref "$(printf '9.9.9.9\tZONEID\tRULEID\t123')" \
  && check parse-legacy-zone "${_CFR_SCOPE}/${_CFR_SID}/${_CFR_RID}/${_CFR_EXP}" "zone/ZONEID/RULEID/123"
_cf_parse_ref "$(printf '9.9.9.9\taccount\tACCTID\tRULEID\t456')" \
  && check parse-scoped-account "${_CFR_SCOPE}/${_CFR_SID}/${_CFR_RID}/${_CFR_EXP}" "account/ACCTID/RULEID/456"
_cf_parse_ref "" ; check parse-blank-rejected "$?" "1"

# ---- unblock: a failed delete must KEEP the ref and fail loudly -----------
# Dropping the ref on a failed API delete orphans a live CF rule with no handle
# left to remove it (unblock retry + expiry sweep both work off cf-rules.tsv).
refs="${STATE_DIR}/cf-rules.tsv"
printf '9.9.9.9\tzone\tZID\tR1\t123\n8.8.8.8\tzone\tZID\tR2\t456\n' > "$refs"
_cf_delete_ref() { return 1; }
swatter_cf_unblock 9.9.9.9 2>/dev/null; check cfunb-fail-rc "$?" "1"
check cfunb-fail-ref-kept  "$(grep -c $'^9.9.9.9\t' "$refs")" "1"
check cfunb-fail-other-kept "$(grep -c $'^8.8.8.8\t' "$refs")" "1"
# ...and a successful delete removes ONLY this IP's refs (rc 0).
_cf_delete_ref() { return 0; }
swatter_cf_unblock 9.9.9.9; check cfunb-ok-rc "$?" "0"
check cfunb-ok-ref-gone   "$(grep -c $'^9.9.9.9\t' "$refs")" "0"
check cfunb-ok-other-kept "$(grep -c $'^8.8.8.8\t' "$refs")" "1"

# ==== pristine re-source for sweep + account-resolution coverage ==========
# Earlier cases stubbed _cf_load_accounts and _cf_api globally. Re-source the
# lib to get pristine functions, then re-stub only the plane gate + creds loader.
source "${ROOT}/lib/block_cf.sh"
swatter_cf_manages_plane() { return 0; }
_cf_load() { :; }
SWATTER_HAVE_JQ=1; SWATTER_HAVE_CURL=1

# ---- swatter_cf_sweep_expired: only expired refs deleted, future kept ------
# The sole remover of expired CF rules (TTL emulation). Seed an expired 5-field
# row, a future 5-field row, and a legacy 4-field (expired) row; assert only the
# expired refs are deleted and the future row survives in the file.
SWATTER_MODE="report"   # sweep runs regardless of mode
refs="${STATE_DIR}/cf-rules.tsv"
now="$(swatter_now)"
{ printf '1.1.1.1\tzone\tZID\tEXPIRED\t1\n'
  printf '2.2.2.2\taccount\tAID\tFUTURE\t%s\n' "$(( now + 100000 ))"
  printf '3.3.3.3\tZLEG\tLEGACY\t1\n'
} > "$refs"
_swept="${STATE_DIR}/swept.log"; : > "$_swept"
_cf_delete_ref() { printf '%s\n' "$3" >> "$_swept"; return 0; }   # $3 = rule id
swatter_cf_sweep_expired
check sweep-expired-deleted     "$(grep -c '^EXPIRED$' "$_swept")" "1"
check sweep-legacy-deleted      "$(grep -c '^LEGACY$'  "$_swept")" "1"
check sweep-future-not-deleted  "$(grep -c '^FUTURE$'  "$_swept")" "0"
check sweep-future-kept         "$(grep -c $'^2.2.2.2\t' "$refs")" "1"
check sweep-expired-gone        "$(grep -c $'\tEXPIRED\t' "$refs")" "0"
check sweep-legacy-gone         "$(grep -c 'LEGACY' "$refs")" "0"

# ---- _cf_load_accounts: all-or-retry, pagination, cache staleness ----------
# A) token A resolves OK, token B fails -> non-zero AND no cache written (a
#    partial map must never be baked in — it would mark IPs handled while a whole
#    account stays uncovered).
_cf_api() { case "$1" in
  tokA) printf '%s' '{"success":true,"result":[{"id":"acctA1"}],"result_info":{"total_pages":1}}';;
  *)    printf '%s' '{"success":false,"errors":[{"message":"nope"}]}';;
esac; }
declare -A _CF_TOKEN _CF_TOKEN_OF_ACCTID
_CF_TOKEN=([A]=tokA [B]=tokB); _CF_TOKEN_OF_ACCTID=(); _CF_ACCTS_LOADED=0
rm -f "${STATE_DIR}/cf-accounts.tsv"
_cf_load_accounts; check loadacct-anyfail-rc "$?" "1"
check loadacct-anyfail-nocache "$([[ -e "${STATE_DIR}/cf-accounts.tsv" ]] && echo yes || echo no)" "no"

# B) multi-page: total_pages=2 -> both pages' account ids resolved and cached.
_cf_api() { case "$3" in
  *page=1*) printf '%s' '{"success":true,"result":[{"id":"p1a"}],"result_info":{"total_pages":2}}';;
  *page=2*) printf '%s' '{"success":true,"result":[{"id":"p2a"}],"result_info":{"total_pages":2}}';;
esac; }
_CF_TOKEN=([A]=tokA); _CF_TOKEN_OF_ACCTID=(); _CF_ACCTS_LOADED=0
rm -f "${STATE_DIR}/cf-accounts.tsv"
_cf_load_accounts; check loadacct-multipage-rc "$?" "0"
check loadacct-multipage-p1 "${_CF_TOKEN_OF_ACCTID[p1a]:-}" "tokA"
check loadacct-multipage-p2 "${_CF_TOKEN_OF_ACCTID[p2a]:-}" "tokA"
check loadacct-multipage-cached "$([[ -s "${STATE_DIR}/cf-accounts.tsv" ]] && echo yes || echo no)" "yes"

# C) cache older than the creds file is IGNORED (adding an account+token line
#    bumps creds mtime and must force a re-resolve). Stale cache holds a bogus id
#    that the API never returns; the result must reflect the API, not the cache.
CF_CREDS_FILE="${STATE_DIR}/creds"; printf 'A\ttokA\n' > "$CF_CREDS_FILE"
printf 'STALEID\tA\n' > "${STATE_DIR}/cf-accounts.tsv"
touch -t 202001010000 "${STATE_DIR}/cf-accounts.tsv"   # cache far older than creds
_cf_api() { printf '%s' '{"success":true,"result":[{"id":"freshID"}],"result_info":{"total_pages":1}}'; }
_CF_TOKEN=([A]=tokA); _CF_TOKEN_OF_ACCTID=(); _CF_ACCTS_LOADED=0
_cf_load_accounts; check loadacct-stalecache-rc "$?" "0"
check loadacct-stalecache-ignored "${_CF_TOKEN_OF_ACCTID[STALEID]:-none}" "none"
check loadacct-stalecache-fresh   "${_CF_TOKEN_OF_ACCTID[freshID]:-}" "tokA"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
