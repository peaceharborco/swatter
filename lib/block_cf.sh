#!/usr/bin/env bash
# lib/block_cf.sh — the Cloudflare plane (offenders arriving via the proxy).
#
# Used for offenders classified VIA_CF, whose TCP socket is a Cloudflare edge and
# therefore must NOT be CSF-denied. Blocks via IP Access Rules
# (`firewall/access_rules/rules`) — deliberately a DIFFERENT product from the WAF
# Rulesets that cf-push-rules.sh owns, so the two never clobber each other. IP
# Access Rules also scale to many entries (unlike the 5-custom-rule cap on Free
# zones).
#
# CF_SCOPE selects where the rule lands:
#   zone    = a zone-scoped rule on the single zone the attacker hit (the top
#             vhost from scoring). Smallest blast radius; needs only a
#             zone-scoped "Firewall Services: Edit" token, but a scanner that
#             rotates target vhosts is only ever challenged on the first zone it
#             touched — it roams free across every other zone on the account.
#   account = an account-scoped rule on EVERY account in CF_CREDS_FILE, so one
#             logical block blankets every zone on every account at once. This is
#             what you want for a confirmed bad actor (intel hit / scanner): the
#             block scope then matches Swatter's per-IP ledger, closing the
#             roaming gap. No target vhost is required. Needs a token with
#             "Account Firewall Access Rules: Edit" (account-scoped) — broader
#             than the zone-scoped token the zone path needs.
#
# Multi-account: zone scope maps the attacked vhost -> CF account via
# CF_DOMAINS_MAP, then the account -> token via CF_CREDS_FILE. Account scope
# resolves each token's account id(s) via the API (cached) and rules every one.
# Cloudflare IP Access Rules have no native TTL, so Swatter stamps the expiry
# into the rule notes and sweeps expired rules each run.
#
# CF_MODE: direct = use the IP Access Rules API (this file). auto = same as
# direct once detection finds the box is behind Cloudflare AND creds+map are
# present (see swatter_cf_manages_plane), otherwise skip-like. skip = the
# operator owns the Cloudflare plane (their own WAF/rate-limit stack); score.sh
# records VIA_CF offenders without acting and never calls in here. off = not
# behind Cloudflare at all. The gate here is swatter_cf_manages_plane.

CF_API="https://api.cloudflare.com/client/v4"

# --- credential + mapping loaders (cached per run) --------------------------
# CF_CREDS_FILE: lines "account<TAB>token" (mode 0600). CF_DOMAINS_MAP: lines
# "domain<TAB>account" (skip-profile domains omitted at deploy time).
declare -A _CF_TOKEN _CF_ACCT_OF_DOMAIN
_CF_LOADED=0

_cf_load() {
    [[ "${_CF_LOADED}" -eq 1 ]] && return 0
    _CF_LOADED=1
    if [[ -r "${CF_CREDS_FILE:-/etc/swatter/cloudflare.creds}" ]]; then
        local acct tok
        # `|| [[ -n "$acct" ]]` so a creds file whose LAST line has no trailing
        # newline still loads that account (else the last token is silently dropped).
        while IFS=$'\t ' read -r acct tok _ || [[ -n "$acct" ]]; do
            [[ -z "$acct" || "${acct:0:1}" == "#" || -z "$tok" ]] && continue
            _CF_TOKEN["$acct"]="$tok"
        done < "${CF_CREDS_FILE:-/etc/swatter/cloudflare.creds}"
    fi
    if [[ -r "${CF_DOMAINS_MAP:-/etc/swatter/cf-domains.map}" ]]; then
        local dom ac
        while IFS=$'\t ' read -r dom ac _ || [[ -n "$dom" ]]; do
            [[ -z "$dom" || "${dom:0:1}" == "#" || -z "$ac" ]] && continue
            _CF_ACCT_OF_DOMAIN["$dom"]="$ac"
        done < "${CF_DOMAINS_MAP:-/etc/swatter/cf-domains.map}"
    fi
}

# Resolve + cache the CF account id(s) each token can manage, building
# _CF_TOKEN_OF_ACCTID[account_id]=token for the account-scope path. The map is
# token-label-free on disk: $STATE_DIR/cf-accounts.tsv holds "account_id<TAB>label"
# (no secrets), and the token is re-attached from CF_CREDS_FILE on load. The
# cache is honoured only while it is NEWER than CF_CREDS_FILE, so adding a new
# account+token line invalidates it (mtime bump) and forces a re-resolve; an account
# newly granted to an *existing* token (creds unchanged) is picked up within
# CF_ACCOUNT_CACHE_TTL (default 7d), or immediately by deleting
# $STATE_DIR/cf-accounts.tsv. Returns non-zero with an empty map when no accounts
# resolve; the caller distinguishes "no creds at all" (config gap) from "creds
# present but resolution failed" (transient/permission -> retryable). The
# _CF_ACCTS_LOADED latch is set ONLY on success, so a transient empty result does
# not poison the rest of the run.
declare -A _CF_TOKEN_OF_ACCTID
_CF_ACCTS_LOADED=0
_cf_load_accounts() {
    [[ "${_CF_ACCTS_LOADED}" -eq 1 ]] && return 0
    _cf_load
    local creds="${CF_CREDS_FILE:-/etc/swatter/cloudflare.creds}"
    local cache="${STATE_DIR}/cf-accounts.tsv"
    _CF_TOKEN_OF_ACCTID=()
    # Cache hit only if present, non-empty, newer than the creds file, AND within
    # the TTL — the mtime check alone never expires, so a token that silently gains
    # a new account (no creds-file edit) would be cached forever. Mirrors the zone
    # cache TTL. Fresh-resolve past the window.
    local _cache_age=-1
    if [[ -s "$cache" ]]; then
        local _now_ts _mtime; _now_ts="$(swatter_now)"; _mtime="$(stat_mtime "$cache" 2>/dev/null || echo 0)"
        [[ "$_mtime" =~ ^[0-9]+$ ]] && _cache_age=$(( _now_ts - _mtime ))
    fi
    if [[ -s "$cache" && "$cache" -nt "$creds" ]] && (( _cache_age >= 0 && _cache_age < ${CF_ACCOUNT_CACHE_TTL:-604800} )); then
        local aid label
        while IFS=$'\t' read -r aid label _; do
            [[ -z "$aid" || -z "$label" ]] && continue
            [[ -n "${_CF_TOKEN[$label]:-}" ]] && _CF_TOKEN_OF_ACCTID["$aid"]="${_CF_TOKEN[$label]}"
        done < "$cache"
        if [[ "${#_CF_TOKEN_OF_ACCTID[@]}" -gt 0 ]]; then _CF_ACCTS_LOADED=1; return 0; fi
    fi
    # Cache miss/stale: resolve each token's accounts via the API, paginated.
    # All-or-retry: if ANY token's resolution call fails (API blip / lost perms),
    # do not cache or latch — a partial map must not be baked in (it would mark
    # IPs handled while a whole account stays uncovered). The next call re-resolves.
    local label tok aid page total resp rows="" row resolve_ok=1 tok_ok
    for label in "${!_CF_TOKEN[@]}"; do
        tok="${_CF_TOKEN[$label]}"
        page=1; total=1; tok_ok=0
        while (( page <= total && page <= 20 )); do
            resp="$(_cf_api "$tok" GET "/accounts?per_page=50&page=${page}")"
            printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1 || break
            tok_ok=1
            while IFS= read -r aid; do
                [[ -z "$aid" ]] && continue
                _CF_TOKEN_OF_ACCTID["$aid"]="$tok"
                printf -v row '%s\t%s\n' "$aid" "$label"; rows+="$row"
            done < <(printf '%s' "$resp" | jq -r '.result[]?.id // empty' 2>/dev/null)
            total="$(printf '%s' "$resp" | jq -r '.result_info.total_pages // 1' 2>/dev/null)"
            [[ "$total" =~ ^[0-9]+$ ]] || total=1
            (( page++ ))
        done
        (( tok_ok )) || resolve_ok=0
    done
    if [[ "${#_CF_TOKEN_OF_ACCTID[@]}" -gt 0 && "$resolve_ok" -eq 1 ]]; then
        mkdir -p "${STATE_DIR}" 2>/dev/null || true
        printf '%s' "$rows" > "$cache" 2>/dev/null || true
        _CF_ACCTS_LOADED=1
        return 0
    fi
    return 1   # do NOT latch on failure -> the next IP in this run retries the API
}

# Resolve a vhost to its CF account. Tries the exact host, then the registrable
# parent (strip leading labels) so www./sub. hosts map to the zone's account.
_cf_account_for_vhost() {
    local vh="$1" probe="$1"
    while [[ -n "$probe" ]]; do
        if [[ -n "${_CF_ACCT_OF_DOMAIN[$probe]:-}" ]]; then printf '%s' "${_CF_ACCT_OF_DOMAIN[$probe]}"; return 0; fi
        [[ "$probe" != *.*.* ]] && break
        probe="${probe#*.}"
    done
    return 1
}

_cf_api() {
    # _cf_api <token> <method> <path> [json-body]
    local token="$1" method="$2" path="$3" body="${4:-}"
    # Bearer token via -K config file, never argv (visible in `ps` on a shared box).
    local cfg rc
    cfg="$(swatter_curl_cfg "header = \"Authorization: Bearer ${token}\"")" || return 1
    local args=(-sS -X "$method" "${CF_API}${path}" -K "$cfg"
        -H "Content-Type: application/json")
    [[ -n "$body" ]] && args+=(--data "$body")
    curl --max-time 10 "${args[@]}" 2>/dev/null
    rc=$?
    rm -f "$cfg"
    return "$rc"
}

# Resolve + cache a zone id for a domain (per-account token). Cache file keyed by
# domain under $STATE_DIR/cf-zones/.
_cf_zone_id() {
    local domain="$1" token="$2"
    local cache="${STATE_DIR}/cf-zones/${domain}"
    # Honour the positive cache only within a TTL, so a domain moved to a
    # different CF account re-resolves to its new zone id instead of pinning the
    # stale one (a rule would otherwise land on the wrong/former zone).
    if [[ -f "$cache" ]]; then
        local now mtime age
        now="$(swatter_now)"; mtime="$(stat_mtime "$cache" 2>/dev/null || echo 0)"
        age=$(( now - mtime ))
        if (( age < ${CF_ZONE_CACHE_TTL:-604800} )); then cat "$cache"; return 0; fi
    fi
    local zid
    zid="$(_cf_api "$token" GET "/zones?name=${domain}&status=active" | jq -r '.result[0].id // empty' 2>/dev/null)"
    [[ -n "$zid" ]] || return 1
    mkdir -p "${STATE_DIR}/cf-zones" 2>/dev/null || true
    printf '%s' "$zid" > "$cache" 2>/dev/null || true
    printf '%s' "$zid"
}

# The IP Access Rule create/delete API path for a scope. zone -> a single zone;
# account -> every zone on that account. Used for both create and delete so the
# bookkeeping (cf-rules.tsv) round-trips to the right endpoint.
_cf_rule_path() {
    # _cf_rule_path <scope> <scope_id> [rule_id]
    local scope="$1" sid="$2" rid="${3:-}"
    local base
    case "$scope" in
        account) base="/accounts/${sid}/firewall/access_rules/rules" ;;
        *)       base="/zones/${sid}/firewall/access_rules/rules" ;;
    esac
    [[ -n "$rid" ]] && base="${base}/${rid}"
    printf '%s' "$base"
}

# Build the IP Access Rule body once (mode + target ip + ownership/TTL note).
_cf_rule_payload() {
    # _cf_rule_payload <ip> <note>
    jq -nc --arg ip "$1" --arg mode "${CF_ACTION}" --arg note "$2" \
        '{mode:$mode, configuration:{target:"ip", value:$ip}, notes:$note}'
}

# Classify a create response. The API says "duplicate" two ways: legacy message
# text ("already exists"/"identical") and, on the account-scoped endpoint, code
# 10009 "firewallaccessrules.api.duplicate_of_existing". Missing the latter
# recorded every retry as `failed`, which both looped the create every scan AND
# starved the repeat-escalation counter (only `temp` rows count toward REPEAT_N),
# so a live repeat offender never went perm.
#   rc 0 = fresh rule minted (echoes the rule id)
#   rc 2 = idempotent duplicate — a rule for this target already exists; the
#          caller must reconcile it (_cf_reconcile_dup) rather than trust it
#          blindly: the existing rule may carry an older/shorter expiry note, a
#          lost cf-rules.tsv ref, or even a different mode (a manual rule).
#   rc 1 = genuine error
_cf_create_ok() {
    # _cf_create_ok <response>  -> echoes rule id on rc 0
    local resp="$1" cls
    cls="$(printf '%s' "$resp" | jq -r '
        if .success == true then "ok\t\(.result.id // "")"
        elif ([.errors[]?] | any((.code == 10009)
              or ((.message // "") | test("already exists|identical|duplicate_of_existing"))))
             then "dup"
        else "err" end' 2>/dev/null)"
    case "$cls" in
        ok$'\t'*) printf '%s' "${cls#ok$'\t'}"; return 0 ;;
        dup)      return 2 ;;
        *)        return 1 ;;
    esac
}

# Rewrite cf-rules.tsv so (ip,scope,scope_id) maps to exactly one row with the
# given rule id + expiry (replacing any stale rows for that triple). Safe against
# concurrent scans via the entrypoint flock.
#
# The ref is the ONLY handle sweep/unblock have on a live edge rule (CF Access
# Rules carry no native TTL), so a lost ref = an unsweepable permanent ban.
# Therefore this returns NON-ZERO on any persistence failure (mktemp/write/mv)
# instead of silently succeeding: the caller reports the block `failed`, which the
# durable retry queue re-drives — the re-POST hits the existing rule as a
# duplicate and _cf_reconcile_dup heals the ref once the state dir is writable
# again. Any partial write is discarded so the existing refs file is never
# truncated (an interrupted rewrite must not strand the OTHER live rules).
_cf_tsv_upsert() {
    # _cf_tsv_upsert <ip> <scope> <sid> <rid> <exp>
    local ip="$1" scope="$2" sid="$3" rid="$4" exp="$5"
    local refs="${STATE_DIR}/cf-rules.tsv"
    mkdir -p "${STATE_DIR}" 2>/dev/null || true
    local why="rule ${rid} for ${ip} has no handle — sweep/unblock can't reach it (edge rule would be permanent)"
    if [[ ! -f "$refs" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "$scope" "$sid" "$rid" "$exp" >> "$refs" 2>/dev/null \
            || { log_error "CF ref persist FAILED (append ${refs}): ${why}"; return 1; }
        return 0
    fi
    local keep; keep="$(mktemp "${TMPDIR:-/tmp}/swatter-cfrules.XXXXXX")" \
        || { log_error "CF ref persist FAILED (mktemp): ${why}"; return 1; }
    local line _CFR_IP _CFR_SCOPE _CFR_SID _CFR_RID _CFR_EXP
    while IFS= read -r line; do
        _cf_parse_ref "$line" || continue
        [[ "${_CFR_IP}" == "$ip" && "${_CFR_SCOPE}" == "$scope" && "${_CFR_SID}" == "$sid" ]] && continue
        # A failed append here would give a PARTIAL keep-file; abort and leave the
        # original refs untouched rather than mv a truncated file over live rules.
        printf '%s\t%s\t%s\t%s\t%s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" "${_CFR_EXP}" >> "$keep" \
            || { rm -f "$keep"; log_error "CF ref persist FAILED (rewrite ${keep}): ${why}; refs left intact"; return 1; }
    done < "$refs"
    printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "$scope" "$sid" "$rid" "$exp" >> "$keep" \
        || { rm -f "$keep"; log_error "CF ref persist FAILED (append ${keep}): ${why}; refs left intact"; return 1; }
    mv "$keep" "$refs" 2>/dev/null \
        || { rm -f "$keep"; log_error "CF ref persist FAILED (mv -> ${refs}): ${why}; refs left intact"; return 1; }
    return 0
}

# Does cf-rules.tsv already hold a handle (ref) for this (ip,scope,sid)? Exact
# field match (not a substring grep) so 11.2.3.4 can't satisfy a query for 1.2.3.4.
_cf_ref_exists() {
    # _cf_ref_exists <ip> <scope> <sid>
    local refs="${STATE_DIR}/cf-rules.tsv"
    [[ -f "$refs" ]] || return 1
    awk -F'\t' -v ip="$1" -v sc="$2" -v sid="$3" \
        '$1==ip && $2==sc && $3==sid { found=1; exit } END { exit !found }' "$refs" 2>/dev/null
}

# On a duplicate-create, look the existing rule up and make our bookkeeping match
# reality instead of assuming a prior run already recorded it:
#   * the rule may be OURS with an older ref — refresh the tsv row's expiry so
#     the sweep honours the NEW ttl (else an escalated/perm block is silently
#     swept at the first temp's expiry while the ledger claims long coverage);
#   * the ref may be LOST (append failed, state restored) — recreate it so
#     sweep/unblock keep a handle on the live rule;
#   * the rule may be someone ELSE'S with a different mode (e.g. a manual
#     whitelist) — that is NOT a block in place: fail loudly, never claim it.
# If the lookup is inconclusive (API blip / token lacks read / no rule returned),
# trust the duplicate ONLY when we already hold a ref for it (sweep/unblock have a
# handle). With NO ref on file — the exact state B2 recovery is retrying to heal —
# trusting would leave a live rule no code can ever reach (a permanent ban), so we
# return non-zero and let the bounded durable-retry queue keep trying to heal via
# this same dup path. If the lookup SUCCEEDS but the healed ref can't be persisted,
# also return non-zero (same reason). None of this risks the old unbounded loop:
# the retry is capped by attempts/age.
_cf_reconcile_dup() {
    # _cf_reconcile_dup <token> <scope> <sid> <ip> <exp>
    local token="$1" scope="$2" sid="$3" ip="$4" exp="$5"
    local resp rid mode
    resp="$(_cf_api "$token" GET "$(_cf_rule_path "$scope" "$sid")?configuration.target=ip&configuration.value=${ip}&per_page=5")"
    if ! printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
        if _cf_ref_exists "$ip" "$scope" "$sid"; then
            log_warn "CF block ${ip}: duplicate reported, rule lookup failed (${scope} ${sid}); trusting the duplicate (ref already on file)"
            return 0
        fi
        SWATTER_LAST_BACKEND_ERR="duplicate reported but rule lookup failed (${scope} ${sid}) and no ref on file — no handle to the live rule; retrying to heal"
        log_warn "CF block ${ip}: ${SWATTER_LAST_BACKEND_ERR}"
        return 1
    fi
    rid="$(printf '%s' "$resp" | jq -r --arg ip "$ip" \
        '[.result[]? | select(.configuration.value == $ip)][0].id // empty' 2>/dev/null)"
    mode="$(printf '%s' "$resp" | jq -r --arg ip "$ip" \
        '[.result[]? | select(.configuration.value == $ip)][0].mode // empty' 2>/dev/null)"
    if [[ -z "$rid" ]]; then
        if _cf_ref_exists "$ip" "$scope" "$sid"; then
            log_warn "CF block ${ip}: duplicate reported but no rule found on ${scope} ${sid}; ref already on file, trusting"
            return 0
        fi
        SWATTER_LAST_BACKEND_ERR="duplicate reported but no rule found on ${scope} ${sid} and no ref on file; retrying to (re)create"
        log_warn "CF block ${ip}: ${SWATTER_LAST_BACKEND_ERR}"
        return 1
    fi
    if [[ "$mode" != "${CF_ACTION}" ]]; then
        SWATTER_LAST_BACKEND_ERR="existing rule for ${ip} on ${scope} ${sid} has mode=${mode} (want ${CF_ACTION}) — not swatter's rule, refusing to claim it"
        log_warn "CF block ${ip}: ${SWATTER_LAST_BACKEND_ERR}"
        return 1
    fi
    if ! _cf_tsv_upsert "$ip" "$scope" "$sid" "$rid" "$exp"; then
        SWATTER_LAST_BACKEND_ERR="duplicate rule ${rid} for ${ip} reconciled but ref not persisted (state dir unwritable) — retrying to heal the handle"
        return 1
    fi
    return 0
}

# A zone-scoped block on the single zone the attacker hit (CF_SCOPE=zone).
# Preserves the original return-code contract score.sh depends on.
_cf_block_zone() {
    local ip="$1" ttl="$2" reason="$3" vhost="${4:-}"
    # Non-block preconditions use the shared rc protocol (see lib/common.sh):
    #   no nameable vhost this window -> RC_NOVHOST (data-dependent, may resolve
    #     next scan — NOT a config error, so don't send operators chasing a map);
    #   vhost present but unmapped / no token -> RC_CONFIG (deterministic gap);
    #   broken tooling / zone-resolve / API errors below stay 1 ("failed").
    if [[ -z "$vhost" ]]; then
        log_warn "CF block ${ip}: no target vhost in this window's evidence; cannot pick a zone — skipping (may resolve next scan)"
        return "$SWATTER_RC_NOVHOST"
    fi
    local acct; acct="$(_cf_account_for_vhost "$vhost")" || {
        log_warn "CF block ${ip}: vhost ${vhost} not in CF_DOMAINS_MAP — skipping (add it or it's a skip-profile domain)"
        return "$SWATTER_RC_CONFIG"
    }
    local token="${_CF_TOKEN[$acct]:-}"
    [[ -n "$token" ]] || { log_warn "CF block ${ip}: no token for account ${acct} in CF_CREDS_FILE — skipping"; return "$SWATTER_RC_CONFIG"; }

    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] cloudflare ${CF_ACTION} ${ip} in ${vhost} (acct ${acct}; ${reason})"
        return 0
    fi
    [[ "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || { SWATTER_LAST_BACKEND_ERR="jq/curl unavailable"; log_error "CF plane needs jq+curl"; return 1; }

    local zid; zid="$(_cf_zone_id "$vhost" "$token")" || { SWATTER_LAST_BACKEND_ERR="zone unresolved for ${vhost}"; log_warn "CF block ${ip}: could not resolve zone for ${vhost}"; return 1; }
    local expiry note resp rid
    expiry=$(( $(swatter_now) + ttl ))
    note="${CF_RULE_PREFIX:-swatter}|exp=${expiry}|${reason}"
    resp="$(_cf_api "$token" POST "$(_cf_rule_path zone "$zid")" "$(_cf_rule_payload "$ip" "$note")")"
    local crc; rid="$(_cf_create_ok "$resp")"; crc=$?
    if (( crc == 0 )); then
        # Record the (scope,scope_id,rule) ref so unblock/sweep are O(1). If the ref
        # can't be persisted the rule is live but unsweepable — report failed so the
        # retry queue re-drives it (the re-POST dup-reconciles + heals the ref).
        if ! _cf_tsv_upsert "$ip" "zone" "$zid" "$rid" "$expiry"; then
            SWATTER_LAST_BACKEND_ERR="rule ${rid} created for ${ip} (zone ${zid}) but ref not persisted (state dir unwritable)"
            log_warn "CF block ${ip} in ${vhost}: ${SWATTER_LAST_BACKEND_ERR}"
            return 1
        fi
        log_info "cloudflare ${CF_ACTION} ${ip} in ${vhost} (zone ${zid}, acct ${acct})"
        return 0
    fi
    if (( crc == 2 )); then
        # Duplicate: a rule already exists — reconcile it (refresh the ref's
        # expiry to THIS ttl, recover a lost ref, reject a foreign-mode rule).
        if _cf_reconcile_dup "$token" "zone" "$zid" "$ip" "$expiry"; then
            log_info "cloudflare ${CF_ACTION} ${ip} in ${vhost} (zone ${zid}, acct ${acct}; existing rule refreshed)"
            return 0
        fi
        return 1   # foreign-mode rule: SWATTER_LAST_BACKEND_ERR already set
    fi
    # Capture the reduced API error so score.sh can record it on the `failed`
    # decision (makes a block_failed self-diagnosing), not just log it to stderr.
    SWATTER_LAST_BACKEND_ERR="$(printf '%s' "$resp" | _cf_err_summary)"
    # Defense-in-depth: never let the bearer token reach decisions.jsonl even if a
    # (crafted/proxied) error body echoed it. CF real errors don't, but redact anyway.
    [[ -n "${token:-}" ]] && SWATTER_LAST_BACKEND_ERR="${SWATTER_LAST_BACKEND_ERR//${token}/***}"
    log_warn "CF block ${ip} in ${vhost} failed: ${SWATTER_LAST_BACKEND_ERR}"
    return 1
}

# An account-scoped block on every CF account in creds (CF_SCOPE=account). No
# target vhost is needed — the rule blankets every zone on every account. RC
# contract score.sh depends on:
#   no tokens in creds at all          -> RC_CONFIG (deterministic config gap);
#   creds present but 0 accounts resolve (API down, or token lacks account read)
#                                      -> 1 (retryable failure, NOT config — a
#                                         blip must not permanently skip blocking);
#   missing jq/curl                    -> 1;
#   EVERY account rule in place        -> 0 (handled);
#   ANY account failed (partial)       -> 1, so the ledger does NOT mark the IP
#                                         handled and the next run retries every
#                                         account (the succeeded ones idempotently
#                                         dup-OK). Returning 0 on partial would
#                                         re-open the very roaming gap this closes:
#                                         a still-uncovered account would never be
#                                         retried. Per-account success rows are
#                                         still recorded so sweep cleans them.
_cf_block_account() {
    local ip="$1" ttl="$2" reason="$3" vhost="${4:-}"   # vhost unused; kept for signature parity
    _cf_load
    if [[ "${#_CF_TOKEN[@]}" -eq 0 ]]; then
        log_warn "CF block ${ip}: CF_CREDS_FILE has no account tokens — skipping"
        return "$SWATTER_RC_CONFIG"
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] cloudflare ${CF_ACTION} ${ip} on all accounts (${reason})"
        return 0
    fi
    [[ "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || { SWATTER_LAST_BACKEND_ERR="jq/curl unavailable"; log_error "CF plane needs jq+curl"; return 1; }
    _cf_load_accounts || {
        SWATTER_LAST_BACKEND_ERR="0 CF accounts resolved (API unreachable or token lacks account read)"
        log_warn "CF block ${ip}: 0 CF accounts resolved (API unreachable, or token lacks 'Account Firewall Access Rules: Edit' / account read) — will retry"
        return 1
    }

    local expiry note payload aid token resp rid ok=0 fail=0
    expiry=$(( $(swatter_now) + ttl ))
    note="${CF_RULE_PREFIX:-swatter}|exp=${expiry}|${reason}"
    payload="$(_cf_rule_payload "$ip" "$note")"
    local crc
    for aid in "${!_CF_TOKEN_OF_ACCTID[@]}"; do
        token="${_CF_TOKEN_OF_ACCTID[$aid]}"
        resp="$(_cf_api "$token" POST "$(_cf_rule_path account "$aid")" "$payload")"
        rid="$(_cf_create_ok "$resp")"; crc=$?
        if (( crc == 2 )); then
            # Duplicate: reconcile (refresh ref expiry / recover a lost ref /
            # reject a foreign-mode rule). Success folds into the ok tally;
            # a foreign-mode rejection falls through to the failure branch.
            if _cf_reconcile_dup "$token" "account" "$aid" "$ip" "$expiry"; then
                log_info "cloudflare ${CF_ACTION} ${ip} on account ${aid} (existing rule refreshed)"
                ok=$(( ok + 1 )); continue
            fi
            log_warn "CF block ${ip} on account ${aid} failed: ${SWATTER_LAST_BACKEND_ERR}"
            fail=$(( fail + 1 )); continue
        fi
        if (( crc == 0 )); then
            # A created rule whose ref won't persist is an unsweepable ban — count
            # it as a FAIL so the block is retried (dup-reconcile heals the ref),
            # not silently marked handled.
            if _cf_tsv_upsert "$ip" "account" "$aid" "$rid" "$expiry"; then
                log_info "cloudflare ${CF_ACTION} ${ip} on account ${aid}"
                ok=$(( ok + 1 ))
            else
                SWATTER_LAST_BACKEND_ERR="rule ${rid} created on account ${aid} but ref not persisted (state dir unwritable)"
                log_warn "CF block ${ip} on account ${aid}: ${SWATTER_LAST_BACKEND_ERR}"
                fail=$(( fail + 1 ))
            fi
        else
            SWATTER_LAST_BACKEND_ERR="$(printf '%s' "$resp" | _cf_err_summary)"
    # Defense-in-depth: never let the bearer token reach decisions.jsonl even if a
    # (crafted/proxied) error body echoed it. CF real errors don't, but redact anyway.
    [[ -n "${token:-}" ]] && SWATTER_LAST_BACKEND_ERR="${SWATTER_LAST_BACKEND_ERR//${token}/***}"
            log_warn "CF block ${ip} on account ${aid} failed: ${SWATTER_LAST_BACKEND_ERR}"
            fail=$(( fail + 1 ))
        fi
    done
    if (( fail == 0 && ok > 0 )); then return 0; fi
    log_warn "CF block ${ip}: ${ok} account(s) ruled, ${fail} failed — not marking handled, will retry"
    return 1
}

# swatter_cf_block <ip> <ttl> <reason> <vhost> — dispatch on CF_SCOPE.
swatter_cf_block() {
    local ip="$1" ttl="$2" reason="$3" vhost="${4:-}"
    # Fresh each attempt so a prior IP's CF error can't attach to this one's
    # `failed` record (score.sh reads SWATTER_LAST_BACKEND_ERR on the failed branch).
    SWATTER_LAST_BACKEND_ERR=""
    # Defense-in-depth: never build a Cloudflare access rule for a malformed IP or
    # an unsafe target (/0 / unspecified), regardless of caller.
    if ! swatter_is_valid_ip_or_cidr "$ip" || _swatter_is_unsafe_block_target "$ip"; then
        SWATTER_LAST_BACKEND_ERR="malformed or unsafe ip"
        log_warn "CF block: refusing malformed/unsafe target '${ip}'"; return 1
    fi
    # Belt over score.sh's routing: only a plane-managing posture may create
    # rules (explicit direct, or auto that detected CF + has creds). Return 1 so a
    # caller bug can't record a block that never happened.
    swatter_cf_manages_plane || { log_debug "CF_MODE=${CF_MODE}; not CF-blocking ${ip}"; return 1; }
    _cf_load
    case "${CF_SCOPE:-zone}" in
        account) _cf_block_account "$ip" "$ttl" "$reason" "$vhost" ;;
        *)       _cf_block_zone    "$ip" "$ttl" "$reason" "$vhost" ;;
    esac
}

# Reduce a CF API error response (stdin) to one log-friendly line. Must
# tolerate every shape the API can return: empty .errors arrays, items
# without .message, no .errors at all, and non-JSON bodies.
_cf_err_summary() {
    local s
    s="$(jq -rc '[.errors[]?.message // empty] | if length == 0 then "unknown error" else join("; ") end' 2>/dev/null | cut -c1-200)"
    printf '%s' "${s:-unknown error}"
}

# Parse one cf-rules.tsv line into the caller's named vars. Tolerates both the
# legacy 4-field zone row (ip zone rule exp) and the 5-field scoped row
# (ip scope scope_id rule exp), so rules written by an older Swatter keep
# sweeping/unblocking through their natural expiry. Echoes nothing; sets the
# four globals _CFR_IP _CFR_SCOPE _CFR_SID _CFR_RID _CFR_EXP. Returns 1 on a
# blank/garbage line.
_cf_parse_ref() {
    local line="$1"; local -a f
    IFS=$'\t' read -r -a f <<<"$line"
    if [[ "${#f[@]}" -ge 5 ]]; then
        _CFR_IP="${f[0]}"; _CFR_SCOPE="${f[1]}"; _CFR_SID="${f[2]}"; _CFR_RID="${f[3]}"; _CFR_EXP="${f[4]}"
    elif [[ "${#f[@]}" -eq 4 ]]; then
        _CFR_IP="${f[0]}"; _CFR_SCOPE="zone"; _CFR_SID="${f[1]}"; _CFR_RID="${f[2]}"; _CFR_EXP="${f[3]}"
    else
        return 1
    fi
    [[ -n "${_CFR_IP}" ]]
}

# Delete a recorded rule, trying every token (cheap, few) since any account's
# token may own the scope. Returns 0 if some token deleted it.
_cf_delete_ref() {
    local scope="$1" sid="$2" rid="$3" path acct tok
    path="$(_cf_rule_path "$scope" "$sid" "$rid")"
    for acct in "${!_CF_TOKEN[@]}"; do
        tok="${_CF_TOKEN[$acct]}"
        if _cf_api "$tok" DELETE "$path" | jq -e '.success==true' >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# swatter_cf_unblock <ip>: remove every Swatter-created access rule for this IP,
# using the recorded (scope,scope_id,rule) refs. A ref whose API delete FAILED is
# kept and the unblock returns 1: dropping it would orphan a live CF rule with no
# handle left to ever remove it (retry and the expiry sweep both work off this
# file), while the operator walks away believing the IP is clear.
swatter_cf_unblock() {
    local ip="$1" refs="${STATE_DIR}/cf-rules.tsv" rc=0
    # Clean up recorded CF rules regardless of the CURRENT CF_MODE: a rule created
    # while CF was active must stay unblockable even after CF is turned off, or it
    # is stranded (an unremovable edge ban). Gate on refs existing, not on the plane
    # being currently managed. No creds -> _cf_delete_ref fails and the ref is kept.
    [[ -f "$refs" && -s "$refs" ]] || return 0
    _cf_load
    local keep
    keep="$(mktemp "${TMPDIR:-/tmp}/swatter-cfrules.XXXXXX")" \
        || { log_error "cloudflare unblock ${ip}: mktemp failed — refs untouched"; return 1; }
    local line _CFR_IP _CFR_SCOPE _CFR_SID _CFR_RID _CFR_EXP
    while IFS= read -r line; do
        _cf_parse_ref "$line" || continue
        if [[ "${_CFR_IP}" != "$ip" ]]; then
            printf '%s\t%s\t%s\t%s\t%s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" "${_CFR_EXP}" >> "$keep"
            continue
        fi
        if _cf_delete_ref "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}"; then
            log_info "cloudflare unblock ${ip} (${_CFR_SCOPE} ${_CFR_SID}, rule ${_CFR_RID})"
        else
            printf '%s\t%s\t%s\t%s\t%s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" "${_CFR_EXP}" >> "$keep"
            log_error "cloudflare unblock ${ip} FAILED (${_CFR_SCOPE} ${_CFR_SID}, rule ${_CFR_RID}) — rule may still be live; ref kept for retry/sweep"
            rc=1
        fi
    done < "$refs"
    # Full-file rewrite is safe against a concurrent append: the scan holds the
    # entrypoint flock and `swatter unblock` now takes the same lock
    # (swatter_with_state_lock), so no other process is appending to cf-rules.tsv
    # while this read+mv runs.
    mv "$keep" "$refs" 2>/dev/null || { rm -f "$keep"; rc=1; }
    (( rc )) && SWATTER_LAST_BACKEND_ERR="cloudflare rule delete failed (ref kept; retry unblock or wait for the expiry sweep)"
    return "$rc"
}

# Sweep expired Swatter access rules (TTL emulation) using recorded refs.
swatter_cf_sweep_expired() {
    # Sweep recorded rules regardless of the CURRENT CF_MODE — a TTL promised when
    # CF was active must still be honoured after CF is turned off, or the rule is
    # stranded (a permanent edge ban). Gate on refs existing, not on the plane being
    # managed. No creds -> _cf_delete_ref fails and the ref is kept for a later run.
    local refs="${STATE_DIR}/cf-rules.tsv"
    [[ -f "$refs" && -s "$refs" ]] || return 0
    [[ "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0
    _cf_load
    local now; now="$(swatter_now)"
    # Fail closed on mktemp (like unblock): sweeping without a keep-file would
    # otherwise rewrite the refs from an empty file, orphaning every live rule.
    local keep
    keep="$(mktemp "${TMPDIR:-/tmp}/swatter-cfrules.XXXXXX")" \
        || { log_error "cloudflare sweep: mktemp failed — refs untouched, sweep skipped"; return 1; }
    local line _CFR_IP _CFR_SCOPE _CFR_SID _CFR_RID _CFR_EXP
    while IFS= read -r line; do
        _cf_parse_ref "$line" || continue
        if [[ "${_CFR_EXP:-0}" =~ ^[0-9]+$ ]] && (( _CFR_EXP < now )); then
            # Sweep regardless of mode: removing an expired rule is cleanup, not
            # enforcement — the TTL was promised when the rule was created.
            # Gating this on enforce stranded every live rule (permanently
            # blocked) whenever the operator rolled back to report mode. Rows we
            # cannot delete (token gone) are kept so a later run retries.
            if _cf_delete_ref "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}"; then
                log_info "cloudflare sweep: expired rule ${_CFR_RID} (${_CFR_SCOPE} ${_CFR_SID}) removed"
            else
                printf '%s\t%s\t%s\t%s\t%s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" "${_CFR_EXP}" >> "$keep"
            fi
        else
            printf '%s\t%s\t%s\t%s\t%s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" "${_CFR_EXP}" >> "$keep"
        fi
    done < "$refs"
    mv "$keep" "$refs" 2>/dev/null || rm -f "$keep"
}

# List Swatter-owned CF blocks (from recorded refs).
swatter_cf_list_rules() {
    local refs="${STATE_DIR}/cf-rules.tsv"
    [[ -f "$refs" ]] || { echo "(no Cloudflare blocks recorded)"; return 0; }
    printf '%-16s %-8s %-34s %-22s %s\n' "IP" "SCOPE" "SCOPE-ID" "RULE" "EXPIRES"
    local line _CFR_IP _CFR_SCOPE _CFR_SID _CFR_RID _CFR_EXP
    while IFS= read -r line; do
        _cf_parse_ref "$line" || continue
        # GNU `date -d @epoch` and BSD/macOS `date -r epoch` both tried; a host
        # with neither just prints the raw epoch (display-only, never load-bearing).
        printf '%-16s %-8s %-34s %-22s %s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" \
            "$(date -u -d "@${_CFR_EXP}" '+%Y-%m-%d %H:%M' 2>/dev/null \
               || date -u -r "${_CFR_EXP}" '+%Y-%m-%d %H:%M' 2>/dev/null \
               || echo "${_CFR_EXP}")"
    done < "$refs"
}
