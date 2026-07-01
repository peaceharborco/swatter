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
        while IFS=$'\t ' read -r acct tok _; do
            [[ -z "$acct" || "${acct:0:1}" == "#" || -z "$tok" ]] && continue
            _CF_TOKEN["$acct"]="$tok"
        done < "${CF_CREDS_FILE:-/etc/swatter/cloudflare.creds}"
    fi
    if [[ -r "${CF_DOMAINS_MAP:-/etc/swatter/cf-domains.map}" ]]; then
        local dom ac
        while IFS=$'\t ' read -r dom ac _; do
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
# account+token line invalidates it (mtime bump) and forces a re-resolve; to pick
# up an account newly granted to an *existing* token (creds unchanged), delete
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
    # Cache hit only if present, non-empty, AND newer than the creds file.
    if [[ -s "$cache" && "$cache" -nt "$creds" ]]; then
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
    local args=(-sS -X "$method" "${CF_API}${path}"
        -H "Authorization: Bearer ${token}" -H "Content-Type: application/json")
    [[ -n "$body" ]] && args+=(--data "$body")
    curl --max-time 10 "${args[@]}" 2>/dev/null
}

# Resolve + cache a zone id for a domain (per-account token). Cache file keyed by
# domain under $STATE_DIR/cf-zones/.
_cf_zone_id() {
    local domain="$1" token="$2"
    local cache="${STATE_DIR}/cf-zones/${domain}"
    if [[ -f "$cache" ]]; then cat "$cache"; return 0; fi
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

# A create response that is success OR an idempotent duplicate ("already
# exists"/"identical") is, for our purposes, a rule in place. Returns 0 and
# echoes the rule id when the API minted one (empty on duplicate).
_cf_create_ok() {
    # _cf_create_ok <response>  -> echoes rule id (may be empty); rc 0 if in place
    local resp="$1"
    if printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
        printf '%s' "$resp" | jq -r '.result.id // empty'; return 0
    fi
    if printf '%s' "$resp" | jq -e '[.errors[]?.message] | any(test("already exists|identical"))' >/dev/null 2>&1; then
        return 0
    fi
    return 1
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
    if rid="$(_cf_create_ok "$resp")"; then
        # Record the (scope,scope_id,rule) ref so unblock/sweep are O(1). A bare
        # duplicate yields no id (nothing to record beyond what a prior run did).
        [[ -n "$rid" ]] && printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "zone" "$zid" "$rid" "$expiry" >> "${STATE_DIR}/cf-rules.tsv" 2>/dev/null || true
        log_info "cloudflare ${CF_ACTION} ${ip} in ${vhost} (zone ${zid}, acct ${acct})"
        return 0
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
    for aid in "${!_CF_TOKEN_OF_ACCTID[@]}"; do
        token="${_CF_TOKEN_OF_ACCTID[$aid]}"
        resp="$(_cf_api "$token" POST "$(_cf_rule_path account "$aid")" "$payload")"
        if rid="$(_cf_create_ok "$resp")"; then
            [[ -n "$rid" ]] && printf '%s\t%s\t%s\t%s\t%s\n' "$ip" "account" "$aid" "$rid" "$expiry" >> "${STATE_DIR}/cf-rules.tsv" 2>/dev/null || true
            log_info "cloudflare ${CF_ACTION} ${ip} on account ${aid}"
            ok=$(( ok + 1 ))
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
# using the recorded (scope,scope_id,rule) refs.
swatter_cf_unblock() {
    local ip="$1" refs="${STATE_DIR}/cf-rules.tsv"
    swatter_cf_manages_plane || return 0
    [[ -f "$refs" ]] || return 0
    _cf_load
    local line _CFR_IP _CFR_SCOPE _CFR_SID _CFR_RID _CFR_EXP
    while IFS= read -r line; do
        _cf_parse_ref "$line" || continue
        [[ "${_CFR_IP}" == "$ip" ]] || continue
        if _cf_delete_ref "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}"; then
            log_info "cloudflare unblock ${ip} (${_CFR_SCOPE} ${_CFR_SID}, rule ${_CFR_RID})"
        fi
    done < "$refs"
    # Drop this IP's refs. grep -v exits 1 when no lines survive (unblocking the
    # last IP in the file), so the mv must not be gated on its status.
    grep -v "^${ip}$(printf '\t')" "$refs" > "${refs}.tmp" 2>/dev/null || true
    mv "${refs}.tmp" "$refs"
}

# Sweep expired Swatter access rules (TTL emulation) using recorded refs.
swatter_cf_sweep_expired() {
    swatter_cf_manages_plane || return 0
    local refs="${STATE_DIR}/cf-rules.tsv"
    [[ -f "$refs" ]] || return 0
    [[ "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0
    _cf_load
    local now; now="$(swatter_now)"
    local keep; keep="$(mktemp "${TMPDIR:-/tmp}/swatter-cfrules.XXXXXX")"
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
        printf '%-16s %-8s %-34s %-22s %s\n' "${_CFR_IP}" "${_CFR_SCOPE}" "${_CFR_SID}" "${_CFR_RID}" \
            "$(date -u -d "@${_CFR_EXP}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "${_CFR_EXP}")"
    done < "$refs"
}
