#!/usr/bin/env bash
# lib/block_cf.sh — the Cloudflare plane (offenders arriving via the proxy).
#
# Used for offenders classified VIA_CF, whose TCP socket is a Cloudflare edge and
# therefore must NOT be CSF-denied. Blocks via zone-level IP Access Rules
# (`/zones/{id}/firewall/access_rules/rules`) — deliberately a DIFFERENT product
# from the WAF Rulesets that cf-push-rules.sh owns, so the two never clobber each
# other. IP Access Rules also scale to many entries (unlike the 5-custom-rule cap
# on Free zones), and a minimal "Firewall Services: Edit" token is enough.
#
# Multi-account: each offender is blocked in the specific zone it attacked (the
# top vhost from scoring). The vhost maps to a CF account via CF_DOMAINS_MAP; the
# account maps to a token via CF_CREDS_FILE. Zone IDs are resolved once and
# cached. Cloudflare IP Access Rules have no native TTL, so Swatter stamps the
# expiry into the rule notes and sweeps expired rules each run.
#
# CF_MODE: direct = use the IP Access Rules API (this file). skip = the operator
# owns the Cloudflare plane (their own WAF/rate-limit stack); score.sh records
# VIA_CF offenders without acting and never calls in here. off = not behind
# Cloudflare at all.

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

# swatter_cf_block <ip> <ttl> <reason> <vhost>
swatter_cf_block() {
    local ip="$1" ttl="$2" reason="$3" vhost="${4:-}"
    # Belt over score.sh's routing: only a plane-managing posture may create
    # rules (explicit direct, or auto that detected CF + has creds). Return 1 so a
    # caller bug can't record a block that never happened.
    swatter_cf_manages_plane || { log_debug "CF_MODE=${CF_MODE}; not CF-blocking ${ip}"; return 1; }
    _cf_load

    if [[ -z "$vhost" ]]; then
        log_warn "CF block ${ip}: no target vhost in evidence; cannot pick a zone — skipping"
        return 1
    fi
    local acct; acct="$(_cf_account_for_vhost "$vhost")" || {
        log_warn "CF block ${ip}: vhost ${vhost} not in CF_DOMAINS_MAP — skipping (add it or it's a skip-profile domain)"
        return 1
    }
    local token="${_CF_TOKEN[$acct]:-}"
    [[ -n "$token" ]] || { log_warn "CF block ${ip}: no token for account ${acct} in CF_CREDS_FILE — skipping"; return 1; }

    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] cloudflare ${CF_ACTION} ${ip} in ${vhost} (acct ${acct}; ${reason})"
        return 0
    fi
    [[ "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_error "CF plane needs jq+curl"; return 1; }

    local zid; zid="$(_cf_zone_id "$vhost" "$token")" || { log_warn "CF block ${ip}: could not resolve zone for ${vhost}"; return 1; }
    local expiry note payload resp rid
    expiry=$(( $(swatter_now) + ttl ))
    note="${CF_RULE_PREFIX:-swatter}|exp=${expiry}|${reason}"
    payload="$(jq -nc --arg ip "$ip" --arg mode "${CF_ACTION}" --arg note "$note" \
        '{mode:$mode, configuration:{target:"ip", value:$ip}, notes:$note}')"
    resp="$(_cf_api "$token" POST "/zones/${zid}/firewall/access_rules/rules" "$payload")"
    if printf '%s' "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
        rid="$(printf '%s' "$resp" | jq -r '.result.id')"
        # Record the (zone,rule) ref so unblock/sweep are O(1).
        printf '%s\t%s\t%s\t%s\n' "$ip" "$zid" "$rid" "$expiry" >> "${STATE_DIR}/cf-rules.tsv" 2>/dev/null || true
        log_info "cloudflare ${CF_ACTION} ${ip} in ${vhost} (zone ${zid}, acct ${acct})"
        return 0
    fi
    # A duplicate (already blocked) is success for our purposes.
    if printf '%s' "$resp" | jq -e '[.errors[]?.message] | any(test("already exists|identical"))' >/dev/null 2>&1; then
        log_info "cloudflare ${ip} already blocked in ${vhost}"
        return 0
    fi
    log_warn "CF block ${ip} in ${vhost} failed: $(printf '%s' "$resp" | _cf_err_summary)"
    return 1
}

# Reduce a CF API error response (stdin) to one log-friendly line. Must
# tolerate every shape the API can return: empty .errors arrays, items
# without .message, no .errors at all, and non-JSON bodies.
_cf_err_summary() {
    local s
    s="$(jq -rc '[.errors[]?.message // empty] | if length == 0 then "unknown error" else join("; ") end' 2>/dev/null | cut -c1-200)"
    printf '%s' "${s:-unknown error}"
}

# swatter_cf_unblock <ip>: remove every Swatter-created access rule for this IP,
# using the (zone,rule) refs we recorded.
swatter_cf_unblock() {
    local ip="$1" refs="${STATE_DIR}/cf-rules.tsv"
    swatter_cf_manages_plane || return 0
    [[ -f "$refs" ]] || return 0
    _cf_load
    local rip zid rid exp
    while IFS=$'\t' read -r rip zid rid exp; do
        [[ "$rip" == "$ip" ]] || continue
        # Find a token whose account owns this zone: try every token (cheap, few).
        local acct tok
        for acct in "${!_CF_TOKEN[@]}"; do
            tok="${_CF_TOKEN[$acct]}"
            if _cf_api "$tok" DELETE "/zones/${zid}/firewall/access_rules/rules/${rid}" | jq -e '.success==true' >/dev/null 2>&1; then
                log_info "cloudflare unblock ${ip} (zone ${zid}, rule ${rid})"
                break
            fi
        done
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
    local rip zid rid exp acct tok removed
    while IFS=$'\t' read -r rip zid rid exp; do
        [[ -z "$rip" ]] && continue
        if [[ "${exp:-0}" =~ ^[0-9]+$ ]] && (( exp < now )); then
            # Sweep regardless of mode: removing an expired rule is cleanup, not
            # enforcement — the TTL was promised when the rule was created.
            # Gating this on enforce stranded every live rule (permanently
            # blocked) whenever the operator rolled back to report mode.
            removed=0
            for acct in "${!_CF_TOKEN[@]}"; do
                tok="${_CF_TOKEN[$acct]}"
                if _cf_api "$tok" DELETE "/zones/${zid}/firewall/access_rules/rules/${rid}" | jq -e '.success==true' >/dev/null 2>&1; then
                    log_info "cloudflare sweep: expired rule ${rid} (zone ${zid}) removed"; removed=1; break
                fi
            done
            (( removed )) || printf '%s\t%s\t%s\t%s\n' "$rip" "$zid" "$rid" "$exp" >> "$keep"
        else
            printf '%s\t%s\t%s\t%s\n' "$rip" "$zid" "$rid" "$exp" >> "$keep"
        fi
    done < "$refs"
    mv "$keep" "$refs" 2>/dev/null || rm -f "$keep"
}

# List Swatter-owned CF blocks (from recorded refs).
swatter_cf_list_rules() {
    local refs="${STATE_DIR}/cf-rules.tsv"
    [[ -f "$refs" ]] || { echo "(no Cloudflare blocks recorded)"; return 0; }
    printf '%-16s %-34s %-22s %s\n' "IP" "ZONE" "RULE" "EXPIRES"
    local rip zid rid exp
    while IFS=$'\t' read -r rip zid rid exp; do
        [[ -z "$rip" ]] && continue
        printf '%-16s %-34s %-22s %s\n' "$rip" "$zid" "$rid" "$(date -u -d "@${exp}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$exp")"
    done < "$refs"
}
