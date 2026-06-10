#!/usr/bin/env bash
# lib/block_cf.sh — the Cloudflare WAF plane (offenders arriving via the proxy).
#
# Used for offenders classified VIA_CF, whose TCP socket is a Cloudflare edge and
# therefore must NOT be CSF-denied. Two modes:
#   direct  — call the Cloudflare API and add a custom firewall rule per zone
#             (ip.src eq <ip> -> block|managed_challenge). TTL is emulated:
#             swatter_cf_sweep_expired removes rules past their TTL each run.
#   native  — let CSF mirror the deny to Cloudflare via `csf --cloudflare deny`
#             (operator must have populated csf.cloudflare).
#
# Cloudflare has no native per-rule TTL on custom rules, so Swatter stamps the
# expiry into the rule description and sweeps. Requires jq + curl in direct mode.

CF_API="https://api.cloudflare.com/client/v4"

_cf_zone_ids() {
    # CF_ZONES = "domain:zoneid domain2:zoneid2" -> emit zoneids, one per line.
    local pair
    for pair in ${CF_ZONES}; do
        [[ "$pair" == *:* ]] && printf '%s\n' "${pair#*:}"
    done
}

_cf_api() {
    # _cf_api <method> <path> [json-body]
    local method="$1" path="$2" body="${3:-}"
    local args=(-sS -X "$method" "${CF_API}${path}"
        -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")
    [[ -n "$body" ]] && args+=(--data "$body")
    curl --max-time 10 "${args[@]}" 2>/dev/null
}

# swatter_cf_block <ip> <ttl_seconds> <reason>
swatter_cf_block() {
    local ip="$1" ttl="$2" reason="$3"
    local expiry; expiry=$(( $(swatter_now) + ttl ))
    local note="${CF_RULE_PREFIX}|exp=${expiry}|${reason}"

    if [[ "${CF_MODE}" == "off" ]]; then
        log_debug "CF_MODE=off; not blocking ${ip} on Cloudflare plane"
        return 0
    fi

    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] cloudflare ${CF_ACTION} ${ip} (${reason})"
        return 0
    fi

    if [[ "${CF_MODE}" == "native" ]]; then
        if [[ "${SWATTER_HAVE_CSF}" -eq 1 ]]; then
            csf --cloudflare deny "$ip" >/dev/null 2>&1 \
                && { log_info "cloudflare(native) deny ${ip}"; return 0; }
        fi
        log_error "native CF deny failed for ${ip}"; return 1
    fi

    # direct mode
    if [[ "${SWATTER_HAVE_JQ}" -ne 1 || "${SWATTER_HAVE_CURL}" -ne 1 ]]; then
        log_error "CF direct mode needs jq+curl; cannot block ${ip}"; return 1
    fi
    if [[ -z "${CF_API_TOKEN}" || -z "${CF_ZONES}" ]]; then
        log_error "CF_API_TOKEN/CF_ZONES unset; cannot block ${ip} on Cloudflare"; return 1
    fi

    local zid rc ok=0
    while IFS= read -r zid; do
        [[ -n "$zid" ]] || continue
        # Cloudflare Rulesets API: add a custom-rule to the zone's
        # http_request_firewall_custom phase entrypoint.
        local payload
        payload="$(jq -nc --arg ip "$ip" --arg act "${CF_ACTION}" --arg note "$note" '
            {action:$act, expression:("ip.src eq "+$ip), description:$note, enabled:true}')"
        rc="$(_cf_api POST "/zones/${zid}/rulesets/phases/http_request_firewall_custom/entrypoint/rules" "$payload")"
        if printf '%s' "$rc" | jq -e '.success == true' >/dev/null 2>&1; then
            ok=1
        else
            log_warn "CF rule add failed zone=${zid} ip=${ip}: $(printf '%s' "$rc" | jq -rc '.errors // empty' 2>/dev/null)"
        fi
    done < <(_cf_zone_ids)

    if (( ok )); then log_info "cloudflare ${CF_ACTION} ${ip} (${reason})"; return 0; fi
    return 1
}

# Remove a Swatter-owned CF rule for an IP across all zones (unblock).
swatter_cf_unblock() {
    local ip="$1"
    [[ "${CF_MODE}" == "direct" && "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0
    [[ -n "${CF_API_TOKEN}" && -n "${CF_ZONES}" ]] || return 0
    local zid
    while IFS= read -r zid; do
        [[ -n "$zid" ]] || continue
        local rules
        rules="$(_cf_api GET "/zones/${zid}/rulesets/phases/http_request_firewall_custom/entrypoint")"
        local rid
        while IFS= read -r rid; do
            [[ -n "$rid" ]] || continue
            _cf_api DELETE "/zones/${zid}/rulesets/phases/http_request_firewall_custom/entrypoint/rules/${rid}" >/dev/null
            log_info "cloudflare unblock ${ip} (rule ${rid} zone ${zid})"
        done < <(printf '%s' "$rules" | jq -r --arg ip "$ip" --arg px "${CF_RULE_PREFIX}" \
            '.result.rules[]? | select(.description|startswith($px)) | select(.expression | test("ip.src eq "+($ip|gsub("\\.";"\\.")))) | .id' 2>/dev/null)
    done < <(_cf_zone_ids)
}

# Sweep expired Swatter rules (TTL emulation). Run once per scan.
swatter_cf_sweep_expired() {
    [[ "${CF_MODE}" == "direct" ]] || return 0
    [[ "${SWATTER_HAVE_JQ}" -eq 1 && "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0
    [[ -n "${CF_API_TOKEN}" && -n "${CF_ZONES}" ]] || return 0
    local now; now="$(swatter_now)"
    local zid
    while IFS= read -r zid; do
        [[ -n "$zid" ]] || continue
        local rules
        rules="$(_cf_api GET "/zones/${zid}/rulesets/phases/http_request_firewall_custom/entrypoint")"
        local rid
        while IFS= read -r rid; do
            [[ -n "$rid" ]] || continue
            if [[ "${SWATTER_MODE}" == "enforce" ]]; then
                _cf_api DELETE "/zones/${zid}/rulesets/phases/http_request_firewall_custom/entrypoint/rules/${rid}" >/dev/null
                log_info "cloudflare sweep: removed expired rule ${rid} zone ${zid}"
            else
                log_info "[dry-run] cloudflare sweep would remove expired rule ${rid} zone ${zid}"
            fi
        done < <(printf '%s' "$rules" | jq -r --arg px "${CF_RULE_PREFIX}" --argjson now "$now" '
            .result.rules[]? | select(.description|startswith($px))
            | (.description | capture("exp=(?<e>[0-9]+)").e | tonumber) as $exp
            | select($exp < $now) | .id' 2>/dev/null)
    done < <(_cf_zone_ids)
}
