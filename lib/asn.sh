#!/usr/bin/env bash
# lib/asn.sh — Team Cymru IP->ASN origin lookup + hosting-set match.
#
# Resolves an IP's origin ASN via Cymru DNS (origin.asn.cymru.com /
# origin6.asn.cymru.com), cached under $STATE_DIR/asn/<ip>. The hosting match is
# evaluated LIVE against HOSTING_ASNS_FILE each call, so editing the list takes
# effect without re-resolving. Only ever called for IPs past WATCH.

# Reverse IPv4 octets: 1.2.3.4 -> 4.3.2.1
_asn_rev_v4() { local a b c d; IFS=. read -r a b c d <<<"$1"; printf '%s.%s.%s.%s' "$d" "$c" "$b" "$a"; }

# swatter_asn_resolve <ip> : echo origin ASN (digits) or nothing.
swatter_asn_resolve() {
    local ip="$1" cache="${STATE_DIR}/asn/$1" now mtime age txt asn
    [[ "${SWATTER_HAVE_DNS:-0}" -eq 1 ]] || return 1
    if [[ -f "$cache" ]]; then
        now="$(swatter_now)"; mtime="$(stat_mtime "$cache" 2>/dev/null || echo 0)"
        age=$(( now - mtime ))
        if (( age < INTEL_CACHE_TTL )); then cat "$cache" 2>/dev/null; return 0; fi
    fi
    local query
    if [[ "$ip" == *:* ]]; then
        # TODO(v1.3.1): origin6 nibble-reverse for IPv6 ASN lookups; v4 covers
        # the shipped default hosting list. No boost applied to v6 today (safe).
        return 1
    else
        query="$(_asn_rev_v4 "$ip").origin.asn.cymru.com"
    fi
    txt="$(_swatter_dns_txt "$query")" || return 1
    [[ -n "$txt" ]] || return 1
    # "13335 | 1.1.1.0/24 | US | arin | ..." ; first field, first token (multi-origin).
    asn="$(printf '%s' "$txt" | cut -d'|' -f1 | tr -d ' ' )"
    asn="${asn%% *}"
    [[ "$asn" =~ ^[0-9]+$ ]] || return 1
    mkdir -p "${STATE_DIR}/asn" 2>/dev/null && printf '%s' "$asn" > "$cache" 2>/dev/null
    printf '%s' "$asn"
}

# swatter_asn_is_hosting <ip> : echo "AS<n>(<name>)" + return 0 if hosting, else 1.
swatter_asn_is_hosting() {
    local ip="$1" asn line fasn name
    [[ -f "${HOSTING_ASNS_FILE:-}" ]] || return 1
    asn="$(swatter_asn_resolve "$ip")" || return 1
    [[ -n "$asn" ]] || return 1
    while IFS= read -r line; do
        line="${line%%#*}"; fasn="$(printf '%s' "$line" | tr -d ' ')"
        [[ -z "$fasn" ]] && continue
        if [[ "$fasn" == "$asn" ]]; then
            name="$(awk -v a="$asn" '$1==a{sub(/^[^#]*#[ ]*/,""); print; exit}' "${HOSTING_ASNS_FILE}")"
            printf 'AS%s(%s)' "$asn" "${name:-hosting}"; return 0
        fi
    done < "${HOSTING_ASNS_FILE}"
    return 1
}

# _swatter_asn_attack_shaped <evidence_json> : 0 if attack-shaped, else 1.
_swatter_asn_attack_shaped() {
    local ev="$1" rule hibad burst
    rule="$(printf '%s' "$ev"  | sed -n 's/.*"decisive_rule":"\([^"]*\)".*/\1/p')"
    hibad="$(printf '%s' "$ev" | sed -n 's/.*"hibad_fail":\([0-9]*\).*/\1/p')"
    burst="$(printf '%s' "$ev" | sed -n 's/.*"burst":\([0-9]*\).*/\1/p')"
    [[ -n "$rule" ]] && return 0
    [[ "$hibad" =~ ^[0-9]+$ ]] && (( hibad > 0 )) && return 0
    [[ "$burst" =~ ^[0-9]+$ ]] && (( burst >= 50 )) && return 0
    return 1
}
