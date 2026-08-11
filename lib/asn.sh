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
        if (( age < INTEL_CACHE_TTL )); then
            # Re-validate on READ, not just on write (:37). A corrupt or
            # hand-written cache entry must not become an enforcement input now
            # that a matched ASN can DOWNGRADE a block.
            local cached; cached="$(cat "$cache" 2>/dev/null)"
            if [[ "$cached" =~ ^[0-9]+$ ]]; then printf '%s' "$cached"; return 0; fi
        fi
    fi
    local query
    if [[ "$ip" == *:* ]]; then
        # IPv6: expand to 32 hex nibbles, reverse + dot-separate, query origin6.
        declare -F _ipv6_expand >/dev/null || return 1
        local nib rev
        nib="$(_ipv6_expand "$ip")" || return 1
        rev="$(printf '%s' "$nib" | rev | sed 's/./&./g; s/\.$//')"
        query="${rev}.origin6.asn.cymru.com"
    else
        query="$(_asn_rev_v4 "$ip").origin.asn.cymru.com"
    fi
    txt="$(_swatter_dns_txt "$query")" || return 1
    [[ -n "$txt" ]] || return 1
    # first field before '|', then its first token (multi-origin prefixes list
    # several space-separated ASNs; we take the first).
    asn="$(printf '%s' "$txt" | awk -F'|' '{print $1; exit}' | awk '{print $1; exit}')"
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
    # burst is the burst SUBSCORE (0-100), not a raw count: 50 ≈ ~20 raw 403/404/444 hits.
    [[ "$burst" =~ ^[0-9]+$ ]] && (( burst >= 50 )) && return 0
    return 1
}

# --- shared consumer-VPN egress -------------------------------------------
# Memoized per process: "" unchecked, 1 usable, 0 rejected.
_SW_SHARED_CIDR_OK=""

# _swatter_shared_egress_cidr_usable : 0 if the CIDR file exists and every line
# is a valid, not-absurdly-broad prefix.
#
# _ip_in_cidr_file treats a /0 as match-everything (lib/allowlist.sh), so ONE
# bad line here would cap every perm on the host — silently, and in the
# direction nobody notices. Reuse the intel-feed poison guard with a tighter
# floor rather than inventing a second validator.
_swatter_shared_egress_cidr_usable() {
    local f="${SHARED_EGRESS_CIDR_FILE:-}"
    if [[ -n "$_SW_SHARED_CIDR_OK" ]]; then (( _SW_SHARED_CIDR_OK )); return; fi
    if [[ ! -s "$f" ]]; then _SW_SHARED_CIDR_OK=0; return 1; fi
    # swatter_intel_cidr_feed_ok validates raw downloaded feeds (no comments);
    # this file is hand-curated with trailing "# why" notes (see the shipped
    # config), so strip them first the same way _ip_in_cidr_file does on match.
    if sed 's/#.*//' "$f" \
       | INTEL_FEED_MIN_PREFIX4="${SHARED_EGRESS_MIN_PREFIX4:-16}" \
         INTEL_FEED_MIN_PREFIX6="${SHARED_EGRESS_MIN_PREFIX6:-32}" \
         swatter_intel_cidr_feed_ok; then
        _SW_SHARED_CIDR_OK=1; return 0
    fi
    log_warn "shared-egress: ${f} rejected (invalid or over-broad line) — CIDR arm off this run"
    _SW_SHARED_CIDR_OK=0; return 1
}

# swatter_is_shared_egress <ip> : echo a label + return 0 if the IP is shared
# consumer-VPN egress, else return 1 silently.
#
# CIDR first: it needs no network, so the known ranges stay protected even with
# DNS down. ASN second, and fail-open on any resolution failure — failing closed
# would make a third-party DNS service an availability lever on the whole ladder.
# Callers MUST have validated the IP already (the ASN cache key is the raw
# string); _swatter_apply_plane does this at :135, before the veto.
swatter_is_shared_egress() {
    local ip="$1" asn line fasn name
    [[ "${SHARED_EGRESS_ENABLE:-true}" == "true" ]] || return 1
    if _swatter_shared_egress_cidr_usable \
       && _ip_in_cidr_file "$ip" "${SHARED_EGRESS_CIDR_FILE}"; then
        printf 'cidr'; return 0
    fi
    [[ -s "${SHARED_EGRESS_ASNS_FILE:-}" ]] || return 1
    asn="$(swatter_asn_resolve "$ip")" || return 1
    [[ -n "$asn" ]] || return 1
    while IFS= read -r line; do
        line="${line%%#*}"; fasn="$(printf '%s' "$line" | tr -d ' ')"
        [[ -z "$fasn" ]] && continue
        if [[ "$fasn" == "$asn" ]]; then
            name="$(awk -v a="$asn" '$1==a{sub(/^[^#]*#[ ]*/,""); print; exit}' "${SHARED_EGRESS_ASNS_FILE}")"
            printf 'AS%s(%s)' "$asn" "${name:-shared-egress}"; return 0
        fi
    done < "${SHARED_EGRESS_ASNS_FILE}"
    return 1
}
