#!/usr/bin/env bash
# providers/projecthoneypot.sh — Project Honey Pot http:BL (DNS blocklist).
#
# Query <KEY>.<reversed-octets>.dnsbl.httpbl.org A. A hit answers 127.D.S.T:
# D=days-since-activity, S=threat 0-255, T=visitor-type bitmask
# (0=search engine, 1=suspicious, 2=harvester, 4=comment spammer). IPv4 only.
# Type 0 means octet3 is a SEARCH-ENGINE ID, not a threat -> no data. Any DNS
# failure, NXDOMAIN, or non-127 answer -> no data.

provider_projecthoneypot() {
    local ip="$1"
    [[ -n "${HTTPBL_KEY:-}" ]] || return 1
    [[ "${SWATTER_HAVE_DNS:-0}" -eq 1 ]] || return 1
    # IPv4 only.
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1

    local o1 o2 o3 o4; IFS=. read -r o1 o2 o3 o4 <<<"$ip"
    local query="${HTTPBL_KEY}.${o4}.${o3}.${o2}.${o1}.dnsbl.httpbl.org"
    local a; a="$(_swatter_dns_a "$query")"
    [[ -n "$a" ]] || return 1

    local a1 days threat vtype; IFS=. read -r a1 days threat vtype <<<"$a"
    [[ "$a1" == "127" ]] || return 1
    [[ "$vtype" =~ ^[0-9]+$ && "$threat" =~ ^[0-9]+$ ]] || return 1
    (( vtype == 0 )) && return 1     # pure search engine: octet3 is an SE id

    local score=$(( threat * 100 / 255 )); (( score > 100 )) && score=100
    printf '%s\t%s\thttpbl:t%s:s%s:d%s\t\n' "$score" "${INTEL_CACHE_TTL}" "$vtype" "$threat" "$days"
}
