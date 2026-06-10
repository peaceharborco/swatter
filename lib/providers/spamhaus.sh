#!/usr/bin/env bash
# providers/spamhaus.sh — Spamhaus DROP + EDROP lists (no API key).
#
# https://www.spamhaus.org/drop/ — CIDR blocks Spamhaus advises dropping
# entirely (hijacked/criminal netblocks). Any IP inside one is unambiguously
# bad -> score 100. Lists are fetched by `swatter refresh-feeds` into
# $STATE_DIR/feeds/spamhaus.cidr; lookup reuses the allowlist CIDR matcher.

SPAMHAUS_DROP_URL="https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL="https://www.spamhaus.org/drop/edrop.txt"

provider_spamhaus_refresh() {
    local out="${STATE_DIR}/feeds/spamhaus.cidr"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "spamhaus refresh needs curl"; return 1; }
    : > "${out}.tmp"
    local url ok=0
    for url in "${SPAMHAUS_DROP_URL}" "${SPAMHAUS_EDROP_URL}"; do
        if curl --max-time 30 -fsS "$url" 2>/dev/null \
            | awk '/^[0-9]/{print $1}' >> "${out}.tmp"; then ok=1; fi
    done
    if (( ok )) && [[ -s "${out}.tmp" ]]; then
        sort -u "${out}.tmp" > "$out"; rm -f "${out}.tmp"
        log_info "spamhaus feed refreshed ($(wc -l < "$out" 2>/dev/null) CIDRs)"
    else
        rm -f "${out}.tmp" 2>/dev/null; log_warn "spamhaus feed download failed"; return 1
    fi
}

provider_spamhaus() {
    local ip="$1" feed="${STATE_DIR}/feeds/spamhaus.cidr"
    [[ -f "$feed" ]] || return 1
    # _ip_in_cidr_file comes from lib/allowlist.sh (sourced by the entrypoint).
    if declare -F _ip_in_cidr_file >/dev/null && _ip_in_cidr_file "$ip" "$feed"; then
        printf '100\t%s\tdrop\n' "$INTEL_CACHE_TTL"
        return 0
    fi
    return 1
}
