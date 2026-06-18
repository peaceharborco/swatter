#!/usr/bin/env bash
# providers/spamhaus.sh — Spamhaus DROP list (no API key).
#
# https://www.spamhaus.org/drop/ — CIDR blocks Spamhaus advises dropping
# entirely (hijacked/criminal netblocks). Any IP inside one is unambiguously
# bad -> score 100. The list is fetched by `swatter refresh-feeds` into
# $STATE_DIR/feeds/spamhaus.cidr; lookup reuses the allowlist CIDR matcher.
# (EDROP was deprecated and its content merged into drop.txt — removed 2026-06.)

SPAMHAUS_DROP_URL="https://www.spamhaus.org/drop/drop.txt"

provider_spamhaus_refresh() {
    local out="${STATE_DIR}/feeds/spamhaus.cidr"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "spamhaus refresh needs curl"; return 1; }
    curl --max-time 30 -fsS "${SPAMHAUS_DROP_URL}" > "${out}.raw" 2>/dev/null
    if awk '/^[0-9]/{print $1}' "${out}.raw" > "${out}.tmp" 2>/dev/null \
        && [[ -s "${out}.tmp" ]]; then
        sort -u "${out}.tmp" > "$out"; rm -f "${out}.raw" "${out}.tmp"
        log_info "spamhaus feed refreshed ($(wc -l < "$out" 2>/dev/null | tr -d ' ') CIDRs)"
    else
        rm -f "${out}.raw" "${out}.tmp" 2>/dev/null
        log_warn "spamhaus feed download failed"; return 1
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
