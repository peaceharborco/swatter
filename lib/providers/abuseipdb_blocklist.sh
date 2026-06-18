#!/usr/bin/env bash
# providers/abuseipdb_blocklist.sh — AbuseIPDB daily blocklist (opt-in).
#
# Downloads the GET /api/v2/blacklist plaintext list (IPs at/above
# ABUSEIPDB_BLOCKLIST_CONFIDENCE) once per `refresh-feeds` into
# $STATE_DIR/feeds/abuseipdb_blocklist.txt; lookup is a grep -> score 90. Reuses
# ABUSEIPDB_KEY. Opt-in: add 'abuseipdb_blocklist' to INTEL_PROVIDERS. Inert (no
# fetch, no-data) without the key or curl; any HTTP failure keeps the prior file.

ABUSEIPDB_BLOCKLIST_URL="https://api.abuseipdb.com/api/v2/blacklist"

provider_abuseipdb_blocklist_refresh() {
    local out="${STATE_DIR}/feeds/abuseipdb_blocklist.txt"
    [[ -n "${ABUSEIPDB_KEY:-}" ]] || { log_warn "abuseipdb_blocklist needs ABUSEIPDB_KEY"; return 1; }
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "abuseipdb_blocklist needs curl"; return 1; }
    if curl --max-time 30 -fsS -G "${ABUSEIPDB_BLOCKLIST_URL}" \
        --data-urlencode "confidenceMinimum=${ABUSEIPDB_BLOCKLIST_CONFIDENCE:-90}" \
        -H "Key: ${ABUSEIPDB_KEY}" -H "Accept: text/plain" 2>/dev/null \
        | awk '/^[0-9A-Fa-f]/{print $1}' > "${out}.tmp" 2>/dev/null && [[ -s "${out}.tmp" ]]; then
        mv "${out}.tmp" "$out"
        log_info "abuseipdb_blocklist refreshed ($(wc -l < "$out" 2>/dev/null | tr -d ' ') IPs)"
    else
        rm -f "${out}.tmp" 2>/dev/null; log_warn "abuseipdb_blocklist download failed"; return 1
    fi
}

provider_abuseipdb_blocklist() {
    local ip="$1" feed="${STATE_DIR}/feeds/abuseipdb_blocklist.txt"
    [[ -f "$feed" ]] || return 1
    awk -v ip="$ip" '$1==ip{f=1; exit} END{exit !f}' "$feed" 2>/dev/null || return 1
    printf '90\t%s\tabuseipdb_blocklist\n' "${INTEL_CACHE_TTL}"
}
