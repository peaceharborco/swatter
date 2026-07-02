#!/usr/bin/env bash
# providers/abuseipdb.sh — AbuseIPDB reputation (free tier: 1000 checks/day).
#
# https://docs.abuseipdb.com/ — GET /api/v2/check returns abuseConfidenceScore
# (0-100), which we use directly. Needs ABUSEIPDB_KEY. A per-day quota counter
# in $STATE_DIR/feeds/abuseipdb.quota.<YYYYMMDD> stops us exceeding the free
# tier; once exhausted the provider returns "no data" and scanning continues.

ABUSEIPDB_URL="https://api.abuseipdb.com/api/v2/check"

_abuseipdb_quota_file() {
    printf '%s/feeds/abuseipdb.quota.%s' "${STATE_DIR}" "$(date -u +%Y%m%d)"
}

_abuseipdb_quota_ok() {
    local qf used; qf="$(_abuseipdb_quota_file)"
    used="$(cat "$qf" 2>/dev/null || echo 0)"
    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    (( used < ABUSEIPDB_DAILY_QUOTA ))
}

_abuseipdb_quota_inc() {
    local qf used; qf="$(_abuseipdb_quota_file)"
    used="$(cat "$qf" 2>/dev/null || echo 0)"
    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    printf '%s' "$(( used + 1 ))" > "$qf" 2>/dev/null || true
}

provider_abuseipdb() {
    local ip="$1"
    [[ -n "${ABUSEIPDB_KEY}" ]] || return 1
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || return 1
    _abuseipdb_quota_ok || { log_debug "abuseipdb daily quota exhausted"; return 1; }

    # API key via -K config file, never argv (visible in `ps` on a shared box).
    local cfg resp rc score
    cfg="$(swatter_curl_cfg "header = \"Key: ${ABUSEIPDB_KEY}\"")" || return 1
    resp="$(curl --max-time 5 -fsS -G "${ABUSEIPDB_URL}" \
        --data-urlencode "ipAddress=${ip}" --data-urlencode "maxAgeInDays=90" \
        -K "$cfg" -H "Accept: application/json" 2>/dev/null)"; rc=$?
    rm -f "$cfg"
    (( rc == 0 )) || return 1
    _abuseipdb_quota_inc
    score="$(printf '%s' "$resp" | jq -r '.data.abuseConfidenceScore // empty' 2>/dev/null)"
    [[ "$score" =~ ^[0-9]+$ ]] || return 1
    printf '%s\t%s\tconfidence%s\n' "$score" "$INTEL_CACHE_TTL" "$score"
}
