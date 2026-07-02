#!/usr/bin/env bash
# providers/greynoise.sh — GreyNoise Community API reputation + RIOT suppress.
#
# GET https://api.greynoise.io/v3/community/{ip} with header "key: <KEY>".
# Free Community tier. classification=malicious -> 100; riot=true -> suppress
# (known business service, soft-allowlist); benign -> 0 (label only); unknown
# or 404 -> no data. A per-day quota guard mirrors abuseipdb. Any transport
# failure is treated as no-data, never a block.

GREYNOISE_URL="https://api.greynoise.io/v3/community"

_greynoise_quota_file() { printf '%s/feeds/greynoise.quota.%s' "${STATE_DIR}" "$(date -u +%Y%m%d)"; }
_greynoise_quota_ok() {
    local qf used; qf="$(_greynoise_quota_file)"; used="$(cat "$qf" 2>/dev/null || echo 0)"
    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    (( used < ${GREYNOISE_DAILY_QUOTA:-100} ))
}
_greynoise_quota_inc() {
    local qf used; qf="$(_greynoise_quota_file)"; used="$(cat "$qf" 2>/dev/null || echo 0)"
    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    printf '%s' "$(( used + 1 ))" > "$qf" 2>/dev/null || true
}

provider_greynoise() {
    local ip="$1"
    [[ -n "${GREYNOISE_KEY:-}" ]] || return 1
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || return 1
    _greynoise_quota_ok || { log_debug "greynoise daily quota exhausted"; return 1; }

    # API key via -K config file, never argv (visible in `ps` on a shared box).
    local cfg resp rc
    cfg="$(swatter_curl_cfg "header = \"key: ${GREYNOISE_KEY}\"")" || return 1
    resp="$(curl --max-time 5 -fsS "${GREYNOISE_URL}/${ip}" \
        -K "$cfg" -H "Accept: application/json" 2>/dev/null)"; rc=$?
    rm -f "$cfg"
    (( rc == 0 )) || return 1
    _greynoise_quota_inc
    [[ -n "$resp" ]] || return 1

    local cls riot name ttl="${INTEL_CACHE_TTL}"
    cls="$(printf '%s' "$resp"  | jq -r '.classification // empty' 2>/dev/null)"
    riot="$(printf '%s' "$resp" | jq -r '.riot // false'          2>/dev/null)"
    name="$(printf '%s' "$resp" | jq -r '.name // empty'          2>/dev/null)"

    if [[ "$riot" == "true" ]]; then
        printf '0\t%s\triot:%s\tsuppress\n' "$ttl" "${name:-riot}"; return 0
    fi
    case "$cls" in
        malicious) printf '100\t%s\tmalicious:%s\t\n' "$ttl" "${name:-gn}"; return 0 ;;
        benign)    printf '0\t%s\tbenign:%s\t\n'      "$ttl" "${name:-gn}"; return 0 ;;
        *)         return 1 ;;
    esac
}
