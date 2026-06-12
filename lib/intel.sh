#!/usr/bin/env bash
# lib/intel.sh — pluggable threat-intel reputation, cached and quota-limited.
#
# Each provider is a function provider_<name> "$ip" that prints
#   score_0_100 \t ttl_seconds \t label
# on success (exit 0) or exits non-zero for "no data". intel.sh dispatches the
# configured INTEL_PROVIDERS in order, caches results under
# $STATE_DIR/intel/<provider>/<ip>, and returns the MAX malicious score seen.
#
# Hard rules:
#   - Only ever called for IPs already past WATCH (don't spend quota on benign).
#   - Never blocks because a lookup failed; absence of data == score 0.
#   - List feeds (ipsum, spamhaus) are refreshed by `swatter refresh-feeds`, not
#     per IP, so they cost nothing at scan time.

# shellcheck source=providers/ipsum.sh
# (providers are sourced lazily in swatter_intel_init)

swatter_intel_init() {
    local p
    for p in ${INTEL_PROVIDERS}; do
        local f="${SWATTER_LIB_DIR}/providers/${p}.sh"
        if [[ -f "$f" ]]; then
            # shellcheck disable=SC1090
            source "$f"
        else
            log_warn "intel provider not found: ${p} (${f})"
        fi
    done
    SWATTER_INTEL_QUOTA_USED=0
}

# Has intel at all? (used to decide whether to fold W_REPUTATION into the score)
swatter_intel_available() {
    [[ -n "${INTEL_PROVIDERS// }" ]]
}

_intel_cache_get() {
    # $1=provider $2=ip ; echoes "score\tlabel" if fresh, else nothing
    local prov="$1" ip="$2"
    local f="${STATE_DIR}/intel/${prov}/${ip}"
    [[ -f "$f" ]] || return 1
    local now mtime age
    now="$(swatter_now)"; mtime="$(stat_mtime "$f" 2>/dev/null || echo 0)"
    age=$(( now - mtime ))
    (( age < INTEL_CACHE_TTL )) || return 1
    cat "$f" 2>/dev/null
}

_intel_cache_put() {
    local prov="$1" ip="$2" score="$3" label="$4"
    local d="${STATE_DIR}/intel/${prov}"
    mkdir -p "$d" 2>/dev/null || return 0
    printf '%s\t%s\n' "$score" "$label" > "${d}/${ip}" 2>/dev/null || true
}

# swatter_intel_score <ip> : echoes "score\tlabel" (max across providers).
# score 0 means no malicious signal (or no data).
swatter_intel_score() {
    local ip="$1" best=0 bestlabel="" prov out cached score ttl label
    for prov in ${INTEL_PROVIDERS}; do
        # Cache first.
        if cached="$(_intel_cache_get "$prov" "$ip")"; then
            score="${cached%%$'\t'*}"; label="${cached#*$'\t'}"
        else
            # Provider function present?
            if ! declare -F "provider_${prov}" >/dev/null; then continue; fi
            if out="$(provider_"${prov}" "$ip" 2>/dev/null)"; then
                score="$(printf '%s' "$out" | cut -f1)"
                ttl="$(printf '%s' "$out" | cut -f2)"
                label="$(printf '%s' "$out" | cut -f3)"
                [[ "$score" =~ ^[0-9]+$ ]] || score=0
                _intel_cache_put "$prov" "$ip" "$score" "$label"
            else
                score=0; label=""
                _intel_cache_put "$prov" "$ip" 0 "nodata"
            fi
        fi
        if (( score > best )); then best="$score"; bestlabel="${prov}:${label}"; fi
    done
    printf '%s\t%s\n' "$best" "$bestlabel"
}
