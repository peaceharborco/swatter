#!/usr/bin/env bash
# lib/providers/swarm.sh — fleet feed as an intel provider.
#
# refresh: GET /feed (bare) -> feeds/swarm.txt via swatter_cidr_list_ok with
# TWO frozen consume obligations (hub plan Global Constraints):
#   1. a VALID EMPTY 200 means "no active offenders" -> CLEAR swarm.txt + meta
#      (must NOT go through swatter_cidr_list_ok, whose n>0 would reject it);
#      keep-last-good applies ONLY to non-200/transport failures.
#   2. corroborated-block needs host_count -> the ?format=json sidecar
#      (feeds/swarm.meta.json). Fresh-or-absent invariant: a FAILED sidecar
#      fetch DELETES prior meta so corroboration never acts on stale counts.
# lookup: provider_swarm "$ip" (Task 4) — score scaled by host_count.

provider_swarm_refresh() {
    _swarm_enabled || return 0
    local out="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "swarm refresh needs curl"; return 1; }
    local cfg hdrs code
    cfg="$(_swarm_curl_cfg_token "${SWARM_READ_TOKEN_FILE}")" || return 1
    hdrs="$(mktemp "${TMPDIR:-/tmp}/swatter-swarmhdr.XXXXXX")" || { rm -f "$cfg"; return 1; }
    code="$(curl --max-time 30 -sS -K "$cfg" -D "$hdrs" -o "${out}.raw" -w '%{http_code}' \
                 "${SWARM_HUB_URL%/}/feed" 2>/dev/null)"
    local crc=$?
    rm -f "$cfg"
    if (( crc != 0 )) || [[ "$code" != "200" ]]; then
        rm -f "${out}.raw" "$hdrs"
        log_warn "swarm feed fetch failed (http ${code:-none} rc=${crc}) — keeping last-good"
        return 1
    fi
    grep -qi '^x-swarm-truncated: *true' "$hdrs" \
        && log_warn "swarm feed TRUNCATED at the hub row cap — high addresses may be missing every cycle"
    rm -f "$hdrs"

    # Frozen obligation 1: valid empty 200 = "no active offenders" -> CLEAR.
    if ! grep -q '[^[:space:]]' "${out}.raw" 2>/dev/null; then
        : > "$out"; rm -f "$meta"   # fresh-or-absent: meta removed, not stubbed
        rm -f "${out}.raw"
        log_info "swarm feed empty (no active offenders) — cleared"
        return 0
    fi

    if tr -d '\r' < "${out}.raw" > "${out}.tmp" && swatter_cidr_list_ok < "${out}.tmp"; then
        mv "${out}.tmp" "$out"; rm -f "${out}.raw"
        log_info "swarm feed refreshed ($(grep -c . "$out" 2>/dev/null | tr -d ' ') entries)"
    else
        rm -f "${out}.raw" "${out}.tmp"
        log_warn "swarm feed INVALID (poisoned/garbled body) — keeping last-good"
        return 1
    fi

    # JSON sidecar for host_count. Fresh-or-absent: any sidecar failure removes
    # prior meta so corroboration/scaling never runs on stale counts. The bare
    # feed already installed, so refresh still returns 0 (boost unaffected).
    if [[ "${SWATTER_HAVE_JQ}" -eq 1 ]]; then
        cfg="$(_swarm_curl_cfg_token "${SWARM_READ_TOKEN_FILE}")" || { rm -f "$meta"; return 0; }
        code="$(curl --max-time 30 -sS -K "$cfg" -o "${meta}.raw" -w '%{http_code}' \
                     "${SWARM_HUB_URL%/}/feed?format=json" 2>/dev/null)"
        local mcrc=$?
        rm -f "$cfg"
        if (( mcrc == 0 )) && [[ "$code" == "200" ]] && jq -e 'type=="array"' "${meta}.raw" >/dev/null 2>&1; then
            mv "${meta}.raw" "$meta"
        else
            rm -f "${meta}.raw" "$meta"
            log_warn "swarm meta (json feed) fetch failed — host_count unavailable (stale meta removed)"
            [[ "${SWARM_ACTION:-boost}" == "corroborated-block" ]] \
                && log_warn "swarm: corroborated-block REQUIRES the json feed — sweep will be skipped"
        fi
    elif [[ "${SWARM_ACTION:-boost}" == "corroborated-block" ]]; then
        log_warn "swarm: corroborated-block requires jq for the json feed — install jq or use SWARM_ACTION=boost"
    fi
    return 0
}

# Per-IP lookup against the local swarm feed. Free (no network): exact-IP line
# match, then CIDR containment via the allowlist matcher. Score scales with the
# fleet's corroboration: base SWARM_BASE_SCORE at host_count=1, +15 per extra
# distinct host, capped 100 (folds through the standard W_REPUTATION path —
# swarm is a NORMAL intel provider, not a new fold weight; spec §8).
# NOTE (locked decision): an IP contained in a corroborated CIDR row scores at
# the conservative BASE — meta host_count is keyed by the CIDR string. The
# corroborated-block sweep is unaffected (it iterates meta rows directly).
provider_swarm() {
    local ip="$1" feed="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    _swarm_enabled || return 1
    [[ -s "$feed" ]] || return 1

    # Staleness (spec §4.3): older than SWARM_MAX_AGE_DAYS => signal ABSENT
    # (+ one warn per process, not per IP).
    local age
    age=$(( $(swatter_now) - $(stat_mtime "$feed" || echo 0) ))
    if (( age > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )); then
        if [[ -z "${_SWARM_STALE_WARNED:-}" ]]; then
            log_warn "swarm feed stale (>${SWARM_MAX_AGE_DAYS}d old) — swarm signal ignored (run: swatter refresh-feeds)"
            _SWARM_STALE_WARNED=1
        fi
        return 1
    fi

    # Fleet canary: a fleet-allow IP is never swarm-boosted (spec §4.5).
    [[ -s "${SWARM_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${SWARM_ALLOW_FILE}" && return 1

    local hit=0
    awk -v ip="$ip" '$1==ip{f=1; exit} END{exit !f}' "$feed" && hit=1
    if (( ! hit )) && declare -F _ip_in_cidr_file >/dev/null; then
        _ip_in_cidr_file "$ip" "$feed" && hit=1
    fi
    (( hit )) || return 1

    local hc=1
    if [[ "${SWATTER_HAVE_JQ}" -eq 1 && -s "$meta" ]]; then
        hc="$(jq -r --arg ip "$ip" '[.[] | select(.ip==$ip)][0].host_count // 1' "$meta" 2>/dev/null)"
        [[ "$hc" =~ ^[0-9]+$ ]] || hc=1
    fi
    local score=$(( ${SWARM_BASE_SCORE:-70} + 15 * (hc - 1) ))
    (( score > 100 )) && score=100
    printf '%s\t%s\thosts=%s\n' "$score" "${INTEL_CACHE_TTL}" "$hc"
}
