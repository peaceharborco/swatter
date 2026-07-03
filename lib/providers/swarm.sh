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
        : > "$out"; printf '[]' > "$meta"
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
        rm -f "$cfg"
        if [[ "$code" == "200" ]] && jq -e 'type=="array"' "${meta}.raw" >/dev/null 2>&1; then
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

