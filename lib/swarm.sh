#!/usr/bin/env bash
# lib/swarm.sh — fleet reputation sharing, host side (subsystem 2 of 2).
#
# Publishes this box's CONFIRMED perm bans to the operator's self-hosted hub
# (POST /contribute) and consumes the merged fleet feed back as the intel
# provider `swarm` (lib/providers/swarm.sh). Opt-in corroborated-block sweeps
# route through _swatter_execute_block so every local gate still applies.
# All inert unless SWARM_ENABLE=true + SWARM_HUB_URL set (see spec §9).

_swarm_enabled() {
    [[ "${SWARM_ENABLE:-false}" == "true" && -n "${SWARM_HUB_URL:-}" ]]
}

# Opaque, stable, random per box — NOT hostname/IP (spec §6). Created 0600 on
# first use; only enrolled ids count toward hub corroboration.
swatter_swarm_host_id() {
    local f="${STATE_DIR}/swarm.host_id" id
    if [[ -s "$f" ]]; then printf '%s' "$(tr -d '[:space:]' < "$f")"; return 0; fi
    id="$(od -vAn -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    [[ "$id" =~ ^[0-9a-f]{32}$ ]] || { log_error "swarm: host_id generation failed"; return 1; }
    ( umask 0177; printf '%s' "$id" > "$f" ) || { log_error "swarm: cannot write ${f}"; return 1; }
    printf '%s' "$id"
}

# Bearer-token curl config from a 0400 token file (secret NEVER in argv —
# same rule every credentialed curl in this repo follows; curl_secrets_test).
# Caller MUST rm -f the printed path right after curl returns.
_swarm_curl_cfg_token() {
    local tf="$1" tok
    [[ -r "$tf" ]] || { log_warn "swarm: token file missing/unreadable: ${tf}"; return 1; }
    tok="$(tr -d '[:space:]' < "$tf")"
    [[ -n "$tok" ]] || { log_warn "swarm: token file empty: ${tf}"; return 1; }
    swatter_curl_cfg "header = \"Authorization: Bearer ${tok}\""
}

# Publish the delta of CONFIRMED perm bans (enforced, still banned) to the hub.
# Runs after a scan inside the scan lock; FAIL-SOFT: any failure warns, keeps
# the cursor, returns 1 — it must never abort or delay a scan (spec §4.1/§12).
# Frozen contract: POST /contribute {host_id, entries:[{ip}]} — category omitted
# in Phase 1 (taxonomy is spec open question §16; the field is contract-optional).
# Cursor discipline (Grok review): max_ts is computed ONLY over rows actually
# sent. Policy-filtered rows (never-block/canary/unsafe/invalid) never consume
# the cursor — they get re-read + re-filtered until a later publishable ban
# advances past them (cheap, and self-healing if the policy changes). A chunk
# failure mid-publish re-sends the whole delta next cycle; hub upserts are
# idempotent, so duplicates are harmless.
_SWARM_CHUNK=500   # hub MAX_ENTRIES defaults to 1000; stay comfortably under

swatter_swarm_publish() {
    _swarm_enabled || return 0
    [[ "${SWARM_PUBLISH:-true}" == "true" ]] || return 0
    # Mirror the AbuseIPDB reporter guard: never publish a ban we didn't make.
    [[ "${SWATTER_MODE:-report}" == "enforce" ]] || return 0
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0

    local cursor_file="${STATE_DIR}/swarm.publish.cursor" since=0
    [[ -s "$cursor_file" ]] && since="$(tr -d '[:space:]' < "$cursor_file")"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0

    # Delta + the four outbound gates (validate / unsafe / never-block / canary).
    # max_ts tracks SENT rows only (see header comment).
    local ip ts max_ts="$since" ips=()
    while IFS=$'\t' read -r ip ts; do
        [[ -n "$ip" ]] || continue
        swatter_is_valid_ip_or_cidr "$ip" || continue
        _swatter_is_unsafe_block_target "$ip" && continue
        swatter_is_never_block "$ip" >/dev/null && continue
        [[ -s "${SWARM_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${SWARM_ALLOW_FILE}" && continue
        ips+=("$ip")
        [[ "$ts" =~ ^[0-9]+$ ]] && (( ts > max_ts )) && max_ts="$ts"
    done < <(swatter_store_perm_ips_since "$since")
    (( ${#ips[@]} )) || return 0

    local host_id; host_id="$(swatter_swarm_host_id)" || return 1

    local i chunk payload cfg rtmp code
    for (( i = 0; i < ${#ips[@]}; i += _SWARM_CHUNK )); do
        chunk=("${ips[@]:i:_SWARM_CHUNK}")
        # Hand-built JSON is safe here: every ip passed the validator (charset
        # [0-9a-fA-F:./]) and host_id is our own 32-hex.
        payload="{\"host_id\":\"${host_id}\",\"entries\":["
        local first=1 e
        for e in "${chunk[@]}"; do
            (( first )) && first=0 || payload+=","
            payload+="{\"ip\":\"${e}\"}"
        done
        payload+="]}"

        cfg="$(_swarm_curl_cfg_token "${SWARM_WRITE_TOKEN_FILE}")" || return 1
        rtmp="$(mktemp "${TMPDIR:-/tmp}/swatter-swarmresp.XXXXXX")" || { rm -f "$cfg"; return 1; }
        printf 'header = "Content-Type: application/json"\n' >> "$cfg"
        code="$(printf '%s' "$payload" > "${rtmp}.req" && \
                curl --max-time 15 -sS -K "$cfg" -o "$rtmp" -w '%{http_code}' \
                     --data-binary "@${rtmp}.req" "${SWARM_HUB_URL%/}/contribute" 2>/dev/null)"
        local crc=$?
        rm -f "$cfg" "${rtmp}.req"
        if (( crc != 0 )) || [[ "$code" != "200" ]]; then
            rm -f "$rtmp"
            log_warn "swarm publish failed (http ${code:-none} rc=${crc}) — cursor kept, retry next scan"
            return 1
        fi
        if grep -q '"enrolled":false' "$rtmp" 2>/dev/null; then
            rm -f "$rtmp"
            log_warn "swarm publish REJECTED: this host_id is not enrolled — run: swatter swarm enroll (cursor kept)"
            return 1
        fi
        # Validator-drift visibility (review): the hub silently dropping entries
        # must not be silent HERE. Cursor still advances — hub validation is
        # deterministic, so retrying the same entries can never succeed.
        local nrej
        nrej="$(grep -o '"rejected":[0-9]*' "$rtmp" 2>/dev/null | cut -d: -f2)"
        [[ "$nrej" =~ ^[0-9]+$ ]] && (( nrej > 0 )) \
            && log_warn "swarm publish: hub rejected ${nrej} entr(ies) — bash/hub validator drift? (not retried)"
        rm -f "$rtmp"
    done

    printf '%s' "$max_ts" > "$cursor_file"
    log_info "swarm publish: ${#ips[@]} confirmed ban(s) contributed (cursor=${max_ts})"
}

# Opt-in proactive sweep (SWARM_ACTION=corroborated-block): temp-block feed IPs
# corroborated by >= SWARM_MIN_CORROBORATION distinct enrolled hosts. EVERY
# block routes through _swatter_execute_block — never a raw block path — so
# never-block/classify/unsafe/cap/fail-closed/audit ALL apply (spec §8).
# Requires the json sidecar (frozen obligation 2); jq-gated.
# Cadence (locked): re-issues temp for still-corroborated IPs each daily
# refresh — keep-alive while corroborated, natural decay when dropped from the
# feed (ladder TTL caps at 3d > daily cadence). Report mode dry-runs through
# the backends exactly like scan/import-bans (dry_run=1 records — a preview,
# and dry temps never escalate or publish).
swatter_swarm_sweep() {
    _swarm_enabled || return 0
    [[ "${SWARM_ACTION:-boost}" == "corroborated-block" ]] || return 0
    [[ "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_warn "swarm sweep: corroborated-block requires jq — skipped"; return 0; }
    local meta="${STATE_DIR}/feeds/swarm.meta.json"
    [[ -s "$meta" ]] || { log_info "swarm sweep: no corroboration data (empty feed or meta fetch failed)"; return 0; }

    # Same staleness policy as the provider (spec §4.3).
    local age
    age=$(( $(swatter_now) - $(stat_mtime "$meta" || echo 0) ))
    if (( age > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )); then
        log_warn "swarm sweep: meta stale (>${SWARM_MAX_AGE_DAYS}d) — skipped"
        return 0
    fi

    # Mirror swatter_scan's health gate + per-run breaker scope: the sweep gets
    # its own MAX_BLOCKS_PER_RUN budget via _SW_TOTAL_BLOCKS (score.sh:93-97).
    local healthy=1
    swatter_failclosed_active && healthy=0
    _SW_TOTAL_BLOCKS=0

    local ip hc n=0 score ttl prior
    while IFS=$'\t' read -r ip hc; do
        [[ -n "$ip" ]] || continue
        [[ "$hc" =~ ^[0-9]+$ ]] || continue
        swatter_is_valid_ip_or_cidr "$ip" || continue
        # Fleet canary consult (spec §4.5) — cheap pre-filter; never-block and
        # the rest are re-checked inside _swatter_execute_block.
        [[ -s "${SWARM_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${SWARM_ALLOW_FILE}" && continue
        swatter_store_is_perm "$ip" && continue
        score=$(( ${SWARM_BASE_SCORE:-70} + 15 * (hc - 1) )); (( score > 100 )) && score=100
        prior="$(swatter_store_recent_temp_count "$ip")"
        ttl="$(_swatter_pick_ttl "$prior")"
        # No local traffic => no top_vhost: CF-plane targets audit skipped-novhost;
        # the sweep protects the DIRECT plane (same posture as import-bans).
        # rep=$score: the swarm score IS this block's reputation input.
        _swatter_execute_block "$ip" temp "$ttl" "$score" \
            "swarm-corroborated hosts=${hc}" "{\"swarm\":true,\"hosts\":${hc}}" \
            "$score" 0 "" "$healthy" && n=$(( n + 1 ))
    done < <(jq -r --argjson n "${SWARM_MIN_CORROBORATION:-2}" \
                '.[] | select((.host_count // 0) >= $n) | [.ip, .host_count] | @tsv' "$meta" 2>/dev/null)
    (( n > 0 )) && log_info "swarm sweep: ${n} corroborated block(s) applied"
    return 0
}
cmd_swarm()             { log_error "swarm: not yet implemented"; return 2; }
