#!/usr/bin/env bash
# lib/score.sh — the scan orchestrator.
#
# Pipeline: ingest -> score.awk -> (per IP past WATCH) intel -> reputation-fold
# -> classify -> decide action -> block on the right plane -> record + audit.
#
# The weighted behavioral score comes from score.awk (W_REPUTATION excluded
# there). Here we add reputation as a post-hoc fold so threat-intel availability
# changes the score without re-running awk, and so a missing lookup never blocks.

# Run score.awk over parsed TSV on stdin -> "ip\tscore\treqs\tevidence_json".
_swatter_run_scorer() {
    gawk -v NOW="$(swatter_now)" -v WINDOW="${WINDOW_SECONDS}" -v MIN_REQS="${MIN_REQS}" \
         -v RATE_SAT="${RATE_SAT}" -v SCORE_WATCH="${SCORE_WATCH}" \
         -v W_RATE="${W_RATE}" -v W_ERR_RATIO="${W_ERR_RATIO}" -v W_ERR_BURST="${W_ERR_BURST}" \
         -v W_FANOUT="${W_FANOUT}" -v W_BADPATH="${W_BADPATH}" -v W_UA="${W_UA}" \
         -v W_POST_FLOOD="${W_POST_FLOOD}" -v W_NOVHOST="${W_NOVHOST}" \
         -v BADPATHS="${BADPATHS_CONF}" \
         -v HONEYPOTS="${HONEYPOT_PATHS_FILE:-}" \
         -f "${SWATTER_LIB_DIR}/score.awk"
}

# Fold a reputation score (0-100) into a behavioral score using W_REPUTATION,
# re-normalizing as a weighted average of (behavioral, reputation).
_swatter_fold_reputation() {
    local behav="$1" rep="$2"
    awk -v b="$behav" -v r="$rep" -v wb="100" -v wr="${W_REPUTATION}" '
        BEGIN {
            # Behavioral score already represents the sum of its own weights
            # normalized to 0-100, so treat it as weight 100 against W_REPUTATION.
            s = (b*wb + r*wr) / (wb + wr)
            # Reputation corroboration can only raise a borderline score, never
            # lower a strong behavioral one.
            if (s < b) s = b
            printf "%d", int(s + 0.5)
        }'
}

# Pick TTL from the ladder by how many temp blocks this IP already has.
_swatter_pick_ttl() {
    local prior="$1"; local -a ladder
    read -r -a ladder <<<"${TTL_LADDER}"
    local idx="$prior"
    (( idx >= ${#ladder[@]} )) && idx=$(( ${#ladder[@]} - 1 ))
    printf '%s' "${ladder[$idx]}"
}

# Append one structured decision line to decisions.jsonl.
_swatter_audit() {
    # $1 ip $2 score $3 action $4 channel $5 ttl $6 reason $7 evidence_json $8 reputation
    local f="${LOG_DIR}/decisions.jsonl" now; now="$(swatter_now)"
    printf '{"ts":%s,"iso":"%s","ip":"%s","score":%s,"action":"%s","channel":"%s","ttl":%s,"reason":"%s","reputation":%s,"mode":"%s","evidence":%s}\n' \
        "$now" "$(ts)" "$1" "$2" "$3" "$4" "${5:-0}" "${6//\"/\'}" "${8:-0}" "${SWATTER_MODE}" "$7" \
        >> "$f" 2>/dev/null || true
}

# Execute a decided block on the right plane. Reads/updates the run-scoped
# globals _SW_TOTAL_BLOCKS / SWATTER_RUN_ACTED. Echoes nothing; audits + records.
#   _swatter_execute_block <ip> <action> <ttl> <folded> <reason> <ev> <rep> <novhost> <top_vhost> <healthy>
_swatter_execute_block() {
    local ip="$1" action="$2" ttl="$3" folded="$4" reason="$5" ev="$6" rep="$7" novhost="$8" top_vhost="$9" healthy="${10}"
    # never-block, LAST, right before acting.
    local nb
    if nb="$(swatter_is_never_block "$ip")"; then
        log_info "exempt ${ip} (${nb}) score=${folded}"
        _swatter_audit "$ip" "$folded" "exempt" "none" 0 "exempt:${nb}" "$ev" "$rep"; return 1
    fi
    if (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )); then
        log_warn "circuit_breaker: MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN} reached; ${ip} skipped"
        SWATTER_RUN_BREAKER=1
        _swatter_audit "$ip" "$folded" "skipped-cap" "none" 0 "circuit_breaker" "$ev" "$rep"; return 1
    fi
    local plane; plane="$(swatter_classify "$ip" "$novhost")"
    local channel="none" did=0
    if [[ "$plane" == "DIRECT" ]]; then
        channel="${DIRECT_BACKEND:-csf}"
        if (( ! healthy )); then
            log_warn "fail-closed: not ${channel}-denying ${ip} (allowlist unhealthy)"
            _swatter_audit "$ip" "$folded" "skipped-failclosed" "$channel" "$ttl" "$reason" "$ev" "$rep"; return 1
        fi
        if [[ "$action" == "perm" ]]; then swatter_block_direct_perm "$ip" "$reason" && did=1
        else swatter_block_direct_temp "$ip" "$ttl" "$reason" && did=1; fi
    else
        channel="cloudflare"
        if ! swatter_cf_manages_plane; then
            _swatter_audit "$ip" "$folded" "skipped-cf-plane" "$channel" 0 "${reason} cf_mode=${CF_MODE}" "$ev" "$rep"; return 1
        fi
        [[ "$action" == "perm" ]] && ttl="$(_swatter_pick_ttl 99)"
        swatter_cf_block "$ip" "$ttl" "$reason" "$top_vhost" && did=1
    fi
    if (( did )); then
        _SW_TOTAL_BLOCKS=$(( _SW_TOTAL_BLOCKS + 1 )); SWATTER_RUN_ACTED=$(( SWATTER_RUN_ACTED + 1 ))
        swatter_store_sighting_clear "$ip"
        swatter_store_record "$ip" "$action" "$channel" "$ttl" "$folded" "$reason" \
            "$([[ "${SWATTER_MODE}" == "enforce" ]] && echo 0 || echo 1)"
        swatter_abuseipdb_report "$ip" "$ev" "$reason"
        _swatter_audit "$ip" "$folded" "$action" "$channel" "$ttl" "$reason" "$ev" "$rep"
    else
        # The backend block call returned non-zero (CF API timeout/5xx, unresolved
        # zone, missing token, CSF failure). Record the TRUTH — a failed attempt,
        # not the intended action — so the decision log and digest never count a
        # block that never reached the firewall, and so offenders.perm stays 0 and
        # the next run legitimately retries instead of a phantom perm being logged
        # every cycle. "failed" is distinct from the deliberate skipped-* family
        # (skipped = policy choice; failed = backend error) and, counted by exact
        # action match in report.sh, drops out of the block tallies cleanly.
        log_warn "block ${ip} (${action}/${channel}) failed; recording 'failed' not '${action}'"
        _swatter_audit "$ip" "$folded" "failed" "$channel" "$ttl" "block_failed action=${action} ${reason}" "$ev" "$rep"
    fi
    return 0
}

# Main scan.
swatter_scan() {
    # Fail closed only when a Cloudflare plane exists but its range list is
    # untrustworthy (can't tell a CF edge from a direct socket). On a box that
    # isn't behind Cloudflare there is nothing to misroute, so CSF denies run
    # normally even with no range list — see swatter_failclosed_active.
    local healthy=1
    swatter_failclosed_active && healthy=0
    if (( ! healthy )) && [[ "${SWATTER_MODE}" == "enforce" ]]; then
        log_warn "allowlist unhealthy -> CSF denies disabled this run (fail closed)"
        swatter_notify "swatter fail-closed on $(hostname -s 2>/dev/null)" \
            "CSF/direct denies disabled — Cloudflare range list stale/missing. Run: swatter refresh-feeds." "fail_closed"
    fi

    swatter_build_direct_set
    swatter_cf_sweep_expired

    local parsed scored
    parsed="$(mktemp "${TMPDIR:-/tmp}/swatter-parsed.XXXXXX")"
    scored="$(mktemp "${TMPDIR:-/tmp}/swatter-scored.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -f '$parsed' '$scored'" RETURN

    swatter_ingest > "$parsed"
    _swatter_run_scorer < "$parsed" | sort -t$'\t' -k2,2nr > "$scored"

    local ip score reqs ev novhost rep replabel suppress folded
    _SW_TOTAL_BLOCKS=0; SWATTER_RUN_WATCHED=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
    while IFS=$'\t' read -r ip score reqs ev; do
        [[ -n "$ip" ]] || continue
        SWATTER_RUN_WATCHED=$(( SWATTER_RUN_WATCHED + 1 ))

        novhost="$(printf '%s' "$ev" | sed -n 's/.*"novhost":\([0-9]*\).*/\1/p')"
        [[ "$novhost" =~ ^[0-9]+$ ]] || novhost=0
        local top_vhost; top_vhost="$(printf '%s' "$ev" | sed -n 's/.*"top_vhost":"\([^"]*\)".*/\1/p')"
        local is_honeypot=0
        printf '%s' "$ev" | grep -q '"honeypot":1' && is_honeypot=1

        # Reputation enrichment (now 3-field: score, label, suppress).
        rep=0; replabel=""; suppress=0
        if swatter_intel_available; then
            local ir; ir="$(swatter_intel_score "$ip")"
            rep="$(printf '%s' "$ir" | cut -f1)"; replabel="$(printf '%s' "$ir" | cut -f2)"
            suppress="$(printf '%s' "$ir" | cut -f3)"
            [[ "$rep" =~ ^[0-9]+$ ]] || rep=0; [[ "$suppress" =~ ^[01]$ ]] || suppress=0
        fi

        folded="$score"
        if [[ "$suppress" != "1" ]] && (( rep > 0 )); then
            folded="$(_swatter_fold_reputation "$score" "$rep")"
        fi

        # ASN conditional boost (only when not suppressed and behavior is attack-shaped).
        local asn_label=""
        if [[ "$suppress" != "1" && "${ASN_SIGNAL_ENABLE:-false}" == "true" ]] \
           && _swatter_asn_attack_shaped "$ev"; then
            if asn_label="$(swatter_asn_is_hosting "$ip")"; then
                folded=$(( folded + ${W_ASN:-12} )); (( folded > 100 )) && folded=100
            else asn_label=""; fi
        fi

        local reason="score=${folded}"
        [[ -n "$replabel" ]] && reason="${reason} intel=${replabel}(${rep})"
        [[ -n "$asn_label" ]] && reason="${reason} asn=${asn_label}+${W_ASN:-12}"

        # Suppression is total — exempt everywhere — UNLESS a honeypot hit and
        # HONEYPOT_OVERRIDES_SUPPRESS=true together override it (operator opt-in;
        # default false keeps a known-good RIOT range safe even on a trap hit).
        if [[ "$suppress" == "1" ]] \
           && ! { (( is_honeypot )) && [[ "${HONEYPOT_OVERRIDES_SUPPRESS:-false}" == "true" ]]; }; then
            log_info "exempt ${ip} (intel:${replabel}) score=${folded}"
            _swatter_audit "$ip" "$folded" "exempt" "none" 0 "intel:${replabel}" "$ev" "$rep"
            continue
        fi

        # Honeypot -> instant perm (skip the ladder).
        if (( is_honeypot )); then
            if swatter_store_is_perm "$ip"; then
                _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"; continue
            fi
            _swatter_execute_block "$ip" "perm" 0 "$folded" "honeypot ${reason}" "$ev" "$rep" "$novhost" "$top_vhost" "$healthy"
            continue
        fi

        if (( folded >= SCORE_TEMP )); then
            if swatter_store_is_perm "$ip"; then
                log_debug "${ip} already perm-blocked; skipping"
                _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"; continue
            fi
            local prior; prior="$(swatter_store_recent_temp_count "$ip")"
            [[ "$prior" =~ ^[0-9]+$ ]] || prior=0
            local action ttl=0
            if (( prior + 1 >= REPEAT_N )); then action="perm"
            else
                action="temp"; ttl="$(_swatter_pick_ttl "$prior")"
                if printf '%s' "$ev" | grep -q '"badpath_cat":"CRITICAL"'; then
                    (( ttl < CRITICAL_TTL_FLOOR )) && ttl="${CRITICAL_TTL_FLOOR}"
                fi
            fi
            _swatter_execute_block "$ip" "$action" "$ttl" "$folded" "$reason" "$ev" "$rep" "$novhost" "$top_vhost" "$healthy"
        else
            # WATCH band: low-and-slow accrual + escalation.
            _swatter_audit "$ip" "$folded" "watch" "none" 0 "$reason" "$ev" "$rep"
            if [[ "${PERSIST_ENABLE:-true}" == "true" && "${STORE}" == "sqlite" ]]; then
                swatter_store_sighting_add "$ip" "$folded" "${PERSIST_BUCKET_SECONDS:-3600}"
                local nb; nb="$(swatter_store_sighting_buckets "$ip" "${PERSIST_WINDOW_DAYS:-3}")"
                if [[ "$nb" =~ ^[0-9]+$ ]] && (( nb >= ${PERSIST_N:-6} )); then
                    _swatter_execute_block "$ip" "temp" "$(_swatter_pick_ttl 0)" "$folded" \
                        "low_and_slow_persist buckets=${nb} ${reason}" "$ev" "$rep" "$novhost" "$top_vhost" "$healthy"
                fi
            fi
        fi
    done < "$scored"

    [[ "${PERSIST_ENABLE:-true}" == "true" ]] && swatter_store_sighting_sweep "${PERSIST_WINDOW_DAYS:-3}"

    log_info "scan complete: ${SWATTER_RUN_WATCHED} over-watch, ${SWATTER_RUN_ACTED} acted (mode=${SWATTER_MODE}, cap=${MAX_BLOCKS_PER_RUN})"
    swatter_metrics_write

    if (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )); then
        swatter_notify "swatter circuit breaker tripped on $(hostname -s 2>/dev/null)" \
            "Reached MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN}. Review ${LOG_DIR}/decisions.jsonl." "circuit_breaker"
    fi
}
