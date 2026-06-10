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

# Main scan.
swatter_scan() {
    local healthy=1
    swatter_allowlist_healthy || healthy=0
    if (( ! healthy )) && [[ "${SWATTER_MODE}" == "enforce" ]]; then
        log_warn "allowlist unhealthy -> CSF denies disabled this run (fail closed)"
    fi

    swatter_build_direct_set
    swatter_cf_sweep_expired

    local intel_on=0
    swatter_intel_available && intel_on=1

    local total_blocks=0 watched=0 acted=0
    local parsed scored
    parsed="$(mktemp "${TMPDIR:-/tmp}/swatter-parsed.XXXXXX")"
    scored="$(mktemp "${TMPDIR:-/tmp}/swatter-scored.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -f '$parsed' '$scored'" RETURN

    swatter_ingest > "$parsed"
    _swatter_run_scorer < "$parsed" | sort -t$'\t' -k2,2nr > "$scored"

    local ip score reqs ev novhost rep replabel folded
    while IFS=$'\t' read -r ip score reqs ev; do
        [[ -n "$ip" ]] || continue
        watched=$(( watched + 1 ))

        # novhost subscore drives the direct/CF classifier.
        novhost="$(printf '%s' "$ev" | sed -n 's/.*"novhost":\([0-9]*\).*/\1/p')"
        [[ "$novhost" =~ ^[0-9]+$ ]] || novhost=0

        # Reputation enrichment only for IPs past WATCH (we are already there).
        rep=0; replabel=""
        if (( intel_on )); then
            local ir; ir="$(swatter_intel_score "$ip")"
            rep="$(printf '%s' "$ir" | cut -f1)"; replabel="$(printf '%s' "$ir" | cut -f2)"
            [[ "$rep" =~ ^[0-9]+$ ]] || rep=0
        fi

        folded="$score"
        if (( intel_on && rep > 0 )); then
            folded="$(_swatter_fold_reputation "$score" "$rep")"
        fi

        # Decide action from the folded score.
        local action="watch" channel="none" ttl=0 reason
        reason="score=${folded}"
        [[ -n "$replabel" ]] && reason="${reason} intel=${replabel}(${rep})"

        if (( folded >= SCORE_TEMP )); then
            # Already permanently blocked? skip.
            if swatter_store_is_perm "$ip"; then
                log_debug "${ip} already perm-blocked; skipping"
                _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"
                continue
            fi
            # Never-block check, LAST, right before acting.
            local nb
            if nb="$(swatter_is_never_block "$ip")"; then
                log_info "exempt ${ip} (${nb}) score=${folded}"
                _swatter_audit "$ip" "$folded" "exempt" "none" 0 "exempt:${nb}" "$ev" "$rep"
                continue
            fi
            # Circuit breaker.
            if (( total_blocks >= MAX_BLOCKS_PER_RUN )); then
                log_warn "circuit_breaker: MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN} reached; ${ip} (score ${folded}) skipped"
                _swatter_audit "$ip" "$folded" "skipped-cap" "none" 0 "circuit_breaker" "$ev" "$rep"
                continue
            fi

            # Classify plane.
            local plane; plane="$(swatter_classify "$ip" "$novhost")"

            # Repeat-offender escalation.
            local prior; prior="$(swatter_store_recent_temp_count "$ip")"
            [[ "$prior" =~ ^[0-9]+$ ]] || prior=0

            if (( prior + 1 >= REPEAT_N )); then
                action="perm"
            else
                action="temp"
                ttl="$(_swatter_pick_ttl "$prior")"
                # CRITICAL bad-path gets a TTL floor.
                if printf '%s' "$ev" | grep -q '"badpath_cat":"CRITICAL"'; then
                    (( ttl < CRITICAL_TTL_FLOOR )) && ttl="${CRITICAL_TTL_FLOOR}"
                fi
            fi

            # Route to the plane. DIRECT -> CSF (gated by allowlist health).
            local did=0
            if [[ "$plane" == "DIRECT" ]]; then
                channel="csf"
                if (( ! healthy )); then
                    log_warn "fail-closed: not CSF-denying ${ip} (allowlist unhealthy)"
                    _swatter_audit "$ip" "$folded" "skipped-failclosed" "csf" "$ttl" "$reason" "$ev" "$rep"
                    continue
                fi
                if [[ "$action" == "perm" ]]; then swatter_csf_perm "$ip" "$reason" && did=1
                else swatter_csf_temp "$ip" "$ttl" "$reason" && did=1; fi
            else
                channel="cloudflare"
                # Cloudflare plane has no "permanent" vs temp distinction here; a
                # perm decision just uses the longest TTL.
                [[ "$action" == "perm" ]] && ttl="$(_swatter_pick_ttl 99)"
                swatter_cf_block "$ip" "$ttl" "$reason" && did=1
            fi

            if (( did )); then
                total_blocks=$(( total_blocks + 1 )); acted=$(( acted + 1 ))
                swatter_store_record "$ip" "$action" "$channel" "$ttl" "$folded" "$reason" \
                    "$([[ "${SWATTER_MODE}" == "enforce" ]] && echo 0 || echo 1)"
            fi
            _swatter_audit "$ip" "$folded" "$action" "$channel" "$ttl" "$reason" "$ev" "$rep"
        else
            # WATCH band: log to the decision trail, count toward history, no action.
            _swatter_audit "$ip" "$folded" "watch" "none" 0 "$reason" "$ev" "$rep"
        fi
    done < "$scored"

    log_info "scan complete: ${watched} over-watch, ${acted} acted (mode=${SWATTER_MODE}, cap=${MAX_BLOCKS_PER_RUN})"

    # Circuit-breaker notification.
    if (( total_blocks >= MAX_BLOCKS_PER_RUN )) && [[ -n "${NOTIFY_EMAIL}" ]]; then
        swatter_notify "swatter circuit breaker tripped on $(hostname -s 2>/dev/null)" \
            "Reached MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN}. Review ${LOG_DIR}/decisions.jsonl." || true
    fi
}

# Minimal mail hook (best-effort; uses local mail if present).
swatter_notify() {
    local subj="$1" body="$2"
    [[ -n "${NOTIFY_EMAIL}" ]] || return 0
    if have mail; then printf '%s\n' "$body" | mail -s "$subj" "${NOTIFY_EMAIL}" 2>/dev/null || true; fi
}
