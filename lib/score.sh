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
    # A failed append must be LOUD (never abort the block path, but never
    # vanish either): blocks landing on the firewall with no decision record
    # silently break caps, repeat-escalation, and every /server-logs count.
    printf '{"ts":%s,"iso":"%s","ip":"%s","score":%s,"action":"%s","channel":"%s","ttl":%s,"reason":"%s","reputation":%s,"mode":"%s","evidence":%s}\n' \
        "$now" "$(ts)" "$1" "$2" "$3" "$4" "${5:-0}" "${6//\"/\'}" "${8:-0}" "${SWATTER_MODE}" "$7" \
        >> "$f" 2>/dev/null || log_error "audit write FAILED (${f}): decision '${3}' for ${1} NOT recorded"
}

# Execute a decided block on the right plane. Reads/updates the run-scoped
# globals _SW_TOTAL_BLOCKS / SWATTER_RUN_ACTED. Echoes nothing; audits + records.
#   _swatter_execute_block <ip> <action> <ttl> <folded> <reason> <ev> <rep> <novhost> <top_vhost> <healthy>
_swatter_execute_block() {
    local ip="$1" action="$2" ttl="$3" folded="$4" reason="$5" ev="$6" rep="$7" novhost="$8" top_vhost="$9" healthy="${10}"
    SWATTER_LAST_BACKEND_ERR=""   # per-IP: a backend failure below sets it; no cross-IP bleed
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
    # Backend return-code protocol — defined once in lib/common.sh (SWATTER_RC_*),
    # consumed here: 0 => did=1 (real action); RC_CAP => skipped-cap;
    # RC_CONFIG => skipped-config; RC_NOVHOST => skipped-novhost; other => failed.
    local channel="none" did=0 rc=0
    if [[ "$plane" == "DIRECT" ]]; then
        channel="${DIRECT_BACKEND:-csf}"
        if (( ! healthy )); then
            log_warn "fail-closed: not ${channel}-denying ${ip} (allowlist unhealthy)"
            _swatter_audit "$ip" "$folded" "skipped-failclosed" "$channel" "$ttl" "$reason" "$ev" "$rep"; return 1
        fi
        if [[ "$action" == "perm" ]]; then swatter_block_direct_perm "$ip" "$reason"; rc=$?
        else swatter_block_direct_temp "$ip" "$ttl" "$reason"; rc=$?; fi
    else
        channel="cloudflare"
        if ! swatter_cf_manages_plane; then
            _swatter_audit "$ip" "$folded" "skipped-cf-plane" "$channel" 0 "${reason} cf_mode=${CF_MODE}" "$ev" "$rep"; return 1
        fi
        [[ "$action" == "perm" ]] && ttl="$(_swatter_pick_ttl 99)"
        swatter_cf_block "$ip" "$ttl" "$reason" "$top_vhost"; rc=$?
    fi
    (( rc == 0 )) && did=1
    if (( did )); then
        _SW_TOTAL_BLOCKS=$(( _SW_TOTAL_BLOCKS + 1 )); SWATTER_RUN_ACTED=$(( SWATTER_RUN_ACTED + 1 ))
        swatter_store_sighting_clear "$ip"
        swatter_store_record "$ip" "$action" "$channel" "$ttl" "$folded" "$reason" \
            "$([[ "${SWATTER_MODE}" == "enforce" ]] && echo 0 || echo 1)"
        swatter_abuseipdb_report "$ip" "$ev" "$reason"
        _swatter_audit "$ip" "$folded" "$action" "$channel" "$ttl" "$reason" "$ev" "$rep"
    elif (( rc == SWATTER_RC_CAP )); then
        # Backend hit its per-run deny cap (a deliberate throttle) — not a failure.
        # Mirror the MAX_BLOCKS_PER_RUN skipped-cap above so a high-volume incident
        # doesn't read as a wave of firewall failures.
        _swatter_audit "$ip" "$folded" "skipped-cap" "$channel" 0 "backend_cap action=${action} ${reason}" "$ev" "$rep"
    elif (( rc == SWATTER_RC_CONFIG )); then
        # Deterministic config gap the offender can't satisfy by retrying (vhost not
        # in CF_DOMAINS_MAP / no token). A config skip, not a backend error — keep
        # it out of "failed" so a misconfig doesn't masquerade as a transient API
        # failure on every */5 run forever.
        _swatter_audit "$ip" "$folded" "skipped-config" "$channel" 0 "precondition action=${action} ${reason}" "$ev" "$rep"
    elif (( rc == SWATTER_RC_NOVHOST )); then
        # No nameable target vhost in this scan's evidence (raw-IP / no-Host hits).
        # Data-dependent, not a config error — the same IP may present a vhost next
        # window — so it gets its own label rather than the permanent skipped-config.
        _swatter_audit "$ip" "$folded" "skipped-novhost" "$channel" 0 "no_target_vhost action=${action} ${reason}" "$ev" "$rep"
    else
        # Genuine backend error (CF API timeout/5xx or unresolved zone, csf/ipset
        # command failure, missing tooling). Record the TRUTH — not a phantom
        # success — so the decision log/digest never count a block that never
        # reached the firewall, and offenders.perm stays 0 so the next run
        # legitimately retries instead of a phantom perm looping every cycle.
        # "failed" is exact-matched out of the block tallies in report.sh.
        # Thread the captured backend error (CF API summary) into the record as a
        # structured evidence.backend_err so a future /server-logs read shows the
        # cause inline instead of dead-ending. Bounded + no secret (see _cf_err_summary).
        local ev_failed="$ev" fail_reason="block_failed action=${action} ${reason}"
        if [[ -n "${SWATTER_LAST_BACKEND_ERR:-}" ]]; then
            if [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
                ev_failed="$(printf '%s' "$ev" | jq -c --arg e "${SWATTER_LAST_BACKEND_ERR}" '. + {backend_err:$e}' 2>/dev/null || printf '%s' "$ev")"
            else
                # No jq: the record is written via printf, so keep diagnosability by
                # threading the cause into the reason string instead of the evidence.
                fail_reason="${fail_reason} backend_err=${SWATTER_LAST_BACKEND_ERR}"
            fi
        fi
        log_warn "block ${ip} (${action}/${channel}) failed (rc=${rc})${SWATTER_LAST_BACKEND_ERR:+: ${SWATTER_LAST_BACKEND_ERR}}; recording 'failed' not '${action}'"
        _swatter_audit "$ip" "$folded" "failed" "$channel" "$ttl" "$fail_reason" "$ev_failed" "$rep"
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
