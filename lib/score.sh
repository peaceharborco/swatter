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
    # An empty ladder would index ladder[-1] on a nonexistent array; fall back to a
    # sane 1h temp block rather than emit an empty TTL into the backend.
    (( ${#ladder[@]} == 0 )) && { printf '%s' 3600; return 0; }
    local idx="$prior"
    (( idx >= ${#ladder[@]} )) && idx=$(( ${#ladder[@]} - 1 ))
    printf '%s' "${ladder[$idx]}"
}

# Append one structured decision line to decisions.jsonl.
_swatter_audit() {
    # $1 ip $2 score $3 action $4 channel $5 ttl $6 reason $7 evidence_json $8 reputation
    local f="${LOG_DIR}/decisions.jsonl" now; now="$(swatter_now)"
    # reason is the only free-text field here and can carry intel-derived text.
    # Neutralize the three chars that break a hand-built JSON line: backslash
    # (the escaper below doesn't handle it), double-quote (closes the string),
    # and any control char incl. newline (splits the JSONL record that report.sh
    # / `why` parse with jq). Intel labels are already cleaned upstream; this is
    # the record-layer backstop so no future reason source can corrupt the log.
    local reason="${6//\\/\\\\}"; reason="${reason//\"/\'}"; reason="${reason//[[:cntrl:]]/ }"
    # The ip field is charset-safe from the scorer today, but sanitize it here too
    # (same backslash/quote/cntrl neutralization) so the record layer is
    # self-protecting for any future caller that reaches _swatter_audit directly.
    local aip="${1//\\/\\\\}"; aip="${aip//\"/\'}"; aip="${aip//[[:cntrl:]]/}"
    # score/ttl/reputation are interpolated raw (unquoted) into the JSON. A caller
    # passing an empty or non-numeric value would produce "score":, — corrupt JSONL
    # that breaks jq in report.sh/`why`. Default every numeric field to 0 unless it
    # is a plain integer.
    local ascore="$2"; [[ "$ascore" =~ ^-?[0-9]+$ ]] || ascore=0
    local attl="${5:-0}"; [[ "$attl" =~ ^-?[0-9]+$ ]] || attl=0
    local arep="${8:-0}"; [[ "$arep" =~ ^-?[0-9]+$ ]] || arep=0
    # A failed append must be LOUD (never abort the block path, but never
    # vanish either): blocks landing on the firewall with no decision record
    # silently break caps, repeat-escalation, and every /server-logs count.
    printf '{"ts":%s,"iso":"%s","ip":"%s","score":%s,"action":"%s","channel":"%s","ttl":%s,"reason":"%s","reputation":%s,"mode":"%s","evidence":%s}\n' \
        "$now" "$(ts)" "$aip" "$ascore" "$3" "$4" "$attl" "$reason" "$arep" "${SWATTER_MODE}" "$7" \
        >> "$f" 2>/dev/null || log_error "audit write FAILED (${f}): decision '${3}' for ${1} NOT recorded"
}

# Merge one integer field into a scorer-built evidence JSON blob.
#
# Safety contract — this runs on the SUCCESS path, where a bad return is worse
# than on the failure path _swatter_apply_plane's backend_err merge models:
# _swatter_audit interpolates evidence RAW into hand-built JSONL, and the house
# convention is `set -uo pipefail` WITHOUT -e, so a failure here does not abort
# the run — it would emit `"evidence":` with no value, corrupting the record and
# breaking jq in report.sh / `swatter why`. Therefore: never echo empty, never
# die, and return the ORIGINAL evidence on any failure.
#   _swatter_ev_stamp <ev_json> <key> <int_value>  -> echoes JSON
_swatter_ev_stamp() {
    local ev="${1:-}" key="${2:-}" val="${3:-}"
    # Empty evidence would make `printf '' | jq` fail and the fallback echo
    # nothing; normalize to an empty object so the record stays well-formed.
    [[ -n "$ev" ]] || ev='{}'
    # Guard the value BEFORE --argjson: a non-integer would make jq fail (or, for
    # a bare word, parse as something unintended).
    [[ "$val" =~ ^[0-9]+$ ]] || { printf '%s' "$ev"; return 0; }
    [[ -n "$key" ]] || { printf '%s' "$ev"; return 0; }
    [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]] || { printf '%s' "$ev"; return 0; }
    # --argjson (not --arg) so the field lands as a JSON number. The fallback is
    # INSIDE the substitution so any jq failure still yields the original.
    printf '%s' "$ev" | jq -c --arg k "$key" --argjson n "$val" '. + {($k): $n}' 2>/dev/null \
        || printf '%s' "$ev"
}

# Apply a decided block on an EXPLICIT plane. Runs all the shared gates (valid/
# safe target, never_block, MAX_BLOCKS_PER_RUN breaker), the DIRECT vs VIA_CF
# backend call, and the shared success/skip/fail audit tail. Every block path
# (normal, and — later — upgrade/dual-plane/swarm) funnels through here so the
# gates and counters are enforced in exactly one place.
#   _swatter_apply_plane <ip> <plane:DIRECT|VIA_CF> <action> <ttl> <reason>
#                        <top_vhost> <healthy> <folded> <ev> <rep> [audit_action]
# Reads/updates the run-scoped globals _SW_TOTAL_BLOCKS / SWATTER_RUN_ACTED.
# Echoes nothing; audits + records. audit_action (optional) overrides the action
# label shown in the success audit (default = action) so an upgrade can surface
# as 'plane-upgrade' while still recording action=perm/temp.

# Alert key for the perm-rate tripwire, bucketed by SEVERITY BAND.
#
# _notify_ratelimited marks its key before channels send and suppresses for
# ALERT_REPEAT_TTL (6h by default), and the marker is written even when every
# channel fails. A STATIC key would therefore fire once and then stay silent
# through exactly the multi-hour burst this exists to catch.
#
# The first fix for that keyed on the HOUR, which removed the ceiling entirely:
# every hour minted a new key, and because the day arm reads a TRAILING 24h
# count, once it crosses it stays crossed — so one incident re-alerted every
# hour for a full day. Two alerts can even land five minutes apart when a run
# straddles an hour boundary (observed on cds1 2026-08-15: 10:55 and 11:00).
#
# Keying on how many full thresholds' worth have accrued keeps both properties:
# a steady incident is ONE alert (then governed by ALERT_REPEAT_TTL), while one
# that is genuinely worsening re-alerts the moment it crosses the next band.
# Loud on escalation, quiet on repetition.
#
# This function is PURE — it computes the band for a pair of counts and nothing
# else. The band that actually keys the alert is the incident HIGH-WATER (see
# _swatter_perm_rate_hw_key), because a raw current band re-alerts on the way
# DOWN: a trailing-24h count decaying 140 -> 100 moves d2 -> d1, a new key, and
# _notify_ratelimited cannot tell that apart from a new incident. Paging on
# recovery is the same defect as the hour bucket wearing a different hat.
#   _swatter_perm_rate_key <run_perms> <day_perms>
_swatter_perm_rate_key() {
    local run="${1:-0}" day="${2:-0}" rt="${PERM_RATE_ALERT_PER_RUN:-5}" dt="${PERM_RATE_ALERT_PER_DAY:-15}" v
    # Bash re-resolves a non-numeric string in an arithmetic context as a
    # variable name and aborts the run under `set -u` (CLAUDE.md, "Config
    # knobs"). An unreadable severity gets its OWN key so it still alerts,
    # rather than colliding with a band that may already be suppressed.
    for v in "$run" "$day" "$rt" "$dt"; do
        [[ "$v" =~ ^[0-9]+$ ]] || { printf 'perm_rate.unreadable'; return 0; }
    done
    (( rt > 0 )) || rt=1   # a 0 threshold would divide by zero
    (( dt > 0 )) || dt=1
    printf 'perm_rate.r%s.d%s' "$(( run / rt ))" "$(( day / dt ))"
}

# Where the open incident's high-water band lives. Cleared when the tripwire
# stops firing, so the NEXT wave alerts from a clean slate instead of being
# suppressed by a band some earlier incident already reached.
#
# Concurrency is handled for us: cmd_scan takes swatter_acquire_lock before
# swatter_scan, so two */5 runs cannot interleave a read-modify-write here.
# Prints nothing if STATE_DIR is empty/unset — callers treat that as "no
# high-water available" rather than building a path at the filesystem root.
_swatter_perm_rate_hw_file() {
    [[ -n "${STATE_DIR:-}" ]] || return 1
    printf '%s/perm_rate.band' "${STATE_DIR}"
}

# The alert key: the high-water band of the OPEN incident, ratcheted up only.
# Reads the current band from _swatter_perm_rate_key, raises the stored
# high-water if this is worse, and keys on the result — so worsening mints a new
# key and alerts, while steady OR IMPROVING reuses the key and stays quiet.
#   _swatter_perm_rate_hw_key <run_perms> <day_perms>
_swatter_perm_rate_hw_key() {
    local cur f hw_r=0 hw_d=0 cr=0 cd=0
    cur="$(_swatter_perm_rate_key "$1" "$2")"
    # An unreadable severity has no band to ratchet — key it as-is.
    [[ "$cur" == perm_rate.r*.d* ]] || { printf '%s' "$cur"; return 0; }
    cr="${cur#perm_rate.r}"; cr="${cr%%.d*}"
    cd="${cur##*.d}"
    # No usable state dir -> no ratchet; fall back to the pure band rather than
    # failing the scan. Losing the ratchet costs a duplicate alert, not silence.
    f="$(_swatter_perm_rate_hw_file)" || { printf '%s' "$cur"; return 0; }
    # -f, not -r: a directory at that path would make `read` hang or error.
    #
    # A high-water older than ALERT_REPEAT_TTL is STALE and ignored. Without
    # this the file is a one-way ratchet with exactly one clear path (the
    # not-tripped branch below), so a clear that never lands — read-only fs,
    # bad perms, a copied state dir — wedges the band high FOREVER and every
    # later wave at or below that band is suppressed. Expiring it makes the
    # wedge self-heal instead of silently disarming the alarm.
    if [[ -f "$f" && -r "$f" ]]; then
        local _age _mt
        _mt="$(stat_mtime "$f" 2>/dev/null || echo 0)"
        _age=$(( $(swatter_now) - ${_mt:-0} ))
        if (( _age < ${ALERT_REPEAT_TTL:-21600} )); then
            read -r hw_r hw_d _ < "$f" 2>/dev/null || true
        fi
    fi
    # Clamp before any arithmetic: `^[0-9]+$` admits a 21-digit number, and
    # `(( cr > hw_r ))` on that prints "value too great for base" and writes the
    # garbage straight back. Bands are small by construction.
    [[ "$hw_r" =~ ^[0-9]{1,6}$ ]] || hw_r=0
    [[ "$hw_d" =~ ^[0-9]{1,6}$ ]] || hw_d=0
    [[ "$cr"   =~ ^[0-9]{1,6}$ ]] || cr=0
    [[ "$cd"   =~ ^[0-9]{1,6}$ ]] || cd=0
    (( cr > hw_r )) && hw_r="$cr"
    (( cd > hw_d )) && hw_d="$cd"
    # Braces, not `printf ... 2>/dev/null`: a failed REDIRECTION is reported by
    # the shell before printf ever runs, so its own stderr redirect cannot catch
    # it and the noise would land in the cron log every 5 minutes.
    { printf '%s %s\n' "$hw_r" "$hw_d" > "$f"; } 2>/dev/null || true
    printf 'perm_rate.r%s.d%s' "$hw_r" "$hw_d"
}

_swatter_apply_plane() {
    local ip="$1" plane="$2" action="$3" ttl="$4" reason="$5" top_vhost="$6" healthy="$7" \
          folded="$8" ev="$9" rep="${10}" audit_action="${11:-$3}"
    SWATTER_LAST_BACKEND_ERR=""   # per-IP: a backend failure below sets it; no cross-IP bleed
    # Strict validity + safe-target gate, FIRST. score.awk's charset pre-filter
    # admits tokens like 999.999.999.999 or '::::' (harmless bytes, but not
    # addresses), and a /0 / unspecified address is valid-but-catastrophic — none
    # may reach csf/ipset/the CF API as a block target. Audit the skip (parity
    # with the never-block exempt path) so it is visible to `why`/report.
    if ! swatter_is_valid_ip_or_cidr "$ip" || _swatter_is_unsafe_block_target "$ip"; then
        log_warn "refusing to act on invalid/unsafe ip token '${ip}'"
        _swatter_audit "$ip" "$folded" "skipped-invalid" "none" 0 "invalid_or_unsafe_ip ${reason}" "$ev" "$rep"
        return 1
    fi
    # never-block, LAST, right before acting.
    local nb
    if nb="$(swatter_is_never_block "$ip")"; then
        log_info "exempt ${ip} (${nb}) score=${folded}"
        _swatter_audit "$ip" "$folded" "exempt" "none" 0 "exempt:${nb}" "$ev" "$rep"; return 1
    fi
    # Shared consumer-VPN egress: cap at a ladder-max temp, never a perm.
    # The offense is real, but the identifier is shared by many unrelated
    # people, so a PERMANENT ban is collateral against all of them — and a
    # published one recommends that every other host do the same.
    #
    # audit_action MUST move with action. It is bound once at entry (:128) and
    # is what the success audit writes (:212) — and the nightly digest counts
    # perms from the AUDIT log, not the ledger (lib/report.sh). Downgrading
    # only `action` would report a permanent ban that was never placed.
    # A secondary leg's own label (dual-plane / plane-upgrade) is preserved.
    local shared_egress=""
    if [[ "$action" == "perm" && "${SHARED_EGRESS_ENABLE:-true}" == "true" ]]; then
        # A missing lib/asn.sh must not resolve to the same outcome as a
        # genuine non-match: both leave `shared_egress` empty and let the
        # perm proceed, but a silent skip here is indistinguishable from "not
        # shared egress" in exactly the dangerous direction (an uncapped perm,
        # unlogged, uncounted). Production always sources asn.sh before
        # score.sh (bin/swatter's module loop), so this only fires for a
        # future entry point that forgets it — but it must be loud when it
        # does. Still fails open: the perm proceeds either way.
        if ! declare -F swatter_is_shared_egress >/dev/null; then
            log_warn "shared-egress cap unavailable: lib/asn.sh not loaded (swatter_is_shared_egress undefined); ${ip} perm proceeding uncapped"
        elif shared_egress="$(swatter_is_shared_egress "$ip")"; then
            action="temp"
            [[ "$audit_action" == "perm" ]] && audit_action="temp"
            ttl="$(_swatter_pick_ttl 99)"   # ladder max; :168's CF rewrite is skipped now
            reason="${reason} shared-egress=${shared_egress} perm-capped"
            ev="$(_swatter_ev_stamp "$ev" shared_egress 1)"   # integer only — a label here no-ops
            SWATTER_RUN_SHARED_CAPS=$(( ${SWATTER_RUN_SHARED_CAPS:-0} + 1 ))
            log_warn "shared-egress cap: ${ip} (${shared_egress}) perm -> temp ttl=${ttl}"
        fi
    fi
    # No else branch is needed: swatter_is_shared_egress echoes nothing when it
    # returns 1, and a short-circuit on the outer `action`/enable test never
    # reaches either inner branch at all — `shared_egress` is "" in every
    # non-match case. It stays in scope for the AbuseIPDB guard below.
    if (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )); then
        log_warn "circuit_breaker: MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN} reached; ${ip} skipped"
        SWATTER_RUN_BREAKER=1
        _swatter_audit "$ip" "$folded" "skipped-cap" "none" 0 "circuit_breaker" "$ev" "$rep"; return 1
    fi
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
        # Ladder perms only, enforce-mode only: a dual-plane / plane-upgrade
        # second leg carries a distinct audit_action and would otherwise
        # double-count one IP, and report mode's backend calls short-circuit to
        # a dry-run "success" (rc=0) that places no real ban — see
        # block_csf.sh/block_cf.sh's `[[ "${SWATTER_MODE}" != "enforce" ]]`
        # dry-run branches. Neither may drive a tripwire meant to fire only on
        # bans actually placed.
        [[ "$action" == "perm" && "$audit_action" == "$action" && "${SWATTER_MODE}" == "enforce" ]] \
            && SWATTER_RUN_PERMS=$(( ${SWATTER_RUN_PERMS:-0} + 1 ))
        swatter_store_sighting_clear "$ip"
        swatter_store_record "$ip" "$action" "$channel" "$ttl" "$folded" "$reason" \
            "$([[ "${SWATTER_MODE}" == "enforce" ]] && echo 0 || echo 1)"
        # Per-plane ledger — written ONLY on an enforced block (never dry-run/report),
        # mirroring swatter_store_record's dry_run==0 path. sqlite-only; flatfile no-op.
        # The Cloudflare plane has NO true perm: a CF 'perm' is a TTL-emulated rule
        # (ttl was rewritten to the ladder max above) that swatter_cf_sweep_expired
        # removes at expiry. It is recorded as an EXPIRING perm (kind='perm' with
        # that real expiry — see swatter_store_plane_set): is_perm_on holds while
        # the edge rule is live, so perm_gate noops instead of re-applying a
        # "plane-upgrade" every scan (which burned MAX_BLOCKS_PER_RUN), and lapses
        # at expiry so a returning offender is legitimately re-blocked after the
        # sweep. The DIRECT plane's perm passes ttl=0 -> a genuine never-expiring perm.
        [[ "${SWATTER_MODE}" == "enforce" ]] && swatter_store_plane_set "$ip" "$channel" "$action" "$ttl"
        # The block landed — cancel any durable retry queued for this plane by an
        # earlier failed attempt (no-op if none). Keyed on the routing plane
        # (DIRECT|VIA_CF), the same key swatter_store_pending_set stored.
        [[ "${SWATTER_MODE}" == "enforce" ]] && swatter_store_pending_clear "$ip" "$plane"
        # Report to AbuseIPDB once per IP: only the primary block (audit_action ==
        # action). An upgrade / dual-plane second leg carries a distinct
        # audit_action, so it records + blocks but does not re-report the same IP.
        # Conservative default (ABUSEIPDB_REPORT_MIN_ACTION=perm): report only
        # high-confidence PERM blocks (repeat offender / hard intel), not first-seen
        # temps — a scoring false-positive or a swarm-corroborated temp is outbound
        # reputational harm to a third party. Set to 'temp' to report both.
        # `shared_egress` is checked FIRST and explicitly: the protection must
        # not rest on the perm/temp distinction. With
        # ABUSEIPDB_REPORT_MIN_ACTION=temp the clauses below are both true for a
        # capped IP, which would report the very address the cap exists to keep
        # off a public blocklist.
        if [[ -z "$shared_egress" ]] \
           && [[ "$audit_action" == "$action" ]] \
           && { [[ "${ABUSEIPDB_REPORT_MIN_ACTION:-perm}" == "temp" ]] || [[ "$action" == "perm" ]]; }; then
            swatter_abuseipdb_report "$ip" "$ev" "$reason"
        fi
        _swatter_audit "$ip" "$folded" "$audit_action" "$channel" "$ttl" "$reason" "$ev" "$rep"
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
        # A now-deterministic config gap (unmapped vhost / no token) can never be
        # satisfied by retrying — drop any intent an earlier transient failure queued.
        [[ "${SWATTER_MODE}" == "enforce" ]] && swatter_store_pending_clear "$ip" "$plane"
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
        # Durably queue the INTENT so this block is retried on a later scan even if
        # the offender never reappears in the ingest window. Without this, a
        # transient CF/csf backend error permanently drops the block for a
        # single-burst offender (ingest is cursor-based — see swatter_store_pending_set).
        # Enforce-only: report/dry-run never reaches this branch (the backend
        # short-circuits to success), and a preview must not seed a real retry.
        # Store the original evidence + audit_action so the drain replays the block
        # faithfully (counts + reports like a primary; stays silent for a secondary
        # leg). $ev (not $ev_failed) — the offense evidence, not the failure note.
        [[ "${SWATTER_MODE}" == "enforce" ]] \
            && swatter_store_pending_set "$ip" "$plane" "$action" "$ttl" "$reason" "$top_vhost" "$folded" "$rep" "$ev" "$audit_action"
    fi
    return 0
}

# Execute a decided block on the right plane. Classifies the IP once, then
# delegates to _swatter_apply_plane, which runs all the gates + backend calls.
# Reads/updates the run-scoped globals _SW_TOTAL_BLOCKS / SWATTER_RUN_ACTED.
#   _swatter_execute_block <ip> <action> <ttl> <folded> <reason> <ev> <rep> <novhost> <top_vhost> <healthy>
_swatter_execute_block() {
    local ip="$1" action="$2" ttl="$3" folded="$4" reason="$5" ev="$6" rep="$7" novhost="$8" top_vhost="$9" healthy="${10}"
    local plane; plane="$(swatter_classify "$ip" "$novhost")"
    _swatter_apply_plane "$ip" "$plane" "$action" "$ttl" "$reason" "$top_vhost" "$healthy" "$folded" "$ev" "$rep"
}

# Plane-aware replacement for the old global "already perm -> noop" short-circuit.
# Given the plane the current evidence points to (want_ch = its firewall channel):
#   * already perm on THAT plane  -> audit noop-perm, return 0 (caller continues)
#   * perm on some OTHER plane     -> UPGRADE: add a perm block on this plane too
#                                     (audits plane-upgrade), return 0
#   * not perm on any plane        -> return 1 (caller runs the normal block path)
# Keyed on the PER-PLANE ledger (plane_blocks), never on global offenders.perm,
# so a phantom dry-run perm / legacy import can't drive a noop→upgrade loop. A
# live TEMP is deliberately NOT a noop (is_perm_on is perm-only), so the temp->
# perm escalation ladder still runs. For a hard-intel IP already perm on the
# evidence plane, a missing OTHER plane is healed here (retries a dual-plane leg
# that failed earlier under fail-closed / cap).
#   _swatter_perm_gate <ip> <plane> <want_ch> <folded> <reason> <ev> <rep> <top_vhost> <healthy>
_swatter_perm_gate() {
    local ip="$1" plane="$2" want_ch="$3" folded="$4" reason="$5" ev="$6" rep="$7" top_vhost="$8" healthy="$9"
    # Flatfile store OR report mode: no trustworthy per-plane ledger (plane_set is
    # sqlite + enforce only). Preserve the original global-perm noop so a preview
    # or flatfile run never loops on phantom upgrades.
    if [[ "${STORE:-sqlite}" != "sqlite" || "${SWATTER_MODE}" != "enforce" ]]; then
        swatter_store_is_perm "$ip" || return 1
        _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"; return 0
    fi

    local other other_ch hard=0
    if [[ "$plane" == "DIRECT" ]]; then other="VIA_CF"; other_ch="cloudflare"
    else other="DIRECT"; other_ch="${DIRECT_BACKEND:-csf}"; fi
    [[ "${DUAL_PLANE_HARD_INTEL:-true}" == "true" && "$rep" =~ ^[0-9]+$ ]] \
        && (( rep >= ${INTEL_HARDBLOCK_MIN:-100} )) && hard=1

    if swatter_store_is_perm_on "$ip" "$want_ch"; then
        # Already perm on the evidence plane. For hard-intel, ensure the OTHER
        # plane is covered too — heals a dual-plane leg that failed earlier.
        if (( hard )) && ! swatter_store_is_perm_on "$ip" "$other_ch"; then
            _swatter_apply_plane "$ip" "$other" "perm" 0 "dual-plane ${reason}" \
                "$top_vhost" "$healthy" "$folded" "$ev" "$rep" "dual-plane"
        else
            _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"
        fi
        return 0
    fi

    if swatter_store_is_perm_on "$ip" "$other_ch"; then
        # Perm on the other plane, evidence now points here -> upgrade onto this
        # plane. Both planes are then covered, so no separate dual-plane needed.
        _swatter_apply_plane "$ip" "$plane" "perm" 0 "plane-upgrade ${reason}" \
            "$top_vhost" "$healthy" "$folded" "$ev" "$rep" "plane-upgrade"
        return 0
    fi

    # offenders.perm alone is not evidence. Before 15aad86 a DRY-RUN perm set
    # that flag exactly as it inflated temp_count, and the rollup is never
    # recomputed — so on any host that ran report mode before enforce (cds1 did)
    # a report-mode ghost would be permanently banned on sight here, skipping
    # the ladder, the CRITICAL-single bar, and recidivism accounting entirely.
    # Require an enforced perm in the ledger, the same rollup-AND-ledger idiom
    # swatter_store_perm_ips_since already uses. A legitimate import-bans entry
    # still backfills, because it writes a real enforced action row.
    if swatter_store_is_perm "$ip" && swatter_store_has_enforced_perm "$ip"; then
        # offenders.perm=1 but NO plane_blocks row on either plane — a legacy
        # import (bin/swatter import-bans) or a perm predating this feature.
        # Backfill: perm on the evidence plane now, plus the other plane for
        # hard-intel, restoring per-plane coverage.
        _swatter_apply_plane "$ip" "$plane" "perm" 0 "plane-upgrade ${reason}" \
            "$top_vhost" "$healthy" "$folded" "$ev" "$rep" "plane-upgrade"
        (( hard )) && _swatter_maybe_dual_plane "$ip" "$plane" "perm" "$folded" "$reason" "$ev" "$rep" "$top_vhost" "$healthy"
        return 0
    fi

    return 1   # not perm on any plane -> caller runs the temp/perm ladder
}

# After a fresh PERM on $plane, a hard-intel IP (reputation >= INTEL_HARDBLOCK_MIN
# — Spamhaus DROP / AbuseIPDB 100, never a real visitor) also gets the OTHER plane
# so direct-to-origin ports are covered too. Fired regardless of whether the
# primary leg succeeded: if the primary was DIRECT and fail-closed (stale CF
# ranges), this still places the CF block — degrading to CF-only rather than
# neither plane. never_block + the fail-closed gate inside _swatter_apply_plane
# still ensure a CF edge range can never be CSF-denied.
#   _swatter_maybe_dual_plane <ip> <plane> <action> <folded> <reason> <ev> <rep> <top_vhost> <healthy>
_swatter_maybe_dual_plane() {
    local ip="$1" plane="$2" action="$3" folded="$4" reason="$5" ev="$6" rep="$7" top_vhost="$8" healthy="$9"
    [[ "${DUAL_PLANE_HARD_INTEL:-true}" == "true" ]] || return 0
    [[ "$action" == "perm" ]] || return 0
    [[ "$rep" =~ ^[0-9]+$ ]] && (( rep >= ${INTEL_HARDBLOCK_MIN:-100} )) || return 0
    local other; other=$([[ "$plane" == "DIRECT" ]] && echo "VIA_CF" || echo "DIRECT")
    _swatter_apply_plane "$ip" "$other" "perm" 0 "dual-plane ${reason}" \
        "$top_vhost" "$healthy" "$folded" "$ev" "$rep" "dual-plane"
}

# Re-drive durably-queued failed blocks (see swatter_store_pending_set). Runs
# every scan, off the stored queue rather than fresh log evidence, so a block that
# hit a transient backend error is retried even after the offender's traffic has
# aged out of the ingest cursor. Bounded so an intent that can never be satisfied
# self-reaps: given up after PENDING_RETRY_MAX_ATTEMPTS re-attempts or
# PENDING_RETRY_MAX_AGE_HOURS, whichever comes first. sqlite+enforce only; a
# flatfile / report run has no queue and no-ops. Runs under the entrypoint flock
# (called from swatter_scan) so it shares the single-writer guarantee.
#   _swatter_retry_pending <healthy>
_swatter_retry_pending() {
    local healthy="$1"
    [[ "${STORE:-sqlite}" == "sqlite" && "${SWATTER_MODE}" == "enforce" ]] || return 0
    local rows; rows="$(swatter_store_pending_list)" || return 0
    [[ -n "$rows" ]] || return 0
    # swatter_store_pending_list runs in sqlite's `.mode ascii` (see
    # _sql_ascii) and terminates each ROW with char(30)/RS instead of a
    # newline. Convert back to newline so the existing line-oriented `while
    # read` loop below needs no other change; fields within a row split on
    # IFS=$'\037' (US) instead.
    rows="${rows//$'\036'/$'\n'}"
    local now; now="$(swatter_now)"
    local hours="${PENDING_RETRY_MAX_AGE_HOURS:-24}"; [[ "$hours" =~ ^[0-9]+$ ]] || hours=24
    local max_age=$(( hours * 3600 ))
    local max_att="${PENDING_RETRY_MAX_ATTEMPTS:-12}"; [[ "$max_att" =~ ^[0-9]+$ ]] || max_att=12
    # Cap re-attempts per scan so a large queue (mass outage recovery) can never
    # consume the whole MAX_BLOCKS_PER_RUN budget and starve THIS scan's fresh
    # offenders. Rows past the cap simply persist for the next scan (oldest first).
    local max_run="${PENDING_RETRY_MAX_PER_RUN:-10}"; [[ "$max_run" =~ ^[0-9]+$ ]] || max_run=10
    local drained=0
    local ip plane action ttl folded rep first_failed attempts audit_action reason top_vhost ev
    # Iterate a SNAPSHOT: re-attempts mutate pending_blocks (bump attempts / clear),
    # but the loop consumes the list captured above, so one drain touches each row once.
    # IFS=$'\037' (ASCII unit separator), matching swatter_store_pending_list's
    # delimiter — NOT a tab: bash's `read` treats tab as IFS-whitespace no
    # matter how IFS is set, so adjacent tabs (an empty field, e.g. a
    # DIRECT-plane row with no top_vhost) collapse and shift every later
    # column — including `ev`, which the disarm gate below depends on — left
    # by one. US is not in that whitespace class, so empty fields survive.
    while IFS=$'\037' read -r ip plane action ttl folded rep first_failed attempts audit_action reason top_vhost ev; do
        [[ -n "$ip" && -n "$plane" ]] || continue
        [[ "$first_failed" =~ ^[0-9]+$ ]] || first_failed="$now"
        [[ "$attempts"     =~ ^[0-9]+$ ]] || attempts=1
        [[ -n "$audit_action" ]] || audit_action="$action"
        [[ -n "$ev" ]] || ev='{}'
        # The firewall channel this plane maps to (plane_blocks is keyed on channel,
        # not the DIRECT|VIA_CF routing plane) — used for the coverage check and the
        # retry-exhausted audit's channel field.
        local want_ch; want_ch=$([[ "$plane" == "DIRECT" ]] && echo "${DIRECT_BACKEND:-csf}" || echo "cloudflare")
        # Give up on an intent that will never land (self-limits the queue).
        # Deliberately ahead of the disarm hold below: reaping is orthogonal to
        # the ladder switch and must keep running while disarmed too, or the
        # queue grows unbounded during a pause and dumps every stale row at
        # once (dropped, not applied) the instant the drain re-checks it after
        # re-arm.
        if (( attempts >= max_att )) || (( now - first_failed > max_age )); then
            log_warn "durable-retry: giving up on ${ip}/${plane} after ${attempts} attempt(s), $(( (now - first_failed) / 3600 ))h queued; dropping"
            _swatter_audit "$ip" "$folded" "retry-exhausted" "$want_ch" 0 "durable_retry_gaveup attempts=${attempts} ${reason}" '{"retry":1}' "$rep"
            swatter_store_pending_clear "$ip" "$plane"
            continue
        fi
        # Ladder disarmed: refuse to replay a queued PERMANENT ban we cannot
        # prove came from somewhere other than the ladder. The obvious filter —
        # "skip rows whose reason contains recidivism=" — is wrong: that stamp
        # is written only by this release, so every perm queued by the version
        # currently deployed lacks it and would sail straight through the very
        # gate meant to stop it. Allowlist the known non-ladder origin instead.
        # Match on the EVIDENCE marker, not free text in `reason`: INTEL_PROVIDERS
        # includes a provider literally named "projecthoneypot" (lib/common.sh),
        # so a plain ladder perm scored via that intel feed renders as
        # "intel=projecthoneypot:...(NN)" — a reason substring match on
        # "honeypot" would wrongly allow that through. `ev` carries a structured
        # "honeypot":1 flag set only for a genuine trap hit (line ~504), and it
        # is preserved verbatim on the queued row (see swatter_store_pending_set),
        # so it survives into the dual-plane leg of a real trap perm too.
        # The row is LEFT QUEUED and its attempt counter is NOT bumped: pausing
        # the ladder must not destroy intent for the life of the pause. But this
        # check runs AFTER the give-up block above, on purpose — a held row is
        # still subject to the normal age/attempt reap, so it does NOT survive
        # a disarm longer than PENDING_RETRY_MAX_AGE_HOURS (default 24h).
        # `swatter pending --drain-perms` clears them when the operator wants
        # an explicit abort rather than a pause.
        if [[ "$action" == "perm" && "${REPEAT_ENABLE}" != "true" && "$ev" != *'"honeypot":1'* ]]; then
            log_warn "ladder disarmed: holding queued perm for ${ip}/${plane} (clear with: swatter pending --drain-perms)"
            continue
        fi
        # Overridden since queueing (operator allow, or the token/IP went invalid):
        # cancel rather than re-block. _swatter_apply_plane re-checks these too, but
        # clearing here stops the row lingering until it ages out.
        if ! swatter_is_valid_ip_or_cidr "$ip" || _swatter_is_unsafe_block_target "$ip" \
           || swatter_is_never_block "$ip" >/dev/null 2>&1; then
            swatter_store_pending_clear "$ip" "$plane"; continue
        fi
        # Already covered on this plane by a later scan — but the coverage must MATCH
        # the intent: a live TEMP does NOT satisfy a queued PERM (the temp expires and
        # the perm escalation would be silently lost — the very bug this fixes). So a
        # perm intent clears only on a live perm; a temp intent clears on any live block.
        local covered=0
        if [[ "$action" == "perm" ]]; then
            swatter_store_is_perm_on "$ip" "$want_ch" && covered=1
        else
            swatter_store_active_on "$ip" "$want_ch" && covered=1
        fi
        if (( covered )); then
            swatter_store_pending_clear "$ip" "$plane"; continue
        fi
        # Leave cap headroom for fresh offenders: past the per-run retry cap, the row
        # persists (unattempted, attempts NOT bumped) for the next scan.
        (( drained >= max_run )) && continue
        drained=$(( drained + 1 ))
        # Re-attempt through the shared gated path, replaying the ORIGINAL evidence +
        # audit_action so a primary block counts + reports on success and a secondary
        # leg stays silent — exactly as the first attempt would have. retry:1 is merged
        # into the evidence for provenance. Success clears the row (did branch); another
        # failure re-enqueues with the pristine reason and bumps attempts.
        local rev="$ev"
        [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]] && rev="$(printf '%s' "$ev" | jq -c '. + {retry:1}' 2>/dev/null || printf '%s' "$ev")"
        _swatter_apply_plane "$ip" "$plane" "$action" "$ttl" "$reason" \
            "$top_vhost" "$healthy" "$folded" "$rev" "$rep" "$audit_action"
    done <<< "$rows"
}

# Escalation threshold for this IP. Normally REPEAT_N; raised when EVERY
# in-window temp was a single-request CRITICAL probe (see REPEAT_N_CRITICAL_SINGLE).
#   _swatter_recid_threshold <all_critical:0|1>
_swatter_recid_threshold() {
    if [[ "${1:-0}" == "1" ]]; then printf '%s' "${REPEAT_N_CRITICAL_SINGLE:-4}"
    else printf '%s' "${REPEAT_N}"; fi
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
    # SWATTER_DIRECT_SET is mktemp'd by swatter_build_direct_set above; clean it
    # here too so a */5 cron doesn't leak one /tmp file per scan.
    trap "rm -f '$parsed' '$scored' \"\${SWATTER_DIRECT_SET:-}\"" RETURN

    swatter_ingest > "$parsed"
    _swatter_run_scorer < "$parsed" | sort -t$'\t' -k2,2nr > "$scored"

    local ip score reqs ev novhost rep replabel suppress folded
    _SW_TOTAL_BLOCKS=0; SWATTER_RUN_WATCHED=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
    SWATTER_RUN_PERMS=0; SWATTER_RUN_SHARED_CAPS=0
    # Re-drive durably-queued failed blocks FIRST — before this scan's fresh
    # offenders — so a transient backend failure is retried even when the offender
    # never reappears in the log. Retries count against MAX_BLOCKS_PER_RUN (they go
    # through the same gated path), so this must run after the counter reset above.
    _swatter_retry_pending "$healthy"
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
        local drule; drule="$(printf '%s' "$ev" | sed -n 's/.*"decisive_rule":"\([^"]*\)".*/\1/p')"
        [[ -n "$drule" ]] && reason="${reason} rule=${drule}"

        # srcset_flood is WATCH-ONLY, and this is the line that MAKES it so.
        # score.awk caps it at SCORE_WATCH, but reputation and ASN fold in HERE,
        # afterwards -- so "cannot temp" was arithmetic coincidence at the shipped
        # defaults (50 + 14 + 12 = 76 would have crossed a SCORE_TEMP of 70 the
        # moment anyone raised SCORE_WATCH or W_ASN), not an enforced property.
        # The exempted class is residential by construction; it must never reach
        # the ladder, and therefore never an AbuseIPDB report.
        if [[ "$drule" == "srcset_flood" ]] && (( folded >= SCORE_TEMP )); then
            folded=$(( SCORE_TEMP - 1 ))
            reason="${reason} watch-only-capped"
        fi

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
            local hp_plane hp_want
            hp_plane="$(swatter_classify "$ip" "$novhost")"
            hp_want=$([[ "$hp_plane" == "DIRECT" ]] && echo "${DIRECT_BACKEND:-csf}" || echo "cloudflare")
            _swatter_perm_gate "$ip" "$hp_plane" "$hp_want" "$folded" "$reason" "$ev" "$rep" "$top_vhost" "$healthy" && continue
            _swatter_apply_plane "$ip" "$hp_plane" "perm" 0 "honeypot ${reason}" \
                "$top_vhost" "$healthy" "$folded" "$ev" "$rep"
            _swatter_maybe_dual_plane "$ip" "$hp_plane" "perm" "$folded" "honeypot ${reason}" "$ev" "$rep" "$top_vhost" "$healthy"
            continue
        fi

        if (( folded >= SCORE_TEMP )); then
            local plane want_ch
            plane="$(swatter_classify "$ip" "$novhost")"
            want_ch=$([[ "$plane" == "DIRECT" ]] && echo "${DIRECT_BACKEND:-csf}" || echo "cloudflare")
            # Plane-aware perm gate: noop only if already perm on the evidence's
            # plane; upgrade if perm elsewhere; else fall through to the ladder.
            _swatter_perm_gate "$ip" "$plane" "$want_ch" "$folded" "$reason" "$ev" "$rep" "$top_vhost" "$healthy" && continue
            local prior; prior="$(swatter_store_recent_temp_count "$ip")"
            [[ "$prior" =~ ^[0-9]+$ ]] || prior=0
            local allcrit thresh
            allcrit="$(swatter_store_temps_all_critical_single "$ip" "$(( $(swatter_now) - REPEAT_WINDOW_DAYS*86400 ))")"
            thresh="$(_swatter_recid_threshold "$allcrit")"
            local action ttl=0
            if [[ "${REPEAT_ENABLE}" == "true" ]] && (( prior + 1 >= thresh )); then
                action="perm"
                # Make the escalation self-explanatory: without this a ladder
                # perm's reason reads only `score=91 intel=...`, so neither the
                # digest nor `swatter why` can say WHY it went permanent.
                # decisive_rule is deliberately untouched — it is the behavioral
                # offense-type vocabulary the digest groups on (report.sh
                # _RPT_RULE_LABELS); recidivism is a different axis.
                reason="${reason} recidivism=$(( prior + 1 ))/${REPEAT_WINDOW_DAYS}d"
                (( allcrit )) && reason="${reason} crit-single"
                ev="$(_swatter_ev_stamp "$ev" recidivism "$(( prior + 1 ))")"
            else
                action="temp"; ttl="$(_swatter_pick_ttl "$prior")"
                if printf '%s' "$ev" | grep -q '"badpath_cat":"CRITICAL"'; then
                    (( ttl < CRITICAL_TTL_FLOOR )) && ttl="${CRITICAL_TTL_FLOOR}"
                fi
            fi
            _swatter_apply_plane "$ip" "$plane" "$action" "$ttl" "$reason" \
                "$top_vhost" "$healthy" "$folded" "$ev" "$rep"
            _swatter_maybe_dual_plane "$ip" "$plane" "$action" "$folded" "$reason" "$ev" "$rep" "$top_vhost" "$healthy"
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

    # shared-egress caps are reported at RUN level, not just per IP: a valid but
    # too-wide CIDR line (an exact /16 paste error is inside the width floor)
    # mass-caps perms, and per-IP warnings scattered through a busy log are
    # exactly what nobody reads. Suffixed only when non-zero so the line every
    # operator greps for keeps its shape on a normal run.
    log_info "scan complete: ${SWATTER_RUN_WATCHED} over-watch, ${SWATTER_RUN_ACTED} acted (mode=${SWATTER_MODE}, cap=${MAX_BLOCKS_PER_RUN})$( (( ${SWATTER_RUN_SHARED_CAPS:-0} > 0 )) && printf ', %s shared-egress perm-capped' "${SWATTER_RUN_SHARED_CAPS}" )"
    swatter_metrics_write

    if (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )); then
        swatter_notify "swatter circuit breaker tripped on $(hostname -s 2>/dev/null)" \
            "Reached MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN}. Review ${LOG_DIR}/decisions.jsonl." "circuit_breaker"
    fi

    # Perm-rate tripwire — same run that placed them, not the next digest.
    local _pday _pday_txt _unreadable=0
    _pday="$(swatter_store_perm_count_since $(( $(swatter_now) - 86400 )) )"
    # A ledger that could not be read is NOT a quiet day. Trip on it: the day arm
    # is the only thing watching a slow accumulation, and a lock timeout during a
    # live wave is exactly when it must not report absence.
    if [[ "$_pday" =~ ^[0-9]+$ ]]; then
        _pday_txt="$_pday"
    else
        _unreadable=1; _pday=0
        _pday_txt="UNREADABLE (the ledger exists but could not be read — treat this as an alarm, not a quiet day)"
    fi
    if (( _unreadable )) || (( SWATTER_RUN_PERMS >= PERM_RATE_ALERT_PER_RUN || _pday >= PERM_RATE_ALERT_PER_DAY )); then
        local _key
        if (( _unreadable )); then
            # Still ratchet the RUN arm. A flat "perm_rate.unreadable" is one
            # static key, so a live wave placing perms every scan would page
            # once and then be suppressed for ALERT_REPEAT_TTL — the day arm
            # being blind must not also disarm the arm that can still see.
            local _rk; _rk="$(_swatter_perm_rate_hw_key "${SWATTER_RUN_PERMS}" 0)"
            _key="perm_rate.unreadable.${_rk#perm_rate.}"
        else
            _key="$(_swatter_perm_rate_hw_key "${SWATTER_RUN_PERMS}" "${_pday}")"
        fi
        swatter_notify "swatter perm-rate tripwire on $(hostname -s 2>/dev/null)" \
            "Placed ${SWATTER_RUN_PERMS} permanent block(s) this run; ${_pday_txt} in the last 24h (thresholds ${PERM_RATE_ALERT_PER_RUN}/run, ${PERM_RATE_ALERT_PER_DAY}/day). Review: swatter escalate-preview; undo: swatter rollback-ladder --since <ts>." \
            "$_key"
    else
        # Nothing tripped: the incident (if there was one) is over. Drop the
        # high-water so the next wave is judged on its own merits.
        local _hwf
        if _hwf="$(_swatter_perm_rate_hw_file)" && [[ -e "$_hwf" ]]; then
            # A clear that silently fails leaves the band wedged high; the mtime
            # staleness check above bounds the damage, but say so either way.
            rm -f "$_hwf" 2>/dev/null || log_warn "perm-rate: could not clear high-water ${_hwf} (band may stay latched until it ages out)"
        fi
    fi
}
