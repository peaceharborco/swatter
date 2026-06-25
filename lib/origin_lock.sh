#!/usr/bin/env bash
# lib/origin_lock.sh — inline L3 origin lock: restrict the web ports (80/443) to
# Cloudflare edges so direct-to-origin Cloudflare-bypass traffic is dropped at the
# kernel, the structural complement to the reactive classify.sh detection.
#
# One idempotent code path (`apply`) builds, in accept-first / drop-last order:
#   1. ACCEPT Cloudflare edges (ipset src match) -> web ports
#   2. (opt) ACCEPT /.well-known/ on :80 (HTTP domain-validation: ACME + cPanel DCV)
#   3. LOG (rate-limited) the remainder, prefix "ORIGIN-LOCK: "
#   4. (drop mode) DROP the remainder
#
# Execution context is explicit, never guessed: the csfpre drop-in calls
# `apply --hook=csf` (CSF already supplies lo/established/csf.allow accepts above
# csfpre, so we add ONLY cf/acme accept + LOG/DROP); plain `apply` (systemd/CLI,
# standalone) lays a safe preamble first (ACCEPT -i lo + ACCEPT allow/monitoring
# ranges, both -> web ports) — but NOT an established/related accept, which would
# both survive the lock for pre-existing non-CF flows and risk the conntrack-loose
# handshake leak. Returns on ephemeral ports never match the web-port DROP anyway.
#
# Fail-open spine: a missing/empty/under-min cloudflare.cidr installs NOTHING
# (an empty allowlist + DROP would firewall the whole internet). v6 is gated on
# ip6tables presence (warn-and-skip if absent, never fail). The ACME accept
# soft-fails with a warning if xt_string is unavailable.

# Minimum CF ranges below which we refuse to build (fail-open guard). The real
# Cloudflare set is ~15 v4 + ~7 v6; anything tiny means a broken/partial file.
: "${ORIGIN_LOCK_MIN_RANGES:=3}"

# Persistence locations (overridable in tests). Must match install/install.sh.
: "${SWATTER_OL_CSFPRE:=/etc/csf/csfpre.sh}"
: "${SWATTER_OL_UNIT:=/etc/systemd/system/swatter-origin-lock.service}"

_ol_set_base() { printf '%s' "${ORIGIN_LOCK_SET:-cf_origin}"; }
_ol_set4()     { printf '%s4' "$(_ol_set_base)"; }
_ol_set6()     { printf '%s6' "$(_ol_set_base)"; }
_ol_ports()    { printf '%s' "${ORIGIN_LOCK_PORTS:-80,443}"; }
_ol_mode()     { printf '%s' "${ORIGIN_LOCK:-off}"; }

# xt_string availability for the ACME accept. Tests can pin
# SWATTER_OL_HAVE_XT_STRING; otherwise probe iptables for the string match.
_ol_have_xt_string() {
    if [[ -n "${SWATTER_OL_HAVE_XT_STRING:-}" ]]; then
        [[ "${SWATTER_OL_HAVE_XT_STRING}" -eq 1 ]]; return
    fi
    iptables -m string --help >/dev/null 2>&1
}

# Read the CF ranges file, split into v4 / v6 CIDR lists on stdout via globals.
# Sets _OL_V4 and _OL_V6 (newline-separated). Returns 1 if the file is missing.
_ol_load_ranges() {
    local f="${CLOUDFLARE_IPS_FILE}"
    _OL_V4=""; _OL_V6=""
    [[ -s "$f" ]] || return 1
    local line
    while IFS= read -r line; do
        line="${line%%#*}"; line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        if [[ "$line" == *:* ]]; then _OL_V6+="${line}"$'\n'
        else _OL_V4+="${line}"$'\n'; fi
    done < "$f"
    return 0
}

# Count non-blank CIDR lines across both families.
_ol_range_count() {
    local n=0
    [[ -n "${_OL_V4:-}" ]] && n=$(( n + $(printf '%s' "${_OL_V4}" | grep -c .) ))
    [[ -n "${_OL_V6:-}" ]] && n=$(( n + $(printf '%s' "${_OL_V6}" | grep -c .) ))
    printf '%s' "$n"
}

# Fail-open gate: 0 if the CF range source is trustworthy enough to build a lock.
# Reuses swatter_allowlist_healthy (freshness) plus a hard minimum range count,
# and falls back to the built-in CF set if the file is missing but the builtin is
# sane. Returns 1 (install nothing) on any doubt.
_ol_ranges_healthy() {
    if ! _ol_load_ranges; then
        # Missing/empty cloudflare.cidr -> install NOTHING. We deliberately do NOT
        # fall back to the compiled-in CF set here: unlike the allowlist (where an
        # over-broad never-block set is harmless), an enforcing DROP built from a
        # possibly-stale builtin could drop newly-added Cloudflare edges and take
        # sites offline. A missing file means refresh-feeds never ran — fail open.
        log_error "origin-lock: ${CLOUDFLARE_IPS_FILE} missing/empty — installing NOTHING (fail-open). Run: swatter refresh-feeds"
        return 1
    fi
    local n; n="$(_ol_range_count)"
    if (( n < ORIGIN_LOCK_MIN_RANGES )); then
        log_error "origin-lock: only ${n} CF range(s) in ${CLOUDFLARE_IPS_FILE} (< ${ORIGIN_LOCK_MIN_RANGES}) — installing NOTHING (fail-open)"
        return 1
    fi
    # Freshness advisory only — an under-min file already bailed above; a stale but
    # populated file still locks (better than an open origin) but we warn loudly.
    if declare -F swatter_allowlist_healthy >/dev/null && ! swatter_allowlist_healthy; then
        log_warn "origin-lock: CF range list is stale — proceeding (populated) but run: swatter refresh-feeds"
    fi
    return 0
}

# Build/refresh an ipset from a newline CIDR list. hash:net (CIDR-capable),
# -exist so re-create never errors; entries added with -exist for idempotency.
_ol_build_set() {
    local set="$1" family="$2" ranges="$3" cidr
    ipset create "$set" hash:net family "$family" -exist 2>/dev/null
    while IFS= read -r cidr; do
        [[ -n "$cidr" ]] || continue
        ipset add "$set" "$cidr" -exist 2>/dev/null
    done <<< "$ranges"
}

# Append a rule (csfpre context: the chain is flushed by `csf -r` before each run,
# so a plain -A never stacks).
_ol_append() {
    local ipt="$1"; shift
    "$ipt" -A INPUT "$@" 2>/dev/null
}

# Insert-if-absent (standalone context: no flush, so guard with -C then -I).
_ol_ensure() {
    local ipt="$1"; shift
    "$ipt" -C INPUT "$@" 2>/dev/null || "$ipt" -I INPUT "$@" 2>/dev/null
}

# Per-family rule build. $1=iptables|ip6tables  $2=set  $3=hook(csf|standalone)
#
# ORDER INVARIANT — the effective top-to-bottom INPUT chain order for the rules
# this function lays down MUST be: CF-ACCEPT, ACME-ACCEPT, LOG, DROP (accept-first
# / drop-last — the fail-open spine). Two builders honor this differently:
#   * csf hook  -> _ol_append (`-A`, append): emit in forward order, the chain is
#     flushed by `csf -r` before each run so a plain append preserves order.
#   * standalone -> _ol_ensure (`-I`, prepend to position 1): every insert lands at
#     the TOP, so emitting forward would REVERSE the chain (DROP would end up above
#     the ACCEPTs and silently drop legit Cloudflare traffic). We therefore emit in
#     REVERSE here (DROP, LOG, ACME, CF) so each prepend stacks the final order
#     right-side-up. The lo/allow preamble is inserted separately, AFTER this, so
#     those accepts prepend to the very top (above CF-ACCEPT).
_ol_rules_family() {
    local ipt="$1" set="$2" hook="$3" ports mode
    ports="$(_ol_ports)"; mode="$(_ol_mode)"

    local add reverse
    if [[ "$hook" == "csf" ]]; then add=_ol_append; reverse=0; else add=_ol_ensure; reverse=1; fi

    # Resolve the ACME accept availability once (so the warning fires regardless of
    # emission order, and at most once per family).
    local emit_acme=0
    if [[ "${ORIGIN_LOCK_ALLOW_ACME:-true}" == "true" ]]; then
        if _ol_have_xt_string; then
            emit_acme=1
        else
            log_warn "origin-lock: xt_string unavailable — skipping /.well-known/ domain-validation accept (set ORIGIN_LOCK_ALLOW_ACME=false or use DNS-01)"
        fi
    fi

    _ol_emit_cf()   { "$add" "$ipt" -p tcp -m multiport --dports "$ports" -m set --match-set "$set" src -j ACCEPT; }
    _ol_emit_acme() { (( emit_acme )) && "$add" "$ipt" -p tcp --dport 80 -m string --string "/.well-known/" --algo bm -j ACCEPT; }
    _ol_emit_log()  { "$add" "$ipt" -p tcp -m multiport --dports "$ports" -m limit --limit 5/min -j LOG --log-prefix "ORIGIN-LOCK: "; }
    _ol_emit_drop() { [[ "$mode" == "drop" ]] && "$add" "$ipt" -p tcp -m multiport --dports "$ports" -j DROP; }

    if (( reverse )); then
        # -I prepends: emit bottom-up so the final chain reads CF, ACME, LOG, DROP.
        _ol_emit_drop; _ol_emit_log; _ol_emit_acme; _ol_emit_cf
    else
        # -A appends: emit top-down.
        _ol_emit_cf; _ol_emit_acme; _ol_emit_log; _ol_emit_drop
    fi
}

# Standalone safe preamble: lo + allow/monitoring ranges -> web ports. NO
# established/related accept (see header). Guarded inserts (idempotent).
_ol_preamble_family() {
    local ipt="$1" ports cidr f
    ports="$(_ol_ports)"
    _ol_ensure "$ipt" -i lo -p tcp -m multiport --dports "$ports" -j ACCEPT
    for f in "${OPERATOR_ALLOW_FILE:-}" "${MONITORING_RANGES_FILE:-}"; do
        [[ -n "$f" && -f "$f" ]] || continue
        while IFS= read -r cidr; do
            cidr="${cidr%%#*}"; cidr="${cidr//[[:space:]]/}"
            [[ -z "$cidr" ]] && continue
            # v6 CIDRs only into ip6tables, v4 only into iptables.
            if [[ "$ipt" == "ip6tables" && "$cidr" != *:* ]]; then continue; fi
            if [[ "$ipt" == "iptables"  && "$cidr" == *:* ]]; then continue; fi
            _ol_ensure "$ipt" -s "$cidr" -p tcp -m multiport --dports "$ports" -j ACCEPT
        done < "$f"
    done
}

# Remove every rule this module installs from a family's INPUT chain. Best-effort,
# loops -D until the check misses so duplicates from older runs all clear.
_ol_teardown_family() {
    local ipt="$1" set="$2" ports
    ports="$(_ol_ports)"
    local rules=(
        "-p tcp -m multiport --dports ${ports} -m set --match-set ${set} src -j ACCEPT"
        "-p tcp --dport 80 -m string --string /.well-known/ --algo bm -j ACCEPT"
        "-p tcp -m multiport --dports ${ports} -m limit --limit 5/min -j LOG --log-prefix ORIGIN-LOCK: "
        "-p tcp -m multiport --dports ${ports} -j DROP"
        "-i lo -p tcp -m multiport --dports ${ports} -j ACCEPT"
    )
    local r tries
    for r in "${rules[@]}"; do
        tries=0
        # Delete directly in a loop: -D removes one matching rule and returns
        # nonzero once none remain (so duplicates from older runs all clear). No
        # -C guard — -D is harmless/no-op when the rule is absent.
        # shellcheck disable=SC2086
        while (( tries < 20 )) && "$ipt" -D INPUT $r 2>/dev/null; do
            tries=$(( tries + 1 ))
        done
    done
    # Also drop any -s allow/monitoring preamble accepts.
    local cidr f
    for f in "${OPERATOR_ALLOW_FILE:-}" "${MONITORING_RANGES_FILE:-}"; do
        [[ -n "$f" && -f "$f" ]] || continue
        while IFS= read -r cidr; do
            cidr="${cidr%%#*}"; cidr="${cidr//[[:space:]]/}"
            [[ -z "$cidr" ]] && continue
            if [[ "$ipt" == "ip6tables" && "$cidr" != *:* ]]; then continue; fi
            if [[ "$ipt" == "iptables"  && "$cidr" == *:* ]]; then continue; fi
            "$ipt" -D INPUT -s "$cidr" -p tcp -m multiport --dports "$ports" -j ACCEPT 2>/dev/null || true
        done < "$f"
    done
}

# Full teardown: rules (v4 + v6) and the cf_origin sets. Idempotent.
swatter_origin_lock_teardown() {
    local destroy="${1:-yes}"
    _ol_teardown_family iptables "$(_ol_set4)"
    if [[ "${SWATTER_HAVE_IP6TABLES:-0}" -eq 1 ]]; then
        _ol_teardown_family ip6tables "$(_ol_set6)"
    fi
    if [[ "$destroy" == "yes" ]]; then
        ipset destroy "$(_ol_set4)" 2>/dev/null || true
        ipset destroy "$(_ol_set6)" 2>/dev/null || true
    fi
}

# Persistence-hook markers — MUST match install/install.sh's ORIGIN_LOCK_BEGIN/END.
_OL_CSFPRE_BEGIN="# >>> swatter origin-lock (managed) >>>"
_OL_CSFPRE_END="# <<< swatter origin-lock (managed) <<<"

# Remove the boot/reload persistence so a disabled lock never re-applies: strip the
# managed block from csfpre.sh (in-place rewrite preserves the rest + file perms)
# and disable + remove the systemd unit.
_ol_remove_persistence() {
    if [[ -f "${SWATTER_OL_CSFPRE}" ]] && grep -qF "${_OL_CSFPRE_BEGIN}" "${SWATTER_OL_CSFPRE}" 2>/dev/null; then
        local tmp
        if tmp="$(mktemp 2>/dev/null)"; then
            if awk -v b="${_OL_CSFPRE_BEGIN}" -v e="${_OL_CSFPRE_END}" '
                    $0==b {skip=1; next} $0==e {skip=0; next} !skip {print}
                ' "${SWATTER_OL_CSFPRE}" > "$tmp" 2>/dev/null; then
                cat "$tmp" > "${SWATTER_OL_CSFPRE}" 2>/dev/null \
                    && echo "removed origin-lock block from ${SWATTER_OL_CSFPRE}"
            fi
            rm -f "$tmp"
        fi
    fi
    if [[ -f "${SWATTER_OL_UNIT}" ]]; then
        command -v systemctl >/dev/null 2>&1 && systemctl disable --now swatter-origin-lock.service >/dev/null 2>&1 || true
        rm -f "${SWATTER_OL_UNIT}"
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
        echo "removed ${SWATTER_OL_UNIT}"
    fi
}

# Core apply. $1=hook(csf|standalone).
swatter_origin_lock_apply() {
    local hook="${1:-standalone}" mode
    mode="$(_ol_mode)"

    if [[ "$mode" != "off" && "$mode" != "log" && "$mode" != "drop" ]]; then
        log_error "origin-lock: invalid ORIGIN_LOCK='${mode}' (expected off|log|drop)"
        return 2
    fi

    # Dry-run guard BEFORE any firewall mutation — report mode must never touch the
    # firewall, including the off-mode teardown.
    if [[ "${SWATTER_MODE:-report}" != "enforce" ]]; then
        if [[ "$mode" == "off" ]]; then
            log_info "[dry-run] origin-lock: ORIGIN_LOCK=off — would tear down any existing lock (no firewall changes)"
        else
            log_info "[dry-run] origin-lock apply (mode=${mode}, hook=${hook}) — no firewall changes"
        fi
        return 0
    fi

    if [[ "$mode" == "off" ]]; then
        log_info "origin-lock: ORIGIN_LOCK=off — tearing down any existing lock"
        swatter_origin_lock_teardown yes
        return 0
    fi

    # Fail-open gate.
    if ! _ol_ranges_healthy; then
        return 1
    fi

    # Build the v4 set + rules.
    _ol_build_set "$(_ol_set4)" inet "${_OL_V4}"
    _ol_rules_family iptables "$(_ol_set4)" "$hook"

    # v6 gated on ip6tables presence (warn-and-skip if absent — leaving v6 web
    # ports uncovered rather than failing the whole apply).
    if [[ -n "${_OL_V6//[$'\n']/}" ]]; then
        if [[ "${SWATTER_HAVE_IP6TABLES:-0}" -eq 1 ]]; then
            _ol_build_set "$(_ol_set6)" inet6 "${_OL_V6}"
            _ol_rules_family ip6tables "$(_ol_set6)" "$hook"
        else
            log_warn "origin-lock: ip6tables not found — IPv6 web ports left UNCOVERED (v4 lock only)"
        fi
    fi

    # Standalone preamble (lo + allow/monitoring) — only when NOT under csfpre,
    # since CSF already supplies those accepts above the csfpre hook.
    if [[ "$hook" != "csf" ]]; then
        _ol_preamble_family iptables
        [[ "${SWATTER_HAVE_IP6TABLES:-0}" -eq 1 ]] && _ol_preamble_family ip6tables
    fi

    log_info "origin-lock applied (mode=${mode}, hook=${hook}, ports=$(_ol_ports))"
    if [[ "$mode" == "log" ]]; then
        log_warn "origin-lock is in LOG mode: validate would-be-drops with 'swatter origin-lock preflight', allowlist legit sources, THEN set ORIGIN_LOCK=drop."
    fi
    return 0
}

# --------------------------------------------------------------------------
# preflight — classify the ORIGIN-LOCK: LOG sample against intel feeds + allowlist.
# --------------------------------------------------------------------------

# Locate the kernel-LOG source portably and emit matching lines on stdout. Tests
# pin SWATTER_OL_LOG_SAMPLE to a fixture file.
_ol_log_sample() {
    if [[ -n "${SWATTER_OL_LOG_SAMPLE:-}" && -f "${SWATTER_OL_LOG_SAMPLE}" ]]; then
        grep -aF 'ORIGIN-LOCK:' "${SWATTER_OL_LOG_SAMPLE}" 2>/dev/null
        return 0
    fi
    if have journalctl; then
        journalctl -k --no-pager 2>/dev/null | grep -aF 'ORIGIN-LOCK:'
        return 0
    fi
    local f
    for f in /var/log/messages /var/log/syslog /var/log/kern.log; do
        [[ -r "$f" ]] && grep -aF 'ORIGIN-LOCK:' "$f" 2>/dev/null
    done
}

# Extract unique SRC= IPs from the sample.
_ol_sample_ips() {
    _ol_log_sample | grep -oE 'SRC=[0-9a-fA-F:.]+' | sed 's/^SRC=//' | sort -u
}

swatter_origin_lock_preflight() {
    echo "== origin-lock preflight =="
    local src="kernel LOG"
    if [[ -n "${SWATTER_OL_LOG_SAMPLE:-}" && -f "${SWATTER_OL_LOG_SAMPLE}" ]]; then src="${SWATTER_OL_LOG_SAMPLE}"
    elif have journalctl; then src="journalctl -k"
    else src="/var/log/{messages,syslog,kern.log}"; fi
    echo "source: ${src} (rate-limited LOG sample — not every packet)"
    echo
    printf '%-40s  %s\n' "SOURCE IP" "VERDICT"

    local ip n=0 score label verdict
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        n=$(( n + 1 ))
        # 1. intel feed -> confirmed attacker.
        score=0; label=""
        if declare -F swatter_intel_score >/dev/null; then
            local sc; sc="$(swatter_intel_score "$ip" 2>/dev/null)"
            score="$(printf '%s' "$sc" | cut -f1)"; label="$(printf '%s' "$sc" | cut -f2)"
            [[ "$score" =~ ^[0-9]+$ ]] || score=0
        fi
        if (( score > 0 )); then
            printf '%-40s  %s\n' "$ip" "confirmed attacker (intel: ${label:-deny}) — safe to drop"
            continue
        fi
        # 2. allowlist / monitoring -> legit, allowlist before DROP.
        if { [[ -f "${OPERATOR_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${OPERATOR_ALLOW_FILE}"; } \
           || { [[ -f "${MONITORING_RANGES_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${MONITORING_RANGES_FILE}"; }; then
            printf '%-40s  %s\n' "$ip" "legit — allowlist before DROP (in allow/monitoring)"
            continue
        fi
        # 3. neither -> unknown, review.
        printf '%-40s  %s\n' "$ip" "unknown — review (could be a real visitor to a non-CF site)"
    done < <(_ol_sample_ips)

    echo
    if (( n == 0 )); then
        echo "(no ORIGIN-LOCK: log lines found — run LOG mode for a while first)"
    else
        echo "${n} distinct source(s) classified."
    fi
}

# --------------------------------------------------------------------------
# status — mode, ipset health, live counters.
# --------------------------------------------------------------------------
_ol_set_count() {
    local set="$1" out
    out="$(ipset list "$set" 2>/dev/null)" || { printf 'absent'; return; }
    printf '%s' "$(printf '%s\n' "$out" | grep -cE '^[0-9a-fA-F]')"
}

swatter_origin_lock_status() {
    local mode; mode="$(_ol_mode)"
    echo "origin-lock:"
    echo "  mode:        ${mode}  (ports $(_ol_ports))"
    echo "  set v4:      $(_ol_set4) -> $(_ol_set_count "$(_ol_set4)") entr(y/ies)"
    if [[ "${SWATTER_HAVE_IP6TABLES:-0}" -eq 1 ]]; then
        echo "  set v6:      $(_ol_set6) -> $(_ol_set_count "$(_ol_set6)") entr(y/ies)"
    else
        echo "  set v6:      (ip6tables absent — v6 uncovered)"
    fi
    # Persistence mode.
    local persist="none"
    if [[ -f "${SWATTER_OL_CSFPRE}" ]] && grep -q 'origin-lock' "${SWATTER_OL_CSFPRE}" 2>/dev/null; then
        persist="csfpre hook"
    elif [[ -f "${SWATTER_OL_UNIT}" ]]; then
        persist="systemd unit"
    fi
    echo "  persistence: ${persist}"
}

# --------------------------------------------------------------------------
# Subcommand dispatch (apply|status|preflight|disable) with the drop guard.
# Lives in the lib so the test can drive it without bin/swatter. bin/swatter's
# cmd_origin_lock is a thin wrapper around this.
# --------------------------------------------------------------------------
cmd_origin_lock() {
    local action="${1:-status}"; shift || true
    local hook="standalone" assume_yes=0 arg
    for arg in "$@"; do
        case "$arg" in
            --hook=csf)        hook="csf" ;;
            --hook=standalone) hook="standalone" ;;
            --yes|--force)     assume_yes=1 ;;
            *) log_warn "origin-lock: ignoring unknown flag '${arg}'" ;;
        esac
    done

    case "$action" in
        apply)
            # Drop guard: installing DROP requires preflight + explicit consent.
            if [[ "$(_ol_mode)" == "drop" && "${SWATTER_MODE:-report}" == "enforce" ]]; then
                if (( ! assume_yes )); then
                    echo "ORIGIN_LOCK=drop will DROP non-Cloudflare traffic to the web ports." >&2
                    echo "Running preflight first — review the would-be-drops below:" >&2
                    swatter_origin_lock_preflight >&2
                    echo >&2
                    if [[ -t 0 ]]; then
                        local reply
                        read -r -p "Proceed installing DROP? Type 'yes' to confirm: " reply
                        if [[ "$reply" != "yes" ]]; then
                            log_error "origin-lock: DROP not confirmed — aborting (no rules changed)"
                            return 3
                        fi
                    else
                        log_error "origin-lock: DROP mode requires --yes/--force (or an interactive confirm) — aborting"
                        return 3
                    fi
                fi
            fi
            swatter_origin_lock_apply "$hook"
            ;;
        status)    swatter_origin_lock_status ;;
        preflight) swatter_origin_lock_preflight ;;
        disable)
            swatter_origin_lock_teardown yes
            _ol_remove_persistence
            log_info "origin-lock disabled — rules + ipset sets removed and persistence hooks stripped (csfpre block + systemd unit)."
            echo "origin-lock disabled — rules + ipset sets removed; persistence (csfpre block / systemd unit) stripped so it won't re-apply on boot or 'csf -r'."
            ;;
        *) log_error "origin-lock: unknown subcommand '${action}' (apply|status|preflight|disable)"; return 2 ;;
    esac
}

# --- nightly-report digest section (read-only) ------------------------------
# Resolve the syslog source(s) holding ORIGIN-LOCK: lines.
_ol_digest_logs() {
    if [[ -n "${ORIGIN_LOCK_LOG:-}" ]]; then printf '%s' "${ORIGIN_LOCK_LOG:-}"; return; fi
    printf '/var/log/messages'
}

# Gate: should the section render given <hits> in the window?
_ol_digest_should_render() {
    local hits="${1:-0}"
    case "${ORIGIN_LOCK_DIGEST:-auto}" in
        on)  return 0 ;;
        off) return 1 ;;
        *)   (( hits > 0 )) ;;   # auto: render only when there were drops
    esac
}

# Is <ip> in a swatter threat feed (attacker) or an allow/monitoring range (legit)?
_ol_tag_ip() {
    local ip="$1" f
    for f in "${STATE_DIR}/feeds/"ipsum.txt "${STATE_DIR}/feeds/"blocklist_de.txt \
             "${STATE_DIR}/feeds/"cins.txt "${STATE_DIR}/feeds/"greensnow.txt \
             "${STATE_DIR}/feeds/"et_compromised.txt; do
        [[ -r "$f" ]] && grep -qxF "$ip" "$f" 2>/dev/null && { printf 'attacker'; return; }
    done
    local c
    for c in /etc/swatter/monitoring.cidr /etc/swatter/allow.cidr; do
        [[ -r "$c" ]] && grep -qF "$ip" "$c" 2>/dev/null && { printf 'legit'; return; }
    done
    printf 'uncategorized'
}

# swatter_originlock_section <window> — emits the plain-text Origin-Lock section
# and sets OL_* globals for the renderers. Read-only.
swatter_originlock_section() {
    local window="$1"
    OL_HITS=0 OL_IPS=0 OL_P80=0 OL_P443=0 OL_MODE="" OL_TOP_ROWS=""

    # Build the set of syslog day-labels (Mon DD) that fall inside the window.
    # days = floor(window_secs/86400)+1 covers the boundary day and prevents
    # unbounded-retention over-counting (the grep below spans the full live log).
    local window_secs days
    window_secs="$(_report_window_secs "$window")"
    days=$(( window_secs / 86400 + 1 ))
    local now_ts; now_ts="$(swatter_now)"
    # Build a pipe-separated label string (avoids newline-in-awk-var BSD awk limits).
    local label_str="" i ts lbl
    for (( i = 0; i < days; i++ )); do
        ts=$(( now_ts - i * 86400 ))
        lbl="$(date -d "@$ts" +'%b %e' 2>/dev/null || date -r "$ts" +'%b %e')"
        # Normalize the double-space produced for single-digit days ("Jun  5" ->
        # "Jun 5") to match awk's $1" "$2 reconstruction which collapses fields.
        lbl="${lbl//  / }"
        label_str+="${lbl}|"
    done
    label_str="${label_str%|}"; # strip trailing pipe

    local logs; logs="$(_ol_digest_logs)"
    # shellcheck disable=SC2086
    # $logs intentionally word-splits for multi-path glob support
    local raw_hits; raw_hits="$(grep -hE "ORIGIN-LOCK:" $logs 2>/dev/null || true)"

    # Keep only lines whose leading syslog "Mon DD" ($1 " " $2) is in the day set.
    local hits
    hits="$(printf '%s\n' "$raw_hits" | awk -v labels="$label_str" '
        BEGIN {
            n = split(labels, a, "|")
            for (i = 1; i <= n; i++) { if (a[i] != "") valid[a[i]] = 1 }
        }
        NF > 0 { if (($1 " " $2) in valid) print }
    ')"

    OL_HITS=$(printf '%s\n' "$hits" | grep -c . || true)
    [[ "$OL_HITS" -gt 0 ]] || { OL_HITS=0; echo "Origin-lock: no direct-to-origin drops in the last ${window}."; return 0; }

    OL_P80=$(printf '%s\n' "$hits"  | grep -oE 'DPT=80\b'  | grep -c . || true)
    OL_P443=$(printf '%s\n' "$hits" | grep -oE 'DPT=443\b' | grep -c . || true)
    OL_MODE="$(grep -m1 '^MODE=' "${SWATTER_OL_CSFPRE:-/etc/csf/csfpre.sh}" 2>/dev/null | sed 's/.*=//; s/"//g; s/ .*//' || true)"
    [[ -n "$OL_MODE" ]] || OL_MODE="$( [[ "$(_ol_mode)" == off ]] && echo "?" || echo "$(_ol_mode)" )"

    local srcs; srcs="$(printf '%s\n' "$hits" | grep -oE 'SRC=[0-9a-fA-F:.]+' | sed 's/SRC=//' | sort | uniq -c | sort -rn)"
    OL_IPS=$(printf '%s\n' "$srcs" | grep -c . || true)

    local ip n tag
    while read -r n ip; do
        [[ -n "$ip" ]] || continue
        tag="$(_ol_tag_ip "$ip")"
        OL_TOP_ROWS+="${ip}"$'\t'"${n}"$'\t'"${tag}"$'\n'
    done < <(printf '%s\n' "$srcs" | head -10)

    {
        echo "Direct-to-origin drops: ${OL_HITS} from ${OL_IPS} IPs  (:80 ${OL_P80} · :443 ${OL_P443}; mode ${OL_MODE})"
        echo
        echo "Top sources"
        echo "-----------"
        printf '%s' "$OL_TOP_ROWS" | awk -F'\t' '{printf "  %-16s %5s  %s\n",$1,$2,$3}'
    }
}

# Brief one-line summary for `swatter status` / `swatter test-config`.
swatter_origin_lock_summary() {
    local mode; mode="$(_ol_mode)"
    local hook="no"
    { [[ -f "${SWATTER_OL_CSFPRE}" ]] && grep -q 'origin-lock' "${SWATTER_OL_CSFPRE}" 2>/dev/null; } && hook="csfpre"
    [[ -f "${SWATTER_OL_UNIT}" ]] && hook="systemd"
    local health="n/a"
    if [[ "$mode" != "off" ]]; then
        if _ol_load_ranges && (( $(_ol_range_count) >= ORIGIN_LOCK_MIN_RANGES )); then health="ranges ok"; else health="ranges MISSING/too-small (fail-open)"; fi
    fi
    printf 'mode=%s, hook=%s, %s' "$mode" "$hook" "$health"
}
