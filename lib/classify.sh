#!/usr/bin/env bash
# lib/classify.sh — decide which firewall plane a block belongs to.
#
# The rule that prevents an outage: an offender whose traffic transited
# Cloudflare has a Cloudflare EDGE IP as its TCP socket. CSF-denying that socket
# firewalls the proxy and takes every site down. So such offenders must be
# blocked at the Cloudflare WAF, never at CSF. Only offenders we can prove hit
# the origin DIRECTLY (raw IP / cPanel service ports) are CSF-denied.
#
# classify() returns one of: DIRECT | VIA_CF
#   DIRECT -> CSF deny is safe (the socket is the attacker)
#   VIA_CF -> Cloudflare-plane only (the socket is a CF edge); this is also the
#             ambiguous/no-direct-evidence default (the safe plane)
#
# Portability: on a box NOT behind Cloudflare, every offender is DIRECT, so
# Swatter works as a plain CSF auto-blocker with zero Cloudflare config.

# Is Cloudflare actually fronting this server? If not, all traffic is direct and
# CSF is always the right (and only) plane.
#
# "off" means NOT BEHIND CLOUDFLARE — it disables classification entirely and
# every offender becomes DIRECT/CSF. Never set "off" on a CF-fronted box to mean
# "leave Cloudflare alone": proxied offenders (including real customers behind
# the proxy) would be misrouted to CSF. That posture is CF_MODE="skip", which
# keeps classification on and simply doesn't act on the VIA_CF plane.
#
# "auto" (the default) defers to a cached detection verdict (see
# swatter_detect_cf): a confident "not-behind" reading behaves like "off"; any
# other reading ("behind"/"uncertain"/absent) keeps the safe, classification-on
# posture until detection proves the box is bare.
#
# swatter_cf_fronted : posture only — does a Cloudflare plane exist in front of
# this box? Independent of whether the range list is present, so it can gate the
# fail-closed rail even when ranges have gone missing.
swatter_cf_fronted() {
    [[ "${CF_MODE}" == "off" ]] && return 1
    if [[ "${CF_MODE}" == "auto" ]]; then
        [[ "$(swatter_cached_cf_verdict)" == "not-behind" ]] && return 1
    fi
    return 0
}

# swatter_cf_in_use : fronted AND we actually have ranges to classify against.
# This is the classifier's shortcut — with no ranges (or no CF plane) every
# offender is DIRECT. Preserves the original semantics; only adds the auto/off
# posture short-circuit via swatter_cf_fronted.
swatter_cf_in_use() {
    swatter_cf_fronted || return 1
    [[ -s "${CLOUDFLARE_IPS_FILE}" ]] && return 0
    return 1
}

# swatter_cf_manages_plane : 0 (true) when Swatter should ACTIVELY run the
# Cloudflare plane (create/sweep IP Access Rules). True for explicit "direct"
# (which still skips per-offender if a token is missing, as before), or for
# "auto" once it has detected a CF-fronted box AND the creds + domain map needed
# to act are present. Otherwise the via-CF plane is left alone (skip-like): a
# fresh auto box with no creds logs via-CF offenders without erroring.
swatter_cf_manages_plane() {
    case "${CF_MODE}" in
        direct) return 0 ;;
        auto)
            swatter_cf_fronted || return 1
            [[ -s "${CF_CREDS_FILE}" && -s "${CF_DOMAINS_MAP}" ]] || return 1
            return 0 ;;
        *) return 1 ;;
    esac
}

# swatter_failclosed_active : 0 (true) when CSF denies must be suppressed this
# run. That is ONLY when the box is CF-fronted AND the range list we classify
# against is missing/stale — without trustworthy ranges we cannot tell a CF edge
# socket from a direct one, so a CSF deny could firewall the proxy. With no CF
# plane there is nothing to misroute, so a bare box keeps blocking normally.
# Gated on posture (fronted), NOT cf_in_use: a direct/auto-behind box with
# missing ranges must still fail closed, exactly as before.
swatter_failclosed_active() {
    swatter_cf_fronted || return 1
    swatter_allowlist_healthy && return 1
    return 0
}

# _swatter_resolve_host <hostname> : print resolved IPs, one per line (empty if
# unresolvable or no resolver). Isolated so tests can dependency-inject it.
_swatter_resolve_host() {
    local h="$1"
    if have getent; then
        getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u
    elif have host; then
        host "$h" 2>/dev/null | awk '/has address/{print $NF} /IPv6 address/{print $NF}'
    elif have dig; then
        dig +short +time=3 +tries=1 "$h" A "$h" AAAA 2>/dev/null \
            | grep -E '^[0-9a-fA-F:.]+$'
    fi
}

# _swatter_own_vhosts : distinct, domain-looking hostnames this box serves,
# derived from the domlog filenames. cPanel suffixes (-ssl_log, _log) collapse
# to the bare host. Bounded to the first 20 so detection stays cheap.
_swatter_own_vhosts() {
    local f base
    for f in ${DOMLOGS_GLOB}; do
        [[ -e "$f" ]] || continue
        base="$(basename -- "$f")"
        base="${base%-ssl_log}"; base="${base%_log}"; base="${base%.log}"
        [[ "$base" == *.* ]] || continue
        printf '%s\n' "$base"
    done | sort -u | head -n 20
}

# swatter_compute_cf_verdict : decide whether this box sits behind Cloudflare.
# Prints "<verdict>\t<reason>" where verdict is behind | not-behind | uncertain.
# Pure (no cache write). Safety bias: only the authoritative DNS signal may
# conclude "not-behind"; every other inconclusive path yields "uncertain", which
# callers treat as behind (the safe, classification-on plane).
swatter_compute_cf_verdict() {
    # 1. Operator already wired Cloudflare — definitive.
    if [[ -s "${CF_DOMAINS_MAP}" ]] && grep -qvE '^[[:space:]]*(#|$)' "${CF_DOMAINS_MAP}" 2>/dev/null; then
        printf 'behind\toperator CF domain map present'; return 0
    fi
    if [[ -s "${CF_CREDS_FILE}" ]] && grep -qvE '^[[:space:]]*(#|$)' "${CF_CREDS_FILE}" 2>/dev/null; then
        printf 'behind\toperator CF creds present'; return 0
    fi

    # 2. DNS of the box's own vhosts — authoritative, and the only signal that
    # may conclude "not-behind". Needs the CF range list to test membership.
    if [[ -s "${CLOUDFLARE_IPS_FILE}" ]]; then
        local host ip resolved=0
        while IFS= read -r host; do
            [[ -n "$host" ]] || continue
            local got=0
            while IFS= read -r ip; do
                [[ -n "$ip" ]] || continue
                got=1
                if _ip_in_cidr_file "$ip" "${CLOUDFLARE_IPS_FILE}"; then
                    printf 'behind\tvhost %s resolves into a Cloudflare range' "$host"; return 0
                fi
            done < <(_swatter_resolve_host "$host")
            (( got )) && resolved=$(( resolved + 1 ))
        done < <(_swatter_own_vhosts)
        if (( resolved > 0 )); then
            printf 'not-behind\t%d vhost(s) resolve, none to Cloudflare' "$resolved"; return 0
        fi
    fi

    # 3. Web-server config references Cloudflare (mod_remoteip / CF-Connecting-IP).
    local hc
    for hc in ${SWATTER_HTTPD_CF_GLOB}; do
        [[ -r "$hc" ]] || continue
        if grep -qiE 'CF-Connecting-IP|cloudflare' "$hc" 2>/dev/null; then
            printf 'behind\tweb-server config references Cloudflare'; return 0
        fi
    done

    # 4. An inbound socket landed in a CF range (weak; "behind" is the safe way
    # to be wrong, so this only ever over-protects).
    if [[ -s "${CLOUDFLARE_IPS_FILE}" && -n "${LFD_LOG}" && -r "${LFD_LOG}" ]]; then
        local sip
        while IFS= read -r sip; do
            if _ip_in_cidr_file "$sip" "${CLOUDFLARE_IPS_FILE}"; then
                printf 'behind\tinbound socket %s is a Cloudflare edge' "$sip"; return 0
            fi
        done < <(grep -aoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "${LFD_LOG}" 2>/dev/null | sort -u | head -n 200)
    fi

    printf 'uncertain\tno conclusive Cloudflare signal'; return 0
}

# swatter_cached_cf_verdict : print the cached verdict word ("" if none).
swatter_cached_cf_verdict() {
    local f="${STATE_DIR}/cf-detect"
    [[ -r "$f" ]] || return 0
    cut -f1 "$f" 2>/dev/null | head -n1
}

# swatter_detect_cf : compute the verdict and cache it as "<verdict>\t<epoch>\t
# <reason>" in $STATE_DIR/cf-detect. Run at install / refresh-feeds / test-config
# — never implicitly by scan, so the cron path stays network-free. Best-effort:
# never aborts.
swatter_detect_cf() {
    local out verdict reason now
    out="$(swatter_compute_cf_verdict)" || out="uncertain	detection error"
    verdict="${out%%	*}"; reason="${out#*	}"
    now="$(swatter_now)"
    mkdir -p "${STATE_DIR}" 2>/dev/null || true
    printf '%s\t%s\t%s\n' "$verdict" "$now" "$reason" > "${STATE_DIR}/cf-detect" 2>/dev/null || true
    log_info "cf-detect: ${verdict} (${reason})"
    printf '%s' "$verdict"
}

# Live remote IPv4 peers of TCP connections to this box's web ports
# (DIRECT_WEB_PORTS). A Cloudflare-proxied request arrives from a CF EDGE socket;
# mod_remoteip restores the visitor IP only at L7, so a socket peer that is not a
# CF edge is hitting the origin directly. Dependency-injected in tests. Empty
# DIRECT_WEB_PORTS or a missing `ss` yields nothing (graceful no-op). IPv4 only,
# matching the lfd direct set; IPv6 direct sockets are a follow-up.
_swatter_websocket_peers() {
    [[ -n "${DIRECT_WEB_PORTS:-}" ]] || return 0
    have ss || return 0
    local p filter=""
    for p in ${DIRECT_WEB_PORTS}; do
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        [[ -n "$filter" ]] && filter+=" or "
        filter+="sport = :$p"
    done
    [[ -n "$filter" ]] || return 0
    # Established + half-open (a flood mid-handshake still counts). Take the peer
    # field (last column) and keep only its IPv4 address.
    ss -Htn state established state syn-recv "( $filter )" 2>/dev/null \
        | awk '{print $NF}' \
        | grep -aoE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u
}

# Build the set of IPs seen hitting the origin DIRECTLY this run. Two sources:
#   1. lfd.log connections against cPanel service ports (2082/2083/2086/2087/
#      2095/2096/2077/2078) — not proxied by Cloudflare. Window-scoped: stale lfd
#      history must not grant "direct" evidence, or a customer who once touched a
#      cPanel port would be CSF-denied for an offense that arrived via the proxy.
#   2. Live web-port sockets from non-Cloudflare peers — a confirmed offender
#      POSTing straight to the origin IP with a valid Host (CF bypass). Folded in
#      ONLY when the CF range list is trustworthy (swatter_allowlist_healthy):
#      without it we cannot tell a CF edge socket from a direct one, and folding
#      an edge in could CSF the proxy. (CSF denies are already fail-closed-
#      suppressed when ranges are bad; this keeps the set itself clean too.)
# Cached in a temp file path stored in SWATTER_DIRECT_SET.
swatter_build_direct_set() {
    local out; out="$(mktemp "${TMPDIR:-/tmp}/swatter-direct.XXXXXX")"
    SWATTER_DIRECT_SET="$out"
    export SWATTER_DIRECT_SET

    # Source 1: lfd cPanel-service-port hits within the window.
    if [[ -n "${LFD_LOG}" && -r "${LFD_LOG}" ]]; then
        local now cutoff
        now="$(swatter_now)"; cutoff=$(( now - WINDOW_SECONDS ))
        # lfd/syslog writes stamps in the host's LOCAL time. common.sh forces
        # TZ=UTC process-wide, which would make gawk's mktime() read those local
        # stamps as UTC and skew the window filter on non-UTC hosts. Unset TZ for
        # THIS invocation only so mktime() matches the stamp's zone (/etc/localtime).
        ( unset TZ; gawk -v cutoff="$cutoff" -v now="$now" '
            BEGIN {
                split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
                for (i = 1; i <= 12; i++) mon[mn[i]] = i
                year = strftime("%Y", now) + 0
            }
            /2082|2083|2086|2087|2095|2096|2077|2078/ {
                # syslog stamp: "Mon dd HH:MM:SS" in local time, no year.
                if (!($1 in mon) || split($3, t, ":") != 3) next
                ts = mktime(year " " mon[$1] " " $2 " " t[1] " " t[2] " " t[3])
                if (ts > now + 86400)   # "future" stamp = line from last year
                    ts = mktime((year - 1) " " mon[$1] " " $2 " " t[1] " " t[2] " " t[3])
                if (ts >= cutoff) print
            }' "${LFD_LOG}" ) 2>/dev/null \
            | grep -aoE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            >> "$out" 2>/dev/null || true
    fi

    # Source 2: live web-port sockets from non-Cloudflare peers (CF bypass).
    if [[ -n "${DIRECT_WEB_PORTS:-}" ]] && swatter_allowlist_healthy; then
        local peer
        while IFS= read -r peer; do
            [[ -n "$peer" ]] || continue
            _ip_in_cidr_file "$peer" "${CLOUDFLARE_IPS_FILE}" && continue
            printf '%s\n' "$peer"
        done < <(_swatter_websocket_peers) >> "$out" 2>/dev/null || true
    fi

    sort -u -o "$out" "$out" 2>/dev/null || true
}

# Does the offender have direct-socket evidence?
#   $1 = ip
#   $2 = novhost_subscore (0-100 from score.awk; >0 means it hit raw IP/no vhost)
_swatter_has_direct_evidence() {
    local ip="$1" novhost="${2:-0}"
    # Hit a cPanel service port directly (strongest signal).
    if [[ -n "${SWATTER_DIRECT_SET:-}" && -f "${SWATTER_DIRECT_SET}" ]]; then
        grep -qxF "$ip" "${SWATTER_DIRECT_SET}" && return 0
    fi
    # Hit the raw server IP / sent no usable Host (logged with empty vhost).
    (( novhost > 0 )) && return 0
    return 1
}

# classify <ip> <novhost_subscore>
swatter_classify() {
    local ip="$1" novhost="${2:-0}"
    if ! swatter_cf_in_use; then
        echo "DIRECT"; return 0
    fi
    if _swatter_has_direct_evidence "$ip" "$novhost"; then
        # Direct evidence present. If the IP ALSO appears via proxied vhosts we
        # cannot tell apart here, prefer DIRECT (CSF stops the real socket); a CF
        # rule is added too only when proxied evidence is explicit. For v1 we act
        # DIRECT — safe, because direct evidence means the socket is the attacker.
        echo "DIRECT"; return 0
    fi
    # No direct evidence on a CF-fronted box: assume proxied. Fail toward the
    # safe plane.
    echo "VIA_CF"; return 0
}
