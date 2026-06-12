#!/usr/bin/env bash
# lib/classify.sh — decide which firewall plane a block belongs to.
#
# The rule that prevents an outage: an offender whose traffic transited
# Cloudflare has a Cloudflare EDGE IP as its TCP socket. CSF-denying that socket
# firewalls the proxy and takes every site down. So such offenders must be
# blocked at the Cloudflare WAF, never at CSF. Only offenders we can prove hit
# the origin DIRECTLY (raw IP / cPanel service ports) are CSF-denied.
#
# classify() returns one of: DIRECT | VIA_CF | BOTH
#   DIRECT -> CSF deny is safe (the socket is the attacker)
#   VIA_CF -> Cloudflare-plane only (the socket is a CF edge)
#   BOTH   -> direct evidence AND proxied evidence; act on both planes
#
# Portability: on a box NOT behind Cloudflare, every offender is DIRECT, so
# Swatter works as a plain CSF auto-blocker with zero Cloudflare config.

# Is Cloudflare actually fronting this server? If not, all traffic is direct and
# CSF is always the right (and only) plane.
swatter_cf_in_use() {
    [[ "${CF_MODE}" == "off" ]] && return 1
    [[ -s "${CLOUDFLARE_IPS_FILE}" ]] && return 0
    return 1
}

# Build the set of IPs seen hitting the origin DIRECTLY this run, from lfd.log:
# connections logged against cPanel service ports (2082/2083/2086/2087/2095/2096
# /2077/2078) or raw web ports by IP are not proxied by Cloudflare. Cached in a
# temp file path stored in SWATTER_DIRECT_SET.
#
# Only lines inside the scoring window count. Stale lfd history must not grant
# "direct" evidence: a customer who once touched a cPanel port would otherwise
# be CSF-denied (mail/cPanel lockout) for an offense that arrived via the proxy.
swatter_build_direct_set() {
    local out; out="$(mktemp "${TMPDIR:-/tmp}/swatter-direct.XXXXXX")"
    SWATTER_DIRECT_SET="$out"
    export SWATTER_DIRECT_SET
    [[ -n "${LFD_LOG}" && -r "${LFD_LOG}" ]] || return 0
    # lfd lines vary, but the offending IP and dport are present on connection
    # tracking / port-scan lines. Pull any IPv4 that appears with a cPanel port.
    local now cutoff
    now="$(swatter_now)"; cutoff=$(( now - WINDOW_SECONDS ))
    gawk -v cutoff="$cutoff" -v now="$now" '
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
        }' "${LFD_LOG}" 2>/dev/null \
        | grep -aoE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u > "$out" 2>/dev/null || true
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
