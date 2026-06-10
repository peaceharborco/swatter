#!/usr/bin/env bash
# lib/allowlist.sh — the never-block set, checked LAST before every block.
#
# An IP in any of these categories is never blocked, on either plane:
#   - Cloudflare ranges (so we can never firewall the proxy = outage)
#   - live csf.allow entries
#   - the server's own IPs, loopback, RFC1918
#   - operator IPs (config) and monitoring ranges (file)
#   - forward-confirmed good crawlers (Googlebot/Bingbot/etc.)
#
# CIDR membership is computed in awk over 32-bit integers (IPv4). IPv6 is matched
# by hardcoded Cloudflare v6 prefixes and exact string fallback; v6 attacker
# blocking is conservative by design (prefer Cloudflare-plane handling).

# Convert dotted-quad to uint32. Echoes nothing on parse failure.
_ip2int() {
    local a b c d IFS=.
    read -r a b c d <<<"$1"
    [[ "$a$b$c$d" =~ ^[0-9]+$ ]] || return 1
    (( a<256 && b<256 && c<256 && d<256 )) || return 1
    printf '%u' "$(( (a<<24) + (b<<16) + (c<<8) + d ))"
}

# _ip_in_cidr_file <ip> <file> : 0 if ip falls in any CIDR/IP line of file.
# Comments (#) and blanks ignored. Handles bare IPs and a.b.c.d/len.
_ip_in_cidr_file() {
    local ip="$1" file="$2" ipint
    [[ -f "$file" ]] || return 1
    # IPv6: substring/prefix match only (no integer math here).
    if [[ "$ip" == *:* ]]; then
        local pfx
        while IFS= read -r pfx; do
            pfx="${pfx%%#*}"; pfx="${pfx//[[:space:]]/}"
            [[ -z "$pfx" ]] && continue
            [[ "$pfx" != *:* ]] && continue
            # match on the network portion before '::' or '/'
            local base="${pfx%%/*}"; base="${base%%::*}"
            [[ -n "$base" && "$ip" == "$base"* ]] && return 0
        done < "$file"
        return 1
    fi
    ipint="$(_ip2int "$ip")" || return 1
    # Compare network portions by integer division: two addresses share a /len
    # network iff floor(addr / 2^(32-len)) is equal.
    awk -v ipint="$ipint" '
        /^[[:space:]]*#/ { next }
        { sub(/#.*/, ""); gsub(/[[:space:]]/, "") }
        $0 == "" { next }
        $0 ~ /:/ { next }                       # skip IPv6 lines here
        {
            n = split($0, p, "/")
            split(p[1], o, ".")
            if (o[1]=="" || o[4]=="") next
            base = (o[1]*16777216) + (o[2]*65536) + (o[3]*256) + o[4]
            len = (n >= 2) ? p[2]+0 : 32
            if (len < 0 || len > 32) next
            if (len == 0) { found=1; exit }
            div = 2 ^ (32 - len)
            if (int(base/div) == int(ipint/div)) { found=1; exit }
        }
        END { exit (found ? 0 : 1) }
    ' "$file"
}

# Build the list of server-local IPs once per run (cached in a global).
_swatter_self_ips() {
    [[ -n "${SWATTER_SELF_IPS:-}" ]] && { printf '%s\n' "${SWATTER_SELF_IPS}"; return; }
    local ips
    ips="$(ip -o addr show 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="inet"||$i=="inet6"){split($(i+1),a,"/"); print a[1]}}')"
    SWATTER_SELF_IPS="$ips"
    printf '%s\n' "$ips"
}

# Parse csf.allow into a temp CIDR file once per run.
_swatter_csf_allow_file() {
    [[ -n "${SWATTER_CSF_ALLOW_FILE:-}" && -f "${SWATTER_CSF_ALLOW_FILE}" ]] && { printf '%s' "${SWATTER_CSF_ALLOW_FILE}"; return; }
    local out; out="$(mktemp "${TMPDIR:-/tmp}/swatter-csfallow.XXXXXX")"
    if [[ -f /etc/csf/csf.allow ]]; then
        # csf.allow lines may be "1.2.3.4 # comment" or "tcp|in|...|1.2.3.4"; pull
        # the leading IP/CIDR token only.
        awk '!/^[[:space:]]*#/ {
            line=$1
            if (line ~ /\|/) { n=split(line,f,"|"); line=f[n] }
            if (line ~ /^[0-9]/ || line ~ /:/) print line
        }' /etc/csf/csf.allow > "$out" 2>/dev/null
    fi
    SWATTER_CSF_ALLOW_FILE="$out"
    printf '%s' "$out"
}

# Forward-confirmed reverse DNS for good crawlers. PTR alone is forgeable, so we
# also resolve the PTR name forward and require it to contain the original IP.
# Cached under $STATE_DIR/intel/crawler/<ip>.
_swatter_is_good_crawler() {
    local ip="$1"
    [[ "${VERIFY_GOOD_CRAWLERS}" == "true" ]] || return 1
    have host || have dig || return 1

    local cache="${STATE_DIR}/intel/crawler/${ip}"
    if [[ -f "$cache" ]]; then
        local age now mtime
        now="$(swatter_now)"; mtime="$(stat_mtime "$cache" 2>/dev/null || echo 0)"
        age=$(( now - mtime ))
        if (( age < 604800 )); then   # 7d TTL
            [[ "$(cat "$cache" 2>/dev/null)" == "yes" ]] && return 0 || return 1
        fi
    fi

    local ptr verdict="no"
    if have host; then
        ptr="$(host "$ip" 2>/dev/null | awk '/pointer|domain name pointer/{print $NF; exit}' | sed 's/\.$//')"
    else
        ptr="$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')"
    fi
    # ONLY crawler-specific hostnames — NOT generic cloud PTRs. googleusercontent.com
    # (GCP customer VMs), amazonaws.com, etc. are attacker-rentable and must never
    # match. Real crawlers live under dedicated crawl domains.
    if [[ "$ptr" =~ \.(googlebot\.com|google\.com|search\.msn\.com|applebot\.apple\.com|duckduckgo\.com|crawl\.yahoo\.net|yandex\.(com|ru|net))$ ]]; then
        # Forward-confirm.
        local fwd
        if have host; then fwd="$(host "$ptr" 2>/dev/null | awk '/has address|has IPv6/{print $NF}')"
        else fwd="$(dig +short "$ptr" 2>/dev/null)"; fi
        if grep -qxF "$ip" <<<"$fwd"; then verdict="yes"; fi
    fi
    mkdir -p "${STATE_DIR}/intel/crawler" 2>/dev/null || true
    printf '%s' "$verdict" > "$cache" 2>/dev/null || true
    [[ "$verdict" == "yes" ]]
}

# swatter_is_never_block <ip> : returns 0 (never block) with a reason on stdout,
# or 1 (blockable).
swatter_is_never_block() {
    local ip="$1"

    # Loopback / RFC1918 / link-local (never the real internet attacker).
    case "$ip" in
        127.*|10.*|192.168.*|169.254.*|::1|fe80:*) echo "local/private"; return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)    echo "rfc1918";       return 0 ;;
    esac

    # Cloudflare ranges — the catastrophic case. Hardcoded list refreshed by
    # refresh-feeds; if the file is missing/stale the caller fails closed.
    if _ip_in_cidr_file "$ip" "${CLOUDFLARE_IPS_FILE}"; then echo "cloudflare-range"; return 0; fi

    # Operator IPs (inline list -> temp file membership for CIDR support).
    if [[ -n "${OPERATOR_IPS}" ]]; then
        local of; of="$(mktemp "${TMPDIR:-/tmp}/swatter-op.XXXXXX")"
        printf '%s\n' ${OPERATOR_IPS} > "$of"
        if _ip_in_cidr_file "$ip" "$of"; then rm -f "$of"; echo "operator-ip"; return 0; fi
        rm -f "$of"
    fi

    # Monitoring ranges file.
    if _ip_in_cidr_file "$ip" "${MONITORING_RANGES_FILE}"; then echo "monitoring"; return 0; fi

    # csf.allow.
    local caf; caf="$(_swatter_csf_allow_file)"
    if _ip_in_cidr_file "$ip" "$caf"; then echo "csf.allow"; return 0; fi

    # Server's own IPs.
    if _swatter_self_ips | grep -qxF "$ip"; then echo "server-self"; return 0; fi

    # Forward-confirmed good crawler.
    if _swatter_is_good_crawler "$ip"; then echo "verified-crawler"; return 0; fi

    return 1
}

# swatter_allowlist_healthy : 0 if the Cloudflare range list exists and is fresh
# enough to trust classification. Callers fail closed (no CSF denies) otherwise.
swatter_allowlist_healthy() {
    local f="${CLOUDFLARE_IPS_FILE}"
    [[ -s "$f" ]] || { log_warn "Cloudflare range list missing/empty: $f"; return 1; }
    local now mtime age maxage
    now="$(swatter_now)"; mtime="$(stat_mtime "$f" 2>/dev/null || echo 0)"
    age=$(( now - mtime )); maxage=$(( ALLOWLIST_MAX_AGE_DAYS * 86400 ))
    if (( age > maxage )); then
        log_warn "Cloudflare range list stale ($(( age/86400 ))d > ${ALLOWLIST_MAX_AGE_DAYS}d): $f"
        return 1
    fi
    return 0
}
