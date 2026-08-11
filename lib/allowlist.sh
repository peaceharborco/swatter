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
# CIDR membership is computed in awk over 32-bit integers (IPv4) and in bash
# over expanded 128-bit nibble strings (IPv6) — exact prefix-length matching
# on both families.
#
# A compiled-in Cloudflare range fallback guarantees the never-block set is never
# empty even if `refresh-feeds` has not yet run — the README's safety promise must
# not depend on a network fetch having succeeded. The live file (refreshed daily)
# takes precedence; this is only the floor.
SWATTER_CF_FALLBACK_V4="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
SWATTER_CF_FALLBACK_V6="2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"

# Convert dotted-quad to uint32. Echoes nothing on parse failure.
_ip2int() {
    local a b c d IFS=.
    read -r a b c d <<<"$1"
    [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" ]] || return 1
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
    # Force base-10: a zero-padded octet ("010", "08") must NOT be read as octal,
    # which would silently corrupt CIDR membership incl. the CF never-block check.
    a=$((10#$a)) b=$((10#$b)) c=$((10#$c)) d=$((10#$d))
    (( a<256 && b<256 && c<256 && d<256 )) || return 1
    printf '%u' "$(( (a<<24) + (b<<16) + (c<<8) + d ))"
}

# Expand an IPv6 address to its full 128-bit value as 32 lowercase hex
# nibbles (no colons): handles :: compression and a trailing embedded IPv4
# dotted quad (::ffff:1.2.3.4). Echoes nothing / returns 1 on malformed input.
_ipv6_expand() {
    local a="${1,,}"
    # Embedded IPv4 tail -> two hextets.
    if [[ "$a" == *.* ]]; then
        local v4int
        v4int="$(_ip2int "${a##*:}")" || return 1
        a="$(printf '%s:%x:%x' "${a%:*}" $(( v4int >> 16 )) $(( v4int & 65535 )))"
    fi
    local -a L=() R=()
    local compressed=0
    if [[ "$a" == *::* ]]; then
        [[ "$a" == *::*::* ]] && return 1          # at most one ::
        compressed=1
        IFS=: read -ra L <<<"${a%%::*}"
        IFS=: read -ra R <<<"${a#*::}"
    else
        IFS=: read -ra L <<<"$a"
    fi
    local n=$(( ${#L[@]} + ${#R[@]} ))
    if (( compressed )); then (( n <= 8 )) || return 1
    else (( n == 8 )) || return 1; fi
    local out="" g i
    for g in ${L[@]+"${L[@]}"}; do
        [[ "$g" =~ ^[0-9a-f]{1,4}$ ]] || return 1
        out+="$(printf '%04x' "0x$g")"
    done
    for (( i = n; i < 8; i++ )); do out+="0000"; done
    for g in ${R[@]+"${R[@]}"}; do
        [[ "$g" =~ ^[0-9a-f]{1,4}$ ]] || return 1
        out+="$(printf '%04x' "0x$g")"
    done
    printf '%s' "$out"
}

# _ipv6_in_prefix <ip-nibbles> <net-nibbles> <plen> : exact membership over
# the expanded forms — whole nibbles string-compared, the partial nibble
# masked to its significant bits.
_ipv6_in_prefix() {
    local ipx="$1" netx="$2" plen="$3"
    [[ "$plen" =~ ^[0-9]+$ ]] || return 1
    plen=$(( 10#$plen ))   # "09" must parse as 9, not octal
    (( plen <= 128 )) || return 1
    (( plen == 0 )) && return 0
    local nib=$(( plen / 4 )) rem=$(( plen % 4 ))
    [[ "${ipx:0:nib}" == "${netx:0:nib}" ]] || return 1
    (( rem == 0 )) && return 0
    local mask=$(( (15 << (4 - rem)) & 15 ))
    (( ( 0x${ipx:nib:1} & mask ) == ( 0x${netx:nib:1} & mask ) ))
}

# _ip_in_cidr_file <ip> <file> : 0 if ip falls in any CIDR/IP line of file.
# Comments (#) and blanks ignored. Handles bare IPs and a.b.c.d/len.
_ip_in_cidr_file() {
    local ip="$1" file="$2" ipint
    [[ -f "$file" ]] || return 1
    if [[ "$ip" == *:* ]]; then
        local ipx pfx net plen netx
        ipx="$(_ipv6_expand "$ip")" || return 1
        while IFS= read -r pfx; do
            pfx="${pfx%%#*}"; pfx="${pfx//[[:space:]]/}"
            [[ -z "$pfx" || "$pfx" != *:* ]] && continue
            net="${pfx%%/*}" plen="${pfx##*/}"
            [[ "$plen" == "$pfx" ]] && plen=128
            netx="$(_ipv6_expand "$net")" || continue
            _ipv6_in_prefix "$ipx" "$netx" "$plen" && return 0
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

# _cidr_overlaps_file <ip-or-cidr> <file> : 0 if the TOKEN OVERLAPS any CIDR/IP
# line of the file — i.e. the two share a network at the SHORTER of the two
# prefix lengths, so either contains the other.
#
# _ip_in_cidr_file answers a narrower question: "is this host address inside a
# listed range". That is the wrong question wherever a CIDR token can itself be
# an enforcement target: 104.28.1.1 is inside 104.28.0.0/16, but the token
# 104.28.0.0/16 is not "inside" itself by host-address membership (_ip2int
# rejects a token with a slash), so a policy built on containment alone refuses
# the members of a protected pool while waving the pool itself through. A bare
# address is just a /32 (/128) here, so this is a strict superset of the
# containment test and behaves identically for every host IP.
_cidr_overlaps_file() {
    local tok="$1" file="$2" addr="${1%%/*}" plen="${1#*/}"
    [[ -f "$file" ]] || return 1
    [[ "$plen" == "$tok" ]] && plen=""      # no '/' at all -> single address
    if [[ "$addr" == *:* ]]; then
        local tx pfx net nplen netx m
        tx="$(_ipv6_expand "$addr")" || return 1
        plen="${plen:-128}"
        [[ "$plen" =~ ^[0-9]+$ ]] || return 1
        plen=$(( 10#$plen )); (( plen <= 128 )) || return 1
        while IFS= read -r pfx; do
            pfx="${pfx%%#*}"; pfx="${pfx//[[:space:]]/}"
            [[ -z "$pfx" || "$pfx" != *:* ]] && continue
            net="${pfx%%/*}" nplen="${pfx##*/}"
            [[ "$nplen" == "$pfx" ]] && nplen=128
            [[ "$nplen" =~ ^[0-9]+$ ]] || continue
            nplen=$(( 10#$nplen ))
            netx="$(_ipv6_expand "$net")" || continue
            m=$(( nplen < plen ? nplen : plen ))
            _ipv6_in_prefix "$tx" "$netx" "$m" && return 0
        done < "$file"
        return 1
    fi
    local ipint; ipint="$(_ip2int "$addr")" || return 1
    plen="${plen:-32}"
    [[ "$plen" =~ ^[0-9]+$ ]] || return 1
    plen=$(( 10#$plen )); (( plen <= 32 )) || return 1
    awk -v ipint="$ipint" -v tlen="$plen" '
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
            # Compare only the bits BOTH prefixes actually pin down.
            m = (len < tlen) ? len : tlen
            if (m == 0) { found=1; exit }
            div = 2 ^ (32 - m)
            if (int(base/div) == int(ipint/div)) { found=1; exit }
        }
        END { exit (found ? 0 : 1) }
    ' "$file"
}

# _ip_in_cidr_list <ip> <space-separated CIDRs> : overlap against an inline list.
# Only ever used for the never-block set (the compiled-in CF fallback and
# OPERATOR_IPS), so it uses the same overlap test the file checks there do.
_ip_in_cidr_list() {
    local ip="$1"; shift
    local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/swatter-cidrs.XXXXXX")"
    # shellcheck disable=SC2048,SC2086
    printf '%s\n' $* > "$tmp"
    local rc=1
    _cidr_overlaps_file "$ip" "$tmp" && rc=0
    rm -f "$tmp"
    return $rc
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

    # Hard-bound every resolver call: abusive networks blackhole PTR queries,
    # and a single unanswered lookup otherwise hangs the whole scan under the
    # flock — Swatter stays down until someone kills the stuck pipeline.
    local tmo=()
    have timeout && tmo=(timeout 5)
    local ptr verdict="no" raw rc
    if have host; then
        raw="$("${tmo[@]}" host -W 2 "$ip" 2>/dev/null)"; rc=$?
        ptr="$(awk '/pointer|domain name pointer/{print $NF; exit}' <<<"$raw" | sed 's/\.$//')"
    else
        raw="$("${tmo[@]}" dig +time=2 +tries=1 +short -x "$ip" 2>/dev/null)"; rc=$?
        ptr="$(head -1 <<<"$raw" | sed 's/\.$//')"
    fi
    # A blackholed/timed-out resolver (timeout(1) → 124; host/dig → nonzero) with
    # no answer is a TRANSIENT failure — do NOT cache a negative, or one flaky
    # lookup exposes Googlebot/Bingbot as blockable for the full 7d TTL. Return
    # unverified this run and re-check next time.
    if (( rc != 0 )) && [[ -z "$ptr" ]]; then
        return 1
    fi
    # ONLY crawler-specific hostnames — NOT generic cloud PTRs. googleusercontent.com
    # (GCP customer VMs), amazonaws.com, etc. are attacker-rentable and must never
    # match. Real crawlers live under dedicated crawl domains.
    if [[ "$ptr" =~ \.(googlebot\.com|google\.com|search\.msn\.com|applebot\.apple\.com|duckduckgo\.com|crawl\.yahoo\.net|yandex\.(com|ru|net))$ ]]; then
        # Forward-confirm.
        local fwd fwdrc
        if have host; then fwd="$("${tmo[@]}" host -W 2 "$ptr" 2>/dev/null | awk '/has address|has IPv6/{print $NF}')"; fwdrc=${PIPESTATUS[0]}
        else fwd="$("${tmo[@]}" dig +time=2 +tries=1 +short "$ptr" 2>/dev/null)"; fwdrc=$?; fi
        if grep -qxF "$ip" <<<"$fwd"; then verdict="yes"
        elif (( fwdrc != 0 )) && [[ -z "$fwd" ]]; then
            # Forward leg failed transiently — matched a real crawler PTR but
            # couldn't confirm. Don't cache the false negative; retry next run.
            return 1
        fi
    fi
    mkdir -p "${STATE_DIR}/intel/crawler" 2>/dev/null || true
    printf '%s' "$verdict" > "$cache" 2>/dev/null || true
    [[ "$verdict" == "yes" ]]
}

# swatter_is_never_block <ip> : returns 0 (never block) with a reason on stdout,
# or 1 (blockable).
#
# <ip> may be a CIDR — import-bans, the swarm publish gate and the pending-retry
# replay all pass block TARGETS through here, and a target may be a prefix. Every
# range check below therefore uses _cidr_overlaps_file, not host containment: a
# prefix token makes _ip2int/_ipv6_expand fail, so containment answered "not
# allowlisted" for EVERY prefix, and `swatter import-bans` with a line reading
# 162.158.0.0/15 (a real Cloudflare edge range) would have CSF-denied the proxy —
# the outage this whole file exists to prevent. Overlap is also the right
# semantics on its own terms: banning a prefix that merely touches an allowlisted
# range still bans the allowlisted addresses inside it. Host addresses are
# unaffected — a /32 overlaps a range exactly when it is inside it.
swatter_is_never_block() {
    local ip="$1"

    # IPv4-mapped IPv6 (::ffff:a.b.c.d) is just an IPv4 address wearing a v6 hat;
    # unwrap it to its embedded v4 so the private/loopback/CIDR checks see the
    # real address rather than treating it as an unrecognized v6 attacker.
    local lip="${ip,,}"
    # Both the compact (::ffff:a.b.c.d) and fully-expanded (0:0:0:0:0:ffff:a.b.c.d)
    # notations getent/host can emit map to the same embedded IPv4.
    if [[ "$lip" == ::ffff:*.*.*.* || "$lip" == 0:0:0:0:0:ffff:*.*.*.* ]]; then
        ip="${ip##*:}"; lip="${ip,,}"
    fi

    # Loopback / RFC1918 / link-local / IPv6 unique-local (fc00::/7 = fc/fd) —
    # never the real internet attacker.
    case "$lip" in
        127.*|10.*|192.168.*|169.254.*|::1|fe80:*|fc*:*|fd*:*) echo "local/private"; return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)                echo "rfc1918";       return 0 ;;
    esac

    # Cloudflare ranges — the catastrophic case. Check the live file first, then
    # the compiled-in fallback so a never-refreshed install is still protected.
    if _cidr_overlaps_file "$ip" "${CLOUDFLARE_IPS_FILE}"; then echo "cloudflare-range"; return 0; fi
    if _ip_in_cidr_list "$ip" "${SWATTER_CF_FALLBACK_V4} ${SWATTER_CF_FALLBACK_V6}"; then echo "cloudflare-range(builtin)"; return 0; fi

    # Operator IPs (inline list -> temp file membership for CIDR support).
    if [[ -n "${OPERATOR_IPS}" ]]; then
        local of; of="$(mktemp "${TMPDIR:-/tmp}/swatter-op.XXXXXX")"
        printf '%s\n' ${OPERATOR_IPS} > "$of"
        if _cidr_overlaps_file "$ip" "$of"; then rm -f "$of"; echo "operator-ip"; return 0; fi
        rm -f "$of"
    fi

    # Operator allow file (managed by `swatter allow`).
    if _cidr_overlaps_file "$ip" "${OPERATOR_ALLOW_FILE}"; then echo "operator-allow"; return 0; fi

    # Monitoring ranges file.
    if _cidr_overlaps_file "$ip" "${MONITORING_RANGES_FILE}"; then echo "monitoring"; return 0; fi

    # csf.allow.
    local caf; caf="$(_swatter_csf_allow_file)"
    if _cidr_overlaps_file "$ip" "$caf"; then echo "csf.allow"; return 0; fi

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
