#!/usr/bin/env bash
# providers/listfeeds.sh — data-driven keyless list-feed providers.
#
# One registry row per feed: name -> "url|score|kind" (kind: ip | cidr | dshield).
# Two generic handlers do the work; provider_<name> and provider_<name>_refresh are
# generated per row at source time, so the intel layer dispatches each by name and
# refresh-feeds finds each _refresh. Feeds download (via `swatter refresh-feeds`)
# to $STATE_DIR/feeds/<name>.{txt|cidr}; lookup is a grep (ip) or CIDR match. A hit
# emits "score\tINTEL_CACHE_TTL\tname" (3-field; feeds never suppress).
#
# Confidence tiers: 95 = near-zero-FP (firehol_level1, cins, dshield); 80 = high
# (blocklist_de, et_compromised); 70 = moderate (greensnow). The score bounds how
# hard a feed can push a borderline (already past-WATCH) IP over TEMP.
#
# Bogon note: firehol_level1 includes reserved/bogon ranges by design — safe here,
# since intel only sees IPs past WATCH and the never-block allowlist wins last.

_LISTFEED_NAMES="firehol_level1 cins dshield blocklist_de et_compromised greensnow"

# name -> "url|score|kind"
_listfeed_row() {
    case "$1" in
        firehol_level1) echo 'https://iplists.firehol.org/files/firehol_level1.netset|95|cidr' ;;
        cins)           echo 'https://cinsscore.com/list/ci-badguys.txt|95|ip' ;;
        dshield)        echo 'https://feeds.dshield.org/block.txt|95|dshield' ;;
        blocklist_de)   echo 'https://lists.blocklist.de/lists/all.txt|80|ip' ;;
        et_compromised) echo 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt|80|ip' ;;
        greensnow)      echo 'https://blocklist.greensnow.co/greensnow.txt|70|ip' ;;
        *) return 1 ;;
    esac
}

# ip-kind feeds store one IP per line (.txt); cidr/dshield store CIDRs (.cidr).
_listfeed_file() {
    local ext="cidr"; [[ "$2" == "ip" ]] && ext="txt"
    printf '%s/feeds/%s.%s' "${STATE_DIR}" "$1" "$ext"
}

# _listfeed_refresh <name> : download + parse to the feed file (atomic).
_listfeed_refresh() {
    local name="$1" row url score kind out parse
    row="$(_listfeed_row "$name")" || { log_warn "listfeed unknown: ${name}"; return 1; }
    IFS='|' read -r url score kind <<<"$row"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "${name} refresh needs curl"; return 1; }
    out="$(_listfeed_file "$name" "$kind")"
    case "$kind" in
        ip)      parse='/^[0-9A-Fa-f]/{print $1}' ;;
        cidr)    parse='/^[0-9]/{print $1}' ;;
        dshield) parse='/^[0-9]/ && $3>=0 && $3<=32 {print $1"/"$3}' ;;
    esac
    if curl --max-time 30 -fsS "$url" 2>/dev/null | awk "$parse" > "${out}.tmp" 2>/dev/null && [[ -s "${out}.tmp" ]]; then
        mv "${out}.tmp" "$out"
        log_info "${name} feed refreshed ($(wc -l < "$out" 2>/dev/null | tr -d ' ') entries)"
    else
        rm -f "${out}.tmp" 2>/dev/null; log_warn "${name} feed download failed"; return 1
    fi
}

# _listfeed_lookup <name> <ip> : emit "score\tttl\tname" on hit, else return 1.
_listfeed_lookup() {
    local name="$1" ip="$2" row url score kind feed
    row="$(_listfeed_row "$name")" || return 1
    IFS='|' read -r url score kind <<<"$row"
    feed="$(_listfeed_file "$name" "$kind")"
    [[ -f "$feed" ]] || return 1
    if [[ "$kind" == "ip" ]]; then
        awk -v ip="$ip" '$1==ip{f=1; exit} END{exit !f}' "$feed" 2>/dev/null || return 1
    else
        declare -F _ip_in_cidr_file >/dev/null && _ip_in_cidr_file "$ip" "$feed" || return 1
    fi
    printf '%s\t%s\t%s\n' "$score" "${INTEL_CACHE_TTL}" "$name"
}

# Generate provider_<name> + provider_<name>_refresh for each registry row.
_listfeed_generate() {
    local n
    for n in ${_LISTFEED_NAMES}; do
        eval "provider_${n}()         { _listfeed_lookup ${n} \"\$1\"; }"
        eval "provider_${n}_refresh() { _listfeed_refresh ${n}; }"
    done
}
_listfeed_generate
