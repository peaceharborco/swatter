#!/usr/bin/env bash
# providers/ipsum.sh — IPsum threat list (no API key).
#
# https://github.com/stamparm/ipsum — a daily-aggregated list of malicious IPs
# with a "level" = number of blacklists the IP appears on. We map level -> score
# (min(100, level*15)). The list is downloaded by `swatter refresh-feeds` into
# $STATE_DIR/feeds/ipsum.txt (format: "IP<tab>level"); lookup is a grep.

IPSUM_FEED_URL="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

# Called by refresh-feeds.
provider_ipsum_refresh() {
    local out="${STATE_DIR}/feeds/ipsum.txt"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "ipsum refresh needs curl"; return 1; }
    # -s guard mirrors listfeeds.sh: an empty 200 body must not clobber a
    # populated feed with nothing.
    if curl --max-time 30 -fsS "${IPSUM_FEED_URL}" -o "${out}.tmp" 2>/dev/null && [[ -s "${out}.tmp" ]]; then
        mv "${out}.tmp" "$out"
        log_info "ipsum feed refreshed ($(wc -l < "$out" 2>/dev/null) entries)"
    else
        rm -f "${out}.tmp" 2>/dev/null
        log_warn "ipsum feed download failed or empty"; return 1
    fi
}

provider_ipsum() {
    local ip="$1" feed="${STATE_DIR}/feeds/ipsum.txt" level
    [[ -f "$feed" ]] || return 1
    level="$(awk -v ip="$ip" '$1==ip{print $2; exit}' "$feed" 2>/dev/null)"
    [[ -n "$level" ]] || { return 1; }
    local score=$(( level * 15 )); (( score > 100 )) && score=100
    printf '%s\t%s\tlevel%s\n' "$score" "$INTEL_CACHE_TTL" "$level"
}
