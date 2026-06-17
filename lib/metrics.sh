#!/usr/bin/env bash
# lib/metrics.sh — node_exporter textfile-collector exposition for Swatter.
#
# swatter_metrics_emit  -> prints the .prom text to stdout.
# swatter_metrics_write -> atomically writes it to $METRICS_FILE (or $1).
# Best-effort: never fails the scan; a missing/unwritable dir warns once + skips.

_metric_feed_age() {  # <feed_file> -> seconds since mtime, or -1
    local f="$1" now mtime
    [[ -f "$f" ]] || { echo "-1"; return; }
    now="$(swatter_now)"; mtime="$(stat_mtime "$f" 2>/dev/null || echo 0)"
    echo $(( now - mtime ))
}

swatter_metrics_emit() {
    local now; now="$(swatter_now)"
    local counts t p; counts="$(swatter_store_counts 2>/dev/null)"
    t="$(printf '%s' "$counts" | cut -f1)"; p="$(printf '%s' "$counts" | cut -f2)"
    [[ "$t" =~ ^[0-9]+$ ]] || t=0; [[ "$p" =~ ^[0-9]+$ ]] || p=0
    local failed=0; declare -F swatter_failclosed_active >/dev/null && { swatter_failclosed_active && failed=1; }

    printf '# HELP swatter_build_info Swatter version.\n# TYPE swatter_build_info gauge\n'
    printf 'swatter_build_info{version="%s"} 1\n' "${SWATTER_VERSION:-unknown}"
    printf '# HELP swatter_mode Active mode.\n# TYPE swatter_mode gauge\n'
    printf 'swatter_mode{mode="%s"} 1\n' "${SWATTER_MODE:-report}"
    printf '# HELP swatter_scan_timestamp_seconds Last scan completion (unix).\n# TYPE swatter_scan_timestamp_seconds gauge\n'
    printf 'swatter_scan_timestamp_seconds %s\n' "$now"
    printf '# HELP swatter_scan_watched IPs over WATCH last run.\n# TYPE swatter_scan_watched gauge\n'
    printf 'swatter_scan_watched %s\n' "${SWATTER_RUN_WATCHED:-0}"
    printf '# HELP swatter_scan_acted Blocks issued last run.\n# TYPE swatter_scan_acted gauge\n'
    printf 'swatter_scan_acted %s\n' "${SWATTER_RUN_ACTED:-0}"
    printf '# HELP swatter_circuit_breaker_tripped 1 if the breaker tripped last run.\n# TYPE swatter_circuit_breaker_tripped gauge\n'
    printf 'swatter_circuit_breaker_tripped %s\n' "${SWATTER_RUN_BREAKER:-0}"
    printf '# HELP swatter_failclosed 1 if CSF denies are disabled (allowlist unhealthy).\n# TYPE swatter_failclosed gauge\n'
    printf 'swatter_failclosed %s\n' "$failed"
    printf '# HELP swatter_offenders Current offenders by state.\n# TYPE swatter_offenders gauge\n'
    printf 'swatter_offenders{state="temp"} %s\n' "$t"
    printf 'swatter_offenders{state="perm"} %s\n' "$p"
    printf '# HELP swatter_feed_age_seconds Age of an intel/range feed file.\n# TYPE swatter_feed_age_seconds gauge\n'
    printf 'swatter_feed_age_seconds{feed="cloudflare"} %s\n' "$(_metric_feed_age "${CLOUDFLARE_IPS_FILE:-/etc/swatter/cloudflare.cidr}")"
    printf 'swatter_feed_age_seconds{feed="ipsum"} %s\n'      "$(_metric_feed_age "${STATE_DIR}/feeds/ipsum.txt")"
    printf 'swatter_feed_age_seconds{feed="spamhaus"} %s\n'   "$(_metric_feed_age "${STATE_DIR}/feeds/spamhaus.cidr")"
    local qf used
    for prov in abuseipdb greynoise; do
        qf="${STATE_DIR}/feeds/${prov}.quota.$(date -u +%Y%m%d)"
        used="$(cat "$qf" 2>/dev/null || echo 0)"; [[ "$used" =~ ^[0-9]+$ ]] || used=0
        printf '# TYPE swatter_intel_quota_used gauge\nswatter_intel_quota_used{provider="%s"} %s\n' "$prov" "$used"
    done
}

_SW_METRICS_WARNED=0
swatter_metrics_write() {
    local target="${1:-${METRICS_FILE:-}}"
    [[ -n "$target" ]] || return 0
    local dir; dir="$(dirname "$target")"
    if [[ ! -d "$dir" || ! -w "$dir" ]]; then
        (( _SW_METRICS_WARNED == 0 )) && { log_warn "metrics: ${dir} missing or unwritable; skipping"; _SW_METRICS_WARNED=1; }
        return 0
    fi
    local tmp; tmp="$(mktemp "${dir}/.swatter-metrics.XXXXXX")" || return 0
    swatter_metrics_emit > "$tmp" 2>/dev/null && mv -f "$tmp" "$target" 2>/dev/null || rm -f "$tmp" 2>/dev/null
}
