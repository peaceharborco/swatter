#!/usr/bin/env bash
# lib/report_abuseipdb.sh — opt-in outbound reporting to AbuseIPDB.
#
# After a CONFIRMED block (enforce mode only), optionally report the offender to
# AbuseIPDB so the wider community benefits. Gated on SWATTER_MODE=enforce +
# ABUSEIPDB_REPORT=true + ABUSEIPDB_KEY (off by default — it publishes data
# externally). In report/dry-run mode the function no-ops so no POST is made and
# no dedup marker is written. Best-effort and NON-BLOCKING: the dedup marker is
# written synchronously, then the POST runs in the background with a bounded
# timeout, so a slow endpoint never delays the scan. Deduped per IP within
# ABUSEIPDB_REPORT_TTL.

ABUSEIPDB_REPORT_URL="https://api.abuseipdb.com/api/v2/report"

# decisive_rule -> AbuseIPDB category codes.
_abuseipdb_categories() {
    case "$1" in
        honeypot)                          echo "21,19" ;;  # Web App Attack, Bad Web Bot
        high_badpath_repeat)               echo "18,21" ;;  # Brute-Force, Web App Attack
        critical_badpath|scanner_profile)  echo "21,14" ;;  # Web App Attack, Port Scan
        request_flood)                     echo "4"     ;;  # DDoS Attack
        # srcset_flood is WATCH-ONLY: score.sh caps it below SCORE_TEMP and
        # skips persist accrual, so it cannot reach a perm and cannot reach
        # this map. Listed so that stays deliberate: if it is ever promoted
        # to an actionable rule, 4 (DDoS) is the category, NOT the 21 (Web
        # App Attack) default -- this shape is volume, not an exploit
        # attempt, and the population behind it is residential.
        srcset_flood|403ex_flood)          echo "4"     ;;  # DDoS Attack (watch-only)
        *)                                 echo "21"    ;;  # Web App Attack
    esac
}

# swatter_abuseipdb_report <ip> <evidence_json> <reason>
# Only fires in enforce mode — after a CONFIRMED block. In report/dry-run mode
# no block was actually made, so we must not publish data externally or write
# a dedup marker that would suppress a future (real) report.
swatter_abuseipdb_report() {
    local ip="$1" ev="$2" reason="$3"
    [[ "${SWATTER_MODE:-report}" == "enforce" ]] || return 0   # never report on a block we didn't actually make
    [[ "${ABUSEIPDB_REPORT:-false}" == "true" ]] || return 0
    [[ -n "${ABUSEIPDB_KEY:-}" && "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0

    local marker="${STATE_DIR}/reported/${ip}" now mtime age
    mkdir -p "${STATE_DIR}/reported" 2>/dev/null
    if [[ -f "$marker" ]]; then
        now="$(swatter_now)"; mtime="$(stat_mtime "$marker" 2>/dev/null || echo 0)"; age=$(( now - mtime ))
        (( age < ${ABUSEIPDB_REPORT_TTL:-900} )) && return 0
    fi
    : > "$marker" 2>/dev/null   # synchronous dedup marker BEFORE backgrounding

    local rule cats comment
    rule="$(printf '%s' "$ev" | sed -n 's/.*"decisive_rule":"\([^"]*\)".*/\1/p')"
    cats="$(_abuseipdb_categories "$rule")"
    comment="Swatter: ${reason}"   # short, no log contents / PII
    # API key via -K config file, never argv (visible in `ps` on a shared box).
    # Created synchronously; the background subshell removes it after the POST.
    local cfg
    cfg="$(swatter_curl_cfg "header = \"Key: ${ABUSEIPDB_KEY}\"")" || { rm -f "$marker"; return 0; }
    # On failure: log the cause and REMOVE the dedup marker so the next confirmed
    # block retries — a revoked key must not silently mute reporting per-IP for
    # the whole TTL with zero operator visibility.
    ( _abuse_err="$(curl --max-time 5 -fsS -X POST "${ABUSEIPDB_REPORT_URL}" \
        -K "$cfg" -H "Accept: application/json" \
        --data-urlencode "ip=${ip}" --data-urlencode "categories=${cats}" \
        --data-urlencode "comment=${comment}" 2>&1 >/dev/null)" || {
          rm -f "$marker" 2>/dev/null
          log_warn "abuseipdb report ${ip} failed${_abuse_err:+: $(printf '%s' "${_abuse_err//${ABUSEIPDB_KEY}/***}" | tr '\n' ' ' | cut -c1-160)} (marker cleared for retry)"
      }
      rm -f "$cfg" ) &
    return 0
}
