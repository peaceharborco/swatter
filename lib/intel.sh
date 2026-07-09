#!/usr/bin/env bash
# lib/intel.sh — pluggable threat-intel reputation, cached and quota-limited.
#
# Each provider is a function provider_<name> "$ip" that prints
#   score_0_100 \t ttl_seconds \t label [\t verdict]
# on success (exit 0) or exits non-zero for "no data". verdict is optional;
# omit it (3-field output) for legacy providers — an empty cut -f4 is valid.
# verdict ∈ "" | "suppress" (suppress = known-good soft-allowlist exemption).
# intel.sh dispatches the configured INTEL_PROVIDERS in order, caches results
# under $STATE_DIR/intel/<provider>/<ip>, and returns the MAX malicious score
# seen plus a suppress_flag.
#
# Hard rules:
#   - Only ever called for IPs already past WATCH (don't spend quota on benign).
#   - Never blocks because a lookup failed; absence of data == score 0.
#   - List feeds (ipsum, spamhaus) are refreshed by `swatter refresh-feeds`, not
#     per IP, so they cost nothing at scan time.

# shellcheck source=providers/ipsum.sh
# (providers are sourced lazily in swatter_intel_init)

# Provider exit code that signals a TRANSIENT failure (quota exhausted, transport
# error, timeout) as distinct from an authoritative "no record" (any other
# non-zero exit). A transient failure must NOT poison the durable no-data cache
# for the whole INTEL_CACHE_TTL — it gets a short negative TTL so the next scan
# retries soon instead of being blind to the provider for a full cache cycle.
INTEL_RC_TEMPFAIL="${INTEL_RC_TEMPFAIL:-75}"   # sysexits EX_TEMPFAIL
INTEL_FAIL_TTL="${INTEL_FAIL_TTL:-300}"        # negative-cache TTL after a tempfail

swatter_intel_init() {
    # Aggregate provider files define multiple named providers (registry feeds);
    # source them first so per-name resolution can find them.
    local agg
    for agg in listfeeds; do
        local af="${SWATTER_LIB_DIR}/providers/${agg}.sh"
        # shellcheck disable=SC1090
        [[ -f "$af" ]] && source "$af"
    done
    local p
    for p in ${INTEL_PROVIDERS}; do
        local f="${SWATTER_LIB_DIR}/providers/${p}.sh"
        if [[ -f "$f" ]]; then
            # shellcheck disable=SC1090
            source "$f"
        elif declare -F "provider_${p}" >/dev/null; then
            :   # already defined by an aggregate (e.g. listfeeds)
        else
            log_warn "intel provider not found: ${p} (${f})"
        fi
    done
    SWATTER_INTEL_QUOTA_USED=0
}

# Refresh every list feed: call provider_<p>_refresh for each configured provider
# that defines one (per-IP providers define none and are skipped). Partial
# failures warn (stale lists still score); ALL refresh-capable feeds failing
# returns 1 so refresh-feeds cron can alert instead of reporting exit 0.
swatter_intel_refresh_all() {
    local p tried=0 failed=0
    for p in ${INTEL_PROVIDERS}; do
        if declare -F "provider_${p}_refresh" >/dev/null; then
            tried=$(( tried + 1 ))
            provider_"${p}"_refresh || failed=$(( failed + 1 ))
        fi
    done
    if (( failed > 0 )); then
        log_warn "intel refresh: ${failed}/${tried} feed(s) failed (stale lists remain in use)"
        (( failed == tried )) && return 1
    fi
    return 0
}

# Has intel at all? (used to decide whether to fold W_REPUTATION into the score)
swatter_intel_available() {
    [[ -n "${INTEL_PROVIDERS// }" ]]
}

# Sanitize an attacker/MITM-influenceable provider label to a single clean token:
# strip CR/LF (would split the TSV score contract + decisions.jsonl), tabs (would
# mis-split our own 3-field output), and backslashes (would corrupt the hand-built
# audit JSON, whose escaper only handles quotes). Bounded to 80 chars.
_intel_clean() {
    local s="${1:-}"
    # Explicit single-char substitutions (a combined bracket class mixing these
    # plus a backslash before ']' parses ambiguously across bash versions):
    s="${s//\\/}"          # drop backslashes (would corrupt hand-built JSON)
    s="${s//\"/}"          # drop double-quotes (would break a JSON string value)
    s="${s//$'\t'/ }"      # tab -> space (would mis-split the 3-field TSV)
    s="${s//$'\r'/ }"
    s="${s//$'\n'/ }"      # CR/LF -> space (would split the record)
    s="${s//[[:cntrl:]]/}" # strip any remaining control chars
    printf '%s' "${s:0:80}"
}

_intel_cache_get() {
    # $1=provider $2=ip ; echoes "score\tlabel\tverdict" if fresh, else nothing.
    # verdict field may be empty (3-field legacy cache files are still valid).
    local prov="$1" ip="$2"
    local f="${STATE_DIR}/intel/${prov}/${ip}"
    [[ -f "$f" ]] || return 1
    local now mtime age ttl
    now="$(swatter_now)"; mtime="$(stat_mtime "$f" 2>/dev/null || echo 0)"
    age=$(( now - mtime ))
    # Per-entry TTL (4th field) governs freshness — a short negative TTL after a
    # transient failure expires long before a durable no-data entry. Legacy
    # 3-field files and any non-numeric value fall back to the global TTL.
    ttl="$(awk -F'\t' 'NF{print $4; exit}' "$f" 2>/dev/null)"
    [[ "$ttl" =~ ^[0-9]+$ ]] || ttl="$INTEL_CACHE_TTL"
    (( age < ttl )) || return 1
    cat "$f" 2>/dev/null
}

_intel_cache_put() {
    local prov="$1" ip="$2" score="$3" label="$4" verdict="${5:-}" ttl="${6:-}"
    local d="${STATE_DIR}/intel/${prov}"
    mkdir -p "$d" 2>/dev/null || return 0
    printf '%s\t%s\t%s\t%s\n' "$score" "$label" "$verdict" "$ttl" > "${d}/${ip}" 2>/dev/null || true
}

# First NON-blank line of a provider/cache payload. Dropping injected TRAILING
# lines (a hostile label carrying a newline) AND skipping a LEADING blank/CRLF
# line (a MITM/proxy prepending whitespace, which would otherwise zero the score).
_intel_firstline() { printf '%s' "${1:-}" | awk 'NF{print; exit}'; }

# swatter_intel_score <ip> : echoes "best_score \t best_label \t suppress_flag".
# suppress_flag is 1 when any provider returned verdict "suppress"; else 0.
# score 0 means no malicious signal (or no data).
swatter_intel_score() {
    local ip="$1" best=0 bestlabel="" suppress=0
    local prov out cached score ttl label verdict line rc
    for prov in ${INTEL_PROVIDERS}; do
        if cached="$(_intel_cache_get "$prov" "$ip")"; then
            line="$(_intel_firstline "$cached")"
            score="$(printf '%s' "$line" | cut -f1)"
            # A corrupt/hostile cache file must not carry a non-numeric score
            # into the arithmetic below (the live path guards the same way).
            [[ "$score" =~ ^[0-9]+$ ]] || score=0
            label="$(_intel_clean "$(printf '%s' "$line" | cut -f2)")"
            verdict="$(_intel_clean "$(printf '%s' "$line" | cut -f3)")"
        else
            if ! declare -F "provider_${prov}" >/dev/null; then continue; fi
            if out="$(provider_"${prov}" "$ip" 2>/dev/null)"; then
                # Parse ONLY the first non-blank line: a provider whose label
                # carries a newline (hostile/MITM API field) must not leak extra
                # lines into the score contract or the cache, and a leading blank
                # must not swallow the real score line.
                out="$(_intel_firstline "$out")"
                score="$(printf '%s' "$out" | cut -f1)"
                ttl="$(printf '%s' "$out" | cut -f2)"
                label="$(_intel_clean "$(printf '%s' "$out" | cut -f3)")"
                verdict="$(_intel_clean "$(printf '%s' "$out" | cut -f4)")"
                [[ "$score" =~ ^[0-9]+$ ]] || score=0
                # Honor the provider's TTL for this entry; fall back to the
                # global cache TTL when absent or non-numeric.
                [[ "$ttl" =~ ^[0-9]+$ ]] || ttl="$INTEL_CACHE_TTL"
                _intel_cache_put "$prov" "$ip" "$score" "$label" "$verdict" "$ttl"
            else
                rc=$?
                score=0; label=""; verdict=""
                if (( rc == INTEL_RC_TEMPFAIL )); then
                    # Transient failure (quota/transport): short negative TTL so
                    # the next scan retries — do NOT suppress this provider for a
                    # full INTEL_CACHE_TTL over a temporary outage.
                    _intel_cache_put "$prov" "$ip" 0 "tempfail" "" "$INTEL_FAIL_TTL"
                else
                    # Authoritative no-record: durable no-data cache.
                    _intel_cache_put "$prov" "$ip" 0 "nodata" "" "$INTEL_CACHE_TTL"
                fi
            fi
        fi
        [[ "$verdict" == "suppress" ]] && { suppress=1; [[ -z "$bestlabel" ]] && bestlabel="${prov}:${label}"; }
        if (( score > best )); then best="$score"; bestlabel="${prov}:${label}"; fi
    done
    printf '%s\t%s\t%s\n' "$best" "$bestlabel" "$suppress"
}
