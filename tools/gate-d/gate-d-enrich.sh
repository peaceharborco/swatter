#!/usr/bin/env bash
# gate-d-enrich.sh — enrich a `swatter escalate-preview` list and sort it into
# the three gate D review buckets.
#
# Rewritten 2026-08-20 after both grok-4.6 and grok-4.5 returned HOLD on the
# first draft (5 Blockers). See
# docs/superpowers/specs/2026-08-20-gate-d-enrich-review-grok.md — every design
# choice below that looks fussy is a Blocker that review found.
#
# READ-ONLY against swatter state: it never writes under $STATE_DIR and never
# changes a ban, an allowlist or a config. Its own output goes under --out. It is
# NOT literally "writes only inside --out" — an earlier version of this header
# claimed that and was wrong: the sourced never-block helpers plant short-lived
# mktemps under $TMPDIR (_ip_in_cidr_list, _swatter_csf_allow_file, and the
# OPERATOR_IPS overlay). The csf.allow one is cleaned by the EXIT trap; the
# others are per-call and removed inline. In particular it deliberately does
# NOT call swatter_is_never_block or swatter_asn_resolve, because those write
# per-IP cache files under $STATE_DIR (lib/allowlist.sh:283-284, lib/asn.sh:44)
# — ~1000 writes as root racing the */5 scan, and a missed forward-confirm
# caches "no" for a crawler for 7 days, which would make Googlebot blockable.
# CIDR/IPv6 matching is still swatter's own `_cidr_overlaps_file`; only the
# COMPOSITION is done here.
#
# House convention: `set -uo pipefail` WITHOUT -e. A failing command does not
# abort the run, so every helper returns a usable value on failure.
#
# ---------------------------------------------------------------------------
# THE ONE INVARIANT: the sort fails toward bucket 3 (human review).
#
#   1 inert   — operator-allowlisted, private, or shared-egress capped. Cannot
#               perm. Count, do not review.
#   2 hostile — hard external intel AND nothing served AND no UA on ANY request.
#               Not read row-by-row; only a 25-30 row sample is audited.
#   3 human   — everything else, AND anything we could not fully evidence:
#               an unparseable log line, a partial domlog read, a failed ASN
#               lookup, an invalid candidate, a request_flood history.
#
# Note the fail direction is INVERTED relative to the enforcer on purpose.
# swatter_is_shared_egress fails OPEN (lib/asn.sh:131-132) so DNS cannot become
# an availability lever on the ladder — right for banning, backwards for
# classifying. Here "could not tell" means a human looks.
# ---------------------------------------------------------------------------

set -uo pipefail
umask 0077                      # BEFORE anything is created; the closing chmod
                                # in the first draft left files 0644 for the
                                # whole multi-minute run.

# swatter's own helpers use ${var,,} (lib/allowlist.sh:39), which is bash 4+.
# Under bash 3.2 (macOS /bin/bash) that is a "bad substitution" error, and
# because we run without -e the function limps on with an empty value — which
# would quietly weaken _inert_reason's private/loopback match. Fail loudly
# instead. Found the hard way: an early smoke test of this script ran under 3.2
# and silently skipped every lowercase path.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "gate-d-enrich: needs bash 4+ (found ${BASH_VERSION}); swatter's helpers use \${var,,}" >&2
    exit 1
fi

PREVIEW="" OUT="" DOMLOGS_GLOB_ARG="" LIBDIR="" CONF="" SAMPLE_SEED=""

die()  { echo "gate-d-enrich: $*" >&2; exit 1; }
note() { echo "gate-d-enrich: $*" >&2; }

usage() {
    cat >&2 <<'EOF'
usage: gate-d-enrich.sh --preview FILE [--out DIR] [--domlogs GLOB]
                        [--libdir DIR] [--conf FILE] [--seed N]

  --preview FILE   output of `swatter escalate-preview --window N` (required)
  --out DIR        where the round's files land (default: a sibling of the
                   preview named enrich-<preview base>)
  --domlogs GLOB   override DOMLOGS_GLOB from the swatter config
  --libdir DIR     swatter lib dir (default: ../lib, then /usr/local/lib/swatter)
  --conf FILE      swatter config file (exported as SWATTER_CONF and LOADED)
  --seed N         integer seed for the bucket-2 audit sample (default 1)
EOF
    exit 2
}

while (( $# )); do
    case "$1" in
        --preview) PREVIEW="${2:-}"; shift 2 || usage ;;
        --out)     OUT="${2:-}"; shift 2 || usage ;;
        --domlogs) DOMLOGS_GLOB_ARG="${2:-}"; shift 2 || usage ;;
        --libdir)  LIBDIR="${2:-}"; shift 2 || usage ;;
        --conf)    CONF="${2:-}"; shift 2 || usage ;;
        --seed)    SAMPLE_SEED="${2:-}"; shift 2 || usage ;;
        -h|--help) usage ;;
        *) die "unknown option '$1' (try --help)" ;;
    esac
done

[[ -n "$PREVIEW" ]] || usage
[[ -f "$PREVIEW" ]] || die "preview not readable: ${PREVIEW}"

# Numeric-knob validation, house idiom. A non-numeric string in an arithmetic
# context re-resolves as a variable NAME and aborts under `set -u`. Note the
# default is applied to the VARIABLE, not just to the case subject — the first
# draft tested "${SAMPLE_SEED:-1}" and then expanded the still-empty variable.
SAMPLE_SEED="${SAMPLE_SEED:-1}"
case "$SAMPLE_SEED" in
    ''|*[!0-9]*|??????*) note "invalid --seed '${SAMPLE_SEED}', using 1"; SAMPLE_SEED=1 ;;
    *) SAMPLE_SEED=$(( 10#$SAMPLE_SEED )) ;;
esac

# ---------------------------------------------------------------- swatter libs
# Repo layout first, matching bin/swatter:49-52. The first draft inverted this.
if [[ -z "$LIBDIR" ]]; then
    _self_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${_self_dir}/../lib/common.sh" ]]; then
        LIBDIR="$(cd -- "${_self_dir}/../lib" && pwd)"
    elif [[ -f /usr/local/lib/swatter/common.sh ]]; then
        LIBDIR=/usr/local/lib/swatter
    fi
fi
[[ -n "$LIBDIR" && -f "${LIBDIR}/common.sh" ]] || die "cannot locate swatter lib/ (try --libdir)"

if [[ -n "$CONF" ]]; then
    # swatter_load_config sources only when the file exists and never returns
    # non-zero (lib/common.sh:374-377), so `|| die` on it is dead code and a
    # typo'd path silently falls back to compiled defaults.
    [[ -f "$CONF" ]] || die "--conf not readable: ${CONF}"
    export SWATTER_CONF="$CONF"
fi
# shellcheck source=/dev/null
source "${LIBDIR}/common.sh" || die "failed to source common.sh"
# LOAD THE CONFIG. bin/swatter:59-61 does this and the first draft did not, so
# STATE_DIR / DOMLOGS_GLOB / OPERATOR_ALLOW_FILE / SHARED_EGRESS_* were all
# defaults and --conf was a silent no-op.
swatter_load_config || die "swatter_load_config failed"
# Deliberately NOT swatter_check_deps: it exists to arm SWATTER_HAVE_DNS for the
# cache-writing resolvers we are avoiding. We do our own DNS below.
# shellcheck source=/dev/null
source "${LIBDIR}/allowlist.sh" || die "failed to source allowlist.sh"
# asn.sh only ASSIGNS one variable at top level (_SW_SHARED_CIDR_OK); we source
# it for _swatter_shared_egress_cidr_usable, which reads and validates but never
# writes. We still never call swatter_is_shared_egress / swatter_asn_resolve —
# those are the cache writers.
# shellcheck source=/dev/null
source "${LIBDIR}/asn.sh" || die "failed to source asn.sh"

AWK="$(command -v gawk || command -v awk)"
[[ -n "$AWK" ]] || die "no awk found"
[[ "$AWK" == *gawk ]] || note "NOTE: gawk not found, using ${AWK}; ingest parses with gawk (lib/ingest.sh:19)"

DB="${STATE_DIR:-/var/lib/swatter}/swatter.db"
GLOB="${DOMLOGS_GLOB_ARG:-${DOMLOGS_GLOB:-/etc/apache2/logs/domlogs/*}}"
SE_CIDR="${SHARED_EGRESS_CIDR_FILE:-/etc/swatter/shared-egress.cidr}"
SE_ASNS="${SHARED_EGRESS_ASNS_FILE:-/etc/swatter/shared-egress-asns.txt}"

[[ -n "$OUT" ]] || OUT="$(dirname -- "$PREVIEW")/enrich-$(basename -- "$PREVIEW" .tsv)"
mkdir -p -- "$OUT" || die "cannot create --out dir: ${OUT}"
chmod 0700 -- "$OUT" 2>/dev/null
case "$OUT" in
    /tmp/*|/var/tmp/*|/dev/shm/*)
        note "WARNING: --out is under a shared temp path (${OUT}). Output holds"
        note "         customer IP-to-vhost mappings. Prefer /root/gate-d-review/." ;;
esac

# The never-block files get no usability guard from swatter, and _inert_reason
# consults them for every candidate. One over-broad line in allow.cidr or
# monitoring.cidr would mark EVERY row inert — the review would report "1000
# inert, 0 to review" and look like a clean run while having examined nothing.
# Found by the Claude-side sweep, not by either model.
for _nb in "${OPERATOR_ALLOW_FILE:-}" "${MONITORING_RANGES_FILE:-}"; do
    [[ -s "$_nb" ]] || continue
    if ! sed 's/#.*//' "$_nb" \
         | INTEL_FEED_MIN_PREFIX4="${SHARED_EGRESS_MIN_PREFIX4:-16}" \
           INTEL_FEED_MIN_PREFIX6="${SHARED_EGRESS_MIN_PREFIX6:-32}" \
           swatter_intel_cidr_feed_ok 2>/dev/null; then
        die "never-block file ${_nb} contains an invalid or over-broad range. Every
     candidate would be marked inert and the review would silently examine
     nothing. Fix the file before running."
    fi
done

CAND="${OUT}/candidates.tsv"
TRAFFIC="${OUT}/traffic.tsv"
INTEL="${OUT}/intel.tsv"
ENRICHED="${OUT}/enriched.tsv"
BUCKETS="${OUT}/buckets.txt"
DECISIONS="${OUT}/decisions.tsv"

# Invalidate the previous round's published pair BEFORE overwriting any input.
# Otherwise a kill during the multi-minute lookup phase leaves a stale
# enriched.tsv + buckets.txt — still ending in "COMPLETE n/n" — sitting beside
# a brand-new candidates.tsv, and its audit sample reads as authoritative for a
# list it was never computed from.
rm -f -- "$ENRICHED" "$BUCKETS"

# ------------------------------------------------------------ phase 1: parse
"$AWK" -F'\t' 'NF==4 && $1!="ip" && $1!="" { print }' "$PREVIEW" > "$CAND"
n_cand=$(wc -l < "$CAND" | tr -d ' ')
(( n_cand > 0 )) || die "no candidate rows parsed from ${PREVIEW}"
note "parsed ${n_cand} candidates"

# ------------------------------------------------- phase 2: one domlog pass
# ONE pass over every domlog. Errors are NOT swallowed: a file we could not read
# is counted and, if any exist, every row is forced to bucket 3 — a partial read
# looks exactly like "this IP served nothing", which is the bucket-2 predicate.
#
# Parsing mirrors lib/ingest.sh:75-93 rather than using whitespace field
# indices: status is the first 3-digit token AFTER the request quote, and the
# UA is the LAST quote pair, lowercased. `$9` shifts the moment a request path
# contains a space.
# Mirror ingest (lib/ingest.sh:181-182) and hand awk only regular files. A
# cPanel per-user subdirectory inside the glob makes gawk write "is a directory"
# to stderr, which trips the degraded-read guard and collapses the entire sort
# into a ~1000-row human review.
_logfiles=()
# shellcheck disable=SC2086
for _f in $GLOB; do [[ -f "$_f" ]] && _logfiles+=("$_f"); done
# ingest also always reads ACCESS_LOG (lib/ingest.sh:191, default
# lib/common.sh:45). Omitting it meant an IP whose only successful responses
# live in the shared access log read as "served nothing" — bucket-2 eligible on
# incomplete evidence.
[[ -f "${ACCESS_LOG:-}" ]] && _logfiles+=("${ACCESS_LOG}")
(( ${#_logfiles[@]} > 0 )) || die "no readable log files matched ${GLOB} (and no ACCESS_LOG)"
note "scanning ${#_logfiles[@]} domlog files: ${GLOB}"
: > "${OUT}/.scan_err"
# shellcheck disable=SC2086
"$AWK" -v candfile="$CAND" '
    BEGIN {
        while ((getline line < candfile) > 0) {
            split(line, f, "\t"); if (f[1] != "") want[f[1]] = 1
        }
        close(candfile)
    }
    FNR==1 {
        vhost = FILENAME
        sub(/^.*\//, "", vhost)
        # ingest skips byte logs (lib/ingest.sh:185-186); they carry no status
        # or UA and would read as "served nothing, no UA".
        skip = (vhost ~ /-bytes_log$/)
        sub(/-ssl_log$/, "", vhost); sub(/_log$/, "", vhost)
    }
    skip { next }
    {
        ip = $1
        sub(/^::[fF][fF][fF][fF]:/, "", ip)      # ingest unwraps these (lib/ingest.sh:33-34)
        if (!(ip in want)) next
        reqs[ip]++
        vh[ip SUBSEP vhost]++
        if (vhcount[ip] < vh[ip SUBSEP vhost]) { vhcount[ip] = vh[ip SUBSEP vhost]; vhtop[ip] = vhost }

        nq = split($0, q, "\"")
        if (nq < 3) { bad[ip]++; next }        # unparseable -> evidence, not silence

        after = q[3]
        ns = split(after, sp, " ")
        status = ""
        for (k = 1; k <= ns; k++) if (sp[k] ~ /^[0-9][0-9][0-9]$/) { status = sp[k]; break }
        if (status == "") { bad[ip]++ }
        # 304 and 206 ARE successful deliveries to a real client. The first
        # lines of a real cds1 customer log are 304s.
        else if (status ~ /^2[0-9][0-9]$/ || status == "304" || status == "206") served[ip]++

        ua = tolower(q[nq-1])                  # last quote pair, lowercased as ingest does
        if (ua == "" || ua == "-") uaempty[ip]++
        else {
            uapresent[ip]++
            if (!seenua[ip SUBSEP ua]++) uadistinct[ip]++
            if (ua ~ /mozilla|chrome|safari|firefox|edge|edg\/|opera|msie|trident|cfnetwork|dalvik|okhttp|lynx|w3m|outlook/)
                browser[ip] = 1
        }
        split(q[2], r, " "); if (!seenp[ip SUBSEP r[2]]++) paths[ip]++
    }
    END {
        for (ip in reqs)
            printf "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\t%d\n",
                   ip, reqs[ip], served[ip]+0, uapresent[ip]+0, uaempty[ip]+0,
                   uadistinct[ip]+0, browser[ip]+0,
                   (vhtop[ip]==""?"-":vhtop[ip]), paths[ip]+0, bad[ip]+0
    }
' "${_logfiles[@]}" > "$TRAFFIC" 2> "${OUT}/.scan_err"
awk_rc=$?
scan_errs=$(wc -l < "${OUT}/.scan_err" | tr -d ' ')
if (( awk_rc != 0 )); then
    note "domlog pass exited ${awk_rc} — treating the read as partial"
    scan_errs=$(( scan_errs + 1 ))
fi
note "domlog rows for $(wc -l < "$TRAFFIC" | tr -d ' ') of ${n_cand} candidates (read errors: ${scan_errs})"
if (( scan_errs > 0 )); then
    note "DEGRADED: ${scan_errs} domlog read error(s) — forcing EVERY row to bucket 3."
    note "          A partial read is indistinguishable from 'served nothing'."
fi

# --------------------------------------------------- phase 3: ledger, one query
# One GROUP BY, not one query per IP. The first draft issued ~1000 queries.
: > "$INTEL"
intel_ok=0
if [[ -f "$DB" ]]; then
    sqlite3 -cmd '.timeout 5000' -separator $'\t' "$DB" \
        "SELECT a.ip, GROUP_CONCAT(a.reason, ' ') FROM actions a
           JOIN (SELECT ip, MAX(ts) mt FROM actions WHERE dry_run=0 GROUP BY ip) m
             ON a.ip = m.ip AND a.ts = m.mt
          WHERE a.dry_run=0
          GROUP BY a.ip;" > "$INTEL" 2>/dev/null
    intel_ok=$?
else
    # A missing ledger is not a successful empty read. The first rewrite took
    # `$?` of the `if` itself, which is 0 when the file is absent, so the
    # degradation banner never fired.
    intel_ok=2
fi

# Shared-egress policy state, resolved ONCE (production caches this too).
#
# THE POINT OF THIS BLOCK: "shared-egress says no" and "shared-egress could not
# be evaluated" are different answers, and only the first one may let a row
# reach bucket 2. Both arms have to be usable, or we cannot rule out shared
# egress for ANY row and every non-inert candidate is a human's problem.
# Round-2 review found three separate ways this collapsed into a false negative
# on the AS206092 / WARP cohort — the arm being off, the ASN list being
# unreadable, and the CIDR file being rejected — each ending in an irreversible
# public report against an address the enforcer itself would cap.
# _asn_is_shared <asn>... — 0 if ANY supplied ASN is on the shared list.
# Two hazards, both reproduced:
#  - The `|| [[ -n "$line" ]]` is the house idiom (lib/common.sh:616-621). cds1's
#    list is a SINGLE line; hand-edited without a trailing newline, `grep` (which
#    _swatter_shared_egress_asns_usable uses) still sees it and reports the arm
#    usable, while a bare `while read` never yields it. The arm then reports "not
#    shared" for the one ASN it exists to catch.
#  - Every candidate ASN is tested, not just the first. See _asn_of.
_asn_is_shared() {
    local line f a
    [[ -f "$SE_ASNS" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"; line="${line%%#*}"; f="${line//[[:space:]]/}"
        [[ -n "$f" ]] || continue
        for a in "$@"; do [[ "$f" == "$a" ]] && return 0; done
    done < "$SE_ASNS"
    return 1
}

# PROBE THE MATCHERS, DO NOT TRUST THE VALIDATORS. Round 4 found that
# `se_cidr_ok && se_asns_ok` proves only "both files passed a different parser",
# not "this IP was matched by both arms" — and those are different languages:
#   * _swatter_shared_egress_asns_usable is `grep -qE '^[[:space:]]*[0-9]'`, so a
#     documentation line like "1. Add your ASNs below" passes, while the matcher
#     strips whitespace to "1.AddyourASNsbelow" and can never equal an ASN.
#   * _swatter_shared_egress_cidr_usable is sed+bash, but the IPv4 matcher inside
#     _cidr_overlaps_file is a separate awk process. If that awk fails, the
#     function returns 1 — identical to "not in the file". WARP v4
#     (104.28.0.0/16) is CIDR-only, so that single return code is its ONLY
#     protection.
# So: take an entry we KNOW is in each file and require the real matcher to find
# it. A matcher that cannot match its own file is a broken arm, not a clean miss.
# NOTE: deliberately the LAST entry. The whole trailing-newline defect class
# drops the FINAL line, so probing the first entry would prove nothing about the
# one actually at risk — and this script may be pointed at an installed
# /usr/local/lib/swatter that predates the library-side fix.
_probe_cidr_arm() {
    local tok net
    tok="$(sed 's/#.*//' "$SE_CIDR" 2>/dev/null | tr -d '[:blank:]' \
           | grep -E '^[0-9a-fA-F:.]+/[0-9]+$' | tail -1)" || return 1
    [[ -n "$tok" ]] || return 1
    net="${tok%%/*}"                      # a prefix always contains its own network address
    _cidr_overlaps_file "$net" "$SE_CIDR" 2>/dev/null
}
_probe_asn_arm() {
    local tok
    tok="$(sed 's/#.*//' "$SE_ASNS" 2>/dev/null | tr -d '[:blank:]' \
           | grep -E '^[0-9]+$' | tail -1)" || return 1
    [[ -n "$tok" ]] || return 1
    _asn_is_shared "$tok"
}

se_enabled=1
[[ "${SHARED_EGRESS_ENABLE:-true}" == "true" ]] || se_enabled=0
se_cidr_ok=0; se_asns_ok=0
if (( se_enabled )); then
    if _swatter_shared_egress_cidr_usable 2>/dev/null && _probe_cidr_arm; then
        se_cidr_ok=1
    else
        note "shared-egress CIDR arm did NOT match its own first entry — arm treated as broken"
    fi
    if _swatter_shared_egress_asns_usable 2>/dev/null && _probe_asn_arm; then
        se_asns_ok=1
    else
        note "shared-egress ASN arm did NOT match its own first entry — arm treated as broken"
    fi
fi
# A policy file whose last line lacks a trailing newline is read differently by
# its validator than by its matcher: _cidr_overlaps_file's IPv6 branch
# (lib/allowlist.sh:151) is a bare `while read` and drops it, while the IPv4
# branch is awk and does not, and the usability check is grep/awk. A silently
# dropped last line is exactly the absence-as-absence failure this sort must not
# make, so treat the arm as unusable instead.
# $( ) strips trailing newlines, so a file ending in "\n" yields the empty
# string and one ending in any other byte yields that byte. No od, no escaping.
_ends_with_newline() { [[ -s "$1" ]] || return 1; [[ -z "$(tail -c1 -- "$1")" ]]; }
for _f in "$SE_CIDR" "$SE_ASNS"; do
    if [[ -s "$_f" ]] && ! _ends_with_newline "$_f"; then
        note "NOTE: ${_f} has no trailing newline. Historically that made the last"
        note "      line invisible to the matcher while validators still passed the"
        note "      file. The last-entry probe below is what actually decides now —"
        note "      if it matches, the file is readable and this is informational."
    fi
done

se_evaluable=0
(( se_enabled && se_cidr_ok && se_asns_ok )) && se_evaluable=1
if (( se_evaluable == 0 )); then
    note "SHARED-EGRESS NOT FULLY EVALUABLE (enabled=${se_enabled} cidr=${se_cidr_ok} asns=${se_asns_ok})"
    note "  -> no row can be cleared of shared egress; every non-inert candidate goes to bucket 3."
    note "  -> a row can still be marked inert by whichever arm IS usable, but no"
    note "     row can be CLEARED for bucket 2."
fi
declare -A INTEL_OF=()
while IFS=$'\t' read -r i r || [[ -n "$i" ]]; do [[ -n "$i" ]] && INTEL_OF["$i"]="$r"; done < "$INTEL"

# History-wide flags. The max-ts reason only shows the LATEST action, so an
# older request_flood under a newer hard-intel reason was invisible, and a perm
# the enforcer capped months ago could be missed. Both are vetoes, so read the
# whole history for them.
declare -A FLOOD_EVER=() SECAP_EVER=()
hist_ok=1
if [[ -f "$DB" ]]; then
    # This is a full-table LIKE scan of an append-only table, racing the */5
    # scan for the same lock. If it fails, both maps come back empty — which is
    # indistinguishable from "this IP was never capped and never flooded". Track
    # the status so the sort can refuse to clear anything.
    _hist="$(sqlite3 -cmd '.timeout 5000' -separator $'\t' "$DB" \
        "SELECT DISTINCT ip, 'flood' FROM actions WHERE reason LIKE '%request_flood%'
         UNION SELECT DISTINCT ip, 'secap' FROM actions
           WHERE reason LIKE '%shared-egress=%' OR reason LIKE '%perm-capped%';" 2>&1)" || hist_ok=0
    case "$_hist" in *"Error"*|*"error"*|*"locked"*) hist_ok=0 ;; esac
    while IFS=$'\t' read -r i k || [[ -n "$i" ]]; do
        [[ -n "$i" ]] || continue
        [[ "$k" == "flood" ]] && FLOOD_EVER["$i"]=1
        [[ "$k" == "secap" ]] && SECAP_EVER["$i"]=1
    done <<< "$_hist"
else
    hist_ok=0
fi
(( hist_ok )) || note "WARNING: ledger history query failed — request_flood and shared-egress-capped vetoes are BLIND; forcing every non-inert row to bucket 3"

declare -A TRAF_OF=()
while IFS= read -r l || [[ -n "$l" ]]; do [[ -n "$l" ]] && TRAF_OF["${l%%$'\t'*}"]="$l"; done < "$TRAFFIC"

# --------------------------------------------------------------- ASN, no cache
# swatter_asn_resolve writes $STATE_DIR/asn/<ip> and is gated on a flag only
# swatter_check_deps sets. We do the same Cymru lookup without either.
_asn_of() {
    local ip="$1" rev
    if [[ "$ip" == *:* ]]; then
        rev="$(_ipv6_expand "$ip" 2>/dev/null)" || { printf ''; return 1; }
        rev="$(printf '%s' "$rev" | tr -d ':' | rev | sed 's/./&./g')origin6.asn.cymru.com"
    else
        local o1 o2 o3 o4; IFS=. read -r o1 o2 o3 o4 <<< "$ip"
        rev="${o4}.${o3}.${o2}.${o1}.origin.asn.cymru.com"
    fi
    # EVERY TXT RR, and EVERY origin token in each. Production takes only the
    # first (lib/asn.sh:40-42) because enforcement FAILS OPEN there by design —
    # a missed ASN just means the ban proceeds. This sort fails the other way:
    # if 206092 is present anywhere in the answer and we only inspected 13335,
    # we would "clear" a shared exit into bucket 2 and report it permanently.
    # A prefix really can have several origin ASNs, and Cymru can answer with
    # several RRs. Any non-digit token makes the whole answer ambiguous -> the
    # caller sends the row to human review.
    local -a asns=(); local rr tok
    # B-M3: query as an ABSOLUTE name (trailing dot). Without it a resolver
    # search list can append a local domain and answer from somewhere that is
    # not Cymru; a numeric answer from there would "clear" the row.
    # A-M4: honour dig's exit status — a truncated or failed lookup that still
    # emitted digit-looking bytes must not count as a successful evaluation.
    local _dig_out _dig_rc=0
    _dig_out="$(dig +short +time=2 +tries=1 TXT "${rev}." 2>/dev/null)" || _dig_rc=$?
    (( _dig_rc == 0 )) || { printf ''; return 1; }
    while IFS= read -r rr || [[ -n "$rr" ]]; do
        [[ -n "$rr" ]] || continue
        rr="${rr%\"}"; rr="${rr#\"}"
        rr="${rr%%|*}"
        for tok in $rr; do
            [[ "$tok" =~ ^[0-9]+$ ]] || { printf ''; return 1; }
            asns+=("$tok")
        done
    done <<< "$_dig_out"
    (( ${#asns[@]} > 0 )) || { printf ''; return 1; }
    printf '%s' "${asns[*]}"
}

# _inert_reason <ip> — mirrors swatter_is_never_block (lib/allowlist.sh:301-352)
# leg for leg, IN THE SAME ORDER, with ONE deliberate omission: the final
# forward-confirmed-crawler leg, which writes a 7-day verdict cache per IP.
# Checking only the operator allow file (as an earlier attempt did) would have
# silently dropped the Cloudflare, monitoring, csf.allow and server-self legs —
# safe direction, but it would inflate bucket 3 with rows that are genuinely
# inert. A crawler cannot be a ladder candidate anyway: it is exempted at scan
# time, so it never accumulates the temps escalate-preview reads.
#
# CORRECTION (round-2 review): that last sentence is wrong and is kept only to
# be struck. swatter_is_never_block runs at APPLY time (lib/score.sh:232-237),
# not at scoring, so a crawler whose forward-confirm failed CAN accrue temps and
# appear in escalate-preview. The omission is still safe, but for a different
# reason: a real crawler sends a User-Agent, so uapres > 0 and it cannot satisfy
# the bucket-2 predicate. It lands in bucket 3 and a human sees it.
_inert_reason() {
    local ip="$1" lip="${1,,}" of caf
    if [[ "$lip" == ::ffff:*.*.*.* || "$lip" == 0:0:0:0:0:ffff:*.*.*.* ]]; then
        ip="${ip##*:}"; lip="${ip,,}"
    fi
    case "$lip" in
        127.*|10.*|192.168.*|169.254.*|::1|fe80:*|fc*:*|fd*:*) echo "local/private"; return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)                echo "rfc1918";       return 0 ;;
    esac
    _cidr_overlaps_file "$ip" "${CLOUDFLARE_IPS_FILE}" 2>/dev/null && { echo "cloudflare-range"; return 0; }
    _ip_in_cidr_list "$ip" "${SWATTER_CF_FALLBACK_V4} ${SWATTER_CF_FALLBACK_V6}" 2>/dev/null \
        && { echo "cloudflare-range(builtin)"; return 0; }
    if [[ -n "${OPERATOR_IPS:-}" ]]; then
        # A failed mktemp must NOT abandon the remaining legs: production
        # falls through and still checks operator-allow / monitoring /
        # csf.allow / server-self (lib/allowlist.sh:326-332). Returning here
        # skipped all four for EVERY candidate whenever OPERATOR_IPS was set,
        # and a missed inert leg can land in bucket 2 — not merely wasteful.
        if of="$(mktemp "${TMPDIR:-/tmp}/gated-op.XXXXXX")"; then
            # shellcheck disable=SC2086
            printf '%s\n' ${OPERATOR_IPS} > "$of"
            if _cidr_overlaps_file "$ip" "$of" 2>/dev/null; then rm -f -- "$of"; echo "operator-ip"; return 0; fi
            rm -f -- "$of"
        fi
    fi
    _cidr_overlaps_file "$ip" "${OPERATOR_ALLOW_FILE}" 2>/dev/null   && { echo "operator-allow"; return 0; }
    _cidr_overlaps_file "$ip" "${MONITORING_RANGES_FILE}" 2>/dev/null && { echo "monitoring"; return 0; }
    caf="$(_swatter_csf_allow_file 2>/dev/null)"
    [[ -n "$caf" ]] && _cidr_overlaps_file "$ip" "$caf" 2>/dev/null   && { echo "csf.allow"; return 0; }
    _swatter_self_ips 2>/dev/null | grep -qxF "$ip"                   && { echo "server-self"; return 0; }
    return 1
}

# _swatter_csf_allow_file plants one mktemp per process and never removes it
# (lib/allowlist.sh:216) — a documented leak. We own the process, so we clean it.
_cleanup() { [[ -n "${SWATTER_CSF_ALLOW_FILE:-}" ]] && rm -f -- "${SWATTER_CSF_ALLOW_FILE}"; }
trap _cleanup EXIT


# ------------------------------------------------------------ phase 4: bucket
printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\tinert\tasn\tptr\tptr_confirmed\tvhost_top\treqs\tserved\tua_present\tua_empty\tua_distinct\tbrowser\tpaths\tbadlines\tintel\tbucket\twhy\n' > "${ENRICHED}.partial"

while IFS=$'\t' read -r ip temps last status || [[ -n "$ip" ]]; do
    [[ -n "$ip" ]] || continue

    # Blocker 4: validate BEFORE the value becomes a dig argument or an awk -v.
    # The non-fatal variant (common.sh:570) — the ...validate... wrapper dies.
    if ! swatter_is_valid_ip_or_cidr "$ip"; then
        printf '%s\t%s\t%s\t%s\t-\t-\t-\t-\t-\t0\t0\t0\t0\t0\t0\t0\t0\t-\t3\tinvalid-candidate\n' \
            "$ip" "$temps" "$last" "$status" >> "${ENRICHED}.partial"
        continue
    fi

    inert="" asn="" ptr="-" ptrc="-" why="" bucket=""

    # --- inert leg 1: every never-block leg except the cache-writing crawler one
    inert="$(_inert_reason "$ip")" || inert=""

    # --- inert leg 2: shared-egress, CIDR arm (no DNS, no writes).
    # Gated on the same poison guard production uses (lib/asn.sh:95-109). Without
    # it, a single over-broad line in the file marks EVERY candidate inert and
    # silently turns the whole review off — the mirror image of the "one
    # over-broad line disables the CIDR arm" lesson already in TODO.md.
    if [[ -z "$inert" ]] && (( se_cidr_ok )) \
       && _cidr_overlaps_file "$ip" "$SE_CIDR" 2>/dev/null; then
        inert="shared-egress:cidr"
    fi

    # --- inert leg 3: shared-egress, ASN arm.
    # Resolved for EVERY non-inert row, not just bucket-2 candidates. Scoping it
    # to the bucket-2 predicate (as the first rewrite did) meant an AS206092 exit
    # that served anything landed in bucket 3 as an ordinary review row — safer
    # than bucket 2, but still wrong: a human can mark it ban-ok, which is
    # exactly what the inert bucket exists to prevent.
    # Gated on se_asns_ok alone, NOT se_evaluable: the arms are independent for
    # deciding INERT (production does the same, lib/asn.sh:145-151). Only
    # CLEARING a row for bucket 2 needs both arms, and that is enforced in the
    # sort below. Skipping it when the ASN arm is broken also avoids ~1000
    # serial digs for an answer we would refuse to trust anyway.
    asn_ok=1
    if [[ -z "$inert" ]] && (( se_enabled && se_asns_ok )); then
        if asn="$(_asn_of "$ip")" && [[ -n "$asn" ]]; then
            # shellcheck disable=SC2086
            _asn_is_shared $asn && inert="shared-egress:AS${asn// /+AS}"
        else
            asn=""; asn_ok=0
        fi
    fi

    line="${TRAF_OF[$ip]:-}"
    if [[ -n "$line" ]]; then
        IFS=$'\t' read -r _ reqs served uapres uaempty uad br vhost paths badl <<< "$line"
        have_traffic=1
    else
        reqs=0 served=0 uapres=0 uaempty=0 uad=0 br=0 vhost="-" paths=0 badl=0
        have_traffic=0
    fi

    intel="${INTEL_OF[$ip]:--}"
    # M1 (round 3): the enforcer stamps "shared-egress=<what> perm-capped" on a
    # capped action (lib/score.sh:264). That is the authority itself saying "do
    # not perm, do not publish" about this address. Honour it BEFORE any live
    # rematch, so a DNS answer that disagrees with the ledger cannot undo it.
    if [[ -z "$inert" ]]; then
        case "$intel" in *shared-egress=*|*perm-capped*) inert="ledger:shared-egress-capped" ;; esac
        [[ -z "$inert" && -n "${SECAP_EVER[$ip]:-}" ]] && inert="ledger:shared-egress-capped(history)"
    fi
    hard=0
    case "$intel" in *spamhaus:drop*|*abuseipdb:confidence100*) hard=1 ;; esac
    flood=0
    case "$intel" in *request_flood*) flood=1 ;; esac
    [[ -n "${FLOOD_EVER[$ip]:-}" ]] && flood=1

    # --- the sort ------------------------------------------------------------
    if [[ -n "$inert" ]]; then
        bucket=1; why="inert:${inert}"
    elif (( scan_errs > 0 )); then
        bucket=3; why="degraded-domlog-read"
    elif (( have_traffic == 0 )); then
        bucket=3; why="no-traffic-evidence"
    elif (( badl > 0 )); then
        bucket=3; why="unparseable-log-lines:${badl}"
    elif (( flood == 1 )); then
        bucket=3; why="request_flood"          # spec says human; now a real veto
    elif (( hist_ok == 0 )); then
        bucket=3; why="ledger-history-unreadable-vetoes-blind"
    elif (( se_evaluable == 0 )); then
        bucket=3; why="shared-egress-not-evaluable"
    elif (( asn_ok == 0 )); then
        # Enforcement fails OPEN on an ASN miss so DNS cannot become an
        # availability lever on the ladder. Classification must not: an
        # unresolved ASN means we could not rule out shared egress.
        bucket=3; why="asn-unresolved-cannot-rule-out-shared-egress"
    elif (( hard == 1 && served == 0 && uapres == 0 )); then
        bucket=2; why="hard-intel+nothing-served+no-ua-on-any-request"
    else
        bucket=3; why="review"
        (( hard == 0 ))    && why="${why}:weak-intel"
        (( served > 0 ))   && why="${why}:served-content"
        (( uapres > 0 ))   && why="${why}:sent-a-ua"
        (( br == 1 ))      && why="${why}:browser-ua"
    fi

    # PTR is for the human dossier, not for the sort — so resolve it only for
    # the rows a human will actually read, and forward-confirm it, because a
    # bare PTR is set by the address's own owner.
    if (( bucket == 3 )); then
        ptr="$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null | head -1)"; ptr="${ptr%.}"
        # The PTR is attacker-controlled: whoever owns the address picks the
        # string. Passing it straight back as dig argv lets a value like
        # "-f/etc/hosts" become a FLAG, and dig then reads that file as root.
        # Accept only a hostname charset before it is ever an argument.
        if [[ -n "$ptr" && ! "$ptr" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$ ]]; then
            ptr="(rejected-ptr)"; ptrc="REJECTED"
        elif [[ -n "$ptr" ]]; then
            if dig +short +time=2 +tries=1 "$ptr" A "$ptr" AAAA 2>/dev/null | grep -qxF "$ip"; then
                ptrc="confirmed"
            else
                ptrc="UNCONFIRMED"
            fi
        else
            ptr="-"; ptrc="none"
        fi
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\t%s\n' \
        "$ip" "$temps" "$last" "$status" "${inert:--}" "${asn:--}" "$ptr" "$ptrc" \
        "$vhost" "$reqs" "$served" "$uapres" "$uaempty" "$uad" "$br" "$paths" "$badl" \
        "$intel" "$bucket" "$why" >> "${ENRICHED}.partial"
done < "$CAND"

n_rows=$(( $(wc -l < "${ENRICHED}.partial" | tr -d ' ') - 1 ))
if (( n_rows != n_cand )); then
    die "INCOMPLETE: enriched ${n_rows} of ${n_cand} candidates — refusing to publish a partial run. Partial left at ${ENRICHED}.partial"
fi

# ------------------------------------------------------------ phase 5: report
{
    echo "gate D enrichment — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "preview:    ${PREVIEW}"
    echo "domlogs:    ${GLOB}"
    echo "candidates: ${n_cand}   enriched: ${n_rows}"
    (( scan_errs > 0 )) && echo "!! DEGRADED: ${scan_errs} domlog read error(s); every row forced to bucket 3"
    (( intel_ok != 0 )) && echo "!! ledger query returned non-zero; intel may be incomplete"
    echo
    awk -F'\t' 'NR>1{c[$19]++} END{
        printf "  bucket 1 (inert, count only):        %d\n", c[1]+0
        printf "  bucket 2 (hostile, sample-audited):  %d\n", c[2]+0
        printf "  bucket 3 (HUMAN REVIEW):             %d\n", c[3]+0
    }' "${ENRICHED}.partial"
    echo
    echo "bucket 3 reasons:"
    awk -F'\t' 'NR>1 && $19==3 {c[$20]++} END{for(k in c) printf "  %-52s %d\n", k, c[k]}' "${ENRICHED}.partial" | sort -k2 -rn
    echo
    echo "bucket 2 audit sample (seed=${SAMPLE_SEED}; ONE false positive collapses"
    echo "the whole bucket into 3 — see the recording scheme in TODO.md):"
    awk -F'\t' 'NR>1 && $19==2 {print $1}' "${ENRICHED}.partial" \
        | awk -v seed="$SAMPLE_SEED" 'BEGIN{srand(seed)} {print rand()"\t"$0}' \
        | sort -n | head -30 | cut -f2 | sed 's/^/  /'
    echo
    echo "CAVEAT: 'served' reflects only the LIVE logs scanned above. The preview"
    echo "  window is 7-30 days; a 2xx/304 that has already rotated out is invisible"
    echo "  here, so served=0 means 'nothing in the current logs', not 'never served"
    echo "  anything'. Audit a bucket-2 sample against the rotated /home/*/logs/*.gz"
    echo "  before trusting it — that is how the 2026-08-01 scanner_profile audit was"
    echo "  done, and it is why that audit could make absolute claims."
    echo
    echo "COMPLETE ${n_rows}/${n_cand}"
} > "${BUCKETS}.partial"

# Publish both files atomically, together. An interrupted first draft left a new
# partial enriched.tsv beside the PREVIOUS run's buckets.txt — including its
# stale audit sample, against a different list.
# Two mv's are not atomic *together*: a kill between them leaves a NEW
# enriched.tsv beside the PREVIOUS buckets.txt and its stale audit sample. So
# destroy the old report FIRST. A crash now leaves an enriched file with no
# report, which reads as obviously incomplete instead of quietly wrong.
rm -f -- "$BUCKETS"
mv -f -- "${ENRICHED}.partial" "$ENRICHED" || die "failed to publish ${ENRICHED}"
mv -f -- "${BUCKETS}.partial"  "$BUCKETS"  || die "failed to publish ${BUCKETS}"
[[ -f "$DECISIONS" ]] || printf 'ip\tbucket\tverdict\treason\treviewer\tutc\n' > "$DECISIONS"
chmod 0600 -- "$ENRICHED" "$BUCKETS" "$TRAFFIC" "$CAND" "$INTEL" "$DECISIONS" 2>/dev/null
rm -f -- "${OUT}/.scan_err"

cat "$BUCKETS"
note "wrote ${ENRICHED}, ${BUCKETS}, and scaffolded ${DECISIONS}"
