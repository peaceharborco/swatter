#!/usr/bin/env bash
# test/score_test.sh — golden-score assertions for the parse + scoring pipeline.
#
# Runs lib/ingest.sh's combined-log parser into lib/score.awk and checks that
# representative traffic lands in the expected score band. No network, no
# firewall, no root — pure pipeline. Run: bash test/score_test.sh
#
# Fixtures are generated inline with a fixed base time and realistic timestamp
# spread (requests scattered across the window, as in a real log) so the rate
# math is meaningful and the window cutoff is deterministic.

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"

# shellcheck source=../lib/common.sh
source "${ROOT}/lib/common.sh"
# shellcheck source=../lib/ingest.sh
source "${ROOT}/lib/ingest.sh"

# Fixed clock: NOW is 2026-06-10 12:10:00 UTC; the window is the prior 600s, so
# events stamped 12:00:01..12:10:00 are in-window.
NOW_EPOCH=1749557400
WIN_START=$(( NOW_EPOCH - 600 ))

PASS=0; FAIL=0

# tstamp <epoch> -> "dd/Mon/yyyy:HH:MM:SS +0000" (combined-log time field)
# GNU date (-d @epoch) first, BSD date (-r epoch) fallback — on Linux, -r means
# file-mtime, so the order matters.
tstamp() {
    date -u -d "@$1" '+%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null \
        || date -u -r "$1" '+%d/%b/%Y:%H:%M:%S +0000'
}

# emit_spread <outfile> <ip> <request> <status> <ua> <count>
# Spreads <count> requests evenly across the last 300s of the window.
emit_spread() {
    local out="$1" ip="$2" req="$3" status="$4" ua="$5" count="$6"
    local i ep step start
    start=$(( NOW_EPOCH - 300 )); step=$(( 300 / (count > 0 ? count : 1) ))
    (( step < 1 )) && step=1
    for (( i=0; i<count; i++ )); do
        ep=$(( start + i*step ))
        printf '%s - - [%s] "%s" %s 0 "-" "%s"\n' "$ip" "$(tstamp "$ep")" "$req" "$status" "$ua" >> "$out"
    done
}

# score_of <vhost> <logfile> -> score for the first IP, or "NONE"
score_of() {
    local vhost="$1" file="$2"
    _swatter_parse "$vhost" < "$file" \
      | gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 \
             -v SCORE_WATCH=50 \
             -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 \
             -v W_BADPATH=22 -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
             -v BADPATHS="${ROOT}/config/badpaths.conf" \
             -f "${ROOT}/lib/score.awk" \
      | awk -F'\t' 'NR==1{print $2; found=1} END{if(!found) print "NONE"}'
}

assert_band() {
    local name="$1" got="$2" lo="$3" hi="$4"
    [[ "$got" == "NONE" ]] && got=0
    if (( got >= lo && got <= hi )); then
        printf 'PASS  %-30s score=%-3s (want %s-%s)\n' "$name" "$got" "$lo" "$hi"
        PASS=$((PASS+1))
    else
        printf 'FAIL  %-30s score=%-3s (want %s-%s)\n' "$name" "$got" "$lo" "$hi"
        FAIL=$((FAIL+1))
    fi
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/swatter-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# --- 1: legit low-volume visitor (mostly 200s, a stray 404) -> under watch ---
: > "$tmp/legit.log"
for i in $(seq 1 18); do
    emit_spread "$tmp/legit.log" "203.0.113.50" "GET /page$i HTTP/1.1" 200 "Mozilla/5.0 (Macintosh)" 1
done
emit_spread "$tmp/legit.log" "203.0.113.50" "GET /missing HTTP/1.1" 404 "Mozilla/5.0 (Macintosh)" 2
assert_band "legit-visitor" "$(score_of example.com "$tmp/legit.log")" 0 49

# --- 1b: mangled-srcset 404 storm is the SITE's bug, not a probe ------------
# 2026-08-28 gate D review: third-party Chromium-based clients request a whole
# srcset value as one URL. 17,829 such requests from 8,767 DISTINCT client IPs
# across 35 hosted sites, overwhelmingly residential broadband. Nineteen real
# visitors were already temp-blocked, six by rule=error_burst, one a live perm
# candidate. A real visitor must not be banned for what their client does -- and
# the exemption must not become a detection blind spot. Both review models broke
# the FIRST version of this fix; the bypass strings they supplied are pinned below
# by name.
#
# NOTE the cause was corrected AFTER v2.17.0 shipped: this was first diagnosed as
# the sites emitting broken markup, and they do not -- see the header comment on
# is_mangled_srcset() in lib/score.awk. The tests are unchanged by that
# correction (the request shape is identical either way); what changed is that
# there is no upstream fix coming, so these assertions are permanent.
HP="$tmp/honeypots.conf"; printf '/__trap_a7f3c1d9(/|$)\n' > "$HP"
srcset_score() {  # srcset_score <path> <count> [status] -> score or NONE
    local pth="$1" cnt="$2" st="${3:-404}" i
    : > "$tmp/ss.tsv"
    for (( i=1; i<=cnt; i++ )); do
        printf '198.51.100.9\t%s\tGET\t%s\t%s\t-\tcurl/8.0\n' \
            $(( NOW_EPOCH - 300 + i )) "$pth" "$st" >> "$tmp/ss.tsv"
    done
    gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
         -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
         -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
         -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
         -f "${ROOT}/lib/score.awk" "$tmp/ss.tsv" \
      | awk -F'\t' 'NR==1{print $2; f=1} END{if(!f) print "NONE"}'
}
ss_band() { assert_band "$1" "$2" "$3" "$4"; }

# A real 5-candidate srcset, truncated to 256 bytes exactly as lib/ingest.sh does.
SS_LONG_FULL='/wp-content/uploads/2025/10/summer-collection-hero-480x360.jpg%20480w,%20https://cdn.example.com/wp-content/uploads/2025/10/summer-collection-hero-768x576.jpg%20768w,%20https://cdn.example.com/wp-content/uploads/2025/10/summer-collection-hero-1024x768.jpg%201024w,%20https://cdn.example.com/wp-content/uploads/2025/10/summer-collection-hero-1920x1440.jpg%201920w'
SS_LONG_TRUNC="${SS_LONG_FULL:0:256}"

_srcset_burst_tsv() {  # <count> <seconds> [other_requests]
    local cnt="$1" secs="$2" other="${3:-0}" i
    : > "$tmp/burst.tsv"
    for (( i=1; i<=cnt; i++ )); do
        printf '198.51.100.7\t%s\tGET\t/wp-content/uploads/2025/10/gallery-img%s-768x576.jpg%%20768w,%%20https://e.com/g%s-900x675.jpg%%20900w\t404\t-\tMozilla/5.0\texample.com\n' \
            $(( NOW_EPOCH - 300 + (i * secs / cnt) )) "$i" "$i" >> "$tmp/burst.tsv"
    done
    for (( i=1; i<=other; i++ )); do
        printf '198.51.100.7\t%s\tGET\t/page-%s\t200\t-\tMozilla/5.0\texample.com\n' \
            $(( NOW_EPOCH - 320 + i )) "$i" >> "$tmp/burst.tsv"
    done
}
_srcset_burst_run() {
    gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
         -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
         -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
         -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
         -f "${ROOT}/lib/score.awk" "$tmp/burst.tsv" | head -1
}
srcset_burst()       { _srcset_burst_tsv "$1" "$2";     local r; r="$(_srcset_burst_run | cut -f2)"; printf '%s' "${r:-NONE}"; }
srcset_burst_status() {  # <count> <seconds> <status>
    local cnt="$1" secs="$2" st="$3" i
    : > "$tmp/burst.tsv"
    for (( i=1; i<=cnt; i++ )); do
        printf '198.51.100.7\t%s\tGET\t/wp-content/uploads/2025/10/gallery-img%s-768x576.jpg%%20768w,%%20https://e.com/g%s-900x675.jpg%%20900w\t%s\t-\tMozilla/5.0\texample.com\n' \
            $(( NOW_EPOCH - 300 + (i * secs / cnt) )) "$i" "$i" "$st" >> "$tmp/burst.tsv"
    done
    local r; r="$(_srcset_burst_run | cut -f2)"; printf '%s' "${r:-NONE}"
}
srcset_burst_mixed() { _srcset_burst_tsv "$1" "$2" "$3"; local r; r="$(_srcset_burst_run | cut -f2)"; printf '%s' "${r:-NONE}"; }
srcset_burst_rule()  { _srcset_burst_tsv "$1" "$2";     _srcset_burst_run | grep -o '"decisive_rule":"[^"]*"' | cut -d'"' -f4; }

srcset_rule_fast() {  # <path> <count> <status> -> decisive_rule (field 3 is the count; rule is in the JSON)
    srcset_score_fast "$1" "$2" "$3" >/dev/null
    gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
         -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
         -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
         -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
         -f "${ROOT}/lib/score.awk" "$tmp/ssf.tsv" \
      | head -1 | grep -o '"decisive_rule":"[^"]*"' | cut -d'"' -f4
}

srcset_score_fast() {  # <path> <count> <status> -> score, all inside 20s (rps>=8)
    local pth="$1" cnt="$2" st="$3" i
    : > "$tmp/ssf.tsv"
    for (( i=1; i<=cnt; i++ )); do
        printf '198.51.100.9\t%s\tGET\t%s\t%s\t-\tMozilla/5.0\texample.com\n' \
            $(( NOW_EPOCH - 60 + (i % 20) )) "$pth" "$st" >> "$tmp/ssf.tsv"
    done
    gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
         -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
         -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
         -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
         -f "${ROOT}/lib/score.awk" "$tmp/ssf.tsv" \
      | awk -F'\t' 'NR==1{print $2; f=1} END{if(!f) print "NONE"}'
}

# The real production shapes must NOT score.
SS_REAL='/wp-content/uploads/2025/10/photo-768x576.jpg%20768w,%20https://example.com/photo-900x675.jpg%20900w'
ss_band "srcset-real-shape-not-banned" "$(srcset_score "$SS_REAL" 220)" 0 49
# The observed log form: consecutive-slash collapse at the edge turns
# https://host into https:/host. Documented in the gate-D handoff. Requiring
# // for later-candidate hosts scored this at 75/error_burst.
ss_band "srcset-edge-collapsed-https-one-slash" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo-768x576.jpg%20768w,%20https:/example.com/photo-900x675.jpg%20900w' 220)" 0 49
# Single-candidate srcset has no trailing comma; density (sizes) descriptors use Nx.
# Both are the same defect and were MISSED by the first version of the fix.
ss_band "srcset-single-candidate-no-comma"  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w' 220)" 0 49
ss_band "srcset-density-descriptor"         "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%202x,%20https://e.example/y.jpg%203x' 220)" 0 49

# --- 2026-08-28 falsification review: the class is not all 404 --------------
# The report that overturned the markup diagnosis measured the class's status
# split: 15,299 x 404, 1,936 x 301, 592 x 302, 2 x 200. The v2.17.0 exemption was
# gated on status==404, so 2,528 requests (14%) still entered reqs[] -- which
# REOPENED the very err_ratio dilution lever the drop-before-reqs[] design closed.
# Measured on the real scorer: a 60-probe run scores 78 bare, 78 padded with
# srcset 404s (neutral, as designed), and 18 padded with srcset 301s.
#
# The gate is now shape + path_scores_on_its_own, with NO status carve-out at all,
# because any status carve-out IS the lever: an attacker simply pads with
# shape-matching URLs that return a status outside the exempt set.
# THE EXEMPT STATUS SET IS {2xx, 3xx, 404} AND NOTHING ELSE.
# The first version of this fix removed the status gate entirely, on the argument
# that any status set is itself a dilution lever. That argument is WRONG, and the
# review measured why: err_ratio is nerr/n, so only a status that stays OUT of
# cerr[] dilutes. 5xx feeds cerr[]. 403 used to feed cerr[] AND cburst[] -- and
# that was the own-challenge loop, closed separately: static-asset and
# mangled-srcset 403s are now dropped before reqs[] (see own-403-not-scanner),
# so they neither raise nor dilute. Padding a probe run with 5xx RAISES the score, it does not lower it.
# Only 2xx/3xx dilute -- and the measured srcset class is 15,299x404 + 1,936x301
# + 592x302 + 2x200, with ZERO 5xx and ZERO 403. So the set is calibrated to
# the evidence: drop what the class actually contains, and keep every status
# that carries real signal. Dropping 5xx would have made an origin melt
# invisible (measured: 400 requests in 20s scored 75 request_flood before,
# NONE after).
# 403 is often OUR answer (CSF deny / a challenge that still hit origin).
# Counting it in cerr[]/cburst[] is the scanner_profile feedback loop: being
# challenged drives nerr/n up across every distinct asset path the client
# retries. Non-badpath 403s are dropped before reqs[], same dilution split as
# srcset. A srcset-shaped 403 is not a probe; it is a challenged client.
ss_band "srcset-403-not-our-challenge" "$(srcset_score "$SS_REAL" 220 403)" 0 49
ss_band "srcset-500-flood-still-scores" "$(srcset_score_fast "$SS_REAL" 400 500)" 75 100
ss_band "srcset-401-still-scores" "$(srcset_score_fast "$SS_REAL" 400 401)" 75 100
# 429 is a rate-limiter answering. It feeds cerr[] so it cannot dilute, but
# exempting it would throw away the signal that something is being throttled --
# the one status that most directly says "this client is already too much".
ss_band "srcset-429-still-scores" "$(srcset_score_fast "$SS_REAL" 400 429)" 75 100

# Exempt statuses at ORDINARY rate (220 requests over 220s, ~1 rps) must not score.
ss_band "srcset-404-exempt" "$(srcset_score "$SS_REAL" 220 404)" 0 49
ss_band "srcset-301-exempt" "$(srcset_score "$SS_REAL" 220 301)" 0 49
ss_band "srcset-302-exempt" "$(srcset_score "$SS_REAL" 220 302)" 0 49
ss_band "srcset-200-exempt" "$(srcset_score "$SS_REAL" 220 200)" 0 49

# The unmetered-channel problem this used to pin is now covered by the
# gallery-burst / watch-only block further down, which replaced a 75 floor that
# could temp a real visitor. Kept here: the ordinary-rate exemption cases above.
# A slow, high-VOLUME client stays exempt -- the tripwire is a rate, not a count,
# because the real class is high-volume-low-rate and must never be caught by it.
ss_band "srcset-high-volume-slow-still-exempt" "$(srcset_score "$SS_REAL" 3000 404)" 0 49
# Both tripwire thresholds pinned: just under each bar must stay silent, just over
# must surface. Mutants moving 500->400 or 25->20 rps previously stayed green.
ss_band "tripwire-just-under-count" "$(srcset_burst 499 20)" 0 49
ss_band "tripwire-at-count"         "$(srcset_burst 500 20)" 50 69
ss_band "tripwire-just-under-rate"  "$(srcset_burst 500 21)" 0 49
# ...and the count bar independently, with the rate comfortably over its own.
ss_band "tripwire-count-450-over-rate" "$(srcset_burst 450 10)" 0 49
ss_band "tripwire-count-500-over-rate" "$(srcset_burst 500 10)" 50 69

# THE DEFECT, part 1 -- request_flood. 3xx never reaches error_burst, but it does
# reach reqs[]/rps, so a tight retry loop on this shape trips the flood floor at
# 75 and temps a real visitor (SCORE_TEMP=70). The observed heaviest client fired
# 544 requests for 14 distinct URLs in one day: a retry loop, exactly this shape.


# THE DEFECT, part 2 -- err_ratio dilution. This is the SAME lever the 2.17.0
# design closed by dropping the request before reqs[] rather than merely keeping
# it out of cerr[]. Gating that drop on status==404 reopened it for every other
# status: pad a real probe run with shape-matching URLs that redirect and
# err_ratio (nerr/n) collapses. Measured before the fix: 78 bare -> 18 padded.
# The probe run is deliberately kept BELOW the error_burst knee (nburst>=100) and
# spread over distinct paths, so the COMPOSITE decides the score. An absolute
# floor cannot be diluted, so a 120-request probe run would mask this defect
# entirely -- which is why the existing 404 padding test could not have caught it.
emit_scan() {  # <out> <ip> <status> <count> <ndistinct> -- distinct-path probe run
    local out="$1" ip="$2" st="$3" cnt="$4" nd="$5" i ep
    for (( i=0; i<cnt; i++ )); do
        ep=$(( NOW_EPOCH - 300 + i*4 ))
        printf '%s - - [%s] "GET /nope-%s HTTP/1.1" %s 0 "-" "curl/8.0"\n' \
            "$ip" "$(tstamp "$ep")" "$(( i % nd ))" "$st" >> "$out"
    done
}
: > "$tmp/probe_bare.log"
emit_scan "$tmp/probe_bare.log" "203.0.113.83" 404 60 30
BARE301="$(score_of example.com "$tmp/probe_bare.log")"
: > "$tmp/probe_padded301.log"
emit_scan "$tmp/probe_padded301.log" "203.0.113.83" 404 60 30
emit_spread "$tmp/probe_padded301.log" "203.0.113.83" "GET ${SS_REAL} HTTP/1.1" 301 "curl/8.0" 500
PADDED301="$(score_of example.com "$tmp/probe_padded301.log")"
ss_band "probe-run-scores-below-burst-floor" "$BARE301" 75 100
ss_band "probe-run-still-scores-when-padded-301" "$PADDED301" 75 100
if [[ "$BARE301" == "$PADDED301" ]]; then
    printf 'PASS  %-30s 301 padding is neutral (both %s)\n' "srcset-301-padding-neutral" "$BARE301"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s bare=%s padded=%s\n' "srcset-301-padding-neutral" "$BARE301" "$PADDED301"; FAIL=$((FAIL+1))
fi

# --- regex gaps the review found (all real shapes on this fleet) ------------
# WordPress MULTISITE puts uploads under sites/N/ -- unexempted before this fix.
ss_band "srcset-multisite-path" \
  "$(srcset_score '/wp-content/uploads/sites/2/2025/10/photo-768x576.jpg%20768w,%20https://e.com/p.jpg%20900w' 220)" 0 49
# Nested subdirectories under uploads/YYYY/MM/ (plugin thumbnail trees).
ss_band "srcset-nested-subdir" \
  "$(srcset_score '/wp-content/uploads/2025/10/thumbs/photo.jpg%20768w,' 220)" 0 49
ss_band "srcset-bmp-extension" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.bmp%20768w,' 220)" 0 49
# A space BEFORE the comma is legal srcset whitespace.
ss_band "srcset-space-before-comma" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w%20,%20https://e.com/p.jpg%20900w' 220)" 0 49

# --- THE STEM CLOAK: [^/]+ let any name wear an image extension -------------
# Found by pre-ship review. The stem between YYYY/MM/ and the extension was
# [^\/]+, which admits dots and percent-encoding. Everything the exemption
# REQUIRES in order to look like an image (a real extension immediately before the
# descriptor) is exactly what made these probes MISS path_scores_on_its_own():
# the badpath table keys on literal spellings, and tolower() case-folds without
# decoding. Real WordPress upload names (photo-768x576) fit [a-z0-9_~-]+, the same
# class the directories already use -- so the stem now uses it too.
ss_band "cloak-wp-config-php-jpg"  "$(srcset_score '/wp-content/uploads/2025/10/wp-config.php.jpg%20768w,' 220)" 75 100
ss_band "cloak-c99-php-jpg"        "$(srcset_score '/wp-content/uploads/2025/10/c99.php.jpg%20768w,' 220)" 75 100
ss_band "cloak-backdoor-php-jpg"   "$(srcset_score '/wp-content/uploads/2025/10/backdoor.php.jpg%20768w,' 220)" 75 100
ss_band "cloak-htaccess-jpg"       "$(srcset_score '/wp-content/uploads/2025/10/.htaccess.jpg%20768w,' 220)" 75 100
ss_band "cloak-encoded-dot-env"    "$(srcset_score '/wp-content/uploads/2025/10/%2eenv.jpg%20768w,' 220)" 75 100
ss_band "cloak-encoded-slash-env"  "$(srcset_score '/wp-content/uploads/2025/10/x%2f.env.jpg%20300w,' 220)" 75 100

# --- ...but the stem must not become a FALSE POSITIVE either ----------------
# Tightening the stem to [a-z0-9_~-]+ closed the cloaks and immediately created
# the harm the exemption exists to prevent: WordPress sanitize_file_name() strips
# ?[]\/=<>:;,'"&$#*()|~`!{}%+ and NUL, but NOT '.' and NOT '@'. So these are all
# REAL upload names, and all three scored 75 under the first tightening -- three
# such temps is a permanent, non-deletable AbuseIPDB report against a residential
# visitor. The stem now admits dots and '@' (never '%', which is how %2e/%2f got
# in), and safety comes from refusing any dot-component that is an executable or
# config EXTENSION -- a bounded deny list over a single token, not a path blocklist.
ss_band "real-name-dotted-stem"   "$(srcset_score '/wp-content/uploads/2025/10/my.photo-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-versioned"     "$(srcset_score '/wp-content/uploads/2025/10/report.v2-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-retina-at2x"   "$(srcset_score '/wp-content/uploads/2025/10/logo@2x-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-multi-dot"     "$(srcset_score '/wp-content/uploads/2025/10/a.b.c-768x576.jpg%20768w,' 220)" 0 49
# The deny list is what keeps the cloaks shut once dots are allowed back in.
ss_band "cloak-phtml"             "$(srcset_score '/wp-content/uploads/2025/10/x.phtml.jpg%20768w,' 220)" 75 100
ss_band "cloak-env-component"     "$(srcset_score '/wp-content/uploads/2025/10/x.env.jpg%20768w,' 220)" 75 100
ss_band "cloak-sql-dump"          "$(srcset_score '/wp-content/uploads/2025/10/db.sql.jpg%20768w,' 220)" 75 100
ss_band "cloak-pem-key"           "$(srcset_score '/wp-content/uploads/2025/10/server.pem.jpg%20768w,' 220)" 75 100

# --- MORE REAL SHAPES THAT MUST NOT SCORE (false-positive direction) --------
# Each of these is legitimate markup a real visitor's client will request.
ss_band "real-scheme-relative-candidate" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w,%20//cdn.example.com/wp-content/uploads/2025/10/photo-900x675.jpg%20900w' 220)" 0 49
ss_band "real-trailing-comma-space" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w,%20' 220)" 0 49
ss_band "real-heic-extension"  "$(srcset_score '/wp-content/uploads/2025/10/photo.heic%20768w,' 220)" 0 49
ss_band "real-jfif-extension"  "$(srcset_score '/wp-content/uploads/2025/10/photo.jfif%20768w,' 220)" 0 49

# --- the 1xx / status-0 half of the predicate --------------------------------
# The predicate is (status < 400 || status == 404) -- i.e. {0, 1xx, 2xx, 3xx, 404}.
# 1xx and the status-0 that ingest emits for an unparseable line do NOT feed
# cerr[], so they dilute exactly the way 3xx does. Narrowing the predicate to the
# {2xx,3xx,404} that the docs used to claim would REOPEN the lever this change
# exists to close, so it is pinned here as behaviour, not left to a comment.
: > "$tmp/pad1xx.log"
emit_scan "$tmp/pad1xx.log" "203.0.113.84" 404 60 30
emit_spread "$tmp/pad1xx.log" "203.0.113.84" "GET ${SS_REAL} HTTP/1.1" 100 "curl/8.0" 500
ss_band "probe-run-not-diluted-by-1xx-padding" "$(score_of example.com "$tmp/pad1xx.log")" 75 100
# ...and status 0, which is what ingest emits for a line it could not parse. The
# changelog claimed this was pinned when only the 1xx case was, and a mutant
# dropping 0 from the predicate stayed green.
: > "$tmp/pad0.log"
emit_scan "$tmp/pad0.log" "203.0.113.85" 404 60 30
emit_spread "$tmp/pad0.log" "203.0.113.85" "GET ${SS_REAL} HTTP/1.1" 0 "curl/8.0" 500
ss_band "probe-run-not-diluted-by-status0-padding" "$(score_of example.com "$tmp/pad0.log")" 75 100

# --- deny-list cloaks: the tokens round 2 found missing ---------------------
# stem_is_safe() is a DENY LIST, so it has a residual tail by construction. These
# are the shapes a review actually produced; the list is not a structural
# guarantee and the docs must not claim one.
ss_band "cloak-phtm"     "$(srcset_score '/wp-content/uploads/2025/10/c99.phtm.jpg%20768w,' 220)" 75 100
ss_band "cloak-php-cgi"  "$(srcset_score '/wp-content/uploads/2025/10/x.php-cgi.jpg%20768w,' 220)" 75 100
# js / inc / cmd were REMOVED from the deny list in round 4, deliberately.
# "chart.js.jpg" and "three.js.jpg" are ordinary screenshot names, "Inc." is in
# every other business name, and .cmd is a Windows batch extension on a Linux
# WordPress fleet. None of them executes when the request ends in a srcset
# descriptor and the server serves a .jpg. Under the harm asymmetry -- a missed
# token costs intent-evidence, a wrong token bans a real person irreversibly --
# they are false-positive risks with no matching upside.
ss_band "real-name-js"   "$(srcset_score '/wp-content/uploads/2025/10/chart.js.jpg%20768w,' 220)" 0 49
ss_band "real-name-inc"  "$(srcset_score '/wp-content/uploads/2025/10/acme.inc.jpg%20768w,' 220)" 0 49
ss_band "real-name-cmd"  "$(srcset_score '/wp-content/uploads/2025/10/run.cmd.jpg%20768w,' 220)" 0 49
ss_band "cloak-jspx"     "$(srcset_score '/wp-content/uploads/2025/10/x.jspx.jpg%20768w,' 220)" 75 100
ss_band "cloak-ashx"     "$(srcset_score '/wp-content/uploads/2025/10/x.ashx.jpg%20768w,' 220)" 75 100
ss_band "cloak-shtml"    "$(srcset_score '/wp-content/uploads/2025/10/x.shtml.jpg%20768w,' 220)" 75 100
# NOT a cloak: an archive is neither executed nor a secret, and "backup.zip.jpg"
# is a plausible real upload. The deny list is scoped to extensions that would be
# EXECUTED or would leak a secret -- widening it past that banned real visitors.
ss_band "real-name-archive-component" "$(srcset_score '/wp-content/uploads/2025/10/backup.zip.jpg%20768w,' 220)" 0 49
ss_band "cloak-php5"     "$(srcset_score '/wp-content/uploads/2025/10/x.php5.jpg%20768w,' 220)" 75 100
ss_band "cloak-phar"     "$(srcset_score '/wp-content/uploads/2025/10/x.phar.jpg%20768w,' 220)" 75 100
# ...and the deny list must be applied to LATER candidates too, not only the first.
ss_band "cloak-later-candidate-php" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w,%20https://e.com/c99.php.jpg%20900w' 220)" 75 100
ss_band "cloak-later-candidate-phar" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w,%20https://e.com/x.phar.jpg%20900w' 220)" 75 100
# An empty element in the MIDDLE is not a candidate and must not be skipped.
ss_band "empty-middle-element-refused" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w,,%20https://e.com/p.jpg%20900w' 220)" 75 100

# --- the deny list must not ban REAL upload names (round 3) -----------------
# Scoping it to "anything that looks like an extension" temp-banned ordinary
# files. WordPress leaves these dots alone, so every one of these is a real name a
# visitor's client will request, and each scored 75 -- the same irreversible ladder
# that produced the original 19 residential temps.
ss_band "real-name-dot-bak"   "$(srcset_score '/wp-content/uploads/2025/10/photo.bak.jpg%20300w,' 220)" 0 49
ss_band "real-name-dot-old"   "$(srcset_score '/wp-content/uploads/2025/10/photo.old.jpg%20300w,' 220)" 0 49
ss_band "real-name-dot-tmp"   "$(srcset_score '/wp-content/uploads/2025/10/image.tmp.jpg%20300w,' 220)" 0 49
ss_band "real-name-dot-copy"  "$(srcset_score '/wp-content/uploads/2025/10/hero.copy.jpg%20300w,' 220)" 0 49
ss_band "real-name-dot-orig"  "$(srcset_score '/wp-content/uploads/2025/10/banner.orig.jpg%20300w,' 220)" 0 49
ss_band "real-name-dot-svg"   "$(srcset_score '/wp-content/uploads/2025/10/logo.svg.jpg%20300w,' 220)" 0 49
# A stem with NO dot cannot be a double extension at all, so the deny list must
# not look at it -- these short names were being banned on the bare token.
ss_band "real-name-bare-old"  "$(srcset_score '/wp-content/uploads/2025/10/old.jpg%20300w,' 220)" 0 49
ss_band "real-name-bare-tmp"  "$(srcset_score '/wp-content/uploads/2025/10/tmp.jpg%20300w,' 220)" 0 49
ss_band "real-name-bare-copy" "$(srcset_score '/wp-content/uploads/2025/10/copy.jpg%20300w,' 220)" 0 49
ss_band "real-name-bare-env"  "$(srcset_score '/wp-content/uploads/2025/10/env.jpg%20300w,' 220)" 0 49
# ...but a genuine double extension still scores, including the leading-dot form.
ss_band "cloak-still-wp-config" "$(srcset_score '/wp-content/uploads/2025/10/wp-config.php.jpg%20300w,' 220)" 75 100
ss_band "cloak-still-htaccess"  "$(srcset_score '/wp-content/uploads/2025/10/.htaccess.jpg%20300w,' 220)" 75 100
ss_band "cloak-still-dot-env"   "$(srcset_score '/wp-content/uploads/2025/10/secrets.env.jpg%20300w,' 220)" 75 100

# --- multi-digit PHP versions ------------------------------------------------
# php[0-9] matched one digit, so php81/php82/php74 -- the spellings a modern
# multi-PHP host actually uses -- sailed through while php5 was caught.
ss_band "cloak-php81" "$(srcset_score '/wp-content/uploads/2025/10/x.php81.jpg%20300w,' 220)" 75 100
ss_band "cloak-php82" "$(srcset_score '/wp-content/uploads/2025/10/x.php82.jpg%20300w,' 220)" 75 100
ss_band "cloak-php74" "$(srcset_score '/wp-content/uploads/2025/10/x.php74.jpg%20300w,' 220)" 75 100

# --- a COMPLETE final candidate at the 256 boundary must be fully validated ---
# candidate_prefix_ok() is a SUPERSET of complete candidates, so skipping the
# final element whenever it looked like a prefix let a finished attack candidate
# ride: the same tail scored 75 at 255 bytes and was exempt at 256. A final
# element that parses as a complete candidate is now held to the full check,
# stem_is_safe() included; only a genuinely incomplete one gets prefix treatment.
B256() { python3 -c "
import sys
h='/wp-content/uploads/2025/10/'; t='.jpg%20300w'; pay=sys.argv[1]
print(h + 'a'*(256-len(h)-len(t)-len(pay)) + t + pay)" "$1"; }
ss_band "trunc-256-complete-php-final"  "$(srcset_score "$(B256 ',/x.php.jpg%20300w')" 220)" 75 100
ss_band "trunc-256-complete-php8-final" "$(srcset_score "$(B256 ',/x.php8.jpg%20300w')" 220)" 75 100
# ...and a complete SAFE final candidate at the boundary stays exempt.
ss_band "trunc-256-complete-safe-final" "$(srcset_score "$(B256 ',/b.jpg%20300w')" 220)" 0 49

# --- ROUND 4: the truncation cut lands in the SCHEME, not the filename -------
# The round-2 truncation fix was tested at ONE offset. SS_LONG_FULL happens to cut
# mid-filename, so it never exercised the window where ingest lands on a partial
# "https" -- and a realistic 4-candidate srcset with a 20-character stem is ~354
# bytes and cuts exactly there. candidate_prefix_ok() rejected an incomplete
# scheme, so real visitors scored 75 at those offsets. Every cut point is pinned
# now, not one lucky one.
CUT() { python3 -c "
import sys
h='/wp-content/uploads/2025/10/'; t='.jpg%20300w,'; f=sys.argv[1]
print(h + 'a'*(256-len(h)-len(t)-len(f)) + t + f)" "$1"; }
for frag in '%20h' '%20ht' '%20htt' '%20http' '%20https' '%20https:' '%20https:/' '%20https://' '%20https://c' '%20https://cdn.example.com' '%20//cdn.example.com' '%20http://cdn.example.com'; do
    ss_band "trunc-cut-at-${frag//[^a-z0-9]/_}" "$(srcset_score "$(CUT "$frag")" 220)" 0 49
done
# ...and the whole realistic value, cut by ingest exactly as production would.
SS_REAL4="$(python3 -c "
stem='family-portrait-2024'
c=[('/wp-content/uploads/2025/10/%s-%dx%d.jpg %dw'%(stem,w,int(w*.75),w)) for w in (480,768,1024,1536)]
v=c[0]+', '+', '.join('https://cdn.example.com'+x for x in c[1:])
print(v.replace(' ','%20')[:256])")"
ss_band "real-4-candidate-truncated-exempt" "$(srcset_score "$SS_REAL4" 220)" 0 49

# --- ROUND 4: ordinary WORDS are not file extensions -------------------------
# The deny list banned real uploads for a third round running. These are all
# ordinary names: an animal, Portuguese "do", a noun, Poland, Shanghai, a
# conjunction, and three data/markup suffixes that execute nothing when the file
# is served as .jpg. The list is now scoped to unambiguous, high-signal tokens.
ss_band "real-name-bat"    "$(srcset_score '/wp-content/uploads/2025/10/the.bat.jpg%20300w,' 220)" 0 49
ss_band "real-name-do"     "$(srcset_score '/wp-content/uploads/2025/10/foto.do.evento.jpg%20300w,' 220)" 0 49
ss_band "real-name-key"    "$(srcset_score '/wp-content/uploads/2025/10/my.key.jpg%20300w,' 220)" 0 49
ss_band "real-name-pl"     "$(srcset_score '/wp-content/uploads/2025/10/warsaw.pl.jpg%20300w,' 220)" 0 49
ss_band "real-name-sh"     "$(srcset_score '/wp-content/uploads/2025/10/shanghai.sh.jpg%20300w,' 220)" 0 49
ss_band "real-name-so"     "$(srcset_score '/wp-content/uploads/2025/10/and.so.jpg%20300w,' 220)" 0 49
ss_band "real-name-html"   "$(srcset_score '/wp-content/uploads/2025/10/x.html.jpg%20300w,' 220)" 0 49
ss_band "real-name-json"   "$(srcset_score '/wp-content/uploads/2025/10/data.json.jpg%20300w,' 220)" 0 49
ss_band "real-name-xml"    "$(srcset_score '/wp-content/uploads/2025/10/chart.xml.jpg%20300w,' 220)" 0 49
# Percent-encoded UTF-8 is what a non-ASCII upload name looks like on the wire.
ss_band "real-http-scheme-candidate" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w,%20http://cdn.example.com/wp-content/uploads/2025/10/p.jpg%20900w' 220)" 0 49
ss_band "real-name-utf8"   "$(srcset_score '/wp-content/uploads/2025/10/caf%c3%a9-768x576.jpg%20300w,' 220)" 0 49

# --- ROUND 4: the cloaks that must still score ------------------------------
# Editor-backup and pool spellings evade an exact-match deny list.
ss_band "cloak-php-tilde"   "$(srcset_score '/wp-content/uploads/2025/10/c99.php~.jpg%20300w,' 220)" 75 100
ss_band "cloak-php-under"   "$(srcset_score '/wp-content/uploads/2025/10/x.php_.jpg%20300w,' 220)" 75 100
ss_band "cloak-php-backup"  "$(srcset_score '/wp-content/uploads/2025/10/x.php_backup.jpg%20300w,' 220)" 75 100
ss_band "cloak-php-fpm"     "$(srcset_score '/wp-content/uploads/2025/10/x.php-fpm.jpg%20300w,' 220)" 75 100
ss_band "cloak-later-tilde" "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w,%20https://e.com/x.php~.jpg%20900w' 220)" 75 100
# An INCOMPLETE final element at 256 must still be stem-checked. The round-3 fix
# only full-validated COMPLETE finals, so these rode straight through -- and
# badpaths.conf has no generic \.php rule, so nothing backstopped them.
ss_band "trunc-256-incomplete-c99-php"   "$(srcset_score "$(CUT '/c99.php')" 220)" 75 100
ss_band "trunc-256-incomplete-wp-config" "$(srcset_score "$(CUT '/wp-config.php')" 220)" 75 100
ss_band "trunc-256-incomplete-no-desc"   "$(srcset_score "$(CUT '/x.php.jpg')" 220)" 75 100
ss_band "trunc-256-incomplete-cut-desc"  "$(srcset_score "$(CUT '/x.php.jpg%20300')" 220)" 75 100
# wasm was unpinned; an executable module is exactly what the list is for.
ss_band "cloak-wasm" "$(srcset_score '/wp-content/uploads/2025/10/x.wasm.jpg%20300w,' 220)" 75 100

# --- ROUND 5: double-encoding evades a substring guard ----------------------
# Admitting '%' into the stem (needed for percent-encoded UTF-8 names) meant the
# only thing refusing an encoded dot was the substring guard on %2e/%2f. "%252e"
# does not CONTAIN "%2e" -- it is % 2 5 2 e -- and a stem with no literal dot never
# reaches the deny list at all. Works at ANY length, not just the 256 boundary.
ss_band "cloak-double-encoded-php"    "$(srcset_score '/wp-content/uploads/2025/10/x%252ephp.jpg%20300w,' 220)" 75 100
ss_band "cloak-double-encoded-config" "$(srcset_score '/wp-content/uploads/2025/10/wp-config%252ephp.jpg%20300w,' 220)" 75 100
ss_band "cloak-double-encoded-env"    "$(srcset_score '/wp-content/uploads/2025/10/x%252eenv.jpg%20300w,' 220)" 75 100
ss_band "cloak-double-encoded-slash"  "$(srcset_score '/wp-content/uploads/2025/10/x%252fetc.jpg%20300w,' 220)" 75 100
ss_band "cloak-encoded-nul"           "$(srcset_score '/wp-content/uploads/2025/10/x%00php.jpg%20300w,' 220)" 75 100
# ...while a genuine percent-encoded UTF-8 name is still exempt.
ss_band "real-name-utf8-still-exempt" "$(srcset_score '/wp-content/uploads/2025/10/caf%c3%a9-768x576.jpg%20300w,' 220)" 0 49

# --- ROUND 5: ordinary words, and the WordPress thumbnail suffix ------------
# conf/jar/war/shadow are ordinary English, and the blanket suffix strip added in
# round 4 ate WordPress's own -WIDTHxHEIGHT and then matched the leftover: an
# upload named mens.conf.jpg becomes mens.conf-768x576.jpg in every srcset.
ss_band "real-name-conf-thumb"  "$(srcset_score '/wp-content/uploads/2025/10/mens.conf-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-conf"        "$(srcset_score '/wp-content/uploads/2025/10/mens.conf.jpg%20300w,' 220)" 0 49
ss_band "real-name-conf-scaled" "$(srcset_score '/wp-content/uploads/2025/10/youth.conf-scaled.jpg%201024w,' 220)" 0 49
ss_band "real-name-jar"         "$(srcset_score '/wp-content/uploads/2025/10/cookie.jar.jpg%20300w,' 220)" 0 49
ss_band "real-name-jar-thumb"   "$(srcset_score '/wp-content/uploads/2025/10/mason.jar-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-war-thumb"   "$(srcset_score '/wp-content/uploads/2025/10/civil.war-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-shadow"      "$(srcset_score '/wp-content/uploads/2025/10/my.shadow-768x576.jpg%20768w,' 220)" 0 49

# --- ROUND 5: ...but the WP suffix must not HIDE a cloak either -------------
# The same single sub() that detonated conf-768x576 failed to reach php-cgi:
# it stripped only the dimensions and left a token that is not an exact match.
# Stripping is now iterative over WELL-DEFINED WordPress/editor forms only.
ss_band "cloak-php-cgi-thumb"    "$(srcset_score '/wp-content/uploads/2025/10/x.php-cgi-768x576.jpg%20768w,' 220)" 75 100
ss_band "cloak-php-fpm-thumb"    "$(srcset_score '/wp-content/uploads/2025/10/c99.php-fpm-768x576.jpg%20768w,' 220)" 75 100
ss_band "cloak-php-backup-thumb" "$(srcset_score '/wp-content/uploads/2025/10/x.php_backup-768x576.jpg%20768w,' 220)" 75 100
ss_band "cloak-php-scaled"       "$(srcset_score '/wp-content/uploads/2025/10/x.php-scaled.jpg%201024w,' 220)" 75 100
# Stripping must ITERATE, not run once: a variant suffix sitting BEFORE the
# dimensions re-exposes a dimension suffix after it is removed, so one pass leaves
# "php-768x576" and the token is never reached.
ss_band "cloak-php-variant-before-dims" \
  "$(srcset_score '/wp-content/uploads/2025/10/x.php-768x576-backup.jpg%20768w,' 220)" 75 100
# ...and stripping must stay targeted: an ordinary hyphenated word is NOT a suffix.
ss_band "real-name-conf-room"    "$(srcset_score '/wp-content/uploads/2025/10/my.conf-room-768x576.jpg%20768w,' 220)" 0 49

# --- ROUND 6: a deny token in the FIRST component is not a double extension --
# Found by sweeping 62,700 generated WordPress-realistic names through the real
# predicate: 8,316 of 18,216 refusals (46%) were refused ONLY because the first
# dot-component happened to be a deny token. A cloak puts the dangerous token
# immediately before the real extension ("wp-config.php.jpg"); a LEADING "cfg." or
# "env." is just a name prefix and the file is still a .jpg. The deny list now
# skips component 1, which is what its own stated purpose implies.
ss_band "real-name-leading-cfg"  "$(srcset_score '/wp-content/uploads/2025/10/cfg.autumn-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-leading-sql"  "$(srcset_score '/wp-content/uploads/2025/10/sql.report-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-leading-py"   "$(srcset_score '/wp-content/uploads/2025/10/py.workshop.jpg%20768w,' 220)" 0 49
# ...and every genuine cloak, where the token sits in the extension position, still scores.
ss_band "cloak-still-wp-config-2" "$(srcset_score '/wp-content/uploads/2025/10/wp-config.php.jpg%20768w,' 220)" 75 100
ss_band "cloak-still-htaccess-2"  "$(srcset_score '/wp-content/uploads/2025/10/.htaccess.jpg%20768w,' 220)" 75 100
ss_band "cloak-still-trailing-env" "$(srcset_score '/wp-content/uploads/2025/10/secrets.e'"'"'nv.jpg%20768w,' 220)" 75 100
ss_band "real-name-pen-pal"      "$(srcset_score '/wp-content/uploads/2025/10/the.pen-pal-768x576.jpg%20768w,' 220)" 0 49

# --- ROUND 7: short/ordinary words still on the deny list --------------------
# The comment names the rule (unambiguous extensions AND rarely ordinary words;
# short words and inert data suffixes are OUT) while the list still carried py
# (Paraguay ccTLD — same class as the pl round 4 removed), rb, ini, cnf, cfm, crt.
ss_band "real-name-py-cctld"  "$(srcset_score '/wp-content/uploads/2025/10/asuncion.py-768x576.jpg%20768w,' 220)" 0 49
ss_band "real-name-rb"        "$(srcset_score '/wp-content/uploads/2025/10/logo.rb.jpg%20300w,' 220)" 0 49
ss_band "real-name-ini"       "$(srcset_score '/wp-content/uploads/2025/10/foto.ini.jpg%20300w,' 220)" 0 49
# cnf/cfm/crt are unambiguous secret/executable extensions, not ordinary words.
# my.cnf is the canonical MySQL credentials filename.
ss_band "cloak-my-cnf"        "$(srcset_score '/wp-content/uploads/2025/10/my.cnf.jpg%20300w,' 220)" 75 100
ss_band "cloak-cfm"           "$(srcset_score '/wp-content/uploads/2025/10/notes.cfm.jpg%20300w,' 220)" 75 100
ss_band "cloak-crt"           "$(srcset_score '/wp-content/uploads/2025/10/tv.crt.jpg%20300w,' 220)" 75 100
# passwd was an unpinned deny token: removing it from _deny_token left the suite
# green. A cloak named x.passwd.jpg must still score.
ss_band "cloak-passwd"        "$(srcset_score '/wp-content/uploads/2025/10/x.passwd.jpg%20300w,' 220)" 75 100

# --- ROUND 5: the cut can land INSIDE the inter-candidate separator ---------
# Between candidates the logged form is ",%20https://...". A cut on the first or
# second byte of that %20 leaves a tail of exactly "%" or "%2", which the prefix
# check refused -- the round-4 scheme-cut bug one byte earlier.
ss_band "trunc-cut-torn-pct"   "$(srcset_score "$(CUT '%')" 220)" 0 49
ss_band "trunc-cut-torn-pct2"  "$(srcset_score "$(CUT '%2')" 220)" 0 49
# A torn escape is only benign when it IS the whole tail; anything after it is not
# a truncation artifact and must not ride in on this allowance.
ss_band "trunc-torn-pct-with-payload" "$(srcset_score "$(CUT '%/etc/passwd')" 220)" 75 100
ss_band "trunc-torn-pct-nul"          "$(srcset_score "$(CUT '%00')" 220)" 75 100

# A SINGLE candidate cut at the boundary had no prefix path at all: it was held to
# the full end-anchored match it cannot satisfy, so it scored. Percent-encoded CJK
# or accented stems inflate ~3x, so real names reach this length.
SS_ONE_LONG="$(python3 -c "
h='/wp-content/uploads/2025/10/'
print((h + 'sommerfest-familienportraet-' + 'a'*200 + '-768x576.jpg%20768w')[:256])")"
ss_band "trunc-single-candidate-exempt" "$(srcset_score "$SS_ONE_LONG" 220)" 0 49
# ...but it must still prove it began as this shape, and still be stem-checked.
ss_band "trunc-single-not-uploads-tree" \
  "$(srcset_score "$(python3 -c "print(('/wp-admin/includes/' + 'a'*240 + '.jpg%20768w')[:256])")" 220)" 75 100
# The stem check still applies to a truncated single candidate. Note the payload
# must contain a genuine denied COMPONENT: "php-aaaa" is not one ("php-cgi" and
# "php-fpm" are in the variant list because they are real handler names, an
# arbitrary "php-<junk>" is not), so an earlier version of this test asserted a
# cloak that was never a cloak.
ss_band "trunc-single-unsafe-stem" \
  "$(srcset_score "$(python3 -c "
h='/wp-content/uploads/2025/10/'
print((h + 'wp-config.php.' + 'a'*205 + '-768x576.jpg%20768w')[:256])")" 220)" 75 100

# --- ROUND 7: + is a legal srcset separator, including at the 256 cut ------
# candidate_prefix_ok admitted % in the final token but omitted +, while every
# complete-candidate predicate treats (%20|\+| ) as three equal spellings. A
# truncation landing on the + spelling of the descriptor scored a real visitor.
# Bare-space cases are unreachable (ingest splits the request line on space) and
# are still accepted here so the function does not depend on its caller.
PAD256() { python3 -c "
import sys
h='/wp-content/uploads/2025/10/'
s=sys.argv[1]
print(h + 'a'*(256-len(h)-len(s)) + s)" "$1"; }
ss_band "trunc-256-plus-sep-jpg-plus"    "$(srcset_score "$(PAD256 '.jpg+')" 220)" 0 49
ss_band "trunc-256-plus-sep-jpg-plus-9"  "$(srcset_score "$(PAD256 '.jpg+9')" 220)" 0 49
ss_band "trunc-256-pct20-sep-jpg-pct20"  "$(srcset_score "$(PAD256 '.jpg%20')" 220)" 0 49
ss_band "trunc-256-pct20-sep-jpg-pct209" "$(srcset_score "$(PAD256 '.jpg%209')" 220)" 0 49
PLUS_CUT() { python3 -c "
import sys
h='/wp-content/uploads/2025/10/'; t='.jpg+300w,'; f=sys.argv[1]
print(h + 'a'*(256-len(h)-len(t)-len(f)) + t + f)" "$1"; }
ss_band "trunc-256-plus-cut-jpg-plus"    "$(srcset_score "$(PLUS_CUT '/p.jpg+')" 220)" 0 49
ss_band "trunc-256-plus-cut-jpg-plus-9"  "$(srcset_score "$(PLUS_CUT '/p.jpg+9')" 220)" 0 49
# Admitting + in the prefix class let a deny token hide behind a trailing
# separator: wp-config.php+ parsed as a safe stem because "php+" is not "php".
# badpaths.conf has no generic \.php rule.
ss_band "trunc-256-plus-cut-wp-config-php-plus" "$(srcset_score "$(PLUS_CUT '/wp-config.php+')" 220)" 75 100
ss_band "trunc-256-plus-cut-c99-php-plus"       "$(srcset_score "$(PLUS_CUT '/c99.php+')" 220)" 75 100
ss_band "trunc-256-plus-sep-wp-config-php-plus" "$(srcset_score "$(PAD256 'wp-config.php+')" 220)" 75 100

# Later-candidate hosts are scheme+host (`https://`, `https:/` edge-collapse,
# `http://`) or protocol-relative `//host`. A path-only `/wp-config.php/x.jpg`
# must not parse as a host (dots legal in a host, illegal in a directory).
ss_band "later-path-dots-not-a-host" \
  "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w,/wp-config.php/x.jpg%20300w' 220)" 75 100

# Descriptor-less first candidates are legal HTML (`logo.png, logo@2x.png 2x`)
# and are NOT exempt: every candidate regex requires a descriptor. Making the
# descriptor optional would exempt every missing WP upload (pinned below as
# mutant-descriptor-required). Documented, not widened.
ss_band "descriptor-less-first-candidate-not-exempt" \
  "$(srcset_score '/wp-content/uploads/2025/10/logo.png,%20/wp-content/uploads/2025/10/logo@2x.png%202x' 220)" 75 100

# n==1 truncated branch: uploads-tree + prefix + stem, no image extension
# required. Wider than a complete candidate; contained by the dot-free
# directory rule.
ss_band "trunc-single-no-image-ext" \
  "$(srcset_score "$(python3 -c "
h='/wp-content/uploads/2025/10/'
print(h + 'a'*(256-len(h)))")" 220)" 0 49

# Re-sweep the 256-byte cut at every offset of a well-formed + -separated
# later candidate, and of the %20 spelling, and of a single-candidate
# descriptor. Rounds 4, 5 and 6 each found a distinct FP at a different
# offset of this area. One gawk run; any IP that scores is a new FP.
python3 - "$tmp/plus_sweep.tsv" "$NOW_EPOCH" <<'PY'
import sys
out, now = sys.argv[1], int(sys.argv[2])
head = '/wp-content/uploads/2025/10/'
first_end = '.jpg+300w,'
seconds = [
    'https://cdn.example.com/wp-content/uploads/2025/10/photo-900.jpg+900w',
    '%20https://cdn.example.com/wp-content/uploads/2025/10/photo-900.jpg%20900w',
    '/photo-900.jpg+900w',
]
nreq = 120
idx = 0
with open(out, 'w') as f:
    def emit(path):
        global idx
        idx += 1
        ip = '198.51.{}.{}'.format(1 + idx // 250, 1 + idx % 250)
        for i in range(nreq):
            f.write('%s\t%s\tGET\t%s\t404\t-\tMozilla/5.0\texample.com\n' %
                    (ip, now - 300 + i, path))
        return ip
    ips = []
    for second in seconds:
        for n in range(0, len(second) + 1):
            frag = second[:n]
            pad = 256 - len(head) - len(first_end) - len(frag)
            if pad < 1:
                continue
            path = head + ('a' * pad) + first_end + frag
            assert len(path) == 256, (len(path), path[-20:])
            ips.append(emit(path))
    # single-candidate: cut through the +descriptor
    for n in range(0, len('+300w') + 1):
        s = '.jpg' + '+300w'[:n]
        pad = 256 - len(head) - len(s)
        path = head + ('a' * pad) + s
        assert len(path) == 256
        ips.append(emit(path))
    # ips counted only to build the TSV; gawk reports scoring IPs.
PY
SWEEP_HITS="$(gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
     -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
     -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
     -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
     -f "${ROOT}/lib/score.awk" "$tmp/plus_sweep.tsv" | awk -F'\t' '$2+0>=50{c++} END{print c+0}')"
if [[ "$SWEEP_HITS" == "0" ]]; then
    printf 'PASS  %-30s scoring-IPs=0\n' "trunc-256-plus-every-offset"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s scoring-IPs=%s (want 0)\n' "trunc-256-plus-every-offset" "$SWEEP_HITS"; FAIL=$((FAIL+1))
fi

# --- THE UNCONSTRAINED TAIL -------------------------------------------------
# ^/ anchored the START; nothing anchored the END. Once the alternation took the
# ',' branch, the whole remainder of the path was unvalidated, so any target could
# ride behind a valid srcset head. badpaths.conf carries NO '..' or %2e pattern,
# so path_scores_on_its_own() is blind to traversal and these were dropped at
# every status -- verified at 200, where the server normalizes the .. and serves
# the real target. The match is now end-anchored over the WHOLE candidate list.
ss_band "tail-traversal-etc-passwd" "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w,/../../../../etc/passwd' 220)" 75 100
ss_band "tail-traversal-encoded"    "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w,/%2e%2e/%2e%2e/wp-admin/' 220)" 75 100
ss_band "tail-traversal-wp-login"   "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w,/../../../wp-login.php' 220)" 75 100
ss_band "tail-arbitrary-junk"       "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w,anything-at-all' 220)" 75 100

# --- pins for mutants that survived the first round -------------------------
# Each of these stayed 49/49 green while changing real behavior.
# M2b: making the descriptor optional would exempt EVERY missing WP upload.
ss_band "mutant-descriptor-required" "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg' 220)" 75 100
# M1: adding php to the extension list would exempt a bare webshell probe.
ss_band "mutant-php-not-an-image"    "$(srcset_score '/wp-content/uploads/2025/10/backdoor.php%20768w,' 220)" 75 100
# M4: widening the dir class to admit % would relaunder encoded dots.
ss_band "mutant-encoded-dot-dir"     "$(srcset_score '/wp-content/uploads/2025/10/foo%2ebar/x.jpg%20768w,' 220)" 75 100
# NOTE this must still contain uploads/YYYY/MM/, or it fails the prefilter for an
# unrelated reason and pins nothing -- the first version of this test did exactly
# that and let the prefix-dir mutant survive.
ss_band "mutant-encoded-dot-prefix"  "$(srcset_score '/%2egit/uploads/2025/10/x.jpg%20768w,' 220)" 75 100
# %2c IS a comma. If it is not normalised before the split, the tail after an
# encoded comma escapes candidate validation entirely.
ss_band "mutant-encoded-comma-tail"  "$(srcset_score '/wp-content/uploads/2025/10/a.jpg%20300w%2c/../../../etc/passwd' 220)" 75 100
ss_band "encoded-comma-real-shape-exempt" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w%2c%20https://e.com/p.jpg%20900w' 220)" 0 49
# The extensions the class actually uses must STAY exempt (nothing pinned these).
ss_band "ext-jpeg-exempt" "$(srcset_score '/wp-content/uploads/2025/10/photo.jpeg%20768w,%20https://e.com/p.jpeg%20900w' 220)" 0 49
ss_band "ext-webp-exempt" "$(srcset_score '/wp-content/uploads/2025/10/photo.webp%20768w,%20https://e.com/p.webp%20900w' 220)" 0 49
ss_band "ext-avif-exempt" "$(srcset_score '/wp-content/uploads/2025/10/photo.avif%20768w,%20https://e.com/p.avif%20900w' 220)" 0 49
ss_band "ext-png-exempt"  "$(srcset_score '/wp-content/uploads/2025/10/photo.png%20768w,%20https://e.com/p.png%20900w' 220)" 0 49

# --- the widened shape must NOT launder a dot through the new nesting -------
# uploads/YYYY/MM/ now admits intermediate dirs; they must stay dot-free for the
# same reason the prefix segments do, and multisite must not become a new prefix.
ss_band "bypass-nested-dotfile"    "$(srcset_score '/wp-content/uploads/2025/10/.env/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-nested-git-config" "$(srcset_score '/wp-content/uploads/2025/10/.git/config.jpg%20300w,' 220)" 75 100
ss_band "bypass-multisite-dotfile" "$(srcset_score '/wp-content/uploads/sites/2/2025/10/.env/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-multisite-nonnumeric" "$(srcset_score '/wp-content/uploads/sites/.env/2025/10/x.jpg%20300w,' 220)" 75 100
# ...and the same for the multisite blog id: '.env' above is ALSO a badpath, so it
# would still be refused if [0-9]+ were loosened. 'foo' is in no badpath pattern,
# so only the numeric class can refuse it. (Second hole found by mutation.)
ss_band "bypass-multisite-id-not-numeric" \
  "$(srcset_score '/wp-content/uploads/sites/foo/2025/10/x.jpg%20300w,' 220)" 75 100
# The dot refusal is STRUCTURAL, and these pin it as such. Every other bypass case
# here carries a segment the badpath table also catches (.env, .git, .php), so they
# would still pass if the dir class were loosened to admit dots -- mutation testing
# found exactly that hole. These segments are in NO badpath pattern, so the regex
# is the only thing that can refuse them, on both sides of uploads/YYYY/MM/.
ss_band "bypass-nested-dot-not-badpath" \
  "$(srcset_score '/wp-content/uploads/2025/10/foo.bar/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-prefix-dot-not-badpath" \
  "$(srcset_score '/foo.bar/uploads/2025/10/x.jpg%20300w,' 220)" 75 100
# A bad path is never exempted at ANY status, now that status no longer gates.
ss_band "bypass-badpath-at-301"    "$(srcset_score '/.env/uploads/2025/10/x.jpg%20300w,' 220 301)" 75 100
ss_band "bypass-honeypot-at-301"   "$(srcset_score '/__trap_a7f3c1d9/uploads/2025/10/x.jpg%20300w,' 220 301)" 90 100

# --- the bypasses both models found in the first version of this fix --------
# Each of these must STILL score. Named for the reviewer that supplied them.
ss_band "bypass-badpath-prefix-dotfile"     "$(srcset_score '/.env/uploads/2025/10/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-git-config-prefix"          "$(srcset_score '/.git/config/uploads/2025/10/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-honeypot-prefix"            "$(srcset_score '/__trap_a7f3c1d9/uploads/2025/10/x.jpg%20300w,' 220)" 90 100
ss_band "bypass-pathinfo-index-php"         "$(srcset_score '/index.php/uploads/2025/10/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-scanner-html-prefix"        "$(srcset_score '/scan/path-1.html/uploads/2025/10/x.jpg%20300w,' 220)" 75 100
ss_band "bypass-shell-php-jpg"              "$(srcset_score '/wp-content/uploads/2025/10/shell.php.jpg%20768w,' 220)" 75 100
ss_band "bypass-trailing-dotenv"            "$(srcset_score '/uploads/2025/10/x.jpg%20300w,/.env' 220)" 75 100
ss_band "bypass-traversal-to-dotenv"        "$(srcset_score '/uploads/2025/10/../../../.env.jpg%20300w,' 220)" 75 100
# The independent-substring hole: ext and descriptor must be ADJACENT.
ss_band "bypass-nonadjacent-descriptor"     "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg,foo%20300w,' 220)" 75 100

# --- controls: ordinary detection is untouched ------------------------------
ss_band "plain-404-storm-still-scores"      "$(srcset_score '/nope-page' 220)" 75 100
ss_band "bare-critical-badpath-still-floors" "$(srcset_score '/.env' 2)" 90 100
ss_band "bare-honeypot-still-floors"        "$(srcset_score '/__trap_a7f3c1d9' 2)" 90 100

# ...and the exemption is NEUTRAL, never a shield: a real probe run scores the
# same padded or not. This is why the exempted request is dropped BEFORE reqs[]
# rather than merely kept out of cerr[] -- err_ratio is nerr/n, so counting
# padding in n while excluding it from nerr would be a dilution lever.
: > "$tmp/probe_only.log"
emit_spread "$tmp/probe_only.log" "203.0.113.81" "GET /nope-page HTTP/1.1" 404 "curl/8.0" 120
BARE="$(score_of example.com "$tmp/probe_only.log")"
: > "$tmp/probe_padded.log"
PAD='/wp-content/uploads/2025/10/photo-768x576.jpg%20768w,%20https://example.com/photo-900x675.jpg%20900w'
emit_spread "$tmp/probe_padded.log" "203.0.113.82" "GET /nope-page HTTP/1.1" 404 "curl/8.0" 120
emit_spread "$tmp/probe_padded.log" "203.0.113.82" "GET ${PAD} HTTP/1.1" 404 "curl/8.0" 440
PADDED="$(score_of example.com "$tmp/probe_padded.log")"
ss_band "probe-run-still-scores-when-padded" "$PADDED" 75 100
if [[ "$BARE" == "$PADDED" ]]; then
    printf 'PASS  %-30s padding is neutral (both %s)\n' "srcset-padding-is-neutral" "$BARE"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s bare=%s padded=%s\n' "srcset-padding-is-neutral" "$BARE" "$PADDED"; FAIL=$((FAIL+1))
fi

# --- THE TRIPWIRE MUST NEVER BE ABLE TO BAN A VISITOR ------------------------
# The first version of the tripwire used >= 60 exempted requests at >= RATE_SAT,
# and justified it as "~1300x above the heaviest real client (544/day, 0.006 rps)".
# That compared a DAILY AVERAGE against a BURST rate and they are not the same
# quantity. The tripwire measures burst span (last_sr - first_sr), and the real
# defect class IS a burst: one image-heavy page makes a Chromium client fetch every
# srcset on it at once. Measured: 70 gallery images in 5s scored 75 -- a TEMP on a
# visitor who loaded ONE page, three of which is a permanent AbuseIPDB report.
#
# A rate tripwire on this shape will always hit gallery bursts, so it must not be
# able to act. It now tops out at SCORE_WATCH, which the config defines as
# "log + count, no action", and the threshold is raised far above any page load.
ss_band "gallery-burst-70-in-5s-not-temped"   "$(srcset_burst 70 5)" 0 49
ss_band "gallery-burst-200-in-10s-not-temped" "$(srcset_burst 200 10)" 0 49
ss_band "gallery-burst-400-in-20s-not-temped" "$(srcset_burst 400 20)" 0 49
# A real DoS in this shape still surfaces -- at WATCH level, never a temp.
ss_band "srcset-dos-surfaces-at-watch-only"   "$(srcset_burst 3000 30)" 50 69
RULE2="$(srcset_burst_rule 3000 30)"
if [[ "$RULE2" == "srcset_flood" ]]; then
    printf 'PASS  %-30s decisive_rule=%s\n' "srcset-dos-rule-attributed" "$RULE2"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s decisive_rule=%s (want srcset_flood)\n' "srcset-dos-rule-attributed" "$RULE2"; FAIL=$((FAIL+1))
fi
# ...and it must be counted for a MIXED client too, not just a srcset-only one.
# The first version seeded reqs[] only when the IP had none, and the n < MIN_REQS
# guard ran before the floor, so 10 ordinary requests disabled the tripwire.
ss_band "srcset-dos-counted-for-mixed-client" "$(srcset_burst_mixed 3000 30 10)" 50 100

# Raising SCORE_WATCH above a genuine floor must not let srcset_flood overwrite
# that floor's rule or lift its score. Safe at the shipped default (50); the
# first version overstated "never an override".
: > "$tmp/sw80.tsv"
for i in $(seq 1 80); do
    printf '198.51.100.31\t%s\tGET\t/page-%s\t200\t-\tMozilla/5.0\texample.com\n' \
        $(( NOW_EPOCH - 10 + (i % 8) )) "$i" >> "$tmp/sw80.tsv"
done
for i in $(seq 1 500); do
    printf '198.51.100.31\t%s\tGET\t/wp-content/uploads/2025/10/g%s-768x576.jpg%%20768w,%%20https://e.com/g%s-900.jpg%%20900w\t404\t-\tMozilla/5.0\texample.com\n' \
        $(( NOW_EPOCH - 20 + (i * 20 / 500) )) "$i" "$i" >> "$tmp/sw80.tsv"
done
SW80="$(gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=80 \
     -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
     -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
     -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
     -f "${ROOT}/lib/score.awk" "$tmp/sw80.tsv" | head -1)"
SW80_SCORE="$(printf '%s' "$SW80" | cut -f2)"
SW80_RULE="$(printf '%s' "$SW80" | grep -o '"decisive_rule":"[^"]*"' | cut -d'"' -f4)"
# SCORE_WATCH=80 hides a 75 request_flood (score < watch is dropped). The
# defect was lifting that 75 to 80 and relabeling it srcset_flood. Either
# no row, or request_flood at 75, is fine; a srcset_flood row at 80 is not.
if [[ "$SW80_RULE" == "srcset_flood" || "$SW80_SCORE" == "80" ]]; then
    printf 'FAIL  %-30s score=%s rule=%s (must not lift/relabel a genuine floor)\n' \
        "srcset-flood-does-not-override-floor" "${SW80_SCORE:-NONE}" "$SW80_RULE"
    FAIL=$((FAIL+1))
else
    printf 'PASS  %-30s score=%s rule=%s\n' \
        "srcset-flood-does-not-override-floor" "${SW80_SCORE:-NONE}" "${SW80_RULE:-none}"
    PASS=$((PASS+1))
fi

# --- REAL LONG srcset VALUES SURVIVE INGEST TRUNCATION -----------------------
# lib/ingest.sh:72 truncates the path at 256 bytes. End-anchoring every candidate
# meant a REAL 5-candidate value (461 bytes here) was cut mid-candidate, failed
# validation, and scored 75 as an ordinary 404 storm -- a false positive created by
# the end-anchor fix itself. When the path is at the truncation boundary the final
# candidate is incomplete by construction, so it is not held to the end anchor;
# every COMPLETE candidate still is, and at least one is required.
ss_band "real-long-srcset-truncated-still-exempt" "$(srcset_score "$SS_LONG_TRUNC" 220)" 0 49

# ...but tolerating truncation must not hand the tail bypass back. ingest only
# truncates when length > 256, so a path arriving at EXACTLY 256 is indistinguishable
# from a truncated one -- and the first version of this tolerance simply skipped the
# final candidate, so an attacker padded to exactly 256 and rode again. Measured:
# the same traversal scored 75 at 255 bytes and was DROPPED at 256.
# The final incomplete candidate is therefore not ignored: it must still be a valid
# PREFIX of a well-formed candidate. A cut-off real URL is; "/../../../etc/passwd"
# is not, because its segments carry dots.
SS_B256="$(python3 -c "
head='/wp-content/uploads/2025/10/'; tail='.jpg%20300w'; pay=',/../../../../etc/passwd'
print(head + 'a'*(256-len(head)-len(tail)-len(pay)) + tail + pay)")"
ss_band "truncation-boundary-256-tail-refused" "$(srcset_score "$SS_B256" 220)" 75 100
ss_band "truncation-boundary-255-tail-refused" "$(srcset_score "${SS_B256/aaa/aa}" 220)" 75 100
# ...and the prefix check must refuse a COMPLETE encoded dot/slash in that tail,
# which is the same cloak wearing the truncation boundary instead of the stem.
# The payload must be one the STRUCTURAL prefix check would otherwise accept --
# a single final token, no extra segments -- or the test passes on the structure
# and pins nothing. (First version of this test did exactly that.)
SS_B256E="$(python3 -c "
head='/wp-content/uploads/2025/10/'; tail='.jpg%20300w'; pay=',/x%2fetc%2fpasswd'
print(head + 'a'*(256-len(head)-len(tail)-len(pay)) + tail + pay)")"
ss_band "truncation-boundary-encoded-tail-refused" "$(srcset_score "$SS_B256E" 220)" 75 100

# --- the evidence field is part of the contract; pin its NAME and its count ---
# It only appears for an IP that scores on its OTHER traffic, because END walks
# reqs[] and a srcset-only client deliberately has no reqs[] entry.
: > "$tmp/ev.tsv"
for i in $(seq 1 60); do
  printf '203.0.113.90\t%s\tGET\t/nope-%s\t404\t-\tcurl/8.0\texample.com\n' \
    $(( NOW_EPOCH - 300 + i )) $(( i % 30 )) >> "$tmp/ev.tsv"
done
for i in $(seq 1 7); do
  printf '203.0.113.90\t%s\tGET\t%s\t404\t-\tcurl/8.0\texample.com\n' \
    $(( NOW_EPOCH - 200 + i )) "$SS_REAL" >> "$tmp/ev.tsv"
done
EV="$(gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
   -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
   -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
   -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
   -f "${ROOT}/lib/score.awk" "$tmp/ev.tsv" | head -1 | grep -o '"srcset_exempt":[0-9]*')"
if [[ "$EV" == '"srcset_exempt":7' ]]; then
    printf 'PASS  %-30s %s\n' "evidence-srcset-exempt-count" "$EV"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s got=%s (want "srcset_exempt":7)\n' "evidence-srcset-exempt-count" "${EV:-MISSING}"; FAIL=$((FAIL+1))
fi

# --- 2: wp-login.php credential brute (HIGH bad-path, repeated, POST) --------
: > "$tmp/wpbrute.log"
emit_spread "$tmp/wpbrute.log" "45.146.165.10" "POST /wp-login.php HTTP/1.1" 200 "python-requests/2.31" 60
assert_band "wp-login-brute" "$(score_of example.com "$tmp/wpbrute.log")" 80 100

# --- 3: CRITICAL secret-file probe (/.env, /.git) -> floored >=90 -----------
: > "$tmp/envprobe.log"
emit_spread "$tmp/envprobe.log" "185.220.101.5" "GET /.env HTTP/1.1" 404 "curl/8.0" 1
emit_spread "$tmp/envprobe.log" "185.220.101.5" "GET /.git/config HTTP/1.1" 404 "curl/8.0" 1
assert_band "env-secret-probe" "$(score_of example.com "$tmp/envprobe.log")" 90 100

# --- 4: path scanner — broad distinct 404 fanout, bot UA --------------------
: > "$tmp/scanner.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/scanner.log" "104.152.52.20" "GET /scan/path-$i.html HTTP/1.1" 404 "Go-http-client/1.1" 1
done
assert_band "path-scanner" "$(score_of example.com "$tmp/scanner.log")" 70 100

# --- 403 is our answer, not their probe (CI / challenged-visitor loop) ------
# Same shape as path-scanner (80 distinct paths, 300s) but answered 403.
# Today that is scanner_profile 78 -- the challenge promoting the client.
# After the drop it must produce no row.
: > "$tmp/own403.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403.log" "203.0.113.40" "GET /assets/file-$i.css HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-not-scanner" "$(score_of example.com "$tmp/own403.log")" 0 49
# One-dot /assets/file-N.css is not the fleet. jquery.min.js / dashicons.min.css
# / logo@2x.png are. A challenged WP page of those must not promote.
: > "$tmp/own403min.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403min.log" "203.0.113.60" "GET /wp-includes/js/jquery/jquery-$i.min.js HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-minjs-not-scanner" "$(score_of example.com "$tmp/own403min.log")" 0 49
: > "$tmp/own403mincss.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403mincss.log" "203.0.113.61" "GET /wp-includes/css/dashicons-$i.min.css HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-mincss-not-scanner" "$(score_of example.com "$tmp/own403mincss.log")" 0 49
: > "$tmp/own403at2x.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403at2x.log" "203.0.113.62" "GET /wp-content/uploads/2025/10/logo-$i@2x.png HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-at2x-not-scanner" "$(score_of example.com "$tmp/own403at2x.log")" 0 49
: > "$tmp/own403hash.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403hash.log" "203.0.113.64" "GET /static/js/app-$i.a3f9c2b1.js HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-hashed-not-scanner" "$(score_of example.com "$tmp/own403hash.log")" 0 49
: > "$tmp/own403map.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403map.log" "203.0.113.65" "GET /static/js/app-$i.js.map HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-map-not-scanner" "$(score_of example.com "$tmp/own403map.log")" 0 49

# Claude HOLD B1: 60 asset 200s in 5s plus 50 challenged .css retries over
# ~5 minutes must NOT collapse into request_flood. The 403 timestamps have
# to stay in the span even though they leave n.
: > "$tmp/403span.tsv"
for i in $(seq 1 60); do
    printf '203.0.113.46\t%s\tGET\t/assets/ok-%s.css\t200\t-\tMozilla/5.0\texample.com\n' \
        $(( NOW_EPOCH - 300 + (i % 5) )) "$i" >> "$tmp/403span.tsv"
done
for i in $(seq 1 50); do
    printf '203.0.113.46\t%s\tGET\t/assets/retry-%s.css\t403\t-\tMozilla/5.0\texample.com\n' \
        $(( NOW_EPOCH - 290 + i*5 )) "$i" >> "$tmp/403span.tsv"
done
assert_band "403-drop-does-not-collapse-span" "$(
    gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
         -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
         -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
         -v BADPATHS="${ROOT}/config/badpaths.conf" \
         -f "${ROOT}/lib/score.awk" "$tmp/403span.tsv" \
      | awk -F'\t' 'NR==1{print $2; f=1} END{if(!f) print "NONE"}'
)" 0 49

# Claude HOLD B2: srcset-shaped 403s still feed the volume tripwire.
# Attribution must stay srcset_flood (lifted first); 403ex_flood used to
# win because both counters increment on this class.
ss_band "srcset-403-tripwire-still-fires" "$(srcset_burst_status 500 10 403)" 50 69
SS403_RULE="$(_srcset_burst_run | grep -o '"decisive_rule":"[^"]*"' | cut -d'"' -f4)"
if [[ "$SS403_RULE" == "srcset_flood" ]]; then
    printf 'PASS  %-30s rule=srcset_flood\n' "srcset-403-tripwire-rule"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s rule=%s (want srcset_flood)\n' "srcset-403-tripwire-rule" "${SS403_RULE:-NONE}"; FAIL=$((FAIL+1))
fi
# Claude EXECUTE B1: a 403-only static-asset flood must surface as watch,
# not vanish and not temp. 500 .css in 10s is past 500@25rps.
: > "$tmp/403flood.tsv"
for i in $(seq 1 500); do
    printf '203.0.113.47\t%s\tGET\t/assets/x-%s.css\t403\t-\tGo-http-client/1.1\texample.com\n' \
        $(( NOW_EPOCH - 300 + (i * 10 / 500) )) "$i" >> "$tmp/403flood.tsv"
done
FLOODROW="$(gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
   -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
   -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
   -v BADPATHS="${ROOT}/config/badpaths.conf" \
   -f "${ROOT}/lib/score.awk" "$tmp/403flood.tsv" | head -1)"
FLOOD_S="$(printf '%s' "$FLOODROW" | awk -F'\t' '{print $2}')"
FLOOD_R="$(printf '%s' "$FLOODROW" | grep -o '"decisive_rule":"[^"]*"' | cut -d'"' -f4)"
if [[ -n "$FLOOD_S" ]] && (( FLOOD_S >= 50 && FLOOD_S <= 69 )) && [[ "$FLOOD_R" == "403ex_flood" ]]; then
    printf 'PASS  %-30s score=%s rule=%s\n' "403ex-flood-watch-only" "$FLOOD_S" "$FLOOD_R"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s score=%s rule=%s (want 50-69 403ex_flood)\n' "403ex-flood-watch-only" "${FLOOD_S:-NONE}" "${FLOOD_R:-NONE}"; FAIL=$((FAIL+1))
fi

# A 403 on a path that is independently hostile still scores.
: > "$tmp/403login.log"
emit_spread "$tmp/403login.log" "203.0.113.41" "POST /wp-login.php HTTP/1.1" 403 "python-requests/2.31" 60
assert_band "403-on-wp-login-still-scores" "$(score_of example.com "$tmp/403login.log")" 80 100
: > "$tmp/403env.log"
emit_spread "$tmp/403env.log" "203.0.113.42" "GET /.env HTTP/1.1" 403 "curl/8.0" 1
assert_band "403-on-env-still-scores" "$(score_of example.com "$tmp/403env.log")" 90 100
# Claude HOLD B2: a WAF 403 on /index.php must not vanish. 200 copies over
# 300s is error_burst, not scanner_profile (ndist=1).
: > "$tmp/403index.log"
emit_spread "$tmp/403index.log" "203.0.113.44" "GET /index.php HTTP/1.1" 403 "python-requests/2.31" 200
assert_band "403-on-index-php-still-scores" "$(score_of example.com "$tmp/403index.log")" 75 100
# Distinct-path 403s that are NOT static assets (direct-to-origin /p-N).
: > "$tmp/403scan.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403scan.log" "203.0.113.45" "GET /p-$i HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-html-paths-still-scanner" "$(score_of example.com "$tmp/403scan.log")" 70 100
# Claude HOLD B1: extension-suffixing a probe must not hide it.
: > "$tmp/403cloak.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403cloak.log" "203.0.113.48" "GET /x/c99-$i.php.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-png-not-asset" "$(score_of example.com "$tmp/403cloak.log")" 70 100
: > "$tmp/403phpjs.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpjs.log" "203.0.113.63" "GET /x/c99-$i.php.js HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-js-not-asset" "$(score_of example.com "$tmp/403phpjs.log")" 70 100
: > "$tmp/403phpsp.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpsp.log" "203.0.113.66" "GET /x/c99-$i.php%20.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-space-png-not-asset" "$(score_of example.com "$tmp/403phpsp.log")" 70 100
: > "$tmp/403phppct.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phppct.log" "203.0.113.67" "GET /x/c99-$i.%70%68%70.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-pct-png-not-asset" "$(score_of example.com "$tmp/403phppct.log")" 70 100
: > "$tmp/403phpmid.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpmid.log" "203.0.113.68" "GET /x/c99-$i.p%68p.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-midpct-png-not-asset" "$(score_of example.com "$tmp/403phpmid.log")" 70 100
: > "$tmp/403phpend.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpend.log" "203.0.113.71" "GET /x/c99-$i.ph%70.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-endpct-png-not-asset" "$(score_of example.com "$tmp/403phpend.log")" 70 100
: > "$tmp/403barephp.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403barephp.log" "203.0.113.69" "GET /x/$i/php.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-bare-php-png-not-asset" "$(score_of example.com "$tmp/403barephp.log")" 70 100
: > "$tmp/403asp.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403asp.log" "203.0.113.70" "GET /x/shell-$i.asp.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-asp-png-not-asset" "$(score_of example.com "$tmp/403asp.log")" 70 100
: > "$tmp/403phpat.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpat.log" "203.0.113.72" "GET /x/c99-$i.php@2x.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-at2x-not-asset" "$(score_of example.com "$tmp/403phpat.log")" 70 100
: > "$tmp/403phpat2.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpat2.log" "203.0.113.76" "GET /x/c99-$i.php@2x@2x.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-at2x-at2x-not-asset" "$(score_of example.com "$tmp/403phpat2.log")" 70 100
: > "$tmp/403php7.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403php7.log" "203.0.113.73" "GET /index.php7/x-$i.css HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php7-pathinfo-not-asset" "$(score_of example.com "$tmp/403php7.log")" 70 100
: > "$tmp/403phpscaled.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403phpscaled.log" "203.0.113.74" "GET /x/$i/php-scaled.png HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-php-scaled-basename-not-asset" "$(score_of example.com "$tmp/403phpscaled.log")" 70 100
: > "$tmp/own403pl.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/own403pl.log" "203.0.113.75" "GET /wp-includes/js/tinymce/langs/$i/pl.js HTTP/1.1" 403 "Mozilla/5.0" 1
done
assert_band "own-403-pl-js-not-scanner" "$(score_of example.com "$tmp/own403pl.log")" 0 49
: > "$tmp/403trav.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403trav.log" "203.0.113.49" "GET /x/..%2fetc/passwd-$i.css HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-traversal-css-not-asset" "$(score_of example.com "$tmp/403trav.log")" 70 100
: > "$tmp/403pi.log"
for i in $(seq 1 80); do
    emit_spread "$tmp/403pi.log" "203.0.113.50" "GET /index.php/x-$i.css HTTP/1.1" 403 "Go-http-client/1.1" 1
done
assert_band "403-pathinfo-css-not-asset" "$(score_of example.com "$tmp/403pi.log")" 70 100
ss_band "honeypot-403-still-floors" "$(srcset_score '/__trap_a7f3c1d9' 2 403)" 90 100

# Mixed: 60 404 probes + 200 of our 403s on assets. reqs must stay 60 (the
# 403s must not enter n, or err_ratio and rps both lie). 403_exempt=200.
: > "$tmp/403mix.tsv"
for i in $(seq 1 60); do
    printf '203.0.113.43\t%s\tGET\t/nope-%s\t404\t-\tcurl/8.0\texample.com\n' \
        $(( NOW_EPOCH - 300 + i*4 )) $(( i % 30 )) >> "$tmp/403mix.tsv"
done
for i in $(seq 1 200); do
    printf '203.0.113.43\t%s\tGET\t/assets/x-%s.css\t403\t-\tMozilla/5.0\texample.com\n' \
        $(( NOW_EPOCH - 280 + i )) "$i" >> "$tmp/403mix.tsv"
done
MIXROW="$(gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
   -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
   -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
   -v BADPATHS="${ROOT}/config/badpaths.conf" \
   -f "${ROOT}/lib/score.awk" "$tmp/403mix.tsv" | head -1)"
MIX_N="$(printf '%s' "$MIXROW" | awk -F'\t' '{print $3}')"
MIX_EX="$(printf '%s' "$MIXROW" | grep -o '"403_exempt":[0-9]*')"
if [[ "$MIX_N" == "60" ]]; then
    printf 'PASS  %-30s reqs=%s\n' "403-exempt-not-in-n" "$MIX_N"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s reqs=%s (want 60)\n' "403-exempt-not-in-n" "${MIX_N:-MISSING}"; FAIL=$((FAIL+1))
fi
if [[ "$MIX_EX" == '"403_exempt":200' ]]; then
    printf 'PASS  %-30s %s\n' "evidence-403-exempt-count" "$MIX_EX"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s got=%s (want "403_exempt":200)\n' "evidence-403-exempt-count" "${MIX_EX:-MISSING}"; FAIL=$((FAIL+1))
fi
MIX_S="$(printf '%s' "$MIXROW" | awk -F'\t' '{print $2}')"
if [[ -n "$MIX_S" ]] && (( MIX_S >= 75 && MIX_S <= 100 )); then
    printf 'PASS  %-30s score=%s (probes still score)\n' "403-pad-does-not-dilute" "$MIX_S"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s score=%s (want 75-100 -- dropping 403s must not dilute the probes)\n' "403-pad-does-not-dilute" "${MIX_S:-MISSING}"; FAIL=$((FAIL+1))
fi

# --- 5: direct-to-origin exploit scan on the raw IP (cgi-bin/shell probes) ---
: > "$tmp/rawip.log"
for p in cgi-bin/test.cgi boaform/admin/formLogin HNAP1 shell.php cmd.php cgi-bin/.%2e/bin/sh; do
    for i in $(seq 1 6); do
        emit_spread "$tmp/rawip.log" "34.32.24.86" "GET /$p HTTP/1.1" 404 "Mozilla/5.0 zgrab/0.x" 1
    done
done
assert_band "rawip-exploit-scan" "$(score_of "" "$tmp/rawip.log")" 75 100

# --- 6: below MIN_REQS benign — must not score ------------------------------
: > "$tmp/lowvol.log"
for i in $(seq 1 5); do
    emit_spread "$tmp/lowvol.log" "198.51.100.9" "GET /about-$i HTTP/1.1" 200 "Mozilla/5.0" 1
done
assert_band "below-min-reqs" "$(score_of example.com "$tmp/lowvol.log")" 0 49

# --- 7: xmlrpc.php flood (HIGH bad-path repeated) ---------------------------
: > "$tmp/xmlrpc.log"
emit_spread "$tmp/xmlrpc.log" "91.219.236.7" "POST /xmlrpc.php HTTP/1.1" 200 "Mozilla/5.0" 40
assert_band "xmlrpc-flood" "$(score_of example.com "$tmp/xmlrpc.log")" 80 100

# --- 8: site owner logging in and working in wp-admin -> never blockable ----
# Modeled on a real 2026-06-10 false positive: one login (two mistyped
# passwords), then a dashboard session — admin-ajax heartbeats and plugin
# assets, ~99% 2xx. The HIGH wp-login entry plus LOW admin-ajax hits must not
# add up to a block when there is no failure evidence.
: > "$tmp/owner.log"
UA_CHROME="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/148.0.0.0"
emit_spread "$tmp/owner.log" "205.220.208.99" "GET /wp-login.php HTTP/1.1" 200 "$UA_CHROME" 1
emit_spread "$tmp/owner.log" "205.220.208.99" "POST /wp-login.php HTTP/1.1" 200 "$UA_CHROME" 2
emit_spread "$tmp/owner.log" "205.220.208.99" "POST /wp-login.php HTTP/1.1" 302 "$UA_CHROME" 1
emit_spread "$tmp/owner.log" "205.220.208.99" "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 "$UA_CHROME" 50
for i in $(seq 1 10); do
    emit_spread "$tmp/owner.log" "205.220.208.99" "GET /wp-admin/edit.php?page=$i HTTP/1.1" 200 "$UA_CHROME" 1
done
for i in $(seq 1 30); do
    emit_spread "$tmp/owner.log" "205.220.208.99" "GET /wp-content/plugins/some-plugin/assets/style-$i.css HTTP/1.1" 200 "$UA_CHROME" 1
done
assert_band "owner-wp-admin-session" "$(score_of example.com "$tmp/owner.log")" 0 69

# --- 9: owner with asset-heavy page loads (fanout at saturation) ------------
# Second real 2026-06-10 false positive: a login plus pages pulling ~300
# distinct asset URLs. High fanout on 2xx traffic must not combine with the
# wp-login HIGH hit into a block.
: > "$tmp/owner2.log"
emit_spread "$tmp/owner2.log" "203.0.113.77" "GET /wp-login.php HTTP/1.1" 200 "$UA_CHROME" 3
emit_spread "$tmp/owner2.log" "203.0.113.77" "POST /wp-login.php HTTP/1.1" 302 "$UA_CHROME" 1
for i in $(seq 1 290); do
    emit_spread "$tmp/owner2.log" "203.0.113.77" "GET /wp-content/themes/site/asset-$i.js HTTP/1.1" 200 "$UA_CHROME" 1
done
assert_band "owner-asset-fanout" "$(score_of example.com "$tmp/owner2.log")" 0 69

# --- 10: low-volume credential brute — failed POSTs alone must still floor ---
: > "$tmp/slowbrute.log"
emit_spread "$tmp/slowbrute.log" "45.146.165.11" "POST /wp-login.php HTTP/1.1" 200 "python-requests/2.31" 15
assert_band "slow-wp-login-brute" "$(score_of example.com "$tmp/slowbrute.log")" 80 100

echo
echo "=== validator + allowlist logic tests ==="
# Test swatter_validate_ip_or_cidr (from common)
VALIDATOR_PASS=0 VALIDATOR_FAIL=0
for good in 1.2.3.4 192.168.0.1/24 2001:db8::1 2001:db8:1:2::/64 ::1 :: 2400:cb00::/32 \
            ::ffff:192.0.2.1 ::ffff:1.2.3.4/128 2001:DB8::1; do
    # Subshell: a wrongly-rejecting validator die()s, which must fail this case,
    # not abort the whole suite.
    if (swatter_validate_ip_or_cidr "$good") 2>/dev/null; then
        VALIDATOR_PASS=$((VALIDATOR_PASS+1))
    else
        echo "FAIL validator good: $good"; VALIDATOR_FAIL=$((VALIDATOR_FAIL+1))
    fi
done
# The bad list includes tokens that pass score.awk's loose charset gate
# (999...., deadbeef, ::::) — the validator is the authoritative gate the
# block path relies on, so it must reject what the fast pre-filter lets by.
for bad in "not-ip" "1.2.3" "1.2.3.4.5" "example.com" "1.2.3.4/99" "" \
           "999.999.999.999" "256.1.1.1" "deadbeef" "::::" "1::2::3" \
           "1:2:3:4:5:6:7:8:9" "12345::1" "1.2.3.4/1/2"; do
    if (swatter_validate_ip_or_cidr "$bad") 2>/dev/null; then
        echo "FAIL validator should-reject: $bad"; VALIDATOR_FAIL=$((VALIDATOR_FAIL+1))
    else
        VALIDATOR_PASS=$((VALIDATOR_PASS+1))
    fi
done
printf '  validator: %d passed, %d failed\n' "$VALIDATOR_PASS" "$VALIDATOR_FAIL"
(( VALIDATOR_FAIL == 0 )) || FAIL=$((FAIL+1))

# swatter_cidr_list_ok must accept a valid list whose LAST line has no trailing
# newline (a `read` loop without the `|| [[ -n $line ]]` guard silently drops it).
CLO_PASS=0 CLO_FAIL=0
printf '1.2.3.0/24' | swatter_cidr_list_ok && CLO_PASS=$((CLO_PASS+1)) || { echo "FAIL cidr_list_ok drops no-newline last line"; CLO_FAIL=$((CLO_FAIL+1)); }
printf '1.2.3.0/24\n2001:db8::/32' | swatter_cidr_list_ok && CLO_PASS=$((CLO_PASS+1)) || { echo "FAIL cidr_list_ok multi no-newline last"; CLO_FAIL=$((CLO_FAIL+1)); }
# ...and still rejects an invalid last line / empty input.
printf '1.2.3.0/24\ngarbage' | swatter_cidr_list_ok && { echo "FAIL cidr_list_ok accepted garbage last line"; CLO_FAIL=$((CLO_FAIL+1)); } || CLO_PASS=$((CLO_PASS+1))
printf '' | swatter_cidr_list_ok && { echo "FAIL cidr_list_ok accepted empty"; CLO_FAIL=$((CLO_FAIL+1)); } || CLO_PASS=$((CLO_PASS+1))
printf '  cidr_list_ok: %d passed, %d failed\n' "$CLO_PASS" "$CLO_FAIL"
(( CLO_FAIL == 0 )) || FAIL=$((FAIL+1))

# Test "already allowed" logic (awk $1 == ip) with temp file
# Note: the check matches the *stored token* exactly (so "198.51.100.0/24" matches only when querying the cidr itself; per-ip membership is handled later by _ip_in_cidr_file).
ALLOW_PASS=0 ALLOW_FAIL=0
allowtmp="$(mktemp "${TMPDIR:-/tmp}/swatter-allowtest.XXXXXX")"
printf '203.0.113.5 # office\n198.51.100.0/24 # client\n2001:db8::/32 # v6\n' > "$allowtmp"
if awk -v ip="203.0.113.5" '$1 == ip { found=1; exit } END { exit !found }' "$allowtmp"; then ALLOW_PASS=$((ALLOW_PASS+1)); else echo "FAIL already-allow exact ip"; ALLOW_FAIL=$((ALLOW_FAIL+1)); fi
if awk -v ip="198.51.100.0/24" '$1 == ip { found=1; exit } END { exit !found }' "$allowtmp"; then ALLOW_PASS=$((ALLOW_PASS+1)); else echo "FAIL already-allow exact cidr token"; ALLOW_FAIL=$((ALLOW_FAIL+1)); fi
if awk -v ip="10.0.0.1" '$1 == ip { found=1; exit } END { exit !found }' "$allowtmp"; then echo "FAIL already-allow should miss"; ALLOW_FAIL=$((ALLOW_FAIL+1)); else ALLOW_PASS=$((ALLOW_PASS+1)); fi
rm -f "$allowtmp"
printf '  allow-already: %d passed, %d failed\n' "$ALLOW_PASS" "$ALLOW_FAIL"
(( ALLOW_FAIL == 0 )) || FAIL=$((FAIL+1))

echo
echo "=== IPv6 allowlist prefix matching ==="
# shellcheck source=../lib/allowlist.sh
source "${ROOT}/lib/allowlist.sh"
V6_PASS=0 V6_FAIL=0

# v6_check <file> <ip> <yes|no> <name>
v6_check() {
    local file="$1" ip="$2" want="$3" name="$4" got=no
    _ip_in_cidr_file "$ip" "$file" && got=yes
    if [[ "$got" == "$want" ]]; then
        V6_PASS=$((V6_PASS+1))
    else
        echo "FAIL v6-match ${name}: ${ip} want=${want} got=${got}"
        V6_FAIL=$((V6_FAIL+1))
    fi
}

# A /32 must cover every address in it, not just those that share the
# compressed-string prefix of the network address.
printf '2001:db8::/32 # docs range\n' > "$tmp/v6-range.txt"
v6_check "$tmp/v6-range.txt" 2001:db8::1            yes compressed-in-range
v6_check "$tmp/v6-range.txt" 2001:db8:1::1          yes subnet-in-range
v6_check "$tmp/v6-range.txt" 2001:db8:ffff:abcd::9  yes deep-in-range
v6_check "$tmp/v6-range.txt" 2001:db8a::1           no  char-prefix-near-miss
v6_check "$tmp/v6-range.txt" 2001:db9::1            no  adjacent-range

# A /128 is a single host — string-prefix matching must not bleed onto ::50.
printf '2607:db8::5/128 # single host\n' > "$tmp/v6-host.txt"
v6_check "$tmp/v6-host.txt" 2607:db8::5   yes host-rule-exact
v6_check "$tmp/v6-host.txt" 2607:db8::50  no  host-rule-over-match

# Uncompressed entries must match compressed candidates and vice versa.
printf '2607:f8b0:4005:80a:0:0:0:200e/64 # uncompressed\n' > "$tmp/v6-uncomp.txt"
v6_check "$tmp/v6-uncomp.txt" 2607:f8b0:4005:80a::1    yes uncompressed-entry-match
v6_check "$tmp/v6-uncomp.txt" 2607:f8b0:4005:80b::1    no  uncompressed-entry-miss

# Bare entry (no /len) is /128.
printf '2001:db8::7\n' > "$tmp/v6-bare.txt"
v6_check "$tmp/v6-bare.txt" 2001:db8::7  yes bare-entry-exact
v6_check "$tmp/v6-bare.txt" 2001:db8::70 no  bare-entry-over-match

printf '  v6-match: %d passed, %d failed\n' "$V6_PASS" "$V6_FAIL"
(( V6_FAIL == 0 )) || FAIL=$((FAIL+1))

echo
echo "=== ingest IP normalization ==="
ING_PASS=0 ING_FAIL=0

# ing_check <raw-ip> <want-ip> <name>
ing_check() {
    local raw="$1" want="$2" name="$3" got
    got="$(printf '%s - - [10/Jun/2026:12:05:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n' "$raw" \
        | _swatter_parse example.com | awk -F'\t' '{print $1; exit}')"
    if [[ "$got" == "$want" ]]; then
        ING_PASS=$((ING_PASS+1))
    else
        echo "FAIL ingest ${name}: want=${want} got=${got}"
        ING_FAIL=$((ING_FAIL+1))
    fi
}

ing_check "::ffff:198.51.100.7" "198.51.100.7" v4-mapped-lower
ing_check "::FFFF:198.51.100.7" "198.51.100.7" v4-mapped-upper
ing_check "fe80::1%eth0"        "fe80::1"      zone-id-stripped
ing_check "203.0.113.9"         "203.0.113.9"  plain-v4-untouched
ing_check "2001:db8::1"         "2001:db8::1"  plain-v6-untouched

printf '  ingest-normalize: %d passed, %d failed\n' "$ING_PASS" "$ING_FAIL"
(( ING_FAIL == 0 )) || FAIL=$((FAIL+1))

echo
echo "=== store guards: malformed ip must never be fatal ==="
# shellcheck source=../lib/store_sqlite.sh
source "${ROOT}/lib/store_sqlite.sh"
STORE=flatfile
STATE_DIR="$tmp/state"; mkdir -p "$STATE_DIR"
REPEAT_WINDOW_DAYS=7
LOG_LEVEL="${LOG_LEVEL:-info}"
swatter_store_init
ST_PASS=0 ST_FAIL=0

# st_check <name> <expected-tail> <cmd...> — run cmd in a subshell, echo a
# sentinel after it; if the function die()s the sentinel never prints.
st_check() {
    local name="$1"; shift
    local out
    out="$( ( "$@" ; echo "__alive__" ) 2>/dev/null )"
    if [[ "$out" == *__alive__* ]]; then
        ST_PASS=$((ST_PASS+1))
    else
        echo "FAIL store-guard ${name}: function exited the shell"
        ST_FAIL=$((ST_FAIL+1))
    fi
}

st_check is-perm-survives          swatter_store_is_perm "::ffff:1.2.3.4"
st_check temp-count-survives       swatter_store_recent_temp_count "%%bogus%%"
st_check record-survives           swatter_store_record "bogus;ip" temp csf 60 90 "r" 0
st_check history-survives          swatter_store_history "not-an-ip"
st_check unblock-survives          swatter_store_unblock "not-an-ip"

# temp-count on a malformed ip must still yield a numeric 0 for callers.
got_cnt="$( (swatter_store_recent_temp_count "%%bogus%%") 2>/dev/null )"
if [[ "$got_cnt" == "0" ]]; then
    ST_PASS=$((ST_PASS+1))
else
    echo "FAIL store-guard temp-count-zero: want 0 got '${got_cnt}'"
    ST_FAIL=$((ST_FAIL+1))
fi

# a refused record must not land in the ledger.
if grep -qF 'bogus;ip' "$STATE_DIR/ledger.jsonl" 2>/dev/null; then
    echo "FAIL store-guard record-refused: malformed ip was recorded"
    ST_FAIL=$((ST_FAIL+1))
else
    ST_PASS=$((ST_PASS+1))
fi

printf '  store-guards: %d passed, %d failed\n' "$ST_PASS" "$ST_FAIL"
(( ST_FAIL == 0 )) || FAIL=$((FAIL+1))

echo
echo "=== CF error summary ==="
# shellcheck source=../lib/block_cf.sh
source "${ROOT}/lib/block_cf.sh"
CF_PASS=0 CF_FAIL=0

# cfe_check <json> <want> <name>
cfe_check() {
    local json="$1" want="$2" name="$3" got
    got="$(printf '%s' "$json" | _cf_err_summary 2>/dev/null)"
    if [[ "$got" == "$want" ]]; then
        CF_PASS=$((CF_PASS+1))
    else
        echo "FAIL cf-err ${name}: want='${want}' got='${got}'"
        CF_FAIL=$((CF_FAIL+1))
    fi
}

cfe_check '{"success":false,"errors":[{"message":"auth error"},{"message":"second"}]}' "auth error; second" messages-joined
cfe_check '{"success":false,"errors":[]}'              "unknown error" empty-errors
cfe_check '{"success":false,"errors":[{"code":10000}]}' "unknown error" message-less
cfe_check '{"success":false}'                           "unknown error" no-errors-field
cfe_check 'not json at all'                             "unknown error" non-json

printf '  cf-err-summary: %d passed, %d failed\n' "$CF_PASS" "$CF_FAIL"
(( CF_FAIL == 0 )) || FAIL=$((FAIL+1))

echo
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
