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
# 2026-08-28 gate D review: broken srcset markup made browsers request the whole
# srcset value as one URL, always 404. 17,829 such requests from 8,767 DISTINCT
# client IPs across 35 hosted sites, overwhelmingly residential broadband with
# ordinary consumer browser UAs. Nineteen real visitors were already temp-blocked,
# six by rule=error_burst, one a live perm candidate. A real visitor must not be
# banned for the site's own markup -- and the exemption must not become a
# detection blind spot. Both review models broke the FIRST version of this fix;
# the bypass strings they supplied are pinned below by name.
HP="$tmp/honeypots.conf"; printf '/__trap_a7f3c1d9(/|$)\n' > "$HP"
srcset_score() {  # srcset_score <path> <count> -> score or NONE
    local pth="$1" cnt="$2" i
    : > "$tmp/ss.tsv"
    for (( i=1; i<=cnt; i++ )); do
        printf '198.51.100.9\t%s\tGET\t%s\t404\t-\tcurl/8.0\n' \
            $(( NOW_EPOCH - 300 + i )) "$pth" >> "$tmp/ss.tsv"
    done
    gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
         -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 -v W_BADPATH=22 \
         -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
         -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$HP" \
         -f "${ROOT}/lib/score.awk" "$tmp/ss.tsv" \
      | awk -F'\t' 'NR==1{print $2; f=1} END{if(!f) print "NONE"}'
}
ss_band() { assert_band "$1" "$2" "$3" "$4"; }

# The real production shapes must NOT score.
ss_band "srcset-real-shape-not-banned" \
  "$(srcset_score '/wp-content/uploads/2025/10/photo-768x576.jpg%20768w,%20https:/example.com/photo-900x675.jpg%20900w' 220)" 0 49
# Single-candidate srcset has no trailing comma; density (sizes) descriptors use Nx.
# Both are the same defect and were MISSED by the first version of the fix.
ss_band "srcset-single-candidate-no-comma"  "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%20768w' 220)" 0 49
ss_band "srcset-density-descriptor"         "$(srcset_score '/wp-content/uploads/2025/10/photo.jpg%202x,%20https:/e/y.jpg%203x' 220)" 0 49

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
PAD='/wp-content/uploads/2025/10/photo-768x576.jpg%20768w,%20https:/example.com/photo-900x675.jpg%20900w'
emit_spread "$tmp/probe_padded.log" "203.0.113.82" "GET /nope-page HTTP/1.1" 404 "curl/8.0" 120
emit_spread "$tmp/probe_padded.log" "203.0.113.82" "GET ${PAD} HTTP/1.1" 404 "curl/8.0" 440
PADDED="$(score_of example.com "$tmp/probe_padded.log")"
ss_band "probe-run-still-scores-when-padded" "$PADDED" 75 100
if [[ "$BARE" == "$PADDED" ]]; then
    printf 'PASS  %-30s padding is neutral (both %s)\n' "srcset-padding-is-neutral" "$BARE"; PASS=$((PASS+1))
else
    printf 'FAIL  %-30s bare=%s padded=%s\n' "srcset-padding-is-neutral" "$BARE" "$PADDED"; FAIL=$((FAIL+1))
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
