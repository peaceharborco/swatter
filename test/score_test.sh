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
tstamp() { date -u -r "$1" '+%d/%b/%Y:%H:%M:%S +0000'; }

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

echo
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
