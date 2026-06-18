#!/usr/bin/env bash
# test/honeypot_test.sh — a single honeypot-path hit perm-floors at 100.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/ingest.sh"

PASS=0; FAIL=0
NOW_EPOCH=1749557400
tmp="$(mktemp -d "${TMPDIR:-/tmp}/swatter-hp.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
tstamp() { date -u -d "@$1" '+%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null || date -u -r "$1" '+%d/%b/%Y:%H:%M:%S +0000'; }

printf '/__trap_a7f3(/|$)\n' > "$tmp/honeypot.paths"

run() { # <logfile> -> "score<TAB>evidence" for first IP
  _swatter_parse example.com < "$1" \
    | gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
           -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 \
           -v W_BADPATH=22 -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
           -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$tmp/honeypot.paths" \
           -f "${ROOT}/lib/score.awk" | awk -F'\t' 'NR==1{print $2"\t"$4}'
}
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# ONE hit on the trap, well below MIN_REQS, must score 100.
: > "$tmp/trap.log"
printf '%s - - [%s] "GET /__trap_a7f3/ HTTP/1.1" 404 0 "-" "curl/8"\n' "66.66.66.66" "$(tstamp "$NOW_EPOCH")" >> "$tmp/trap.log"
line="$(run "$tmp/trap.log")"
check trap-score "$(printf '%s' "$line" | cut -f1)" "100"
case "$(printf '%s' "$line" | cut -f2)" in
  *'"honeypot":1'*) PASS=$((PASS+1));;
  *) echo "FAIL trap-evidence-flag"; FAIL=$((FAIL+1));;
esac
case "$(printf '%s' "$line" | cut -f2)" in
  *'"decisive_rule":"honeypot"'*) PASS=$((PASS+1));;
  *) echo "FAIL trap-decisive-rule"; FAIL=$((FAIL+1));;
esac

# A normal visitor NOT hitting the trap is unaffected (no honeypot flag).
: > "$tmp/clean.log"
for i in $(seq 1 18); do printf '%s - - [%s] "GET /page%s HTTP/1.1" 200 0 "-" "Mozilla/5.0"\n' "70.0.0.1" "$(tstamp "$NOW_EPOCH")" "$i" >> "$tmp/clean.log"; done
case "$(run "$tmp/clean.log" | cut -f2)" in
  *'"honeypot":1'*) echo "FAIL clean-no-flag"; FAIL=$((FAIL+1));;
  *) PASS=$((PASS+1));;
esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
