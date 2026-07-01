#!/usr/bin/env bash
# test/report_test.sh — nightly report: verdict, subject, planes/degradation, render.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Fixed UTC date for the subject assertion (override swatter_now via SOURCE_DATE).
swatter_now() { echo 1782396000; }   # 2026-06-25 (UTC)
DATE_UTC="$(date -u -d "@1782396000" +%F 2>/dev/null || date -u -r 1782396000 +%F)"

# verdict: green when only blocks, amber when genuine non-FATAL errors, red on FATAL.
RPT_PERM=36 RPT_TEMP=162 RPT_ACTED=198 RPT_EXEMPT=0 OL_HITS=0 ERR_GENUINE=0 ERR_FATAL=0
check verdict-green "$(_report_verdict | cut -f1)" "green"
ERR_GENUINE=4 ERR_FATAL=0
check verdict-amber "$(_report_verdict | cut -f1)" "amber"
ERR_GENUINE=4 ERR_FATAL=2
check verdict-red   "$(_report_verdict | cut -f1)" "red"

# subject: "Report YYYY-MM-DD - <summary>"
ERR_GENUINE=0 ERR_FATAL=0
check subject-shape "$(_report_subject 24h)" "Report ${DATE_UTC} - healthy · 198 blocked, 0 FATAL"
OL_HITS=253
check subject-ol "$(_report_subject 24h | grep -c '253 origin-lock')" "1"

# Plane assembly + degradation. Stub the section builders so the test is hermetic.
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rpt.XXXXXX")"; : > "$LOG_DIR/decisions.jsonl"
SWATTER_HAVE_JQ=1; SWATTER_MODE="enforce"
swatter_errors_section()    { ERR_GENUINE=0 ERR_FATAL=0; echo "(errors section)"; }
swatter_originlock_section(){ OL_HITS="${FAKE_OL:-0}"; echo "(origin-lock section)"; }
_ol_digest_should_render()  { local h="${1:-0}"; case "${ORIGIN_LOCK_DIGEST:-auto}" in on) return 0;; off) return 1;; *) (( h > 0 ));; esac; }

# 1 plane: abuse only (error digest off, no origin-lock hits).
ERROR_DIGEST_ENABLE="false"; ORIGIN_LOCK_DIGEST="auto"; FAKE_OL=0
body="$(swatter_report_build 24h)"
check title-report      "$(printf '%s' "$body" | grep -c 'Swatter Nightly Report')" "1"
check titlecase-bad     "$(printf '%s' "$body" | grep -c 'Bad Actors')" "1"
check no-origin-1plane  "$(printf '%s' "$body" | grep -c 'Origin-Lock')" "0"
check no-errors-1plane  "$(printf '%s' "$body" | grep -c 'Server Errors')" "0"

# 3 planes: error digest on + origin-lock hits present.
ERROR_DIGEST_ENABLE="true"; ORIGIN_LOCK_DIGEST="auto"; FAKE_OL=253
body="$(swatter_report_build 24h)"
check has-origin-3plane "$(printf '%s' "$body" | grep -c 'Origin-Lock')" "1"
check has-errors-3plane "$(printf '%s' "$body" | grep -c 'Server Errors')" "1"

# Text digest surfaces backend failures + dominant cause from the decision log.
: > "$LOG_DIR/decisions.jsonl"; _now=$(date +%s)
for ip in 9.9.9.9 9.9.9.8; do
  printf '{"ts":%s,"action":"failed","channel":"cloudflare","score":91,"ip":"%s","reason":"block_failed","evidence":{"backend_err":"cloudflare 429 rate limited"}}\n' "$_now" "$ip" >> "$LOG_DIR/decisions.jsonl"
done
ERROR_DIGEST_ENABLE="false"; FAKE_OL=0
fbody="$(swatter_report_build 24h)"
check text-backend-failed "$(printf '%s' "$fbody" | grep -c 'backend-failed:')" "1"
check text-backend-cause  "$(printf '%s' "$fbody" | grep -c 'cloudflare 429 rate limited')" "1"
rm -rf "$LOG_DIR"

# HTML render: Direction B structure, verdict color, tiles, no <pre> dump.
RPT_PERM=36 RPT_TEMP=162 RPT_ACTED=198 RPT_CF=198 RPT_DIRECT=0 RPT_EXEMPT=62 RPT_WATCH=2
ERR_GENUINE=0 ERR_FATAL=0; OL_HITS=253 OL_IPS=61 OL_P80=171 OL_P443=82 OL_MODE="DROP"
OL_TOP_ROWS=$'45.135.232.17\t88\tattacker\n193.32.162.40\t41\tattacker\n'
ERROR_DIGEST_ENABLE="true"; ORIGIN_LOCK_DIGEST="auto"
html="$(_report_render_html "plain body here")"
check html-title    "$(printf '%s' "$html" | grep -c 'Swatter Nightly Report')" "1"
check html-bad      "$(printf '%s' "$html" | grep -c '🛡️ Bad Actors')" "1"
check html-origin   "$(printf '%s' "$html" | grep -c '🔒 Origin-Lock')" "1"
check html-no-pre   "$(printf '%s' "$html" | grep -c '<pre')" "0"
# Grade card: letter B (state above is 198 blocks, 0 errors -> Review), legend, recommendation.
check html-grade-word   "$(printf '%s' "$html" | grep -c 'Review')" "1"
check html-grade-legend "$(printf '%s' "$html" | grep -c 'A All Clear')" "1"
check html-reco         "$(printf '%s' "$html" | grep -c 'Skim the sections below')" "1"
# Section summaries + the renamed Non-Fatal wording.
check html-actors-sum   "$(printf '%s' "$html" | grep -c 'Automated attackers')" "1"
check html-nonfatal     "$(printf '%s' "$html" | grep -c 'Non-Fatal')" "1"
check html-no-genuine   "$(printf '%s' "$html" | grep -c 'Genuine')" "0"
# Footer: branding credit + links, and the clearer (Title Case, italic) help line.
check html-footer-phs   "$(printf '%s' "$html" | grep -c 'Peace Harbor Studios')" "1"
check html-footer-phlink "$(printf '%s' "$html" | grep -c 'studios.peaceharbor.com')" "1"
check html-footer-gh    "$(printf '%s' "$html" | grep -c 'github.com/peaceharborco/swatter')" "1"
check html-help-clear   "$(printf '%s' "$html" | grep -c 'Why An IP Was Flagged')" "1"
# Backend-failure surfacing: shows when there are failed CF blocks, hidden at 0.
check html-no-backend-when-0 "$(printf '%s' "$html" | grep -c 'backend-failed')" "0"
RPT_FAILED=3 RPT_FAIL_CAUSE="cloudflare 429 rate limited"; html2="$(_report_render_html "")"
check html-backend-failed "$(printf '%s' "$html2" | grep -c '3 backend-failed')" "1"
check html-backend-cause  "$(printf '%s' "$html2" | grep -c 'cloudflare 429 rate limited')" "1"
RPT_FAILED=0 RPT_FAIL_CAUSE=""
# Text body carries the same footer.
tbody="$(swatter_report_build 24h)"
check text-footer-phs   "$(printf '%s' "$tbody" | grep -c 'a Peace Harbor Studios project')" "1"
check text-footer-gh    "$(printf '%s' "$tbody" | grep -c 'github.com/peaceharborco/swatter')" "1"

# Grade logic — worst signal wins. (f=fatal e=non-fatal ol=origin b=blocks)
_grade() { ERR_FATAL="$1" ERR_GENUINE="$2" OL_HITS="$3" RPT_ACTED="$4" REPORT_WINDOW=24h REPORT_TRIAGE_HINT=""; _report_grade; printf '%s' "$RPT_GRADE"; }
check grade-A "$(_grade 0 0 0 0)"      "A"
check grade-B "$(_grade 0 26 0 165)"   "B"   # today's sample: routine noise + blocks
check grade-blocks-stay-B "$(_grade 0 0 0 900)" "B"   # a big attack Swatter handled is still B
check grade-C "$(_grade 0 120 0 0)"    "C"   # elevated non-fatal errors
check grade-D "$(_grade 0 350 0 0)"    "D"   # error flood
check grade-F "$(_grade 2 5 0 0)"      "F"   # any fatal wins
# Recommendation adapts to the triage hint (public default = blank -> generic wording).
ERR_FATAL=0 ERR_GENUINE=20 OL_HITS=0 RPT_ACTED=0 REPORT_WINDOW=24h REPORT_TRIAGE_HINT="/server-logs"; _report_grade
check reco-hint "$(printf '%s' "$RPT_RECO" | grep -c '/server-logs')" "1"
ERR_FATAL=0 ERR_GENUINE=20 OL_HITS=0 RPT_ACTED=0 REPORT_WINDOW=24h REPORT_TRIAGE_HINT=""; _report_grade
check reco-generic "$(printf '%s' "$RPT_RECO" | grep -c 'server-logs')" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
