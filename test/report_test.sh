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
rm -rf "$LOG_DIR"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
