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

# verdict: green when only blocks, yellow when genuine non-FATAL errors, red on FATAL.
RPT_PERM=36 RPT_TEMP=162 RPT_ACTED=198 RPT_EXEMPT=0 OL_HITS=0 ERR_GENUINE=0 ERR_FATAL=0
check verdict-green "$(_report_verdict | cut -f1)" "green"
ERR_GENUINE=4 ERR_FATAL=0
check verdict-yellow "$(_report_verdict | cut -f1)" "yellow"
ERR_GENUINE=4 ERR_FATAL=2
check verdict-red   "$(_report_verdict | cut -f1)" "red"

# subject: "<icon> Report YYYY-MM-DD - <summary>" — leads with the status icon.
ERR_GENUINE=0 ERR_FATAL=0; REPORT_GRADE_FORCE="" _report_grade   # GREEN -> 🟢
check subject-shape "$(_report_subject 24h)" "🟢 Report ${DATE_UTC} - healthy · 198 blocked, 0 FATAL"
OL_HITS=253
check subject-ol "$(_report_subject 24h | grep -c '253 origin-lock')" "1"

# Plane assembly + degradation. Stub the section builders so the test is hermetic.
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rpt.XXXXXX")"; : > "$LOG_DIR/decisions.jsonl"
SWATTER_HAVE_JQ=1; SWATTER_MODE="enforce"
swatter_errors_section()    { ERR_GENUINE=0 ERR_FATAL=0; echo "(errors section)"; }
swatter_originlock_section(){ OL_HITS="${FAKE_OL:-0}"; echo "(origin-lock section)"; }
_ol_digest_should_render()  { local h="${1:-0}"; case "${ORIGIN_LOCK_DIGEST:-auto}" in on) return 0;; off) return 1;; *) (( h > 0 ));; esac; }
# _swarm_enabled lives in swarm.sh, which this hermetic harness never sources.
# Stub it identically to the real gate so the builder's swarm calls resolve;
# defaults OFF (SWARM_ENABLE unset) so pre-existing cases are unaffected.
_swarm_enabled() { [[ "${SWARM_ENABLE:-false}" == "true" && -n "${SWARM_HUB_URL:-}" ]]; }

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
check html-bad      "$(printf '%s' "$html" | grep -c 'Bad Actors')" "1"
check html-origin   "$(printf '%s' "$html" | grep -c 'Origin-Lock')" "1"
check html-no-pre   "$(printf '%s' "$html" | grep -c '<pre')" "0"
# Canonical PH system-email template (peaceharbor repo: brand/email-template.md,
# owner-approved 2026-07-02) — STUDIOS lockup, brand tokens, division footer,
# no emoji headings, and none of the legacy pre-template palette.
check html-ph-lockup   "$(printf '%s' "$html" | grep -c 'ph-lockup-stacked-studios-email-720w-v2.png')" "1"
check html-ph-alt      "$(printf '%s' "$html" | grep -c 'alt="Peace Harbor Studios"')" "1"
check html-ph-rule     "$(printf '%s' "$html" | grep -c 'border-bottom:3px solid #4A5568')" "1"
check html-ph-cream    "$(printf '%s' "$html" | grep -c 'background:#F4F0E8')" "1"
check html-ph-card     "$(printf '%s' "$html" | grep -c 'width="600"')" "1"
check html-ph-sora     "$(printf '%s' "$html" | grep -c 'Sora,Helvetica')" "1"
check html-ph-manrope  "$(printf '%s' "$html" | grep -c 'Manrope,Helvetica')" "1"
check html-ph-division "$(printf '%s' "$html" | grep -c 'a division of <a href="https://peaceharbor.com"')" "1"
check html-ph-no-emoji  "$(printf '%s' "$html" | grep -cE '🪰|🛡️|🔒|🩺')" "0"
check html-ph-no-legacy "$(printf '%s' "$html" | grep -cE '#545d69|#c0392b|#1f8a4c|#B26A00|#2a6b7c|#1b1f24')" "0"
# Status card: GREEN / All Clear (state above is 198 blocks, 0 errors -> Swatter working), legend, recommendation.
check html-status-word   "$(printf '%s' "$html" | grep -c 'All Clear')" "1"
check html-status-token  "$(printf '%s' "$html" | grep -c 'GREEN')" "1"
check html-status-icon   "$(printf '%s' "$html" | grep -c '🟢')" "1"   # green traffic-light icon present
check html-status-legend "$(printf '%s' "$html" | grep -c 'GREEN All Clear')" "1"
check html-reco          "$(printf '%s' "$html" | grep -c 'Skim the sections below')" "1"
# Section summaries + the renamed Non-Fatal wording.
check html-actors-sum   "$(printf '%s' "$html" | grep -c 'Automated attackers')" "1"
check html-nonfatal     "$(printf '%s' "$html" | grep -c 'Non-Fatal')" "1"
check html-no-genuine   "$(printf '%s' "$html" | grep -c 'Genuine')" "0"
# Footer: branding credit + links, and the clearer (Title Case, italic) help line.
check html-footer-phs   "$(printf '%s' "$html" | grep -c 'Peace Harbor Studios')" "1"
check html-footer-phlink "$(printf '%s' "$html" | grep -c 'studios.peaceharbor.com')" "1"
check html-footer-phclink "$(printf '%s' "$html" | grep -c 'href="https://peaceharbor.com"')" "1"
check html-footer-gh    "$(printf '%s' "$html" | grep -c 'github.com/peaceharborco/swatter')" "1"
check html-help-clear   "$(printf '%s' "$html" | grep -c 'Why An IP Was Flagged')" "1"
# Backend-failure surfacing: shows when there are failed CF blocks, hidden at 0.
check html-no-backend-when-0 "$(printf '%s' "$html" | grep -c 'backend-failed')" "0"
RPT_FAILED=3 RPT_FAIL_CAUSE="cloudflare 429 rate limited"; html2="$(_report_render_html "")"
check html-backend-failed "$(printf '%s' "$html2" | grep -c '3 backend-failed')" "1"
check html-backend-cause  "$(printf '%s' "$html2" | grep -c 'cloudflare 429 rate limited')" "1"
check html2-ph-no-legacy  "$(printf '%s' "$html2" | grep -cE '#545d69|#B26A00')" "0"
RPT_FAILED=0 RPT_FAIL_CAUSE=""
# Public-repo customization: operators may put their own logo in the header
# (REPORT_LOGO_URL/REPORT_LOGO_ALT); the footer branding is NOT configurable.
REPORT_LOGO_URL="https://example.com/acme.png" REPORT_LOGO_ALT='Acme <Corp> "X"'
html3="$(_report_render_html "")"
check html-logo-custom   "$(printf '%s' "$html3" | grep -c 'src="https://example.com/acme.png"')" "1"
check html-logo-alt-esc  "$(printf '%s' "$html3" | grep -c 'alt="Acme &lt;Corp&gt; &quot;X&quot;"')" "1"
check html-logo-no-ph    "$(printf '%s' "$html3" | grep -c 'ph-lockup')" "0"
check html-footer-perm   "$(printf '%s' "$html3" | grep -c 'a division of <a href="https://peaceharbor.com"')" "1"
REPORT_LOGO_URL="" REPORT_LOGO_ALT=""
# Config-sourced strings are escaped in markup (mode/window land in the meta line).
SWATTER_MODE='enforce<script>' REPORT_WINDOW='24h'
html4="$(_report_render_html "")"
check html-mode-escaped  "$(printf '%s' "$html4" | grep -c '<script>')" "0"
check html-mode-entity   "$(printf '%s' "$html4" | grep -c 'Enforce&lt;script&gt;')" "1"
SWATTER_MODE="enforce"
# Text body carries the division footer line, unlinked (spec: the text/plain
# part keeps the unlinked line).
tbody="$(swatter_report_build 24h)"
check text-footer-division "$(printf '%s' "$tbody" | grep -c 'Peace Harbor Studios — a division of Peace Harbor Companies')" "1"
check text-footer-gh    "$(printf '%s' "$tbody" | grep -c 'github.com/peaceharborco/swatter')" "1"

# Status logic — traffic light, worst signal wins. (f=fatal e=non-fatal ol=origin b=blocks)
_grade() { ERR_FATAL="$1" ERR_GENUINE="$2" OL_HITS="$3" RPT_ACTED="$4" REPORT_WINDOW=24h REPORT_TRIAGE_HINT="" REPORT_GRADE_FORCE=""; _report_grade; printf '%s' "$RPT_GRADE"; }
check status-quiet-green   "$(_grade 0 0 0 0)"      "GREEN"    # nothing at all
check status-noise-green   "$(_grade 0 26 0 165)"   "GREEN"    # routine noise + blocks stay green
check status-blocks-green  "$(_grade 0 0 0 900)"    "GREEN"    # a big attack Swatter handled is still green
check status-elevated-yellow "$(_grade 0 120 0 0)"  "YELLOW"   # elevated non-fatal errors (was C)
check status-flood-yellow  "$(_grade 0 350 0 0)"    "YELLOW"   # error flood (was D)
check status-fatal-red     "$(_grade 2 5 0 0)"      "RED"      # any fatal wins
# Forced override lets an operator preview any status regardless of data.
check status-force-red     "$(ERR_FATAL=0 ERR_GENUINE=0 OL_HITS=0 RPT_ACTED=0 REPORT_GRADE_FORCE=red _report_grade; printf '%s' "$RPT_GRADE")" "RED"
check status-force-yellow  "$(ERR_FATAL=0 ERR_GENUINE=0 OL_HITS=0 RPT_ACTED=0 REPORT_GRADE_FORCE=YELLOW _report_grade; printf '%s' "$RPT_GRADE")" "YELLOW"
# Recommendation adapts to the triage hint (public default = blank -> generic wording).
ERR_FATAL=0 ERR_GENUINE=20 OL_HITS=0 RPT_ACTED=0 REPORT_WINDOW=24h REPORT_TRIAGE_HINT="/server-logs"; _report_grade
check reco-hint "$(printf '%s' "$RPT_RECO" | grep -c '/server-logs')" "1"
ERR_FATAL=0 ERR_GENUINE=20 OL_HITS=0 RPT_ACTED=0 REPORT_WINDOW=24h REPORT_TRIAGE_HINT=""; _report_grade
check reco-generic "$(printf '%s' "$RPT_RECO" | grep -c 'server-logs')" "0"

# --- Swarm plane: present only when enabled; never touches grade/verdict/silence ---
SW_ST="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rptsw.XXXXXX")"; mkdir -p "${SW_ST}/feeds"
SWNOW="$(swatter_now)"
printf '198.51.100.7\n198.51.100.8\n' > "${SW_ST}/feeds/swarm.txt"
printf '[{"ip":"198.51.100.7","host_count":3}]\n' > "${SW_ST}/feeds/swarm.meta.json"
printf '{"ts":%s,"count":4}\n' "$SWNOW" > "${SW_ST}/swarm.publish.log"
SW_LOG="${SW_ST}/decisions.jsonl"
# Two dispatched sweep rows: one clean reason, one novhost-PREFIXED reason. Both
# carry evidence.swarm=true, so the evidence-based selector must count BOTH (2);
# a .reason startswith would wrongly count only the clean one (regression guard).
printf '{"ts":%s,"ip":"185.220.101.1","action":"temp","reason":"swarm-corroborated hosts=3","evidence":{"swarm":true,"hosts":3}}\n' "$SWNOW"  > "$SW_LOG"
printf '{"ts":%s,"ip":"185.220.101.2","action":"temp","reason":"no_target_vhost action=temp swarm-corroborated hosts=2","evidence":{"swarm":true,"hosts":2}}\n' "$SWNOW" >> "$SW_LOG"
SW_CUT=$(( SWNOW - 86400 ))
SW_STATE_SAVE="${STATE_DIR:-}"; STATE_DIR="$SW_ST"

# Disabled → the section is a silent no-op (empty body).
SWARM_ENABLE=false
check swplane-off "$(swatter_swarm_section 24h "$SW_CUT" "$SW_LOG" | grep -c .)" "0"

# Enabled → section sets globals; the summary line renders them. Assert on full,
# fixed-string phrases (grep -Fc) so digits can't false-match a substring.
SWARM_ENABLE=true SWARM_HUB_URL="https://hub.example" SWARM_MAX_AGE_DAYS=3
swatter_swarm_section 24h "$SW_CUT" "$SW_LOG" >/dev/null   # sets SWARM_* globals
sum="$(_report_summary_swarm)"
check swplane-feed    "$(printf '%s' "$sum" | grep -Fc 'Consuming 2 fleet IP(s)')" "1"
check swplane-preblk  "$(printf '%s' "$sum" | grep -Fc '2 pre-blocked')"           "1"
check swplane-contrib "$(printf '%s' "$sum" | grep -Fc '4 contributed')"           "1"

# grade/verdict identical with the plane's globals set vs unset
RPT_ACTED=0 RPT_EXEMPT=0 ERR_GENUINE=0 ERR_FATAL=0 OL_HITS=0
_report_grade; g0="$RPT_GRADE"; v0="$(_report_verdict | cut -f1)"
SWARM_FEED_N=99 SWARM_PREBLOCKED=99 SWARM_CONTRIB=99
_report_grade; check swplane-nograde "$RPT_GRADE" "$g0"
check swplane-noverdict "$(_report_verdict | cut -f1)" "$v0"
# Silence invariant as a SOURCE-level guard (robust to line drift): the silence
# gate's body must reference no SWARM_* global.
check swplane-silence-clean "$(awk '/Stay silent only when BOTH planes/,/return 0/' "${ROOT}/lib/report.sh" | grep -c SWARM)" "0"
STATE_DIR="$SW_STATE_SAVE"; SWARM_ENABLE=false; rm -rf "$SW_ST"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
