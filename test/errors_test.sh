#!/usr/bin/env bash
# test/errors_test.sh — errors plane: fatal classification (genuine vs scanner-induced).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
source "${ROOT}/lib/errors.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Fixed clock; fixture digest log written inside the window.
swatter_now() { echo 1782396000; }   # 2026-06-25 12:00:00 UTC
TS="2026-06-25 10:00:00"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/swatter-errt.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ERROR_DIGEST_LOG="${WORK}/digest.log"

# Run the section against the fixture and capture body + counters. Redirection,
# NOT command substitution — the ERR_* globals must persist in this shell.
_run() { swatter_errors_section 24h > "${WORK}/sec.out"; SECTION_OUT="$(cat "${WORK}/sec.out")"; }

SCAN1='PHP Fatal error: Uncaught Error: Undefined constant "ABSPATH" in /home/acct/public_html/wp-settings.php:34'
SCAN2='PHP Fatal error: Uncaught Error: Call to undefined function get_header() in /home/acct/public_html/wp-content/themes/x/index.php:11'
REAL1='PHP Fatal error: Allowed memory size of 536870912 bytes exhausted (tried to allocate 262144 bytes) in /home/acct/public_html/wp-includes/class-wpdb.php:2431'

# --- one-off scanner-signature fatals -> scanner-induced, not genuine ---------
{
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
  echo "[${TS}] [FATAL] [php/acct] ${SCAN2}"
} > "$ERROR_DIGEST_LOG"
_run
check oneoff-total    "$ERR_FATAL" "2"
check oneoff-genuine  "$ERR_FATAL_GENUINE" "0"
check oneoff-scanner  "$ERR_FATAL_SCANNER" "2"
check oneoff-section  "$(printf '%s' "$SECTION_OUT" | grep -c 'Scanner-induced FATALs')" "1"
check oneoff-noverb   "$(printf '%s' "$SECTION_OUT" | grep -c 'FATAL entries (verbatim)')" "0"

# --- same scanner signature repeating >= threshold -> genuine (real breakage) -
{
  for _ in 1 2 3; do echo "[${TS}] [FATAL] [php/acct] ${SCAN2}"; done
} > "$ERROR_DIGEST_LOG"
_run
check repeat-genuine  "$ERR_FATAL_GENUINE" "3"
check repeat-scanner  "$ERR_FATAL_SCANNER" "0"

# --- threshold is tunable -----------------------------------------------------
{
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
} > "$ERROR_DIGEST_LOG"
ERROR_FATAL_SCANNER_REPEATS=2; _run
check tune-genuine    "$ERR_FATAL_GENUINE" "2"
ERROR_FATAL_SCANNER_REPEATS=3; _run
check tune-scanner    "$ERR_FATAL_SCANNER" "2"

# --- a fatal that does not match the pattern is always genuine ---------------
{
  echo "[${TS}] [FATAL] [php/acct] ${REAL1}"
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
} > "$ERROR_DIGEST_LOG"
_run
check mixed-total     "$ERR_FATAL" "2"
check mixed-genuine   "$ERR_FATAL_GENUINE" "1"
check mixed-scanner   "$ERR_FATAL_SCANNER" "1"
check mixed-verb      "$(printf '%s' "$SECTION_OUT" | sed -n '/FATAL entries/,/^$/p' | grep -c 'class-wpdb')" "1"
# genuine list must NOT contain the scanner line; scanner list must.
check mixed-split     "$(printf '%s' "$SECTION_OUT" | sed -n '/Scanner-induced/,$p' | grep -c 'ABSPATH')" "1"

# --- header breakdown only when scanner fatals exist -------------------------
check mixed-header    "$(printf '%s' "$SECTION_OUT" | grep -c '1 genuine · 1 scanner-induced')" "1"
{ echo "[${TS}] [FATAL] [php/acct] ${REAL1}"; } > "$ERROR_DIGEST_LOG"
_run
check plain-header    "$(printf '%s' "$SECTION_OUT" | grep -c 'Fatal: 1  ')" "1"

# --- fail-safe: invalid or empty pattern falls back to the built-in default --
_saved="$ERROR_FATAL_SCANNER"
ERROR_FATAL_SCANNER='(['  # invalid ERE
_errors_validate_fatal_scanner
check regex-fallback  "$ERROR_FATAL_SCANNER" "$_ERR_FATAL_SCANNER_DEFAULT"
ERROR_FATAL_SCANNER='   '
_errors_validate_fatal_scanner
check empty-fallback  "$ERROR_FATAL_SCANNER" "$_ERR_FATAL_SCANNER_DEFAULT"
ERROR_FATAL_SCANNER="$_saved"
# non-numeric repeat threshold falls back to the default (3)
ERROR_FATAL_SCANNER_REPEATS="lots"
_errors_validate_fatal_scanner
check reps-fallback   "$ERROR_FATAL_SCANNER_REPEATS" "3"
# 0 disables the classifier (RED-safe) and must NOT be clamped upward
ERROR_FATAL_SCANNER_REPEATS=0
_errors_validate_fatal_scanner
check reps-zero-kept  "$ERROR_FATAL_SCANNER_REPEATS" "0"
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"
_run
check reps-zero-off   "$ERR_FATAL_GENUINE" "1"
ERROR_FATAL_SCANNER_REPEATS=3

# --- local CLI fatals are vetoed out of the scanner class --------------------
# Real shape from a broken `wp eval` maintenance script: matches the scanner
# pattern ("Undefined constant") and repeats only twice, so without the veto it
# would be filed as bot noise. It ran on the box; it belongs in the genuine count.
CLI1='PHP Fatal error: Uncaught Error: Undefined constant "ok" in phar:///usr/local/bin/wp-cli.phar/vendor/wp-cli/eval-command/src/Eval_Command.php(39) : eval()'"'"'d code:1'
{
  echo "[${TS}] [FATAL] [php/acct] ${CLI1}"
  echo "[${TS}] [FATAL] [php/acct] ${CLI1}"
} > "$ERROR_DIGEST_LOG"
_run
check cli-veto-genuine "$ERR_FATAL_GENUINE" "2"
check cli-veto-scanner "$ERR_FATAL_SCANNER" "0"
# and it must be listed verbatim, not buried in the scanner-induced tail
check cli-veto-verb    "$(printf '%s' "$SECTION_OUT" | sed -n '/FATAL entries/,/^$/p' | grep -c 'wp-cli.phar')" "2"

# a scanner fatal alongside a CLI fatal still splits correctly
{
  echo "[${TS}] [FATAL] [php/acct] ${CLI1}"
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
} > "$ERROR_DIGEST_LOG"
_run
check cli-mixed-genuine "$ERR_FATAL_GENUINE" "1"
check cli-mixed-scanner "$ERR_FATAL_SCANNER" "1"

# veto is disengageable: '^$' matches nothing (a signature is never empty), so it
# restores pre-veto behaviour. Guards the documented recipe against the grep/awk
# dialect gap — '$^' validates under grep -E but is an awk syntax error, which
# would void classification entirely rather than just disabling the veto.
_savedx="$ERROR_FATAL_SCANNER_EXCLUDE"
ERROR_FATAL_SCANNER_EXCLUDE='^$'
{
  echo "[${TS}] [FATAL] [php/acct] ${CLI1}"
  echo "[${TS}] [FATAL] [php/acct] ${CLI1}"
} > "$ERROR_DIGEST_LOG"
_run
check cli-veto-off     "$ERR_FATAL_SCANNER" "2"
ERROR_FATAL_SCANNER_EXCLUDE="$_savedx"

# a genuine bot fatal must STILL be scanner-induced under the default veto —
# regression guard against the veto being written too broadly
{
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
  echo "[${TS}] [FATAL] [php/acct] ${SCAN2}"
} > "$ERROR_DIGEST_LOG"
_run
check veto-not-greedy  "$ERR_FATAL_SCANNER" "2"

# a bot-induced phar:// deserialization probe is NOT vetoed in: the veto proves
# "ran locally" only via a known local entrypoint, and this fatal is a security
# event that belongs in the scanner class on the classifier's own terms
PHARBOT='PHP Fatal error: Uncaught Error: Call to undefined function x() in phar:///home/acct/public_html/wp-content/uploads/evil.phar/payload.php:3'
{ echo "[${TS}] [FATAL] [php/acct] ${PHARBOT}"; } > "$ERROR_DIGEST_LOG"
_run
check veto-bare-phar   "$ERR_FATAL_SCANNER" "1"

# fail-safe: invalid or empty veto falls back to the built-in default, never to
# "veto everything" (an empty regex matches every line and would void the class)
ERROR_FATAL_SCANNER_EXCLUDE='(['
_errors_validate_fatal_scanner
check xregex-fallback  "$ERROR_FATAL_SCANNER_EXCLUDE" "$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
ERROR_FATAL_SCANNER_EXCLUDE='   '
_errors_validate_fatal_scanner
check xempty-fallback  "$ERROR_FATAL_SCANNER_EXCLUDE" "$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"

# --- grep/awk dialect gap is caught at config time, not at apply time --------
# '$^' and '(?i)x' are legal to grep -E and syntax errors to awk. Before dual
# validation these sailed through and blew up mid-classification, emptying the
# result and dumping every fatal into genuine. Both patterns, both knobs.
for _bad in '$^' '(?i)x'; do
  ERROR_FATAL_SCANNER_EXCLUDE="$_bad"
  _errors_validate_fatal_scanner
  check "xdialect-${_bad}" "$ERROR_FATAL_SCANNER_EXCLUDE" "$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
  ERROR_FATAL_SCANNER="$_bad"
  _errors_validate_fatal_scanner
  check "sdialect-${_bad}" "$ERROR_FATAL_SCANNER" "$_ERR_FATAL_SCANNER_DEFAULT"
done

# and after a rejected pattern falls back, classification still actually works
{
  echo "[${TS}] [FATAL] [php/acct] ${CLI1}"
  echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"
} > "$ERROR_DIGEST_LOG"
_run
check dialect-recovered-g "$ERR_FATAL_GENUINE" "1"
check dialect-recovered-s "$ERR_FATAL_SCANNER" "1"

# --- parse errors never match the default pattern (real breakage stays red) --
{ echo "[${TS}] [FATAL] [php/acct] PHP Parse error: syntax error, unexpected token \"}\" in /home/acct/public_html/wp-content/plugins/x/x.php:12"; } > "$ERROR_DIGEST_LOG"
_run
check parse-genuine   "$ERR_FATAL_GENUINE" "1"

echo "errors_test: PASS=${PASS} FAIL=${FAIL}"
(( FAIL == 0 ))
