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

# the apply path must pass the veto via ENVIRON, never awk's -v. The default
# contains `wp-cli\.phar`: through ENVIRON the backslash survives and `\.` is a
# literal dot, but -v escape-processes it to `wp-cli.phar`, where `.` matches ANY
# character. This signature carries an 'X' where the dot belongs, so it is NOT
# vetoed under ENVIRON (stays scanner) and WOULD be vetoed — wrongly pushed into
# the genuine count — under -v. Fails loudly if anyone "simplifies" the plumbing.
ERROR_FATAL_SCANNER_EXCLUDE="$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
ERROR_FATAL_SCANNER_REPEATS=3
ENVBOT='PHP Fatal error: Uncaught Error: Call to undefined function x() in /home/acct/public_html/wp-cliXphar:3'
{ echo "[${TS}] [FATAL] [php/acct] ${ENVBOT}"; } > "$ERROR_DIGEST_LOG"
_run
check environ-not-dashv "$ERR_FATAL_SCANNER" "1"
check environ-not-genuine "$ERR_FATAL_GENUINE" "0"

# fail-safe: invalid or empty veto falls back to the built-in default, never to
# "veto everything" (an empty regex matches every line and would void the class)
ERROR_FATAL_SCANNER_EXCLUDE='(['
_errors_validate_fatal_scanner
check xregex-fallback  "$ERROR_FATAL_SCANNER_EXCLUDE" "$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
ERROR_FATAL_SCANNER_EXCLUDE='   '
_errors_validate_fatal_scanner
check xempty-fallback  "$ERROR_FATAL_SCANNER_EXCLUDE" "$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"

# --- grep/awk dialect gap is caught at config time, not at apply time --------
# '$^' and '(?i)x' are legal to grep -E and rejected by SOME awks. Which ones is
# a property of the local awk, not of swatter, and it moves with the version:
# BSD awk (macOS) rejects both, gawk 5.4 rejects '(?i)x' only, gawk 5.2 (CI)
# accepts both. So do NOT assert "this pattern always falls back" — that
# hardcodes one dialect and fails everywhere else, which is exactly how this
# suite came to pass on macOS and fail in CI. Assert instead the invariant that
# holds in every dialect and is the whole point of validating with awk as well
# as grep: whatever survives validation is a pattern THIS awk can compile, so
# classification can never abort mid-run, empty `marked`, and dump every fatal
# into genuine. Where the dialect gap does exist locally, also pin the fallback
# target — that is the half that catches a validator which forgot to probe awk,
# so it bites on BSD awk and gawk >= 5.3 but is vacuous on an awk that accepts
# both probes. There is no portable pattern that every awk rejects and grep
# accepts, so that asymmetry is inherent, not an oversight.
_awk_compiles() {  # 0 = this awk can compile the regex, 1 = it cannot
  SWATTER_RE_CHK="$1" awk 'BEGIN { r = ("x" ~ ENVIRON["SWATTER_RE_CHK"]) }' </dev/null 2>/dev/null
}
for _bad in '$^' '(?i)x'; do
  _rejected=0; _awk_compiles "$_bad" || _rejected=1

  ERROR_FATAL_SCANNER_EXCLUDE="$_bad"
  _errors_validate_fatal_scanner
  _awk_compiles "$ERROR_FATAL_SCANNER_EXCLUDE" && _r=compiles || _r=uncompilable
  check "xdialect-${_bad}" "$_r" "compiles"
  (( _rejected )) && check "xdialect-fallback-${_bad}" \
    "$ERROR_FATAL_SCANNER_EXCLUDE" "$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"

  ERROR_FATAL_SCANNER="$_bad"
  _errors_validate_fatal_scanner
  _awk_compiles "$ERROR_FATAL_SCANNER" && _r=compiles || _r=uncompilable
  check "sdialect-${_bad}" "$_r" "compiles"
  (( _rejected )) && check "sdialect-fallback-${_bad}" \
    "$ERROR_FATAL_SCANNER" "$_ERR_FATAL_SCANNER_DEFAULT"
done

# and after a rejected pattern falls back, classification still actually works.
# Reset both knobs explicitly: on an awk that ACCEPTS the probes above they are
# still set to '(?i)x' here, and this block is about post-fallback behaviour, not
# about whatever the loop happened to leave behind.
ERROR_FATAL_SCANNER="$_ERR_FATAL_SCANNER_DEFAULT"
ERROR_FATAL_SCANNER_EXCLUDE="$_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT"
_errors_validate_fatal_scanner
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

# --- fan-out threshold knob: validation + fail direction ----------------------
# Non-numeric, negative and empty all fall back to the built-in default (4).
# Never clamp upward: 0 and 1 are legal and are the RED-safe end of the range.
_fanout_default=4
ERROR_FATAL_FANOUT_ACCOUNTS="abc"; _errors_validate_fatal_scanner
check fanout-knob-nonnum   "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS=""; _errors_validate_fatal_scanner
check fanout-knob-empty    "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS="-2"; _errors_validate_fatal_scanner
check fanout-knob-negative "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS="4.5"; _errors_validate_fatal_scanner
check fanout-knob-float    "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS=0; _errors_validate_fatal_scanner
check fanout-knob-zero-ok  "$ERROR_FATAL_FANOUT_ACCOUNTS" "0"
ERROR_FATAL_FANOUT_ACCOUNTS=1; _errors_validate_fatal_scanner
check fanout-knob-one-ok   "$ERROR_FATAL_FANOUT_ACCOUNTS" "1"
ERROR_FATAL_FANOUT_ACCOUNTS=12; _errors_validate_fatal_scanner
check fanout-knob-passthru "$ERROR_FATAL_FANOUT_ACCOUNTS" "12"
# A threshold no account count can ever reach is "gate off" wearing the costume
# of a configured value, and it fails silent-and-green. Bound the width so a typo
# or a pasted digit run lands on the default with a warning instead.
ERROR_FATAL_FANOUT_ACCOUNTS="9999999999999999999999999"; _errors_validate_fatal_scanner
check fanout-knob-huge     "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS="99999"; _errors_validate_fatal_scanner
check fanout-knob-maxwidth "$ERROR_FATAL_FANOUT_ACCOUNTS" "99999"
ERROR_FATAL_SCANNER_REPEATS="1234567"; _errors_validate_fatal_scanner
check repeats-knob-huge    "$ERROR_FATAL_SCANNER_REPEATS" "3"
ERROR_FATAL_SCANNER_REPEATS=3
ERROR_FATAL_FANOUT_ACCOUNTS=4
# the shipped default must match the validation fallback and the example conf
check fanout-default-common "$(grep -c '^ERROR_FATAL_FANOUT_ACCOUNTS=4$' "${ROOT}/lib/common.sh")" "1"
check fanout-default-conf   "$(grep -c '^ERROR_FATAL_FANOUT_ACCOUNTS=4$' "${ROOT}/config/swatter.example.conf")" "1"

# --- fan-out gate: breadth joins depth ---------------------------------------
# One shared bug across N accounts is N raw signatures of count 1, so the depth
# gate never fires on it. Breadth is what catches it.
_mkfan() { # _mkfan <n_accounts> <root> <tag_override|-> <msg>
  local n="$1" root="$2" tag="$3" msg="$4" i a
  for i in $(seq -w 1 "$n"); do a="acct$i"
    printf '[%s] [FATAL] [php/%s] %s in %s/%s/public_html/wp-content/plugins/v/r.php:88\n' \
      "$TS" "$([[ "$tag" == "-" ]] && echo "$a" || echo "$tag")" "$msg" "$root" "$a"
  done
}
FANMSG='PHP Fatal error: Uncaught Error: Call to undefined function shared_helper()'

ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4

# the defect itself: 17 accounts x 1 fatal must be genuine, not scanner
_mkfan 17 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-defect-total   "$ERR_FATAL" "17"
check fanout-defect-genuine "$ERR_FATAL_GENUINE" "17"
check fanout-defect-scanner "$ERR_FATAL_SCANNER" "0"
# a regression to cut -f2- would splice the fan-out count into the digest
# body, where no other assertion here would notice it: SECTION_OUT checks are
# unanchored substring greps and ERR_FATAL_GENUINE is a line count, so a
# leading "4<TAB>" on a FATAL entry changes nothing they inspect. Pin the
# field offset directly: a printed FATAL line must never start with
# "<indent><digits><tab>".
check fanout-body-no-fan "$(printf '%s' "$SECTION_OUT" | grep -cE '^ +[0-9]+'$'\t')" "0"

# multi-home cPanel roots must normalize too, or the account stays in the
# signature and breadth never groups
_mkfan 17 /home2 - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-home2 "$ERR_FATAL_GENUINE" "17"
_mkfan 17 /home3 - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-home3 "$ERR_FATAL_GENUINE" "17"

# the live collector's fallback tag is the literal shared string "unknown"
# (lib/errors.sh:85) — it must NOT be treated as one account
_mkfan 17 /home unknown "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-unknown-sentinel "$ERR_FATAL_GENUINE" "17"
_mkfan 17 /home2 unknown "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-unknown-home2 "$ERR_FATAL_GENUINE" "17"

# cPanel virtfs jails re-nest a normal /home[0-9]*/<acct>/... path one level
# down as /home[0-9]*/virtfs/<acct>/home[0-9]*/<acct>/.... Left unwrapped, tier
# 2 misreads the literal shared string "virtfs" as the account, and even where
# a correct [php/<acct>] tag supplies acct, nsig normalization is untouched by
# which tier won and stays broken on its own. Both shapes must fan out.
{ for i in $(seq -w 1 10); do
    echo "[${TS}] [FATAL] ${FANMSG} in /home/virtfs/acct${i}/home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-virtfs-untagged "$ERR_FATAL_GENUINE" "10"
{ for i in $(seq -w 1 5); do
    echo "[${TS}] [FATAL] [php/acct${i}] ${FANMSG} in /home/virtfs/acct${i}/home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-virtfs-tagged "$ERR_FATAL_GENUINE" "5"

# only the php collector emits a per-account tag; apache emits a vhost, fpm a
# pool. Those must fall back to the account in the path.
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [apache/site${i}.com] ${FANMSG} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-apache-tag "$ERR_FATAL_GENUINE" "17"
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [fpm/8.2:acct${i}] ${FANMSG} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-fpm-tag "$ERR_FATAL_GENUINE" "17"

# threshold behaviour
_mkfan 3 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-below-threshold "$ERR_FATAL_SCANNER" "3"
_mkfan 4 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-at-threshold "$ERR_FATAL_GENUINE" "4"
ERROR_FATAL_FANOUT_ACCOUNTS=8
_mkfan 4 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-tunable-8 "$ERR_FATAL_SCANNER" "4"
ERROR_FATAL_FANOUT_ACCOUNTS=0
_mkfan 17 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-disabled-zero "$ERR_FATAL_SCANNER" "17"
ERROR_FATAL_FANOUT_ACCOUNTS=1
_mkfan 1 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-one-all-genuine "$ERR_FATAL_GENUINE" "1"
ERROR_FATAL_FANOUT_ACCOUNTS=4

# single-account behaviour must be bit-identical to before this change
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-parity-1x1 "$ERR_FATAL_SCANNER" "1"
{ for _ in 1 2; do echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-parity-1x2 "$ERR_FATAL_SCANNER" "2"
{ for _ in 1 2 3; do echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-parity-1x3 "$ERR_FATAL_GENUINE" "3"

# a feed that forges distinct account tags INFLATES fan-out, which grades genuine
# -> RED. That is the safe direction and must stay that way: an untrusted feed
# must never be able to talk the classifier into hiding something.
{ for i in $(seq -w 1 5); do
    echo "[${TS}] [FATAL] [php/forged${i}] ${FANMSG} in /var/www/nohome/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-feed-forged "$ERR_FATAL_GENUINE" "5"

# a fatal with neither tag nor path is depth 1 / breadth 1 -> scanner, exactly as
# today. Tier 3 (the per-line unique key) is a fail-direction backstop, not a
# breadth driver: with no path to normalize, nsig differs exactly when the raw
# signature differs, so such lines can only share an nsig by being identical — and
# then depth already fires. There is deliberately no "many untagged fan out" case.
{ echo "[${TS}] [FATAL] ${FANMSG}"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-single-untagged "$ERR_FATAL_SCANNER" "1"
{ for i in $(seq 1 17); do echo "[${TS}] [FATAL] ${FANMSG} at offset ${i}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-untagged-distinct "$ERR_FATAL_SCANNER" "17"

# a feed that omits the source tag but keeps the path must still fan out, via the
# path tier. This is the case tier 2 exists for.
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] ${FANMSG} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-untagged-path "$ERR_FATAL_GENUINE" "17"

# distinct messages across accounts are unrelated: breadth must not group them
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [php/acct${i}] PHP Fatal error: Uncaught Error: Call to undefined function fn${i}() in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-distinct-sigs "$ERR_FATAL_SCANNER" "17"

# the CLI veto still forces genuine, and wins over a scanner verdict
{ for i in $(seq -w 1 2); do
    echo "[${TS}] [FATAL] [php/acct${i}] PHP Fatal error: Uncaught Error: Undefined constant \"X\" in phar:///usr/local/bin/wp-cli.phar/x.php:9"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-veto-still-genuine "$ERR_FATAL_GENUINE" "2"

# a SUBSEP byte in the line must not merge two accounts' keys
{ printf '[%s] [FATAL] [php/acctA] %s in /home/acctA/public_html/x.php:88\n' "$TS" "$FANMSG"
  printf '[%s] [FATAL] [php/acctB] %s\034 in /home/acctB/public_html/x.php:88\n' "$TS" "$FANMSG"
  printf '[%s] [FATAL] [php/acctC] %s in /home/acctC/public_html/x.php:88\n' "$TS" "$FANMSG"
  printf '[%s] [FATAL] [php/acctD] %s in /home/acctD/public_html/x.php:88\n' "$TS" "$FANMSG"
} > "$ERROR_DIGEST_LOG"; _run
check fanout-subsep-no-merge "$ERR_FATAL_GENUINE" "4"

# a \034 byte inside the matched pattern span must not touch depth or re/ex:
# the SUBSEP strip is for account-identity/nsig key material only, never for
# the raw signature. Splitting "Error:" with an injected byte breaks the
# literal substring SWATTER_FS_RE expects, so this must stay unmatched (and
# thus genuine) regardless of how low its depth or breadth are — a strip that
# leaked into the raw signature would repair the substring and flip this to
# scanner.
FS_BYTE=$'\x1c'
{ printf '[%s] [FATAL] [php/acct] PHP Fatal error: Uncaught Erro%sr: Call to undefined function boom() in /home/acct/public_html/x.php:88\n' \
    "$TS" "$FS_BYTE"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-raw-sig-untouched "$ERR_FATAL_GENUINE" "1"

# --- digest body must distinguish breadth from depth -------------------------
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
_mkfan 17 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-body-max   "$ERR_FATAL_FANOUT_MAX" "17"
check fanout-body-label "$(printf '%s' "$SECTION_OUT" | grep -c 'across 17 accounts')" "1"
# a depth-only cluster (one account, repeats) must NOT claim a cross-account spread
{ for _ in 1 2 3; do echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-body-depth-max   "$ERR_FATAL_FANOUT_MAX" "1"
check fanout-body-depth-label "$(printf '%s' "$SECTION_OUT" | grep -c 'across .* accounts')" "0"
# no genuine fatals at all -> zero, no label
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-body-none-max "$ERR_FATAL_FANOUT_MAX" "0"

# the max must come from a NUMERIC sort, not a lexical one: "9" sorts higher
# than "17" as strings, so a window with two distinct genuine signatures at
# 9 and 17 accounts would silently under-report to 9 under `sort -r`. Both
# breadths sit at/above ERROR_FATAL_FANOUT_ACCOUNTS (still 4 from above), so
# both land in G regardless of message content -- this isolates the sort
# itself, not the classification.
FANMSG_LO='PHP Fatal error: Uncaught Error: Call to undefined function shared_helper_lo()'
FANMSG_HI='PHP Fatal error: Uncaught Error: Call to undefined function shared_helper_hi()'
{ _mkfan 9 /home - "$FANMSG_LO"; _mkfan 17 /home2 - "$FANMSG_HI"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-max-numeric-sort "$ERR_FATAL_FANOUT_MAX" "17"

# --- the two feeds must normalize whitespace identically ---------------------
# Raw PHP logs "PHP Fatal error:" with TWO spaces. The live emit collapses runs
# (see _ERR_AWKLIB emit); this pre-consolidated path did not, so the same error
# produced different signatures on the two feeds and matched no pattern here.
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
TWOSP='PHP Fatal error:  Uncaught Error: Call to undefined function shared_helper()'
{ echo "[${TS}] [FATAL] [php/acct] ${TWOSP} in /home/acct/public_html/x.php:88"; } > "$ERROR_DIGEST_LOG"; _run
check twospace-eligible "$ERR_FATAL_SCANNER" "1"
# and breadth still applies once the pattern matches
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [php/acct${i}] ${TWOSP} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check twospace-fanout "$ERR_FATAL_GENUINE" "17"
# one- and two-space forms of the same error must collapse to ONE signature, so
# three of them cross the depth gate together
{ echo "[${TS}] [FATAL] [php/acct] ${TWOSP} in /home/acct/public_html/x.php:88"
  echo "[${TS}] [FATAL] [php/acct] ${FANMSG} in /home/acct/public_html/x.php:88"
  echo "[${TS}] [FATAL] [php/acct] ${TWOSP} in /home/acct/public_html/x.php:88"
} > "$ERROR_DIGEST_LOG"; _run
check twospace-collapse "$ERR_FATAL_GENUINE" "3"

# --- a wrong-but-non-empty tag must not collapse the fleet onto one account --
# Account identity is the PAIR (source tag, /home path), so two rows share an
# account only when both agree. A feed that stamps a CONSTANT account on every
# line used to win outright — the path was consulted only for an empty or
# "unknown" tag — and six accounts collapsed to fan=1, which is the original
# false GREEN this whole gate exists to close.
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
{ for i in 1 2 3 4 5 6; do
    echo "[${TS}] [FATAL] [php/webuser] ${FANMSG} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-constant-tag "$ERR_FATAL_GENUINE" "6"
# Same shape, but the deflation comes from the path side: a non-php tag (so the
# path tier is live) plus a shared /home segment earlier in the message than the
# real one. match() takes the FIRST /home, so every row read "fake" as its
# account; the per-row source tag is what keeps them apart.
{ for i in 1 2 3 4 5 6; do
    echo "[${TS}] [FATAL] [apache/s${i}.example] ${FANMSG} referer: /home/fake/x.php in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-injected-path "$ERR_FATAL_GENUINE" "6"
# The pair must not INFLATE: one account repeating on one path is still one
# account, however many rows it emits.
{ for i in 1 2; do
    echo "[${TS}] [FATAL] [php/acct1] ${FANMSG} in /home/acct1/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-pair-no-inflate "$ERR_FATAL_SCANNER" "2"
# \003 is the pair separator, so it gets the same key-only hygiene as \034: a
# literal one in the message must not slice a row out of its account bucket.
{ for i in 1 2 3 4 5 6; do
    printf '[%s] [FATAL] [php/acct%s] %s in /home/acct%s/public_html/x\003y.php:88\n' \
      "${TS}" "$i" "${FANMSG}" "$i"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-etx-no-split "$ERR_FATAL_GENUINE" "6"

# --- the scanner default must stay byte-identical in all three copies --------
# A silent split between the shipping default, the validation fallback and the
# documented value is possible today because nothing compares them.
_scan_common="$(sed -n "s/^ERROR_FATAL_SCANNER='\(.*\)'$/\1/p" "${ROOT}/lib/common.sh")"
_scan_errors="$(sed -n "s/^_ERR_FATAL_SCANNER_DEFAULT='\(.*\)'$/\1/p" "${ROOT}/lib/errors.sh")"
_scan_conf="$(sed -n "s/^ERROR_FATAL_SCANNER='\(.*\)'$/\1/p" "${ROOT}/config/swatter.example.conf")"
check threecopy-nonempty "$([[ -n "$_scan_common" ]] && echo ok)" "ok"
check threecopy-errors   "$_scan_errors" "$_scan_common"
check threecopy-conf     "$_scan_conf"   "$_scan_common"

# --- the digest must not claim these came from direct file execution ---------
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"; _run
check copy-no-direct-exec "$(printf '%s' "$SECTION_OUT" | grep -c 'executing PHP files directly')" "0"
check copy-has-heading    "$(printf '%s' "$SECTION_OUT" | grep -c 'Scanner-induced FATALs')" "1"

echo "errors_test: PASS=${PASS} FAIL=${FAIL}"
(( FAIL == 0 ))
