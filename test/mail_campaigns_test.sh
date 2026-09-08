#!/usr/bin/env bash
# test/mail_campaigns_test.sh — SMTP AUTH campaign digest plane.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
source "${ROOT}/lib/mail_campaigns.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

swatter_now() { echo 1782396000; }   # 2026-06-25 12:00:00 UTC
WORK="$(mktemp -d "${TMPDIR:-/tmp}/swatter-mct.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

EXIM_MAINLOG="${WORK}/exim_mainlog"
MAIL_CAMPAIGN_DIGEST="on"
MAIL_CAMPAIGN_MIN_IPS=5
MAIL_CAMPAIGN_LIST_CAP=20
unset MAILCAMP_GAWK_TZ

_line() { # _line <ip> <id>
  printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo.example [%s]:41666: 535 Incorrect authentication data (set_id=%s)\n' "$1" "$2"
}
_run() { swatter_mail_campaigns_section 24h > "${WORK}/sec.out"; SECTION_OUT="$(cat "${WORK}/sec.out")"; }

# --- happy spray: 5 IPs, one attempt each, same mailbox ----------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14; do
  _line "$ip" "box1" >> "$EXIM_MAINLOG"
done
_run
check happy-ok     "$MAILCAMP_OK" "1"
check happy-n      "$MAILCAMP_N" "1"
check happy-fails  "$MAILCAMP_FAILS" "5"
check happy-ips    "$MAILCAMP_IPS" "5"
check happy-lists  "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "1"
check happy-no-unr "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "0"

# --- below threshold: 4 IPs --------------------------------------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13; do
  _line "$ip" "box1" >> "$EXIM_MAINLOG"
done
_run
check below-n      "$MAILCAMP_N" "0"
check below-zero   "$(printf '%s' "$SECTION_OUT" | grep -c 'No SMTP AUTH campaigns this window.')" "1"
check below-absent "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "0"

# --- typo: 23 fails, one IP --------------------------------------------------
: > "$EXIM_MAINLOG"
for _i in $(seq 1 23); do _line "198.51.100.10" "box1" >> "$EXIM_MAINLOG"; done
_run
check typo-n       "$MAILCAMP_N" "0"
check typo-absent  "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "0"

# --- threshold knob ----------------------------------------------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13; do
  _line "$ip" "box1" >> "$EXIM_MAINLOG"
done
MAIL_CAMPAIGN_MIN_IPS=4; _run
check knob-n       "$MAILCAMP_N" "1"
MAIL_CAMPAIGN_MIN_IPS=5

# --- verbatim set_id: shipping vs shipping@x.com -----------------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14; do
  _line "$ip" "shipping" >> "$EXIM_MAINLOG"
  _line "203.0.113.${ip##*.}" "shipping@x.com" >> "$EXIM_MAINLOG"
done
_run
check verbatim-n   "$MAILCAMP_N" "2"

# --- HELO decoy: parenthetical IP is not the connecting IP -------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do
  printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=([203.0.113.9]) [198.51.100.%s]:56131: 535 Incorrect authentication data (set_id=box1)\n' "$n" >> "$EXIM_MAINLOG"
done
_run
check helo-n       "$MAILCAMP_N" "1"
check helo-ips     "$MAILCAMP_IPS" "5"

# --- T5: tab + fake [ip]:port inside set_id (after 535) ----------------------
: > "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data (set_id=x\t[203.0.113.9]:25)\n' >> "$EXIM_MAINLOG"
for n in 11 12 13 14; do _line "198.51.100.$n" "x	[203.0.113.9]:25" >> "$EXIM_MAINLOG"; done
_run
check t5-n         "$MAILCAMP_N" "1"
# Decoy may appear in the mailbox column (verbatim set_id); must not be a connecting IP.
check t5-ips       "$MAILCAMP_IPS" "5"
check t5-mailbox   "$(printf '%s' "$SECTION_OUT" | grep -c '203.0.113.9')" "1"

# --- tab in set_id: shared prefix before tab must not merge -------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do
  _line "198.51.100.$n" "x	alpha" >> "$EXIM_MAINLOG"
  _line "203.0.113.$n" "x	beta" >> "$EXIM_MAINLOG"
done
_run
check tabkey-n     "$MAILCAMP_N" "2"
check tabkey-a     "$(printf '%s' "$SECTION_OUT" | grep -c 'x	alpha')" "1"
check tabkey-b     "$(printf '%s' "$SECTION_OUT" | grep -c 'x	beta')" "1"

# --- drop incomplete lines ---------------------------------------------------
: > "$EXIM_MAINLOG"
printf 'not a stamp dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data (set_id=box1)\n' >> "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo no-addr 535 Incorrect authentication data (set_id=box1)\n' >> "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data\n' >> "$EXIM_MAINLOG"
_run
check drop-fails   "$MAILCAMP_FAILS" "0"
check drop-ok      "$MAILCAMP_OK" "1"

# --- T13: binary byte on one line does not drop the valid neighbor ----------
: > "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data (set_id=box1)\n' >> "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 \x80dovecot_login authenticator failed for H=foo [198.51.100.99]:41666: 535 Incorrect authentication data (set_id=junk)\n' >> "$EXIM_MAINLOG"
for n in 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
_run
# T13: high byte must not drop the valid neighbor; garbage line may still parse.
check t13-fails    "$MAILCAMP_FAILS" "6"
check t13-n        "$MAILCAMP_N" "1"

# --- IPv6 connecting IP ------------------------------------------------------
: > "$EXIM_MAINLOG"
for h in 1 2 3 4 5; do
  printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [2001:db8::%s]:465: 535 Incorrect authentication data (set_id=box1)\n' "$h" >> "$EXIM_MAINLOG"
done
_run
check v6-n         "$MAILCAMP_N" "1"
check v6-ips       "$MAILCAMP_IPS" "5"

# --- cap: 25 campaigns, list 20 + remainder ---------------------------------
: > "$EXIM_MAINLOG"
for c in $(seq 1 25); do
  for n in 10 11 12 13 14; do _line "198.51.100.$n" "box$c" >> "$EXIM_MAINLOG"; done
done
_run
check cap-n        "$MAILCAMP_N" "25"
check cap-remain   "$(printf '%s' "$SECTION_OUT" | grep -c '+ 5 more')" "1"
check cap-rows     "$(printf '%s' "$SECTION_OUT" | grep -c '^  box')" "20"

# --- TZ: near-cutoff stamp; mktime must honor host-local zone (v2.15.0) -----
# swatter_now = 1782396000 (2026-06-25 12:00:00 UTC); 24h cutoff =
# 2026-06-24 12:00:00 UTC. Stamp 2026-06-24 10:00:00:
#   TZ=UTC               → 10:00 UTC 24 Jun → BEFORE cutoff → dropped
#   TZ=America/New_York  → 10:00 EDT = 14:00 UTC 24 Jun → AFTER cutoff → kept
# Production _mailcamp_parse uses ( unset TZ; gawk … ). MAILCAMP_GAWK_TZ is
# a test-only hook that exports that TZ into the gawk subshell instead of
# unset. NY keeps the stamp; UTC drops it — the v2.15.0 class if unset TZ
# is deleted while common.sh still exports TZ=UTC.
_ep_utc="$(TZ=UTC gawk 'BEGIN{print mktime("2026 06 24 10 00 00")}')"
_ep_ny="$(TZ=America/New_York gawk 'BEGIN{print mktime("2026 06 24 10 00 00")}')"
if [[ -n "$_ep_utc" && -n "$_ep_ny" && "$_ep_utc" != "$_ep_ny" ]]; then
  check tz-mktime-diff "differ" "differ"
else
  check tz-mktime-diff "utc=${_ep_utc:-empty} ny=${_ep_ny:-empty}" "differ"
fi
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do
  printf '2026-06-24 10:00:00 dovecot_login authenticator failed for H=foo.example [198.51.100.%s]:41666: 535 Incorrect authentication data (set_id=box1)\n' "$n" >> "$EXIM_MAINLOG"
done
MAILCAMP_GAWK_TZ=America/New_York
_run
check tz-ny-n      "$MAILCAMP_N" "1"
MAILCAMP_GAWK_TZ=UTC
_run
check tz-utc-n     "$MAILCAMP_N" "0"
unset MAILCAMP_GAWK_TZ

# --- RETURN trap: section must not clobber the caller's RETURN trap ----------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
_mailcamp_caller_return_probe() { :; }
trap '_mailcamp_caller_return_probe' RETURN
swatter_mail_campaigns_section 24h >/dev/null
trap -p RETURN > "${WORK}/trap.out"
check trap-preserved "$(grep -c '_mailcamp_caller_return_probe' "${WORK}/trap.out")" "1"
trap - RETURN

# --- unreadable live file ----------------------------------------------------
: > "$EXIM_MAINLOG"
chmod 000 "$EXIM_MAINLOG"
_run
check unr-ok       "$MAILCAMP_OK" "0"
check unr-word     "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "1"
check unr-not-zero "$(printf '%s' "$SECTION_OUT" | grep -c 'No SMTP AUTH campaigns')" "0"
chmod 600 "$EXIM_MAINLOG"

# --- selected rotation unreadable: no partial list ---------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
touch -t 202606251000 "$EXIM_MAINLOG-20260625"
chmod 000 "$EXIM_MAINLOG-20260625"
_run
check rot-unr-ok   "$MAILCAMP_OK" "0"
check rot-unr-word "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "1"
check rot-unr-no   "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "0"
chmod 600 "$EXIM_MAINLOG-20260625"
rm -f "$EXIM_MAINLOG-20260625"

# --- ancient unreadable rotation is NOT selected -----------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
touch -t 202001010000 "$EXIM_MAINLOG-20200101"
chmod 000 "$EXIM_MAINLOG-20200101"
_run
check ancient-ok   "$MAILCAMP_OK" "1"
check ancient-n    "$MAILCAMP_N" "1"
chmod 600 "$EXIM_MAINLOG-20200101"
rm -f "$EXIM_MAINLOG-20200101"

# --- rotation sums live + dated file ----------------------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
: > "$EXIM_MAINLOG-20260625"
for n in 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG-20260625"; done
touch -t 202606251000 "$EXIM_MAINLOG-20260625"
_run
check rot-n        "$MAILCAMP_N" "1"
check rot-fails    "$MAILCAMP_FAILS" "5"
rm -f "$EXIM_MAINLOG-20260625"

# --- gzip rotation -----------------------------------------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
: > "${WORK}/rot.txt"
for n in 13 14; do _line "198.51.100.$n" "box1" >> "${WORK}/rot.txt"; done
gzip -c "${WORK}/rot.txt" > "$EXIM_MAINLOG-20260625.gz"
touch -t 202606251000 "$EXIM_MAINLOG-20260625.gz"
_run
check gz-n         "$MAILCAMP_N" "1"
check gz-fails     "$MAILCAMP_FAILS" "5"
rm -f "$EXIM_MAINLOG-20260625.gz"

# --- auto + missing default path: should_run is false (skip, not UNREADABLE) -
EXIM_MAINLOG=""
MAIL_CAMPAIGN_DIGEST="auto"
check auto-skip    "$(_mailcamp_should_run; echo $?)" "1"
# --- on + missing path: section UNREADABLE ----------------------------------
MAIL_CAMPAIGN_DIGEST="on"
EXIM_MAINLOG="${WORK}/no-such-exim"
_run
check on-miss-ok   "$MAILCAMP_OK" "0"
check on-miss-word "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "1"
# --- auto + explicit missing path: UNREADABLE --------------------------------
MAIL_CAMPAIGN_DIGEST="auto"
EXIM_MAINLOG="${WORK}/no-such-exim"
check auto-expl    "$(_mailcamp_should_run; echo $?)" "0"
_run
check auto-expl-ok "$MAILCAMP_OK" "0"
MAIL_CAMPAIGN_DIGEST="on"
EXIM_MAINLOG="${WORK}/exim_mainlog"

echo "PASS=$PASS FAIL=$FAIL"
(( FAIL == 0 ))
