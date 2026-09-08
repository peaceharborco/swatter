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

# --- TZ wrapper: process-wide TZ=UTC must not drop an in-window local stamp --
# The parser unsets TZ for mktime (errors.sh Apache collector). A 10:00 stamp
# on 2026-06-25 is inside a 24h window from 12:00 UTC on any host TZ that is
# not more than 10 hours ahead of UTC — and on UTC it is trivially inside.
TZ=UTC
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
_run
check tz-n         "$MAILCAMP_N" "1"
check tz-unset     "$(grep -c 'unset TZ' "${ROOT}/lib/mail_campaigns.sh")" "1"
unset TZ
export TZ=UTC

echo "PASS=$PASS FAIL=$FAIL"
(( FAIL == 0 ))
