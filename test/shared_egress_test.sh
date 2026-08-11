#!/usr/bin/env bash
# test/shared_egress_test.sh — shared consumer-VPN egress identification:
# CIDR-first, ASN fallback, fail-open, and the /0 poison guard.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"   # _cidr_overlaps_file, _ipv6_expand
source "${ROOT}/lib/asn.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
yes_() { local name="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); else echo "FAIL ${name}"; FAIL=$((FAIL+1)); fi; }
no_()  { local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL ${name}"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-se.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/asn"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_DNS=1
SHARED_EGRESS_ENABLE="true"
SHARED_EGRESS_CIDR_FILE="$STATE_DIR/se.cidr"
SHARED_EGRESS_ASNS_FILE="$STATE_DIR/se-asns.txt"

CYMRU_TXT=""
_swatter_dns_txt() { [[ -n "$CYMRU_TXT" ]] && printf '%s\n' "$CYMRU_TXT"; }
reset() { _SW_SHARED_CIDR_OK=""; rm -rf "${STATE_DIR:?}/asn"; mkdir -p "$STATE_DIR/asn"; }

# --- CIDR arm: matches with NO DNS at all ---
printf '104.28.0.0/16 # WARP\n' > "$SHARED_EGRESS_CIDR_FILE"
: > "$SHARED_EGRESS_ASNS_FILE"
SWATTER_HAVE_DNS=0; reset
check cidr-match "$(swatter_is_shared_egress 104.28.1.1)" "cidr"
no_ cidr-nonmatch swatter_is_shared_egress 192.0.2.5
SWATTER_HAVE_DNS=1

# --- /0 poison guard: one bad line disables the whole CIDR arm ---
printf '0.0.0.0/0\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
no_ zeroslash-rejected swatter_is_shared_egress 192.0.2.5
no_ zeroslash-no-selfmatch swatter_is_shared_egress 104.28.1.1

# --- over-broad guard: /8 is narrower than /0 but still far too wide ---
printf '104.0.0.0/8\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
no_ overbroad-rejected swatter_is_shared_egress 104.28.1.1

# --- CIDR TOKENS: a prefix that overlaps a protected range must match too ---
# import-bans and _swatter_apply_plane both accept a prefix as a block target,
# so a policy that only recognized member addresses would refuse 104.28.1.1 and
# then perm-ban 104.28.0.0/16 — the whole pool — on the next line of the same
# file. Both directions of overlap count: the token inside the range, and the
# range inside the token.
printf '104.28.0.0/16 # WARP\n' > "$SHARED_EGRESS_CIDR_FILE"
: > "$SHARED_EGRESS_ASNS_FILE"
SWATTER_HAVE_DNS=0; reset
check cidr-token-narrower "$(swatter_is_shared_egress 104.28.0.0/24)" "cidr"
check cidr-token-exact    "$(swatter_is_shared_egress 104.28.0.0/16)" "cidr"
check cidr-token-wider    "$(swatter_is_shared_egress 104.0.0.0/8)"   "cidr"
check cidr-token-offset   "$(swatter_is_shared_egress 104.28.9.0/24)" "cidr"
no_ cidr-token-nonmatch swatter_is_shared_egress 192.0.2.0/24
no_ cidr-token-adjacent swatter_is_shared_egress 104.29.0.0/16
# v6 parity: the same overlap logic, both directions.
printf '2001:db8:1::/48 # documentation range\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
check cidr6-token-narrower "$(swatter_is_shared_egress 2001:db8:1:2::/64)" "cidr"
check cidr6-token-wider    "$(swatter_is_shared_egress 2001:db8::/32)"     "cidr"
no_ cidr6-token-nonmatch swatter_is_shared_egress 2001:db8:9::/48
printf '104.28.0.0/16 # WARP\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
SWATTER_HAVE_DNS=1

# --- ASN arm ---
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"
printf '64496 # Example consumer VPN\n' > "$SHARED_EGRESS_ASNS_FILE"; reset
CYMRU_TXT='64496 | 203.0.113.0/24 | ZZ | example | 2020-01-01'
check asn-match "$(swatter_is_shared_egress 203.0.113.64)" "AS64496(Example consumer VPN)"
reset; CYMRU_TXT='16276 | 51.222.0.0/16 | FR | ripencc | 2015-01-01'
no_ asn-unlisted swatter_is_shared_egress 51.222.1.1

# Whether a DNS lookup HAPPENED is the assertion for the two cases below, and
# swatter_is_shared_egress resolves inside $( ) — so the tally has to survive a
# subshell. A file does; a shell variable would silently read 0 either way.
DNS_LOG="$STATE_DIR/dns-calls"; : > "$DNS_LOG"
_swatter_dns_txt() { echo x >> "$DNS_LOG"; [[ -n "$CYMRU_TXT" ]] && printf '%s\n' "$CYMRU_TXT"; }
dns_calls() { grep -c . "$DNS_LOG" | tr -d ' '; }

# The ASN arm must be SKIPPED for a prefix token: a prefix has no single origin
# ASN, so the lookup can only ever waste a DNS round trip (and, cached under the
# raw token, poison $STATE_DIR/asn with a "1.0.28.104/24"-shaped key).
reset; CYMRU_TXT='64496 | 203.0.113.0/24 | ZZ | example | 2020-01-01'
: > "$DNS_LOG"
no_ asn-arm-skipped-for-prefix swatter_is_shared_egress 203.0.113.0/24
check asn-arm-no-dns-for-prefix "$(dns_calls)" "0"

# The ASN arm must also be inert when the list holds only comments. The shipped
# /etc/swatter/shared-egress-asns.txt is exactly that shape — documentation, no
# entries — so a `-s` (non-empty) gate here bought a Cymru lookup per perm
# candidate against a list nothing can match.
reset; printf '# only comments, no entries\n#64496 # commented out\n' > "$SHARED_EGRESS_ASNS_FILE"
: > "$DNS_LOG"
no_ asn-comments-only-no-match swatter_is_shared_egress 203.0.113.64
check asn-comments-only-no-dns "$(dns_calls)" "0"
printf '64496 # Example consumer VPN\n' > "$SHARED_EGRESS_ASNS_FILE"; reset
# Control: with a real entry the arm IS live and DOES resolve — otherwise the
# two zero-lookup assertions above would also pass on a permanently dead arm.
: > "$DNS_LOG"
check asn-live-arm-match "$(swatter_is_shared_egress 203.0.113.64)" "AS64496(Example consumer VPN)"
check asn-live-arm-resolves "$(dns_calls)" "1"

# --- fail open: DNS dead + no CIDR match ---
reset; CYMRU_TXT=""
no_ dns-fail-open swatter_is_shared_egress 51.222.1.1

# --- disable switch ---
reset; SHARED_EGRESS_ENABLE="false"
no_ disabled swatter_is_shared_egress 104.28.1.1
SHARED_EGRESS_ENABLE="true"

# --- missing / empty files fail open ---
reset; rm -f "$SHARED_EGRESS_CIDR_FILE" "$SHARED_EGRESS_ASNS_FILE"
no_ missing-files swatter_is_shared_egress 104.28.1.1
reset; : > "$SHARED_EGRESS_CIDR_FILE"; : > "$SHARED_EGRESS_ASNS_FILE"
no_ empty-files swatter_is_shared_egress 104.28.1.1

# --- poisoned ASN cache is rejected on READ, not just on write ---
# Asserted against swatter_asn_resolve DIRECTLY, which is the only place the
# read-time validation is observable. Routing it through swatter_is_shared_egress
# proves nothing: a corrupt cached value is compared against a list of numeric
# ASNs, so it cannot match whether or not it was validated — that assertion stays
# green with the validation deleted. Here, deleting it makes swatter_asn_resolve
# hand "not-an-asn" back to its caller as a resolved ASN.
printf '64496 # Example consumer VPN\n' > "$SHARED_EGRESS_ASNS_FILE"
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
printf 'not-an-asn' > "$STATE_DIR/asn/203.0.113.9"
CYMRU_TXT=""   # cache is the only source; a corrupt entry must not be trusted
check poisoned-cache-not-returned "$(swatter_asn_resolve 203.0.113.9)" ""
no_ poisoned-cache-resolve-fails swatter_asn_resolve 203.0.113.9
no_ poisoned-cache-rejected swatter_is_shared_egress 203.0.113.9

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
