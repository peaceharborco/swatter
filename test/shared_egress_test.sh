#!/usr/bin/env bash
# test/shared_egress_test.sh — shared consumer-VPN egress identification:
# CIDR-first, ASN fallback, fail-open, and the /0 poison guard.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"   # _ip_in_cidr_file, _ipv6_expand
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

# --- ASN arm ---
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"
printf '206092 # VPN Consumer\n' > "$SHARED_EGRESS_ASNS_FILE"; reset
CYMRU_TXT='206092 | 45.157.112.0/24 | CY | ripencc | 2019-01-01'
check asn-match "$(swatter_is_shared_egress 45.157.112.64)" "AS206092(VPN Consumer)"
reset; CYMRU_TXT='16276 | 51.222.0.0/16 | FR | ripencc | 2015-01-01'
no_ asn-unlisted swatter_is_shared_egress 51.222.1.1

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
printf '206092 # VPN Consumer\n' > "$SHARED_EGRESS_ASNS_FILE"
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
printf 'not-an-asn' > "$STATE_DIR/asn/203.0.113.9"
CYMRU_TXT=""   # cache is the only source; a corrupt entry must not be trusted
no_ poisoned-cache-rejected swatter_is_shared_egress 203.0.113.9

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
