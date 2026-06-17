#!/usr/bin/env bash
# test/projecthoneypot_test.sh — http:BL decode with a mocked DNS resolver.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/providers/projecthoneypot.sh"

PASS=0; FAIL=0
INTEL_CACHE_TTL=86400; HTTPBL_KEY="abcdefghijkl"; SWATTER_HAVE_DNS=1

# Mock the resolver: return $HBL_A for any query.
HBL_A=""
_swatter_dns_a() { [[ -n "$HBL_A" ]] && printf '%s\n' "$HBL_A"; }

field() { provider_projecthoneypot "$1" 2>/dev/null | cut -f"$2"; }
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# 127.<days>.<threat>.<type>: comment-spammer, threat 255 -> score 100.
HBL_A="127.2.255.4"; check spammer-max "$(field 1.2.3.4 1)" "100"
# harvester, threat 128 -> ~50.
HBL_A="127.1.128.2"; check harvester-mid "$(field 1.2.3.4 1)" "50"
# search-engine type 0: octet3 is an SE id, not a threat -> no-data.
HBL_A="127.0.7.0"
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL se-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
# non-127 first octet -> no-data.
HBL_A="0.0.0.0"
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL non127-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
# IPv6 -> no-data (http:BL is v4 only).
HBL_A="127.2.255.4"
if provider_projecthoneypot 2001:db8::1 >/dev/null 2>&1; then echo "FAIL v6-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
# No DNS client -> no-data.
SWATTER_HAVE_DNS=0
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL nodns-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
SWATTER_HAVE_DNS=1
# Empty key -> no-data.
HTTPBL_KEY=""
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL nokey-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
