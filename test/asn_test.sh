#!/usr/bin/env bash
# test/asn_test.sh — Cymru ASN resolve/match (mocked DNS) + attack-shaped gate.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/asn.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-asn.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/asn"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_DNS=1; ASN_SIGNAL_ENABLE="true"; W_ASN=12
HOSTING_ASNS_FILE="$STATE_DIR/hosting.txt"
printf '16276 # OVH\n14061 # DigitalOcean\n' > "$HOSTING_ASNS_FILE"

# Mock TXT resolver: Cymru origin format "ASN | prefix | CC | registry | date".
CYMRU_TXT=""
_swatter_dns_txt() { [[ -n "$CYMRU_TXT" ]] && printf '%s\n' "$CYMRU_TXT"; }

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

CYMRU_TXT='16276 | 51.222.0.0/16 | FR | ripencc | 2015-01-01'
check resolve-ovh "$(swatter_asn_resolve 51.222.1.1)" "16276"
if swatter_asn_is_hosting 51.222.1.1 >/dev/null; then PASS=$((PASS+1)); else echo "FAIL ovh-is-hosting"; FAIL=$((FAIL+1)); fi

CYMRU_TXT='15169 | 8.8.8.0/24 | US | arin | 2000-01-01'
rm -f "$STATE_DIR/asn/8.8.8.8"
if swatter_asn_is_hosting 8.8.8.8 >/dev/null; then echo "FAIL google-not-hosting"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

# Attack-shaped gate.
if _swatter_asn_attack_shaped '{"sub":{"burst":10},"hibad_fail":12,"decisive_rule":""}'; then PASS=$((PASS+1)); else echo "FAIL shaped-hibad"; FAIL=$((FAIL+1)); fi
if _swatter_asn_attack_shaped '{"sub":{"burst":80},"hibad_fail":0,"decisive_rule":""}'; then PASS=$((PASS+1)); else echo "FAIL shaped-burst"; FAIL=$((FAIL+1)); fi
if _swatter_asn_attack_shaped '{"sub":{"burst":5},"hibad_fail":0,"decisive_rule":"scanner_profile"}'; then PASS=$((PASS+1)); else echo "FAIL shaped-rule"; FAIL=$((FAIL+1)); fi
if _swatter_asn_attack_shaped '{"sub":{"burst":5},"hibad_fail":0,"decisive_rule":""}'; then echo "FAIL clean-not-shaped"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
