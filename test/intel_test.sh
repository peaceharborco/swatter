#!/usr/bin/env bash
# test/intel_test.sh — intel dispatch: max score, suppress verdict, legacy 3-field.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/intel.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-intel.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/intel"
INTEL_CACHE_TTL=86400

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Fake providers (4-field, 3-field legacy, and a suppress verdict).
provider_high()    { printf '90\t%s\thigh\t\n'      "$INTEL_CACHE_TTL"; }
provider_legacy()  { printf '40\t%s\tlegacy\n'      "$INTEL_CACHE_TTL"; }   # 3-field
provider_riot()    { printf '0\t%s\triot:google\tsuppress\n' "$INTEL_CACHE_TTL"; }
provider_nodata()  { return 1; }

# Max across providers, no suppress.
INTEL_PROVIDERS="legacy high"
out="$(swatter_intel_score 1.2.3.4)"
check max-score   "$(printf '%s' "$out" | cut -f1)" "90"
check max-supp0   "$(printf '%s' "$out" | cut -f3)" "0"

# Suppress flag set when any provider suppresses, even alongside a high score.
INTEL_PROVIDERS="high riot"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 5.6.7.8)"
check supp-flag   "$(printf '%s' "$out" | cut -f3)" "1"

# No-data provider contributes nothing.
INTEL_PROVIDERS="nodata"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 9.9.9.9)"
check nodata      "$(printf '%s' "$out" | cut -f1)" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
