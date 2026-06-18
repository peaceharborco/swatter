#!/usr/bin/env bash
# test/greynoise_test.sh — GreyNoise mapping with mocked curl.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/providers/greynoise.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-gn.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; GREYNOISE_KEY="testkey"; GREYNOISE_DAILY_QUOTA=1000
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=1

# Mock curl: echo whatever $GN_RESP holds, exit per $GN_RC.
GN_RESP='{}'; GN_RC=0
curl() { printf '%s' "$GN_RESP"; return "$GN_RC"; }

field() { provider_greynoise "$1" 2>/dev/null | cut -f"$2"; }
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

GN_RESP='{"classification":"malicious","riot":false,"name":"Mirai"}'
check mal-score "$(field 1.1.1.1 1)" "100"
check mal-supp  "$(field 1.1.1.1 4)" ""

GN_RESP='{"classification":"benign","riot":true,"name":"Google"}'
check riot-score "$(field 2.2.2.2 1)" "0"
check riot-supp  "$(field 2.2.2.2 4)" "suppress"

GN_RESP='{"classification":"benign","riot":false,"name":"Censys"}'
check ben-score "$(field 3.3.3.3 1)" "0"
check ben-supp  "$(field 3.3.3.3 4)" ""

GN_RESP='{"classification":"unknown","riot":false}'
if provider_greynoise 4.4.4.4 >/dev/null 2>&1; then echo "FAIL unknown-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

# Transport failure -> no-data.
GN_RC=7; GN_RESP=''
if provider_greynoise 5.5.5.5 >/dev/null 2>&1; then echo "FAIL curlfail-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
GN_RC=0

# Empty key -> no-data.
GREYNOISE_KEY=""
if provider_greynoise 6.6.6.6 >/dev/null 2>&1; then echo "FAIL nokey-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

# Daily quota exhausted -> no-data (restore key + a good response so only quota gates it).
GREYNOISE_KEY="testkey"; GREYNOISE_DAILY_QUOTA=0
GN_RESP='{"classification":"malicious","riot":false,"name":"Mirai"}'
if provider_greynoise 7.7.7.7 >/dev/null 2>&1; then echo "FAIL quota-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
GREYNOISE_DAILY_QUOTA=1000

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
