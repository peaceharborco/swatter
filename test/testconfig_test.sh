#!/usr/bin/env bash
# test/testconfig_test.sh — readiness advisories surface in test-config output.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-tc-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-tc.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
STORE="flatfile"
SWATTER_NO_LOCK=1
INTEL_PROVIDERS="greynoise"
GREYNOISE_KEY=""
ASN_SIGNAL_ENABLE="true"
HOSTING_ASNS_FILE="$state/does-not-exist.txt"
EOF

out="$(bash "${ROOT}/bin/swatter" test-config 2>&1)"
case "$out" in *greynoise*) PASS=$((PASS+1));; *) echo "FAIL mentions-greynoise"; FAIL=$((FAIL+1));; esac
case "$out" in *[Kk]ey*) PASS=$((PASS+1));; *) echo "FAIL warns-empty-key"; FAIL=$((FAIL+1));; esac
case "$out" in *hosting*|*ASN*|*asn*) PASS=$((PASS+1));; *) echo "FAIL warns-asn-file"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
