#!/usr/bin/env bash
# test/cli_test.sh — honeypot + metrics subcommands.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-cli-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-cli.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
HONEYPOT_PATHS_FILE="$state/honeypot.paths"
METRICS_FILE=""
STORE="flatfile"
SWATTER_NO_LOCK=1
EOF

out="$(bash "${ROOT}/bin/swatter" honeypot 2>/dev/null)"
case "$out" in *'Disallow:'*) PASS=$((PASS+1));; *) echo "FAIL honeypot-robots"; FAIL=$((FAIL+1));; esac
case "$out" in *'display:none'*|*'hidden'*) PASS=$((PASS+1));; *) echo "FAIL honeypot-anchor"; FAIL=$((FAIL+1));; esac

out="$(bash "${ROOT}/bin/swatter" metrics --print 2>/dev/null)"
case "$out" in *'swatter_build_info'*) PASS=$((PASS+1));; *) echo "FAIL metrics-print"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
