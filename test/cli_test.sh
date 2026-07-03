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

# A store-init failure must ABORT `scan`, not proceed on a silently-empty ledger
# (blocking without the ledger loses caps + repeat-escalation + perm tracking).
# Force it by making the DB path a DIRECTORY so sqlite3 can't open it as a file.
if command -v sqlite3 >/dev/null 2>&1; then
    s2="$(mktemp -d "${TMPDIR:-/tmp}/swatter-cli2.XXXXXX")"
    c2="$(mktemp "${TMPDIR:-/tmp}/swatter-cli2-conf.XXXXXX")"
    mkdir -p "$s2/log" "$s2/none" "$s2/swatter.db"   # swatter.db as a dir -> open fails
    cat > "$c2" <<EOF
STATE_DIR="$s2"
LOG_DIR="$s2/log"
STORE="sqlite"
SWATTER_NO_LOCK=1
CF_MODE="off"
INTEL_PROVIDERS=""
DOMLOGS_GLOB="$s2/none/*"
EOF
    SWATTER_CONF="$c2" bash "${ROOT}/bin/swatter" scan --dry-run >/dev/null 2>"$s2/err"; rc=$?
    [[ $rc -ne 0 ]] && PASS=$((PASS+1)) || { echo "FAIL scan-store-init-abort-rc (got $rc)"; FAIL=$((FAIL+1)); }
    grep -qi "store init" "$s2/err" && PASS=$((PASS+1)) || { echo "FAIL scan-store-init-abort-msg"; FAIL=$((FAIL+1)); }
    # And the scan itself must NOT have run (no "scan complete" line).
    grep -qi "scan complete" "$s2/err" && { echo "FAIL scan-ran-despite-broken-store"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
    rm -rf "$s2" "$c2"
fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
