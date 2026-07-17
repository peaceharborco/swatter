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

    # import-bans WRITES the ledger too, so it must ALSO abort on a broken store
    # rather than firewall-block without recording (untracked denies). Enforce mode
    # + a ban file with one IP; the abort must happen before any block.
    printf '203.0.113.200\n' > "$s2/bans.txt"
    SWATTER_MODE=enforce SWATTER_CONF="$c2" bash "${ROOT}/bin/swatter" import-bans "$s2/bans.txt" >/dev/null 2>"$s2/err2"; rc=$?
    [[ $rc -ne 0 ]] && PASS=$((PASS+1)) || { echo "FAIL import-store-init-abort-rc (got $rc)"; FAIL=$((FAIL+1)); }
    grep -qi "store init" "$s2/err2" && PASS=$((PASS+1)) || { echo "FAIL import-store-init-abort-msg"; FAIL=$((FAIL+1)); }
    grep -qi "ban(s) applied" "$s2/err2" && { echo "FAIL import-ran-despite-broken-store"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

    # But a READ-ONLY command (status) must NOT inherit the hard abort — it should
    # still run (degrade) on a transiently-broken DB, only warning.
    SWATTER_CONF="$c2" bash "${ROOT}/bin/swatter" status >/dev/null 2>"$s2/err3"; rc=$?
    [[ $rc -eq 0 ]] && PASS=$((PASS+1)) || { echo "FAIL status-should-not-abort (got $rc)"; FAIL=$((FAIL+1)); }
    rm -rf "$s2" "$c2"
fi

# `swatter top -n` must reject a non-numeric N (it is interpolated into SQL LIMIT).
bash "${ROOT}/bin/swatter" top -n 'abc; DROP' >/dev/null 2>"$state/toperr"; rc=$?
[[ $rc -ne 0 ]] && PASS=$((PASS+1)) || { echo "FAIL top-n-nonnumeric-rejected"; FAIL=$((FAIL+1)); }
bash "${ROOT}/bin/swatter" top -n 5 >/dev/null 2>&1 && PASS=$((PASS+1)) || { echo "FAIL top-n-numeric-ok"; FAIL=$((FAIL+1)); }

# import-bans is a deliberate bulk op — it must NOT be truncated by the per-run
# deny cap (default 10). With a fake csf on PATH + enforce, importing 12 IPs must
# apply all 12. (Skip if a real csf is installed so we never shadow it.)
if ! command -v csf >/dev/null 2>&1; then
    fakebin="$(mktemp -d "${TMPDIR:-/tmp}/swatter-fakecsf.XXXXXX")"
    printf '#!/bin/sh\nexit 0\n' > "$fakebin/csf"; chmod +x "$fakebin/csf"
    s3="$(mktemp -d "${TMPDIR:-/tmp}/swatter-imp.XXXXXX")"; c3="$(mktemp)"; mkdir -p "$s3/log"
    cat > "$c3" <<EOF
STATE_DIR="$s3"
LOG_DIR="$s3/log"
STORE="flatfile"
SWATTER_NO_LOCK=1
DIRECT_BACKEND="csf"
CF_MODE="off"
INTEL_PROVIDERS=""
EOF
    : > "$s3/bans.txt"; for i in $(seq 1 12); do printf '203.0.113.%d\n' "$i" >> "$s3/bans.txt"; done
    PATH="$fakebin:$PATH" SWATTER_MODE=enforce SWATTER_CONF="$c3" bash "${ROOT}/bin/swatter" import-bans "$s3/bans.txt" 2>"$s3/err" >/dev/null
    applied="$(sed -n 's/.*: \([0-9]*\) ban(s) applied.*/\1/p' "$s3/err")"
    [[ "$applied" == "12" ]] && PASS=$((PASS+1)) || { echo "FAIL import-bans-cap-bypass (applied='${applied}' want 12)"; FAIL=$((FAIL+1)); }
    rm -rf "$fakebin" "$s3" "$c3"
fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
