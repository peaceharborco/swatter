#!/usr/bin/env bash
# test/shared_egress_audit_test.sh — import-bans gate + shared-egress-audit.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }
# import-bans (DIRECT_BACKEND=csf, swatter's default) needs a real `csf -d` to
# succeed for the control IP, so this test stands in a fake `csf` on PATH (see
# below). Never do that on a box with a REAL csf — that would risk shadowing
# it in a way that touches the actual firewall. Skip clean instead.
command -v csf >/dev/null 2>&1 && { echo "SKIP (real csf present)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/swatter-seaudit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/etc" "$WORK/state"
printf '104.28.0.0/16\n' > "$WORK/etc/shared-egress.cidr"
: > "$WORK/etc/shared-egress-asns.txt"
: > "$WORK/etc/allow.cidr"; : > "$WORK/etc/cloudflare.cidr"; : > "$WORK/etc/monitoring.cidr"

# import-bans takes the blocking state lock (swatter_with_state_lock) BEFORE
# the loop that contains the shared-egress skip line below, so this test
# deliberately does NOT set SWATTER_NO_LOCK=1 here — it exercises the real
# lock-then-log path production actually runs. That used to matter a lot:
# swatter_with_state_lock opened fd 9 via a bare `exec ... 2>/dev/null` (no
# command word), which is a bash quirk where ALL of an unbraced exec's
# redirections attach to the shell PERMANENTLY, not just for that one open —
# so stderr went dark for the rest of the process, and the operator-facing
# "skip shared-egress" log line this task exists to produce would have been
# silently swallowed in every real run, not just dry ones. Fixed in
# lib/common.sh (brace-scoped the 2>/dev/null); see test/state_lock_test.sh
# for the focused regression. (NOTE for future edits to this comment: keep it
# OUTSIDE the <<CONF heredoc below — that heredoc is unquoted for $WORK
# expansion, so any backticks placed inside it are executed as real command
# substitution, not treated as inline-code punctuation.)
cat > "$WORK/etc/swatter.conf" <<CONF
STORE=sqlite
SWATTER_MODE=enforce
STATE_DIR="$WORK/state"
SHARED_EGRESS_ENABLE=true
SHARED_EGRESS_CIDR_FILE="$WORK/etc/shared-egress.cidr"
SHARED_EGRESS_ASNS_FILE="$WORK/etc/shared-egress-asns.txt"
OPERATOR_ALLOW_FILE="$WORK/etc/allow.cidr"
CLOUDFLARE_IPS_FILE="$WORK/etc/cloudflare.cidr"
MONITORING_RANGES_FILE="$WORK/etc/monitoring.cidr"
CF_MODE=off
DIRECT_BACKEND=csf
CONF

sw() { SWATTER_CONF="$WORK/etc/swatter.conf" PATH="$FAKEBIN:$PATH" bash "${ROOT}/bin/swatter" "$@" 2>&1; }

# Stand in a fake csf so swatter_block_direct_perm's enforce path succeeds for
# the control IP — exactly like the existing import-bans coverage in
# cli_test.sh (`import-bans-cap-bypass`). Guarded above: never reached with a
# real csf on PATH.
FAKEBIN="$(mktemp -d "${TMPDIR:-/tmp}/swatter-fakecsf.XXXXXX")"
printf '#!/bin/sh\nexit 0\n' > "$FAKEBIN/csf"; chmod +x "$FAKEBIN/csf"
trap 'rm -rf "$WORK" "$FAKEBIN"' EXIT

printf '104.28.9.9\n192.0.2.77\n' > "$WORK/bans.txt"
out="$(sw import-bans "$WORK/bans.txt")"
db="$WORK/state/swatter.db"
imported() { sqlite3 "$db" "SELECT COUNT(*) FROM actions WHERE ip='$1' AND action='perm';" 2>/dev/null || echo 0; }

check import-skips-shared "$(imported 104.28.9.9)" "0"
check import-keeps-normal "$(imported 192.0.2.77)" "1"
case "$out" in *"skip shared-egress"*) PASS=$((PASS+1));;
  *) echo "FAIL import-logs-skip: ${out}"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
