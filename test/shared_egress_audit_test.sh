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

# The CIDR tokens are the point of this list, not padding. import-bans accepts a
# prefix (swatter_is_valid_ip_or_cidr) and hands it straight to `csf -d`, so a
# gate that only recognizes member ADDRESSES refuses 104.28.9.9 on one line and
# then permanently bans all of consumer WARP on the next — the single worst
# outcome the whole policy exists to prevent. 192.0.2.0/24 proves the refusal is
# scoped to overlap and did not just break CIDR imports.
printf '104.28.9.9\n192.0.2.77\n104.28.0.0/24\n104.28.0.0/16\n192.0.2.0/24\n' > "$WORK/bans.txt"
out="$(sw import-bans "$WORK/bans.txt")"
db="$WORK/state/swatter.db"
imported() { sqlite3 "$db" "SELECT COUNT(*) FROM actions WHERE ip='$1' AND action='perm';" 2>/dev/null || echo 0; }

check import-skips-shared "$(imported 104.28.9.9)" "0"
check import-keeps-normal "$(imported 192.0.2.77)" "1"
check import-refuses-cidr-24 "$(imported 104.28.0.0/24)" "0"
check import-refuses-cidr-16 "$(imported 104.28.0.0/16)" "0"
check import-keeps-normal-cidr "$(imported 192.0.2.0/24)" "1"
case "$out" in *"skip shared-egress"*) PASS=$((PASS+1));;
  *) echo "FAIL import-logs-skip: ${out}"; FAIL=$((FAIL+1));; esac
# The refusal has to be visible: a bulk import that would blanket a shared pool
# is an operator error worth a warning, not a silent one-fewer-line outcome.
case "$out" in *"REFUSED 104.28.0.0/16"*) PASS=$((PASS+1));;
  *) echo "FAIL import-logs-cidr-refusal: ${out}"; FAIL=$((FAIL+1));; esac

# --- shared-egress-audit ---
now="$(date +%s)"
seed() {  # <ip>
  sqlite3 "$db" "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
                 VALUES('$1',${now},${now},91,1,0,1,'x','csf');
                 INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
                 VALUES('$1',${now},'perm','csf',0,91,'seeded',0);"
}
seed 104.28.11.11
seed 192.0.2.99

out="$(sw shared-egress-audit)"
case "$out" in *104.28.11.11*) PASS=$((PASS+1));;
  *) echo "FAIL audit-lists-shared: ${out}"; FAIL=$((FAIL+1));; esac
case "$out" in *192.0.2.99*) echo "FAIL audit-lists-normal: ${out}"; FAIL=$((FAIL+1));;
  *) PASS=$((PASS+1));; esac
permflag() { sqlite3 "$db" "SELECT perm FROM offenders WHERE ip='$1';"; }
check audit-readonly-no-change "$(permflag 104.28.11.11)" "1"

out="$(sw shared-egress-audit --fix)"
check audit-fix-clears     "$(permflag 104.28.11.11)" "0"
check audit-fix-spares     "$(permflag 192.0.2.99)"   "1"
# --fix must NOT allowlist: allow.cidr stays empty.
check audit-fix-no-allow   "$(grep -c . "$WORK/etc/allow.cidr" | tr -d ' ')" "0"

# The two cases above pass identically whether or not $failed/rc and the count
# gate exist at all — deleting either from bin/swatter still leaves all of the
# assertions above green (CF_MODE=off makes swatter_cf_unblock a no-op 0, and
# the fake csf above is an unconditional `exit 0`, so nothing ever drives a
# real backend to failure). That is exactly the "test passes while production
# is broken" shape this task's own design doc warns against, so the two cases
# below drive a REAL backend failure and a REAL over-the-cap selection, and
# check the exit status directly rather than through a command substitution
# (`out="$(sw ...)"` loses no exit status by itself, but making the check
# explicit — write to a file, read $? right after — removes any doubt).

# --- partial-failure verification: a real backend failure must produce
# PARTIAL + a non-zero exit, and must not stop the run for the other IP.
BADIP="104.28.20.1"
FAKEBIN2="$(mktemp -d "${TMPDIR:-/tmp}/swatter-fakecsf2.XXXXXX")"
cat > "$FAKEBIN2/csf" <<EOF
#!/bin/sh
if [ "\$1" = "-dr" ] && [ "\$2" = "$BADIP" ]; then
  echo "simulated failure" >&2
  exit 1
fi
exit 0
EOF
chmod +x "$FAKEBIN2/csf"
trap 'rm -rf "$WORK" "$FAKEBIN" "$FAKEBIN2"' EXIT

seed 104.28.20.1
seed 104.28.20.2
SWATTER_CONF="$WORK/etc/swatter.conf" PATH="$FAKEBIN2:$PATH" \
    bash "${ROOT}/bin/swatter" shared-egress-audit --fix >"$WORK/fix-partial.out" 2>&1
rc_partial=$?
fixout="$(cat "$WORK/fix-partial.out")"
[[ "$rc_partial" -eq 1 ]] && PASS=$((PASS+1)) \
  || { echo "FAIL audit-fix-partial-rc (got ${rc_partial}): ${fixout}"; FAIL=$((FAIL+1)); }
case "$fixout" in *"104.28.20.1"*"PARTIAL"*) PASS=$((PASS+1));;
  *) echo "FAIL audit-fix-partial-marks-failed: ${fixout}"; FAIL=$((FAIL+1));; esac
case "$fixout" in *"104.28.20.2"*"ok"*) PASS=$((PASS+1));;
  *) echo "FAIL audit-fix-partial-still-processes-other: ${fixout}"; FAIL=$((FAIL+1));; esac

# --- count-gate verification: over SHARED_EGRESS_AUDIT_MAX without --force
# must refuse AND must not have mutated anything yet (offenders.perm intact
# for every selected IP) — proving the gate fires before any unblock, not that
# it merely races the loop and reports failure after partial damage.
seed 104.28.30.1
seed 104.28.30.2
SWATTER_CONF="$WORK/etc/swatter.conf" PATH="$FAKEBIN:$PATH" SHARED_EGRESS_AUDIT_MAX=1 \
    bash "${ROOT}/bin/swatter" shared-egress-audit --fix >"$WORK/fix-gate.out" 2>&1
rc_gate=$?
[[ "$rc_gate" -ne 0 ]] && PASS=$((PASS+1)) \
  || { echo "FAIL audit-fix-count-gate-rc (got ${rc_gate})"; FAIL=$((FAIL+1)); }
check audit-fix-count-gate-untouched-1 "$(permflag 104.28.30.1)" "1"
check audit-fix-count-gate-untouched-2 "$(permflag 104.28.30.2)" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
