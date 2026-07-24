#!/usr/bin/env bash
# test/rollback_ladder_test.sh — bulk rollback of ladder perms: selection from
# sqlite (not the rotated log), single lock acquisition, tolerance of a per-IP
# backend failure (both planes called unconditionally, no &&-short-circuit),
# --dry-run mutating nothing, and the swarm-gap notice.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# --------------------------------------------------------------------------
# Part 1: the sqlite selector, in-process (no CLI involved).
# --------------------------------------------------------------------------
STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_N=3; REPEAT_WINDOW_DAYS=30
swatter_store_init
db="$STATE_DIR/swatter.db"; NOW="$(swatter_now)"; DAY=86400
seedp() { sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('$1',$(( NOW - $2*DAY )),'perm','csf',0,91,'$3',0);"; }

# Two ladder perms inside the window, one outside, one non-ladder perm.
seedp 10.2.0.1 2 'score=91 recidivism=3/30d'
seedp 10.2.0.2 1 'score=95 recidivism=4/30d'
seedp 10.2.0.3 9 'score=91 recidivism=3/30d'   # older than --since
seedp 10.2.0.4 1 'honeypot score=100'          # not a ladder perm

sel="$(swatter_ladder_perms_since $(( NOW - 5*DAY )))"
check rb-selects-two   "$(printf '%s\n' "$sel" | grep -c . )" "2"
check rb-has-1         "$(printf '%s\n' "$sel" | grep -c '^10\.2\.0\.1$')" "1"
check rb-excl-old      "$(printf '%s\n' "$sel" | grep -c '^10\.2\.0\.3$' || true)" "0"
check rb-excl-honeypot "$(printf '%s\n' "$sel" | grep -c '^10\.2\.0\.4$' || true)" "0"

# A never-scanned host (no DB file at all) must not have one PLANTED by a mere
# query — matches the guard Task 5 added to swatter_escalate_preview.
NODB_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb-nodb.XXXXXX")"
(
  STATE_DIR="$NODB_DIR"
  swatter_ladder_perms_since "$(( NOW - 5*DAY ))" >/dev/null 2>&1
)
check rb-no-phantom-db "$( [[ -e "$NODB_DIR/swatter.db" ]] && echo present || echo absent )" "absent"
rm -rf "$NODB_DIR"

# --------------------------------------------------------------------------
# Part 2: the CLI subcommand end-to-end (bin/swatter rollback-ladder).
# --------------------------------------------------------------------------
mkconf() {
    local dir="$1" conf="$2"
    mkdir -p "$dir/log"
    cat > "$conf" <<EOF
STATE_DIR="$dir"
LOG_DIR="$dir/log"
STORE="sqlite"
SWATTER_NO_LOCK=1
DIRECT_BACKEND="csf"
CF_MODE="off"
INTEL_PROVIDERS=""
DOMLOGS_GLOB="$dir/nomatch/*"
REPEAT_N=3
REPEAT_WINDOW_DAYS=30
EOF
}

seed_cli_db() {
    local dir="$1" now="$2"
    sqlite3 "$dir/swatter.db" <<SQL
CREATE TABLE IF NOT EXISTS offenders(
  ip TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER,
  worst_score INTEGER DEFAULT 0, total_offenses INTEGER DEFAULT 0,
  temp_count INTEGER DEFAULT 0, perm INTEGER DEFAULT 0,
  last_label TEXT, channel TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, ts INTEGER,
  action TEXT, channel TEXT, ttl INTEGER, score INTEGER, reason TEXT, dry_run INTEGER);
CREATE INDEX IF NOT EXISTS ix_actions_ip_ts ON actions(ip, ts);
CREATE TABLE IF NOT EXISTS sightings(
  ip TEXT, bucket INTEGER, hits INTEGER DEFAULT 0,
  worst_score INTEGER DEFAULT 0, last_ts INTEGER,
  PRIMARY KEY (ip, bucket));
CREATE TABLE IF NOT EXISTS plane_blocks(
  ip TEXT NOT NULL, plane TEXT NOT NULL,
  kind TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (ip, plane));
CREATE TABLE IF NOT EXISTS pending_blocks(
  ip TEXT NOT NULL, plane TEXT NOT NULL,
  action TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 0,
  reason TEXT, top_vhost TEXT,
  folded INTEGER NOT NULL DEFAULT 0, rep INTEGER NOT NULL DEFAULT 0,
  ev TEXT, audit_action TEXT,
  first_failed INTEGER NOT NULL, last_attempt INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (ip, plane));
INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('10.3.0.1',${now}-1*86400,'perm','csf',0,91,'score=91 recidivism=3/30d',0);
INSERT OR REPLACE INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,perm,channel)
  VALUES('10.3.0.1',${now}-1*86400,${now}-1*86400,91,3,1,'csf');
INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('10.3.0.2',${now}-1*86400,'perm','csf',0,95,'score=95 recidivism=4/30d',0);
INSERT OR REPLACE INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,perm,channel)
  VALUES('10.3.0.2',${now}-1*86400,${now}-1*86400,95,4,1,'csf');
SQL
}

CNOW="$(date -u +%s)"

# --- 2a. --dry-run mutates nothing: no csf calls, ledger perm flags untouched.
d1="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb1.XXXXXX")"; c1="$(mktemp "${TMPDIR:-/tmp}/swatter-rb1-conf.XXXXXX")"
mkconf "$d1" "$c1"; seed_cli_db "$d1" "$CNOW"
fakebin1="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb-fake1.XXXXXX")"
cat > "$fakebin1/csf" <<'EOF'
#!/bin/sh
echo "CSF-CALLED $*" >> "${CSF_CALL_LOG:-/dev/null}"
exit 0
EOF
chmod +x "$fakebin1/csf"
calllog1="$d1/csf-calls.log"
out1="$(PATH="$fakebin1:$PATH" CSF_CALL_LOG="$calllog1" SWATTER_CONF="$c1" \
    bash "${ROOT}/bin/swatter" rollback-ladder --since $(( CNOW - 5*86400 )) --dry-run 2>&1)"
rc1=$?
check dry-run-exit-0     "$rc1" "0"
check dry-run-no-csf-call "$( [[ -s "$calllog1" ]] && echo called || echo none )" "none"
permcount1="$(sqlite3 "$d1/swatter.db" "SELECT COUNT(*) FROM offenders WHERE perm=1;")"
check dry-run-ledger-untouched "$permcount1" "2"
check dry-run-mentions-both "$(printf '%s' "$out1" | grep -c 'would unblock')" "2"
rm -rf "$d1" "$c1" "$fakebin1"

# --- 2b. Loop survives a failing backend: one IP's csf calls fail, the other
# succeeds; both are attempted (loop doesn't abort), overall exit is non-zero,
# and the summary reports 1 partial + 1 unblocked.
d2="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb2.XXXXXX")"; c2="$(mktemp "${TMPDIR:-/tmp}/swatter-rb2-conf.XXXXXX")"
mkconf "$d2" "$c2"; seed_cli_db "$d2" "$CNOW"
fakebin2="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb-fake2.XXXXXX")"
cat > "$fakebin2/csf" <<'EOF'
#!/bin/sh
# Fail every call that targets the "bad" IP; succeed otherwise.
for a in "$@"; do
    [ "$a" = "10.3.0.1" ] && exit 1
done
exit 0
EOF
chmod +x "$fakebin2/csf"
out2="$(PATH="$fakebin2:$PATH" SWATTER_CONF="$c2" \
    bash "${ROOT}/bin/swatter" rollback-ladder --since $(( CNOW - 5*86400 )) 2>&1)"
rc2=$?
check partial-exit-nonzero "$( [[ $rc2 -ne 0 ]] && echo yes || echo no )" "yes"
check partial-bad-reported  "$(printf '%s' "$out2" | grep -c 'PARTIAL 10\.3\.0\.1')" "1"
check partial-good-reported "$(printf '%s' "$out2" | grep -c '^unblocked 10\.3\.0\.2$')" "1"
check partial-summary "$(printf '%s' "$out2" | grep -c 'rollback-ladder: 2 selected, 1 unblocked, 1 partial')" "1"
# The failing IP's ledger perm flag is still cleared (documented tradeoff: a
# partial undo reports which IP needs a retry, rather than leaving it silently
# stuck as perm forever).
permcount2="$(sqlite3 "$d2/swatter.db" "SELECT COUNT(*) FROM offenders WHERE perm=1;")"
check partial-ledger-cleared "$permcount2" "0"
rm -rf "$d2" "$c2" "$fakebin2"

# --- 2c (dual-plane spy). A failed DIRECT-plane unblock must NOT skip the
# Cloudflare unblock for the SAME ip (no &&-short-circuit): a ladder perm can
# be dual-planed (CSF + Cloudflare — see _swatter_maybe_dual_plane in
# lib/score.sh). Seed a real cf-rules.tsv ref for BOTH ips, make csf fail for
# one of them, and prove swatter_cf_unblock still runs for it: a fake `curl`
# that always reports {"success":true} lets the real _cf_delete_ref path
# execute end to end, so the spy is "the ref for the csf-failing ip is
# actually gone afterward" — impossible if `swatter_cf_unblock` were skipped.
d2b="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb2b.XXXXXX")"; c2b="$(mktemp "${TMPDIR:-/tmp}/swatter-rb2b-conf.XXXXXX")"
mkconf "$d2b" "$c2b"; seed_cli_db "$d2b" "$CNOW"
{
    echo "CF_CREDS_FILE=\"$d2b/cf-creds\""
} >> "$c2b"
printf 'acctA\ttokA\n' > "$d2b/cf-creds"
refs2b="$d2b/cf-rules.tsv"
printf '10.3.0.1\tzone\tzoneA\tRULE1\t9999999999\n10.3.0.2\tzone\tzoneA\tRULE2\t9999999999\n' > "$refs2b"
fakebin2b="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb-fake2b.XXXXXX")"
cat > "$fakebin2b/csf" <<'EOF'
#!/bin/sh
for a in "$@"; do
    [ "$a" = "10.3.0.1" ] && exit 1
done
exit 0
EOF
chmod +x "$fakebin2b/csf"
curllog2b="$d2b/curl-calls.log"
cat > "$fakebin2b/curl" <<'EOF'
#!/bin/sh
echo "CURL-CALLED $*" >> "${CURL_CALL_LOG:-/dev/null}"
echo '{"success":true,"result":{}}'
exit 0
EOF
chmod +x "$fakebin2b/curl"
out2b="$(PATH="$fakebin2b:$PATH" CURL_CALL_LOG="$curllog2b" SWATTER_CONF="$c2b" \
    bash "${ROOT}/bin/swatter" rollback-ladder --since $(( CNOW - 5*86400 )) 2>&1)"
rc2b=$?
check dualplane-still-partial "$( [[ $rc2b -ne 0 ]] && echo yes || echo no )" "yes"
check dualplane-curl-was-called "$( [[ -s "$curllog2b" ]] && echo yes || echo no )" "yes"
# The proof: even though 10.3.0.1's DIRECT unblock failed, its Cloudflare ref
# is gone too (curl reported success) — swatter_cf_unblock genuinely ran for
# it instead of being skipped by a `direct && cf` short-circuit.
check dualplane-bad-ip-cf-ref-cleared \
    "$(grep -c '^10\.3\.0\.1' "$refs2b" 2>/dev/null || true)" "0"
check dualplane-good-ip-cf-ref-cleared \
    "$(grep -c '^10\.3\.0\.2' "$refs2b" 2>/dev/null || true)" "0"
check dualplane-partial-names-direct \
    "$(printf '%s' "$out2b" | grep -c 'PARTIAL 10\.3\.0\.1: direct')" "1"
rm -rf "$d2b" "$c2b" "$fakebin2b"

# --- 2c. Swarm notice appears ONLY when SWARM_ENABLE=true.
d3="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb3.XXXXXX")"; c3="$(mktemp "${TMPDIR:-/tmp}/swatter-rb3-conf.XXXXXX")"
mkconf "$d3" "$c3"; seed_cli_db "$d3" "$CNOW"
fakebin3="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb-fake3.XXXXXX")"
printf '#!/bin/sh\nexit 0\n' > "$fakebin3/csf"; chmod +x "$fakebin3/csf"

out_off="$(PATH="$fakebin3:$PATH" SWATTER_CONF="$c3" \
    bash "${ROOT}/bin/swatter" rollback-ladder --since $(( CNOW - 5*86400 )) 2>&1)"
check swarm-notice-absent "$(printf '%s' "$out_off" | grep -c 'NOT retracted')" "0"

# Re-seed (previous run already unblocked/cleared these IPs).
seed_cli_db "$d3" "$CNOW"
out_on="$(PATH="$fakebin3:$PATH" SWARM_ENABLE=true SWATTER_CONF="$c3" \
    bash "${ROOT}/bin/swatter" rollback-ladder --since $(( CNOW - 5*86400 )) 2>&1)"
check swarm-notice-present "$(printf '%s' "$out_on" | grep -c 'NOT retracted')" "1"
rm -rf "$d3" "$c3" "$fakebin3"

# --- 2d. `--since` as the last bare arg must not hang. With `set -uo pipefail`
# (no -e), `shift 2` on the last positional silently fails and leaves
# $1 == "--since", spinning the arg-parse loop forever unless the arg count is
# validated before shift (Task 5's `--window` bug, verified live). Guarded with
# `timeout` so a reintroduced hang fails the suite fast instead of wedging it.
d4="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb4.XXXXXX")"; c4="$(mktemp "${TMPDIR:-/tmp}/swatter-rb4-conf.XXXXXX")"
mkconf "$d4" "$c4"
SWATTER_CONF="$c4" timeout 5 bash "${ROOT}/bin/swatter" rollback-ladder --since \
    > /dev/null 2>"$d4/err"; rc4=$?
check since-no-value-no-hang "$( [[ $rc4 -ne 0 && $rc4 -ne 124 ]] && echo ok || echo "HUNG-OR-WRONG(rc=$rc4)" )" "ok"
rm -rf "$d4" "$c4"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
