#!/usr/bin/env bash
# test/pending_disarm_test.sh — a disarmed ladder must not let the durable-retry
# drain replay a queued PERMANENT ban.
#
# The drain runs FIRST in every scan and replays a stored intent with no ladder
# re-check, so a ladder perm whose backend call failed can land up to 24h after
# an operator believes they disarmed. The obvious filter — skip rows whose
# reason contains `recidivism=` — is WRONG: that stamp is written only by this
# release, so every row queued by the deployed version lacks it and would sail
# through the gate meant to stop it. Hence an allowlist of provably non-ladder
# origins, exercised here against the real function.
#
# The allowlist keys on the `ev` evidence marker ("honeypot":1), not free text
# in `reason` — a reason substring match on "honeypot" is also wrong: the
# default INTEL_PROVIDERS list ships a provider literally named
# "projecthoneypot" (lib/common.sh), so a plain ladder perm scored via that
# feed would false-positive the allowlist. See disarm-holds-projecthoneypot-
# labeled-ladder below.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"
# common.sh sets STATE_DIR="/var/lib/swatter" unconditionally at source time
# (see lib/common.sh:225), so the temp dir must be assigned AFTER sourcing —
# same ordering test/pending_retry_test.sh uses.
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-disarm.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
export STATE_DIR
STORE=sqlite; SWATTER_MODE=enforce
swatter_store_init
db="$STATE_DIR/swatter.db"
APPLIED="$STATE_DIR/applied.log"

# Stub only the two side-effecting calls the drain makes. Everything else — row
# selection, the age/attempt checks, the coverage check, the new gate — is real.
_swatter_apply_plane() { printf '%s\n' "$1" >> "$APPLIED"; }
_swatter_audit() { :; }

now="$(swatter_now)"
seed() {   # <ip> <action> <reason> [ev] [top_vhost]
  local ev="${4:-"{}"}" vhost="${5:-x.example.com}"
  : > "$APPLIED"
  sqlite3 "$db" "DELETE FROM pending_blocks;"
  sqlite3 "$db" "INSERT INTO pending_blocks(ip,plane,action,ttl,reason,top_vhost,ev,first_failed,last_attempt,attempts)
                 VALUES('$1','DIRECT','$2',0,'$3','$vhost','$ev',${now},${now},1);"
}
applied() { wc -l < "$APPLIED" 2>/dev/null | tr -d ' '; }

# --- armed: everything replays exactly as before ----------------------------
REPEAT_ENABLE=true
seed 10.0.0.1 perm 'score=91 recidivism=3/7d'; _swatter_retry_pending 1
check armed-replays-ladder "$(applied)" "1"
seed 10.0.0.2 perm 'score=91 intel=spamhaus'; _swatter_retry_pending 1
check armed-replays-legacy "$(applied)" "1"

# --- disarmed: perms are held ------------------------------------------------
REPEAT_ENABLE=false
# The row shape the DEPLOYED version queues — no recidivism= token at all.
# A recidivism=-based filter would wrongly replay this one.
seed 10.0.0.3 perm 'score=91 intel=spamhaus'; _swatter_retry_pending 1
check disarm-holds-legacy "$(applied)" "0"
seed 10.0.0.4 perm 'score=91 recidivism=3/7d'; _swatter_retry_pending 1
check disarm-holds-stamped "$(applied)" "0"

# Held, not destroyed — pausing must not lose the intent.
check held-row-remains "$(sqlite3 "$db" "SELECT COUNT(*) FROM pending_blocks WHERE ip='10.0.0.4';")" "1"
check held-attempts-same "$(sqlite3 "$db" "SELECT attempts FROM pending_blocks WHERE ip='10.0.0.4';")" "1"

# A default intel provider is literally named "projecthoneypot" (see
# INTEL_PROVIDERS in lib/common.sh), so a plain ladder perm scored via that
# feed renders its reason as "...intel=projecthoneypot:...". A `reason`
# substring match on "honeypot" would wrongly treat this as the allowlisted
# trap origin and replay it. The queued `ev` has no honeypot marker (this is
# not a real trap hit) — it must stay held.
seed 10.0.0.7 perm 'score=91 intel=projecthoneypot:httpbl:t1:s50:d3(80) recidivism=3/7d'; _swatter_retry_pending 1
check disarm-holds-projecthoneypot-labeled-ladder "$(applied)" "0"

# Honeypot is a separate feature and stays live while the ladder is disarmed.
# The allowlist gate keys on the evidence marker (`ev` carries "honeypot":1
# only for a genuine trap hit — see lib/score.sh:504), not free text in reason.
seed 10.0.0.5 perm 'honeypot /wp-config.bak' '{"honeypot":1}'; _swatter_retry_pending 1
check disarm-replays-honeypot "$(applied)" "1"

# The dual-plane leg of a real trap hit carries the same `ev` through
# (swatter_store_pending_set stores it verbatim) and must replay too.
seed 10.0.0.8 perm 'dual-plane honeypot score=95' '{"honeypot":1}'; _swatter_retry_pending 1
check disarm-replays-honeypot-dualplane "$(applied)" "1"

# A DIRECT-plane row with NO target vhost (raw-IP/no-Host hit — top_vhost is
# legitimately empty; block_direct_perm/_temp never use it). The drain's row
# format is delimited with char(31)/IFS=$'\037' specifically so this empty
# middle field does NOT shift `ev` out of position (a tab delimiter would
# collapse the adjacent tabs and corrupt ev to '{}', wrongly holding a real
# trap perm). This is the case that failed before the char(31) fix.
seed 10.0.0.9 perm 'honeypot (no vhost)' '{"honeypot":1}' ''; _swatter_retry_pending 1
check disarm-replays-honeypot-no-vhost "$(applied)" "1"

# Temps are untouched by the ladder switch.
seed 10.0.0.6 temp 'score=75'; _swatter_retry_pending 1
check disarm-replays-temp "$(applied)" "1"

# The age/attempt reap must keep running while disarmed — it is orthogonal to
# the ladder switch, not suspended by the hold. Otherwise the queue grows
# unbounded during a long pause and dumps every stale row at once (dropped,
# not applied) the moment the drain next runs after re-arm. Seed a row already
# past PENDING_RETRY_MAX_AGE_HOURS (default 24h) with a non-honeypot perm
# reason (would otherwise be HELD, not reaped, if the ordering regressed):
# still disarmed, it must still be reaped (retry-exhausted, row cleared), not
# left held forever.
: > "$APPLIED"
sqlite3 "$db" "DELETE FROM pending_blocks;"
old_ff=$(( now - 90000 ))   # 25h ago > the 24h default max age
sqlite3 "$db" "INSERT INTO pending_blocks(ip,plane,action,ttl,reason,top_vhost,ev,first_failed,last_attempt,attempts)
               VALUES('10.0.0.11','DIRECT','perm',0,'score=91 recidivism=3/7d','x.example.com','{}',${old_ff},${old_ff},1);"
_swatter_retry_pending 1
check disarm-still-reaps-aged-perm "$(applied)" "0"
check disarm-reap-clears-aged-row \
  "$(sqlite3 "$db" "SELECT COUNT(*) FROM pending_blocks WHERE ip='10.0.0.11';")" "0"

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
