#!/usr/bin/env bash
# test/shared_egress_cap_test.sh — the perm veto inside _swatter_apply_plane.
# Asserts the three sinks that must agree (backend, ledger, AUDIT) plus the
# publication and tripwire side effects.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-secap.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce; SWATTER_HAVE_DNS=0
swatter_store_init
db="$STATE_DIR/swatter.db"

SHARED_EGRESS_ENABLE="true"
SHARED_EGRESS_CIDR_FILE="$STATE_DIR/se.cidr"
SHARED_EGRESS_ASNS_FILE="$STATE_DIR/se-asns.txt"
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"
: > "$SHARED_EGRESS_ASNS_FILE"
CLOUDFLARE_IPS_FILE="$STATE_DIR/cf.cidr"; : > "$CLOUDFLARE_IPS_FILE"
OPERATOR_ALLOW_FILE="$STATE_DIR/allow.cidr"; : > "$OPERATOR_ALLOW_FILE"
MONITORING_RANGES_FILE="$STATE_DIR/mon.cidr"; : > "$MONITORING_RANGES_FILE"
OPERATOR_IPS=""

# Record what each sink saw.
BACKEND="$STATE_DIR/backend.log"; AUDIT="$STATE_DIR/audit.log"; ABUSE="$STATE_DIR/abuse.log"
: > "$BACKEND"; : > "$AUDIT"; : > "$ABUSE"
swatter_block_direct_perm() { echo "perm $1" >> "$BACKEND"; return 0; }
swatter_block_direct_temp() { echo "temp $1 ttl=$2" >> "$BACKEND"; return 0; }
swatter_cf_manages_plane()  { return 1; }   # DIRECT plane only in this test
swatter_abuseipdb_report()  { echo "$1" >> "$ABUSE"; }
_swatter_audit() { echo "$3" >> "$AUDIT"; }   # $3 = audit_action
swatter_is_good_crawler() { return 1; }
_swatter_is_good_crawler() { return 1; }
_swatter_self_ips() { :; }

apply() {  # <ip> [audit_action]
  : > "$BACKEND"; : > "$AUDIT"; : > "$ABUSE"
  _SW_TOTAL_BLOCKS=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_PERMS=0; SWATTER_RUN_SHARED_CAPS=0
  _swatter_apply_plane "$1" DIRECT perm 0 "score=91 rule=critical_badpath" "" 1 91 '{}' 100 ${2:+"$2"}
}
led() { sqlite3 "$db" "SELECT action FROM actions WHERE ip='$1' ORDER BY id DESC LIMIT 1;"; }
permflag() { sqlite3 "$db" "SELECT COALESCE((SELECT perm FROM offenders WHERE ip='$1'),'norow');"; }

# --- shared-egress perm is capped: backend, ledger AND audit must all say temp ---
apply 104.28.5.5
check cap-backend "$(cut -d' ' -f1 < "$BACKEND")"       "temp"
check cap-ttl     "$(grep -o 'ttl=[0-9]*' "$BACKEND")"  "ttl=259200"
check cap-ledger  "$(led 104.28.5.5)"                   "temp"
check cap-audit   "$(cat "$AUDIT")"                     "temp"
check cap-permflag "$(permflag 104.28.5.5)"             "0"
check cap-counter "${SWATTER_RUN_SHARED_CAPS}"          "1"
check cap-tripwire "${SWATTER_RUN_PERMS}"               "0"
check cap-no-abuse "$(wc -l < "$ABUSE" | tr -d ' ')"    "0"
check cap-not-published "$(swatter_store_perm_ips_since 0 | wc -l | tr -d ' ')" "0"

# --- the AbuseIPDB guard must not depend on the perm/temp distinction ---
ABUSEIPDB_REPORT_MIN_ACTION="temp"
apply 104.28.6.6
check cap-no-abuse-mintemp "$(wc -l < "$ABUSE" | tr -d ' ')" "0"
ABUSEIPDB_REPORT_MIN_ACTION="perm"

# --- a secondary leg keeps its own label but is still capped ---
apply 104.28.7.7 plane-upgrade
check leg-backend "$(cut -d' ' -f1 < "$BACKEND")" "temp"
check leg-audit   "$(cat "$AUDIT")"               "plane-upgrade"
check leg-ledger  "$(led 104.28.7.7)"             "temp"

# --- a normal IP is untouched (regression guard) ---
apply 192.0.2.50
check normal-backend "$(cut -d' ' -f1 < "$BACKEND")" "perm"
check normal-ledger  "$(led 192.0.2.50)"             "perm"
check normal-audit   "$(cat "$AUDIT")"               "perm"
check normal-permflag "$(permflag 192.0.2.50)"       "1"
check normal-tripwire "${SWATTER_RUN_PERMS}"         "1"
check normal-abuse   "$(wc -l < "$ABUSE" | tr -d ' ')" "1"

# --- disable switch restores today's behavior ---
SHARED_EGRESS_ENABLE="false"; _SW_SHARED_CIDR_OK=""
apply 104.28.8.8
check disabled-backend "$(cut -d' ' -f1 < "$BACKEND")" "perm"
SHARED_EGRESS_ENABLE="true"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
