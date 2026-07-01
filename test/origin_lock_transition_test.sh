#!/usr/bin/env bash
# test/origin_lock_transition_test.sh — regression guard for the log->drop mode
# transition ordering bug (2026-06-30 origin-lock incident, spec §5).
#
# Unlike origin_lock_test.sh (which records the call STREAM), this harness models
# the actual iptables INPUT chain as an ordered list so we can assert the
# EFFECTIVE top-to-bottom order after a *transition* apply, not just a fresh one.
#
# The bug: standalone apply uses `-C ... || -I INPUT ...` (insert-if-absent,
# prepend to pos 1). On a fresh chain the reverse-emit trick yields the right
# order. But on a log->drop transition the CF/ACME/LOG accepts already exist, so
# their `-C` matches and they are NOT re-inserted; only the brand-new DROP gets
# `-I`-prepended to position 1 — ABOVE the CF-ACCEPT — dropping ALL web traffic
# including Cloudflare. Total origin outage.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/origin_lock.sh"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-olt.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT

# --- environment / config under test ---------------------------------------
SWATTER_MODE="enforce"
ORIGIN_LOCK="log"
ORIGIN_LOCK_PORTS="80,443"
ORIGIN_LOCK_ALLOW_ACME="true"
ORIGIN_LOCK_SET="cf_origin"
STATE_DIR="$TMP/state"; LOG_DIR="$TMP/log"; mkdir -p "$STATE_DIR" "$LOG_DIR"
SWATTER_HAVE_IP6TABLES=0          # v4-only keeps the chain model simple
SWATTER_OL_HAVE_XT_STRING=1
SWATTER_OL_CSFPRE="$TMP/csfpre.none"
SWATTER_OL_UNIT="$TMP/unit.none"

CLOUDFLARE_IPS_FILE="$TMP/cloudflare.cidr"
cat > "$CLOUDFLARE_IPS_FILE" <<'EOF'
203.0.113.0/24
198.51.100.0/24
192.0.2.0/24
EOF
OPERATOR_ALLOW_FILE="$TMP/allow.cidr"
MONITORING_RANGES_FILE="$TMP/monitoring.cidr"
: > "$OPERATOR_ALLOW_FILE"; : > "$MONITORING_RANGES_FILE"

# --- iptables fake that models the INPUT chain as an ordered list -----------
# Modeled as a newline-delimited string (one rule per line) to stay robust on
# macOS bash 3.2 (no array word-splitting/empty/`set -u` pitfalls). The FIRST
# line is the TOP of the chain (first-matched). A "rule" is the token string
# after the `INPUT` keyword (position number stripped) so -C can match what
# -I/-A inserted. Rules never contain newlines, so line == rule identity.
CHAIN=""

iptables() {
    local op="$1"; shift
    case "$op" in
        -C)
            shift                                   # drop chain name (INPUT)
            local key="$*" line
            while IFS= read -r line; do
                [[ "$line" == "$key" ]] && return 0
            done <<< "$CHAIN"
            return 1
            ;;
        -I)
            shift                                   # drop INPUT
            local pos=1
            if [[ "${1:-}" =~ ^[0-9]+$ ]]; then pos="$1"; shift; fi
            local key="$*" out="" line i=1 inserted=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ "$i" -eq "$pos" ]]; then out+="${key}"$'\n'; inserted=1; fi
                out+="${line}"$'\n'; i=$(( i + 1 ))
            done <<< "$CHAIN"
            [[ "$inserted" -eq 0 ]] && out+="${key}"$'\n' # pos past end -> append
            CHAIN="$out"
            return 0
            ;;
        -A)
            shift                                   # drop INPUT
            CHAIN+="$*"$'\n'
            return 0
            ;;
        -D)
            shift                                   # drop INPUT
            local key="$*" out="" line removed=1
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ "$removed" -eq 1 && "$line" == "$key" ]]; then removed=0; continue; fi
                out+="${line}"$'\n'
            done <<< "$CHAIN"
            CHAIN="$out"
            [[ "$removed" -eq 0 ]] && return 0 || return 1
            ;;
        *) return 0 ;;
    esac
}
ip6tables() { return 0; }          # v6 disabled in this harness
ipset()     { return 0; }          # set ops are irrelevant to chain ORDER

# 0-based index of the first chain line containing a substring; empty if none.
chain_index() {
    local needle="$1" i=0 line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *"$needle"* ]] && { printf '%s' "$i"; return 0; }
        i=$(( i + 1 ))
    done <<< "$CHAIN"
    return 1
}

# ===========================================================================
# Regression: log -> drop transition must keep DROP BELOW CF-ACCEPT and LOG.
# ===========================================================================
CHAIN=""

# 1. apply LOG mode first (establishes CF-ACCEPT, ACME, LOG, preamble — no DROP)
ORIGIN_LOCK="log"
cmd_origin_lock apply --yes >/dev/null 2>&1

# 2. transition to DROP mode (the buggy path)
ORIGIN_LOCK="drop"
cmd_origin_lock apply --yes >/dev/null 2>&1

cf_idx="$(chain_index 'cf_origin4 src -j ACCEPT' || true)"
log_idx="$(chain_index 'ORIGIN-LOCK:' || true)"
drop_idx="$(chain_index '-j DROP' || true)"

echo "effective chain (top->bottom):"
i=0; while IFS= read -r r; do [[ -z "$r" ]] && continue; echo "  [$i] $r"; i=$((i+1)); done <<< "$CHAIN"

fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }
ok()   { PASS=$((PASS+1)); }

[[ -n "$cf_idx"   ]] && ok || fail "transition: CF-ACCEPT missing from chain"
[[ -n "$drop_idx" ]] && ok || fail "transition: DROP missing from chain"
[[ -n "$log_idx"  ]] && ok || fail "transition: LOG missing from chain"

# The invariant: CF-ACCEPT (and LOG) must sit ABOVE (lower index than) the DROP.
if [[ -n "$cf_idx" && -n "$drop_idx" && "$cf_idx" -lt "$drop_idx" ]]; then
    ok
else
    fail "transition: CF-ACCEPT must be above DROP (cf=$cf_idx drop=$drop_idx) — origin outage"
fi
if [[ -n "$log_idx" && -n "$drop_idx" && "$log_idx" -lt "$drop_idx" ]]; then
    ok
else
    fail "transition: LOG must be above DROP (log=$log_idx drop=$drop_idx)"
fi

# ===========================================================================
# Teardown clears LEGACY DUPLICATE preamble accepts. Older (pre-teardown-first)
# applies could stack multiple identical -s allow accepts. Teardown must delete
# ALL of them (looped -D) so the rebuild lands exactly one — a single-shot -D
# would leave the extras (the -C guard then skips re-adding, so they linger).
# ===========================================================================
chain_count() { local needle="$1" n=0 line; while IFS= read -r line; do [[ -z "$line" ]] && continue; [[ "$line" == *"$needle"* ]] && n=$((n+1)); done <<< "$CHAIN"; printf '%s' "$n"; }

CHAIN=""
printf '10.0.0.0/8\n' > "$OPERATOR_ALLOW_FILE"
# Pre-seed 3 legacy duplicate copies of the operator-allow accept.
seed='-s 10.0.0.0/8 -p tcp -m multiport --dports 80,443 -j ACCEPT'
CHAIN="${seed}"$'\n'"${seed}"$'\n'"${seed}"$'\n'
ORIGIN_LOCK="drop"
cmd_origin_lock apply --yes >/dev/null 2>&1
c="$(chain_count '-s 10.0.0.0/8')"
if [[ "$c" -eq 1 ]]; then ok; else fail "legacy-dup: '-s 10.0.0.0/8' appears ${c}× after apply (want 1 — teardown left duplicates)"; fi
: > "$OPERATOR_ALLOW_FILE"

echo "----------------------------------------"
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
