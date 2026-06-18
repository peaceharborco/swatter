#!/usr/bin/env bash
# test/block_ipset_test.sh — ipset backend: add/del/timeout, v4/v6, dry-run, cap, save.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block_ipset.sh"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-ips.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
CALLS="$TMP/calls"; : > "$CALLS"
SWATTER_HAVE_IPSET=1; SWATTER_MODE="enforce"; MAX_CSF_DENIES_PER_RUN=10
IPSET_SAVE_FILE="$TMP/ipset.save"
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
has()   { local n="$1" pat="$2"; if grep -qF "$pat" "$CALLS"; then PASS=$((PASS+1)); else echo "FAIL ${n}: '${pat}' not in calls"; FAIL=$((FAIL+1)); fi; }

# Mock ipset/iptables/ip6tables. `ipset save` writes the save file via redirection in the impl.
ipset()    { if [[ "$1" == "save" ]]; then echo "SAVED"; else echo "ipset $*" >> "$CALLS"; fi; return 0; }
iptables() { echo "iptables $*" >> "$CALLS"; return 1; }   # return 1 so -C "misses" and -I runs
ip6tables(){ echo "ip6tables $*" >> "$CALLS"; return 1; }

# setup: creates both sets + inserts both DROP rules (idempotent via -exist / -C||-I).
swatter_ipset_setup
has setup-v4-create "ipset create swatter4 hash:ip family inet timeout 0 -exist"
has setup-v6-create "ipset create swatter6 hash:ip family inet6 timeout 0 -exist"
has setup-v4-rule   "iptables -I INPUT -m set --match-set swatter4 src -j DROP"
has setup-v6-rule   "ip6tables -I INPUT -m set --match-set swatter6 src -j DROP"

: > "$CALLS"
# temp v4 -> add to swatter4 with timeout ttl.
swatter_ipset_temp 1.2.3.4 60 r; has temp-v4 "ipset add swatter4 1.2.3.4 timeout 60 -exist"
# temp v6 -> swatter6.
swatter_ipset_temp 2001:db8::1 60 r; has temp-v6 "ipset add swatter6 2001:db8::1 timeout 60 -exist"
# perm -> timeout 0, and writes the save file.
swatter_ipset_perm 5.6.7.8 r; has perm "ipset add swatter4 5.6.7.8 timeout 0 -exist"
[[ -f "$IPSET_SAVE_FILE" ]] && PASS=$((PASS+1)) || { echo "FAIL perm-save"; FAIL=$((FAIL+1)); }
# unblock -> del from both sets.
: > "$CALLS"; swatter_ipset_unblock 5.6.7.8
has unb-v4 "ipset del swatter4 5.6.7.8 -exist"
has unb-v6 "ipset del swatter6 5.6.7.8 -exist"

# dry-run: no ipset add.
: > "$CALLS"; SWATTER_MODE="report"
swatter_ipset_perm 7.7.7.7 r
grep -q "ipset add" "$CALLS" && { echo "FAIL dryrun"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
SWATTER_MODE="enforce"

# cap: once SWATTER_IPSET_DENIES_THIS_RUN hits MAX, returns 2.
SWATTER_IPSET_DENIES_THIS_RUN=10
swatter_ipset_perm 8.8.8.8 r; check cap-rc "$?" "2"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
