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
SWATTER_HAVE_IPSET=1; SWATTER_HAVE_IP6TABLES=1; SWATTER_MODE="enforce"; MAX_CSF_DENIES_PER_RUN=10
IPSET_SAVE_FILE="$TMP/ipset.save"
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
has()   { local n="$1" pat="$2"; if grep -qF "$pat" "$CALLS"; then PASS=$((PASS+1)); else echo "FAIL ${n}: '${pat}' not in calls"; FAIL=$((FAIL+1)); fi; }

# Mock ipset/iptables/ip6tables. For `ipset save <set>` record the call AND emit a
# named create line to stdout (the impl redirects it into the save file).
ipset()    { if [[ "$1" == "save" ]]; then echo "ipset $*" >> "$CALLS"; echo "create $2 hash:ip"; else echo "ipset $*" >> "$CALLS"; fi; return 0; }
# -C "misses" (rc 1) so the -I insert runs; the insert itself succeeds (rc 0).
iptables() { echo "iptables $*" >> "$CALLS"; [[ "$1" == "-C" ]] && return 1; return 0; }
ip6tables(){ echo "ip6tables $*" >> "$CALLS"; [[ "$1" == "-C" ]] && return 1; return 0; }

# setup: creates both sets + inserts both DROP rules (idempotent via -exist / -C||-I).
swatter_ipset_setup; check setup-rc "$?" "0"
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
# save must name ONLY our two sets (not a bare `ipset save` of every set on the box).
has perm-save-v4 "ipset save swatter4"
has perm-save-v6 "ipset save swatter6"
grep -qF "ipset save" "$CALLS" && ! grep -qE 'ipset save$' "$CALLS" && PASS=$((PASS+1)) || { echo "FAIL save-not-bare"; FAIL=$((FAIL+1)); }
# unblock -> del from the family-matching set only (a cross-family del is a
# guaranteed parse error on real ipset, which would now read as a false failure).
: > "$CALLS"; swatter_ipset_unblock 5.6.7.8; check unb-v4-rc "$?" "0"
has unb-v4 "ipset del swatter4 5.6.7.8 -exist"
grep -qF "ipset del swatter6 5.6.7.8" "$CALLS" && { echo "FAIL unb-v4-not-v6"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
: > "$CALLS"; swatter_ipset_unblock 2001:db8::1; check unb-v6-rc "$?" "0"
has unb-v6 "ipset del swatter6 2001:db8::1 -exist"

# dry-run: no ipset add.
: > "$CALLS"; SWATTER_MODE="report"
swatter_ipset_perm 7.7.7.7 r
grep -q "ipset add" "$CALLS" && { echo "FAIL dryrun"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
SWATTER_MODE="enforce"

# cap: once SWATTER_IPSET_DENIES_THIS_RUN hits MAX, returns 2.
SWATTER_IPSET_DENIES_THIS_RUN=10
swatter_ipset_perm 8.8.8.8 r; check cap-rc "$?" "2"

# ipset COMMAND failure -> rc 1 + cause captured from stderr (mirrors the CSF
# twin's diagnosability contract; score.sh records it on the failed decision).
ipset() { echo "ipset v7: Kernel error received: No buffer space available" >&2; return 1; }
SWATTER_IPSET_DENIES_THIS_RUN=0; SWATTER_LAST_BACKEND_ERR=""
swatter_ipset_temp 1.2.3.9 60 r 2>/dev/null; check addfail-temp-rc "$?" "1"
check addfail-temp-cause  "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'ipset add failed')" "1"
check addfail-temp-stderr "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'No buffer space')" "1"
SWATTER_LAST_BACKEND_ERR=""
swatter_ipset_perm 1.2.3.9 r 2>/dev/null; check addfail-perm-rc "$?" "1"
check addfail-perm-cause "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'ipset add failed')" "1"
# UNBLOCK failure -> rc 1 + cause (a failed del must not report success).
SWATTER_LAST_BACKEND_ERR=""
swatter_ipset_unblock 5.6.7.8 2>/dev/null; check unbfail-rc "$?" "1"
check unbfail-cause  "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'ipset del failed')" "1"
check unbfail-stderr "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'No buffer space')" "1"
# restore the recording mock.
ipset() { if [[ "$1" == "save" ]]; then echo "ipset $*" >> "$CALLS"; echo "create $2 hash:ip"; else echo "ipset $*" >> "$CALLS"; fi; return 0; }

# [13] IPv6 block with no ip6tables DROP rule behind it must fail closed (an
# unenforced set member must NOT read as handled), not report success.
: > "$CALLS"; SWATTER_HAVE_IP6TABLES=0; SWATTER_IPSET_DENIES_THIS_RUN=0; SWATTER_LAST_BACKEND_ERR=""
swatter_ipset_temp 2001:db8::9 60 r 2>/dev/null; check v6-noenforce-temp-rc "$?" "1"
grep -q "ipset add" "$CALLS" && { echo "FAIL v6-noenforce-temp-noadd"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
check v6-noenforce-temp-cause "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'not enforced')" "1"
SWATTER_LAST_BACKEND_ERR=""
swatter_ipset_perm 2001:db8::9 r 2>/dev/null; check v6-noenforce-perm-rc "$?" "1"
grep -q "ipset add" "$CALLS" && { echo "FAIL v6-noenforce-perm-noadd"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
# v4 is unaffected when ip6tables is absent.
: > "$CALLS"; SWATTER_IPSET_DENIES_THIS_RUN=0
swatter_ipset_temp 1.2.3.5 60 r; check v4-ok-noip6-rc "$?" "0"
has v4-ok-noip6-add "ipset add swatter4 1.2.3.5 timeout 60 -exist"
SWATTER_HAVE_IP6TABLES=1

# [22] setup with SWATTER_HAVE_IP6TABLES=0: warn fires, NO ip6tables call at all.
: > "$CALLS"; SWATTER_HAVE_IP6TABLES=0
swatter_ipset_setup 2>"$TMP/setup-warn.err"; check setup-noip6-rc "$?" "0"
grep -qF "ip6tables" "$CALLS" && { echo "FAIL setup-noip6-called"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
grep -q "NOT be enforced" "$TMP/setup-warn.err" && PASS=$((PASS+1)) || { echo "FAIL setup-noip6-warn"; FAIL=$((FAIL+1)); }
SWATTER_HAVE_IP6TABLES=1

# [22] a failing iptables -I (DROP rule can't be inserted) surfaces non-zero — the
# set would be unenforced, so setup must fail closed, not silently return 0.
: > "$CALLS"
iptables() { echo "iptables $*" >> "$CALLS"; return 1; }   # both -C and -I fail
swatter_ipset_setup 2>/dev/null; check setup-iptables-fail-rc "$?" "1"
# restore realistic iptables mock.
iptables() { echo "iptables $*" >> "$CALLS"; [[ "$1" == "-C" ]] && return 1; return 0; }

# (m27) _ipset_save atomicity: if `ipset save` fails mid-write, the existing save
# file must be left UNTOUCHED (not truncated) and no .tmp left behind.
printf 'PRIOR-PERM-BANS\n' > "$IPSET_SAVE_FILE"
ipset() { if [[ "$1" == "save" ]]; then return 1; else return 0; fi; }   # save fails
SWATTER_IPSET_DENIES_THIS_RUN=0
swatter_ipset_perm 9.9.9.9 r 2>/dev/null
check save-fail-file-intact "$(cat "$IPSET_SAVE_FILE")" "PRIOR-PERM-BANS"
[[ -e "${IPSET_SAVE_FILE}.tmp" ]] && { echo "FAIL save-fail-no-tmp"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
# restore the recording mock.
ipset() { if [[ "$1" == "save" ]]; then echo "ipset $*" >> "$CALLS"; echo "create $2 hash:ip"; else echo "ipset $*" >> "$CALLS"; fi; return 0; }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
