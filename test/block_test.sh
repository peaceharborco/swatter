#!/usr/bin/env bash
# test/block_test.sh — direct-plane backend router dispatch.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block.sh"
PASS=0; FAIL=0
# _swatter_is_unsafe_block_target is defined in common.sh; pin its contract directly.
_ut() { _swatter_is_unsafe_block_target "$1" && echo unsafe || echo ok; }
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Stub both backends to record which was called.
RAN=""
swatter_csf_temp()      { RAN="csf_temp $*"; return 0; }
swatter_csf_perm()      { RAN="csf_perm $*"; return 0; }
swatter_csf_unblock()   { RAN="csf_unblock $*"; return 0; }
swatter_ipset_temp()    { RAN="ipset_temp $*"; return 0; }
swatter_ipset_perm()    { RAN="ipset_perm $*"; return 0; }
swatter_ipset_unblock() { RAN="ipset_unblock $*"; return 0; }

DIRECT_BACKEND="csf"
swatter_block_direct_temp 1.2.3.4 60 r; check csf-temp "$RAN" "csf_temp 1.2.3.4 60 r"
swatter_block_direct_perm 1.2.3.4 r;    check csf-perm "$RAN" "csf_perm 1.2.3.4 r"
swatter_block_direct_unblock 1.2.3.4;   check csf-unb  "$RAN" "csf_unblock 1.2.3.4"

DIRECT_BACKEND="ipset"
swatter_block_direct_temp 5.6.7.8 60 r; check ips-temp "$RAN" "ipset_temp 5.6.7.8 60 r"
swatter_block_direct_perm 5.6.7.8 r;    check ips-perm "$RAN" "ipset_perm 5.6.7.8 r"
swatter_block_direct_unblock 5.6.7.8;   check ips-unb  "$RAN" "ipset_unblock 5.6.7.8"

# Unset backend defaults to csf.
unset DIRECT_BACKEND
swatter_block_direct_perm 9.9.9.9 r;    check default-csf "$RAN" "csf_perm 9.9.9.9 r"

# Return code passes through.
swatter_csf_perm() { return 2; }; DIRECT_BACKEND="csf"
swatter_block_direct_perm 1.1.1.1 r; check rc-passthrough "$?" "2"

# Defense-in-depth: the router itself refuses a malformed IP so no caller (scan,
# import-bans, or a future one) can hand garbage to csf/ipset. RAN must NOT change.
swatter_csf_perm() { RAN="csf_perm $*"; return 0; }   # restore recorder
RAN="sentinel"; DIRECT_BACKEND="csf"
swatter_block_direct_perm "999.999.999.999" r; check malformed-perm-rc "$?" "1"
check malformed-perm-nocall "$RAN" "sentinel"
RAN="sentinel"
swatter_block_direct_temp "::::" 60 r; check malformed-temp-rc "$?" "1"
check malformed-temp-nocall "$RAN" "sentinel"
# A valid IP still routes through.
RAN=""; swatter_block_direct_perm "203.0.113.4" r; check valid-perm-routes "$RAN" "csf_perm 203.0.113.4 r"

# Unsafe targets: /0 (whole-internet deny) and the unspecified addresses are
# syntactically valid but catastrophic as a block target — the router refuses
# them even though the general validator accepts them (an import-bans file with
# 0.0.0.0/0 must never firewall the entire internet).
for bad in "0.0.0.0/0" "::/0" "1.2.3.4/0" "0.0.0.0" "::"; do
    RAN="sentinel"; swatter_block_direct_perm "$bad" r
    check "unsafe-target-rc(${bad})" "$?" "1"
    check "unsafe-target-nocall(${bad})" "$RAN" "sentinel"
done
# A normal /24 range block is still allowed (import-bans legitimately blocks ranges).
RAN=""; swatter_block_direct_perm "198.51.100.0/24" r; check valid-cidr-routes "$RAN" "csf_perm 198.51.100.0/24 r"

# Direct contract of the unsafe-target predicate.
check ut-v4-any     "$(_ut 0.0.0.0/0)"       "unsafe"
check ut-v6-any     "$(_ut ::/0)"            "unsafe"
check ut-real-any   "$(_ut 1.2.3.4/0)"       "unsafe"
check ut-unspec-v4  "$(_ut 0.0.0.0)"         "unsafe"
check ut-unspec-v6  "$(_ut ::)"              "unsafe"
check ut-unspec-v6l "$(_ut 0:0:0:0:0:0:0:0)" "unsafe"
check ut-normal-ip  "$(_ut 203.0.113.4)"     "ok"
check ut-normal-cidr "$(_ut 198.51.100.0/24)" "ok"
check ut-normal-v6  "$(_ut 2001:db8::1)"     "ok"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
