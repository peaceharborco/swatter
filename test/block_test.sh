#!/usr/bin/env bash
# test/block_test.sh — direct-plane backend router dispatch.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block.sh"
PASS=0; FAIL=0
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

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
