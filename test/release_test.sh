#!/usr/bin/env bash
# test/release_test.sh — version math for install/release.sh (_next_version).
# The orchestration (git/gh/glab) is side-effecting and verified by --dry-run;
# this covers the one pure function whose silent miscompute would mis-tag a
# release. Run: bash test/release_test.sh

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"

# Source without executing main().
source "${ROOT}/install/release.sh"

PASS=0; FAIL=0
assert_eq() { [[ "$2" == "$3" ]] && { printf 'PASS  %s\n' "$1"; PASS=$((PASS+1)); } \
                                 || { printf 'FAIL  %s — got "%s" want "%s"\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); }; }
assert_fail() { if "$@" >/dev/null 2>&1; then printf 'FAIL  rejects: %s\n' "$*"; FAIL=$((FAIL+1)); \
                else printf 'PASS  rejects bad input\n'; PASS=$((PASS+1)); fi; }

assert_eq "patch bumps Z"          "$(_next_version 1.2.2 patch)"  "1.2.3"
assert_eq "minor bumps Y, resets Z" "$(_next_version 1.2.2 minor)" "1.3.0"
assert_eq "major bumps X, resets Y.Z" "$(_next_version 1.2.2 major)" "2.0.0"
assert_eq "explicit version passthrough" "$(_next_version 1.2.2 1.5.9)" "1.5.9"
assert_eq "patch from .9 carries"  "$(_next_version 1.2.9 patch)"  "1.2.10"
assert_eq "from 0.0.0"             "$(_next_version 0.0.0 minor)"  "0.1.0"

assert_fail _next_version 1.2.2 sideways      # unknown bump word
assert_fail _next_version not-a-version patch # malformed current

echo
echo "release: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
