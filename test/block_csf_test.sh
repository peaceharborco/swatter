#!/usr/bin/env bash
# test/block_csf_test.sh — CSF backend return-code contract: dry-run, enforce
# success, per-run cap (SWATTER_RC_CAP=2), and missing-csf failure (1). Mirrors
# block_ipset_test.sh's cap assertion so the protocol code score.sh depends on is
# pinned for BOTH direct backends, not just ipset.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/block_csf.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

MAX_CSF_DENIES_PER_RUN=10
CALLS="$(mktemp "${TMPDIR:-/tmp}/swatter-csfcalls.XXXXXX")"; trap 'rm -f "$CALLS"' EXIT
csf() { echo "csf $*" >> "$CALLS"; return 0; }   # stub the csf binary
SWATTER_HAVE_CSF=1

# dry-run (report mode): never shells out to csf, returns 0.
SWATTER_MODE="report"; SWATTER_CSF_DENIES_THIS_RUN=0; : > "$CALLS"
swatter_csf_perm 1.2.3.4 r; check dryrun-rc "$?" "0"
[[ -s "$CALLS" ]] && check dryrun-nocall "called" "uncalled" || check dryrun-nocall "uncalled" "uncalled"

# enforce success: csf -d invoked, returns 0.
SWATTER_MODE="enforce"; SWATTER_CSF_DENIES_THIS_RUN=0; : > "$CALLS"
swatter_csf_perm 1.2.3.4 r; check enforce-perm-rc "$?" "0"
grep -q "csf -d 1.2.3.4" "$CALLS" && check enforce-perm-call "yes" "yes" || check enforce-perm-call "no" "yes"
swatter_csf_temp 1.2.3.5 3600 r; check enforce-temp-rc "$?" "0"

# cap: at MAX the backend returns SWATTER_RC_CAP and never calls csf.
SWATTER_CSF_DENIES_THIS_RUN="$MAX_CSF_DENIES_PER_RUN"; : > "$CALLS"
swatter_csf_perm 9.9.9.9 r; check cap-perm-rc "$?" "$SWATTER_RC_CAP"
swatter_csf_temp 9.9.9.8 3600 r; check cap-temp-rc "$?" "$SWATTER_RC_CAP"
[[ -s "$CALLS" ]] && check cap-nocall "called" "uncalled" || check cap-nocall "uncalled" "uncalled"

# missing csf binary -> genuine failure (1), distinct from the cap.
SWATTER_CSF_DENIES_THIS_RUN=0; SWATTER_HAVE_CSF=0
swatter_csf_perm 1.2.3.4 r; check nocsf-rc "$?" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
