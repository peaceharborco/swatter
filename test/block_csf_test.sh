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

# missing csf binary -> genuine failure (1), distinct from the cap, WITH a cause.
SWATTER_CSF_DENIES_THIS_RUN=0; SWATTER_HAVE_CSF=0; SWATTER_LAST_BACKEND_ERR=""
swatter_csf_perm 1.2.3.4 r; check nocsf-rc "$?" "1"
check nocsf-cause "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'csf binary not found')" "1"

# csf COMMAND failure -> cause captured from stderr (diagnosability).
SWATTER_HAVE_CSF=1; SWATTER_CSF_DENIES_THIS_RUN=0; SWATTER_LAST_BACKEND_ERR=""
csf() { echo "csf: could not add to deny list" >&2; return 1; }
swatter_csf_temp 1.2.3.4 3600 r; check csffail-rc "$?" "1"
check csffail-cause  "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'csf -td failed')" "1"
check csffail-stderr "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'could not add to deny list')" "1"
csf() { echo "csf $*" >> "$CALLS"; return 0; }   # restore

# UNBLOCK failure -> rc 1 + cause captured; a failed removal must never report
# success while the deny is still live (the unblock twin of block diagnosability).
SWATTER_LAST_BACKEND_ERR=""
csf() { echo "csf: iptables lock timeout" >&2; return 1; }
swatter_csf_unblock 1.2.3.4 2>/dev/null; check unbfail-rc "$?" "1"
check unbfail-cause  "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'csf unblock failed')" "1"
check unbfail-stderr "$(printf '%s' "${SWATTER_LAST_BACKEND_ERR:-}" | grep -c 'iptables lock timeout')" "1"
# UNBLOCK success unchanged -> rc 0.
csf() { echo "csf $*" >> "$CALLS"; return 0; }   # restore
swatter_csf_unblock 1.2.3.4; check unbok-rc "$?" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
