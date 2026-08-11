#!/usr/bin/env bash
# test/testconfig_test.sh — readiness advisories surface in test-config output.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-tc-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-tc.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
STORE="flatfile"
SWATTER_NO_LOCK=1
INTEL_PROVIDERS="greynoise"
GREYNOISE_KEY=""
ASN_SIGNAL_ENABLE="true"
HOSTING_ASNS_FILE="$state/does-not-exist.txt"
EOF

out="$(bash "${ROOT}/bin/swatter" test-config 2>&1)"
case "$out" in *greynoise*) PASS=$((PASS+1));; *) echo "FAIL mentions-greynoise"; FAIL=$((FAIL+1));; esac
case "$out" in *[Kk]ey*) PASS=$((PASS+1));; *) echo "FAIL warns-empty-key"; FAIL=$((FAIL+1));; esac
case "$out" in *hosting*|*ASN*|*asn*) PASS=$((PASS+1));; *) echo "FAIL warns-asn-file"; FAIL=$((FAIL+1));; esac

# Ladder line reports the EFFECTIVE state (post-expansion), not the raw conf
# text — every deploy gate verifies against this exact line. Default conf
# above sets nothing for REPEAT_ENABLE, so lib/common.sh's own default
# (true) should apply and the ladder should read ARMED.
ladder_default="$(printf '%s\n' "$out" | grep 'ladder:')"
case "$ladder_default" in *"ARMED (REPEAT_ENABLE=true)"*) PASS=$((PASS+1));; *) echo "FAIL ladder-default-armed: got '${ladder_default}'"; FAIL=$((FAIL+1));; esac

# REPEAT_ENABLE=false disarms the ladder. lib/common.sh does an unconditional
# `: "${REPEAT_ENABLE:=true}"` default assignment (not a clobbering assign),
# so a plain env export is honored here — unlike STATE_DIR, which is why the
# rest of this file threads state through SWATTER_CONF instead.
out_disarmed="$(REPEAT_ENABLE=false bash "${ROOT}/bin/swatter" test-config 2>&1)"
ladder_disarmed="$(printf '%s\n' "$out_disarmed" | grep 'ladder:')"
case "$ladder_disarmed" in *"DISARMED (REPEAT_ENABLE=false)"*) PASS=$((PASS+1));; *) echo "FAIL ladder-disarmed: got '${ladder_disarmed}'"; FAIL=$((FAIL+1));; esac

# --- shared-egress readiness --------------------------------------------------
# The policy ships ENABLED but both its lists live under /etc/swatter, which a
# surgical file-by-file deploy never creates — so it can be on and completely
# inert, with no log line anywhere (the CIDR validator warns only about a
# REJECTED file, never a missing one). test-config is where the RUNBOOK tells
# the operator to check after editing, so it has to report the DATA.
se_conf="$(mktemp "${TMPDIR:-/tmp}/swatter-tc-se.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF" "$se_conf"' EXIT
se_out() {  # <enable> <cidr-contents-or-MISSING>
  local enable="$1" cidr="$2"
  if [[ "$cidr" == MISSING ]]; then rm -f "$state/se.cidr"; else printf '%s\n' "$cidr" > "$state/se.cidr"; fi
  printf '# comments only, no entries\n' > "$state/se-asns.txt"
  cat > "$se_conf" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
STORE="flatfile"
SWATTER_NO_LOCK=1
SHARED_EGRESS_ENABLE="${enable}"
SHARED_EGRESS_CIDR_FILE="$state/se.cidr"
SHARED_EGRESS_ASNS_FILE="$state/se-asns.txt"
EOF
  SWATTER_CONF="$se_conf" bash "${ROOT}/bin/swatter" test-config 2>&1
}

se_ok="$(se_out true '104.28.0.0/16 # WARP')"
case "$se_ok" in *"shared-egress:"*ENABLED*) PASS=$((PASS+1));; *) echo "FAIL se-reports-enabled"; FAIL=$((FAIL+1));; esac
case "$se_ok" in *"cidr: $state/se.cidr (1 range(s))"*) PASS=$((PASS+1));; *) echo "FAIL se-reports-cidr-count: $(printf '%s\n' "$se_ok" | grep -i 'cidr:')"; FAIL=$((FAIL+1));; esac
case "$se_ok" in *"asns:"*"0 entries"*) PASS=$((PASS+1));; *) echo "FAIL se-reports-asn-count"; FAIL=$((FAIL+1));; esac
case "$se_ok" in *"caps NOTHING"*) echo "FAIL se-false-inert-warning"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac

# Missing CIDR file + entry-free ASN list = the policy is on and caps nothing.
se_missing="$(se_out true MISSING)"
case "$se_missing" in *"cidr:"*MISSING*INERT*) PASS=$((PASS+1));; *) echo "FAIL se-reports-missing: $(printf '%s\n' "$se_missing" | grep -i 'cidr:')"; FAIL=$((FAIL+1));; esac
case "$se_missing" in *"caps NOTHING"*) PASS=$((PASS+1));; *) echo "FAIL se-warns-both-arms-inert"; FAIL=$((FAIL+1));; esac

# A file that exists but is rejected as over-broad is a THIRD state, and must
# not read like a healthy one.
se_broad="$(se_out true '104.0.0.0/8')"
case "$se_broad" in *"cidr:"*REJECTED*) PASS=$((PASS+1));; *) echo "FAIL se-reports-rejected: $(printf '%s\n' "$se_broad" | grep -i 'cidr:')"; FAIL=$((FAIL+1));; esac

se_off="$(se_out false '104.28.0.0/16')"
case "$se_off" in *"shared-egress:"*"off (SHARED_EGRESS_ENABLE=false)"*) PASS=$((PASS+1));; *) echo "FAIL se-reports-disabled"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
