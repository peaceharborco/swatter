#!/usr/bin/env bash
# test/shipped_config_valid_test.sh — the config/ files we SHIP must survive
# their own validators.
#
# Why this exists: the shared-egress CIDR guard is all-or-nothing. One line the
# validator rejects fails the whole file, _swatter_shared_egress_cidr_usable
# logs "CIDR arm off this run", and every perm on the host goes uncapped —
# silently, and in the direction nobody notices. A bad shipped default would do
# that on every NEW install, where no operator has looked at the file yet.
#
# The concrete near-miss (2026-08-13): adding Cloudflare's WARP IPv6 pool as the
# tidy covering 2a09:bac0::/29 instead of eight /32s. A /29 is broader than the
# v6 floor of /32, so it is rejected — and it would have taken the pre-existing
# IPv4 WARP line down with it.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/asn.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
yes_() { local name="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); else echo "FAIL ${name}"; FAIL=$((FAIL+1)); fi; }
no_()  { local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL ${name}"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi; }

SHIPPED_CIDR="${ROOT}/config/shared-egress.cidr"
SHIPPED_ASNS="${ROOT}/config/shared-egress-asns.txt"

# --- the shipped CIDR file passes the real guard, at the real floors ---
SHARED_EGRESS_ENABLE="true"
SHARED_EGRESS_CIDR_FILE="$SHIPPED_CIDR"
SHARED_EGRESS_ASNS_FILE="$SHIPPED_ASNS"
# Pin the floors rather than inheriting ambient env: this test asserts the
# SHIPPED contract, and a looser exported MIN_PREFIX6 would change what
# "over-broad" means underneath it.
SHARED_EGRESS_MIN_PREFIX4=16
SHARED_EGRESS_MIN_PREFIX6=32
_SW_SHARED_CIDR_OK=""
yes_ shipped-cidr-usable _swatter_shared_egress_cidr_usable

# --- and every address it claims to cover actually matches ---
# Regression on the /29-vs-/32 near-miss. EVERY /32 is probed, not just the
# edges: an earlier version tested bac0/bac5/bac7 only, so silently deleting
# bac1-bac4 or bac6 from the shipped file still passed.
WARP6="2a09:bac0::1 2a09:bac1::1 2a09:bac2::1 2a09:bac3::1 2a09:bac4::1"
WARP6="$WARP6 2a09:bac5:33e6:248c::3a4:23 2a09:bac6::1 2a09:bac7:ffff:ffff::9"
# shellcheck disable=SC2086  # deliberate word-splitting of the address list
for ip in 104.28.1.1 $WARP6; do
  _SW_SHARED_CIDR_OK=""
  check "shipped-covers-${ip}" "$(swatter_is_shared_egress "$ip")" "cidr"
done

# --- and it does NOT overreach past the pool boundary ---
# 2a09:bac8:: is the RIPE parent 2a00::/11, not WARP. If this starts matching,
# someone widened a prefix.
for ip in 2a09:bac8::1 2a09:babf::1 104.27.255.255 104.29.0.1 192.0.2.5; do
  _SW_SHARED_CIDR_OK=""
  no_ "shipped-excludes-${ip}" swatter_is_shared_egress "$ip"
done

# --- the shipped ASN list must stay entry-free ---
# An ASN caps every address that AS originates, so the shipped default carries
# documentation only; entries are local and evidence-backed. If this fails,
# someone shipped a host-specific ASN to every install.
no_ shipped-asns-entry-free _swatter_shared_egress_asns_usable

# --- guard the guard: a deliberately over-broad line must still be rejected ---
# If this ever passes, the floor stopped working and the tests above are theatre.
TMP="$(mktemp "${TMPDIR:-/tmp}/swatter-shipped.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
printf '104.28.0.0/16\n2a09:bac0::/29\n' > "$TMP"
SHARED_EGRESS_CIDR_FILE="$TMP"; _SW_SHARED_CIDR_OK=""
no_ over-broad-v6-rejected _swatter_shared_egress_cidr_usable
# ...and prove the blast radius: the good IPv4 line dies with it.
SHARED_EGRESS_CIDR_FILE="$TMP"; _SW_SHARED_CIDR_OK=""
no_ over-broad-v6-kills-v4-line swatter_is_shared_egress 104.28.196.52

echo "shipped_config_valid_test: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]
