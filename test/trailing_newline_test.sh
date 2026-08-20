#!/usr/bin/env bash
# A policy file whose LAST line lacks a trailing newline must still be honoured.
# Every validator in this tree reads such a file with awk or grep and accepts it;
# a bare `while read` silently DROPS that line, so the file passes validation
# while the matcher behaves as though the range were never there. On a
# single-entry file (cds1's shared-egress-asns.txt) that disables the whole arm.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=../lib/common.sh
source lib/common.sh; source lib/allowlist.sh
fails=0
check() { if [[ "$2" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1: got '$2' want '$3'"; fails=$((fails+1)); fi; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# --- IPv6 last line, no trailing newline -----------------------------------
printf '104.28.0.0/16 # v4 first\n2a09:bac7::/32 # v6 LAST, no newline' > "$tmp/v6last.cidr"
_cidr_overlaps_file "2a09:bac7::1" "$tmp/v6last.cidr" && r=match || r=miss
check "v6-last-line-no-newline-still-matches" "$r" "match"
# the v4 line in the same file must be unaffected
_cidr_overlaps_file "104.28.196.52" "$tmp/v6last.cidr" && r=match || r=miss
check "v4-in-same-file-still-matches" "$r" "match"
# a v6 address NOT in the file must still miss
_cidr_overlaps_file "2a09:bac8::1" "$tmp/v6last.cidr" && r=match || r=miss
check "v6-outside-range-still-misses" "$r" "miss"

# --- with the newline present, behaviour is identical ----------------------
printf '2a09:bac7::/32\n' > "$tmp/v6nl.cidr"
_cidr_overlaps_file "2a09:bac7::1" "$tmp/v6nl.cidr" && r=match || r=miss
check "v6-with-newline-matches" "$r" "match"

# --- _ip_in_cidr_file v6 branch, same hazard -------------------------------
if declare -F _ip_in_cidr_file >/dev/null; then
    printf '2a09:bac7::/32 # no newline' > "$tmp/v6b.cidr"
    _ip_in_cidr_file "2a09:bac7::5" "$tmp/v6b.cidr" && r=match || r=miss
    check "ip_in_cidr_file-v6-no-newline" "$r" "match"
fi

# --- _ip_in_cidr_file must still MISS an address outside the range ---------
if declare -F _ip_in_cidr_file >/dev/null; then
    printf '2a09:bac7::/32 # no newline' > "$tmp/v6b2.cidr"
    _ip_in_cidr_file "2a09:bac8::5" "$tmp/v6b2.cidr" && r=match || r=miss
    check "ip_in_cidr_file-v6-outside-range-misses" "$r" "miss"
fi

# --- the shared-egress ASN list: a SINGLE line with no trailing newline -----
# Driven through the PRODUCTION matcher, swatter_is_shared_egress. An earlier
# version of this test reimplemented the fixed read-loop inline, which meant it
# stayed green when the lib/asn.sh fix was reverted — it tested the idiom, not
# the code. swatter_asn_resolve is stubbed so the case needs no live DNS (and
# so it cannot write $STATE_DIR/asn/<ip>).
source lib/asn.sh
swatter_asn_resolve() { printf '206092'; }
SHARED_EGRESS_ENABLE=true
SHARED_EGRESS_CIDR_FILE="$tmp/se.cidr"
printf '192.0.2.0/24 # a range the test IP is NOT in\n' > "$SHARED_EGRESS_CIDR_FILE"
SHARED_EGRESS_ASNS_FILE="$tmp/asns.txt"

printf '206092 # sole entry, no trailing newline' > "$tmp/asns.txt"
_SW_SHARED_CIDR_OK=""
if _swatter_shared_egress_asns_usable; then r=usable; else r=unusable; fi
check "single-line-asn-file-reports-usable" "$r" "usable"
# The validator says usable, so the matcher MUST agree. This is the assertion
# that goes red if lib/asn.sh loses its `|| [[ -n "$line" ]]`.
_SW_SHARED_CIDR_OK=""
out="$(swatter_is_shared_egress "198.51.100.7" 2>/dev/null)" && r="$out" || r=miss
check "asn-arm-matches-sole-unterminated-entry" "$r" "AS206092(sole entry, no trailing newline)"

# ...and an ASN that is NOT listed must still miss, so the test cannot pass by
# matching everything.
swatter_asn_resolve() { printf '13335'; }
_SW_SHARED_CIDR_OK=""
out="$(swatter_is_shared_egress "198.51.100.7" 2>/dev/null)" && r="$out" || r=miss
check "asn-arm-misses-unlisted-asn" "$r" "miss"

# --- origin-lock loader: honour the final line, but validate every line ------
source lib/origin_lock.sh || { echo "FAIL cannot source lib/origin_lock.sh"; exit 1; }
declare -F _ol_load_ranges >/dev/null || { echo "FAIL _ol_load_ranges missing"; exit 1; }
if true; then
    printf '104.16.0.0/13\n2400:cb00::/32' > "$tmp/cf.cidr"   # v6 last, no newline
    CLOUDFLARE_IPS_FILE="$tmp/cf.cidr" _ol_load_ranges
    case "${_OL_V6:-}" in *2400:cb00::/32*) r=kept ;; *) r=dropped ;; esac
    check "origin-lock-keeps-final-v6-without-newline" "$r" "kept"

    # A truncated final line is a valid CIDR and a huge bypass; it must be
    # rejected, not admitted just because we now read the last line.
    printf '104.16.0.0/13\n203.0.113.0/999' > "$tmp/cfbad.cidr"
    CLOUDFLARE_IPS_FILE="$tmp/cfbad.cidr" _ol_load_ranges 2>/dev/null
    case "${_OL_V4:-}" in *203.0.113.0/999*) r=admitted ;; *) r=rejected ;; esac
    check "origin-lock-rejects-malformed-final-line" "$r" "rejected"
    case "${_OL_V4:-}" in *104.16.0.0/13*) r=kept ;; *) r=lost ;; esac
    check "origin-lock-good-line-survives-a-bad-sibling" "$r" "kept"

    # The case the guard's comment actually names: a TRUNCATED prefix. /1 is a
    # perfectly valid CIDR — swatter_is_valid_ip_or_cidr accepts it — so shape
    # checking alone does not stop it. Admitting it would let half the internet
    # past a DROP-mode lock.
    printf '104.16.0.0/13\n104.16.0.0/1' > "$tmp/cftrunc.cidr"
    CLOUDFLARE_IPS_FILE="$tmp/cftrunc.cidr" _ol_load_ranges 2>/dev/null
    # /13 contains "/1" as a substring, so match on the exact stored line.
    r=rejected; while IFS= read -r l; do [[ "$l" == "104.16.0.0/1" ]] && r=admitted; done <<< "${_OL_V4}"
    check "origin-lock-rejects-truncated-over-broad-prefix" "$r" "rejected"
    r=lost; while IFS= read -r l; do [[ "$l" == "104.16.0.0/13" ]] && r=kept; done <<< "${_OL_V4}"
    check "origin-lock-keeps-the-legitimate-13" "$r" "kept"

    # ...and a real Cloudflare v6 range must not be caught by the v6 floor.
    printf '2400:cb00::/32\n' > "$tmp/cfv6.cidr"
    CLOUDFLARE_IPS_FILE="$tmp/cfv6.cidr" _ol_load_ranges 2>/dev/null
    case "${_OL_V6:-}" in *2400:cb00::/32*) r=kept ;; *) r=lost ;; esac
    check "origin-lock-v6-floor-does-not-reject-real-cf-range" "$r" "kept"

    # The compiled CF fallback carries a /29 (lib/allowlist.sh:20). The v6 floor
    # must admit it — this pins the floor so nobody "tightens" it to /32 later.
    printf '2a06:98c0::/29\n' > "$tmp/cfv629.cidr"
    CLOUDFLARE_IPS_FILE="$tmp/cfv629.cidr" _ol_load_ranges 2>/dev/null
    case "${_OL_V6:-}" in *2a06:98c0::/29*) r=kept ;; *) r=lost ;; esac
    check "origin-lock-v6-floor-admits-the-compiled-29-fallback" "$r" "kept"

    # A non-numeric floor from the environment must not reach an arithmetic
    # context: bash would re-resolve it as a variable name and `set -u` aborts —
    # and this runs from _ol_preamble_family, possibly after DROP is installed.
    ( OL_MIN_PREFIX4=abc; source lib/origin_lock.sh
      printf '104.16.0.0/13\n' > "$tmp/cfknob.cidr"
      CLOUDFLARE_IPS_FILE="$tmp/cfknob.cidr" _ol_load_ranges 2>/dev/null
      case "${_OL_V4:-}" in *104.16.0.0/13*) exit 0 ;; *) exit 1 ;; esac ) \
        && r=survived || r=aborted
    check "origin-lock-non-numeric-floor-does-not-abort" "$r" "survived"
fi

(( fails == 0 )) || exit 1
echo "trailing-newline: all passed"
