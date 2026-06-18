#!/usr/bin/env bash
# lib/block.sh — direct-plane firewall backend router.
#
# The scan loop blocks direct-to-origin offenders through these backend-agnostic
# entry points; DIRECT_BACKEND selects the implementation (csf | ipset). The
# router is THIN — each backend keeps its own dry-run/cap/counter logic, so the
# safety-critical CSF path (block_csf.sh) is unchanged. Return codes pass through.

swatter_block_direct_temp() {
    case "${DIRECT_BACKEND:-csf}" in
        ipset) swatter_ipset_temp "$@" ;;
        *)     swatter_csf_temp   "$@" ;;
    esac
}

swatter_block_direct_perm() {
    case "${DIRECT_BACKEND:-csf}" in
        ipset) swatter_ipset_perm "$@" ;;
        *)     swatter_csf_perm   "$@" ;;
    esac
}

swatter_block_direct_unblock() {
    case "${DIRECT_BACKEND:-csf}" in
        ipset) swatter_ipset_unblock "$@" ;;
        *)     swatter_csf_unblock   "$@" ;;
    esac
}
