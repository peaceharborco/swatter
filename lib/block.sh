#!/usr/bin/env bash
# lib/block.sh — direct-plane firewall backend router.
#
# The scan loop blocks direct-to-origin offenders through these backend-agnostic
# entry points; DIRECT_BACKEND selects the implementation (csf | ipset). The
# router is THIN — each backend keeps its own dry-run/cap/counter logic, so the
# safety-critical CSF path (block_csf.sh) is unchanged. Return codes pass through.

# Defense-in-depth IP gate at the router (the single entry every block-creating
# caller uses — scan and import-bans alike). The scan path already validates, but
# making the invariant LOCAL here means no caller, present or future, can hand a
# malformed token to csf/ipset. Non-fatal (return 1 = failure); unblock is NOT
# gated (it's cleanup — a stray removal is harmless).
_swatter_block_ip_ok() {
    if ! swatter_is_valid_ip_or_cidr "${1:-}"; then
        log_warn "block router: refusing malformed ip '${1:-}'"; return 1
    fi
    if _swatter_is_unsafe_block_target "${1:-}"; then
        log_warn "block router: refusing unsafe block target '${1:-}' (/0 or unspecified)"; return 1
    fi
    return 0
}

swatter_block_direct_temp() {
    _swatter_block_ip_ok "${1:-}" || return 1
    case "${DIRECT_BACKEND:-csf}" in
        ipset) swatter_ipset_temp "$@" ;;
        *)     swatter_csf_temp   "$@" ;;
    esac
}

swatter_block_direct_perm() {
    _swatter_block_ip_ok "${1:-}" || return 1
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
