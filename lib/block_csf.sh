#!/usr/bin/env bash
# lib/block_csf.sh — the CSF firewall plane (direct-to-origin offenders only).
#
# Only ever called for offenders classified DIRECT (their TCP socket is the
# attacker, not a Cloudflare edge). Temp blocks use `csf -td IP TTL`; permanent
# blocks use `csf -d IP`. Unblock reverses both. Every call honors dry-run and
# the per-run CSF cap (the catastrophic channel gets its own lower limit).

SWATTER_CSF_DENIES_THIS_RUN=0

# swatter_csf_temp <ip> <ttl_seconds> <reason>
swatter_csf_temp() {
    local ip="$1" ttl="$2" reason="$3"
    if (( SWATTER_CSF_DENIES_THIS_RUN >= MAX_CSF_DENIES_PER_RUN )); then
        log_warn "CSF cap reached (${MAX_CSF_DENIES_PER_RUN}); skipping temp deny ${ip}"
        return 2
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] csf -td ${ip} ${ttl} (${reason})"
        return 0
    fi
    if [[ "${SWATTER_HAVE_CSF}" -ne 1 ]]; then
        log_error "csf not found; cannot temp-deny ${ip}"; return 1
    fi
    if csf -td "$ip" "$ttl" -d inout "swatter: ${reason}" >/dev/null 2>&1; then
        SWATTER_CSF_DENIES_THIS_RUN=$(( SWATTER_CSF_DENIES_THIS_RUN + 1 ))
        log_info "csf temp-deny ${ip} for ${ttl}s (${reason})"
        return 0
    fi
    log_error "csf -td ${ip} failed"; return 1
}

# swatter_csf_perm <ip> <reason>
swatter_csf_perm() {
    local ip="$1" reason="$2"
    if (( SWATTER_CSF_DENIES_THIS_RUN >= MAX_CSF_DENIES_PER_RUN )); then
        log_warn "CSF cap reached (${MAX_CSF_DENIES_PER_RUN}); skipping perm deny ${ip}"
        return 2
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] csf -d ${ip} (${reason})"
        return 0
    fi
    if [[ "${SWATTER_HAVE_CSF}" -ne 1 ]]; then
        log_error "csf not found; cannot perm-deny ${ip}"; return 1
    fi
    # csf -d is permanent; it appends to csf.deny.
    if csf -d "$ip" "swatter: ${reason}" >/dev/null 2>&1; then
        SWATTER_CSF_DENIES_THIS_RUN=$(( SWATTER_CSF_DENIES_THIS_RUN + 1 ))
        log_info "csf PERM-deny ${ip} (${reason})"
        return 0
    fi
    log_error "csf -d ${ip} failed"; return 1
}

# swatter_csf_unblock <ip> : remove temp and permanent denies.
swatter_csf_unblock() {
    local ip="$1"
    if [[ "${SWATTER_HAVE_CSF}" -ne 1 ]]; then
        log_warn "csf not found; nothing to unblock for ${ip}"; return 0
    fi
    csf -tr "$ip" >/dev/null 2>&1 || true     # remove temp
    csf -dr "$ip" >/dev/null 2>&1 || true     # remove permanent
    log_info "csf unblock ${ip} (temp+perm removed)"
}
