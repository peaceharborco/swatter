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
    # csf writes the comment into csf.deny; strip CR/NL and bound length so a
    # crafted reason can't inject lines or corrupt the deny file (mirrors the
    # stderr sanitization below).
    reason="$(printf '%s' "$reason" | tr -d '\n\r' | cut -c1-120)"
    if (( SWATTER_CSF_DENIES_THIS_RUN >= MAX_CSF_DENIES_PER_RUN )); then
        log_warn "CSF cap reached (${MAX_CSF_DENIES_PER_RUN}); skipping temp deny ${ip}"
        return "$SWATTER_RC_CAP"   # protocol: lib/common.sh
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] csf -td ${ip} ${ttl} (${reason})"
        return 0
    fi
    if [[ "${SWATTER_HAVE_CSF}" -ne 1 ]]; then
        SWATTER_LAST_BACKEND_ERR="csf binary not found"
        log_error "csf not found; cannot temp-deny ${ip}"; return 1
    fi
    # Capture stderr (discard stdout) so a `failed` decision records WHY, like the
    # CF path — same command, same effect, exit code preserved.
    local _cerr
    if _cerr="$(csf -td "$ip" "$ttl" -d inout "swatter: ${reason}" 2>&1 >/dev/null)"; then
        SWATTER_CSF_DENIES_THIS_RUN=$(( SWATTER_CSF_DENIES_THIS_RUN + 1 ))
        log_info "csf temp-deny ${ip} for ${ttl}s (${reason})"
        return 0
    fi
    SWATTER_LAST_BACKEND_ERR="csf -td failed${_cerr:+: $(printf '%s' "$_cerr" | tr '\n' ' ' | cut -c1-160)}"
    log_error "csf -td ${ip} failed"; return 1
}

# swatter_csf_perm <ip> <reason>
swatter_csf_perm() {
    local ip="$1" reason="$2"
    # csf appends the comment to csf.deny; strip CR/NL and bound length so a
    # crafted reason can't inject lines or corrupt the deny file (mirrors the
    # stderr sanitization below).
    reason="$(printf '%s' "$reason" | tr -d '\n\r' | cut -c1-120)"
    if (( SWATTER_CSF_DENIES_THIS_RUN >= MAX_CSF_DENIES_PER_RUN )); then
        log_warn "CSF cap reached (${MAX_CSF_DENIES_PER_RUN}); skipping perm deny ${ip}"
        return "$SWATTER_RC_CAP"   # protocol: lib/common.sh
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] csf -d ${ip} (${reason})"
        return 0
    fi
    if [[ "${SWATTER_HAVE_CSF}" -ne 1 ]]; then
        SWATTER_LAST_BACKEND_ERR="csf binary not found"
        log_error "csf not found; cannot perm-deny ${ip}"; return 1
    fi
    # csf -d is permanent; it appends to csf.deny. Capture stderr for diagnosability.
    local _cerr
    if _cerr="$(csf -d "$ip" "swatter: ${reason}" 2>&1 >/dev/null)"; then
        SWATTER_CSF_DENIES_THIS_RUN=$(( SWATTER_CSF_DENIES_THIS_RUN + 1 ))
        log_info "csf PERM-deny ${ip} (${reason})"
        return 0
    fi
    SWATTER_LAST_BACKEND_ERR="csf -d failed${_cerr:+: $(printf '%s' "$_cerr" | tr '\n' ' ' | cut -c1-160)}"
    log_error "csf -d ${ip} failed"; return 1
}

# swatter_csf_unblock <ip> : remove temp and permanent denies. A failed removal
# must NOT report success — the deny may still be live and the operator would
# walk away believing the IP is clear (the unblock twin of block diagnosability).
swatter_csf_unblock() {
    local ip="$1"
    if [[ "${SWATTER_HAVE_CSF}" -ne 1 ]]; then
        log_warn "csf not found; nothing to unblock for ${ip}"; return 0
    fi
    # csf -tr/-dr exit 0 for "not in list", so a nonzero rc here is a genuine
    # command failure worth surfacing, not an unblock of a never-blocked IP.
    local _e _cerr="" rc=0
    _e="$(csf -tr "$ip" 2>&1 >/dev/null)" || { rc=1; _cerr="$_e"; }     # remove temp
    _e="$(csf -dr "$ip" 2>&1 >/dev/null)" || { rc=1; _cerr="${_cerr:-$_e}"; }   # remove permanent
    if (( rc )); then
        SWATTER_LAST_BACKEND_ERR="csf unblock failed${_cerr:+: $(printf '%s' "$_cerr" | tr '\n' ' ' | cut -c1-160)}"
        log_error "csf unblock ${ip} FAILED — deny may still be live (${SWATTER_LAST_BACKEND_ERR})"
        return 1
    fi
    log_info "csf unblock ${ip} (temp+perm removed)"
}
