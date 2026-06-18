#!/usr/bin/env bash
# lib/block_ipset.sh — ipset direct-plane backend (alternative to CSF).
#
# DIRECT_BACKEND=ipset. Two timeout-capable sets (swatter4/swatter6) + one DROP
# rule each; temp blocks use the kernel timeout, perm = timeout 0 (no expiry).
# Mirrors block_csf.sh's dry-run + per-run cap structure (its own counter). Perm
# sets are in-memory, so each perm change rewrites IPSET_SAVE_FILE for boot
# restore. Only ever called for offenders classified DIRECT.

SWATTER_IPSET_V4="swatter4"
SWATTER_IPSET_V6="swatter6"
SWATTER_IPSET_DENIES_THIS_RUN=0

_ipset_set_for() { [[ "$1" == *:* ]] && printf '%s' "${SWATTER_IPSET_V6}" || printf '%s' "${SWATTER_IPSET_V4}"; }

_ipset_save() {
    # Save ONLY our two sets by name — a bare `ipset save` dumps EVERY set on the
    # box (CSF/fail2ban also use ipset), which the documented boot-restore would
    # then clobber or fail on. Written via tmp+mv so a mid-write failure never
    # truncates the existing save file (which would lose perm bans at reboot).
    local f="${IPSET_SAVE_FILE:-/etc/swatter/ipset.save}"
    { ipset save "${SWATTER_IPSET_V4}" 2>/dev/null
      ipset save "${SWATTER_IPSET_V6}" 2>/dev/null; } > "${f}.tmp" 2>/dev/null \
        && mv "${f}.tmp" "$f" 2>/dev/null || rm -f "${f}.tmp" 2>/dev/null
}

# Create the sets + DROP rules (idempotent). Run by `swatter setup-ipset`.
swatter_ipset_setup() {
    [[ "${SWATTER_HAVE_IPSET}" -eq 1 ]] || { log_error "ipset/iptables not found; cannot set up ipset backend"; return 1; }
    ipset create "${SWATTER_IPSET_V4}" hash:ip family inet  timeout 0 -exist 2>/dev/null
    ipset create "${SWATTER_IPSET_V6}" hash:ip family inet6 timeout 0 -exist 2>/dev/null
    iptables  -C INPUT -m set --match-set "${SWATTER_IPSET_V4}" src -j DROP 2>/dev/null \
        || iptables  -I INPUT -m set --match-set "${SWATTER_IPSET_V4}" src -j DROP 2>/dev/null
    # IPv6 DROP rule needs ip6tables; if absent, v6 set members are NOT enforced.
    if [[ "${SWATTER_HAVE_IP6TABLES:-0}" -eq 1 ]]; then
        ip6tables -C INPUT -m set --match-set "${SWATTER_IPSET_V6}" src -j DROP 2>/dev/null \
            || ip6tables -I INPUT -m set --match-set "${SWATTER_IPSET_V6}" src -j DROP 2>/dev/null
    else
        log_warn "ip6tables not found — IPv6 ipset blocks will NOT be enforced (v4 only)"
    fi
    log_info "ipset backend ready (sets ${SWATTER_IPSET_V4}/${SWATTER_IPSET_V6} + DROP rules)"
}

swatter_ipset_temp() {
    local ip="$1" ttl="$2" reason="$3" set
    if (( SWATTER_IPSET_DENIES_THIS_RUN >= MAX_CSF_DENIES_PER_RUN )); then
        log_warn "ipset cap reached (${MAX_CSF_DENIES_PER_RUN}); skipping temp deny ${ip}"; return 2
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] ipset add ${ip} timeout ${ttl} (${reason})"; return 0
    fi
    [[ "${SWATTER_HAVE_IPSET}" -eq 1 ]] || { log_error "ipset not found; cannot temp-deny ${ip}"; return 1; }
    set="$(_ipset_set_for "$ip")"
    if ipset add "$set" "$ip" timeout "$ttl" -exist 2>/dev/null; then
        SWATTER_IPSET_DENIES_THIS_RUN=$(( SWATTER_IPSET_DENIES_THIS_RUN + 1 ))
        log_info "ipset temp-deny ${ip} for ${ttl}s (${reason})"; return 0
    fi
    log_error "ipset add ${ip} failed"; return 1
}

swatter_ipset_perm() {
    local ip="$1" reason="$2" set
    if (( SWATTER_IPSET_DENIES_THIS_RUN >= MAX_CSF_DENIES_PER_RUN )); then
        log_warn "ipset cap reached (${MAX_CSF_DENIES_PER_RUN}); skipping perm deny ${ip}"; return 2
    fi
    if [[ "${SWATTER_MODE}" != "enforce" ]]; then
        log_info "[dry-run] ipset add ${ip} timeout 0 (${reason})"; return 0
    fi
    [[ "${SWATTER_HAVE_IPSET}" -eq 1 ]] || { log_error "ipset not found; cannot perm-deny ${ip}"; return 1; }
    set="$(_ipset_set_for "$ip")"
    if ipset add "$set" "$ip" timeout 0 -exist 2>/dev/null; then
        SWATTER_IPSET_DENIES_THIS_RUN=$(( SWATTER_IPSET_DENIES_THIS_RUN + 1 ))
        _ipset_save
        log_info "ipset PERM-deny ${ip} (${reason})"; return 0
    fi
    log_error "ipset add ${ip} failed"; return 1
}

swatter_ipset_unblock() {
    local ip="$1"
    [[ "${SWATTER_HAVE_IPSET}" -eq 1 ]] || { log_warn "ipset not found; nothing to unblock for ${ip}"; return 0; }
    ipset del "${SWATTER_IPSET_V4}" "$ip" -exist 2>/dev/null || true
    ipset del "${SWATTER_IPSET_V6}" "$ip" -exist 2>/dev/null || true
    _ipset_save
    log_info "ipset unblock ${ip} (v4+v6 sets)"
}
