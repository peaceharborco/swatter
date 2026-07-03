#!/usr/bin/env bash
# lib/swarm.sh — fleet reputation sharing, host side (subsystem 2 of 2).
#
# Publishes this box's CONFIRMED perm bans to the operator's self-hosted hub
# (POST /contribute) and consumes the merged fleet feed back as the intel
# provider `swarm` (lib/providers/swarm.sh). Opt-in corroborated-block sweeps
# route through _swatter_execute_block so every local gate still applies.
# All inert unless SWARM_ENABLE=true + SWARM_HUB_URL set (see spec §9).

_swarm_enabled() {
    [[ "${SWARM_ENABLE:-false}" == "true" && -n "${SWARM_HUB_URL:-}" ]]
}

# Opaque, stable, random per box — NOT hostname/IP (spec §6). Created 0600 on
# first use; only enrolled ids count toward hub corroboration.
swatter_swarm_host_id() {
    local f="${STATE_DIR}/swarm.host_id" id
    if [[ -s "$f" ]]; then printf '%s' "$(tr -d '[:space:]' < "$f")"; return 0; fi
    id="$(od -vAn -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    [[ "$id" =~ ^[0-9a-f]{32}$ ]] || { log_error "swarm: host_id generation failed"; return 1; }
    ( umask 0177; printf '%s' "$id" > "$f" ) || { log_error "swarm: cannot write ${f}"; return 1; }
    printf '%s' "$id"
}

# Bearer-token curl config from a 0400 token file (secret NEVER in argv —
# same rule every credentialed curl in this repo follows; curl_secrets_test).
# Caller MUST rm -f the printed path right after curl returns.
_swarm_curl_cfg_token() {
    local tf="$1" tok
    [[ -r "$tf" ]] || { log_warn "swarm: token file missing/unreadable: ${tf}"; return 1; }
    tok="$(tr -d '[:space:]' < "$tf")"
    [[ -n "$tok" ]] || { log_warn "swarm: token file empty: ${tf}"; return 1; }
    swatter_curl_cfg "header = \"Authorization: Bearer ${tok}\""
}

# --- stubs replaced by later tasks (keep sourcing safe in any order) ---
swatter_swarm_publish() { return 0; }
swatter_swarm_sweep()   { return 0; }
cmd_swarm()             { log_error "swarm: not yet implemented"; return 2; }
