#!/usr/bin/env bash
# install/install.sh — deploy Swatter to a server.
#
# Two modes:
#   ./install.sh local            install on THIS machine (run as root)
#   ./install.sh remote <sshdest> push to a remote host over ssh+scp
#
# Flags (either mode, any position):
#   --no-cron   skip writing /etc/cron.d/swatter{,-report} — leaves whatever
#               cron state the operator already has (e.g. a maintenance hold)
#               undisturbed. Re-enable manually once test-config is green.
#
# Layout installed:
#   /usr/local/bin/swatter                 (CLI, 0755)
#   /usr/local/lib/swatter/*.sh            (libs incl. providers/, score.awk)
#   /etc/swatter/swatter.conf              (0600; copied from example if absent)
#   /etc/swatter/badpaths.conf             (0644)
#   /etc/swatter/monitoring.cidr           (0644)
#   /etc/swatter/hosting-asns.txt          (0644; not overwritten on upgrade)
#   /etc/swatter/hosting-asns.txt.example  (0644; latest curated list to diff)
#   /etc/swatter/honeypot.paths.example    (0644; live honeypot.paths is never overwritten)
#   /etc/cron.d/swatter                    (0644; skipped with --no-cron)
#   /etc/logrotate.d/swatter               (0644)
#   /var/lib/swatter, /var/log/swatter     (0750)
#
# After install: run `swatter refresh-feeds` then `swatter test-config`, leave it
# in report mode for ~a week, review `swatter top`, then set SWATTER_MODE=enforce.

[[ "${1:-}" == "--source-only" ]] && SWATTER_INSTALL_SOURCE_ONLY=1 || SWATTER_INSTALL_SOURCE_ONLY=0
(( SWATTER_INSTALL_SOURCE_ONLY )) || set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd -- "${HERE}/.." && pwd)"

# csfpre.sh markers — the managed block is rewritten idempotently between these.
ORIGIN_LOCK_BEGIN="# >>> swatter origin-lock (managed) >>>"
ORIGIN_LOCK_END="# <<< swatter origin-lock (managed) <<<"

# Wire the origin-lock persistence path. Detection of CSF-vs-not decides which
# path we install: a CSF host re-applies via /etc/csf/csfpre.sh on every
# `csf -r`; a non-CSF host re-applies via a systemd oneshot at boot. Idempotent
# — safe to re-run on upgrade. Never touches the live firewall itself (the
# operator runs `swatter origin-lock apply` for that, default-off).
_install_origin_lock_persistence() {
    if command -v csf >/dev/null 2>&1 || [[ -d /etc/csf ]]; then
        _install_origin_lock_csfpre
    else
        _install_origin_lock_systemd
    fi
}

# CSF path: ensure /etc/csf/csfpre.sh runs the lock before CSF builds its chains.
# The call is GUARDED so a broken or missing swatter binary at `csf -r` time
# fails OPEN — csfpre.sh must never abort partway and leave a DROP without the
# preceding Cloudflare ACCEPT. We therefore:
#   - never `set -e` the guard (a swatter failure is swallowed with `|| true`);
#   - skip cleanly if the binary is absent/non-executable;
#   so the worst case is "lock not applied this cycle", never a half-built chain.
_install_origin_lock_csfpre() {
    local pre="${SWATTER_OL_CSFPRE:-/etc/csf/csfpre.sh}"
    install -d -m 0700 "$(dirname "$pre")"

    if [[ ! -f "${pre}" ]]; then
        # Create a minimal, valid csfpre.sh; CSF sources it, so a shebang +
        # `set -u`-safe body is enough.
        cat > "${pre}" <<'CSFPRE_EOF'
#!/bin/sh
# /etc/csf/csfpre.sh — run by CSF before it builds its iptables chains.
CSFPRE_EOF
        chmod 0700 "${pre}"
        chown root:root "${pre}" 2>/dev/null || true
        echo "created ${pre}"
    fi

    # Rewrite (or append) the managed block, leaving any operator content intact.
    local tmp
    tmp="$(mktemp)" || { echo "  (mktemp failed; skipping csfpre wiring)" >&2; return 0; }
    trap 'rm -f "${tmp:-}"' RETURN

    # Strip a prior managed block (between the markers), keep everything else.
    awk -v b="${ORIGIN_LOCK_BEGIN}" -v e="${ORIGIN_LOCK_END}" '
        $0 == b { skip=1; next }
        $0 == e { skip=0; next }
        skip != 1 { print }
    ' "${pre}" > "${tmp}"

    {
        echo "${ORIGIN_LOCK_BEGIN}"
        echo "# Re-apply the Cloudflare-only web-port lock ahead of CSF's chains."
        echo "# GUARDED: a missing/broken swatter binary fails OPEN (no rule added),"
        echo "# never leaving a DROP without its preceding Cloudflare ACCEPT."
        echo 'if [ -x /usr/local/bin/swatter ]; then'
        # --yes is REQUIRED: this runs non-interactively at `csf -r`, and DROP mode
        # otherwise aborts (return 3) at the interactive-confirm guard, swallowed by
        # `|| true` — silently installing NO rules and leaving the origin open.
        # Setting ORIGIN_LOCK=drop in swatter.conf IS the operator's deliberate consent.
        echo '    /usr/local/bin/swatter origin-lock apply --hook=csf --yes || true'
        echo 'fi'
        echo "${ORIGIN_LOCK_END}"
    } >> "${tmp}"

    install -m 0700 "${tmp}" "${pre}"
    chown root:root "${pre}" 2>/dev/null || true
    echo "wired origin-lock into ${pre} (re-applies on every 'csf -r')"
    echo "  NOTE: origin-lock is default-OFF. Set ORIGIN_LOCK=log (then drop) in"
    echo "        /etc/swatter/swatter.conf and run 'swatter origin-lock apply' to arm it."

    # If CSF is already running, the block is live on the next reload — don't
    # force a reload here (it would rebuild the firewall mid-install).
}

# Neutralize a legacy HAND-WRITTEN static origin-lock block (one predating the
# managed marker block) so it stops enforcing — WITHOUT breaking csfpre.sh syntax.
# It wraps the legacy region — from its first origin-lock signature line to just
# before the managed marker block (or EOF) — in a `: <<'MARKER' … MARKER` here-doc
# fed to the no-op `:`. The wrapped text becomes inert literal input, so the block
# never executes and its internal `if/while/…` constructs no longer need to
# balance (commenting individual matching lines would leave a dangling `then`/`do`
# and make `csf -r` error). Backs up first; idempotent (no-ops once the wrapper is
# present). NOTE: any operator content between the static block and the managed
# block is wrapped too — the backup makes this reversible; retire is deliberate.
_OL_RETIRE_MARK="SWATTER_RETIRED_ORIGIN_LOCK"
_ol_retire_legacy_static() {
    local pre="${1:-${SWATTER_OL_CSFPRE:-/etc/csf/csfpre.sh}}"
    [[ -f "$pre" ]] || return 0
    local b="${ORIGIN_LOCK_BEGIN}" e="${ORIGIN_LOCK_END}" mark="${_OL_RETIRE_MARK}"

    grep -qF -- ": <<'${mark}'" "$pre" && return 0   # already retired -> idempotent no-op

    # First active legacy signature line outside the markers; managed-block start
    # line (if any); total line count.
    local info
    info="$(awk -v b="$b" -v e="$e" '
        $0==b{ if(!mb) mb=NR; inm=1; next } $0==e{inm=0; next} inm{next}
        !lo && ( ($0 ~ /cf_origin/) || ($0 ~ /ORIGIN-LOCK/) || ($0 ~ /--match-set cf_origin/) ||
                 (($0 ~ /-j DROP/) && ($0 ~ /dports 80,443/)) ) { lo=NR }
        END { print (lo?lo:0) " " (mb?mb:0) " " NR }
    ' "$pre")"
    local lo="${info%% *}" rest="${info#* }"; local mb="${rest%% *}" last="${rest##* }"
    [[ "$lo" -gt 0 ]] || return 0                    # no legacy block -> nothing to do
    local end
    if [[ "$mb" -gt "$lo" ]]; then end=$(( mb - 1 )); else end="$last"; fi

    local stamp="${SWATTER_NOW_STAMP:-$(date -u +%Y%m%d-%H%M%S)}"
    cp -p "$pre" "${pre}.bak-${stamp}" || { echo "  (backup failed; aborting retire)" >&2; return 1; }

    local tmp; tmp="$(mktemp)" || return 1
    local opener=": <<'${mark}'   # legacy static origin-lock retired by swatter"
    awk -v lo="$lo" -v end="$end" -v opener="$opener" -v mark="$mark" '
        NR==lo { print opener }
        { print }
        NR==end { print mark }
    ' "$pre" > "$tmp" || { rm -f "$tmp"; return 1; }
    install -m 0700 "$tmp" "$pre"; rm -f "$tmp"
    chown root:root "$pre" 2>/dev/null || true
    echo "retired legacy static origin-lock block (lines ${lo}-${end}) in ${pre}; backup ${pre}.bak-${stamp}"
}

# Non-CSF path: install + enable the systemd oneshot that re-applies at boot.
# Falls back to a clear rc.local note when systemd is not the init system.
_install_origin_lock_systemd() {
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
        install -m 0644 "${SRC}"/install/swatter-origin-lock.service \
            /etc/systemd/system/swatter-origin-lock.service
        systemctl daemon-reload 2>/dev/null || true
        # `enable` only wires the boot symlink; it does NOT start (and thus does
        # NOT apply) the lock now — apply stays the operator's deliberate step.
        if systemctl enable swatter-origin-lock.service >/dev/null 2>&1; then
            echo "installed + enabled swatter-origin-lock.service (re-applies at boot)"
        else
            echo "installed swatter-origin-lock.service (enable failed; check 'systemctl status')"
        fi
        echo "  NOTE: origin-lock is default-OFF. Set ORIGIN_LOCK=log (then drop) in"
        echo "        /etc/swatter/swatter.conf and run 'swatter origin-lock apply' to arm it."
    else
        echo "no CSF and no systemd detected — origin-lock has no boot persistence wired."
        echo "  Add the following to /etc/rc.local (or an equivalent boot hook):"
        echo "    /usr/local/bin/swatter origin-lock apply || true"
    fi
}

# Render /etc/cron.d/swatter-report — the nightly report in its OWN cron file.
# A dedicated file is deliberate: `CRON_TZ` applies to every job that follows it
# in a cron file, so putting the report's timezone in the shared cron would also
# shift the 5-min scan / feed refresh. Here it scopes to the report alone, so the
# schedule tracks REPORT_CRON_TZ (e.g. America/Los_Angeles → 4am Pacific,
# DST-adjusted) while scan/refresh stay in the system zone. The report line
# redirects to a log so a failed nightly send is recorded, never silently lost
# (cron's own output is discarded by MAILTO="").
_swatter_report_cron_file() {
    local report_cron="$1" report_tz="$2"
    echo "# Swatter nightly report — separate cron file so CRON_TZ scopes to the"
    echo "# report only (a bare CRON_TZ in the shared cron would also shift the scan)."
    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    echo 'MAILTO=""'
    [[ -n "$report_tz" ]] && echo "CRON_TZ=${report_tz}"
    echo
    echo "${report_cron} * * * root /usr/local/bin/swatter report >> /var/log/swatter/report.log 2>&1"
}

# Render the report cron from the LIVE conf. install.sh runs in its own shell
# and never sources swatter.conf, so reading "${REPORT_CRON_TZ:-}" here would
# expand empty env vars and silently strip the operator's CRON_TZ on every
# upgrade (2026-07-01: report reverted to 04:00 UTC = 9pm Pacific). Subshell-
# source keeps the conf's other settings out of the installer's environment.
_swatter_report_cron_from_conf() {
    local conf="${1:-/etc/swatter/swatter.conf}" rcron rtz
    rcron="$(bash -c 'source "$1" 2>/dev/null; echo "${REPORT_CRON:-0 4}"' _ "$conf" 2>/dev/null || echo "0 4")"
    rtz="$(bash -c 'source "$1" 2>/dev/null; echo "${REPORT_CRON_TZ:-}"' _ "$conf" 2>/dev/null || true)"
    _swatter_report_cron_file "${rcron:-0 4}" "$rtz"
}

# Pure predicate — no filesystem, no root — so tests can drive the real
# decision logic behind --no-cron instead of grepping the source text.
# Defaults to enabled: only "0" (set by --no-cron in main()) turns it off.
# Fail-open on != "0" (not a strict == "1") so a stray/unexpected value in the
# env (SWATTER_INSTALL_CRON=true, a typo, anything but exactly "0") still
# installs cron rather than silently skipping it on a normal upgrade.
_swatter_cron_should_install() { [[ "${SWATTER_INSTALL_CRON:-1}" != "0" ]]; }

_install_local() {
    [[ "$(id -u)" -eq 0 ]] || { echo "install local must run as root" >&2; exit 1; }

    install -d -m 0755 /usr/local/lib/swatter /usr/local/lib/swatter/providers
    install -m 0644 "${SRC}"/lib/*.sh                /usr/local/lib/swatter/
    install -m 0644 "${SRC}"/lib/score.awk           /usr/local/lib/swatter/
    install -m 0644 "${SRC}"/lib/providers/*.sh      /usr/local/lib/swatter/providers/
    install -m 0755 "${SRC}"/bin/swatter             /usr/local/bin/swatter

    install -d -m 0755 /etc/swatter
    install -m 0644 "${SRC}"/config/badpaths.conf    /etc/swatter/badpaths.conf
    [[ -f /etc/swatter/monitoring.cidr ]] || install -m 0644 "${SRC}"/config/monitoring.cidr /etc/swatter/monitoring.cidr
    # hosting-asns is operator-editable; install live only if absent, always ship .example to diff.
    [[ -f /etc/swatter/hosting-asns.txt ]] || install -m 0644 "${SRC}"/config/hosting-asns.txt /etc/swatter/hosting-asns.txt 2>/dev/null \
        || echo "warning: could not install /etc/swatter/hosting-asns.txt — hosting-ASN heuristics disabled until it exists" >&2
    install -m 0644 "${SRC}"/config/hosting-asns.txt /etc/swatter/hosting-asns.txt.example 2>/dev/null || true
    # honeypot is operator-authored; ship only the example, never overwrite a live file.
    install -m 0644 "${SRC}"/config/honeypot.paths.example /etc/swatter/honeypot.paths.example 2>/dev/null || true
    if [[ -f /etc/swatter/swatter.conf ]]; then
        echo "keeping existing /etc/swatter/swatter.conf"
    else
        install -m 0600 "${SRC}"/config/swatter.example.conf /etc/swatter/swatter.conf
        echo "created /etc/swatter/swatter.conf (mode 0600) — edit before enforcing"
    fi

    install -d -m 0750 /var/lib/swatter /var/log/swatter
    # Shared cron: scan + feed refresh (system timezone). The report is NOT here —
    # it lives in its own file so its CRON_TZ doesn't shift these jobs. Cron is
    # installed LAST-ish and can be suppressed with --no-cron: without this an
    # upgrade silently re-arms the */5 scan in the middle of a maintenance hold,
    # and does so BEFORE test-config runs below — undoing the operator's pause
    # while brand-new code is still unverified. --no-cron leaves whatever cron
    # state the operator set; enable it yourself once test-config is green.
    if _swatter_cron_should_install; then
        install -m 0644 "${SRC}/install/swatter.cron" /etc/cron.d/swatter
        _swatter_report_cron_from_conf /etc/swatter/swatter.conf > /etc/cron.d/swatter-report
        chmod 0644 /etc/cron.d/swatter-report
    else
        echo "skipping cron install (--no-cron): neither /etc/cron.d/swatter nor"
        echo "  /etc/cron.d/swatter-report were written. Re-run 'install.sh local'"
        echo "  (without --no-cron) once test-config is green to install both."
    fi
    install -m 0644 "${SRC}"/install/swatter.logrotate /etc/logrotate.d/swatter

    echo "fetching Cloudflare ranges + intel feeds ..."
    /usr/local/bin/swatter refresh-feeds || echo "  (refresh-feeds had warnings; check connectivity)"
    echo
    /usr/local/bin/swatter test-config
    echo

    # If the operator chose the ipset backend, set up the kernel sets now.
    local _backend=""
    _backend="$(bash -c 'source /etc/swatter/swatter.conf 2>/dev/null; echo "${DIRECT_BACKEND:-csf}"' 2>/dev/null || echo "csf")"
    if [[ "${_backend}" == "ipset" ]]; then
        echo "DIRECT_BACKEND=ipset detected — running setup-ipset ..."
        /usr/local/bin/swatter setup-ipset || echo "  (setup-ipset had errors; install ipset/iptables and re-run)"
        local ipsf
        ipsf="$(bash -c 'source /etc/swatter/swatter.conf 2>/dev/null; echo "${IPSET_SAVE_FILE:-/etc/swatter/ipset.save}"')"
        echo "  NOTE: ipset rules are not persistent across reboots."
        echo "  Add the following to /etc/rc.local (or an equivalent boot hook) to restore them:"
        echo "    ipset restore < \"${ipsf}\""
        echo
    fi

    # Wire origin-lock boot/reload persistence (csfpre on CSF hosts, systemd
    # oneshot otherwise). Does not arm the lock — that stays operator-driven.
    _install_origin_lock_persistence
    echo

    echo
    echo "======================================================================"
    echo " Installed — Swatter is in REPORT mode. It will NOT block anything yet."
    echo "======================================================================"
    echo
    echo " DON'T ENFORCE BLIND. Run report mode for a day or so first, and read"
    echo " what it WOULD have done before you let it touch the firewall:"
    echo
    echo "     swatter scan --dry-run         # score now, decide nothing"
    echo "     swatter report 24h --print     # see the would-be blocks + exemptions"
    echo
    echo " Check the report for any legitimate IP (your office, a monitor, an API"
    echo " client, a good crawler) that scored high — allowlist it BEFORE enforcing."
    echo
    echo " Only once the report looks right, flip to enforcing:"
    echo "     set SWATTER_MODE=\"enforce\" in /etc/swatter/swatter.conf"
    echo "======================================================================"
}

# Pure — no ssh, no filesystem — so tests can drive the real remote command
# line directly. SWATTER_INSTALL_CRON is set/exported in THIS process by
# main(), but that export dies at the ssh boundary: the remote shell never
# inherits it. Without forwarding the flag onto the remote command line,
# `--no-cron remote <dest>` would parse cleanly and still re-arm cron on the
# target — silently defeating the flag on exactly the path it exists for
# (pushing a hold-respecting deploy to a remote host).
_remote_install_cmd() {
    local cmd="bash /tmp/swatter-src/install/install.sh local"
    [[ "${SWATTER_INSTALL_CRON:-1}" == "0" ]] && cmd+=" --no-cron"
    echo "$cmd"
}

_install_remote() {
    local dest="$1"
    [[ -n "$dest" ]] || { echo "usage: install.sh remote <ssh-destination>" >&2; exit 1; }
    echo "staging Swatter to ${dest}:/tmp/swatter-src ..."
    ssh "$dest" 'rm -rf /tmp/swatter-src && mkdir -p /tmp/swatter-src'
    # Copy the tree (bin, lib, config, install).
    scp -q -r "${SRC}/bin" "${SRC}/lib" "${SRC}/config" "${SRC}/install" "${dest}:/tmp/swatter-src/"
    # Integrity check: compute tree hash locally and remotely; abort on mismatch (detects corruption/tampering during transfer).
    local local_hash
    # -L: scp materializes symlinks as regular files remotely, so the local
    # walk must hash targets too or the hashes can never agree.
    local_hash="$(cd "${SRC}" && find -L bin lib config install -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)"
    echo "  local tree hash: ${local_hash}"
    local remote_hash
    remote_hash="$(ssh "$dest" 'cd /tmp/swatter-src && find bin lib config install -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum | cut -d" " -f1')" || remote_hash="error"
    echo "  remote tree hash: ${remote_hash}"
    if [[ "${local_hash}" != "${remote_hash}" ]]; then
        echo "ERROR: tree hash mismatch after scp — aborting remote install for safety" >&2
        ssh "$dest" 'rm -rf /tmp/swatter-src' || true
        exit 1
    fi
    echo "running local install on ${dest} ..."
    ssh "$dest" "$(_remote_install_cmd)"
    ssh "$dest" 'rm -rf /tmp/swatter-src'
}

main() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-cron) SWATTER_INSTALL_CRON=0; export SWATTER_INSTALL_CRON; shift ;;
            *) args+=("$1"); shift ;;
        esac
    done
    # Rebuild "$@" from the leftover positionals. NOT `set -- "${args[@]}"`
    # unguarded: under set -u, bash < 4.4 (RHEL 7's 4.2, macOS's stock
    # /bin/bash 3.2) raises "unbound variable" expanding an EMPTY array with
    # "${arr[@]}" — verified live on both 3.2.57 and 5.3.15. A tempting fix is
    # `"${args[@]:-}"`, but that's a sharp edge of its own: for an empty array
    # the ":-" default substitutes ONE empty-string word, not zero words, so
    # $#=1 and $1="" rather than truly unset — it happens to still reach
    # usage below only because the case matches on "${1:-}" (which treats
    # unset and "" alike), and would silently misbehave the moment anything
    # here relied on $# instead. The size check below sidesteps both bugs:
    # genuinely zero args when the array is empty, on every bash tested.
    if (( ${#args[@]} )); then set -- "${args[@]}"; else set --; fi
    case "${1:-}" in
        local)  _install_local ;;
        remote) _install_remote "${2:-}" ;;
        *) echo "usage: install.sh {local | remote <ssh-destination>} [--no-cron]" >&2; exit 2 ;;
    esac
}
(( SWATTER_INSTALL_SOURCE_ONLY )) || main "$@"
