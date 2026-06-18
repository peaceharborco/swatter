#!/usr/bin/env bash
# install/install.sh — deploy Swatter to a server.
#
# Two modes:
#   ./install.sh local            install on THIS machine (run as root)
#   ./install.sh remote <sshdest> push to a remote host over ssh+scp
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
#   /etc/cron.d/swatter                    (0644)
#   /etc/logrotate.d/swatter               (0644)
#   /var/lib/swatter, /var/log/swatter     (0750)
#
# After install: run `swatter refresh-feeds` then `swatter test-config`, leave it
# in report mode for ~a week, review `swatter top`, then set SWATTER_MODE=enforce.

set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd -- "${HERE}/.." && pwd)"

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
    [[ -f /etc/swatter/hosting-asns.txt ]] || install -m 0644 "${SRC}"/config/hosting-asns.txt /etc/swatter/hosting-asns.txt 2>/dev/null || true
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
    install -m 0644 "${SRC}"/install/swatter.cron      /etc/cron.d/swatter
    install -m 0644 "${SRC}"/install/swatter.logrotate /etc/logrotate.d/swatter

    echo "fetching Cloudflare ranges + intel feeds ..."
    /usr/local/bin/swatter refresh-feeds || echo "  (refresh-feeds had warnings; check connectivity)"
    echo
    /usr/local/bin/swatter test-config
    echo
    echo "Installed. Swatter is in REPORT mode (no blocks). Dry-run now:"
    echo "    swatter scan --dry-run"
    echo "When satisfied, set SWATTER_MODE=\"enforce\" in /etc/swatter/swatter.conf."
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
    ssh "$dest" 'bash /tmp/swatter-src/install/install.sh local'
    ssh "$dest" 'rm -rf /tmp/swatter-src'
}

main() {
    case "${1:-}" in
        local)  _install_local ;;
        remote) _install_remote "${2:-}" ;;
        *) echo "usage: install.sh {local | remote <ssh-destination>}" >&2; exit 2 ;;
    esac
}
main "$@"
