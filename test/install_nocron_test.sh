#!/usr/bin/env bash
# test/install_nocron_test.sh — --no-cron must suppress the cron install so a
# maintenance hold survives the upgrade, and must not disturb the arg parsing
# for `local` / `remote <dest>`.
#
# Drives the REAL code, not a grep of the source text, for everything that can
# be driven without root or touching the real filesystem:
#   - _swatter_cron_should_install is the actual predicate _install_local
#     branches on (extracted as a pure, no-filesystem function precisely so it
#     is testable). We call it directly with SWATTER_INSTALL_CRON set/unset
#     and assert its real return code — not a grep of an "if" line.
#   - main()'s arg-parsing/dispatch is exercised by sourcing install.sh with
#     --source-only (skips `set -euo pipefail` and the auto-run of main "$@"),
#     then overriding _install_local/_install_remote with stubs and calling
#     the real main() with various argv shapes — including the zero-args and
#     --no-cron-only cases the brief flagged as a sharp edge for
#     `set -- "${args[@]:-}"` under `set -u`.
#   - _remote_install_cmd is the actual remote ssh command line, exercised
#     directly (no ssh, no filesystem) — this is what catches the flag
#     failing to cross the ssh boundary (a real bug an adversarial review
#     found in an earlier draft; see section 3 below).
# One structural grep remains (cron-wired, below): _install_local itself needs
# root and writes real /etc paths (install.sh has no override hook for those,
# same constraint test/report_cron_test.sh works within), so — as that
# existing test does for the report-cron wiring — we confirm the predicate is
# actually the thing gating the real install line, rather than re-deriving
# root privileges just to prove it.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-nocron.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Source install.sh for its functions without running main or touching /etc.
# shellcheck disable=SC1091
source "${ROOT}/install/install.sh" --source-only 2>/dev/null || true

# ===========================================================================
# 1. _swatter_cron_should_install: the actual predicate, exercised directly
#    (no root, no filesystem — its real return code, not a text match).
# ===========================================================================
unset SWATTER_INSTALL_CRON
if _swatter_cron_should_install; then ok=yes; else ok=no; fi
check default-enables-cron   "$ok" "yes"

SWATTER_INSTALL_CRON=0
if _swatter_cron_should_install; then ok=yes; else ok=no; fi
check nocron-disables-cron   "$ok" "no"
unset SWATTER_INSTALL_CRON

SWATTER_INSTALL_CRON=1
if _swatter_cron_should_install; then ok=yes; else ok=no; fi
check explicit-1-enables-cron "$ok" "yes"
unset SWATTER_INSTALL_CRON

# Structural check that this predicate — not some other condition — is what
# actually gates the cron install line in _install_local. _install_local
# itself needs root and writes real /etc paths with no override hook (the
# same constraint test/report_cron_test.sh works within for the report-cron
# wiring), so this one assertion stays text-based; everything behavioral
# above and below is driven for real.
install_src="$(sed -n '/^_install_local()/,/^}/p' "${ROOT}/install/install.sh")"
check cron-gated-by-predicate \
  "$(printf '%s\n' "$install_src" | grep -c 'if _swatter_cron_should_install; then')" "1"
check cron-install-line-present \
  "$(printf '%s\n' "$install_src" | grep -c 'install -m 0644 "\${SRC}/install/swatter.cron" /etc/cron.d/swatter$')" "1"

# ===========================================================================
# 2. main(): stub the two real installers so we can drive the actual
#    dispatch/arg-parsing without root or ssh.
# ===========================================================================
_install_local()  { echo "CALLED_LOCAL cron=${SWATTER_INSTALL_CRON:-unset}"; }
_install_remote() { echo "CALLED_REMOTE arg1=<$1>"; }

# No args at all -> usage on stderr, exit 2, neither installer called.
out="$(main 2>&1)"; rc=$?
check noargs-usage   "$(echo "$out" | grep -c '^usage:')" "1"
check noargs-exit     "$rc" "2"
check noargs-no-call  "$(echo "$out" | grep -c CALLED_)" "0"

# --no-cron with no mode positional -> STILL usage (flag alone is not a mode).
out="$(main --no-cron 2>&1)"; rc=$?
check nocronflag-only-usage  "$(echo "$out" | grep -c '^usage:')" "1"
check nocronflag-only-exit    "$rc" "2"

# `local` alone -> real local installer called, cron flag unset (defaults on).
out="$(main local 2>&1)"
check local-called       "$out" "CALLED_LOCAL cron=unset"

# `--no-cron local` -> local installer called, SWATTER_INSTALL_CRON=0 seen.
out="$(main --no-cron local 2>&1)"
check nocron-local-called "$out" "CALLED_LOCAL cron=0"

# `remote root@host` -> the destination arrives at $2 intact, not swallowed
# by the args-array rebuild.
out="$(main remote root@host 2>&1)"
check remote-arg-intact  "$out" "CALLED_REMOTE arg1=<root@host>"

# `--no-cron remote root@host` -> flag consumed, destination still intact
# regardless of flag position.
out="$(main --no-cron remote root@host 2>&1)"
check nocron-remote-arg-intact "$out" "CALLED_REMOTE arg1=<root@host>"

# `local --no-cron` (flag AFTER the mode) -> still recognized: "any position".
out="$(main local --no-cron 2>&1)"
check nocron-after-mode-local "$out" "CALLED_LOCAL cron=0"

# `remote root@host --no-cron` (flag after the dest) -> still recognized, and
# does not get swallowed into $2.
_install_remote() { echo "CALLED_REMOTE arg1=<$1> cron=${SWATTER_INSTALL_CRON:-unset}"; }
out="$(main remote root@host --no-cron 2>&1)"
check nocron-after-mode-remote "$out" "CALLED_REMOTE arg1=<root@host> cron=0"

# ===========================================================================
# 3. _remote_install_cmd: the actual remote command line, exercised directly
#    (no ssh, no filesystem). This is the fix for a real bug Grok's review
#    caught: `main()` exporting SWATTER_INSTALL_CRON does nothing across the
#    ssh boundary — without this, `--no-cron remote <dest>` parsed cleanly
#    and still re-armed cron on the TARGET, defeating the flag on exactly the
#    path it exists for (pushing a hold-respecting deploy to a remote host).
# ===========================================================================
unset SWATTER_INSTALL_CRON
check remote-cmd-default-no-flag \
  "$(_remote_install_cmd | grep -c -- '--no-cron')" "0"

SWATTER_INSTALL_CRON=0
check remote-cmd-forwards-nocron \
  "$(_remote_install_cmd)" "bash /tmp/swatter-src/install/install.sh local --no-cron"
unset SWATTER_INSTALL_CRON

# Structural check that _install_remote actually USES the forwarding helper
# for its local-install ssh call (not some other hardcoded command). Same
# root-required constraint as section 1: _install_remote does real ssh/scp
# and a live tree-hash integrity check with no override hooks, so full
# end-to-end execution isn't driven here — but the command-construction logic
# that mattered for the bug (the forwarding itself) is, in full, above.
remote_src="$(sed -n '/^_install_remote()/,/^}/p' "${ROOT}/install/install.sh")"
check remote-wired-to-helper \
  "$(printf '%s\n' "$remote_src" | grep -c 'ssh "\$dest" "\$(_remote_install_cmd)"')" "1"

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
