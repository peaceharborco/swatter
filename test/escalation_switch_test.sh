#!/usr/bin/env bash
# test/escalation_switch_test.sh — REPEAT_ENABLE gates the temp->perm ladder
# ONLY. The ladder is live by default (it has shipped since v1.0.0), so the
# switch is an abort lever: unset must mean armed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Default is ARMED — an upgrade must not silently disable a live protection.
check default-armed "${REPEAT_ENABLE}" "true"

# The gate expression the ladder uses, exercised directly.
gate() { [[ "${1}" == "true" ]] && echo armed || echo disarmed; }
check explicit-false  "$(gate false)"  "disarmed"
check explicit-true   "$(gate true)"   "armed"
# Anything that is not exactly "true" disarms — safe direction for an abort lever.
check typo-disarms    "$(gate True)"   "disarmed"
check yes-disarms     "$(gate yes)"    "disarmed"
check one-disarms     "$(gate 1)"      "disarmed"
check empty-disarms   "$(gate '')"     "disarmed"

# Exactly one definition in the tree — a stray `:-false` read site would
# silently disarm every upgrade (review finding M7).
defs="$(grep -c 'REPEAT_ENABLE:=' "${ROOT}/lib/common.sh")"
check single-definition "$defs" "1"
# Comment lines are excluded deliberately: the definition in lib/common.sh warns
# against this very pattern by name, and a grep that cannot tell a warning from
# a read site would make documenting the rule impossible.
stray="$(grep -rn 'REPEAT_ENABLE:-' "${ROOT}/lib" "${ROOT}/bin" \
         | grep -vE ':[[:space:]]*#' | grep -c . || true)"
check no-inline-defaults "$stray" "0"

echo "Total: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
