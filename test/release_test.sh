#!/usr/bin/env bash
# test/release_test.sh — version math for install/release.sh (_next_version).
# The orchestration (git/gh/glab) is side-effecting and verified by --dry-run;
# this covers the one pure function whose silent miscompute would mis-tag a
# release. Run: bash test/release_test.sh

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"

# Source without executing main().
source "${ROOT}/install/release.sh"

PASS=0; FAIL=0
assert_eq() { [[ "$2" == "$3" ]] && { printf 'PASS  %s\n' "$1"; PASS=$((PASS+1)); } \
                                 || { printf 'FAIL  %s — got "%s" want "%s"\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); }; }
assert_fail() { if "$@" >/dev/null 2>&1; then printf 'FAIL  rejects: %s\n' "$*"; FAIL=$((FAIL+1)); \
                else printf 'PASS  rejects bad input\n'; PASS=$((PASS+1)); fi; }

assert_eq "patch bumps Z"          "$(_next_version 1.2.2 patch)"  "1.2.3"
assert_eq "minor bumps Y, resets Z" "$(_next_version 1.2.2 minor)" "1.3.0"
assert_eq "major bumps X, resets Y.Z" "$(_next_version 1.2.2 major)" "2.0.0"
assert_eq "explicit version passthrough" "$(_next_version 1.2.2 1.5.9)" "1.5.9"
assert_eq "patch from .9 carries"  "$(_next_version 1.2.9 patch)"  "1.2.10"
assert_eq "from 0.0.0"             "$(_next_version 0.0.0 minor)"  "0.1.0"

assert_fail _next_version 1.2.2 sideways      # unknown bump word
assert_fail _next_version not-a-version patch # malformed current

# The test gate must run each test with stdin CLOSED (</dev/null): a test — or
# a mock inside one — that reads stdin would otherwise block the release
# forever when release.sh is driven from a terminal or pipeline (observed
# 2026-07-01: a curl mock's `cat` hung the v2.5.0 dry-run). The fixture test
# passes ONLY if its stdin is /dev/null; we drive the gate with /dev/zero so
# plain inheritance would fail it.
GATEDIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-relgate.XXXXXX")"
trap 'rm -rf "$GATEDIR" "${WF:-}"' EXIT
cat > "$GATEDIR/stdin_guard_test.sh" <<'EOF'
[[ /dev/stdin -ef /dev/null ]] || exit 1
exit 0
EOF
_release_test_gate "$GATEDIR" </dev/zero >/dev/null 2>&1
assert_eq "gate closes each test's stdin" "$?" "0"
# ...and a failing test still fails the gate.
cat > "$GATEDIR/alwaysfail_test.sh" <<'EOF'
exit 1
EOF
_release_test_gate "$GATEDIR" </dev/null >/dev/null 2>&1
assert_eq "gate propagates test failure" "$?" "1"


# --- CI gate: the hole that let v2.15.0 and v2.15.1 ship red -----------------
# release.sh used to gate on its own test suite only. That suite does not run the
# linter, so a lint-only CI failure could not stop a release.

WF="$(mktemp -d "${TMPDIR:-/tmp}/swatter-relwf.XXXXXX")"

# ---- _ci_lint_cmd: read from the workflow, never duplicated ----
cat > "$WF/ci.yml" <<'EOF'
name: CI
jobs:
  test:
    steps:
      - name: Shellcheck (error severity)
        run: shellcheck --severity=error bin/swatter lib/*.sh
      - name: Full test suite
        run: make test
EOF
assert_eq "lint cmd read from workflow (own-line run:)" \
    "$(_ci_lint_cmd "$WF/ci.yml")" "shellcheck --severity=error bin/swatter lib/*.sh"
# The inline `- run:` shape is equally legal YAML and must also parse, or a
# reformat of ci.yml silently downgrades the gate to UNVERIFIED forever.
printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: shellcheck --severity=error x.sh\n' > "$WF/inline.yml"
assert_eq "lint cmd read from workflow (inline - run:)" \
    "$(_ci_lint_cmd "$WF/inline.yml")" "shellcheck --severity=error x.sh"

# Canary on the REAL workflow. Non-empty is not enough: `run: shellcheck --version`
# is non-empty and lints nothing, so assert the actual severity flag and that it
# names files. If ci.yml legitimately changes shape, update this deliberately.
REAL_CMD="$(_ci_lint_cmd "${ROOT}/.github/workflows/ci.yml")"
assert_eq "real workflow: lint cmd is a real shellcheck run" \
    "$([[ "$REAL_CMD" == shellcheck*--severity=error*.sh* ]] && echo yes)" "yes"
assert_eq "real workflow: lint cmd covers install/ (release.sh lints itself)" \
    "$([[ "$REAL_CMD" == *install/*.sh* ]] && echo yes)" "yes"

# ---- _release_lint_gate: 90 means UNVERIFIED, never "clean" ----
printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: make test\n' > "$WF/nolint.yml"
_release_lint_gate "$WF/nolint.yml" >/dev/null 2>&1
assert_eq "no lint step => 90 (unverified)"    "$?" "90"
_release_lint_gate "$WF/absent.yml" >/dev/null 2>&1
assert_eq "absent workflow => 90 (unverified)" "$?" "90"
printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: make test\n      - run: shellcheck-not-a-real-binary x.sh\n' > "$WF/notsc.yml"
_release_lint_gate "$WF/notsc.yml" >/dev/null 2>&1
assert_eq "non-shellcheck step => 90"          "$?" "90"

if command -v shellcheck >/dev/null; then
    # A lint command that cannot open its file must NOT be reported as
    # unverified. shellcheck exits 2 there, which is exactly why the
    # cannot-verify sentinel is 90 and not 2.
    printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: shellcheck --severity=error /nonexistent-xyz.sh\n' > "$WF/broken.yml"
    _release_lint_gate "$WF/broken.yml" >/dev/null 2>&1; rc=$?
    assert_eq "broken lint cmd is a FAILURE, not unverified" \
        "$([[ "$rc" != 0 && "$rc" != 90 ]] && echo yes)" "yes"
    # Real files with a real error must fail the gate.
    printf 'if then fi\n' > "$WF/bad.sh"
    printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: shellcheck --severity=error %s/bad.sh\n' "$WF" > "$WF/failing.yml"
    _release_lint_gate "$WF/failing.yml" >/dev/null 2>&1; rc=$?
    assert_eq "failing lint fails the gate" "$([[ "$rc" != 0 && "$rc" != 90 ]] && echo yes)" "yes"
    # The shipped tree must be clean under the command CI actually runs.
    ( cd "$ROOT" && _release_lint_gate >/dev/null 2>&1 )
    assert_eq "repo is clean under CI's own lint command" "$?" "0"
    # INJECTION: a `; payload` in ci.yml must reach shellcheck as arguments, never
    # run. An earlier revision used eval and a reviewer proved this executed.
    CANARY="$WF/pwned"
    printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: shellcheck --severity=error /dev/null; touch %s\n' "$CANARY" > "$WF/evil.yml"
    _release_lint_gate "$WF/evil.yml" >/dev/null 2>&1
    assert_eq "semicolon payload not executed"  "$([[ -e "$CANARY" ]] && echo PWNED || echo safe)" "safe"
    CANARY2="$WF/pwned2"
    printf 'name: CI\njobs:\n  t:\n    steps:\n      - run: shellcheck --severity=error $(touch %s)\n' "$CANARY2" > "$WF/evil2.yml"
    _release_lint_gate "$WF/evil2.yml" >/dev/null 2>&1
    assert_eq "command-substitution payload not executed" "$([[ -e "$CANARY2" ]] && echo PWNED || echo safe)" "safe"
else
    printf 'FAIL  shellcheck absent — lint-gate cases could not run\n'; FAIL=$((FAIL+1))
fi

# ---- _ci_commit_state: every branch, and fail-closed on the unknowns ----
# The stub stands in for `gh api ... --jq ...`, so it returns the classification
# the jq program would produce. The jq program itself is exercised separately
# below against real JSON.
# _ci_commit_state must FAIL CLOSED on anything that is not a well-formed answer.
# gh now returns "failed=..;pending=..;present=.." and the bash half classifies.
gh() { echo "HTTP 403: rate limit exceeded" >&2; return 1; }
st="$(_ci_commit_state abc)"
assert_eq "gh failure => transport, not none" "${st%%:*}" "transport"
assert_eq "transport message carries gh stderr" "$([[ "$st" == *"403"* ]] && echo yes)" "yes"
gh() { printf ''; }
assert_eq "empty output => transport" "$(_ci_commit_state abc | cut -d: -f1)" "transport"
gh() { printf 'green'; }
assert_eq "a bare word is NOT a valid answer any more" "$(_ci_commit_state abc | cut -d: -f1)" "transport"
gh() { printf 'truncated:9 checks, only 1 read'; }
assert_eq "truncated => transport (never classified)" "$(_ci_commit_state abc | cut -d: -f1)" "transport"
# The sha must actually reach gh; verifying a different commit is the bug a gate
# must not have.
gh() { printf '%s' "$*" | grep -q "deadbeefcafe" && printf 'failed=;pending=;present=gitleaks,hub,test' || printf 'WRONG-SHA'; }
assert_eq "the requested sha is passed to gh" "$(_ci_commit_state deadbeefcafe)" "green"
unset -f gh; unset st

# ---- the jq program, against real API-shaped JSON ----
if command -v jq >/dev/null; then
    # Extract the REAL jq program out of release.sh rather than keeping a second
    # copy that can drift. Bounded by the --jq opener and the `' 2>&1)"` closer,
    # not by a keyword: an earlier version keyed on the program's last word and
    # silently extracted nothing the moment the classifier was rewritten, which
    # turned every assertion below into a vacuous pass against "".
    JQ_PROG="$(sed -n "/^_ci_commit_state()/,/^}/p" "${ROOT}/install/release.sh" \
               | sed -n "/--jq '/,/' 2>&1)\"\$/p" | sed "s/.*--jq '//; s/' 2>&1)\"\$//")"
    # Guard the guard: if extraction breaks again, fail loudly instead of quietly
    # asserting against an empty program.
    assert_eq "jq program extracted from release.sh" \
        "$([[ "$JQ_PROG" == *"present="* && "$JQ_PROG" == *"group_by"* ]] && echo yes)" "yes"
    jqc() { printf '%s' "$1" | jq -r "$JQ_PROG" 2>/dev/null; }
    assert_eq "jq: no checks => empty present" \
        "$(jqc '{"total_count":0,"check_runs":[]}')" "failed=;pending=;present="
    assert_eq "jq: all success => green" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"test","status":"completed","conclusion":"success","started_at":"1"},{"name":"hub","status":"completed","conclusion":"success","started_at":"1"}]}')" "failed=;pending=;present=hub,test"
    assert_eq "jq: skipped/neutral count as acceptable" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"a","status":"completed","conclusion":"skipped","started_at":"1"},{"name":"b","status":"completed","conclusion":"neutral","started_at":"1"}]}')" "failed=;pending=;present=a,b"
    assert_eq "jq: a failure names the check" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"test","status":"completed","conclusion":"failure","started_at":"1"},{"name":"hub","status":"completed","conclusion":"success","started_at":"1"}]}')" "failed=test;pending=;present=hub,test"
    assert_eq "jq: an unfinished check is pending" \
        "$(jqc '{"total_count":1,"check_runs":[{"name":"test","status":"in_progress","conclusion":null,"started_at":"1"}]}')" "failed=;pending=test;present=test"
    # A re-run leaves the OLD conclusion in the list. Latest-per-name must win, or
    # a commit that was re-run green false-blocks — which teaches the override.
    assert_eq "jq: re-run green beats the stale failure" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"gitleaks","status":"completed","conclusion":"failure","started_at":"1"},{"name":"gitleaks","status":"completed","conclusion":"success","started_at":"2"}]}')" "failed=;pending=;present=gitleaks"
    assert_eq "jq: re-run red beats a stale success" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"gitleaks","status":"completed","conclusion":"success","started_at":"1"},{"name":"gitleaks","status":"completed","conclusion":"failure","started_at":"2"}]}')" "failed=gitleaks;pending=;present=gitleaks"
    # Every non-success conclusion must block. GitHub can emit cancelled,
    # timed_out, action_required, stale, and a completed run with a NULL
    # conclusion; none of those is "green".
    for c in cancelled timed_out action_required stale; do
        assert_eq "jq: ${c} blocks" \
            "$(jqc "{\"total_count\":1,\"check_runs\":[{\"name\":\"a\",\"status\":\"completed\",\"conclusion\":\"${c}\",\"started_at\":\"1\"}]}")" "failed=a;pending=;present=a"
    done
    assert_eq "jq: completed with null conclusion blocks" \
        "$(jqc '{"total_count":1,"check_runs":[{"name":"a","status":"completed","conclusion":null,"started_at":"1"}]}')" "failed=a;pending=;present=a"
    # A TIE on started_at must fail closed. Plain max_by() returns the LAST
    # element, so an equal-timestamped success could otherwise mask a failure.
    assert_eq "jq: tie failure+success => failed" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"a","status":"completed","conclusion":"failure","started_at":"5"},{"name":"a","status":"completed","conclusion":"success","started_at":"5"}]}')" "failed=a;pending=;present=a"
    assert_eq "jq: tie success+failure (reversed) => failed" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"a","status":"completed","conclusion":"success","started_at":"5"},{"name":"a","status":"completed","conclusion":"failure","started_at":"5"}]}')" "failed=a;pending=;present=a"
    assert_eq "jq: tie pending+success => pending" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"a","status":"in_progress","conclusion":null,"started_at":"5"},{"name":"a","status":"completed","conclusion":"success","started_at":"5"}]}')" "failed=;pending=a;present=a"
    # A PARTIAL list cannot be classified: the unread checks might be red. gh
    # applies --jq per page in --paginate mode, so this is the guard against
    # ever silently classifying page 1 of N.
    # A name with ANY unfinished run is pending regardless of timestamps: GitHub
    # leaves started_at null until a run starts, and jq's max prefers a real
    # timestamp over null, so a queued re-run used to lose to its own older
    # success and the commit read green.
    assert_eq "jq: queued re-run (null started_at) => pending" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"test","status":"completed","conclusion":"success","started_at":"1"},{"name":"test","status":"queued","conclusion":null,"started_at":null}]}' | grep -c 'pending=test')" "1"
    # Cross-name: a known failure must be reported even while something else runs.
    assert_eq "jq: failed+pending reports BOTH" \
        "$(jqc '{"total_count":2,"check_runs":[{"name":"test","status":"completed","conclusion":"failure","started_at":"1"},{"name":"hub","status":"in_progress","conclusion":null,"started_at":"1"}]}')" "failed=test;pending=hub;present=hub,test"
    assert_eq "jq: truncated list is not classified" \
        "$(jqc '{"total_count":9,"check_runs":[{"name":"a","status":"completed","conclusion":"success","started_at":"1"}]}' | cut -d: -f1)" "truncated"
    unset -f jqc
else
    printf 'FAIL  jq absent — the classifier program could not be tested\n'; FAIL=$((FAIL+1))
fi

# ---- main() must handle every state the classifier can emit ----
# An inverted or missing case arm is invisible to the helper tests above, so
# assert the wiring by inspection: each state has an arm, and only red/pending
# are allowed to advertise the override.
MAIN_CASE="$(sed -n '/ci="\$(_ci_commit_state/,/^    fi$/p' "${ROOT}/install/release.sh")"
for st in "green)" "failed:\\*)" "pending:\\*)" "missing:\\*)" "none)" "transport:\\*)"; do
    assert_eq "main handles ${st%%\\\\*)*}" \
        "$(printf '%s' "$MAIN_CASE" | grep -cE "^[[:space:]]*${st}" | head -1)" "1"
done

# The override must be OFFERED for a red or unfinished build and NOT offered when
# the answer is merely unknown. Assert BOTH directions: an earlier version of this
# test grepped for a phrase ("override with --skip-ci-check") that appears nowhere
# in the script, so it passed no matter what the arms said.
arm() { printf '%s' "$MAIN_CASE" | sed -n "/^[[:space:]]*$1/,/;;/p"; }
OFFER='(--skip-ci-check'
assert_eq "failed arm DOES offer the override" \
    "$(arm 'failed:\*)' | grep -cF "$OFFER")" "1"
assert_eq "pending arm DOES offer the override" \
    "$(arm 'pending:\*)' | grep -cF "$OFFER")" "1"
for a in 'transport:\*)' 'none)' 'missing:\*)'; do
    assert_eq "${a%%\\*)*} arm does NOT offer the override" \
        "$(arm "$a" | grep -cF "$OFFER")" "0"
done
assert_eq "transport arm actively warns against it" \
    "$(arm 'transport:\*)' | grep -c 'Do NOT reach for')" "1"
unset -f arm

# ---- expected-check derivation ----
# "every check I can see is green" is not "the suite ran": a job that never
# registers is absent, not failing, so one fast green job would otherwise release.
EXP="$(_ci_expected_checks "${ROOT}/.github/workflows" | tr '\n' ' ')"
for j in test hub gitleaks; do
    assert_eq "expected checks include ${j}" "$([[ " $EXP " == *" $j "* ]] && echo yes)" "yes"
done
assert_eq "trigger keys are not mistaken for jobs" \
    "$([[ " $EXP " != *" push "* && " $EXP " != *" pull_request "* ]] && echo yes)" "yes"
assert_eq "absent workflow dir => failure, not an empty pass" \
    "$(_ci_expected_checks "$WF/nope" >/dev/null 2>&1; echo $?)" "1"

# ---- the bash half of the classifier, over stubbed gh output ----
st_of() { gh() { printf '%s' "$1"; }; export -f gh 2>/dev/null; _ci_commit_state x; }
gh() { printf 'failed=;pending=;present=gitleaks,hub,test'; }
assert_eq "all expected present => green"        "$(_ci_commit_state x)" "green"
gh() { printf 'failed=;pending=;present=gitleaks'; }
assert_eq "one fast green job => missing, NOT green" "$(_ci_commit_state x)" "missing:hub,test"
gh() { printf 'failed=;pending=;present=test,hub'; }
assert_eq "gitleaks never ran => missing"        "$(_ci_commit_state x)" "missing:gitleaks"
gh() { printf 'failed=test;pending=hub;present=test,hub'; }
assert_eq "failed OUTRANKS pending"              "$(_ci_commit_state x)" "failed:test"
gh() { printf 'failed=;pending=test;present=test'; }
assert_eq "pending reported when nothing failed" "$(_ci_commit_state x)" "pending:test"
gh() { printf 'failed=;pending=;present='; }
assert_eq "no checks at all => none"             "$(_ci_commit_state x)" "none"
unset -f gh st_of


echo
echo "release: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
