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
#   install/release.sh <X.Y.Z | patch | minor | major> [--dry-run] [--notes-file F]
#
# Preconditions it enforces: run from the repo, on `main`, clean working tree,
# in sync with origin/main, target tag does not yet exist, SWATTER_VERSION ==
# target, and the test suite passes. --dry-run runs every read-only check and
# prints the actions it WOULD take, changing nothing.

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

# _gen_notes <prev-tag> <new-version> -> Markdown release notes on stdout.
_gen_notes() {
    local prev="$1" new="$2"
    printf '## Changes\n\n'
    git log --no-merges --pretty='- %s' "${prev}..HEAD"
    printf '\n**Full changelog:** https://github.com/%s/compare/%s...v%s\n' \
        "$GH_REPO" "$prev" "$new"
}

main() {
    local spec="" dry=0 notes_override=""
    while (( $# )); do
        case "$1" in
            --dry-run) dry=1 ;;
            --notes-file) notes_override="${2:-}"; shift ;;
            -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
            -*) die "unknown flag: $1" ;;
            *) [[ -z "$spec" ]] && spec="$1" || die "unexpected arg: $1" ;;
        esac
        shift
    done
    [[ -n "$spec" ]] || die "usage: release.sh <X.Y.Z|patch|minor|major> [--dry-run]"

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

    # Gate on green tests.
    info "running test suite"
    local t fails=0
    for t in test/*_test.sh; do
        [[ -e "$t" ]] || continue
        if bash "$t" >/dev/null 2>&1; then
            printf '    ok   %s\n' "$(basename "$t")"
        else
            printf '    FAIL %s\n' "$(basename "$t")"; fails=1
        fi
    done
    (( fails == 0 )) || die "tests failing — not releasing"

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
