# Contributing to Swatter

Thanks for your interest in improving Swatter. It's a small, dependency-light
project (Bash + awk), and the bar for a change is simple: **the tests and the
linter stay green, and the diff is focused.**

## Prerequisites

- `bash` (4+)
- `gawk` (the scoring engine uses GNU awk features)
- `shellcheck`
- `jq` and `curl` are runtime-optional (intel / Cloudflare plane); not needed to
  run the test suite.

On Debian/Ubuntu: `sudo apt-get install -y gawk shellcheck`.

## Running the tests

The same two commands CI runs — run both before opening a PR:

```bash
# 1. Lint (must be clean at error severity)
shellcheck --severity=error bin/swatter lib/*.sh install/*.sh test/*.sh

# 2. Test suite
make test
```

Individual test files under `test/` are plain executable scripts and can be run
directly, e.g. `bash test/score_test.sh`. Each `lib/` module has a matching
`*_test.sh`.

## Pull-request checklist

- [ ] `shellcheck --severity=error …` passes (no error-level findings).
- [ ] `make test` passes.
- [ ] New behavior ships with a test in the matching `test/*.sh`.
- [ ] The change is focused — one logical concern per PR.
- [ ] Docs updated if behavior or config changed (README, and a `CHANGELOG.md`
      entry under `## [Unreleased]`).

## Commit messages

Follow the existing convention — a [Conventional Commits]-style prefix scoped to
the area touched:

```
feat(intel): add <provider> reputation lookup
fix(classify): bound the direct-evidence set to the scoring window
docs(readme): clarify the ipset backend
```

Common scopes: `intel`, `classify`, `score`, `block`, `report`, `notify`,
`allowlist`, `cf`, `install`, `docs`.

## Code style

- Match the surrounding code: `set -u`-safe, quoted expansions, `local` for
  function variables, temp files via `mktemp` with a `trap` cleanup.
- Prefer small, single-purpose functions in the relevant `lib/*.sh` module; the
  CLI in `bin/swatter` should stay a thin dispatcher.
- Keep it portable — no GNU-only tools beyond `gawk`/`date -d` where already used.

## Never commit secrets or proprietary data

Swatter is a public project. **Do not commit, in code, tests, comments, examples,
or docs:**

- Real server IP addresses or hostnames, or SSH aliases.
- Real domain names of any site you operate or host (use `example.com`,
  `203.0.113.0/24`, and friends).
- API keys, tokens, or passwords — even "expired" ones. Configure them only in
  your own `/etc/swatter/swatter.conf`, which is never tracked.
- Absolute account paths (`/home/<account>/…`) or other deployment specifics.

Example configuration belongs in the `*.example` files. A `gitleaks` scan runs in
CI as a backstop, but the first line of defense is you.

## Reporting security issues

Please do **not** file security problems as public issues — see
[SECURITY.md](SECURITY.md) for private reporting.

[Conventional Commits]: https://www.conventionalcommits.org/
