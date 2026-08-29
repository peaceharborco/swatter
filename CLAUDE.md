# Swatter — repo rules

Adds to `~/Developer/CLAUDE.md`; never overrides it.

## /grok review is a GATE on release and deploy, not a judgement call

**Run `/grok` over the actual diff before `install/release.sh` and before any
surgical-scp to prod. Not after. Not "if it looks risky."** The gate applies to
every code change that reaches the host, including a one-file fix-forward on top
of a change that was already reviewed.

This is written down because it was skipped once, on 2026-08-12, for v2.15.0 —
tests green, dry-run clean, reviewed design, deployed. The review afterwards found
a **Blocker**: an unvalidated numeric knob in an arithmetic context aborts the
whole nightly report under `set -u`, so a single config typo would have produced
no digest, no RED grade and **no SMS** on exactly the night an outage existed. It
also found a timezone bug that made the new lookup match nothing at all on any
host not already on UTC. Neither was reachable by the test suite, because the
tests were written by the same author as the code and shared its blind spots. That
is the whole reason a second model reads it.

Sequence, every time:

1. `make test` — under BOTH awk dialects (`PATH` shim gawk as `awk`) and a
   non-UTC `TZ`. Green is necessary, never sufficient.
2. **`/grok` over the range that is about to ship.** Fold in the real findings;
   state plainly which you decline and why.
3. Dry-run against real prod data from a temp dir — read-only, nothing installed.
   Fixtures do not contain the shapes that break things; production does. Every
   defect in the 2.14/2.15 series was found this way or by review, none by tests.
4. Release, then deploy, then verify installed files sha256-match the tag.

If a deploy is genuinely urgent and the review has to come after, **say so out
loud and say why**, and run it immediately after. Silence is what made this a rule.

## Deploys

Surgical-scp only — never `install/install.sh remote` (it clobbers the cron
timing fix and rewrites the origin-lock csfpre hook). Stage from the LIVE install,
overwrite the changed files there, validate `test-config` + `scan --dry-run`
against the real conf, hold cron **outside** `/etc/cron.d` (a backup left inside
it is live cron), install, restore cron, then sha-verify against the release tag.

## Config knobs

Any new numeric knob must go through the same validation as its siblings in
`_errors_validate_fatal_scanner` (`*[!0-9]*|''|??????*` → warn + default). Bash
re-resolves a non-numeric string in an arithmetic context as a variable name, and
under `set -u` that aborts the run; a crafted value executes via an array
subscript. Note an environment variable does **not** reach that validation —
`lib/common.sh` assigns defaults unconditionally — so the real vector is the conf
file. Test it with `SWATTER_CONF=<copy>`, not with `VAR=x swatter …`.

## Fail direction

Everything in the errors/alerting plane fails toward the LOUDER reading. A lookup
that could not read its evidence must never report absence, and no signal may turn
a RED green — that is the defect the fan-out gate exists to prevent.


## Grok Bot opportunities

Grok Bot.app is the cloud teammate (persistent VM, browser, routines). This TUI
still owns code, git, `pass-cli`, `cf` writes, and deploys. Tree-wide trigger
and hard nos: `~/Developer/CLAUDE.md` §"Grok Bot".

When the same non-code ask happens twice, name the Bot (or an on-machine script)
instead of silently becoming the routine.

**This repo:**

- Read-only visual of the nightly digest / SMS path *after* this TUI has already produced it — "did the mail/SMS actually land?"
- AbuseIPDB / GreyNoise / HoneyPot dashboard glances when a feed looks stale. Return links, do not tune the scanner.
- Never: surgical-scp, `install/release.sh`, live `swatter.conf` edits, or CSF/origin-lock changes. Those stay on-machine and gated.
