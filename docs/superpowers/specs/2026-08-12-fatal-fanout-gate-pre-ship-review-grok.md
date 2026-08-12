# Pre-ship review — fan-out gate branch (0ec7407..8cea51c)

Run 2026-08-12 before deploy, per `/grok`. Roster held one model family
(`grok-4.5` only), so independence came from two lenses rather than two models:
**pass A** correctness skeptic, **pass B** safety/edge-case red-teamer. Claude-side
`[code-review]`, `[security-review]` and `[gap]` passes ran inline over the same
range (the target is a committed range, so the skills could not bind to it).

Both Grok verdicts: **HOLD**.

## Blockers

### 1. A wrong-but-non-empty account tag collapsed the whole fleet onto one key
`[both]` — pass A M1, pass B B1, reproduced independently.

`lib/errors.sh` consulted the `/home<N>/<acct>/` path only when the tag was empty
or the literal `unknown`. Any other tag won permanently. Six accounts with correct
per-account paths and a constant `[php/webuser]` tag graded `GENUINE=0 SCANNER=6`
— the original false GREEN, intact, with the RED SMS suppressed. `docs/RUNBOOK.md`
claimed the path fallback covered exactly this case; it did not.

### 2. Path-derived identity took the FIRST `/home` match, so earlier text deflated it
`[pass-b]` — reproduced independently before reading the finding.

On a feed whose tag is not `php/<acct>` (apache vhost, fpm pool), a
`/home/<name>/` string appearing in the message ahead of the real path made every
row read the injected name as its account: six accounts → `fan=1` → `SCANNER=6`.

**Fix for both:** account identity is now the **pair** (source tag, `/home` path).
Two rows share an account only when both agree, so deflation takes control of
both at once, and disagreement can only ADD distinct accounts — the RED-safe
direction. The tag component keeps the whole source field rather than the account
after `php/`, since apache and fpm tags are per-site too. Pinned by
`fanout-constant-tag`, `fanout-injected-path`, `fanout-pair-no-inflate` and
`fanout-etx-no-split` (`\003` is the new pair separator and gets the same
key-only hygiene as `\034`). Revert-check: the first two fail against the
pre-fix code, the inflation guards hold in both directions.

## Majors

### 3. The whitespace fix grades RED→GREEN on a two-space feed, and the release notes said only the opposite
`[pass-a]` — accepted as intended behavior, documented rather than changed.

On a feed carrying raw two-space `PHP Fatal error:`, the scanner class was inert,
so every scanner-shaped one-off graded RED. Collapsing whitespace lets the pattern
match, and a single-account one-off then grades GREEN. This is the classifier
reaching a feed it never matched — it is why the breadth gate ships first (spec
§5) — but it is a grading change in the dangerous direction and the CHANGELOG
only warned about GREEN→RED. Now stated explicitly there.

**Open question for the operator:** the spec measured cds1 as single-space, so
this should be inert on the deploy target. That was not re-verified against the
live feed in this session.

### 4. Shipping defaults still taught the retired "bot executing PHP directly" story
`[pass-b][gap]` — `lib/common.sh` (the `ERROR_FATAL_SCANNER` and
`ERROR_FATAL_SCANNER_EXCLUDE` comments) and `lib/errors.sh:188` still framed the
class as bot noise decided by pattern+depth alone. Task 5 had fixed the digest
copy, the example conf and the README but not these. Corrected.

### 5. "isolated one-off crashes" is false for a 2–3-account cluster
`[pass-a]` — under the default threshold of 4, a three-account cluster is
correctly scanner-filed but is not a one-off. The digest heading and the report
summary now say "under the repeat and account-spread gates" instead.

### 6. An absurd threshold read as configured and behaved as off
`[pass-b]` — validation rejected only non-digits and empty. A 25-digit
`ERROR_FATAL_FANOUT_ACCOUNTS` passed, no account count ever reached it, and the
breadth gate was silently off. Both knobs are now bounded to five digits and fall
back with a warning; `fanout-knob-huge`, `fanout-knob-maxwidth` and
`repeats-knob-huge` pin it. The `awk -v` sites also carry `:-3` / `:-4` defaults
so a post-validation empty value cannot switch the gate off either.

## Minors — accepted, not changed

- **`nsig` that never collapses leaves the gate inert** `[pass-b M2]`: per-account
  variance outside `/home<N>/<acct>/` (a hostname in the message, a
  `/var/www/vhosts/…` layout) keeps signatures split. Pre-existing, documented in
  spec §2.7 as a known limitation; strictly narrowing, never a regression.
- **An account or directory literally named `virtfs`** `[pass-a m2]`: the jail
  unwrap eats the segment. Fails safe (tier-3 unique key → inflates → RED).
- **Multiple `/home` segments on one line merge into one `nsig`** `[pass-a m3]`:
  inflates breadth, the safe direction.
- **Body label reports max fan among genuine rows, not "why"** `[pass-b m5]`: a
  cluster made genuine by depth or the veto can still show the spread line.
- **Empty or timestamp-garbage feed grades "none"** `[pass-b M4]`: pre-existing;
  no fail-closed signal that the errors plane had no usable data.
- **Parity tests would pass without the feature** `[pass-a m1]`: by design — they
  pin the "strict narrowing" property, i.e. that depth-only cases did NOT change.
- **No shell/SMS injection** `[pass-b m1, security-review]`: confirmed. The
  pipeline is `printf`/`awk`/`grep`/`cut`/`sed` with no `eval` and no unquoted
  expansion of log text; the SMS body carries grade and recommendation only, not
  fatal text.

## Post-fix verification

- `make test` exit 0 under system awk (BSD, macOS) and under gawk 5.4.1 shimmed
  as `awk`; errors 102 pass / 0 fail, report 114 / 0.
- Both blocker reproductions now grade `GENUINE=6`; the single-account controls
  stay scanner-filed (no inflation).
- Working tree unchanged by both Grok runs (`git status --short` clean before and
  after each).
