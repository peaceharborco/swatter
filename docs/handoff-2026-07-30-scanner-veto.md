# Handoff — scanner-fatal veto (2026-07-30)

**Repo:** `swatter` · **Branch:** `main` · **Commits:** `2499882`, `f2838c5`
**Status:** committed, tests green, **NOT deployed** — cds1 still runs 2.11.0.

---

## Why this change exists

On 2026-07-29 a `ph-hardening.sh` `wp eval` snippet was broken mid-development and
threw across five accounts:

```
PHP Fatal error: Uncaught Error: Undefined constant "ok"
  in phar:///usr/local/bin/wp-cli.phar/vendor/wp-cli/eval-command/src/Eval_Command.php(39)
```

Two occurrences per account. That matched `ERROR_FATAL_SCANNER` and sat under
`ERROR_FATAL_SCANNER_REPEATS=3`, so the nightly digest filed **our own broken
tooling as bot activity** — 10 of the 12 "scanner-induced" fatals in that window
were ours. Two costs: it hid our breakage, and it padded the scanner count.

The wp-eval bug itself is already fixed, so this is not urgent.

## What was changed

**`ERROR_FATAL_SCANNER_EXCLUDE`** — a veto. A fatal matching it is never
scanner-induced, regardless of repeat count. The classifier's premise is a bot
executing a PHP file over HTTP; a known local CLI entrypoint disproves that.

Default: `phar:///usr/local/bin/|/usr/local/bin/wp-cli|wp-cli\.phar`

Deliberately **not** a bare `phar://` — a bot can induce a phar:// frame via
deserialization probes, and that fatal is a security event that belongs in the
genuine count on its own merits, not vetoed in by path prefix. There is a
regression test for exactly this (`veto-bare-phar`).

**Dual-dialect regex validation** (the more interesting fix). Both
`ERROR_FATAL_SCANNER` and the new veto are now validated against **awk as well as
`grep -E`**, because awk is what applies them (`sigof[i] ~ re`) and the dialects
disagree. `$^` and `(?i)x` are grep-legal and awk **syntax errors**; an awk regex
error aborts the whole classification, empties `marked`, and every fatal falls to
genuine. RED-safe, but it silently voids the scanner class.

This was pre-existing exposure on `ERROR_FATAL_SCANNER` — the code comments
already acknowledged the gap. It is now closed for both knobs.

> The awk probe passes the pattern via `ENVIRON`, **not `-v`** — `-v`
> escape-processes backslashes and would validate a different string than the
> classifier receives. Don't "simplify" this to `-v`.

**Disable recipe is `'^$'`, never `'$^'`.** A fatal signature is never empty, so
`^$` can't match. `$^` is the trap above. Documented in all three places.

Files: `lib/errors.sh`, `lib/common.sh`, `config/swatter.example.conf`,
`test/errors_test.sh`, `CHANGELOG.md`.

## Verification already done

- `test/errors_test.sh`: **22 → 38** assertions, all passing
- Full suite (60+ test files): green, no regressions
- Grok adversarial review: **SHIP**, with two Majors folded in before commit
  (awk-side validation; narrowing the over-broad `phar://`)

---

## TODO

### 1. Decide release vs. direct deploy — **blocking, this is the only real gate**

cds1 runs 2.11.0 without the veto. `grep -c ERROR_FATAL_SCANNER_EXCLUDE
/usr/local/lib/swatter/errors.sh` returns 0 on the box.

Two paths, pick one:

- **Cut 2.12.0** via `install/release.sh` — the project's own convention. Note it
  tags and publishes, which is why it wasn't run unilaterally.
- **Deploy untagged** via `install/install.sh remote peaceharbor` — faster, but
  the box then runs code matching no tag.

*Acceptance:* `swatter version` on cds1 reflects the intended version AND
`grep -c ERROR_FATAL_SCANNER_EXCLUDE /usr/local/lib/swatter/errors.sh` returns
non-zero. Then `swatter test-config` green.

### 2. Persist the Grok review output — **housekeeping, do before release**

The developer-wide convention is to save review findings next to the artifact as
`*-review-grok.md`. **That was not done for this change** — the review ran and
returned SHIP, but only the tail of its output was read and the full transcript
was not captured. Prior releases have one (see
`docs/superpowers/specs/2026-07-27-v2.11.0-release-and-cds1-deploy-design-review-grok.md`).

*Acceptance:* either re-run a review pass against `2499882` and save the output,
or record explicitly that this change shipped on an unpersisted review. Don't
leave it ambiguous.

### 3. Consider whether `/etc/swatter/swatter.conf` on cds1 needs the new key

Not required — `lib/common.sh` supplies the default, and an absent key inherits
it. Only add it to the live conf if the box should deviate from the default.

*Acceptance:* conscious decision recorded; no action is a valid outcome.

### 4. Watch the first nightly digest after deploy

The genuine-fatal count is what drives RED and the SMS alert path. The veto moves
matching fatals **into** genuine, so a digest that previously graded green on
CLI-tooling fatals will now grade RED. That is the intent, but it will look like a
regression the first time it fires.

*Acceptance:* one nightly digest observed post-deploy; confirm the split reads
sensibly and no CLI fatal is still landing in the scanner bucket.

---

## Gotchas for whoever picks this up

- **`-v` vs `ENVIRON`** — see the callout above. This is load-bearing.
- **`'$^'` is not a valid disable value.** If someone reports "the veto broke
  everything," check whether they set `$^`; with the new validation it now falls
  back to the default and logs a warning instead of silently voiding.
- **The veto only ever moves fatals toward genuine.** It cannot hide an outage.
  If you're debugging a *missing* fatal, this is not the cause.
- The `eval()` string inside `test/errors_test.sh` is a **log-line fixture**, not
  executed code. A security linter flags it; it's a false positive.
