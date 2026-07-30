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
deserialization probes, so that fatal is left to the classifier's own terms
rather than pulled out of the scanner class by a path prefix. Concretely: under
default knobs a one-off bot phar:// fatal counts **scanner**, not genuine.
There is a regression test for exactly this (`veto-bare-phar`).

> An earlier draft of this section — and of the code comments, example conf, and
> CHANGELOG — claimed such a fatal "belongs in the genuine count on its own
> merits." That was wrong, and `veto-bare-phar` asserted the opposite all along.
> Corrected in v2.12.0; see the Grok review's M1.

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

### 1. Release vs. direct deploy — **DECIDED 2026-07-30: tag now, deploy at the gate C window**

cds1 runs 2.11.0 without the veto. `grep -c ERROR_FATAL_SCANNER_EXCLUDE
/usr/local/lib/swatter/errors.sh` returns 0 on the box.

**v2.12.0 is cut** (tag + GitHub/GitLab release). The deploy is deliberately held
until the ~2026-08-03 gate C window, for three reasons:

- Nothing here is urgent — the wp-eval bug that motivated it is already fixed.
- cds1 is mid-soak on v2.11.0 until ~08-03. The veto touches only the digest's
  fatal classifier, so it cannot disturb the `rule=`-stamped ladder data the soak
  is accumulating — but the operator is going onto the box for the gate C
  measurement and conf edits anyway. One maintenance window beats two.
- Item 4's first-digest RED is easier to read correctly during a week the
  operator is already reading digests closely.

Take the perm-rate measurement FIRST, then deploy — the ledger path is untouched
by this change, so the ordering is bookkeeping hygiene rather than correctness.

**Untagged deploy was rejected**, and not only on convention: `bin/swatter`'s
`SWATTER_VERSION` is not touched by `2499882`, so deploying `main` untagged would
have left cds1 reporting `2.11.0` while running code that is not 2.11.0 —
indistinguishable from a genuine 2.11.0 box except by grepping `errors.sh`. This
handoff's own acceptance test ("`swatter version` reflects the intended version")
was unsatisfiable on that path.

*Deploy command when the window opens:* `install/install.sh remote peaceharbor`
— note it rewrites `/etc/cron.d/swatter` and re-arms the `*/5` scan unless you
pass `--no-cron`. It does **not** touch `/etc/swatter/swatter.conf` (`install.sh:238`),
so `SWARM_PUBLISH=false`, `ABUSEIPDB_REPORT=false`, the provisional perm-rate
tripwire, and `OPERATOR_IPS` all survive. The ~08-10 publication unfreeze is
unaffected either way.

*Acceptance:* `swatter version` on cds1 reflects the intended version AND
`grep -c ERROR_FATAL_SCANNER_EXCLUDE /usr/local/lib/swatter/errors.sh` returns
non-zero. Then `swatter test-config` green.

### 2. Persist the Grok review output — **DONE 2026-07-30**

Re-run against `2499882` + `f2838c5` and saved as
`docs/superpowers/specs/2026-07-30-scanner-fatal-veto-review-grok.md`, with a
disposition table for every finding. Verdict **SHIP**, no Blockers, four Majors —
all documentation/comment correctness, folded in before the v2.12.0 cut. Two
findings were declined with reasons recorded (M2's false-RED surface and M3's
self-contradictory fallback prescription).

The mechanism was probed and held: the `ENVIRON`-not-`-v` claim is true and now
has a regression test (`environ-not-dashv`), operator precedence in the combined
awk condition is correct, and the disable recipe is consistently `'^$'`
everywhere.

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
