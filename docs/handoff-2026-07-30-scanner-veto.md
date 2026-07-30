# Handoff — scanner-fatal veto (2026-07-30)

**Repo:** `swatter` · **Branch:** `main` · **Commits:** `2499882`, `f2838c5`, `ec57ea7`
**Status:** **released as v2.12.0 and deployed** — 2026-07-30. cds1 runs 2.12.0;
`test-config` exit 0. Only the first-digest watch remains open.

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
`test/errors_test.sh`, `test/config_defaults_test.sh`, `CHANGELOG.md`,
`bin/swatter` (version), and the review doc under `docs/superpowers/specs/`.

## Verification already done

- `test/errors_test.sh`: **22 → 40** assertions, all passing (the last two pin the
  `ENVIRON`-not-`-v` plumbing — see `environ-not-dashv`)
- `test/config_defaults_test.sh`: +2, asserting the new key's shipped default
- Full suite: **64 test files, 0 failures**
- Grok adversarial review: **SHIP**, no Blockers. Two Majors folded in before the
  original commit (awk-side validation; narrowing the over-broad `phar://`), four
  more folded in before the v2.12.0 cut — all documentation correctness. Full
  transcript and per-finding disposition:
  `docs/superpowers/specs/2026-07-30-scanner-fatal-veto-review-grok.md`

---

## TODO

### 1. Release + deploy — **DONE 2026-07-30**

Released as **v2.12.0** (`ec57ea7`, tag + GitHub + GitLab) and deployed to cds1
the same day.

**Untagged deploy was rejected**, and not only on convention: `bin/swatter`'s
`SWATTER_VERSION` is not touched by `2499882`, so deploying `main` untagged would
have left cds1 reporting `2.11.0` while running code that is not 2.11.0 —
indistinguishable from a genuine 2.11.0 box except by grepping `errors.sh`. This
handoff's original acceptance test ("`swatter version` reflects the intended
version") was unsatisfiable on that path. Cutting the release first fixed it.

**Deployed with `install/install.sh --no-cron remote peaceharbor`.** The
`--no-cron` was deliberate and is worth remembering for next time: on cds1
`/etc/cron.d/swatter-report` was dated **Jul 18** while `/etc/cron.d/swatter` was
Jul 27, i.e. the v2.11.0 deploy had *not* regenerated the report cron. A default
deploy rewrites it from conf (`install.sh:255`), which would have silently
replaced the file carrying the 4am-Pacific timezone fix. `--no-cron` leaves both
cron files untouched; the `*/5` scan and the nightly report keep whatever
schedule the operator already had.

*Acceptance — all verified post-deploy:*

| Check | Before | After |
|-------|--------|-------|
| `swatter version` | 2.11.0 | **2.12.0** |
| `grep -c ERROR_FATAL_SCANNER_EXCLUDE /usr/local/lib/swatter/errors.sh` | 0 | **8** |
| `grep -c SWATTER_FS_EX …/errors.sh` (ENVIRON plumbing) | — | **2** |
| `swatter test-config` | — | **exit 0** |
| `/etc/swatter/swatter.conf` mtime/size/mode | `2026-07-28 00:43:30` / 8669 / 600 | **identical** |
| `/etc/cron.d/swatter{,-report}` mtimes | Jul 27 23:45 / Jul 18 12:50 | **identical** |

`test-config` reports `mode: enforce`, `ladder: ARMED`, `perm tripwire: 15/run
120/day`, `publication: swarm=false abuseipdb=false` — i.e. the gate C soak and
the ~08-10 publication freeze are both undisturbed, as intended.

> The installer's closing banner says "Swatter is in REPORT mode." That is
> generic first-run text printed unconditionally, **not** live state. cds1 is and
> remains `enforce` — confirmed by `test-config` above. Don't panic-edit the conf
> because of that banner.

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

### 3. Whether `/etc/swatter/swatter.conf` on cds1 needs the new key — **DECIDED 2026-07-30: no**

The key was deliberately **not** added to the live conf. `lib/common.sh` supplies
the default and an absent key inherits it; verified on the box post-deploy:

```
$ grep -E '^ERROR_FATAL_SCANNER_EXCLUDE=' /usr/local/lib/swatter/common.sh
ERROR_FATAL_SCANNER_EXCLUDE='phar:///usr/local/bin/|/usr/local/bin/wp-cli|wp-cli\.phar'
```

Leaving it absent means the box tracks the shipped default on future upgrades
instead of pinning today's value. Only add it if cds1 should deliberately deviate
— e.g. to cover a wp-cli layout the default misses (see the residual below).

### 4. Watch the first nightly digest — **OPEN, the only thing left**

Deployed 2026-07-30; the report cron was left untouched, so the next digest fires
on its existing schedule (4am Pacific).

The genuine-fatal count is what drives RED and the SMS alert path. The veto moves
matching fatals **into** genuine, so a digest that previously graded green on
CLI-tooling fatals will now grade RED. That is the intent, but it will look like a
regression the first time it fires.

What to check when it lands:

- [ ] If it grades RED, read *why* before reacting. A RED whose genuine fatals are
      `phar:///usr/local/bin/wp-cli.phar/...` frames is the veto working exactly as
      designed — that is our tooling breaking, and it is now visible instead of
      being filed as bot noise.
- [ ] Confirm no CLI-tooling fatal is still landing in the scanner bucket.
- [ ] Confirm ordinary bot fatals (`Undefined constant "ABSPATH"` in a docroot
      path, one-off, under 3 repeats) still classify **scanner**. If those started
      counting genuine, the veto is over-matching — check whether someone edited
      `ERROR_FATAL_SCANNER_EXCLUDE` into the live conf.
- [ ] The motivating `wp eval` bug is already fixed, so the first night may simply
      be quiet. A quiet digest is not evidence the veto is broken.

*Acceptance:* one nightly digest observed post-deploy; the split reads sensibly.

### 5. Known residuals — not bugs, decided against fixing now

Both surfaced by the Grok review and declined with reasons (see the review doc):

- **Unanchored `wp-cli\.phar` is a false-RED surface.** An attacker who can drop a
  file named `wp-cli.phar` under a docroot *and* trigger a matching fatal can push
  it into the genuine count and cry wolf. The direction is safe — the veto only
  ever moves fatals toward genuine, never hides one — so this is noise, never
  silence. Tightening it costs the coverage below.
- **The default misses some wp-cli layouts:** `/usr/bin/wp`, `/usr/local/bin/wp`
  (no `wp-cli` substring), and composer-installed
  `vendor/wp-cli/wp-cli/php/wp-cli.php`. Fatals from those paths still classify
  scanner. The motivating incident's path is covered; broadening is a
  default-behaviour change that should be made on evidence, not on spec.

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
- **Deploy cds1 with `--no-cron` unless you mean to rewrite the cron files.** A
  default `install.sh` regenerates `/etc/cron.d/swatter-report` from conf, and
  that file on cds1 carries the 4am-Pacific timezone fix and predates the last two
  deploys. See item 1.
- **The installer's "Swatter is in REPORT mode" closing banner is unconditional
  boilerplate**, not a reading of the live conf. cds1 is `enforce`. Check
  `swatter test-config`, not the banner.
- **A bare `phar://` bot fatal counts SCANNER, not genuine.** This is the one
  thing the docs got wrong before v2.12.0, so anything you remember from the
  earlier draft of this file may be inverted. `veto-bare-phar` is the ground truth.
