# Handoff — the fatal classifier can grade a fleet-wide outage GREEN (2026-08-11)

**Repo:** `swatter` · **Branch:** `main` · **Tree:** clean at `faa62c3` · **cds1 runs v2.13.0.**
**Status:** a defect in the shipping classifier, found while adding a feature. **The feature is
abandoned** (wrong mechanism). The defect is real, is **live on cds1 today**, and predates the
feature. Nothing has been deployed or committed as code.

**Review that caught it:** `docs/proposals/2026-08-11-array-injection-classifier-arm-review-grok.md`.

| | |
|---|---|
| **Defect** | A sparse fleet-wide fatal grades **GREEN**. Live in v2.13.0. |
| **Blast radius today** | Narrow — reachable only by probe-shaped fatals. See §2. |
| **Abandoned fix** | A second `ERROR_FATAL_SCANNER` arm for array-injection TypeErrors. §3. |
| **Chosen direction** | Correlate fatals with IPs Swatter itself scored. §4. |

---

## 1. The defect

`swatter_errors_section` files a fatal as **scanner-induced** — which does **not** trip RED — when
its signature repeats *fewer* than `ERROR_FATAL_SCANNER_REPEATS` (default 3) times in the window.

The signature is the whole log line minus its timestamp (`lib/errors.sh:310-311`), so **it retains
the absolute `/home/<acct>/…` path and the `[php/<acct>]` tag.** One shared bug on N accounts
therefore produces **N distinct signatures, each with count 1** — every one of them under the repeat
gate.

> **17 accounts × 1 identical fatal each → `ERR_FATAL_GENUINE=0`, `ERR_FATAL_SCANNER=17` → GREEN.**

The repeat gate only ever fires *within a single account's path*. Across accounts it is inert.

### Reproduce it

Run from the repo root. Uses only shipped code and the shipping default pattern.

```bash
cat > /tmp/repro.sh <<'EOS'
#!/usr/bin/env bash
set -uo pipefail
ROOT="$PWD"
source "$ROOT/lib/common.sh"; source "$ROOT/lib/report.sh"; source "$ROOT/lib/errors.sh"
swatter_now() { echo 1782396000; }
TS="2026-06-25 10:00:00"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ERROR_DIGEST_LOG="$WORK/digest.log"
: > "$ERROR_DIGEST_LOG"
for a in acct01 acct02 acct03 acct04 acct05 acct06 acct07 acct08 acct09 \
         acct10 acct11 acct12 acct13 acct14 acct15 acct16 acct17; do
  echo "[$TS] [FATAL] [php/$a] PHP Fatal error: Uncaught Error: Call to undefined function shared_helper() in /home/$a/public_html/wp-content/plugins/vendor/render.php:88"
done >> "$ERROR_DIGEST_LOG"
swatter_errors_section 24h >/dev/null
echo "FATAL=$ERR_FATAL GENUINE=$ERR_FATAL_GENUINE SCANNER=$ERR_FATAL_SCANNER"
EOS
bash /tmp/repro.sh   # -> FATAL=17 GENUINE=0 SCANNER=17
```

`ERR_FATAL_GENUINE=0` is what drives the "no genuine fatals" / GREEN path
(`lib/report.sh:422`, `:474`, `:499`).

---

## 2. How much this matters *today* — read before prioritising

**Do not over-read the repro.** With the **shipping** pattern the defect is only reachable by fatals
matching `Call to undefined function|Undefined constant`, and those are genuinely probe-shaped: they
happen when a PHP file is executed **outside the app bootstrap**, which is overwhelmingly a bot
hitting a file head-on. A real fleet-wide bug of *that* shape is rare — it needs a shared include or
a mu-plugin to vanish across many accounts at once, which is possible (a botched fleet deploy) but
not routine.

So today this is a **latent** hole with a narrow mouth, not an active blind spot. It is documented
here because **it is invisible in the digest and it silently widens the moment anyone broadens the
pattern** — which is exactly what §3 tried to do.

**Treat "widen `ERROR_FATAL_SCANNER`" as gated on fixing this first.** That is the durable lesson.

---

## 3. The abandoned fix, and why it is abandoned

**Goal:** a scanner probe (`?page%5Blimit%5D=1` from `208.14.29.180`, 2026-08-11) hit an unguarded
`substr($_GET['page'], …)` in Docket Cache across 17 cds1 accounts and graded that digest window RED.
A digest that overstates severity gets ignored, so the ask was to file that shape as scanner-induced.

**Built and tested** (all green, then discarded): a second arm on the pattern —

```
PHP Fatal error: Uncaught (Error: (Call to undefined function|Undefined constant)|TypeError: [A-Za-z_]+[(][)]: Argument #[0-9]+ .* must be of type [?a-z|]+, array given)
```

Backslash-free by construction (bracket expressions, so single-quoted shell can't mangle it),
validated identical under `grep -E`, BSD awk (macOS) and gawk, 4 positives / 4 negatives, all three
copies updated together, `make test` exit 0, errors plane 50/50.

**Why it must not ship:**

1. **It widens §1's mouth from "probe-shaped" to "ordinary."** `…, array given` is an everyday PHP 8
   app-bug shape. `htmlspecialchars()` in a Divi theme, `trim()` in WooCommerce checkout,
   `explode()`/`preg_match()` on config that became an array after a bad update — all match. Swap the
   fixture in §1's repro for one of those and a genuine fleet-wide outage grades GREEN.
2. **Its premise is false.** The patch comment claimed the shape is "only reachable by decorating a
   query string." It is not: `name="x[]"` form fields and plugins rewriting POST produce the identical
   TypeError with no scanner anywhere.
3. **It is simultaneously too narrow.** `[A-Za-z_]+[(][)]` rejects `WP_Query::get()`,
   `DateTime::modify()`, and namespaced functions — so real method-level array injection stays
   genuine anyway. Over-broad on free functions, incomplete on methods.
4. **Its tests didn't pin what they claimed.** A deliberately over-broad `TypeError:.*array given`
   stand-in produced identical results on all four new fixtures. Verified.

### ⚠️ The obvious mitigation inverts the problem — do not re-propose it

The natural fix is path-normalized counting: strip `/home/<acct>` so N accounts collapse to one
signature. **Checked. It makes things worse.** One signature with 17 hits crosses `REPEATS=3` and
grades **genuine → RED** — precisely the grading the task set out to stop. It trades a false GREEN for
a guaranteed false RED on every scanner sweep.

**The conclusion that survives:** a scanner sweep and a fleet-wide app bug are **textually
identical**. No regex over the fatal message can separate them. Stop looking for one.

---

## 4. Chosen direction — correlate with scored IPs

**Decided 2026-08-11 (Josh)**, over relabeling and over dropping the item.

Swatter holds a discriminator nothing else in this pipeline has: **it already scored the offending
IP.** "This fatal's window overlaps an IP Swatter classified as a scanner" is a signal the error log
cannot carry on its own.

**Known hard parts — recorded now so they are not discovered mid-build:**

- **PHP fatals carry no client IP.** There is no join key. The correlation has to be time-window plus
  account, which is inherently fuzzy. Whatever is built must be honest about false matches rather
  than presenting a heuristic as an attribution.
- **Fail direction is not optional.** Missing, stale, or ambiguous correlation data must resolve to
  **GENUINE / RED**, never to scanner — matching every other knob in this classifier
  (`lib/errors.sh:209-214` documents the same reasoning for the veto's fallback).
- **Decide the data source deliberately:** the scan state/ledger, versus re-deriving offenders from
  domlogs at digest time. The second is self-contained but duplicates scoring logic.
- **This changes what a RED means.** Worth a `RUNBOOK.md` note, not just code.

**Do not start by widening the regex.** The regex is the wrong layer; that is the whole finding.

---

## 5. Loose ends found alongside, all pre-existing

- **Digest copy is inaccurate.** `lib/errors.sh:363` and `lib/report.sh:499` say "bots executing PHP
  files directly." Already wrong for anything inside the app bootstrap — the cds1 case came from
  `…/plugins/docket-cache/…/Plugin.php:1462`, which *is* bootstrapped. Worth fixing regardless of §4.
- **Whitespace asymmetry between the two feeds.** The live emit collapses runs of whitespace
  (`lib/errors.sh:39`); the pre-consolidated `ERROR_DIGEST_LOG` path (`lib/errors.sh:22-26`) does not.
  Raw PHP logs `PHP Fatal error:` with **two** spaces, so on that feed **neither** arm matches. Tests
  use single-space fixtures and therefore cannot catch it.
- **Disable docs are incomplete.** `lib/errors.sh:194` and `config/swatter.example.conf` say
  `REPEATS=1` disables the classifier; `0` also does, and is kept deliberately as RED-safe
  (`lib/errors.sh:254-260`). Say both.
- **Three-copy duplication is currently byte-identical** across `lib/common.sh`, `lib/errors.sh`
  (`_ERR_FATAL_SCANNER_DEFAULT`) and `config/swatter.example.conf` — verified. Nothing tests that
  invariant, so a silent split between shipping default, validation fallback and docs is possible.
  Cheap test, worth adding.

## 6. Not Swatter's problem, tracked upstream

The Docket Cache bug itself — unguarded `substr($_GET['page'], …)` at
`includes/src/Plugin.php:1462` — still 500s one request per probe on 17 cds1 accounts. Report
upstream or drop array-notation `page[]` at the WAF. **Do not patch the plugin locally.**
