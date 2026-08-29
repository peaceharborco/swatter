# Handoff — the srcset residual scoring surface (branch, NOT shipped)

Written 2026-08-28. Branch `fix/srcset-residual-scoring-surface`, **uncommitted**
at the time of writing and **not deployed**. cds1 is still on v2.17.0.

Read this with `docs/handoff-2026-08-28-gate-d-review-complete.md`, which this
supersedes for gate 2. Unrelated to `docs/handoff-2026-08-28-ci-self-swat.md`.

> **Line numbers below were resolved by `grep` at the time of writing, not from
> memory.** Six review rounds found a bad line reference in these docs *every
> single time*, so re-resolve before trusting any of them.

---

## Start here

`is_mangled_srcset()` exempts a real false-positive class: third-party
Chromium-based clients fetch an entire HTML `srcset` attribute VALUE as one URL.
The fleet's markup is CORRECT — this is manufactured client-side, so no upstream
fix exists and the scanner exemption is the only layer that can act. See
`docs/handoff-2026-08-28-gate-d-review-complete.md` §2 for the cause correction.

v2.17.0 shipped that exemption gated on `status == 404`. This branch closes the
gap that gate left, plus everything six review rounds found underneath it.

**It is not ready. Two Blockers are open.** Both were found by an independent
Claude review round after the Grok budget was exhausted mid-round-6, and neither
overlapped the five completed Grok rounds.

---

## Why this matters — measured, not argued

A read-only dry run on cds1 scored **3,126,395 real log rows** (100 rotated
domlogs, a month of fleet traffic) through the installed v2.17.0 scorer and the
candidate, under identical parameters:

| | Result |
|---|---|
| IPs that **lose** detection | **0** |
| IPs that **newly** score (false positives) | **0** |
| IPs whose score changed | **1** |
| srcset requests exempted, old → new | **574 → 828** (+44%) |

That one IP is the whole case. **A real visitor** — Chrome 151, sample paths are
Divi theme JS, child-theme CSS, `et-cache` CSS, `jquery-migrate`; **zero**
badpath hits; 549 requests inside a single 60-second burst, 508 of them (92.5%)
the srcset shape; status split 254×404, 254×301, 41×200.

Replayed through a production-realistic 600-second window, as the `*/5` scan runs:

- **installed v2.17.0 → score 75 → at/above `SCORE_TEMP`. That is a temp block.**
- **candidate → score 50. Watch only.**

v2.17.0 exempts only their 404s, leaving 254 redirects counted — 295 requests at
14.75 rps → `request_flood` → banned. **This is live on cds1 now.** Three such
temps is a permanent, non-deletable AbuseIPDB report against a residential
visitor of a client's own site.

The host was left untouched: read-only, temp dir removed, installed scorer sha
unchanged. Detailed results were deliberately not copied off the host — they
carry client domains and visitor IPs, and this repo is public.

---

## What the branch changes

`lib/score.awk` (the bulk), `lib/score.sh`, `lib/report.sh`,
`lib/report_abuseipdb.sh`, `test/score_test.sh`, plus `CHANGELOG.md`, `TODO.md`,
`README.md` and the gate-D handoff.

1. **Exempt status set** is the predicate `status < 400 || status == 404`
   (`lib/score.awk:444`) — `{0, 1xx, 2xx, 3xx, 404}`. Deliberately wider than the
   measured class: status 0 (ingest's unparseable-line value) and 1xx also fail to
   feed `cerr[]`, so narrowing to a tidier `{2xx,3xx,404}` would REOPEN the
   `err_ratio` dilution lever. `403`/`429`/`5xx`/`444` deliberately still score —
   they feed `cerr[]` and therefore cannot dilute.
2. **End-anchored candidate-list validation.** The path is split on commas (`%2c`
   normalised first) and every COMPLETE candidate must match end to end. v2.17.0
   anchored only `^/`, so everything after the first comma was unvalidated.
3. **Whole-path encoding guard** `%2e|%2f|%25|%00` (`lib/score.awk:283`), once,
   after the `%2c` rewrite. `%25` closes the double-encoded family — `%252e` does
   not contain the substring `%2e`.
4. **Stem** `[a-z0-9_~@.%-]+` — dots, `@` and `%` admitted because real WordPress
   names carry them and non-ASCII names arrive percent-encoded.
5. **`stem_is_safe()`** (`lib/score.awk:243`) — a deliberately NARROW deny list of
   executable/secret extensions, consulted only when the stem has ≥2
   dot-components, **skipping component 1**, with iterative `_strip_wp_suffixes()`
   (`lib/score.awk:190`) for WordPress `-WIDTHxHEIGHT`/`-scaled`/`-eNNN` and editor
   `~`/`_`/variant suffixes.
6. **256-byte truncation tolerance.** `lib/ingest.sh:72` cuts the path at 256
   bytes, so at the boundary the final element is incomplete by construction. A
   final element that parses COMPLETE is fully validated; one that does not must
   satisfy `candidate_prefix_ok()` (`lib/score.awk:148`) AND `stem_is_safe()`.
   Separate `n == 1` branch at `lib/score.awk:288`.
7. **`srcset_flood` tripwire** — intended WATCH-ONLY. Caps at `SCORE_WATCH` in
   `lib/score.awk:647`, thresholds `>= 500` exempted requests at `>= 25` rps
   (`lib/score.awk:549`), hardcoded like `request_flood`'s `60` so no new
   configurable knob is introduced. **See Blocker 1 — this property is not
   actually enforced.**
8. Exempted requests no longer vote for `top_vhost`; `srcset_flood` added to the
   report label map and the AbuseIPDB category map (as a dead branch).

**Test suite: 202 assertions in `test/score_test.sh`, 1,635 total, green under
both awk dialects and a non-UTC TZ. Eight mutation rounds.**

---

## The pattern this change kept hitting — read before touching it

Six review rounds. **Every one found real defects, and the shape never varied: a
fix in one direction created a defect in the other, and the suite stayed green
either way.**

| Round | What the previous round's FIX broke |
|---|---|
| 1 | (baseline) 404-only gate; unvalidated tail; `[^/]+` stem cloak |
| 2 | tripwire banned ordinary gallery page-loads; end-anchoring banned real long srcset values |
| 3 | deny list banned `photo.bak.jpg`/`old.jpg`; `php[0-9]` missed `php81`; complete attack candidate rode at exactly 256 |
| 4 | prefix check rejected cuts through `https` (real 4-candidate values scored); incomplete final skipped `stem_is_safe`; deny list banned `the.bat.jpg`, `my.key.jpg`, `warsaw.pl.jpg` |
| 5 | `%252e` cloak; `conf`/`jar`/`war`/`shadow` banned real names; WP `-768x576` defeated a single-pass strip; a cut inside `,%20` banned real visitors |
| 6 | deny token in the FIRST component refused 8,316 of 18,216 generated realistic names |

Assume it is still true. Two independent reviewers on the current tree each found
a Blocker, and they were **entirely disjoint**.

Also worth internalising: **five separate tests in this suite passed for the wrong
reason** and were only exposed by mutation testing (a double comma in a fixture, a
payload refused structurally rather than by the guard under test, a uniform-status
storm that scored 0 for incidental reasons). And the mutation harness itself
reported false survivors **six times** by patching a *comment* containing the same
text as the code. **Anchor mutation targets to code, and require a unique match.**

---

## OPEN — what is left to do

Numbered items are mirrored into `TODO.md`.

### 1. BLOCKER — `srcset_flood` can reach a real temp block

Found by the Opus correctness review. **Not independently re-verified — do that
first.**

`lib/score.sh:774` is the `else` arm of `folded >= SCORE_TEMP`: the WATCH band,
which does low-and-slow accrual. It calls `swatter_store_sighting_add`
(`lib/score.sh:777`, `lib/store_sqlite.sh:521`) and at `PERSIST_N` distinct
buckets inside `PERSIST_WINDOW_DAYS` executes a real `temp`. Defaults are
`PERSIST_ENABLE=true`, `PERSIST_N=6`, `PERSIST_BUCKET_SECONDS=3600`,
`PERSIST_WINDOW_DAYS=3` (`lib/common.sh:215-218`).

**There is no rule filter on that path** — neither sighting function reads
`decisive_rule`. So a watch-only `srcset_flood` row lands in the WATCH band on
every scan, and six hourly buckets over three days becomes an `action=temp` with
`dry_run=0`, which `swatter_store_recent_temp_count` (`lib/store_sqlite.sh:141`,
called at `lib/score.sh:747`) counts — feeding the recidivism ladder toward
perm + AbuseIPDB.

Sharpest form is a **mixed** client (a real visitor who also loads a heavy
gallery): their ordinary requests supply `topvh`, so the block lands on a
nameable vhost. A seeded srcset-only row fails safe on the CF plane only, because
`topvh` is deliberately not tracked for exempt requests.

**Mutation evidence that nothing guards this: deleting the entire cap block at
`lib/score.sh:715` leaves 202/202 green.** The `score.sh` half of the watch-only
claim is untested.

Fix direction: filter the WATCH-band accrual on `decisive_rule` (a watch-only rule
must not accrue sightings), and pin it with a test that fails when the filter is
removed.

### 2. BLOCKER — `+` separator at the truncation boundary bans real visitors

Found by the Sonnet red-team review. **Independently verified.**

`candidate_prefix_ok()`'s final token class at `lib/score.awk:160` is
`[a-z0-9_~@.%-]` — it admits `%` but omits `+`, while every other predicate in the
file (`candidate_complete`, both candidate regexes) treats `(%20|\+| )` as three
equally legal spellings of the srcset separator. A truncation landing on or after
a literal `+` is misclassified as "not a valid prefix" and the whole request
scores.

Verified at exactly 256 bytes:

| truncated tail | result |
|---|---|
| `…jpg%209`, `…jpg%20` | EXEMPT (correct) |
| `…jpg+9`, `…jpg+` | **SCORES** (defect) |

**Scope correction to the review as filed:** it also reported bare-space cases.
Those are **unreachable in production** — `lib/ingest.sh:66` splits the request
line on space and takes `rp[2]`, so `/x.jpg 9` parses to `/x.jpg` before scoring
sees it. Its "182 of 9,966 boundary paths (1.8%)" figure is therefore roughly
halved; only the `+` spelling is real.

Fix direction: add `+` to the class at `lib/score.awk:160` (and a literal space
for consistency with the rest of the file, even though ingest makes it
unreachable — this function should not depend on its caller). Then **re-sweep the
256-byte boundary at every offset**: rounds 4, 5 and 6 each found a *distinct*
false positive in this same area at a different offset.

### 3. Deny list still carries short/ordinary words

`lib/score.awk:204` still lists `py`, `rb`, `ini`, `cnf`, `cfm`, `crt`. `py` is
the Paraguay ccTLD, structurally identical to `pl` (Poland) which round 4 removed
— and the comment at `lib/score.awk:222` names the exclusion rule explicitly
while the list violates it. Measured: `asuncion.py-768x576.jpg`, `foto.ini.jpg`,
`tv.crt.jpg`, `logo.rb.jpg` all score; `warsaw.pl-768x576.jpg` and
`mens.conf-768x576.jpg` correctly do not.

By the asymmetry the code itself argues (a wrong token bans a real person
irreversibly; a missed token costs intent-evidence on a request that executes
nothing) these should come out. **Owner ratified keeping the list narrow — this
is applying that decision, not reopening it.**

### 4. Descriptor-less srcset candidates are not exempt

The HTML spec makes the width/density descriptor **optional** —
`srcset="logo.png, logo@2x.png 2x"` is the standard retina idiom and its first
candidate is bare. All three candidate regexes require
`(%20|\+| )+[0-9]+(\.[0-9]+)?[wx]`, so such a value scores.

`CHANGELOG.md` claims "two-candidate values, multisite, nested subdirs,
single-candidate, and density descriptors all remain exempt" — an overclaim.
Whether this shape occurs in the measured 17,829-request population is **not
known** and should be checked against the archive before deciding whether to
support it or narrow the claim.

### 5. Line references this branch broke, and doc counts that disagree

- `lib/score.sh:735` cited in `CHANGELOG.md`, this handoff's predecessor, and
  `TODO.md` for `swatter_store_recent_temp_count` — the 12 lines added around
  `lib/score.sh:706-717` moved it. Call site is now **`lib/score.sh:747`**,
  definition `lib/store_sqlite.sh:141`.
- `lib/score.awk:392` cited for the exempt predicate → actually **444**.
- `lib/score.awk:586` cited for `request_flood` → actually **580**.
- `CHANGELOG.md` says 169 assertions and "three mutation rounds"; `TODO.md` and
  the gate-D handoff say 166 and "six mutation rounds"/"four review rounds". The
  suite reports **202**, and there were **six review rounds** and **eight**
  mutation rounds.

### 6. Smaller items from the review round

- **Genuine surviving mutant:** removing `passwd` from `_deny_token` leaves
  202/202 green. `x.passwd.jpg` is unpinned.
- **Dead defensive check (equivalent mutant):** the `%2e|%2f` test inside
  `candidate_prefix_ok` (`lib/score.awk:154`) can never fire — the whole-path
  guard at `lib/score.awk:283` already refused those before either call site.
  Deleting it leaves the suite green. Its comment credits it with stopping the
  encoded cloaks; it does not. Fix the comment or the placement.
- **First/later candidate asymmetry:** the later-candidate host group allows dots,
  which the first-candidate rule structurally forbids, so
  `…/a.jpg%20300w,/wp-config.php/x.jpg%20300w` is EXEMPT and the badpath table
  does not catch it (`config/badpaths.conf:18` requires a suffix after
  `wp-config.php`). No working exploit — same reasoning as the accepted 256-byte
  residual — but the comment claims this is closed.
- **The `n == 1` truncated branch requires no image extension at all**
  (`lib/score.awk:288`): uploads anchor + prefix + stem check only. Contained by
  the dot-free-directory rule, but wider than its comment describes.
- **`srflood` can overwrite a genuine `frule`** when an operator raises
  `SCORE_WATCH` above 75. Safe at defaults; the comment overstates.

### 7. Still gating the widen — operator decision, not code

**The 19 pre-fix temps are on the ledger.** `swatter_store_recent_temp_count`
(`lib/store_sqlite.sh:141`) is a trailing lookback, not forward-only, so raising
`REPEAT_WINDOW_DAYS` from 7 to 30 re-includes temps that already aged out —
including those on residential visitors this class already hit. Stopping new
scoring does not expunge the ladder. Decide this (`swatter rollback-ladder`)
before widening. **This, not the code, is what actually gates gate D.**

Also unchanged from the 08-20 decision: `ABUSEIPDB_REPORT="false"` is to be set
**at** the widen, and someone has to actually execute it.

---

## Sequence from here

1. Re-verify Blocker 1 independently; fix both Blockers TDD-first.
2. Items 3–6.
3. Re-sweep the 256-byte boundary at every offset (rounds 4/5/6 each found a
   distinct FP there).
4. Mutation round; anchor targets to CODE, require a unique match.
5. `make test` under both awk dialects and a non-UTC TZ.
6. **Re-review.** Every round so far found something; there is no evidence that
   has stopped. Note the Grok budget is exhausted — if it is not topped up, the
   two-model Claude round used here is the substitute, and the release notes
   should record which reviewers actually ran.
7. Re-run the prod dry-run — it is cheap, read-only, and it is what proved the
   change is needed.
8. Version bump (this is a **2.18.0**; the CHANGELOG entry is still under
   `[Unreleased]`), release, surgical-scp, sha-verify against the tag.

## Known and deliberately accepted

- At exactly 256 bytes the final element is ambiguous, so a tail not in
  `badpaths.conf` that passes the stem check (`,/etc/passwd`) wins the exemption.
  No working exploit — the URL ends in a srcset descriptor and the server serves
  nothing from it. Note there is **no generic `\.php` rule** in `badpaths.conf`.
- `stem_is_safe()` is a deny list and has a residual tail by construction. Owner
  ratified keeping it narrow.
- Overlong/fullwidth dot spellings (`%c0%ae`, `%ef%bc%8e`) are not closed.
- Photon / ShortPixel / Cloudflare-Images srcsets are not exempted — their URLs
  put a dotted host inside a path segment, and dot-free segments are the traversal
  guard. Latent for any site that enables one.
- Non-`YYYY/MM` upload layouts (old multisite `blogs.dir`, `uploads/202510/`) are
  not exempted.
