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

**The two Blockers from that review are closed on this branch (2026-08-28
pickup). Not shipped.** cds1 is still on v2.17.0. Remaining: re-review, prod
dry-run, 2.18.0. Both blockers were found by an independent Claude review round
after the Grok budget was exhausted mid-round-6, and neither overlapped the
five completed Grok rounds.

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
   (`lib/score.awk:459`) — `{0, 1xx, 2xx, 3xx, 404}`. Deliberately wider than the
   measured class: status 0 (ingest's unparseable-line value) and 1xx also fail to
   feed `cerr[]`, so narrowing to a tidier `{2xx,3xx,404}` would REOPEN the
   `err_ratio` dilution lever. `403`/`429`/`5xx`/`444` deliberately still score —
   they feed `cerr[]` and therefore cannot dilute.
2. **End-anchored candidate-list validation.** The path is split on commas (`%2c`
   normalised first) and every COMPLETE candidate must match end to end. v2.17.0
   anchored only `^/`, so everything after the first comma was unvalidated.
3. **Whole-path encoding guard** `%2e|%2f|%25|%00` (`lib/score.awk:295`), once,
   after the `%2c` rewrite. `%25` closes the double-encoded family — `%252e` does
   not contain the substring `%2e`.
4. **Stem** `[a-z0-9_~@.%-]+` — dots, `@` and `%` admitted because real WordPress
   names carry them and non-ASCII names arrive percent-encoded.
5. **`stem_is_safe()`** (`lib/score.awk:244`) — a deliberately NARROW deny list of
   executable/secret extensions, consulted only when the stem has ≥2
   dot-components, **skipping component 1**, with iterative `_strip_wp_suffixes()`
   (`lib/score.awk:201`) for WordPress `-WIDTHxHEIGHT`/`-scaled`/`-eNNN` and editor
   `~`/`_`/variant suffixes.
6. **256-byte truncation tolerance.** `lib/ingest.sh:72` cuts the path at 256
   bytes, so at the boundary the final element is incomplete by construction. A
   final element that parses COMPLETE is fully validated; one that does not must
   satisfy `candidate_prefix_ok()` (`lib/score.awk:150`) AND `stem_is_safe()`.
   Separate `n == 1` branch at `lib/score.awk:300`.
7. **`srcset_flood` tripwire** — WATCH-ONLY, now enforced. Caps at `SCORE_WATCH`
   only when `floor == 0` (`lib/score.awk:662`); thresholds `>= 500` exempted
   requests at `>= 25` rps (`lib/score.awk:564`); `score.sh` caps any fold back
   below `SCORE_TEMP` and skips persist accrual for `drule=srcset_flood`
   (`lib/score.sh:780`). Hardcoded like `request_flood`'s `60` so no new
   configurable knob is introduced.
8. Exempted requests no longer vote for `top_vhost`; `srcset_flood` added to the
   report label map and the AbuseIPDB category map (as a dead branch).

**Test suite: 224 assertions in `test/score_test.sh`, green under a non-UTC TZ.
Nine mutation rounds (unique-match, code only).**

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

## CLOSED this pickup — items 1–6 (2026-08-28)

Line numbers re-resolved by grep after the edits.

1. **BLOCKER `srcset_flood` persist.** Reproduced: two seeded buckets + one
   `srcset_flood` scan placed a real temp. Filter is
   `[[ "$drule" != "srcset_flood" ]]` at `lib/score.sh:780`. Fold cap pinned.
2. **BLOCKER `+` at 256.** Final token class is `[a-z0-9_~@. %+-]`
   (`lib/score.awk:170`). `%20` controls still exempt. 171-prefix sweep scored 0.
3. **Deny list.** Removed `py`/`rb`/`ini`/`cnf`/`cfm`/`crt` (`lib/score.awk:215`).
   `passwd` pinned.
4. **Descriptor-less.** Not exempt; CHANGELOG overclaim narrowed. Matcher not
   widened.
5. **Line refs / counts.** Call site `lib/score.sh:749`; exempt predicate
   `lib/score.awk:459`; `request_flood` `lib/score.awk:653`. Suite **224**.
6. **Smaller.** `%2e|%2f` comment no longer overclaims; later-candidate hosts
   are scheme+host (`https://`, edge-collapsed `https:/`, `//host`) and a
   path-only `/wp-config.php/x.jpg` cannot parse as a host; `n==1` comment
   states no image extension; `srcset_flood` will not overwrite a genuine
   floor (`floor == 0` at `lib/score.awk:662`).

### 7. Still gating the widen — operator decision, not code

**The 19 pre-fix temps are on the ledger.** `swatter_store_recent_temp_count`
(`lib/store_sqlite.sh:141`, called at `lib/score.sh:749`) is a trailing lookback,
not forward-only, so raising `REPEAT_WINDOW_DAYS` from 7 to 30 re-includes temps
that already aged out — including those on residential visitors this class
already hit. Stopping new scoring does not expunge the ladder. Decide this
(`swatter rollback-ladder`) before widening. **This, not the code, is what
actually gates gate D.**

Also unchanged from the 08-20 decision: `ABUSEIPDB_REPORT="false"` is to be set
**at** the widen, and someone has to actually execute it.

---

## Sequence from here

1. ~~Re-verify Blocker 1; fix both Blockers TDD-first.~~
2. ~~Items 3–6.~~
3. ~~Re-sweep the 256-byte boundary at every offset.~~
4. ~~Mutation round (unique-match, code only).~~
5. ~~`make test` under a non-UTC TZ.~~ (`TZ=Asia/Tokyo make test` green; `gawk` as `awk` on score/errors/scan_wire.)
6. **Re-review.** Every round so far found something; there is no evidence that
   has stopped. Grok budget is exhausted — record which reviewers actually ran.
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
- Descriptor-less first candidates (`logo.png, logo@2x.png 2x`) are not exempt.
  Making the descriptor optional would exempt every missing WP upload.
