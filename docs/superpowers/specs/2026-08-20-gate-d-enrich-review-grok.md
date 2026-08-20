# Gate D enrichment tooling — consolidated pre-ship review (2026-08-20)

**Target:** `gate-d-enrich.sh`, a draft read-only operator script that enriches a
`swatter escalate-preview` list and sorts candidates into the three gate D review
buckets. **Never deployed. Not committed.** See "Disposition" at the bottom.

**Reviewers:** `grok-4.6` (correctness lens, `[4.6-a]`) + `grok-4.5` (safety /
edge-case lens, `[4.5-b]`), run concurrently, `--sandbox read-only`; plus the
Claude-side `[code-review]`, `[security-review]` and `[gap]` sweeps.
`git status --short` was empty and unchanged across the run — no pass wrote
anything.

**Both Grok verdicts: HOLD.** Claude's final pass concurs without reservation.

## Why this review matters more than its subject

The script was ~250 lines of read-only analysis tooling — the kind of thing it is
tempting to wave through as "it only reads." It was not shippable. The sort it
performs is a **safety decision**: buckets 1 and 2 are never read row-by-row (2
gets only a 25–30 row sample), so a row wrongly sorted there escapes human review
entirely, and the downstream consequence is a permanent, irreversible AbuseIPDB
report against an innocent address.

Every Blocker below is a path where the script places a row in bucket 2 that a
human should have seen.

## Blockers

**B1 — Parse failure is indistinguishable from "scanner", and lands in bucket 2.**
`[4.6-a B1]` `[4.5-b B3]` `[code-review]` — three sources.
The bucket-2 predicate is `hard==1 && pct2xx==0 && br==0`. That exact triple is
also what an *unparseable line* produces. The draft used whitespace field `$9`
for status and `split($0,a,"\"")[6]` for UA; production does neither
(`lib/ingest.sh:75-93` takes the first 3-digit token *after* the request quotes,
and the UA from the **last** quote pair). A request path containing a space
shifts `$9` off the status; a common-log line has no UA quotes; an embedded `"`
shifts the UA field. Separately confirmed under bash: `pct2xx` used integer
division, so `ok2xx=4, reqs=1000` → `pct2xx=0` — a row a customer site really
served 4 times reads as "zero 2xx". And `uaempty` was computed, written to the
TSV, and then **not consulted in bucketing at all**.

**B2 — Config is never loaded, so the shared-egress ASN arm is dead, and cds1's
AS206092 cohort routes to bucket 2.** `[4.6-a B2+B3]` `[4.5-b M1]`.
The sharpest finding of the review. `bin/swatter:59-61` sources `common.sh` and
then calls `swatter_load_config` + `swatter_check_deps`. The draft did neither,
so `SWATTER_HAVE_DNS` was unset, so `swatter_asn_resolve` returns 1 immediately
(`lib/asn.sh:15`), so the ASN arm of `swatter_is_shared_egress` never fires
(`lib/asn.sh:151`). **cds1's `shared-egress-asns.txt` holds exactly one entry,
206092, and it is ASN-only — the CIDR file does not cover those exits** (verified
live: the 11 CIDR ranges are WARP v4/v6, PureVPN, VPN Consumer SG). That is the
cohort the 2026-08-11 sweep found and capped.

The full chain: those IPs cannot reach bucket 1 → a scanner-shaped one with
`abuseipdb:confidence100` satisfies the bucket-2 predicate → no human reads it →
it is permanently reported. **Against an address the enforcer itself would refuse
to perm.** And the reason hard-intel cannot save you here is the defect class this
repo already documented: a shared VPN exit legitimately earns maximum AbuseIPDB
confidence *because* many unrelated people use it.

The draft's comment claimed it "reuses swatter's OWN matchers rather than
reimplementing them." True of the function names, false of the behaviour — the
enforcer calls those matchers with config loaded and deps checked. Reusing a
function without reproducing its preconditions is not reuse.

**B3 — Not read-only. It writes ~600–1000 files into live `/var/lib/swatter`, and
can make Googlebot blockable for a week.** `[4.5-b B1]` `[4.6-a M1]`
`[security-review]` — severity taken as the highest assigned.
`swatter_is_never_block` always ends at `_swatter_is_good_crawler` for public IPs
(`lib/allowlist.sh:347-348`), which does `mkdir -p "${STATE_DIR}/intel/crawler"`
and writes a 7-day-TTL verdict file per IP (`:283-284`). Sourcing the libs is
inert; **calling them is not**. Worse than volume: a crawler whose forward-confirm
misses a round-robin A record gets `"no"` cached for 7 days, which makes
Googlebot/Bingbot blockable for that week. All of it racing the `*/5` scan.
`_swatter_csf_allow_file` also plants a `mktemp` that is never unlinked.

**B4 — The candidate IP is never validated before becoming a filename, a `dig`
argument, and an `awk -v` value.** `[4.5-b B4]` `[security-review]`.
`lib/asn.sh:133` states the precondition in the code: *"Callers MUST have
validated the IP already (the ASN cache key is the raw string)."* The draft did
not. A malformed row (`ip=../../../../tmp/x`) is a path-traversal **write as
root** through the crawler cache path. The right validator is
`swatter_is_valid_ip_or_cidr` (`lib/common.sh:570`) — the non-fatal one; the
`swatter_validate_ip_or_cidr` wrapper at `:606` calls `die` and would abort the
run instead of routing the bad row to human review.

**B5 — An interrupted run leaves a new partial `enriched.tsv` beside a STALE
`buckets.txt`.** `[4.5-b B2]`, verified in the draft.
`enriched.tsv` is truncated then appended; `buckets.txt` is written only at the
end. Kill mid-loop and the directory looks complete, with the *previous* run's
"audit these 30 IPs" sample sitting against a different list. Since bucket 2 is
sample-audited only, that is a silently wrong review.

## Majors

- **M1 — The browser-UA regex is not a "human" discriminator, and it is
  case-sensitive.** `[4.6-a M2]` `[4.5-b Minor 3]` `[gap]`. Production lowercases
  the UA first (`lib/ingest.sh:94`); the draft did not, so `mozilla/5.0` reads as
  "no browser". Sampling one real cds1 customer log turned up **Inoreader,
  FreshRSS, a named article feed, GroupMe and WhatsApp** link-preview fetchers —
  all legitimate, none matching the regex. Outlook autodiscover is a *documented*
  false positive in this repo already
  (`2026-07-27-ladder-confidence-floor-design.md:53`). The correct discriminator
  is the one the 2026-08-01 audit actually measured: **UA absent on every
  request** (43 of 63), not "UA doesn't look like a browser".
- **M2 — Domlog read errors are swallowed** (`2>/dev/null` on the whole pass), so
  a partial read looks complete: an IP whose only 2xx lived in the unreadable
  vhost still gets `have_traffic=1` with `ok2xx=0` → bucket 2. `[4.6-a M3]`
  `[4.5-b M5]`.
- **M3 — Output permissions rely on ambient umask.** Files are 0644 for the whole
  multi-minute run before the closing `chmod`; `buckets.txt` is never chmod'd at
  all; and the default `--out` is a sibling of the preview, so a preview under
  `/tmp` puts customer IP↔vhost mappings in a world-readable path. `[4.5-b M2]`
  `[security-review]`.
- **M4 — PTR is not forward-confirmed** (the scheme asks for it) **and is never
  used in bucketing**, so a failed lookup does not force human review. `[4.6-a M4]`
  `[gap]`.
- **M5 — `request_flood` is specified as bucket 3 but is not a veto on bucket 2.**
  `[4.6-a M5]`.
- **M6 — Serial cost at real scale**: ~1000 IPs × several lookups with 2s
  timeouts, worst case hours. `[4.5-b M3]`.
- **M7 — `304`/`206` are not counted as served.** `[gap]` — the first three lines
  of a real customer log on cds1 are `304`s. A human browsing with a warm cache
  serves mostly 304.

## Minors

`*-bytes_log` not skipped (ingest skips it); no `::ffff:a.b.c.d` unwrap; LIBDIR
precedence inverted vs `bin/swatter`; `--seed` default of 1 not applied when the
flag is absent (empty → `10#` → 0, benign); O(n²) per-IP scan of `traffic.tsv`;
the scheme's `decisions-<utc>.tsv` is never scaffolded.

## What both reviewers confirmed is correct

Worth recording so it is not re-litigated: the `stdout`+`rc` pairing for
`swatter_is_never_block` / `swatter_is_shared_egress` matches the production call
sites (`lib/score.sh:234, :260`); `set -uo pipefail` without `-e`; the seed's
`??????*` cap is the house numeric-knob idiom; the sqlite quote-escaping; a
missing/locked ledger returning `?` does **not** set `hard` (fails toward review);
`have_traffic==0` → bucket 3; the hard-intel glob genuinely matches the stored
`reason` strings (`lib/score.sh:701`, `lib/providers/*.sh`); and sourcing the
three libs does not itself flock, mkdir, or load config.

## The fix is a redesign, not a patch

B2 and B3 are **in tension**: the obvious fix for B2 is to call
`swatter_check_deps` like `bin/swatter` does, which switches ASN resolution on —
and that adds `${STATE_DIR}/asn/<ip>` writes, making B3 worse. So:

1. Call `swatter_load_config` (no writes) — this alone fixes the ignored `--conf`,
   `DOMLOGS_GLOB`, `STATE_DIR` and allow-file paths.
2. **Do not call `swatter_is_never_block`.** Check the operator allowlist with
   `_cidr_overlaps_file` directly (pure, no writes) and drop the crawler leg
   entirely — a verified crawler is exempted at scan time and therefore cannot be
   a ladder candidate, so the leg is unreachable for this input set; anything it
   would have caught falls to bucket 3, which is the safe direction.
3. For shared-egress, call `_cidr_overlaps_file` against the shared-egress CIDR
   file and resolve the ASN with a direct `dig` (no cache write), comparing
   against `shared-egress-asns.txt` locally. This reimplements the *composition*,
   never the CIDR/IPv6 matching — that stays swatter's.
4. **Invert the fail-open for classification.** `swatter_is_shared_egress` fails
   open by design so DNS cannot become an availability lever on the ladder
   (`lib/asn.sh:131-132`). For *enforcement* that is right. For *this* sort it is
   backwards: a lookup that could not tell must go to bucket 3, not fall through
   to the bucket-2 predicate.
5. Mirror `lib/ingest.sh` for status and UA parsing rather than field indices;
   require `ok2xx == 0` on the raw count and `ua_empty == reqs`; force bucket 3 on
   any parse anomaly, partial domlog read, or failed lookup.
6. `umask 0077` before creating anything; atomic `.partial` + rename for **both**
   output files; a `COMPLETE` trailer with expected-vs-actual row counts.
7. Validate every candidate with `swatter_is_valid_ip_or_cidr`; route failures to
   bucket 3.

## Disposition

**Not deployed. Not committed.** The draft is not in the repo deliberately — a
known-unsafe script in a public tree is a landmine, and the rewrite should start
from this review rather than from the flawed draft.

This is the same shape as the v2.15.0 incident recorded in `CLAUDE.md`, caught one
step earlier: tests-equivalent checks passed (`bash -n` clean, `shellcheck -S
warning` clean, the awk pass verified against fixtures), and none of that touched
a single Blocker above. The fixtures were written by the code's author and shared
its blind spots. Real data and a second model found everything.

---

# Round 2 — the rewrite, reviewed (2026-08-20)

The redesign above was implemented and re-gated. **Both models returned HOLD
again.** Round-1 B1/B3/B4/B5 were confirmed *actually* fixed (not merely
commented as fixed) — but round 2 found a new route to the same destination.

## The pattern worth naming

Three rounds of review have now found **three distinct mechanisms that end in the
same place**: a shared-egress address (cds1's ASN-only AS206092 cohort, or the
CIDR-only WARP pool) reaching bucket 2, where no human reads it, and being
permanently reported to AbuseIPDB — *against an address the enforcer itself would
refuse to perm.*

1. **Round 1:** the ASN arm never ran at all (config never loaded → `SWATTER_HAVE_DNS` unset).
2. **Round 2 `[4.5-b]`:** the ASN arm ran but parsed a multi-origin Cymru answer
   (`"206092 13335 | …"`) into the nonsense ASN `20609213335`, matching nothing.
3. **Round 2 `[4.6-a]`:** the ASN arm ran and parsed correctly, but a *missing or
   unreadable* `shared-egress-asns.txt` was indistinguishable from "this ASN is
   not listed" — and a rejected CIDR file likewise only disabled matching rather
   than forcing review.

Each was a different bug. All three had one shape: **an absence of evidence being
read as evidence of absence**, on the one predicate whose failure is
irreversible. That is the repo's own documented fail-direction rule
(`CLAUDE.md`: *"a lookup that could not read its evidence must never report
absence"*) being violated three ways in one file.

## Round-2 Blockers, and the fixes

- **`[4.5-b B1]` multi-origin ASN concatenation.** Production takes the first
  field before `|` and then *its first token* (`lib/asn.sh:40-42`); the rewrite
  stripped all whitespace instead. Fixed to mirror production exactly.
- **`[4.5-b B2]` publish not pairwise-atomic.** Two `mv` calls; a kill between
  them paired a new `enriched.tsv` with the previous run's `buckets.txt` — stale
  audit sample against a different list, the round-1 B5 failure wearing a new
  hat. Fixed by deleting the old report *before* publishing, so a crash leaves an
  obviously-incomplete directory rather than a quietly wrong one.
- **`[4.6-a B1]` "could not tell" only inverted for a failed `dig`.** The whole
  point of the rewrite, wired to exactly one of its several failure paths. Fixed
  with a single `se_evaluable` gate computed once per run from swatter's own
  `_swatter_shared_egress_cidr_usable` and `_swatter_shared_egress_asns_usable`:
  unless shared-egress is enabled **and** both arms are usable, no row may reach
  bucket 2 at all and every non-inert candidate goes to bucket 3. It also skips
  ASN lookups entirely in that case — there is nothing they could decide.

## Round-2 Majors folded in

- **`[4.6-a M1]`** `_inert_reason` returned early on a failed `mktemp`, skipping
  the operator-allow / monitoring / `csf.allow` / server-self legs for *every*
  candidate whenever `OPERATOR_IPS` was set. Production falls through. Fixed.
- **`[4.6-a M1]`** the crawler-omission *justification* was factually wrong:
  `swatter_is_never_block` runs at apply time (`lib/score.sh:232-237`), not at
  scoring, so a crawler whose forward-confirm failed *can* accrue temps and
  appear in the preview. The omission is still safe — a real crawler sends a UA,
  so `uapres > 0` and it cannot satisfy the bucket-2 predicate — but the comment
  is now corrected rather than left as a trap for the next reader.
- **`[4.5-b M3]`** an attacker-controlled PTR was passed straight back as `dig`
  argv, so a value like `-f/etc/hosts` becomes a flag and dig reads that file as
  root. Now charset-validated before it is ever an argument.
- **`[4.6-a M2]`** the domlog glob is filtered to regular files
  (`lib/ingest.sh:181-182`); one cPanel subdirectory otherwise tripped the
  degraded-read guard and collapsed the sort into a ~1000-row human review.
- **`[4.6-a M4]`** the ledger query uses `GROUP_CONCAT` so a same-`ts` dual-plane
  twin cannot overwrite a `request_flood` reason and silently drop its veto.
- Minors: case-insensitive `::ffff:` unwrap; `intel_ok` set correctly on a
  missing DB; `SHARED_EGRESS_ENABLE=false` now forces review rather than
  clearing rows.

## Also found by Claude, not by either model

- **The script requires bash 4+** (swatter's helpers use `${var,,}`,
  `lib/allowlist.sh:39`). An early smoke test ran under macOS `/bin/bash` 3.2,
  where that is a "bad substitution" error — and without `-e` the function limps
  on with an empty value, quietly weakening `_inert_reason`'s private/loopback
  match. A version guard now fails loudly. Worth recording because the test
  *passed* while silently skipping every lowercase path.
- **304 and 206 are successful deliveries.** The first lines of a real cds1
  customer log are `304`s — a human browsing with a warm cache. Counting only
  `2xx` as "served" understates delivery on exactly the rows that matter.
- **"No browser UA" is not "not a legitimate client."** One real customer log
  yielded Inoreader, FreshRSS, a named article feed, and GroupMe/WhatsApp
  link-preview fetchers, none matching a browser regex. The 2026-08-01 audit's
  actual measurement was *UA absent on every request* (43 of 63), which is what
  the predicate now uses.

## Status

Round-2 findings are folded in and each fix is verified against fixtures that
reproduce the failure: an unreadable ASN list moves the one bucket-2 row to
bucket 3 and empties bucket 2; a poisoned `/0` CIDR line does the same; a
request path containing a space is correctly seen as served; a malformed line
forces review; an invalid candidate never reaches `dig`.

**Round 3 is running.** This script does not run on cds1 until it clears.

---

# Round 3 (2026-08-20) — both models HOLD again, and the pattern is now the finding

Round 3 confirmed every round-2 fix landed (both passes checked them individually
rather than trusting the comments) and then found **two more Blockers, both
independently reported by both models** — the strongest possible agreement
signal. Both are now fixed and unit-tested.

## The two round-3 Blockers

**R3-B1 — the usability check and the matcher read the same file differently.**
`_swatter_shared_egress_asns_usable` is `grep` (`lib/asn.sh:121-125`), which sees
a final line with no trailing newline. `_asn_is_shared` used a bare
`while IFS= read -r line`, which does not. **cds1's ASN file holds exactly one
payload line — `206092`.** Hand-edit it without a trailing newline and the arm
reports itself usable while matching nothing, so `se_evaluable=1` and the one
cohort it exists to protect sails into bucket 2. Reproduced by both models and
again here. `lib/common.sh:616-621` documents this exact footgun on the CIDR
validator, in almost the same words: *"otherwise a poisoned last line … would be
silently DROPPED and the list would falsely pass."* Fixed with the house idiom,
in `_asn_is_shared` and in all four of this script's file-reading loops.

**R3-B2 — multi-origin Cymru answers were only half-consumed.** Round 2 fixed
concatenation by taking the first token, mirroring `lib/asn.sh:40-42`. But
mirroring production is the **wrong contract here**: enforcement takes the first
token and fails open (`lib/asn.sh:131-132`) because a missed ASN just means the
ban proceeds. In this sort a missed ASN means an irreversible report. A prefix
can have several origin ASNs, and `test/asn_test.sh:29-31` shows the production
shape `"13335 15169 | …"` — numerically 13335 sorts first, and 13335 is
*deliberately never listed*. So `"13335 206092"` parsed to `13335`, missed, and
cleared the row. Now every TXT RR and every origin token is checked; any
non-digit token makes the answer ambiguous and forces bucket 3.

## Round-3 Majors folded in

- awk's **exit status** was ignored — only stderr lines were counted — so a
  signal-kill left a truncated traffic file with an empty error log and rows
  classified on a partial read. Non-zero status now counts as a degraded read.
- `request_flood` was only a veto when it sat on the `MAX(ts)` row; an older
  flood under newer hard intel was invisible. Now queried across all history.
- The enforcer already stamps `shared-egress=… perm-capped` on capped actions
  (`lib/score.sh:264`) — free, authoritative, and previously ignored. It is now
  an inert veto, checked *before* any live rematch, so a DNS answer that
  disagrees with the ledger cannot undo it.
- `se_evaluable` was an AND-gate that disabled the **ASN** arm when the **CIDR**
  file was the one that died; production runs the arms independently
  (`lib/asn.sh:145-151`). Split: either arm can mark a row inert, but *clearing*
  a row for bucket 2 needs both.
- `ACCESS_LOG` was never scanned though ingest always reads it
  (`lib/ingest.sh:191`), so an IP whose only successes lived there read as
  "served nothing".
- `--conf` pointing at a missing file was a silent no-op (`swatter_load_config`
  sources only if `-f` and never returns non-zero, so the `|| die` was dead).
- The pass now prefers `gawk`, as ingest does (`lib/ingest.sh:19`).
- Output carries an explicit caveat that `served=0` means "nothing in the live
  logs", not "never served anything" — rotated logs are outside the scan while
  the preview window is 7–30 days.

## A latent bug in swatter itself, found on the way

**`_cidr_overlaps_file`'s IPv6 branch (`lib/allowlist.sh:151`) is a bare
`while IFS= read -r pfx`; the IPv4 branch is `awk`.** awk processes a final line
with no trailing newline; the bash loop drops it. So for *any* CIDR policy file
whose last line is IPv6 — `allow.cidr`, `cloudflare.cidr`, `shared-egress.cidr`,
`monitoring.cidr` — losing the trailing newline silently removes that range while
every validator still passes the file. The shipped `config/shared-egress.cidr`
ends with `2a09:bac7::/32`, and the code's own comments call the Cloudflare case
"the catastrophic case". **This is not fixed here — it is a swatter bug, tracked
separately.** This script defends itself by refusing to trust a policy file with
no trailing newline.

## The pattern, stated plainly

| Round | Mechanism reaching bucket 2 |
|---|---|
| 1 | ASN arm never ran (config never loaded → `SWATTER_HAVE_DNS` unset) |
| 2a | Multi-origin answer concatenated into a nonsense ASN |
| 2b | Unreadable/missing ASN list read as "not shared" |
| 3a | Usable-but-newline-less file: validator sees it, matcher does not |
| 3b | Multi-origin answer where the shared ASN is present but not first |

**Five distinct bugs, one shape, one destination.** Every one was an absence of
evidence being read as evidence of absence, on the single predicate whose failure
is irreversible. Three independent review rounds each found at least one, and no
round found the previous round's.

That frequency is itself the most important finding in this document, and it
raises a design question the fixes do not answer: **bucket 2 exists only to save
review effort, and it is where all of the irreversible risk lives.** A two-bucket
sort — inert vs. human — would eliminate this entire class by construction. The
cost is a larger human review; the benefit is that no amount of subtle evidence
mishandling can produce a permanent public accusation against an innocent
address. That trade is the operator's to make, and it should be made before this
tool runs, not after.

## Status

All round-3 findings are folded in and unit-tested (no-trailing-newline file →
match still hits; multi-origin with the shared ASN second → hits; neither shared
→ correctly misses; policy file without a trailing newline → arm marked unusable
and bucket 2 forced empty). The script is now committed at
`tools/gate-d/gate-d-enrich.sh`.

**It has NOT been re-reviewed since these fixes.** A round 4 is required before
it runs on cds1 — and note the process error worth not repeating: round-3 pass A
was reviewing the file while round-3 pass B's fixes were being applied to it, so
it reviewed a version that no longer exists. Freeze the target for the duration
of a round.

---

# Disposition (2026-08-20, owner call)

**Bucket 2 stays.** The round-3 section above argued for collapsing to a
two-bucket sort on the grounds that bucket 2 carries all the irreversible risk.
That argument over-weighted a risk that is already largely defused: the owner had
already decided to set `ABUSEIPDB_REPORT="false"` across the widen and its 48h
baseline. During exactly the window where a misclassification could occur, the
irreversible half of the consequence is switched off — a wrong sort costs a
reversible ban, not a permanent public accusation.

What replaces "delete bucket 2" is one cheap step, added to the widen procedure:
**run `swatter shared-egress-audit` and read what the widen actually permed,
before turning reporting back on.** That is the last point at which a wrong perm
is still free to fix, it takes minutes rather than a thousand rows, and it
catches the same class of mistake the bucket-2 machinery exists to prevent.

The five bugs were still worth finding — the script would otherwise have run
unattended with all of them live.

## Related fix, shipped separately

The IPv6 trailing-newline defect this review surfaced in `_cidr_overlaps_file`
was **not** limited to that one function. Six places in swatter read an
operator-editable file with a bare `while IFS= read -r`, silently dropping a
final line that lacks a trailing newline while every validator (awk- or
grep-based) still passes the file:

- `lib/allowlist.sh` — the IPv6 branches of `_ip_in_cidr_file` and
  `_cidr_overlaps_file`. Affects `allow.cidr`, `cloudflare.cidr`,
  `shared-egress.cidr`, `monitoring.cidr`. The code's own comment calls the
  Cloudflare case "the catastrophic case".
- `lib/asn.sh` — `HOSTING_ASNS_FILE` and `SHARED_EGRESS_ASNS_FILE`. cds1's
  shared-egress ASN list is a **single** operator-added line (`206092`), so
  losing it disables that arm entirely while `test-config` still reports it live.
- `lib/origin_lock.sh` — the Cloudflare range loader and the two allow/monitoring
  readers. In DROP mode a dropped range means legitimate edge traffic is
  firewalled off.

All six now use the house idiom `|| [[ -n "$line" ]]`, which
`lib/common.sh:618-621` already documented and used for exactly this reason.
`test/trailing_newline_test.sh` covers it and is mutation-verified: reverting the
`allowlist.sh` fix turns two cases red.

The `block_cf.sh` loops over `${STATE_DIR}/cf-rules.tsv` were left alone
deliberately — swatter writes that file itself and always terminates it.

## Gate result on the library fix

Reviewed by `grok-4.6` and `grok-4.5` before commit. **No Blockers on the idiom
itself** — both confirmed it is correct at all seven sites (it is seven, not the
six first claimed): at EOF the second `read` clears the variable, so there is no
stale re-iteration, and every loop body strips and `continue`s on empty. Four
Majors between them, all fixed:

- **The new test was theater.** It reimplemented the fixed read-loop inline
  instead of calling `swatter_is_shared_egress`, so reverting the `lib/asn.sh`
  fix left it green. It now drives the production matcher with a stubbed
  resolver and is mutation-red.
- **The origin-lock guard did not block the case its own comment named.**
  `swatter_is_valid_ip_or_cidr` accepts `104.16.0.0/1` — a truncated `/13` is
  syntactically valid. Shape checking alone was never going to close it; the fix
  is a prefix floor (`/8` v4, `/19` v6), and the floor is pinned by a test so a
  later "tighten it to /32" cannot drop the compiled `2a06:98c0::/29` fallback.
- **Validation was asymmetric across the origin-lock readers.** The preamble now
  validates too. The teardown deliberately does **not**, and says so: it must be
  at least as permissive as whatever installed the rules, or a range added by an
  older version becomes undeletable and lingers in INPUT.
- **The new floors were an unvalidated numeric knob in an arithmetic context** —
  the exact defect class this repo already has a written rule about, and the same
  shape as the v2.15.0 Blocker. `OL_MIN_PREFIX4=abc` aborted `_ol_load_ranges`
  under `set -u`, on a path that also runs from `_ol_preamble_family` after DROP
  may already be installed. Guarded per `lib/common.sh:639-641` and covered.

Worth stating plainly: three of those four were defects in the *fix* and its
*test*, not in the original code. A change small enough to feel obvious still
produced a knob that could abort the origin lock mid-apply.

Left deliberately: `lib/block_cf.sh`'s loops over `${STATE_DIR}/cf-rules.tsv`.
Swatter writes that file itself and always newline-terminates it, so only a
killed partial append or a hand-edit could bite — but `_cf_ref_exists` is awk and
*would* see such a line while the upsert/sweep loops drop it, which by that
file's own comment means "an unsweepable permanent ban". A defensible scope cut,
not a proof of safety.

---

# Round 4 (2026-08-20) — the fourth route, and why no review found the fifth

Both models HOLD again. This time they converged on one sentence, and pass A put
it best:

> the triple `se_enabled=1, se_cidr_ok=1, se_asns_ok=1` is **"both files passed a
> different parser"**, not **"this IP was matched by both arms."**

The `se_evaluable` gate added in round 3 proved a *weaker proposition* than the
one it needed to prove. Two concrete exploits of that gap:

- **The validator and the matcher speak different languages.**
  `_swatter_shared_egress_asns_usable` is `grep -qE '^[[:space:]]*[0-9]'`, so a
  documentation line like `1. Add your ASNs below` passes it — while the matcher
  strips whitespace to `1.AddyourASNsbelow` and can never equal an ASN. Arm
  reports healthy, matches nothing, AS206092 clears into bucket 2.
- **`_cidr_overlaps_file` returns 1 for "not in the file" AND for "awk failed".**
  Its IPv4 path is a separate awk process that the usability check never
  exercises. WARP v4 (`104.28.0.0/16`) is CIDR-only and its Cymru origin is
  13335, which the shipped ASN list *deliberately never contains* — so a
  successful ASN lookup returning 13335 is **false confidence**, and clearance
  rests entirely on that one ambiguous return code.

**The fix stops trusting validators and probes the actual matchers.** Take an
entry that is provably in each policy file and require the real matcher to find
it; a matcher that cannot match its own file is a broken arm, not a clean miss.
The probe deliberately uses the **last** entry, because the whole
trailing-newline defect class drops the final line — and because this script may
be pointed at an installed `/usr/local/lib/swatter` predating the library fix.

That probe also **subsumed and corrected an over-strict guard of my own**: round
3 had made a missing trailing newline mark an arm unusable. With a last-entry
probe that is both redundant and harmful — it disabled an arm that demonstrably
worked. Downgraded to a note.

Also folded in: the ledger history query (a full-table scan racing the `*/5`
scan's lock) now reports failure instead of returning empty and reading as "never
capped"; the MAX(ts) intel query is `dry_run=0`-filtered so report-mode activity
cannot supply the hard intel that skips human review; `_asn_of` honours dig's
exit status and queries an absolute name; the published pair is invalidated at
the *start* of a run, not just at publish; and the never-block files finally get
a poison guard — one over-broad line in `allow.cidr` would have marked every
candidate inert and reported "1000 inert, 0 to review" as a clean run. That last
one was found by the Claude-side sweep, not by either model.

## The finding that matters most, and it is not a bug

Round 4's Majors included, from both models independently: **no tests for this
script had ever been committed.** Rounds 1-3 claimed unit verification; that
testing was ad-hoc and never entered the tree. `test/trailing_newline_test.sh`
exercises `swatter_is_shared_egress` — a function this script deliberately does
not call.

So `test/gate_d_enrich_test.sh` now runs the real script end-to-end against
fixtures, with `dig` stubbed for determinism, one case per route every round
found, plus a positive control so the suite cannot pass by sorting everything to
human review. It is mutation-verified.

**Writing it immediately found a defect four review rounds had missed:**
`_probe_asn_arm` called `_asn_is_shared` before it was defined, so the ASN arm
was *always* broken and no row could ever reach bucket 2. Fail-safe — and it made
the tool useless, since every candidate would land in human review. Four rounds
of careful reading by two models did not catch it, because **not one of them ever
executed the script.**

That is the lesson worth keeping from this whole exercise. Adversarial reading
found five subtle logic defects that tests would likely never have caught. The
first test run found one that no amount of reading did. Neither substitutes for
the other.

## Status

Both awk dialects green under a non-UTC TZ; `gate_d_enrich_test: PASS=16 FAIL=0`.
The script has **not** been re-reviewed since these round-4 fixes.
