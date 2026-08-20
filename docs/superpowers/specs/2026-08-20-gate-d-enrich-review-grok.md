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
