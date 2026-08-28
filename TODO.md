# Swatter — TODO / parked items

## ✅ CLOSED — the fatal classifier could grade a fleet-wide outage GREEN

**Fixed in v2.14.0, deployed to cds1 2026-08-12 14:36 UTC.** The gate now counts
BREADTH — distinct accounts sharing one account-normalized signature, threshold
`ERROR_FATAL_FANOUT_ACCOUNTS=4` — alongside the existing depth count, and account
identity is the pair (source tag, `/home` path) so a wrong or constant tag cannot
collapse the fleet onto one key. Depth and the pattern/veto still match the RAW
signature, so the conjunct can only ever move a fatal toward genuine.

**Spec:** `docs/superpowers/specs/2026-08-11-fatal-scanner-correlation-design.md`
(rev 4, three adversarial rounds) · **plan:**
`docs/superpowers/plans/2026-08-12-fatal-fanout-gate.md` · **pre-ship review:**
`docs/superpowers/specs/2026-08-12-fatal-fanout-gate-pre-ship-review-grok.md`
(two Blockers found and fixed before deploy) · **sitrep:**
`docs/handoff-2026-08-11-fatal-classifier-false-green.md`.

Validated on cds1's real feed before the deploy: a 96h window holds two genuine
clusters that v2.13.0 graded GREEN — `get_locale()` across **5** accounts and the
Jetpack `ERROR_TYPE_REST` constant across **4** in 50 minutes. Both now grade RED.

**Watch on the first nightly runs:** the `get_locale()` cluster puts exactly 4
accounts inside a single 24h window — the threshold with no margin. A RED there is
the gate working. If the rate is wrong for this host, raise the knob (`0` disables
breadth); see "What a RED from cross-account fatals means" in `docs/RUNBOOK.md`.

Two limitations carried forward deliberately: per-account variance outside
`/home<N>/<acct>/` (a hostname in the message, a non-cPanel layout) keeps
signatures split and leaves the gate inert on that cluster; and a bot sweep across
4+ accounts grades RED, which is accepted — a sweep and a fleet bug are
indistinguishable in the error log.

## ✅ Release log — 2026-08-12 (v2.14.0 → v2.15.0 → v2.15.1)

Three releases in one day. At the time, cds1 ran **v2.15.1**; `bin/swatter`,
`lib/errors.sh` and `lib/report.sh` all sha256-matched the tag (verified
2026-08-13). **cds1 now runs v2.16.1** (`swatter --version`, 2026-08-20) — same
as `main` at `0a7c7f5`, so the perm-rate tripwire fixes are live.

- **v2.14.0** — the fan-out gate. See the CLOSED section at the top of this file.
- **v2.15.0** — outage corroboration. The errors plane reads the affected
  accounts' own domlogs, classifies who actually received the failure, and
  escalates the lamp to 🔥 "Outage" when an outside client did. `RPT_GRADE` stays
  `RED` deliberately: `ALERT_SMS_GRADES` is matched literally against it, so a
  grade named `FIRE` would have sent **no** SMS for the most severe status the
  tool can emit.
- **v2.15.1** — the fix-forward after the review v2.15.0 shipped without. One
  Blocker (`ERROR_CORROBORATE_MAX_SPAN` unvalidated in an arithmetic context
  aborts `swatter_errors_section` under `set -u` — no digest, no RED, no SMS, on
  exactly the night an outage exists) plus four Majors, including a timezone bug
  that made the new lookup match nothing on any non-UTC host. This is the
  incident that turned the `/grok` pre-ship review into a written gate; see
  `CLAUDE.md`.

**v2.16.0 (2026-08-13)** ships the WARP IPv6 pool in the *default* CIDR list plus
a test that the shipped config survives its own validator, and restores CI (red
since v2.15.0 on a shellcheck-version-only `SC2218`; `install/release.sh` runs no
shellcheck and no CI check, which is how two tags shipped red — **fixed
2026-08-13**: `release.sh` now refuses to tag unless every expected GitHub check
for the exact commit is green, and also runs CI's own lint command locally.
`--skip-ci-check` overrides, and is offered only for a red or unfinished build —
never for a failed query or an absent check, because a suggested override is how
a gate stops mattering).

**The repo default and cds1's live file now deliberately DIVERGE.** Repo ships **9**
ranges (IPv4 WARP + the eight v6 `/32`s). cds1 has **11**: those nine plus
`192.253.240.0/20` (PureVPN) and `194.5.82.0/24` (VPN Consumer SG), which are
locally observed and stay local. `install.sh` never overwrites the live file, so
the divergence is stable — but it also means a widened default never reaches an
existing host. Diff `.example` after any upgrade.

**Both post-deploy watch items are now CLOSED** — confirmed 2026-08-20 by reading
a real digest body (`swatter report 24h --print` on cds1, read-only).

- [x] **v2.14.0 fan-out gate — confirmed running.** The 08-20 digest prints a
      *"Scanner-induced FATALs (under both the repeat and account-spread gates —
      no outage signal)"* block holding two entries — `condodelsol`
      `get_locale()` and `kauaicontainer` `ABSPATH` — while a third, unrelated
      fatal passed through and graded the report RED. The gate demonstrably ran,
      separated scanner noise from a genuine fatal, and did not blanket-suppress.
      Residual, deliberately not carried as a checkbox: the specific zero-margin
      case that prompted the watch — `get_locale()` across exactly 4 accounts in
      one 24h window — has not recurred, so the threshold edge itself is still
      unexercised. Nothing to do unless it fires.
- [x] **v2.15.1 corroboration — confirmed on live data.** The 08-20 digest
      carries the evidence line verbatim: *"1 served failure(s) here: 1 to
      outside clients, 0 to the server itself (wp-cron or a loopback call), 0 to
      known bots, 0 with no user agent. Someone outside saw this."* That
      classification is what escalated the lamp to 🔥 and fired the SMS. The
      domlog lookup, the per-account classification and the escalation are all
      proven end-to-end.

**What the 08-20 RED actually was — a false alarm with a clean cause, worth
recording because the next one will look identical.** The genuine fatal was
`php/sandpointlife`: `plugin.php:26` requiring `class-wp-filter-sentinel.php`,
which does not exist in any WordPress before 7.1. That reads exactly like a core
file injection, and it isn't one — the file is genuine 7.1 core
(`final class WP_Filter_Sentinel {}`, `@since 7.1.0`), `version.php` now reads
`7.1`, and `plugin.php`, `version.php` and the sentinel all carry mtime
`2026-08-20 01:25:06`, the same second as the fatal. It is the WordPress 7.1
auto-update mid-flight: the new `plugin.php` landed before its new sibling, and
one outside request fell into a seconds-wide window. Corroboration was right that
someone outside saw it; there was nothing to fix. **A core auto-update is a
recurring source of one-request 🔥 REDs** — check file mtimes against the fatal's
timestamp before treating a missing-core-file fatal as either an outage or an
injection.

## A failed send spends the alert's dedup key — PARKED 2026-08-20 (owner call)

**Owner decision 2026-08-20: parked, not scheduled.** The bug is real and the
analysis below stands, but firing it requires a delivery failure to coincide with
the exact minutes an alert condition first trips — long odds, and the payoff is a
retry of an alert whose underlying condition is still visible in the digest, the
decision log and `report.log`. Not worth changing the return contract of four
functions that carry every alert this tool sends. **Revisit if a delivery failure
is ever actually observed** — a non-2xx Twilio line or a missing `alerts: SMS
sent` on a night that graded RED. Until then this is a known, accepted gap.
Twilio itself is configured and demonstrably working: `report.log` shows
`alerts: SMS sent … via Twilio (201)` on both 2026-08-18 and 2026-08-20.

**Spec:** `docs/superpowers/specs/2026-08-15-notify-delivery-failure-suppresses-retry-design.md`
(rev 1). Nothing implemented yet — the spec stays ready so the work is cheap to
pick up if the trigger above ever lands.

`lib/notify.sh` writes the rate-limit marker BEFORE sending, and no channel reports
whether it succeeded — every `_notify_*` returns 0 for "sent", "failed" and "not
configured" alike. A total delivery failure therefore spends the key for the full
`ALERT_REPEAT_TTL` (6h) while the condition is still live.

**All three ops-critical alerts route through it** — fail-closed (`lib/score.sh:641`),
circuit breaker (`:786`), perm-rate tripwire (`:814`). The **circuit breaker is the
worst case and it predates everything recent**: its key is the literal string
`circuit_breaker`, so a Twilio outage at the moment `MAX_BLOCKS_PER_RUN` trips buys 6h
of silence while the scan is actively dropping blocks.

**Why now:** the perm-rate key used to be hour-bucketed, which accidentally retried a
failed send on the next hour's new key — a side effect of the very bug that was
producing alert spam. Stabilising the key (v2.16.1 branch) removed the accident and
left this exposed. It did not create it.

**The design is not novel** — `lib/alerts.sh` already does this correctly for the
nightly status SMS, records the marker only inside `if swatter_send_sms …; then`, and
states the rule in a comment: *"a failed send must not suppress the retry."* This is
making `notify.sh` follow a convention its sibling already follows. The subtle part —
"intentionally disabled" must count as success, not failure — is already solved there.

**Shape:** three-state channel returns (0 sent / 1 failed / 2 not configured); an
`attempt <epoch>` marker on a short `ALERT_ATTEMPT_TTL` (~one scan interval) promoted
to `sent <epoch>` on the full TTL by the background subshell when any channel
succeeds. Sends stay backgrounded so the `*/5` scan is never delayed.

⚠️ **The migration is the risky half.** Existing markers are empty files. They must
read as `sent`, or the upgrade lapses every live suppression on every host within 5
minutes and the tool's first act after an alert-spam fix is a burst of alert spam.
§2.3 and test 4 in the spec.

Found by `grok-4.6` + `grok-4.5`, both rounds of the perm-rate review; deferred there
on scope (it changes the return contract of four functions used by every alert), not
on merit. Retire the CHANGELOG's "Known and deliberately out of scope" paragraph in
whatever commit lands this.

## ⏭️ NEXT PICKUP: gate D

**Everything is unfrozen and deployed as of 2026-08-11.** cds1 runs **v2.16.1**
(confirmed 2026-08-20; this line read "v2.15.1" until then, and "v2.13.0" before
that — see the release log below), the
shared-egress cap is live, the WARP/shared-VPN cohort is remediated **for IPv4
only** (the 2026-08-13 ASN sweep found WARP IPv6 was never capped — see the
consumer-VPN section), and **both** publication arms are on: `SWARM_PUBLISH="true"` and `ABUSEIPDB_REPORT="true"`
(flipped 13:05 UTC; conf backup `swatter.conf.bak-2026-08-11-abuseipdb`).

Pre-flight at the flip, all clean: `pending_blocks WHERE action='perm'` = 0;
`shared-egress-audit` clean over 1,073 perm bans with both arms live;
`ABUSEIPDB_REPORT_MIN_ACTION` unset → shipped default `perm`, so **temps are
never reported** — which, with the cap, means shared-VPN addresses cannot reach
AbuseIPDB by either route. Perm rate at the flip: 67 primary legs / 7d ≈ 9.6/day.

- [x] **Confirm the first real report — CONFIRMED 2026-08-11.** First submission
      landed **17:00:17 UTC** (`34.66.85.241`, `critical_badpath`). Three perms
      have been placed since the flip and **all three reported cleanly** —
      `34.66.85.241` 17:00, `20.194.31.226` 19:05, `34.53.54.51` 19:30. No
      failures, no `429`, no auth error. The two earlier perms that day (03:15,
      12:05) predate the flip and correctly have no marker.

      **The verification command in the old note was wrong — do not reuse it.**
      `grep -i abuseipdb swatter.log` returns only *intel-enrichment* lines
      (`intel=abuseipdb:confidenceNN`) and never a report line, because the
      success path logs **nothing at all**. swatter.log contained zero lines
      matching `report` in any case. The real check is the marker dir plus the
      failure grep, and it only works **as a pair**:
      ```bash
      ls /var/lib/swatter/reported/                                    # a file = that IP reported OK
      grep 'abuseipdb report .* failed' /var/log/swatter/swatter.log   # empty = no failures
      ```
      Why the pair: on curl failure `lib/report_abuseipdb.sh` runs `rm -f
      "$marker"` so the next perm retries — therefore a **surviving marker means
      curl exited 0**, not merely "attempted", while a **missing** marker is
      ambiguous (never attempted *or* failed-and-cleared). Only the empty
      failure-grep disambiguates. The WARN does reach the log: `log_warn` →
      stderr (`lib/common.sh:489`) → cron's `>> swatter.log 2>&1`; `LOG_LEVEL`
      is `info` so warn passes, and the append-to-file redirect stays valid for
      the backgrounded POST subshell after the parent scan exits.

      Gotcha for later: the marker is **never removed on success** and nothing
      prunes the dir, so it grows one file per reported IP forever. It is an
      append-only ledger — do not read a file count as "recent activity".
      `ABUSEIPDB_REPORT_TTL` is unset → default 900s.
- [x] **Gate D review — DONE 2026-08-28.** All 1,118 candidates dispositioned
      (`/root/gate-d-review/round-20260828T123856Z/decisions.tsv`). Bucket 2
      collapsed into review: its "no UA on ANY request" predicate was false for
      4 of 7 once the ROTATED archive was audited, not just live logs.
- [ ] **THE WIDEN IS BLOCKED — do not run step 4 yet.** The review found two
      false positives, both real people, and the second is an active fleet-wide
      class: broken srcset markup makes browsers request the whole srcset value
      as one URL (always 404). 17,829 requests, **8,767 distinct client IPs**,
      35 sites, still running ~2,100/month; **19 real residential visitors are
      already temp-blocked**, six by `rule=error_burst`. Widening 7d -> 30d gives
      them four times as long to reach the 3-temp bar, and a perm is also a
      permanent public AbuseIPDB accusation against a client's own visitor.
      Swatter-side fix is committed (branch
      `fix/gate-d-round5-and-srcset-false-positives`, `a729dd8`) but **NOT
      deployed**; the WordPress markup bug is untouched.
      **Read `docs/handoff-2026-08-28-gate-d-review-complete.md`.**

> **2026-08-28: the review is COMPLETE and the widen is BLOCKED. Read
> `docs/handoff-2026-08-28-gate-d-review-complete.md` FIRST** — it supersedes
> the 08-20 handoff for everything through step 3 and explains why step 4 must
> wait. The 08-20 document below is still correct for step 4 itself.
>
> **Picking this up on the 26th? Read
> `docs/handoff-2026-08-20-gate-d-widen.md` first.** It is the single
> orientation document: the sequence, the commands, and the traps that will
> bite. This section is the working record behind it.

### 📅 Run-up plan, 2026-08-20 → the floor

Written 2026-08-20 (Thu). **The floor is Wed 2026-08-26 22:40 UTC = 15:40 PDT.**
The organising rule: the two freshness-sensitive checks and the preview must be
run *after* the floor, so everything schedulable early is decision work, and
everything after the floor is measurement then review. Do not pull the fresh runs
forward to "get ahead" — a preview generated before the floor is exactly the
saved list the gate says never to review.

**Thu 08-20 → Sun 08-23 — do now; nothing here is freshness-sensitive**

- [x] **AbuseIPDB freeze question — DECIDED 2026-08-20.** Re-freeze
      `ABUSEIPDB_REPORT="false"` across the widen and its 48h baseline; swarm
      stays on. Rationale and the asymmetry behind it are in the ⚠️ block of the
      gate D section. **Nothing to do today** — the flip is step 1 of the widen
      block below, because until the window is actually 30d there is no risk to
      cover and an early flip only forfeits ~21 legitimate reports/day.
- [x] **Re-baseline the pre-2026-07-27 `swatter top` triage notes — DONE
      2026-08-20; nothing needed correcting.** Full audit and the re-baselined
      picture are in the precondition further down. Two things worth carrying
      forward: `top` is now entirely settled cases (all 20 rows `PERM=1`), so
      triage the review from `escalate-preview`, not `top`; and the same run
      surfaced that the candidate population has grown **1.6× in 19 days** at
      window=7 — see the ⚠️ sizing note, the review is likely bigger than 615.
- [x] **How the review gets recorded — DECIDED 2026-08-20.** Scheme below.
- [x] **Review rule corrected 2026-08-20** — "VPN exits get *allowlisted*" was
      wrong for shared exits and would have had the review never-blocking a
      consumer VPN pop for every subscriber on it. See "allowlist vs
      shared-egress" in the scheme. README and RUNBOOK were checked and were
      already correct; the bad wording was only in this procedure.

**Still open in this block — two, and both want settling before Wednesday:**

- [ ] **Who does the bucket-3 judgement.** Not mine to settle. The enrichment,
      the sort and the sample audit can be automated; the customer-identity calls
      need someone who knows the customers. If that is one person, the calendar
      after 08-27 is theirs, not the floor's.
- [ ] **Build the enrichment + sort tooling — FIRST DRAFT WRITTEN AND KILLED AT
      THE GATE 2026-08-20. Needs a rewrite, not a patch.**
      **Review:** `docs/superpowers/specs/2026-08-20-gate-d-enrich-review-grok.md`
      — `grok-4.6` + `grok-4.5`, both **HOLD**, five Blockers. The draft is
      deliberately **not committed**: a known-unsafe script in a public tree is a
      landmine, and the rewrite starts from the review, not from the draft.

      The one worth carrying in your head, because it is this repo's own defect
      class wearing new clothes: the draft never called `swatter_load_config` /
      `swatter_check_deps`, so `SWATTER_HAVE_DNS` was unset, so
      `swatter_asn_resolve` returned 1 every time, so the **ASN arm of
      shared-egress never fired**. cds1's `shared-egress-asns.txt` holds exactly
      one entry — **206092, ASN-only, not covered by the CIDR file**. So the very
      cohort the 08-11 sweep found and capped could not reach bucket 1, and a
      scanner-shaped member with `abuseipdb:confidence100` lands in bucket 2,
      which no human reads — an irreversible public report **against an address
      the enforcer itself would refuse to perm**. Hard intel cannot save you
      there: a shared VPN exit earns maximum AbuseIPDB confidence precisely
      *because* many unrelated people use it.

      Two structural lessons for the rewrite, both in the review's "the fix is a
      redesign" section:
      - **Reusing a swatter function without reproducing its preconditions is not
        reuse.** The enforcer calls those matchers with config loaded and deps
        checked; the draft called the same names in a different world.
      - **The enforcement fail direction is the WRONG one for this sort.**
        `swatter_is_shared_egress` fails open so DNS cannot become an
        availability lever on the ladder — correct for banning, backwards for
        classifying. A lookup that could not tell must go to bucket 3.

      Still true and still the reason to do this before the floor: written on
      08-26 it is an hour of pressure on the one day that matters. Test against
      the **window=7** preview already captured (201 rows, 2026-08-20) — not the
      gate's list, so it breaks no rule as a fixture.
      ⚠️ **It rides `/grok` again before it runs on cds1.** The first draft was
      `bash -n` clean, `shellcheck -S warning` clean, and verified against
      hand-written fixtures — and not one of those touched a single Blocker. The
      fixtures shared the author's blind spots, which is the whole reason a second
      model reads it.

#### Gate D review — recording scheme

**Where it lives: `/root/gate-d-review/` on cds1, root-only, never committed.**
The working set maps customer IPs to vhosts, and this is a public repo — same
call as the 2026-08-04 redaction. The repo gets aggregates and method; the
concrete rows stay on the box beside the allowlist and the ledger they came from.

Four files, timestamped to one review round:

- **`preview-<utc>.tsv`** — the raw, post-floor `escalate-preview --window 30`
  output, four columns as documented (`ip`, `temps_prior`, `last_temp_utc`,
  `status`). **Immutable — never edited.** This is what makes "which list was
  reviewed" answerable later, and it is the gate's fresh list; editing it in
  place destroys both properties.
- **`enriched-<utc>.tsv`** — preview columns plus ASN, forward-confirmed PTR, top
  vhost, 2xx fraction, UA presence/rotation, intel verdict, shared-egress match,
  already-allowlisted flag.
- **`decisions-<utc>.tsv`** — append-only: `ip, bucket, verdict, reason,
  reviewer, utc`. Verdicts: `allow` / `ban-ok` / `defer`.
- **`NOTES.md`** — names the authoritative preview file and records the
  sample-audit result.

**Three buckets, sorted mechanically, and the sort fails toward human review.**

1. **Inert** — already allowlisted, already shared-egress capped, forward-confirmed
   crawler, RFC1918/loopback. These *cannot* perm. Count them; do not review them.
2. **Corroborated-hostile** — hard external intel (`spamhaus:drop`,
   `abuseipdb:confidence100`) **and** zero 2xx **and** no browser UA. Not reviewed
   row by row. Instead **sample 25–30 at random and audit them properly**, exactly
   as the 2026-08-01 `scanner_profile` audit did (63 audited from raw domlogs, 0
   false positives). **One false positive in the sample collapses the whole bucket
   into bucket 3.**
3. **Human review** — everything else, *plus anything the enrichment could not
   classify*: residential or mobile ASN, a browser UA, any 2xx, appearance on a
   customer vhost, weak or absent intel, or `request_flood` as the decisive rule.

Unclassifiable never lands in bucket 2. That is the same fail direction the rest
of this plane uses — toward the louder reading, which here means a human looks.

**Why this is a defensible reduction and not a corner cut**, from measurements
already in this file: the backlog is **97% hard-corroborated**, and false
positives cluster precisely where corroboration is *absent*; all **five** known
FPs in the tool's history came from `request_flood`, whose lifetime perm record is
**0 for 2**; and the one cohort ever audited exhaustively (63 `scanner_profile`
rows) held zero. So bucket 3 should be tens of rows, not a thousand. **The job is
a ~1,000-row sort and a ~50-row judgement** — size the calendar against the sort
being cheap and the judgement being slow, not the reverse.

**Allowlist vs shared-egress — the review rule's old wording was wrong.**
Corrected 2026-08-20. It used to read "anything resembling NAT/CGNAT, mobile
carrier, VPN exit, crawler, or customer gets **allowlisted** first." Sorting them
out first is right; allowlisting all of them is not. `swatter allow` writes a
**never-block**, and a never-block on a *shared* exit is a free pass for everyone
else riding it — this file already makes exactly that argument about
`monitoring.cidr` ("every CIDR here is a never-block, so ranges for services you
do not use are free passes for anyone on them"). The wording predates the
shared-egress cap, and the 2026-08-11 work **reversed this very mistake**: 7
`--perm-allow` never-blocks were removed and replaced with shared-egress, leaving
those IPs "not never-block but *are* shared-egress, i.e. still bannable, just not
permanently."

Disposition by class:

- **A single identified endpoint** — a customer's office or home IP, a site
  owner, an operator box: **`swatter allow`**. A never-block is correct because
  the address maps to one accountable party. This is what the 10 live allowlist
  entries are.
- **A shared exit** — consumer VPN, CGNAT, mobile carrier NAT, WARP:
  **shared-egress, never allowlist.** Add the range to
  `/etc/swatter/shared-egress.cidr` (or the ASN to `shared-egress-asns.txt`) so a
  matching perm becomes a ladder-max temp, unpublished, while the address stays
  bannable. Validate before it lands — **one over-broad line disables the entire
  CIDR arm silently**, including the IPv4 WARP protection already in the file.
- **Verified crawler** — neither. Forward-confirmed rDNS already exempts it
  (`exempt:verified-crawler` in the digest); adding a never-block range for a
  crawler is the `monitoring.cidr` mistake in a different hat.

Worked example, checked 2026-08-20: the operator's own egress is
`unn-…​.datapacket.com`, **AS212238** — a shared consumer VPN exit. Allowlisting it
would never-block every other subscriber sharing that pop. It needs no action
today (zero ledger rows, zero actions, and its `/24` has zero offenders; the only
perm anywhere in `149.22.x` is a different `/24`, dated 2026-06-27), but it is the
exact shape the review will hit repeatedly — the gate D interaction item alone
counts **209** WARP IPv6 addresses.

**Applying a verdict — the order matters and getting it backwards is silent:**

- `allow` on a candidate carrying **no live ban** → `swatter allow <ip> "<who> -
  <why> - verified <date>"`. That matches the 10 existing entries' format; the
  command appends its own UTC stamp and is idempotent (`already allowed:`).
- `allow` on a candidate that **currently holds a temp** → **`swatter unblock`
  first, then `swatter allow`.** The unblock is what resets the ladder count (the
  2026-07-27 precedent, and README's "`unblock`, not `allow`, clears a false
  positive"). Allow alone leaves the count intact and the IP simply re-escalates.
- Verify every unblock on **both planes** — `swatter list perm`, `swatter list
  cf`, `csf -g <ip>`. The exit code is not enough (`swatter_store_unblock` runs
  before the failure check, so a partial backend failure still clears
  `offenders.perm` and *looks* remediated).

**Resuming:** `decisions-<utc>.tsv` is append-only and keyed by IP, so a session
resumes by diffing enriched against decided. Nothing depends on remembering where
you stopped — which matters, because this is explicitly a multi-session job.

**What comes back into the repo when the review closes:** bucket counts, the
sample-audit result, how many IPs were allowlisted, and any rule change the review
implies. No customer IPs, no vhost mappings.

**Mon 08-24 → Wed 08-26 (before 15:40 PDT) — hold**

- [ ] Nothing to run. Keep reading the nightly digest (11:00 UTC / 04:00 PDT).
      A RED in this window is almost certainly unrelated to gate D — check
      whether the perm rate moved before treating it as one.
- [ ] If any knob drifts, note it. Gate D's baseline assumes today's live values:
      `window=7d`, `REPEAT_N=3`, `crit-single=4`, tripwire `5/run 70/day`.

**Wed 08-26, after 15:40 PDT — the floor opens**

- [ ] Re-run the unstamped-temp check with the **narrowed, pre-stamp-era**
      definition (query and reasoning in limit 3 of the floor section). Expect the
      07-21..27 block to have aged out, and expect post-v2.11.0 intel-driven rows
      to remain — those read as negatives, not as a floor slip.
- [ ] Re-run the `scanner_profile` audit fresh, from raw domlogs — not from
      swatter's own evidence JSON, which folds UA and paths.
- [ ] `swatter escalate-preview --window 30`, fresh.

**Thu 08-27 onward — review, then widen**

- [ ] **The 615-row human review** (ASN, PTR, customer mapping, plane). Sort
      NAT/CGNAT, mobile carrier, VPN exit, crawler and customer out *first* — but
      **allowlist is not the disposition for all of them**; see "allowlist vs
      shared-egress" below. This is a multi-session job at 4.9× the window=7
      population — do not compress it to fit a date. The floor is a floor, not a
      schedule.
- [ ] **Step 1 — freeze AbuseIPDB, BEFORE the knob change.** Back up
      `/etc/swatter/swatter.conf` (dated `.bak`, per the 2026-08-04 precedent),
      set `ABUSEIPDB_REPORT="false"`, confirm with `swatter test-config` that the
      line reads `abuseipdb reporting: off` (that is the exact string —
      `bin/swatter:457`; anything other than the literal `true` renders `off`).
      Config is read per-process, so
      it takes effect on the next `*/5` scan; no cron hold. Leave
      `SWARM_PUBLISH="true"` alone — toggling swarm would flush its whole
      deferred backlog on re-enable. Do this first: a widen that runs even one
      `*/5` with reporting live can publish a false positive that cannot be
      retracted.
- [ ] **Step 2 — only after the review AND step 1:** set `REPEAT_WINDOW_DAYS=30`.
- [ ] Watch the first 48h to establish gate D's **own** rate baseline. Judge
      against that, never against gate C's band. `PERM_RATE_ALERT_*` only
      notifies — a silent tripwire is not a green light, and ladder perms keep
      landing every `*/5` while you wait.
- [ ] **Before restoring reporting — run `swatter shared-egress-audit` and read
      what the widen actually permed.** This is the cheap safety net that makes
      the bucket-2 risk acceptable, and it is the LAST point at which a wrong
      perm is still free to fix. While `ABUSEIPDB_REPORT` is false, a
      misclassified shared exit costs a reversible ban; once reporting is back
      on, the same mistake is a permanent public accusation with no delete API.
      Minutes of work, and it catches the whole class the review scheme's
      bucket 2 is designed around. Owner call 2026-08-20: keep bucket 2 rather
      than collapsing to a two-bucket sort — the freeze already removes the
      irreversible half of the risk during exactly the window it exists in.
- [ ] **After the 48h baseline reads clean AND the audit is clean — restore
      `ABUSEIPDB_REPORT="true"`.**
      Confirm with `test-config`. Nothing replays: the arm has no cursor, so the
      perms placed during the freeze are simply never reported, which is the
      accepted cost of the decision. If the baseline does *not* read clean, the
      freeze stays on through the back-out.
- [ ] Back-out, if needed, is `swatter rollback-ladder --since <ts>` — **never** a
      config revert, which does not undo bans already placed. Verify every unblock
      on both planes; the exit code is not enough.

None of this ships code, so the `/grok` gate does not bind the widen itself. It
binds immediately if any of it turns into a code change.

### Deployed 2026-08-11 (v2.13.0) — do not redo

- Released `v2.13.0` (GitHub + GitLab), surgical-scp deployed under a cron hold;
  all 7 code files sha256-verified against the tag. Backups on cds1:
  `*.bak-9ac0c31-20260811-125417` (bin + 6 libs).
- **`/etc/swatter/shared-egress.cidr` + `shared-egress-asns.txt` were installed
  too** — these are load-bearing; a libs-only scp leaves the policy enabled and
  capping nothing. `swatter test-config` now reports both arms.
- **`206092` added to cds1's `shared-egress-asns.txt`** (cds1-local per the
  design; the shipped default is entry-free). This is what activates the ASN arm
  — without it the 3 AS206092 IPs below would have been left unprotected.
- **12 shared-VPN perms swept** via `shared-egress-audit --fix`, all verified on
  both planes: the 9 known WARP IPs, plus **3 AS206092 IPs the ASN arm surfaced**
  (`158.173.77.34`, `45.157.112.60`, `45.157.112.81`, permed 07-09/07-20/07-24 —
  already published to the swarm before the freeze, so unblocking does not
  retract those hub entries; `/purge` is all-or-nothing and was not used).
- **The 7 `--perm-allow` never-blocks from the morning were removed** from
  `allow.cidr` (17 → 10) and `csf.allow`. Verified: all 7 are now
  *not* never-block but *are* shared-egress, i.e. still bannable, just not
  permanently. Backups: `allow.cidr.bak-20260811-preclean`,
  `csf.allow.bak-20260811-preclean`.
- Verified live on prod: CF edge ranges (`162.158.0.0/15`, `104.16.0.0/13`) are
  never-block as CIDR **tokens** for the first time, and
  `import-bans 104.28.0.0/16` is REFUSED with 0 applied.

### What the 08-10/11 unfreeze actually did

- Backlog re-sized fresh: **264**, not the ~290 the old note predicted. Growth
  ran **~7.7 IPs/day** since 08-08, not the 21/day extrapolated from the June
  regime — **do not reuse the 21/day figure.**
- `pending_blocks WHERE action='perm'` = 0; zero overlap with `allow.cidr` /
  `OPERATOR_IPS`; all four publish gates dropped nothing.
- Rule mix (primary legs): scanner_profile 150, critical_badpath 94,
  high_badpath_repeat 18, error_burst 2, **request_flood 0** (the only two ever
  were the 08-08 FPs, now cleared).
- 7 IPs allowlisted + unblocked before the flip (264 → **257**) — see below.
- `allow.cidr` is now **17** entries (was 10).

**Methodology change, and the reason for it — do this every time from now on:**
the 08-08 review filtered to weakly-corroborated rows and whois'd only those. It
passed `45.157.112.169` and `158.173.77.149` as "defensible" on *confidence
numbers alone*; whois was never run on them, and both turned out to be consumer
VPN exits. **The corroboration filter cannot find this class of problem** — a
shared VPN exit legitimately earns high abuseipdb confidence. Instead, profile
**the whole backlog by ASN** (Team Cymru DNS bulk lookup:
`dig +short <reversed-ip>.origin.asn.cymru.com TXT`, then
`dig +short AS<n>.asn.cymru.com TXT`). It is free, unrated, runs over hundreds of
IPs in a couple of minutes, and it is what surfaced both VPN cohorts. Then whois
the weak set on top. **whois beats PTR** — Automattic had no PTR at all, and 4 of
the 7 cleared this round had none either.

**SQL traps (still true, still bite):** dual-plane/plane-upgrade legs **share a
`ts`** with the primary leg, so a naive `r.ts = MAX(a.ts)` join double-counts;
and in SQLite `a.action="perm"` resolves to the **`offenders.perm` column**
(double quotes = identifier) and silently returns 0 rows. Single-quote SQL
literals. The delta query is:
```sql
SELECT a.ip FROM actions a JOIN offenders o ON o.ip = a.ip
 WHERE o.perm=1 AND a.action='perm' AND a.dry_run=0
 GROUP BY a.ip HAVING MAX(a.ts) > <cursor>;
```
Note `MAX(a.ts) > cursor` also pulls in IPs whose **primary perm predates the
cursor** but that took a `plane-upgrade` leg after it — `103.148.104.75` was
permed 2026-06-25 and entered the backlog on an 08-09 upgrade row. "Oldest ts =
go-live anchor" does **not** mean every ban in the delta is post-go-live.

**Done 2026-08-08 (do not redo):** the two customer-facing FP bans cleared —
`192.0.91.143` (Automattic/Jetpack) and `202.8.43.217` (Ahrefs crawler), both
`allow` + `unblock --perm-allow`, verified on both planes; `monitoring.cidr`
closed as a gate D precondition; `request_flood` characterized (below).

## Cloudflare WARP + shared consumer VPN exits (opened 2026-08-11)

**Found during the unfreeze review; the publishable slice is handled, the ban
policy is not.**

`104.28.0.0/16` is Cloudflare's **consumer WARP egress pool** (the 1.1.1.1 app) —
AS13335, but **not** in Cloudflare's published edge IP list and therefore **not in
`cloudflare.cidr`**, which covers `104.16.0.0/13` + `104.24.0.0/14` (104.16–
104.27) and stops one block short. That is arguably by design: `cloudflare.cidr`
exists to keep us from banning the reverse-proxy **edge**, and WARP is a client,
not the proxy. But the collateral question is independent of that intent.

Lifetime in `104.28.0.0/16` on cds1: **77 distinct IPs temp-banned, 13
perm-banned.** Evidence tier is genuinely strong — most carry
`abuseipdb confidence100` + `rule=critical_badpath` at score 91. These are not
detection false positives; someone really did probe critical paths. The problem
is that the source IP is shared by a large ordinary-user population.

**Cleared 2026-08-11 (allowlist + `unblock --perm-allow`, both planes verified —
`offenders.perm=0`, no `plane_blocks` row, no `cf-rules.tsv` ref, no `csf.deny`
line, present in `csf.allow` + `allow.cidr`, `csf -g` deny hits 2 → 0):**

- `104.28.208.56`, `104.28.214.118`, `104.28.240.187`, `104.28.254.16` — WARP.
- `45.157.112.64`, `45.157.112.169`, `158.173.77.149` — **AS206092**, netname
  `PARIS-FR-45-157-112-0`, org *"VPN Consumer Paris, France"* (F.N.S. Holdings,
  CY). Consumer VPN exit.

**Still open — 9 WARP IPs remain live perm bans** (they predate the publish
cursor, so they were never in the backlog and publication did not touch them):
`104.28.196.52`, `104.28.196.57`, `104.28.201.181`, `104.28.203.54`,
`104.28.208.49`, `104.28.211.186`, `104.28.214.112`, `104.28.217.137`,
`104.28.219.190`. Each is customer-facing today: a WARP user assigned that egress
IP cannot reach any customer site.

**Policy DECIDED 2026-08-11 — option 3 (temp-only), designed and reviewed.**
Spec: `docs/superpowers/specs/2026-08-11-shared-vpn-egress-policy-design.md`
(revision 2); adversarial review beside it as `…-design-review-grok.md` (two
grok-4.5 passes, both EXECUTE-WITH-FIXES, all 5 blockers + 9 majors folded).
Shape: a veto inside `_swatter_apply_plane` caps shared-egress perms at a
ladder-max temp, which suppresses **both** publication arms for free (swarm keys
on `offenders.perm=1`; AbuseIPDB gets an explicit guard). Rejected: allowlisting
the range — every CIDR in those files is a **never-block**, so it would hand any
attacker a bypass via the 1.1.1.1 app.

- [x] **Implemented, released as v2.13.0, and deployed to cds1 2026-08-11.**
- [x] **BL1 fallout — the 7 `--perm-allow` never-blocks were removed** on deploy;
      they are capped now rather than exempt.
- [x] **AS206092 handled** — added to cds1's local ASN file, which surfaced and
      cleared 3 more live perms.
- [x] **Sweep RUN 2026-08-13 over the whole perm set — three new exposures
      found, all still open below.** Profiled all **1,104** perm-banned IPs
      (1,091 IPv4 + 13 IPv6) by ASN via Team Cymru DNS: **101 distinct ASNs, zero
      lookup failures**. Then whois'd all **269** non-hyperscaler IPs — one
      representative per ASN is NOT sufficient, because AS206092 was caught by a
      *netblock* netname, not an AS-wide one, and both new IPv4 hits below sit in
      mixed ASNs where a single sample would have missed them.
      **Why 08-11 missed these:** that sweep profiled the 257-IP publish
      *backlog*, not the full perm set, and all three sit outside it. Two also
      carry maximal corroboration (`abuseipdb:confidence100`, `spamhaus:drop`),
      so a weak-evidence filter would have skipped them a second time — the exact
      failure the methodology note above documents. **Profile the whole perm set,
      not the backlog.**
      Everything else is datacenter/VPS and correctly banned: Microsoft/Azure
      **662** (60% of all perms), DigitalOcean 73, GCP 31, Bucklog 28, Vultr 24,
      TechTies 20, DMZHOST 19, M247 16, Contabo 14. Team Cymru's *bulk* whois
      port rate-limits at this volume; the documented per-IP DNS method
      (`dig … origin.asn.cymru.com`) ran 1,091 lookups clean under `xargs -P 40`.
- [x] **NEW/1 — Cloudflare WARP IPv6 was entirely uncapped. CAPPED 2026-08-13.** `shared-egress.cidr`
      holds exactly one entry, the IPv4 `104.28.0.0/16`; there is **no IPv6
      coverage at all**. WARP's v6 egress is `2a09:bac0::/29` — `bac0` through
      `bac7` each carry netname `CLOUDFLAREWARP` in RIPE, and `bac8` does not, so
      the /29 is the real boundary. On cds1: **209 distinct addresses temp-banned,
      2 perm-banned** — `2a09:bac5:33e6:248c::3a4:23` (2026-06-14) and
      `2a09:bac5:952a:3af::5e:7e` (2026-06-25, at `abuseipdb:confidence5`, i.e.
      effectively uncorroborated). Traffic is current: last temp 2026-08-05.
      Neither perm is on the hub feed today and neither has an AbuseIPDB marker,
      so nothing needs retracting. Same customer-facing collateral as the IPv4
      WARP cohort, across 2.7× more addresses.
- [x] **NEW/2 — PureVPN, `192.253.248.142`. CAPPED + UNBLOCKED 2026-08-13.** AS213790, NetName `PUREVPN`, org
      Secure Internet LLC, range `192.253.240.0/20`. Live perm — score 81,
      `spamhaus:drop(100)`, plane-upgrade 2026-08-05. **It IS in the consumed
      swarm feed, so it was published to the hub** — the only one of the three
      that went out. Not reported to AbuseIPDB. Swarm is recallable (`/purge`,
      7-day TTL) but `/purge` is all-or-nothing.
- [x] **NEW/3 — "VPN Consumer Singapore", `194.5.82.169`. CAPPED + UNBLOCKED 2026-08-13.** AS137409, netname
      `VPN-Consumer-Network`, range `194.5.82.0/24`. Live perm at
      `abuseipdb:confidence100`. **Same operator naming convention as AS206092**
      ("VPN Consumer Paris, France", F.N.S. Holdings) — so that operation spans
      at least two ASNs, and the ASN-keyed 206092 entry added on 08-11 caught
      only one leg of it. Not on the feed, not reported.
- [x] **Remediated with CIDRs, NOT ASN entries — APPLIED 2026-08-13.** Both new
      IPv4 ASNs are **mixed**: AS213790 also originates `AMWAJ` (AE) and AS137409
      also originates `IPLuo BV` (NL), neither of them VPN. An ASN entry would cap
      unrelated space, which is precisely what `shared-egress-asns.txt`'s own
      header warns against. Proposal: add `2a09:bac0::/29`, `192.253.240.0/20`
      and `194.5.82.0/24` to `shared-egress.cidr`, then `shared-egress-audit
      --fix`, verifying each unblock on **both** planes (see the warning below —
      the exit code is not enough).
      **Both questions settled 2026-08-13 — and the first proposal was wrong.**
      (a) The matcher DOES handle IPv6: `_cidr_overlaps_file` (`lib/allowlist.sh`)
      goes through `_ipv6_expand`/`_ipv6_in_prefix`. No code change is needed.
      (b) **Do NOT add the covering `2a09:bac0::/29`.** `SHARED_EGRESS_MIN_PREFIX6`
      is 32, and `swatter_intel_cidr_feed_ok` (`lib/common.sh:636`) rejects any
      global-unicast v6 prefix shorter than that — `case "$addr" in [23]*) ((plen
      < min6)) && return 1`. That rejection fails the **whole file**, so
      `_swatter_shared_egress_cidr_usable` logs "CIDR arm off this run" and the
      existing IPv4 `104.28.0.0/16` protection silently switches **off** too.
      Reproduced in a local harness: with the `/29` line present, the known WARP
      address `104.28.196.52` stops matching entirely.
      **Correct form: the eight discrete `/32`s, `2a09:bac0::/32` through
      `2a09:bac7::/32`** — which is also exactly how RIPE registers them
      (`2a09:bac8::` falls through to the parent `2a00::/11`, confirming bac7 as
      the boundary). Verified 16/16 against the real validator and matcher:
      file accepted, both live v6 perms match, `2a09:bac8::1` and the non-VPN
      neighbours in the mixed ASNs (`185.93.89.147`, `185.137.164.8`) correctly
      do not.
      **General lesson: one over-broad line disables the entire CIDR arm, in the
      direction nobody notices.** Any future addition to this file gets validated
      before it lands, not after.

      **Applied to cds1 2026-08-13 17:56 UTC.** Backup
      `/etc/swatter/shared-egress.cidr.bak-20260813-preipv6`. `test-config` reports
      **11 range(s)** with the arm ENABLED — the live proof the file validates,
      since a rejected file reports the arm off instead. `shared-egress-audit`
      matched exactly the predicted **4** perms (the 2 WARP v6, PureVPN, VPN
      Consumer SG) and no others; `--fix` cleared all four, each verified
      independently on both planes — `offenders.perm=0`, no `csf.deny` line, no
      `csf -g` hit, no `cf-rules.tsv` ref. Post-fix audit is clean and both arms
      report live.
      **Two count reconciliations, so nobody re-derives them in alarm:** the perm
      total reads **1101**, not 1104-4=1100, because a new perm (`34.50.186.119`)
      landed at 17:55 — as *two* rows sharing one `ts`, the primary plus the
      dual-plane leg, which is the documented SQL trap. And the audit reports
      **1090 checked** against 1101 total because it skips the 11 report-mode
      residue rows (`perm=1` with no enforced perm action). Both differences are
      expected; neither is a miscount.
- [x] **Gate D interaction — SETTLED 2026-08-13, re-confirmed 2026-08-20.** Gate
      D's review rule already says VPN exits get sorted out first (it said
      "allowlisted" until 2026-08-20 — wrong for shared exits, corrected in the
      review scheme; shared-egress is the disposition, not a never-block). At
      `REPEAT_WINDOW_DAYS=30` the WARP cohort's temps get a 4.3× wider window to
      accumulate into perms, so this had to be settled **before** the widen, not
      during the 615-row review. The sweep raised the stakes: the uncapped WARP
      **IPv6** pool alone carried **209** temp-banned addresses, an order of
      magnitude more than the IPv4 pool's 77, and every one of them would get that
      wider window. The requirement was to cap the three new ranges before
      widening, or gate D converts a known-shared cohort into perms at scale.
      **Done** — the ranges were applied to cds1 2026-08-13 17:56 UTC (see the
      block above) and `swatter test-config` on 2026-08-20 still reports
      `shared-egress: ENABLED`, **11 range(s)**, ASN arm live. A rejected file
      would report the arm off instead, so that line is the live proof it
      validates. Nothing blocks gate D here any more.

**Verify unblocks on both planes — the exit code is not enough.**
`swatter_store_unblock` runs at `bin/swatter:168` **before** the failure check
at `:175`, so a partial backend failure still clears `offenders.perm` — the IP
drops out of the publish delta and *looks* remediated while CSF or CF may still
deny it. Same pattern in `rollback-ladder`. Confirm with `swatter list perm`,
`swatter list cf`, `csf -g <ip>`.

## `request_flood` — tune on its own merits (open 2026-08-08, NOT a gate D blocker)

Source of **all five** known false positives: three residential visitors
(2026-07-27) plus Automattic and Ahrefs (2026-08-08). Lifetime perm record is
**0 for 2** — exactly two perm bans ever, both wrong. Temps, last 30d: **72
distinct IPs, zero with strong external corroboration** (56 no intel, 16 weak),
against 97% hard-corroborated for the backlog as a whole.

**The gate D amplification worry was checked and dropped — do not re-raise it
without new data:** request_flood temps do not stack (**71 of 72 IPs have
exactly 1 temp**, one has 2; none approach `REPEAT_N=3` in either window), and
of the 90 escalation candidates at 30d, **0 carry a request_flood temp**. Both
FPs escalated on **cross-rule** `recidivism=3/7d`, so a per-rule temp count is
the wrong test — recidivism counts every rule's temps together.

Residual cost is ~5 uncorroborated temp bans/day on legitimate-looking traffic:
customer-visible, self-expiring, occasionally unlucky enough to combine with
other rules into a perm. Worth tuning; not urgent, and not gate D's problem.

(The 13/90 candidate counts are a rough ledger proxy, **not** `escalate-preview`
numbers — that tool reports 125/615 under its own logic. Do not treat these as
contradicting it.)

## Metrics: wire node_exporter textfile collector into monitoring (parked 2026-07-09)

**Status:** DECIDED 2026-07-09 — **skip (option 3)**. Keeping NetData as the box
monitor; not installing node_exporter. The nightly email report + `/server-logs`
already surface everything the `.prom` metrics would show, so putting them on the
NetData dashboard is pure redundancy. Metrics step stays disabled (no-op) on cds1.
If we ever revisit (e.g. 2nd box / unified dashboards), prefer exposing the
metrics over a local HTTP endpoint scraped by NetData's `go.d/prometheus`
collector — no node_exporter daemon needed. Do NOT pick option 2 (dir-only): it
writes a `.prom` file nothing consumes.

Swatter emits node_exporter *textfile* format to
`/var/lib/node_exporter/textfile_collector/swatter.prom` (`METRICS_FILE`,
`lib/metrics.sh`). On cds1 the metrics step is a no-op — `test-config` shows
`metrics: /var/lib/node_exporter/textfile_collector missing/unwritable -> skipped`.

**Finding:** cds1 has **no node_exporter and no Prometheus** — the monitor is
**NetData** (v2.10.3). NetData can scrape a Prometheus *HTTP endpoint* but has no
collector that reads a `.prom` file off disk, so the textfile output has no
consumer as-is.

**Options when circling back:**
1. **node_exporter + NetData scrape** — install node_exporter (bind
   127.0.0.1:9100, `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`),
   create the dir, add a NetData `go.d/prometheus` job → 127.0.0.1:9100/metrics.
   Swatter metrics show in NetData. Cost: one new daemon on the box.
2. **Just create the dir** — `mkdir -p` + perms so root-cron writes `swatter.prom`
   cleanly (warning gone), metrics produced but nothing reads them yet. No daemon.
3. **Skip** — NetData + Swatter's nightly report + `/server-logs` already cover
   the box; the `.prom` is redundant. Leave the metrics step disabled.

Redundancy note: Swatter's own nightly report and `/server-logs` already surface
block / error / origin-lock counts, so #1 is mainly for putting the numbers on
the NetData dashboard specifically.

## Recidivism escalation: v2.11.0 deploy, then the cds1 window widening (open 2026-07-27)

**This is not "just widen to 30."** A release must ship and deploy first —
cds1 was running v2.10.0, which lacks the `REPEAT_ENABLE` abort lever, the
unblock watermark, the perm-gate residue fix, and the queued-perm gating that
makes the abort lever actually stop in-flight perms. Widening the window on
v2.10.0 would triple ban volume on the *least* safe version of the ladder that
exists. See `docs/superpowers/specs/2026-07-27-v2.11.0-release-and-cds1-deploy-design-v2.md`
for the full design; the work is staged across four gates, summarized here.
**`REPEAT_WINDOW_DAYS` is still 7 everywhere** — 30 is a cds1-only conf change
made at gate D, and it has not been made.

**cds1 go-live is pinned to 2026-07-27 23:44:45 UTC** — not merely "07-27". The
ledger dates it to the second: the last unstamped temp is `22:40:01` and the
first `rule=`-stamped temp is `23:44:45`, and 23:45 is the only skipped `*/5`
scan slot that day (the maintenance hold). Every soak window below is measured
from that instant, not from midnight. cds1 has since taken v2.12.0 (2026-07-30),
which changes `lib/errors.sh` (the scanner-fatal veto) and `lib/common.sh`
(config validation) — **not** the scoring or ladder paths, so it does not
disturb the `rule=`-stamped ladder data the soak accumulates.

- [x] **Gate A — build and release v2.11.0.** Local only. Grok review before
      the tag, mandatory for the residue fix and the queued-perm gating. Ends
      at a published `v2.11.0` (`make release V=2.11.0`).
- [x] **Gate B — capture the baseline, then deploy to cds1.** Record
      `swatter version`, the enforced perm count, a sample of perm reasons,
      and the live state of `SWARM_PUBLISH`/`ABUSEIPDB_REPORT` before touching
      the box. Deploy under a maintenance hold (pause cron, install,
      `test-config`, one manual scan, re-enable). **Freeze publication here,
      not at the widen** — set `SWARM_PUBLISH=false` and
      `ABUSEIPDB_REPORT=false` before re-enabling cron, since perms flow from
      the deploy onward, not from the widen. Set a provisional
      `PERM_RATE_ALERT_PER_DAY` with headroom over cds1's known spike of 16
      (the shipped default of 15 would guarantee a false abort). The ladder
      stays ON throughout — this is not a no-op deploy, it changes ban
      arithmetic in the safer direction (watermark + residue fix).
- [x] **Gate C — soak ~7 days, no config changes.** (Closed 2026-08-03 23:45
      UTC; tripwire set 2026-08-04, see below.) This is what brings the
      CRITICAL-single bar alive **at `REPEAT_WINDOW_DAYS=7` only** — it's inert
      until every in-window temp carries the `rule=` stamp, which pre-deploy
      temps lack, so the 7-day window clears on 2026-08-03 22:40 UTC but a
      30-day window does not clear until 2026-08-26 (see gate D). The soak also produces
      the tripwire's real numbers — record the per-day/per-run perm ceiling
      from the ledger and set `PERM_RATE_ALERT_PER_DAY`/`_PER_RUN` from that,
      not a guess.
      - Band measured 2026-08-01 over the first 4.7 days (~1,350 runs, 207 perm
        rows); see RUNBOOK §8 for the numbers and the queries. The band is flat
        (per-day rolling-24h p50 43 / p95 51 / max 54), so the remaining days
        are a formality, but the soak was specified as 7 and the gate stays open
        until it is.
      - [x] **Done 2026-08-04.** Re-ran the RUNBOOK §8 queries over the full
            window (7.9d): per-run p95 1 / max 2, per-day rolling-24h p50 44 /
            p95 55 / max 59 — both inside the "materially moved" bounds below.
            Set `PERM_RATE_ALERT_PER_RUN="5"` / `PERM_RATE_ALERT_PER_DAY="70"`
            on cds1 (was the provisional `15`/`120`); `test-config` confirms
            `5/run 70/day`. Per-day **70**, not the 85 drafted here: the open
            decision below was ratified toward the regime-keyed number — 70
            clears the current regime's max (59) with ~19% headroom and would
            have alerted on the June ramp, which is the desired behavior. Conf
            backup on cds1: `swatter.conf.bak-2026-08-04`.
            - Per-run is **5 because that is the shipped default**
              (`lib/common.sh:79`), and the shipped default already clears the
              lifetime max of 4. An earlier draft of this line said `8`; that was
              a straight error — it is *looser* than the default on a host whose
              observed per-run max is **2**. Do not raise per-run above 5 without
              a measured reason.
            - Per-day: the draft's `85` (clear the lifetime max of 83) was
              **rejected at ratification** in favor of the regime-keyed 70 —
              85's headroom was mostly `plane-upgrade` re-rows, and the 83 it
              cleared came from a **different operational epoch** (the June
              report→enforce ramp), exactly the kind of event the tripwire
              should catch.
            - How it was applied: edited `/etc/swatter/swatter.conf`, then
              `swatter test-config` confirmed the `perm tripwire:` line. No
              cron hold — these knobs only alert and place no bans; config is
              read per-process, so the values took effect on the next `*/5`
              scan. Undo is editing the conf back (or restoring the `.bak`).
            - "Materially" = per-run max moving above 4, or rolling-24h max above
              65, in the units RUNBOOK §8 defines. Either means re-derive both
              numbers rather than pasting these.
- [ ] **Gate D — preview at 30, review, then widen.** In order:
      ~~populate `monitoring.cidr`~~ (**CLOSED 2026-08-08 — correctly empty,
      do not populate; see below**); re-run the unstamped-temp check and the
      `scanner_profile` audit **fresh** (both are freshness-sensitive — run
      them near the 08-26 floor, not early); run
      `swatter escalate-preview --window 30` fresh (never review a saved
      list); human-review every candidate (ASN, PTR, customer mapping, plane;
      sort NAT/CGNAT, mobile carrier, VPN exit, crawler and customer out first —
      ~~all allowlisted~~ **the disposition differs per class, see "allowlist vs
      shared-egress" in the review scheme**); ~~confirm the gate B freeze is still
      active (nothing to change here)~~ — **FALSE as of 2026-08-11, see "the
      publication freeze has inverted" below; this step is now a decision, not a
      confirmation**; set `REPEAT_WINDOW_DAYS=30`; watch the
      first 48h to establish gate D's own rate baseline (the decision to back
      out is judged against *that*, not the gate C band — and it is an
      **operator** decision: `PERM_RATE_ALERT_*` only notifies, there is no
      automatic abort, so a tripwire that stays silent is not a green light and
      ladder perms keep landing every `*/5` scan while you wait. Gate C measured
      a 7-day window and gate D widens it — measured at **4.9×** the candidate
      count, not the "triples" figure used loosely elsewhere in this section;
      comparing against gate C's band
      guarantees either a false abort or a silently blind one). After 14
      clean days post-widen, review what accumulated during the freeze before
      restoring `SWARM_PUBLISH`/`ABUSEIPDB_REPORT`. **Correction 2026-08-08:
      only the swarm arm flushes a backlog.** `swatter_swarm_publish` defers
      rather than suppresses, so `SWARM_PUBLISH=true` publishes the *entire*
      backlog at once — but `swatter_abuseipdb_report` has one caller
      (`lib/score.sh:210`, inline at block time), no cursor and no replay, so
      `ABUSEIPDB_REPORT=true` reports only perms placed **after** the flip
      (~21/day). Swarm is the big-bang arm and is recallable (`/purge`, 7-day
      TTL); AbuseIPDB trickles and is **irreversible** (no delete API). Either
      way the review is the point, not a formality.

### ⚠️ The publication freeze has INVERTED — decide this before widening

**Noticed 2026-08-20.** The sequence above was written assuming the gate B
publication freeze would still be in force across the widen, with the arms
restored only after 14 clean days. **Both arms went back on 2026-08-11** —
`SWARM_PUBLISH="true"` and `ABUSEIPDB_REPORT="true"`, confirmed live by
`test-config` on 2026-08-20 (`publication: swarm=true abuseipdb=true`) — which is
15 days *before* the widen can even start. The freeze no longer covers the widen;
it covers the period before it. That is backwards from the design.

Why it matters: `REPEAT_WINDOW_DAYS=30` is exactly the change most likely to
manufacture a false-positive perm, and the 615-row human review exists because
this cohort is where false positives live. With the arms live, every perm the
widen produces publishes immediately. Swarm is recallable (`/purge`, 7-day TTL).
**AbuseIPDB is not — there is no delete API**, so a wrong perm is published under
our reporter identity permanently.

- [x] **DECIDED 2026-08-20 (owner): re-freeze AbuseIPDB across the widen.**
      `ABUSEIPDB_REPORT="false"` for the widen and its 48h baseline; **swarm stays
      on** — it is recallable via `/purge` on a 7-day TTL, so it carries no
      irreversible exposure. The alternative was accepting permanent publication
      of whatever false positives the 7d → 30d widen manufactures, under our
      reporter identity, with no delete API to walk it back.

      **The flip happens at the widen, not now.** Until `REPEAT_WINDOW_DAYS=30`
      is actually set, the window is still 7d and the risk this freeze exists to
      cover does not exist — flipping early would only forfeit ~21 legitimate
      reports/day for nothing. It is wired in as step 1 of the widen block in the
      run-up plan above, ahead of the knob change, so it cannot be forgotten.

      The asymmetry that makes this cheap, restated so nobody second-guesses it
      mid-widen: `ABUSEIPDB_REPORT` has one caller (`lib/score.sh:210`, inline at
      block time), no cursor and no replay, so a freeze costs exactly the perms
      placed while it is off and nothing queues up. Swarm is the opposite —
      `swatter_swarm_publish` defers rather than suppresses, so toggling it would
      flush the entire backlog at once on re-enable.

**Gate D has a hard date floor of 2026-08-26 22:40 UTC, discovered 2026-08-01.**
`REPEAT_N_CRITICAL_SINGLE` does not merely stay inert on unstamped temps — it
degrades toward *more* banning. `swatter_store_temps_all_critical_single`
(`lib/store_sqlite.sh`) returns 1 only when `tot > 0 && tot == crit`, and `crit`
requires `reason LIKE '%critical_badpath%'`; an unstamped temp counts toward
`tot` and never toward `crit`, so **one** unstamped in-window temp forces
`allcrit=0` and drops the bar from `REPEAT_N_CRITICAL_SINGLE`(4) back to
`REPEAT_N`(3) — the same failure the function's own flatfile branch warns about
out loud. Note this drops the *predicate*, not every candidate's actual bar: an
IP that was never all-`critical_badpath` was already at `REPEAT_N` and loses
nothing (see the "unevaluable ≠ lost" arithmetic below). Measured on cds1 at window=30 on 2026-08-01: of **615** candidates
only **79 (13%)** are fully stamped, **477 (78%)** have zero stamped temps, and
the bar would fire for **25**. 2,633 unstamped temps are still inside a 30-day
window; the last one is dated `2026-07-27 22:40:01 UTC`, so a 30-day window is
not fully stamped until **2026-08-26 22:40 UTC**. Widening before then arms a
30-day ladder whose single-CRITICAL-probe protection is **unevaluable for 536 of
615 candidates (87%)**.

Be precise about what that costs, because "unevaluable" is not the same as
"lost": an IP whose temps were never all-CRITICAL would compute `allcrit=0`
anyway, stamped or not, so it loses nothing. The harm falls only on IPs that
*would* have qualified. Among the 79 fully-stamped candidates, 25 (32%) do
qualify — if that rate carries, on the order of **~170** of the 536 are being
denied a protection they had earned. That is an extrapolation from a
13% sample, not a measurement; the honest floor is "unknown, plausibly in the
hundreds."

**The date is necessary, not sufficient — do not read 2026-08-27 as a green
light.** Four limits, all verified in code:

1. The bar only raises when **every** in-window temp is `critical_badpath`
   (`tot == crit`, `lib/store_sqlite.sh`). It does nothing for `scanner_profile`
   or mixed histories — which is the *majority* of the soft cohort (63 of the
   stamped candidates decompose to `scanner_profile`, see below). Waiting fixes
   one niche bar, not ladder safety generally.
2. **`escalate-preview` does not model `REPEAT_N_CRITICAL_SINGLE` at all** — its
   own preamble says so. The 615 / 64 / 551 counts are pure `REPEAT_N` math, so
   the review instrument for gate D cannot show you the effect of this bar
   either way.
3. **The stamp is conditional in code**, not automatic:
   `[[ -n "$drule" ]] && reason="${reason} rule=${drule}"` (`lib/score.sh`). A
   temp whose evidence carries an empty `decisive_rule` is written unstamped
   *even post-v2.11.0*, and one such row re-breaks `tot == crit` for that IP for
   the rest of the window. Measured 2026-08-01: **0 of 664** post-deploy temps
   were unstamped, so this had not happened on cds1 — but re-run that check at
   gate D rather than assuming the date alone cleared it.

   **It has now happened. Observed 2026-08-20 — and it does NOT move the floor.**
   Two post-v2.11.0 temps are unstamped, both on 2026-08-12
   (`74.248.32.128` 18:25:01, `20.113.132.165` 19:40:01). Both are hard-intel
   blocks: `reason="score=72 intel=abuseipdb:confidence100(100)"`,
   `evidence.decisive_rule=""`, `badpath_cat=MEDIUM`. There was no decisive local
   rule to stamp.

   Why the floor stands: the floor protects against rows that are *unevaluable* —
   pre-stamp-era temps that may or may not have been `critical_badpath` and cannot
   be read either way. These two are honest negatives. With no decisive rule they
   are genuinely not `critical_badpath`, so they fail `tot == crit` whether stamped
   or not, and nothing is lost. Blast radius is those two IPs, and only if they
   otherwise carry an all-CRITICAL history — a bar drop from 4 to 3 on two
   AbuseIPDB-confidence-100 addresses. **The pre-v2.11.0 backlog still clears
   2026-08-26 22:40 UTC.**

   **What this DOES break is the readiness query as written.** A naive "unstamped
   temps still in the 30d window" now returns **646** with a newest date of
   **2026-08-12**, which reads as a floor slip to 2026-09-11 and is not one. Run
   the check scoped to the **pre-stamp era** — treat a post-v2.11.0 row whose
   `decisive_rule` is legitimately empty as a negative, not as unevaluable. The
   query that produced the numbers above:
   ```sql
   SELECT date(ts,'unixepoch') d, COUNT(*) FROM actions
    WHERE action='temp' AND dry_run=0
      AND ts >= strftime('%s','now','-30 days')
      AND reason NOT LIKE '%rule=%'
    GROUP BY d ORDER BY d;   -- the 07-21..27 block is the real backlog
   ```
4. The other gate D preconditions below (`monitoring.cidr` still empty, the
   615-row human review, the publication freeze) are unaffected by this date and
   remain open.

The readiness check is the `critical_badpath` substring specifically, not the
presence of `rule=` — grepping for "has a `rule=` stamp" is the wrong test.

Also measured the same day, and worth sizing before the review: the candidate
population at window=30 is **615** (64 at-bar, 551 one-away) against **125** at
window=7 — 4.9×, not the ~3× "triples" language used throughout this section.
The human-review step in gate D is therefore a 615-row job, not a 300-row one.

**⚠️ Treat 615 as a floor, not the number — it is stale and the population is
growing.** Re-measured 2026-08-20: `escalate-preview --window 7` now reports
**201** candidates (15 at-bar, 186 one-away) against the **125** measured
2026-08-01. That is **1.6× in 19 days** at the same window. If window=30 has
moved anything like proportionally the review is closer to **~1,000 rows** than
615. That is an extrapolation from the 7d arm, not a measurement — the real
number only exists after the post-floor `--window 30` run — but plan capacity
against the larger figure, because discovering it on the 27th is how a review
gets rushed. **Do not pre-run `--window 30` to settle this**; a preview generated
before the floor is the saved list the gate forbids reviewing, and running it
twice means reviewing it twice.

Two items carried over as cds1-specific preconditions, still open:

- [x] **Re-baseline any triage notes taken from `swatter top` before
      2026-07-27 — DONE 2026-08-20. Nothing needed correcting.** Its
      `OFFN`/`TEMP`/`PERM` columns used to include report-mode activity, and cds1
      ran report mode before enforce (2026-06-12), so pre-fix numbers on that box
      are inflated by detections that were never enforced. `top` is not the formal
      gate — `escalate-preview` is — but the README and digest both train
      operators to triage from it. `TEMP` is a LIFETIME enforced count, not the
      ladder's windowed number; read `escalate-preview` for "how close is this IP
      to a perm."

      **What was audited, and why the answer is "none":**
      - **Repo docs** — no surviving pre-07-27 note cites `top`-sourced
        `OFFN`/`TEMP`/`PERM` figures. The 07-24 recidivism design derives its
        numbers straight from the `actions` ledger with the `dry_run` flag
        visible, and it already *corrects* a `top` artifact rather than inheriting
        one ("every IP which reached perm shows `plane-upgrade` as its last
        action" — an ordering artifact, disproved there by counter-example).
      - **The live cds1 allowlist** (10 entries, each carrying a dated triage
        note) — 4 predate 2026-07-27, all from 2026-06-10, i.e. written *during*
        report mode. Every one is justified on **identity**, not on counts:
        site owner, mobile user, confirmed-by-name. Identity triage does not read
        the inflated columns, so none of them is contaminated. The 6 later
        entries (07-27 and 08-08) are post-fix.

      **The re-baselined picture, for whoever triages next.** `swatter top -n 20`
      on 2026-08-20 returns 20 rows that **all carry `PERM=1`** — they are already
      permanently banned, and 19 of 20 show `plane-upgrade` as `LAST`. `top` is
      dominated by settled cases and answers "who has been worst", never "who is
      about to escalate". The instrument that answers the second question, at the
      live window, is:
      ```
      swatter escalate-preview --window 7   # 2026-08-20: 201 candidates
                                            #   15 at-bar, 186 one-away
      ```
      Sanity check from that run, recorded because it is the shared-egress cap
      visibly working: `104.28.208.56` sits **at-bar with 4 prior temps** and is
      inside `104.28.0.0/16`, the WARP IPv4 range — so its next offense converts
      to a ladder-max temp, not a perm. Two `104.28.x` rows are in the list; both
      are capped. Confirmed against the live file, which holds all 11 ranges.
- [x] **`monitoring.cidr` — CLOSED 2026-08-08. Correctly empty; do NOT
      populate it.** The precondition assumed monitors would be temp-banned by
      a 30-day ladder. Nothing that probes cds1 is ban-reachable:
      - **`foghorn` (Worker `down-detector`) probes cds1 every minute** —
        `CHECK_URL=https://cds1.peaceharborhosting.com`, cron `* * * * *`,
        cache-busted `?_cb=`, ~1,440 req/day, **empty UA** (so monitor-UA scans
        miss it entirely). Unbannable twice over: it logs to
        `/etc/apache2/logs/access_log` while swatter ingests only
        `DOMLOGS_GLOB=/etc/apache2/logs/domlogs/*`, and it arrives from
        Cloudflare edge IPs (never-block via `cloudflare.cidr`).
      - **netdata** is localhost-bound (`127.0.0.1:19999/:8125`, `[::1]`),
        agent-push only, no `httpcheck` collector; `127.*`/`::1`/RFC1918 are
        never-block via `lib/allowlist.sh:243`. 0 ledger rows for loopback or
        `67.225.133.76`.
      - No third-party monitor UA in current domlogs or 25 rotations.

      **Never pre-populate with well-known monitor ranges** — every CIDR here
      is a never-block, so ranges for services you do not use are free passes
      for anyone on them. **Re-open only if** foghorn's `CHECK_URL` is pointed
      at a customer vhost (that moves its probes into `domlogs/*`, where
      1,440/day cache-busted GETs with an empty UA is a plausible
      `request_flood` shape).

      Note the original framing still holds for `allow.cidr`, which now holds
      **8** entries — the 4 from 2026-06-10/07-27 plus 4 more: three
      `request_flood` FPs (2026-07-27) and one `scanner_profile` FP, then
      Automattic + Ahrefs on 2026-08-08.

Rollback at any point is `swatter rollback-ladder --since <ts>` — **never** a
config revert, which does not undo bans already placed. `REPEAT_ENABLE=false`
stops new ladder perms but does not stop honeypot or hard-intel perms (see
README).

## Gate D prep: sample the scanner_profile candidates (open 2026-07-27)

**Not a blocker, and not a code change** — an earlier design claimed both and was
withdrawn after review (`docs/superpowers/specs/2026-07-27-ladder-confidence-floor-design.md`,
see its `-review-grok.md`).

What is true: a WordPress page serving >=60 assets in a burst deterministically
floors at score 75 with `rule=request_flood` (`lib/score.awk:254`, `rps = n/span`
over the observed request span). Four such IPs were verified as real visitors on
customer sites and allowlisted 2026-07-27 (`unblock` then `allow`, so the ladder
count reset): three residential-fiber IPv4s and one residential IPv6, one of
them a customer-site owner at wp-login (specifics redacted 2026-08-04 — public
repo; the concrete entries live in the cds1 allowlist).

What is NOT true: that this cohort dominates the ladder candidates. Decomposed by
decisive rule, the 93 soft candidates are 46 `scanner_profile`, 35
`high_badpath_repeat`, 5 blended, and only **3** `request_flood`.

- [x] Before gate D, sample ~20-30 of the 46 `scanner_profile` (score 78)
      candidates from the domlogs. One of the four verified false positives was
      in that band, so it is the cohort most likely to hold more. Humans look
      like 2xx + static assets + a browser UA.
      **Done 2026-08-01 — audited all 63 (the cohort grew from 46), 0 false
      positives.** Every figure below is from the **raw domlogs**
      (`/home/*/logs/*-{Jul,Aug}-2026.gz`), re-derived across all 63 IPs and
      ~14k requests, not from swatter's own evidence JSON — that JSON folds
      `sample_ua` to the **first** UA and `sample_paths` to the **first 5**
      distinct paths (`lib/score.awk`), so it cannot support absolute claims.
      An earlier draft of this entry asserted two absolutes from the folded
      evidence and **both were wrong**; the raw numbers are:

      - **43 of 63 sent no User-Agent on any request** (46 sent none on at
        least one). No browser does this.
      - **4 of 63 did request static assets** — the earlier draft claimed none
        did. This is the finding worth keeping, because it falsifies the
        heuristic in the task line above: *scanners fetch static assets to
        fingerprint*. `103.83.237.2` pulled
        `/wp-content/plugins/kirki-test/assets/css/kirki.min.css` (a probe
        variant — it is testing whether the plugin exists); `27.124.10.134`
        pulled `Divi/style.css` and `Divi-child/style.css` to fingerprint the
        theme; `209.99.191.65`'s 84 "assets" are `/src/config.js`,
        `/api/config.js`, `/admin/site_settings.json` — config exfiltration,
        matched only because a naive extension test counts `.js`.
        **"2xx + static assets + a browser UA" is not sufficient to call a
        human.** Do not reuse it unqualified.
      - **2 rotate User-Agents heavily** — `103.83.237.2` across 24 distinct
        UAs, `27.124.10.134` across 18 (Safari 17.11 Mobile → Safari 16.2 →
        Firefox 122 → Chrome 133/Fedora → Chrome 130/Mac) while enumerating
        `/wp-content/plugins/*/readme.txt` in three case variants. UA rotation
        within one source IP is conclusive on its own.
      - `45.156.129.105` fires ~13 `readme.txt` probes inside one second with a
        self-referential forged `Referer`, across vhosts.
      - From the decision evidence (folded, and used only for aggregates, not
        absolutes): 2xx fraction ≤15% for every IP and 0% for most;
        `distinct_paths ≈ reqs` throughout. The score band is 80-82 now, not
        the 78 recorded above.

      Each of the 4 asset-fetchers is independently confirmed a scanner by UA
      rotation, self-declared scanner UA (`securityresearch/1.0`), or
      webshell/credential path enumeration — so the 0-FP conclusion survives
      the correction, but it rests on those signals, **not** on the
      static-asset test.

      **What this does and does not establish.** It answers the gate D question
      — "of the IPs the widened ladder is about to perm, how many are humans?" —
      because the sample IS that population, drawn from a fresh
      `escalate-preview --window 30`. It is not a general FP rate for
      `scanner_profile`: an IP that never reached candidate status cannot appear,
      and — the sharper limit — **an IP already permanently banned cannot appear
      either**, so a human mis-scored and permed back in June is invisible to
      this method by construction. The four known `request_flood` FPs are
      likewise absent because they were allowlisted on 2026-07-27 — note they
      were `request_flood`, a rule with the *opposite* profile (high 2xx, asset
      re-fetch, low distinct-path count), so this cohort cannot speak to that FP
      mode at all. It also cannot speak to temps that accrue between now and
      gate D, nor to behaviour after the widen changes ban arithmetic.
      - [ ] **Re-run this audit as part of the gate D preview**, not only on a
            customer complaint. A customer-report trigger is post-damage by
            construction: the FP is a live permanent ban on a paying site before
            anyone looks, and `rollback-ladder` only reverses `recidivism=`-
            stamped rows after detection. The audit is one script over the fresh
            preview list — cheap enough that "the last one was clean" is not a
            reason to skip it.
- [x] ~~Only if that sample shows a real FP rate, design a **rule-based**
      exclusion (`request_flood` only, never a score threshold)~~ — **not
      warranted**, closed unstarted 2026-08-01. The sample above shows no FP
      rate to exclude, so the premise fails. The `request_flood` FP mode found
      on 2026-07-27 does not extend to `scanner_profile`. Kept on record because
      the TTL coupling is the trap if this is ever revisited: `prior` drives both
      perm conversion and `_swatter_pick_ttl`, so filtering it freezes the TTL
      ladder at 1h.
- [ ] Separate, larger question for its own design: the rate signal counts asset
      requests rather than page views (`lib/score.awk:198-202`).

## v2.11.0 deferred minors — carried from the SDD review (open 2026-07-27)

Recorded here because the per-task ledger they lived in is deleted once merged,
and the final whole-branch review triaged each as safe to defer, not as
resolved. None blocks the release; all were verified real.

- [ ] **Coverage debt: `pending_disarm_test` seeds one row per case.** Multi-row
      splitting is the behaviour the US/RS delimiter change most affects, and it
      is only manually verified (twice — by a task reviewer and by the final
      reviewer, both correct). Add a mixed multi-row case.
- [ ] **Coverage debt: the hard-intel dual-plane leg is uncovered** in
      `perm_gate_residue_test.sh` — the test drives the gate with `rep=0`, so
      `hard=0` and `_swatter_maybe_dual_plane` never fires.
- [ ] **`absent-db-also-fails-closed-redundant-with-missing-table` is a passenger
      assertion.** sqlite3 auto-creates the DB file, so that path is caught by the
      same check as the missing-table case. Already renamed to say so; delete or
      replace it with a case that can actually fail.
- [ ] **`swatter_store_record` is not transactional.** A partial write can leave
      `offenders.perm=1` with no `actions` row. Fail-safe (falls through to the
      ladder rather than banning), which is why it was deferred.

**Accepted as designed, not defects — do not "fix" without re-reading why:**

- While the ladder is disarmed, hard-intel dual-plane and plane-upgrade *retries*
  are held too, which is broader than "off gates ladder conversion only". Erring
  toward not banning is deliberate; reliably distinguishing them would need the
  substring matching that already produced one bypass (`projecthoneypot` matching
  a `*honeypot*` allowlist).
- Held rows also skip coverage and never-block cleanup while disarmed.

Both are documented in `docs/RUNBOOK.md` §2/§3.

## Validate the remaining silent-arithmetic knobs (CLOSED 2026-08-13)

- [x] SHIPPED 2026-07-27. The escalation knobs (`REPEAT_N`, `REPEAT_WINDOW_DAYS`,
      `REPEAT_N_CRITICAL_SINGLE`) and the tripwire knobs
      (`PERM_RATE_ALERT_PER_RUN`, `PERM_RATE_ALERT_PER_DAY`) are validated at the
      end of `swatter_load_config`.
- [x] **CLOSED 2026-08-13 — the four still listed as open here are done.**
      `SCORE_TEMP`, `MAX_BLOCKS_PER_RUN`, `WINDOW_SECONDS` and `MIN_REQS` each run
      through `_swatter_validate_int` at `lib/common.sh:489-492`, which regex-tests
      `^[0-9]+$` **before** any arithmetic and falls back to the documented default
      with a `log_warn`. That closes the `set -u` mid-scan abort for these four.
      `PERSIST_N` and `TTL_LADDER` already had fallbacks.
      **The hazard class is NOT retired.** v2.15.1's Blocker was this exact bug on
      `ERROR_CORROBORATE_MAX_SPAN`, a knob added after this section was written —
      the section going stale is part of how it got through. Every new numeric
      knob takes the same validation; the rule is in `CLAUDE.md`.

## App-signal ingest, Path A (next up, 2026-07-24)

Handoff at `~/Downloads/swatter-app-signal-handoff.md` (PII item withdrawn; the
no-IP-on-drop item stands). Deliberately sequenced *after* the recidivism work so
a perm-volume change has a clean baseline to be attributed against.

- [ ] Move the proposal to `docs/proposals/app-signals.md`, Grok-review it beside
      the file, fold blockers, then implement Path A behind `APP_SIGNAL_ENABLE=false`.
- [ ] Its design must account for the ladder as it now stands: the standing rule
      is "no perm-ban authority from app signals," but app signals raise scores →
      temps → and the ladder converts temps to perms. State how that indirect path
      is bounded.
- [ ] Verified 2026-07-24 and no longer open: `mod_remoteip` **is** in place on
      cds1 with `RemoteIPTrustedProxy` scoped to Cloudflare ranges, so a WP
      producer will log restored client IPs correctly.
