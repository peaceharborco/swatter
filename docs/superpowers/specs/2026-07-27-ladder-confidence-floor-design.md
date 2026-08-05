# Design — a confidence floor for the recidivism ladder

> ## ⚠️ WITHDRAWN — the proposal is wrong. Do not implement.
>
> Adversarial review on 2026-07-27 (see `…-design-review-grok.md`) returned
> RETHINK from both passes, and a measurement taken during that review inverts
> this document's recommendation.
>
> **Decomposing the 93 soft candidates by decisive rule: only 3 are in the
> `request_flood` band.** 46 are `scanner_profile`, 35 are `high_badpath_repeat`.
> This proposal would exempt 81 genuinely-suspicious IPs to protect 3. It
> conflated soft *volume* (dominated by flood, because a visitor floods once)
> with soft *candidates* (dominated by scanners, because those come back).
>
> `REPEAT_MIN_SCORE=81` also sits above nearly every decisive floor —
> `high_badpath_repeat` is 80, `scanner_profile` 78, `error_burst`/`request_flood`
> 75 — so it exempts the three commonest real attack patterns, becoming an
> evasion primitive rather than a precision cut. And filtering the count would
> silently freeze the TTL ladder, since `prior` drives both perm conversion and
> TTL selection.
>
> **What survives:** the false-positive mechanism is real (a WordPress page
> serving ≥60 assets in a burst deterministically floors at 75), the four
> allowlisted IPs were correct, and `scanner_profile` false-positives too — that
> 46-IP cohort is where a real gate D review should look. **Gate D is not blocked
> on a code change.**
>
> Kept rather than deleted so the reasoning error stays on the record.


**Written:** 2026-07-27, from evidence gathered during the v2.11.0 gate D
preview on cds1. **Blocks gate D** (`REPEAT_WINDOW_DAYS` 7 → 30).

---

## 1. The finding

Running `swatter escalate-preview --window 30` on cds1 produced **739
candidates** — every one of them one offense from a never-expiring ban if the
window were widened. Splitting them by confidence:

| Cohort | Count |
|---|---|
| Backed by hard intel (AbuseIPDB confidence 100 / Spamhaus) | 646 |
| **Never scored above 80** | **93** |

Four IPs were sampled from the soft cohort and identified from the ledger
evidence and raw domlogs. **All four were legitimate human visitors on customer
sites:**

| IP | Site | Actual activity |
|---|---|---|
| `FP-1` (residential fiber, IPv4) | customer WordPress site A | Chrome loading ShopEngine / RevSlider / Elementor assets; Outlook autodiscover POSTs |
| `FP-2` (residential fiber, IPv4) | customer WordPress site B | Chrome + iPhone loading ConvertKit / Divi theme assets |
| `FP-3` (residential, IPv4) | customer WordPress sites C, D | The site owner at `/wp-login.php` — `user-profile.js`, `zxcvbn-async.js` |
| `FP-4` (residential, IPv6) | customer WordPress site E | A human clicking `/staff`, `/students`, `/team`, `/ministries` |

*(IPs and customer domains redacted 2026-08-04 — this repo is public. The
concrete entries live in the cds1 allowlist, added 2026-07-27.)*

All four were allowlisted on 2026-07-27 (`unblock` then `allow`, so the ladder
count reset rather than merely being prevented from firing).

## 2. Root cause

All four tripped `rule=request_flood` at **72–124 requests**. That is one
plugin-heavy WordPress page load: Elementor, Divi and RevSlider each pull dozens
of assets, and the browser fetches them in a burst.

With `WINDOW_SECONDS=600` and `RATE_SAT=8`, a single page view saturates the rate
signal. The blended score lands at 75–78, clears `SCORE_TEMP=70`, and a temp is
placed. Over 30 days, last-30-day figures on cds1:

- **803 soft-band temps (score 70–80) across 704 distinct IPs**
- 2,682 hard-intel temps across 1,980 IPs

So the soft band is not noise at the margin — it is ~23% of temp volume and
~26% of distinct IPs, and the sample suggests a large share are real visitors.

**Temp-blocking them is defensible.** A temp expires, and a via-CF false positive
gets a managed challenge a human can solve — the posture chosen deliberately
after the 2026-06-10 incident. **Escalating them to a permanent ban is not.**

## 3. Why this blocks the widen

At `REPEAT_N=3`, widening to 30 days means **three ordinary visits to a
customer's WordPress site within a month produces a never-expiring ban.**

The current 7-day window conceals this by accident: a casual visitor's temps age
out before a third one lands. Tripling the window removes the accident without
changing anything about who is being counted.

This inverts the framing the v2.11.0 design used. Gate D was gated on *reviewing
a candidate list*. It is actually gated on a **scoring-confidence issue the list
revealed** — and no amount of allowlisting fixes it, because the affected IPs are
dynamic residential addresses that rotate.

## 4. Proposal — `REPEAT_MIN_SCORE`

A temp counts toward the recidivism ladder only if it was placed with a score at
or above `REPEAT_MIN_SCORE`. Below that, the temp still happens — the IP is still
blocked temporarily — it simply does not accumulate toward a permanent ban.

The principle: **a permanent ban is a far larger commitment than a temp, so it
should require correspondingly more confidence.** This is the same instinct as
`REPEAT_N_CRITICAL_SINGLE`, which already raises the bar for a different class of
cheap signal.

### 4.1 Where it applies

The filter must be applied in **all three** places that count in-window temps, or
they will disagree — and the v2.11.0 design already establishes that the preview
must mirror the decider exactly:

| Function | File | Role |
|---|---|---|
| `swatter_store_recent_temp_count` | `lib/store_sqlite.sh` | The decider |
| `swatter_escalate_preview` | `lib/store_sqlite.sh` | Must mirror the decider or the review lies |
| `swatter_store_temps_all_critical_single` | `lib/store_sqlite.sh` | Denominator for the CRITICAL-single bar |

Both the sqlite and flatfile paths need it; `score` is already stored per action
row in both.

### 4.2 Default value

**Proposed default: `81`** — the boundary the cds1 data shows between the
behavioural-only band and the intel-backed band.

This is a behaviour change on upgrade, so it deserves the same scrutiny
`REPEAT_ENABLE` got. The distinction:

- `REPEAT_ENABLE` defaulting off would have **removed** a protection an install
  already had. That was rejected.
- `REPEAT_MIN_SCORE` defaulting to 81 **adds precision** — it removes
  over-banning, not protection. Every install that has this false-positive
  pattern has it silently today.

The alternative — default `0` (preserve exactly today's behaviour) and set `81`
on cds1 only — is defensible and safer for compatibility, but it leaves every
other operator with the defect and no signal that they have it.

**Recommendation: default 81, with a prominent CHANGELOG entry** explaining that
low-confidence temps no longer escalate, and how to restore the old behaviour
with `REPEAT_MIN_SCORE=0`.

### 4.3 What this is not

- **Not a change to who gets temp-blocked.** `SCORE_TEMP` is untouched. The
  soft-band visitors still get temps and still get managed challenges.
- **Not a replacement for fixing the flood signal.** Treating a burst of asset
  requests for one page as a single page view is the real root-cause fix (§6).
  This proposal bounds the *consequence* while that remains open.
- **Not a substitute for the gate D review.** It shrinks the review list; it does
  not remove the need for one.

## 5. Expected effect on cds1

The 93 soft-band candidates drop out of the ladder entirely. The remaining ~646
are hard-intel backed. Gate D's human review becomes a list dominated by
scanners, VPS ranges, and known-malicious sources rather than a mix.

This should be measured, not assumed: re-run the preview after the change and
confirm the count and composition before widening.

## 6. Follow-on, not in this design

**The flood signal counts assets, not page views.** 72–124 requests for one
WordPress page is normal, and any rate-based signal that treats it as a flood
will keep producing soft-band false positives. Options worth exploring: discount
same-referer asset bursts, weight by distinct paths rather than raw count, or
exclude static-asset extensions from the rate signal. That is a larger change to
`lib/score.awk` and belongs in its own design.

## 7. Open questions for review

1. Is `score >= N` the right discriminator, or should it be "carried hard intel"?
   Score is simpler and already stored; intel-based would be stricter but would
   let a high-scoring behavioural attacker escape the ladder.
2. Should the floor apply to `REPEAT_N_CRITICAL_SINGLE`'s denominator too, or
   only to the plain count? A CRITICAL bad-path probe scores 90 by floor, so it
   clears 81 either way — but the interaction should be stated explicitly.
3. Does anything else read these counts that this design has not enumerated?
4. Is 81 correct, or an artifact of one host's tuning? Other installs may band
   differently.
