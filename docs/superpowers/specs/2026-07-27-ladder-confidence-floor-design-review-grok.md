# Consolidated adversarial review — ladder confidence floor

**Reviewed:** `2026-07-27-ladder-confidence-floor-design.md`
**Date:** 2026-07-27
**Reviewers:** two Grok 4.5 passes in lens mode (`[pass-a]` correctness skeptic,
`[pass-b]` safety/evidence red-teamer) plus Claude-side code and measurement
sweeps (`[gap]`).
**Verdicts:** both **RETHINK**.

**Outcome: the design is withdrawn, not patched.** Its central parameter is
wrong, its evidence does not support its conclusion, and a measurement taken
during this review inverts its recommendation.

---

## The measurement that settles it

`[gap]` — taken on cds1 during review, and available to neither reviewer.

The design blocks gate D on the claim that the soft band (score ≤ 80) is full of
false positives. Decomposing the **93 soft ladder candidates** by inferred
decisive rule (the floors in `lib/score.awk:239-254` are deterministic values, so
an exact score identifies the rule for rows predating the `rule=` stamp):

| Inferred rule | Candidate IPs | Their temps |
|---|---|---|
| `scanner_profile` (78) | **46** | 93 |
| `high_badpath_repeat` (80) | **35** | 72 |
| blended / other | 5 | 10 |
| **`request_flood` / `error_burst` (75)** | **3** | 8 |

**Only 3 of 93 candidates are in the band with the proven false-positive
mechanism.** The proposal would exempt 81 genuinely-suspicious IPs — path
scanners and credential-brute sources — to protect 3.

The design conflated **volume** with **candidate composition**. Soft *volume* is
dominated by flood (185 temps at score 75), because a legitimate visitor
flood-temps once or twice. Soft *candidates* are dominated by scanners and brutes,
because those are what come back often enough to accumulate.

---

## Blockers

### B1 — `REPEAT_MIN_SCORE=81` guts nearly every decisive floor
`[both]` `[gap]` — **verified**

The design picked a score threshold without checking it against the decisive
floors, which cluster exactly across it (`lib/score.awk:239-254`):

| Rule | Floor | vs 81 |
|---|---|---|
| `honeypot` | 100 | counts |
| `critical_badpath` | 90 | counts |
| `high_badpath_repeat` | **80** | **never counts** |
| `scanner_profile` | **78** | **never counts** |
| `error_burst` / `request_flood` | **75** | **never counts** |

`high_badpath_repeat` exists specifically so a credential brute is not averaged
down — its own comment says "10 is far above any human session". At floor 80 it
sits one point under the proposed bar **forever**.

### B2 — The exemption is an evasion primitive
`[pass-a]` — **verified**

An attacker need not hover in a narrow band; they can sit on the floors the
scorer already awards for real attacks. Flood/scrape → always 75. wp-login brute
→ 80. Path scanner → 78. All permanently under 81, **even with AbuseIPDB 100**,
because the floor is the score. New or rotating residential/VPS attackers often
lack intel on first contact — exactly when the ladder is meant to accumulate.

### B3 — Filtering the count also freezes the TTL ladder
`[pass-b]` — **verified, and missed entirely by the design**

`prior` from `swatter_store_recent_temp_count` drives **both** the perm
conversion **and** TTL selection (`lib/score.sh:601-619` → `_swatter_pick_ttl
"$prior"`). Excluding soft temps from the count leaves an IP whose offenses are
all soft-band at `prior=0` permanently — **1-hour temps forever**, never
escalating through `TTL_LADDER="3600 21600 86400 259200"`.

§4.3 claims "not a change to who gets temp-blocked". True, and beside the point:
it silently changes how *long*. For a real soft-band attacker that is a second
downgrade of consequence.

### B4 — Low-and-slow loses its only escalation path
`[pass-b]` — **verified**

`PERSIST_N` runs only in the WATCH band and places a temp carrying a sub-70 score
(`lib/score.sh:627-636`). There is no direct low-and-slow → perm path; escalation
*is* the ladder. Under the proposal those temps never count, so slow credential
stuffing and content scraping tuned to stay under `SCORE_TEMP` keep rotating
short temps indefinitely.

### B5 — The evidence does not support the conclusion
`[pass-b]` — **conceded**

Four hand-picked IPs out of 93 cannot establish "a large share are real
visitors". All four shared one story, which demonstrates *one failure mode*
rather than estimating prevalence. The measurement above is what a properly-sized
check looks like, and it contradicts the claim.

---

## Majors

- **M1** `[both]` Score is the wrong discriminator; the decisive **rule** is the
  real design choice. The design's own open question 1 raised this and then
  recommended a score anyway.
- **M2** `[pass-a]` **The root-cause prose is half wrong.** `WINDOW_SECONDS` is
  ingest lookback only; the rate signal uses `rps = n / span` over the observed
  first-to-last request (`lib/score.awk:198-202`). The real signature is "≥60
  requests at ≥8 rps in a burst", not "anything inside a 10-minute window". And
  75 is the *floor*, not a blended score — clean WP composite lands ~30–45.
- **M3** `[pass-a]` 81 is an artifact of one host's empirical split, not a
  property of the score scale.
- **M4** `[pass-a]` The default-81 vs `REPEAT_ENABLE` distinction is
  self-serving: both change behaviour on upgrade, and this one removes real
  protection.
- **M5** `[gap]` Consumer enumeration was correct for the ladder
  (`recent_temp_count`, `escalate_preview`, `temps_all_critical_single`) — the
  other two temp readers, `swatter_store_top_offenders:446` and
  `swatter_store_counts:741`, are display/metrics and unaffected. Confirmed, no
  missed site.

---

## What survives

- **The false-positive mechanism is real.** A WordPress page delivering ≥60
  assets in a burst deterministically floors at 75 with `rule=request_flood`.
  Verified at `lib/score.awk:254` and against four live cases.
- **The four allowlisted IPs were correctly identified and correctly handled**
  (`unblock` then `allow`, so the ladder count reset). `[pass-a] m4` confirms the
  sequence.
- **`scanner_profile` false-positives too.** One of the four (`FP-4`, redacted 2026-08-04)
  scored 78, and 46 of the 93 candidates sit in that band. That cohort — not the
  flood band — is where a real review should focus.

## Disposition

Design withdrawn. Gate D is **not** blocked on a code change. The proportionate
next step is to sample the 46 `scanner_profile` candidates from the domlogs
before gate D, and to treat any fix as a **rule-based** exclusion (`request_flood`
only) if the data warrants one — with the TTL coupling in B3 designed for
explicitly, not inherited.
