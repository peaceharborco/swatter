# Handoff — gate C band + scanner_profile sample (2026-08-01)

**Repo:** `swatter` · **Branch:** `main` · **Commits:** none — **all work is
uncommitted**
**Status:** measurement and review complete; **nothing committed, nothing changed
on cds1.** Written for a pickup on/after **2026-08-04**, by which point the gate C
soak has closed and its one deferred action is live.

> **Picked up 2026-08-04.** Items 1+2: full-window re-measure (per-run max 2,
> rolling-24h max 59) held the gate; tripwire set on cds1 to `5/run 70/day`
> (70 ratified over the drafted 85 — regime-keyed). Item 4: redacted forward
> only, see the note in that section. Item 5: the tree had already been
> committed on 08-01 (`c0447a0`, `b7684f2`). Item 3 (gate D) remains blocked
> until 2026-08-26 22:40 UTC.

Working tree when this was written:

```
 M README.md        (+6 -0)    — CRITICAL-single "inert" now states its direction
 M TODO.md          (+198 -25) — gate status, measured band, gate D date floor
 M docs/RUNBOOK.md  (+132 -12) — §8 rewritten: two arms, queries, measured band
```

`make test`: **58 test files, 0 failures.** No code changed — prose only.

---

## Read this first: the soak clock

**cds1 go-live is `2026-07-27 23:44:45 UTC`**, pinned to the second from the
ledger — last unstamped temp `22:40:01`, first `rule=`-stamped temp `23:44:45`,
and 23:45 is the only skipped `*/5` slot that day (the maintenance hold). Do not
round this to "07-27"; three separate windows are measured from it.

| Milestone | Instant | State at 2026-08-04 pickup |
|---|---|---|
| Gate C soak (7d) closes | **2026-08-03 23:45 UTC** | **passed — action below is live** |
| 7-day window fully stamped | 2026-08-03 22:40 UTC | passed |
| **30-day** window fully stamped | **2026-08-26 22:40 UTC** | **~3 weeks out — gate D floor** |
| Publication unfreeze target | ~2026-08-10 | still ahead; reviewed flip, not blind |

---

## What was done

### 1. Perm-rate band measured — **DONE**, one action deferred to Aug 4

Measured over the first 4.7 days (~1,350 runs, 207 perm rows). Full numbers and
the queries live in **RUNBOOK §8**; the band is flat, so the last 2.3 days were
not expected to move it.

The load-bearing discovery is that **the two arms of the tripwire do not count
the same thing**, and measuring either in the wrong units puts you off by ~3×:

| Arm | Counts | Measured | Was |
|---|---|---|---|
| `PERM_RATE_ALERT_PER_RUN` | `SWATTER_RUN_PERMS` — primary legs only (`audit_action == action` guard, `lib/score.sh`) | p95 **1**, max **2** (lifetime 4) | 15 |
| `PERM_RATE_ALERT_PER_DAY` | `swatter_store_perm_count_since` — **every** row, **rolling 24h**, no such filter (`lib/store_sqlite.sh`) | p95 **51**, max **54** (lifetime 83) | 120 |

207 rows decompose to **67 primary / 70 `dual-plane` / 70 `plane-upgrade`**.

### 2. `scanner_profile` sample — **DONE, 0 false positives in 63**

Audited **all 63** (the cohort grew from the 46 recorded on 07-27), from the
**raw domlogs** across ~14k requests — not from swatter's evidence JSON. Both
follow-up bullets in TODO are now closed; no rule-based exclusion is warranted.

### 3. Adversarial review — **DONE**

Two Grok passes (correctness skeptic + safety red-teamer) plus the Claude-side
sweeps. Pass B returned **BLOCK**; every finding was verified at file:line and
folded in, or declined with a reason. Both Grok runs were sandboxed read-only and
the tree confirms they wrote nothing.

The review caught three real errors in my own first draft — recorded here because
each is a trap for the next person too, see **Gotchas**.

---

## TODO

### 1. Set the tripwire on cds1 — **OPEN, actionable now (was gated on Aug 3)**

Currently live on cds1: the provisional `15`/`120`. Target:

```
PERM_RATE_ALERT_PER_RUN="5"
PERM_RATE_ALERT_PER_DAY="85"
```

- [ ] Re-run the RUNBOOK §8 queries with `<soak-start>` =
      `2026-07-27 23:44:45` — a full week is now available, so this supersedes
      the 4.7-day figures rather than confirming them.
- [ ] If per-run max is still ≤4 and rolling-24h max still ≤65, set the values
      above. If either moved past that, **re-derive both rather than pasting**.
- [ ] Edit `/etc/swatter/swatter.conf`, then `swatter test-config` and confirm
      the `perm tripwire:` line reads `5/run 85/day`.

No cron hold needed — these knobs only notify and place no bans. Config is read
per-process, so they take effect on the next `*/5` scan. Undo is editing the conf
back; there is nothing to roll back because nothing was blocked.

> **Per-run is 5 because that is the shipped default** (`lib/common.sh:79`), and
> the default already clears this box's lifetime max of 4. An earlier draft of
> this work proposed **8** — that was a straight error, *looser* than the shipped
> default on a host whose observed per-run max is **2**. Grok caught it. Do not
> raise per-run above 5 without a measured reason.

### 2. Per-day `85` — **OPEN DECISION, not yet ratified**

`85` was chosen under the principle "clear the lifetime maxima so it has zero
false trips against any history this box has." It is the weaker of the two
numbers and the review argued against it:

- Against the **current** regime (rolling-24h max 54) it leaves ~31 rows of
  headroom, and much of that is `plane-upgrade` re-rows rather than new
  attackers.
- The 83 it clears came from the **June report→enforce ramp** — a different
  operational epoch, arguably exactly the kind of event you'd want to hear about.
- A number keyed to the v2.11.0 regime lands nearer **65-70**.

Decide at the same time as item 1. `85` is defensible and is a 1.41× tightening
either way; this is a detection-vs-silence judgement, not a correctness bug.

### 3. Gate D — **BLOCKED until 2026-08-26 22:40 UTC (new, discovered this session)**

`REPEAT_N_CRITICAL_SINGLE` does not merely go inert on unstamped temps — it
**degrades toward more banning**. `swatter_store_temps_all_critical_single`
returns 1 only when `tot > 0 && tot == crit`, and `crit` requires
`reason LIKE '%critical_badpath%'`. An unstamped temp counts toward `tot` and
never toward `crit`, forcing `allcrit=0` and dropping the bar from
`REPEAT_N_CRITICAL_SINGLE`(4) back to `REPEAT_N`(3).

Measured on cds1 at window=30: of **615** candidates, only **79 (13%)** are fully
stamped, **477 (78%)** have zero stamped temps, and the bar would fire for **25**.
2,633 unstamped temps sit inside a 30-day window; the last is dated
`2026-07-27 22:40:01 UTC`, hence the floor.

**The date is necessary, not sufficient.** Do not read Aug 27 as a green light:

- The bar only covers histories that are **entirely** `critical_badpath`. It does
  nothing for `scanner_profile` or mixed — the majority of the cohort.
- **`escalate-preview` does not model this bar at all** (its own preamble says
  so). The 615/64/551 counts are pure `REPEAT_N` math.
- The stamp is **conditional in code** — `[[ -n "$drule" ]] && reason=...`
  (`lib/score.sh`). A temp with an empty `decisive_rule` is written unstamped even
  post-v2.11.0. Measured **0 of 664** post-deploy temps unstamped, so it has not
  happened here — **re-run that check at gate D** rather than assuming the date
  cleared it.
- `monitoring.cidr` is **still empty** (0 non-comment lines, verified
  2026-08-01) and remains a gate D precondition.

Also resize the expectation: window=30 yields **615** candidates vs **125** at
window=7 — **4.9×**, not the "triples" language used loosely elsewhere. The human
review at gate D is a 615-row job.

- [ ] Re-run the `scanner_profile` audit as part of the gate D preview — it is
      now a checklist item, not a "re-sample if a customer complains" trigger.
      Customer-report-as-trigger is post-damage by construction.

### 4. Pre-existing PII in a public repo — **OPEN, needs your call**

`swatter` is **public** (`gh repo view` → `"visibility":"PUBLIC"`). Already
committed:

- `TODO.md` (gate D prep section) — four residential IPs with ISP attribution,
  one tied to a named customer site
- `docs/superpowers/specs/2026-07-27-ladder-confidence-floor-design.md:53-55` —
  the same IPs tied to named customer sites, described as "a site owner",
  "Chrome + iPhone"

> **Resolved forward-only 2026-08-04:** both files redacted in place
> (anonymized FP labels; concrete entries remain in the cds1 allowlist).
> History untouched — rewrite after publication is irreversible and old
> commits stay reachable by SHA in GitHub's cache.

Residential IPs joined to identifiable people. Untouched: history rewriting is
irreversible and outward-facing, and per `~/Developer/CLAUDE.md` a rewrite after
publication still leaves old commits reachable by SHA in GitHub's cache. The
uncommitted work adds only two attacker IPs and no customer vhosts (grep-verified).

### 5. Commit the working tree — **OPEN**

Three modified files, no commit made. Suggested split: one `docs(runbook)` for §8
and one `docs(todo)` for the gate status, or a single `docs:` commit — your call.

---

## Gotchas for whoever picks this up

- **Never compare the two tripwire arms directly.** "15/run, 120/day" is not an
  8:1 ratio of the same quantity. Per-run counts primary legs; per-day counts
  every row including both plane legs, over a **rolling** 24h — not a calendar
  day. The calendar-day grouping in the old RUNBOOK understated the peak (51 vs
  54 rolling).
- **Do not attribute the ~3× gap to `plane-upgrade` alone.** Half of it is
  `dual-plane` — a **one-shot** hard-intel second leg with nothing to do with
  Cloudflare TTLs. `plane-upgrade` is the only self-repeating one, and it only
  repeats when the IP is **re-observed still attacking** after its CF rule
  lapses (the perm gate sits inside the scored-IP loop). An IP that stops
  sending traffic contributes nothing.
- **Swatter's evidence JSON cannot support absolute claims.** `sample_ua` is the
  **first** UA only; `sample_paths` the **first 5** distinct paths
  (`lib/score.awk`). A first draft of the scanner audit asserted "not one
  requested a static asset" and "44 sent no UA" from that JSON — the raw domlogs
  say **4 did** and **43**. Go to `/home/*/logs/*.gz` for anything absolute.
- **"2xx + static assets + a browser UA" does not mean human.** Scanners fetch
  static assets to *fingerprint*: `kirki-test/assets/css/kirki.min.css` probes
  whether a plugin exists, `Divi/style.css` fingerprints a theme, and
  `/src/config.js` + `/admin/site_settings.json` are config exfiltration that a
  naive `.js` extension test miscounts as an asset. The signals that actually
  held were UA rotation (24 and 18 distinct UAs from single IPs), self-declared
  scanner UAs, and webshell/credential path enumeration.
- **`strftime('%s','<soak-start>')` returns NULL, not an error.** A
  pasted-verbatim RUNBOOK query returns a blank line that reads as "zero perms."
  A blank result means you forgot to substitute.
- **The stamp readiness check is the `critical_badpath` substring**, not the
  presence of `rule=`. Grepping for "has a `rule=` stamp" is the wrong test.
- **There is no automatic abort.** `PERM_RATE_ALERT_*` only notifies. A silent
  tripwire is not a green light, and ladder perms keep landing every `*/5` scan
  while you wait. Backing out is `swatter rollback-ladder --since <ts>` — **never**
  a config revert, which does not undo bans already placed.
- **Publication freeze is holding** — last swarm publish `2026-07-27 23:40:07`,
  none since; `SWARM_PUBLISH=false`, `ABUSEIPDB_REPORT=false`. Restoring publishes
  the *entire* backlog at once (`swatter_swarm_publish` defers, it does not
  suppress), so the ~08-10 unfreeze is a reviewed flip, not a blind one.
