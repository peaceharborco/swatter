# Handoff — publication unfreeze + gate D (2026-08-04)

**Repo:** `swatter` · **Branch:** `main` · **Tree:** clean at `6d9d35a`, pushed
to GitHub + GitLab.
**Status:** gate C is fully closed and every 2026-08-01 handoff item is resolved
(see the pickup note at the top of
`docs/handoff-2026-08-01-gate-c-band-and-scanner-sample.md`). This handoff
carries only what remains. Two clocks, two pickups:

| Pickup | When | What |
|---|---|---|
| **1. Publication unfreeze** | **~2026-08-10** (target, not a deadline) | Reviewed flip of `SWARM_PUBLISH` / `ABUSEIPDB_REPORT` |
| **2. Gate D** | **on/after 2026-08-26 22:40 UTC** (hard floor) | Widen `REPEAT_WINDOW_DAYS` 7 → 30, with preconditions |

Between now and then there is **nothing to do** except item 0 below, which is
passive.

Anchors that must not drift: cds1 go-live is `2026-07-27 23:44:45 UTC`
(pinned to the second — do not round); cds1 runs v2.12.0; SSH host alias is
`peaceharbor`.

---

## 0. Passive watch — the new tripwire (no action unless it fires)

Set 2026-08-04 and live: `PERM_RATE_ALERT_PER_RUN="5"`,
`PERM_RATE_ALERT_PER_DAY="70"` (`test-config` → `5/run 70/day`; backup
`/etc/swatter/swatter.conf.bak-2026-08-04`). Ratified **70** over the drafted
85 — keyed to the current regime's rolling-24h max of **59**, not the lifetime
83 from the June enforce ramp.

Context for judging a trip: the band over the full 7.9-day soak was per-day
p50 44 / p95 55 / max 59, and the max *crept* 54 → 59 during the soak;
`plane-upgrade` churn ran 9–28 rows/day. So a value in the low 60s is drift,
not an attack — **characterize before touching anything** (RUNBOOK §8 queries,
in each arm's own units), and remember the section's rule: going *down* needs
only evidence; going *up* needs a reason the peak was benign. Never raise it to
quiet it.

If it stays silent: that is **not** a green light for anything — it only
alerts, and it was sized to be quiet in this regime.

---

## 1. Publication unfreeze (~2026-08-10) — a reviewed flip, not a toggle

Frozen since the gate B deploy: `SWARM_PUBLISH=false`,
`ABUSEIPDB_REPORT=false`. Last swarm publish `2026-07-27 23:40:07`, none since.

**The trap:** `swatter_swarm_publish` **defers, it does not suppress**.
Flipping back publishes the **entire backlog since 2026-07-27 at once** — to
the swarm hub and (for perms, under `ABUSEIPDB_REPORT_MIN_ACTION=perm`) to
AbuseIPDB. That backlog now includes ~2 weeks of enforced perms from a regime
that has been reviewed (scanner_profile: 0 FPs in 63) — but review the actual
outgoing set, not the audit's memory of it.

- [ ] Size and eyeball the backlog first: what would go out, how many rows,
      any IP you would not stand behind publicly (allowlisted-after-the-fact,
      customer-adjacent, anything from the 08-01 FP audit's gray areas).
- [ ] Flip in `/etc/swatter/swatter.conf` (config is read per-process; takes
      effect next `*/5` scan). Flip **swarm first, AbuseIPDB second** if you
      want to stage the blast radius — they are independent knobs.
- [ ] Watch the first publish cycle: cursor advances, hub `/contribute` 200s,
      no rate-limit storms, AbuseIPDB accepts without 429s.
- [ ] If something bad went out: swarm has `/purge` (rate-limited);
      AbuseIPDB reports cannot be recalled — which is the whole reason this is
      a reviewed flip.

There is no date pressure. ~08-10 was picked as "enough soak to trust the
regime"; later is fine, earlier is not.

---

## 2. Gate D (floor 2026-08-26 22:40 UTC) — the date is necessary, NOT sufficient

The floor is when a 30-day window contains only post-deploy (stampable) temps
— 2,633 unstamped temps sit inside window=30 today, the last dated
`2026-07-27 22:40:01`. Before that instant, unstamped temps make
`REPEAT_N_CRITICAL_SINGLE` **degrade toward more banning** (bar drops 4 → 3),
which is why widening early is worse than it looks. Full mechanics: TODO.md
gate D section and the 08-01 handoff.

Preconditions, in order — none are optional:

- [ ] **Re-run the unstamped-temp check.** The stamp is conditional in code
      (`[[ -n "$drule" ]]`, `lib/score.sh`) — a temp with an empty
      `decisive_rule` is written unstamped even post-v2.11.0. Baseline
      2026-08-01: **0 of 664** post-deploy temps unstamped. The test is the
      `critical_badpath` **substring** in `reason`, NOT the presence of
      `rule=` — grepping for `rule=` is the wrong test.
- [ ] **Re-run the `scanner_profile` audit** from **raw domlogs**
      (`/home/*/logs/*.gz`), not swatter's evidence JSON (`sample_ua` is first
      UA only, `sample_paths` first 5 — they cannot support absolute claims).
      Baseline: 0 FPs in 63 (2026-08-01). This is a checklist item, not a
      "re-sample if a customer complains" trigger.
- [ ] **Populate `monitoring.cidr`** — still empty (0 non-comment lines,
      verified 2026-08-01). Uptime monitors / status probes get temp-banned by
      a 30-day ladder otherwise.
- [ ] **Run `swatter escalate-preview --window 30` fresh** (never review a
      saved list) and human-review every candidate — ASN, PTR, customer
      mapping, plane; anything resembling NAT/CGNAT, mobile carrier, VPN exit,
      crawler, or customer gets allowlisted **first**. Size expectation:
      **615 candidates** at window=30 vs 125 at window=7 (**4.9×**, not
      "triples") — this is a 615-row job, budget real time for it.
      **`escalate-preview` does not model `REPEAT_N_CRITICAL_SINGLE` at all**
      (its own preamble says so) — its counts are pure `REPEAT_N` math.
- [ ] Set `REPEAT_WINDOW_DAYS=30`. Then **watch the first 48h against gate
      D's own fresh baseline, not the gate C band** — the widen raises primary
      perms directly and second-leg rows indirectly by an amount the gate C
      measurement cannot predict, so the 5/70 tripwire numbers are **invalid
      after the widen** and must be re-baselined per RUNBOOK §8 (do not paste
      them forward).
- [ ] Backing out is an **operator** decision — `PERM_RATE_ALERT_*` only
      notifies, there is no automatic abort, and ladder perms keep landing
      every `*/5` scan while you deliberate. Undo of placed bans is
      `swatter rollback-ladder --since <ts>` — **never** a config revert,
      which does not undo bans already placed.

---

## Standing decisions (do not relitigate without new facts)

- **PII: redacted forward-only, history untouched** (`6d9d35a`, decision
  2026-08-04). Rewriting published history is irreversible and old commits
  stay reachable by SHA in GitHub's cache. Revisit only if the repo's
  public/private status itself is revisited.
- **Per-day 70 over 85**: regime-keyed per RUNBOOK §8's anti-ratchet rule. The
  June-ramp 83 is an event the tripwire *should* catch, not clear.
- **The two tripwire arms are different units** — per-run counts primary legs
  only; per-day counts every row (incl. `dual-plane` + `plane-upgrade`) over a
  **rolling** 24h. Never compare them directly; measure each in its own units
  (queries in RUNBOOK §8, and remember `strftime('%s','<soak-start>')`
  returns NULL silently if you forget to substitute — a blank result means a
  bad query, not a quiet host).
