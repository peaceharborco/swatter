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

Between now and then item 0 below is passive — but **two live perm bans need
clearing regardless of the flip** (Automattic/Jetpack + the Ahrefs crawler; see
the backlog sizing in §1). Those are customer-facing today, not 08-10 work.

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

**The trap — swarm only:** `swatter_swarm_publish` **defers, it does not
suppress**. Flipping `SWARM_PUBLISH` publishes the **entire backlog since
2026-07-27 at once**.

**Correction (2026-08-08, Grok-falsified): the AbuseIPDB arm has NO backlog.**
`swatter_abuseipdb_report` has exactly one production caller —
`lib/score.sh:210`, inline at block time during a scan. There is no cursor and
no ledger replay; the only persistence is a per-IP dedup marker with a 900s
TTL, which *suppresses* rather than defers. Flipping `ABUSEIPDB_REPORT`
reports only perms placed **after** the flip.

> **Caveat — one real queue exists.** `_swatter_retry_pending`
> (`lib/score.sh:377`, called from `swatter_scan` at `:532`) re-drives the
> durable `pending_blocks` queue through `_swatter_apply_plane`. A queued
> **primary** perm that succeeds on retry after the flip **will** be reported.
> That is not a flush of the 249, but it is not nothing.
> **Pre-flip check (cheap, read-only):**
> `SELECT COUNT(*) FROM pending_blocks WHERE action='perm';` — verified **0**
> on 2026-08-08, but the queue can refill before the flip. Re-check on the day.

This inverts where the risk sits:

| arm | on flip | recallable? |
|---|---|---|
| `SWARM_PUBLISH` | whole backlog at once | yes — `/purge`, 7-day TTL |
| `ABUSEIPDB_REPORT` | ~21 IPs/day ongoing | **no** — no delete API |

So "flip swarm first to stage the blast radius" front-loads the *recallable*
arm's entire payload while the irreversible arm was never going to burst.
Ordering matters less than making sure the gray-area IPs reach neither.

### Backlog sizing — done 2026-08-08 (read-only)

Publisher's own delta query against live cursor `1785195601`
(`2026-07-27 23:40:01 UTC`):

- **249 distinct IPs**, spanning `2026-07-27 23:44:45` → 08-08. The oldest is
  exactly the go-live anchor — no pre-go-live leakage.
- **0 subsequently unblocked**; **0 overlap** with `allow.cidr` / `OPERATOR_IPS`
  — the four publish gates drop nothing, all 249 go out.
- Rule mix (deduped to primary legs): scanner_profile 144, critical_badpath 85,
  high_badpath_repeat 16, request_flood 2, error_burst 2.
- **242/249 (97%) carry abuseipdb confidence100 or spamhaus DROP.** Only 7 are
  weakly corroborated — that is the whole human-review set.

**Dedup gotcha:** dual-plane / plane-upgrade legs share a `ts` with the primary
leg, so a naive `JOIN ... ON r.ts = MAX(a.ts)` double-counts (369 vs 249).
Pick one row per IP. Separately, in SQLite `a.action="perm"` silently resolves
to the `offenders.perm` **column** (double quotes = identifier) and returns 0
rows — use single quotes.

**Two IPs must be cleared before any flip** (both `request_flood`, the rule
that produced all three verified FPs already in `allow.cidr`):

- [ ] `192.0.91.143` — **Automattic, Inc.** (Jetpack / WordPress.com),
      abuseipdb confidence **1**. No PTR, so a reverse-DNS sweep misses it;
      whois catches it. Publishing lists Automattic publicly as an abuser, and
      the ban plausibly breaks Jetpack on customer WP sites **right now**.
- [ ] `202.8.43.217` — **Ahrefs crawler** (`sardine985.ahrefs.net`), **no
      external intel at all**. The "crawler" category gate D says to allowlist
      first.

Both are live perm bans, so this is a customer-facing issue independent of
publication. Unblocking also drops them from the delta at the source
(`swatter_store_perm_ips_since` requires `offenders.perm=1`), taking the
backlog to 247. Allowlist first so a `*/5` scan cannot re-ban in the gap, then
unblock with `--perm-allow` — the whole unblock runs under
`swatter_with_state_lock` (`bin/swatter:158`), and `--perm-allow` additionally
issues `csf -a`, which a plain `swatter allow` does **not** (`bin/swatter:171`).
The inner `cmd_allow` no-ops ("already allowed"), preserving the richer note:

```bash
swatter allow 192.0.91.143 "Automattic/Jetpack infra - request_flood FP (abuseipdb confidence 1) - verified 2026-08-08"
swatter unblock 192.0.91.143 --perm-allow

swatter allow 202.8.43.217 "Ahrefs crawler (sardine985.ahrefs.net) - request_flood, no external intel - verified 2026-08-08"
swatter unblock 202.8.43.217 --perm-allow
```

> **Verify after — do not trust the exit code alone.** `swatter_store_unblock`
> runs **unconditionally at `bin/swatter:167`, before** the failure check at
> `:174`. So a backend that fails still leaves `offenders.perm=0` — the IP
> drops out of the publish delta and *looks* remediated while CSF or CF may
> still be denying it. Same pattern in `rollback-ladder`. Confirm live on both
> planes: `swatter list perm`, `swatter list cf`, `csf -g <ip>`.

The other 5 weak rows are defensible (confidence 76–92, or own `recidivism=3/7d`
evidence); `136.70.84.163`/`GOOGL-2` is a Google **Cloud customer** VM, not
Google Fiber residential and not Googlebot. A PTR sweep of all 249 surfaced only
the Ahrefs box and one EC2 instance (confidence100 + `crit-single` — publish it);
209 have no PTR at all, itself a scanner signal.

- [x] Size and eyeball the backlog first: what would go out, how many rows,
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
