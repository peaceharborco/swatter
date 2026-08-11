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
passive. (The backlog was sized 2026-08-08 and the two customer-facing bans it
surfaced — Automattic/Jetpack + the Ahrefs crawler — are cleared; see §1.)

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

> **STATUS 2026-08-11 01:30 UTC — swarm arm DONE, AbuseIPDB arm still frozen.**
> Backlog re-sized fresh at **264** (growth was ~7.7/day, **not** the 21/day
> predicted); 7 shared-consumer-VPN IPs allowlisted + unblocked first (264 →
> **257**); `SWARM_PUBLISH=true` flipped, one clean cycle published all 257,
> cursor `1785195601` → `1786410301`, hub `/contribute` 200, hub health ok, 0
> residual backlog, no WARN/ERROR. `ABUSEIPDB_REPORT` remains `false` by choice
> (staged). Conf backup: `/etc/swatter/swatter.conf.bak-2026-08-10-unfreeze`.
> The review found a cohort this document's own method could not have caught —
> see **todo.md → "Cloudflare WARP + shared consumer VPN exits"**, and note the
> methodology change: **profile the whole backlog by ASN, not just the weakly-
> corroborated slice.** Two IPs cleared on 08-08 as "defensible on confidence"
> were consumer VPN exits; a shared VPN exit legitimately earns high abuseipdb
> confidence, so the corroboration filter is blind to this class by construction.

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

**Two IPs had to be cleared before any flip** (both `request_flood`, the rule
that produced all three verified FPs already in `allow.cidr`) — **both DONE
2026-08-08 21:46 UTC**, backlog 249 → **247**:

- [x] `192.0.91.143` — **Automattic, Inc.** (Jetpack / WordPress.com),
      abuseipdb confidence **1**. No PTR, so a reverse-DNS sweep misses it;
      whois catches it. Publishing would have listed Automattic publicly as an
      abuser, and the ban was live on the **Cloudflare plane** (TTL-emulated
      perm expiring 2026-08-09 18:25 UTC) — plausibly breaking Jetpack on
      customer WP sites in the meantime.
- [x] `202.8.43.217` — **Ahrefs crawler** (`sardine985.ahrefs.net`), **no
      external intel at all**. The "crawler" category gate D says to allowlist
      first. Its CF block had already lapsed, but `offenders.perm=1` kept it in
      the publish set regardless — an expired block still publishes.

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
>
> **Verified 2026-08-08** for both IPs: `offenders.perm=0`, `plane_blocks`
> empty, no `cf-rules.tsv` ref, no `csf.deny` line, both present in
> `csf.allow` (from `--perm-allow`'s `csf -a`) and in `allow.cidr` with the
> full note. Delta re-counted at **247**; `pending_blocks WHERE action='perm'`
> = 0; freeze still `SWARM_PUBLISH=false` / `ABUSEIPDB_REPORT=false`.

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
- [x] **`monitoring.cidr` — RESOLVED 2026-08-08: correctly empty, nothing to
      populate.** Not because nothing probes the host — **foghorn does** — but
      because nothing that probes it is reachable by the ladder:
      - **`foghorn` (`peaceharborco/foghorn`, Worker `down-detector`) probes
        cds1 every minute** — `CHECK_URL=https://cds1.peaceharborhosting.com`,
        cron `* * * * *`, cache-busted (`?_cb=<epoch_ms>`), ~1,440 origin
        req/day. Confirmed live in `/etc/apache2/logs/access_log`:
        `GET /?_cb=… HTTP/2.0" 200` with an **empty UA** (`"-"`) — which is why
        a monitor-UA scan finds nothing. **It cannot be banned, for two
        independent reasons:** (1) it lands in the main `access_log`, and
        swatter ingests only `DOMLOGS_GLOB="/etc/apache2/logs/domlogs/*"` —
        that log is never read; (2) the requests arrive from **Cloudflare edge
        IPs** (162.158.163.234, 172.68.87.x, 172.69.40.x, 172.70.142.x), which
        are never-block via `cloudflare.cidr`.
      - **netdata** — bound to **127.0.0.1:19999 / :8125 and [::1]**,
        agent-push to Netdata Cloud (sole outbound: ACLK to 54.198.178.11:443),
        collectors `apache`/`mysql`/`phpfpm` only, **no `httpcheck`**. Its
        localhost polling is never-block anyway via `lib/allowlist.sh:243`
        (`127.*|::1|`RFC1918 → "local/private"); ledger has 0 rows for loopback
        or `67.225.133.76`. `monit`/`monitorix`/`zabbix-agent`/`node_exporter`
        inactive.
      - No third-party monitor: 0 hits for any known monitor UA (UptimeRobot,
        Pingdom, StatusCake, Site24x7, BetterUptime, HetrixTools, NodePing,
        Freshping, Cronitor, GTmetrix, Uptrends, Better Stack, Oh Dear) across
        current domlogs and the 25 most recent rotations. Origin-lock drops
        show no periodic prober — top sources are 1.2k–2.9k-hit scanners.

      **Conditional re-open — the one thing that would change this:** if
      foghorn's `CHECK_URL` is ever pointed at a **customer vhost** instead of
      the server hostname, its probes move into `domlogs/*` and become visible
      to swatter. 1,440/day cache-busted GETs with an empty UA is a plausible
      `request_flood` / `scanner_profile` shape. Re-open this item and add
      foghorn's source range if that URL changes.

      **Do NOT pre-populate with well-known monitor ranges "just in case"** —
      every CIDR in this file is a never-block, so adding ranges for services
      you do not use hands an attacker on one of those IPs a free pass.
      Re-open this item only if an external monitor is actually adopted.
      *Residual (operator-only): confirm no external uptime monitor exists that
      would not appear in this host's logs.*
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

## `request_flood` — characterized 2026-08-08 (watch, do not act yet)

Every false positive on record comes from this one rule: the three residential
visitors allowlisted 2026-07-27, plus Automattic and Ahrefs on 08-08. Its
lifetime perm record is **0 for 2** — it has driven exactly two perm bans ever,
and both were wrong. Temp behaviour, last 30d: **72 distinct IPs, none with
strong external corroboration** (56 no intel at all, 16 weak) — against 97%
hard-corroborated for the backlog as a whole.

**But it is NOT a gate D amplifier, and that concern was checked and dropped:**

- request_flood temps do not stack — **71 of 72 IPs have exactly 1 temp**, one
  has 2. None approach `REPEAT_N=3` in either window.
- Escalation candidates (≥3 temps, any rule): 13 at 7d, 90 at 30d — of which
  **0 carry a request_flood temp**. Widening the window escalates none of them.
- Note the two perms escalated on **cross-rule** `recidivism=3/7d`, not on
  request_flood repetition. A per-rule temp count is the WRONG test here;
  recidivism counts every rule's temps together.

So the residual cost is not perms, it is ~5 uncorroborated temp bans/day landing
on legitimate-looking traffic — customer-visible, self-expiring, and only
occasionally unlucky enough to combine with other rules into a perm. Worth
tuning on its own merits; **not** a gate D blocker.

(Aside: the 13/90 counts above are a rough proxy over the `actions` ledger and
are NOT `escalate-preview` numbers — that tool has its own logic and reports
125/615. Do not treat these as contradicting it; run it fresh per the gate D
checklist.)

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
