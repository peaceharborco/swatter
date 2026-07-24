# Round-2 adversarial review — recidivism escalation design (revised)

**Date:** 2026-07-24
**Target:** `2026-07-24-recidivism-escalation-design.md` (post-round-1 rewrite)
**Round 1:** `2026-07-24-recidivism-escalation-design-review-grok.md`
**Reviewers:** Grok pass A (correctness of the folded fixes) · Grok pass B
(is the revised rollout genuinely safe, or mitigation theater) · Claude-side sweeps
**Verdicts:** pass A **EXECUTE-WITH-FIXES** · pass B **EXECUTE-WITH-FIXES**

Both passes independently confirm every round-1 Blocker was folded in
**correctly in substance**. Pass A found **no Blockers**. The remaining work
splits cleanly:

> **PR 1 and the non-irreversible parts of PR 2 are safe to build now.
> The cds1 30-day enforce flip is blocked** until three items become real
> mechanisms rather than prose.

---

## Confirmed closed from round 1

| Round-1 finding | Status |
|---|---|
| B1 `_swatter_ev_stamp` contract | Closed in design (§4.4); snippet verified `bash -n` clean |
| B4 unblock forgets | Closed as mechanism (§3) — and verified not a fail-open |
| M2 knob validation | Closed in design (§4.1), though placement needs pinning |
| M3 gross 127 → net-new 67 | Corrected (§4.6) |
| M5 / M6 tests | Expanded (§5 product regression) |
| M7 CF-3-day vs CSF-forever | Table added (§4.3) |
| Shipped default stays 7 | Correct (§4.6, §6) |
| M4 swarm propagation | **Documented only** — escalated to Blocker B2 below |

### PR 1 verified sound — not a fail-open

The chief risk in my own PR-1 fix was that some *automatic* path writes an
`unblock` row, which would silently reset the recidivism counter on every
expiry and disable escalation entirely. **Checked independently by me and by
both passes — it does not.**

| Path | Writes `actions.action='unblock'`? |
|---|---|
| `swatter_store_unblock` ← `cmd_unblock` (`bin/swatter:165`) | **Yes — the only production writer** |
| `swatter_cf_sweep_expired` (`lib/block_cf.sh:611-617`) | No — deletes edge refs only |
| CSF / ipset temp expiry | No ledger write |
| `cmd_allow`, `cmd_import_bans`, swarm purge | No |

Exact row contract: `action='unblock'`, `channel='none'`, `ttl=0`, `score=0`,
`reason='manual unblock'`, `dry_run=0` (`lib/store_sqlite.sh:222`).

---

## Blockers — gate the cds1 30-day enforce flip only

### B1 — The report-mode canary is theater and cannot gate anything
`[both passes + claude]` · verified three ways

§6 step 3 says: flip cds1 to report mode with `REPEAT_WINDOW_DAYS=30` for one
cycle and "confirm the would-be escalations match the replayed 67."

It cannot:

- **Ingest is byte-cursor based** (`lib/ingest.sh:5-11`, `:102-104`). One `*/5`
  cycle scores only ~5 minutes of *new* log bytes — it does not re-walk history.
- **Measured rate:** escalation events run **5.37/day** on cds1 (spikes to 16).
  One 5-minute cycle therefore expects **~0.02 events**. Observing a meaningful
  sample would take ~a week of report mode.
- **Report mode still advances the cursors.** `swatter_scan` always calls
  `swatter_ingest` (`lib/score.sh:421`), so attack traffic during the canary is
  *consumed* and will never be re-scored after the enforce flip — an
  actively harmful preview.
- **New attackers go unblocked** for the canary's duration on a live host.

Near-zero would-be perms would read as "canary clean," which is false confidence
in exactly the direction that hurts.

**Required:** delete the report-mode flip. The real preview already exists — the
offline ledger replay that produced the 67. Make it a command:
`swatter escalate-preview --window 30`, reading `actions` directly, ingesting
nothing, advancing no cursor, changing no mode. Step 4's human review then has a
real artifact to review.

### B2 — Rollback is a runbook sketch; the swarm leg is genuinely irreversible
`[pass-b]` · verified

§4.3 proposes: select ladder perms from `decisions.jsonl` by
`evidence.recidivism` since a timestamp, then loop `swatter unblock`. Four
verified problems:

1. **`decisions.jsonl` is rotated weekly with `compress`**
   (`install/swatter.logrotate`). A timestamp query over the live file silently
   misses everything past a rotation boundary. The durable source is the sqlite
   `actions` table, which the runbook never uses.
2. **`swatter unblock` is not bulk-safe.** `cmd_unblock` takes
   `swatter_with_state_lock` with a **30-second** default wait
   (`lib/common.sh:584`, `flock -w 30`) and dies on timeout. A 67-iteration loop
   contends with the `*/5` cron and aborts mid-list, leaving a partial undo — and
   a backend failure still clears the ledger before exiting non-zero
   (`bin/swatter:160-165`), so "the script failed" can mean state is half-applied.
3. **No per-IP swarm retract.** The hub exposes only host-wide `purgeHost`
   (`hub/src/index.js:125`), and `SWARM_TTL=604800` — **7 days**
   (`hub/wrangler.toml:17`). Unblocking locally stops *re*-publication but the
   hub already holds the contribution, and peer hosts may already have taken
   DIRECT temps from the feed (`lib/swarm.sh:161-216`). A false ladder-perm
   poisons the fleet for up to a week with no targeted undo.
4. **Not executable at 2am.** Round 1 asked for a rollback path; the revision
   answered with a paragraph.

**Required:** a real `swatter rollback-ladder --since <ts>` that selects from
sqlite, takes the lock **once**, continues past per-IP failures with a summary
rc, and prints the swarm gap explicitly. Plus one of: per-IP hub delete;
**`SWARM_PUBLISH=false` for the first N days after the flip** (simplest, and my
recommendation); or a written acceptance of up-to-7-day fleet poisoning with a
peer-side cleanup procedure.

### B3 — Empty `REPEAT_N` makes every first offense a permanent ban
`[pass-a]` · verified by execution — **new, and worse than the round-1 hazard**

Round 1 found that an empty/non-numeric `REPEAT_WINDOW_DAYS` silently yields a
0-day window (escalation never fires — fail-safe). The twin is the opposite and
catastrophic:

```bash
REPEAT_N=""      # (( prior + 1 >= REPEAT_N ))  ->  (( 1 >= 0 ))  ->  true
```

Every first temp becomes a **permanent ban**, on every IP, immediately. A single
typo in `swatter.conf` converts Swatter into a mass-perm-banning machine on a
multi-tenant host that publishes to a fleet.

This promotes §4.1 validation from a Major to a **Blocker**, and it must land in
PR 2 regardless of the window decision.

---

## Majors

### M1 — The perm-rate alert cannot be the safety control as specced
`[both]` · verified

§4.2 names it "the safety control," but against the code:

- **No wire point.** The only end-of-scan notify is the circuit breaker on
  `_SW_TOTAL_BLOCKS` (`lib/score.sh:529-531`); perms-placed-this-run is not a
  tracked counter, and `swatter_metrics_write` exposes only aggregate offender
  totals (`lib/metrics.sh:17-38`).
- **The rate limiter suppresses the incident.** `_notify_ratelimited`
  (`lib/notify.sh:14-24`) writes its marker and suppresses for
  `ALERT_REPEAT_TTL` — default **21600s = 6 hours** (`lib/common.sh:68`). A
  static key fires once and then goes silent for six hours *while the backlog
  continues*.
- **Marker written before send.** If every channel fails, the key is still
  marked and retries stay suppressed for 6h.
- **Thresholds undefined**, as is what counts (ladder only vs honeypot /
  dual-plane / plane-upgrade — note dual-plane writes up to two `perm` records
  per IP per run) and where the rolling 24h counter lives.
- §5 has no tests for it.

**Required:** a same-run counter in `swatter_scan`; concrete defaults; a key
strategy that cannot hide a multi-hour incident (hour-bucketed key, or escalating
body with running totals); tests for threshold trip and non-suppression across
consecutive runs.

### M2 — §4.7 residual risk needs one hard gate, not acceptance prose
`[pass-b]` · verified

With B1 (fake canary) and B2 (weak rollback) both hollow, "documented and
accepted" is the *only* thing standing between a CRITICAL single-probe chain and
a permanent ban. Facts unchanged: `monitoring.cidr` ships empty of real ranges;
`bm >= 100` floors the score at 90 and bypasses `MIN_REQS`
(`lib/score.awk:196`, `:240-241`), so one `/.env` hit is a temp; three such over
30 days is a perm; the img-tag/CSRF third-party drive-by stands.

**Proposed gate (small, mechanism not prose):** when every in-window temp's
evidence is CRITICAL-single (`badpath_cat=CRITICAL` with no multi-request or
multi-signal body), require `REPEAT_N + 1` before perm — a dedicated
`REPEAT_N_CRITICAL_SINGLE=4`. Multi-session scanners still escalate at 3;
one-hit probe chains need a fourth. Minimum fallback if that slips: block the
flip until `monitoring.cidr` and known payment/webhook/office ranges are
populated.

### M3 — §7's acceptance narrative is arithmetically wrong
`[pass-a]` · verified

§7 claims `104.168.115.241`'s "next return is its 3rd in-window temp and
escalates automatically." Against its own §1.3 timestamps and the
2026-07-24T18:16:32Z snapshot:

| Temp | Age at snapshot | Inside 30d? |
|---|---|---|
| 2026-06-18 19:45 | **35 days** | **No** |
| 2026-07-03 10:10 | 21 days | Yes |

So `prior = 1`, and its next return is temp #2 — **not** a perm. The *waiver*
still holds (2 enforced temps ever, so no N=3 rule reaches it), but the "due to
escalate" sentence must be rewritten from the actual timestamps.

### M4 — PR-1's SQL fragment must be AND-ed, and the flatfile port is not a mirror
`[pass-a]` · accepted

§3 shows only the new predicate. Spec must print the **full** statement so an
implementer cannot drop the window or the `dry_run=0` safety filter:

```sql
SELECT COUNT(*) FROM actions
 WHERE ip='…' AND action='temp' AND dry_run=0
   AND ts > ${since}
   AND ts > (SELECT COALESCE(MAX(ts),0) FROM actions
             WHERE ip='…' AND action='unblock');
```

The flatfile branch (`lib/store_sqlite.sh:111-117`) is a single-pass temp-only
scan; a correct port needs a per-IP unblock watermark resolved in `END`, not a
one-line change. "Mirrored" undersells it.

### M5 — §5 does not cover the new safety controls
`[both]` · accepted

Missing: preview-command output pinned against a seeded ledger; rollback
selection across a rotated/compressed log; perm-rate alert threshold trip and
rate-limit behavior under burst; digest `.evidence.recidivism`; an assertion that
the full count query retains window **and** `dry_run=0` **and** the watermark.

---

## Minors

- **m1** `[pass-a]` Line drift in the spec: crawler PTR list is
  `lib/allowlist.sh:209` (spec says `:208`); `_report_grade` comment ~428-429.
- **m2** `[pass-a]` Give `REPEAT_N` an upper bound too, so `REPEAT_N=999` isn't
  "valid".
- **m3** `[pass-a]` Same silent-arithmetic class exists on `SCORE_TEMP`,
  `MAX_BLOCKS_PER_RUN`, `WINDOW_SECONDS`, `MIN_REQS` — out of scope here, worth a
  TODO. `PERSIST_N` and `TTL_LADDER` already have fallbacks.
- **m4** `[pass-a]` `swatter allow` alone does not stamp an `unblock` row, so it
  does not reset the ladder — document that `unblock` (or `unblock --perm-allow`)
  is the correct operator path for a false positive.
- **m5** `[pass-a]` `lib/swarm.sh:209-216` uses `recent_temp_count` for TTL only
  and always applies temp — not a second escalation path. PR-1's watermark
  affects swarm TTLs benignly; worth a note.
- **m6** `[pass-a]` `config_defaults_test.sh` currently pins `PERSIST_N` but not
  the escalation knobs; §5's added pin is correct.
- **m7** `[pass-a]` `_swatter_ev_stamp` implementer traps: put the fallback
  *inside* the helper (`jq … 2>/dev/null || printf '%s' "$ev"`), guard
  `[[ "$val" =~ ^[0-9]+$ ]]` before `--argjson`, and treat empty `$ev` as `{}`.

---

## Net effect

The diagnosis and PR 1 are settled. What round 2 changes is the **rollout**: the
two controls the revision leaned on — the canary and the rollback runbook — are
not controls. They have to become two small subcommands
(`escalate-preview`, `rollback-ladder`), plus a decision on swarm publication
during the trial period, plus B3's validation which is now independently urgent.

**Recommended split:**

- **Now, unblocked:** PR 1 (unblock forgets) · PR 2a (knob validation incl. B3,
  ev-stamp, reason/evidence, digest, tests, default stays 7).
- **Before the cds1 flip:** PR 2b (`escalate-preview`, `rollback-ladder`,
  perm-rate alert wired per M1, swarm publish decision, M2's CRITICAL-single
  gate).
- **Then:** offline preview → human review of the candidate list → enforce flip
  with alerting live.
