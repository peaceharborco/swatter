# Operator runbook: recidivism ladder incidents

For the 3am case where a customer's site is down because Swatter permanently
banned something it shouldn't have — or is about to. Read section 1 first, do
the command, then keep going. Every command below is copy-pasteable and was
verified against `bin/swatter`'s dispatch table before this file was written.

---

## 1. Stop new ladder bans now

```
# /etc/swatter/swatter.conf
REPEAT_ENABLE="false"
```

```
swatter test-config
```

Confirm the output line reads:

```
  ladder:         DISARMED (REPEAT_ENABLE=false)
```

**Config is read once per process.** A scan already running when you edit the
file finishes under the *old* setting. If `*/5` cron is active, the next scan
to start is the first one that honors the change — normally under 5 minutes,
but don't assume it's instant if you're mid-incident.

This stops **new ladder escalations only**. It does not touch bans already
placed. Go to section 2 before you conclude anything is broken.

**`test-config` also prints a `crit-single=<N>` value in the `ladder knobs`
line — on a `STORE=flatfile` host, ignore it.** `REPEAT_N_CRITICAL_SINGLE` is
**INERT** without sqlite (`swatter_store_temps_all_critical_single` needs the
reason-indexed ledger, which flatfile doesn't have); escalation falls back to
the plain `REPEAT_N` bar for every offender, including ones whose temps were
all single CRITICAL probes. `test-config` prints the configured value
unconditionally regardless of store backend, so a flatfile host reads this as
a protection it does not actually have — check `swatter test-config`'s
`sqlite3:` line (or `STORE` in the running config) before relying on it.

---

## 2. You will still see permanent bans. That is not a bug.

With `REPEAT_ENABLE=false`, three sources still place permanent bans:

- **Honeypot hits** (`lib/score.sh`, the `is_honeypot` instant-perm branch) —
  any IP that requests the trap path is permed on sight, ladder or no ladder.
- **Hard-intel dual-plane** (`lib/score.sh`, `_swatter_maybe_dual_plane`) —
  an IP already scored >= `INTEL_HARDBLOCK_MIN` (Spamhaus DROP / AbuseIPDB 100)
  gets the *other* plane covered too, regardless of the ladder switch.
- **Plane-upgrade** (`lib/score.sh`, `_swatter_perm_gate`) — an IP already
  perm on one plane that reappears on the other plane gets covered there too.
  This includes the legacy-backfill path for a perm that predates per-plane
  tracking.

**How to tell them apart:** a ladder perm's `reason` contains `recidivism=`.
Honeypot and plane-upgrade never write that stamp. **Hard-intel dual-plane is
the one exception:** it reuses its primary leg's `reason` verbatim, prefixed
`dual-plane `, so if the primary leg was itself a ladder perm that also met
`INTEL_HARDBLOCK_MIN`, the dual-plane leg's reason carries `recidivism=` too
— that reads as "second plane of a ladder perm", not as an independent
hard-intel action, and it's still driven by the ladder switch's decision on
the primary leg. Run:

```
swatter why <ip>
```

and look at the reason string. If it says `honeypot ...`, `dual-plane ...`,
or `plane-upgrade ...` with no `recidivism=`, the switch is working exactly
as designed — do not re-enable the ladder to "test" it, and do not treat this
as evidence the disarm failed.

The retry queue holds the same distinction: queued **ladder** retries are held
while disarmed; queued **hard-intel dual-plane and plane-upgrade retries are
held too** (broader than "ladder only" — this is deliberate and conservative).
Only a genuine honeypot retry (evidence carries `"honeypot":1`) still fires
while disarmed.

---

## 3. Clear queued bans

Disarming **holds** queued perm intents in the retry queue — it does not clear
them. If you want the pause to also mean "and don't apply what's already
queued," you have to say so explicitly:

```
swatter pending --dry-run
```

Review what's queued (IP, plane, action, attempts, reason), then:

```
swatter pending --drain-perms
```

This clears only queued rows with `action=perm`; queued temps are left alone.
It also leaves a genuine **honeypot** perm intent queued (evidence carries
`"honeypot":1`) — the same trap hits section 2 says still fire while
disarmed. The drain agrees with that gate on purpose: honeypot is a separate,
always-on protection, not a ladder escalation, so an explicit drain doesn't
undo what the disarm gate just chose to keep armed. `swatter pending` reports
how many honeypot intents it left in place (`N honeypot intent(s) held, not
drained`) so this isn't silent.

**Held rows are not preserved indefinitely.** They're still subject to the
normal age/attempt reap (`PENDING_RETRY_MAX_ATTEMPTS`, default 12;
`PENDING_RETRY_MAX_AGE_HOURS`, default 24h) — that reap runs *before* the
disarm-hold check and keeps running while disarmed. A pause longer than 24h
loses the queued intent rather than preserving it: it gets dropped as
"retry-exhausted," not applied. If your incident runs longer than a day and
you need those intents to survive, don't rely on the pause — drain them
explicitly (above) or handle the IPs by hand.

While disarmed, held rows also skip the coverage check and the never-block/
invalid-target cleanup that normally run on every retry pass — they're
parked, untouched, until they're either drained, re-armed into, or reaped.

**Race: a scan can re-queue a perm right after the drain reports success.**
Unlike `rollback-ladder`, `swatter pending` takes no state lock. A `*/5` scan
that started just before you ran `--drain-perms` can still be mid-flight when
the drain finishes and, on a genuine backend failure, queue a fresh pending
perm for the same IP — landing after the drain already told you the queue
was clear. Before you re-arm (`REPEAT_ENABLE="true"`), re-run:

```
swatter pending
```

and confirm it reports `queue is empty`. If it doesn't, drain again before
re-arming.

---

## 4. Undo bans already placed

**Record the timestamp before you touch anything.** `--since` is a strict
`>` comparison — a ban placed in the same second as your recorded timestamp
will not match.

```
date -u +%s
```
(or note the wall-clock time before you start.)

Preview first:

```
swatter rollback-ladder --since <ts> --dry-run
```

Then run it for real:

```
swatter rollback-ladder --since <ts>
```

Requires `STORE=sqlite` — it selects on the ledger, not the rotated decision
log.

**It waits up to 120 seconds for the state lock, then dies** if a scan still
holds it — it does not queue or retry on its own. If it dies, wait for the
in-flight scan to finish (or the next `*/5` gap) and re-run.

**Never assume success from the fact that it returned.** Read the reported
counts:

```
rollback-ladder: <selected> selected, <unblocked> unblocked, <partial> partial
```

`partial > 0` means the ledger row was cleared for that IP but a firewall
backend (CSF and/or Cloudflare) failed to actually remove the block — **the
customer is still offline** even though the ledger says otherwise. The
per-IP `PARTIAL <ip>: ... failed; ledger cleared, firewall may still hold`
lines on stderr name which plane failed; check that plane by hand
(`swatter list perm` / `swatter list cf`) and clear it directly if needed.

If `ABUSEIPDB_REPORT=true` or `SWARM_ENABLE=true`, the command prints
additional notices on stderr — see section 6, they matter.

---

## 5. Bans it cannot undo

`rollback-ladder` selects on `reason LIKE '%recidivism=%'`. **That stamp is
new in this release.** Every ladder perm placed by a Swatter version before
this one has no `recidivism=` in its reason and is **invisible to
`rollback-ladder`** — it will not be selected, previewed, or touched, no
matter what `--since` you give it.

For those, per IP:

```
swatter why <ip>
swatter unblock <ip>
```

`swatter why` shows you the ledger history and recent decision-log evidence
so you can confirm it's actually a stale ladder perm before you unblock it.

---

## 6. What cannot be recalled

Once a ban is published outward, undoing it locally does not undo the
publication:

- **Swarm hub** — no per-IP retract exists. The only lever is a **host-wide
  purge** (`swatter swarm purge`), and even that only removes entries after a
  **7-day TTL** — peers may act on a since-unblocked IP until it expires.
  Don't run a full purge to fix one IP; it drops every contribution this host
  has made.
- **AbuseIPDB** — **no retract at all**. An IP reported while
  `ABUSEIPDB_REPORT=true` stays publicly listed as an abuser. The only path
  is requesting removal through AbuseIPDB's own contact form ("remove my
  reports" / report correction), from the account that owns the API key.

**Freezing swarm publication is a deferral, not a suppression.** Setting
`SWARM_PUBLISH="false"` stops new sends, but `swatter_swarm_publish` returns
before it ever reads or advances the publish cursor — so the backlog of
confirmed perm bans placed while frozen keeps accumulating unsent. The moment
you set `SWARM_PUBLISH="true"` again, the **entire accumulated backlog
publishes at once**, including anything you rolled back locally in the
meantime (rollback doesn't retract from the swarm delta query — it only
removes the local perm, so a since-unblocked IP is still "confirmed perm"
as far as the cursor is concerned unless you also cleared it before
re-enabling).

**Before re-enabling `SWARM_PUBLISH`, review what's about to go out.** Check
what was banned while frozen (`swatter list perm`, `swatter why <ip>` on
anything suspect) and roll back / unblock what shouldn't be published before
you flip the switch back on — not after.

---

## 7. A single false positive

Use `unblock`, not `allow`, as the first step — they are not interchangeable:

```
swatter unblock <ip>
swatter allow <ip> "false positive - <why>"
```

`swatter unblock` removes the live block **and resets the ladder's temp
count** for that IP. `swatter allow` alone does **not** reset the ladder — it
only adds the IP to the never-block set going forward. If you `allow` an IP
that's already mid-ladder without first `unblock`-ing it, its accumulated
temp count is still sitting in the ledger; running `swatter escalate-preview`
is how you'd notice something is off, and it's easy to get this order wrong
under pressure, so do `unblock` first, always.

If the block was already permanent, `unblock` clears the firewall block; run
`allow` after so it doesn't re-earn a ban on the next scan.

---

## 8. Alert vs abort

```
swatter test-config
```

reports:

```
  perm tripwire:  <N>/run <M>/day (ALERT floor — not an abort threshold)
```

`PERM_RATE_ALERT_PER_RUN` / `PERM_RATE_ALERT_PER_DAY` fire a notification —
they do not stop anything, and there is no separate abort threshold. **Never
raise these to quiet a noisy alarm.** Doing so raises the bar a genuine attack
wave has to clear before you find out about it — the nightly digest is not a
fallback for a raised tripwire; it grades enforced blocks GREEN by design, so
a wave that stays under a loosened threshold will read as routine in the
digest too.

If the tripwire is legitimately too sensitive for this host's normal traffic,
that's a signal to characterize the host's real band, not to blindly raise
the number.

### The two arms do not count the same thing

Measure each arm in **its own units** or the numbers you set will be wrong by
about 3×. Verified on cds1 2026-08-01: 207 enforced perm rows over 4.7 days
decompose into **67 primary, 70 `dual-plane`, 70 `plane-upgrade`**.

- **`PERM_RATE_ALERT_PER_RUN`** counts `SWATTER_RUN_PERMS`, which `lib/score.sh`
  guards with `audit_action == action` — the second plane leg for an IP is
  deliberately excluded so one IP is not double-counted. **Primary legs only.**
- **`PERM_RATE_ALERT_PER_DAY`** counts `swatter_store_perm_count_since`
  (`lib/store_sqlite.sh`), a bare `COUNT(*) ... action='perm' AND dry_run=0`
  over a **rolling 24h** — not a calendar day, and with **no** such filter.
  **Every row, including both plane legs.**

Three consequences when reading the per-day number:

1. **The ~3× gap is all second legs, and they are two different mechanisms —
   don't attribute it to one.** Of the 140 non-primary rows on cds1, **70 are
   `dual-plane`** and **70 are `plane-upgrade`**.
   - `dual-plane` is a **one-shot** hard-intel second leg: when an IP's
     reputation clears `INTEL_HARDBLOCK_MIN`, the other plane is covered at the
     same time as the first perm. It does not repeat and has nothing to do with
     Cloudflare TTLs.
   - `plane-upgrade` is the recurring one, and also the *only* one of the two
     that re-counts a single IP over time.
2. `plane-upgrade` re-counts **persistent** offenders, so the per-day figure
   overstates how many *distinct* IPs were newly banned. A Cloudflare "perm" is a
   TTL-emulated rule with a real expiry (ladder max, `_swatter_pick_ttl 99` →
   ~3d by default); `swatter_cf_sweep_expired` deletes the edge rule and
   `is_perm_on` — which reads `plane_blocks.expires_at`, not sweep success —
   stops holding. If that IP is then **re-observed scoring over `SCORE_TEMP`**,
   the perm gate writes a fresh `plane-upgrade` row (`lib/score.sh`,
   `test/cf_perm_ledger_test.sh` pins this). One durable attacker therefore
   contributes a new row roughly once per CF TTL for as long as it keeps
   attacking — on cds1 `plane-upgrade` ran 9-28 rows/day.

   It is **not** a function of the standing perm population: the gate sits
   inside the scored-IP loop, so an IP that stops sending traffic contributes
   nothing. Nor is `plane-upgrade` exclusively the CF-refresh case — the same
   label covers a first-time cross-plane upgrade and a legacy-import backfill.

   Widening `REPEAT_WINDOW_DAYS` does **not** directly manufacture
   still-attacking-after-TTL IPs. What it directly raises is *primary* perms
   (more IPs clear the ladder). The second-leg rows follow indirectly, and by an
   amount this measurement cannot predict — which is the actual reason a widen
   must re-baseline rather than reuse the prior band.
3. It is not comparable to the per-run number. "15/run, 120/day" is not an 8:1
   ratio of the same quantity.

This asymmetry is recorded, not resolved — changing the counting unit would
invalidate any band measured under the old one, so it is not a mid-soak edit.

### Measuring

**Measure from the ledger** (`actions` in `swatter.db`), not `swatter status`
(prints lifetime totals only — no per-day/per-run rate) and not
`decisions.jsonl` (rotates, so it cannot cover the window you need).

Per-day, in the arm's real units — **rolling 24h over all rows**. The calendar
`date()` grouping in earlier revisions of this runbook understates the peak
(cds1: 51 by calendar day vs 54 rolling):

```
sqlite3 /var/lib/swatter/swatter.db "
WITH r AS (SELECT a.ts, (SELECT COUNT(*) FROM actions b WHERE b.action='perm' AND b.dry_run=0 AND b.ts > a.ts-86400 AND b.ts <= a.ts) c
           FROM actions a WHERE a.action='perm' AND a.dry_run=0 AND a.ts >= strftime('%s','<soak-start>'))
SELECT MAX(c) FROM r;"
```

Per-run, bucketed by the `*/5` scan cadence and **filtered to primary legs** to
match `SWATTER_RUN_PERMS`:

```
sqlite3 /var/lib/swatter/swatter.db "
SELECT c, COUNT(*) FROM (
  SELECT ts/300 b, COUNT(*) c FROM actions
  WHERE action='perm' AND dry_run=0
    AND reason NOT LIKE 'dual-plane%' AND reason NOT LIKE 'plane-upgrade%'
    AND ts >= strftime('%s','<soak-start>')
  GROUP BY 1) GROUP BY 1 ORDER BY 1;"
```

(adjust `/var/lib/swatter/swatter.db` if `STATE_DIR` differs on this host.)

**Substitute `<soak-start>` with a real timestamp before running.** sqlite's
`strftime('%s','<soak-start>')` returns **NULL, not an error**, so `ts >= NULL`
matches nothing and both queries return a blank line rather than complaining —
a pasted-verbatim query looks like "zero perms" instead of failing. A blank
result means you forgot to substitute; it does not mean the host is quiet.

The band statistics quoted below need percentiles, which neither query above
returns — they give `MAX` and a bucket histogram. For the percentiles:

```
sqlite3 /var/lib/swatter/swatter.db "
WITH r AS (SELECT a.ts, (SELECT COUNT(*) FROM actions b WHERE b.action='perm' AND b.dry_run=0 AND b.ts > a.ts-86400 AND b.ts <= a.ts) c
           FROM actions a WHERE a.action='perm' AND a.dry_run=0 AND a.ts >= strftime('%s','<soak-start>')),
o AS (SELECT c, ROW_NUMBER() OVER (ORDER BY c) rn, COUNT(*) OVER () n FROM r)
SELECT 'p50='||MAX(CASE WHEN rn<=n*0.50 THEN c END)||' p95='||MAX(CASE WHEN rn<=n*0.95 THEN c END)||' max='||MAX(c) FROM o;"
```

(Swap the `r` CTE for the primary-leg-filtered per-run bucket query to get the
per-run percentiles.)

**Set the threshold above the band, not at it — and beware the ratchet.** p95
characterizes the band; it is not a threshold — by construction 5% of samples
sit at or above it, so setting p95 alarms constantly and trains you to ignore
it. Clear the **current regime's** max with modest headroom.

Do **not** make "clear the lifetime max" the standing rule. Lifetime max only
ever grows, so re-deriving from it after every incident ratchets the tripwire
permanently upward — which is the procedural form of the thing this section
opens by forbidding. Two guards:

- **A wave is not a new normal.** If the lifetime max was set by an event you
  would have wanted alerting on (cds1's 83 came from the June report→enforce
  ramp — a different operational epoch), exclude it and anchor on the regime you
  are actually operating in.
- **Never let a threshold rise to accommodate a peak you'd want to hear about.**
  Going *down* needs only evidence; going *up* needs a reason the peak was
  benign.

Sanity-check against the shipped defaults (`lib/common.sh`: 5/run, 15/day). A
per-host number **looser** than the shipped default should be justified out
loud or it is probably wrong — the defaults are the tested baseline, not a
starting bid.

```
This host's measured band:  cds1
  perms/run (primary legs):  p95 1   max 2    (lifetime max 4)
  perms/day (rolling 24h):   p95 51  max 54   (lifetime max 83, June enforce ramp)
  measured over:             2026-07-27 23:44:45 UTC + 4.7d, v2.11.0/v2.12.0, ~1350 runs
  last reviewed:             2026-08-01
```

---

## 9. Deploy / rollback

To hold cron across an upgrade (e.g. verifying `test-config` before the new
code goes live on the cron path):

```
install/install.sh remote <dest> --no-cron
```

This installs the new code but leaves whatever cron state already exists —
it does not touch `/etc/cron.d/swatter` or `/etc/cron.d/swatter-report`. Run
`swatter test-config` against the new install before re-enabling cron.

**Reinstalling the previous release tag is not a rollback.** It's capability
amputation: it silently removes `rollback-ladder`, `escalate-preview`, the
unblock watermark, the `REPEAT_N_CRITICAL_SINGLE` bar, the perm-rate
tripwire, and `REPEAT_ENABLE` itself, all at once — the exact tools this
runbook depends on. If you're rolling back because of THIS release's
behavior, you lose the ability to run half of the sections above. Prefer
fixing forward (disarm via section 1, drain via section 3) over downgrading.
If you must downgrade, do it with full knowledge that the recovery tools in
this document will no longer exist on that host until you upgrade again.

---

## Command reference used above

| Command | Purpose |
|---|---|
| `swatter test-config` | Confirm ladder armed/disarmed state and tripwire values |
| `swatter why <ip>` | Ledger history + decision evidence for one IP |
| `swatter pending [--drain-perms] [--dry-run]` | Inspect / clear the held retry queue |
| `swatter rollback-ladder --since <ts> [--dry-run]` | Bulk-undo ladder perms (recidivism-stamped only) |
| `swatter unblock <ip> [--perm-allow]` | Remove a block; resets the ladder count |
| `swatter allow <ip> [note]` | Never-block set; does NOT reset the ladder |
| `swatter escalate-preview [--window N]` | Who perms on their next offense |
| `install/install.sh remote <dest> --no-cron` | Deploy while holding cron state |
