# Recidivism-based temp→perm escalation — design

**Date:** 2026-07-24
**Status:** design, revised after adversarial review
**Origin:** operator proposal, "recidivism-based temp→perm escalation" (cds1, Swatter 2.10.0)
**Reviews (two rounds, four Grok passes, all EXECUTE-WITH-FIXES):**
- Round 1: `2026-07-24-recidivism-escalation-design-review-grok.md`
- Round 2: `2026-07-24-recidivism-escalation-design-review-grok-rev2.md`

Round 2 confirmed every round-1 Blocker was folded in correctly and cleared PR 1
outright, but found the two controls this design leaned on — the report-mode
canary and the rollback runbook — were not controls at all. Both are replaced
with real mechanisms below, and a new Blocker (empty `REPEAT_N` ⇒ every first
offense is a permanent ban) was found and folded into §4.1.

---

## 1. Investigation (Task 1) — the originating hypothesis is refuted

The proposal hypothesized that permanent blocks only fire on the plane-upgrade
path (CSF→Cloudflare), and that an offender already on the Cloudflare plane has
no route to perm regardless of how many times it returns.

**That is not what the code does, and not what the data shows.**

### 1.1 Where perm decisions come from today

| Path | Location | Trigger |
|---|---|---|
| **Recidivism ladder** | decision at `lib/score.sh:500` (prior fetched `:497-498`) | `prior + 1 >= REPEAT_N`, where `prior` = enforced temp blocks within `REPEAT_WINDOW_DAYS` |
| Honeypot instant-perm | `lib/score.sh:479-487` | any honeypot trap-path hit |
| Hard-intel dual-plane | `_swatter_maybe_dual_plane` | `rep >= INTEL_HARDBLOCK_MIN` (default 100) |
| Plane-upgrade / legacy backfill | `_swatter_perm_gate` | already perm on the *other* plane, or `offenders.perm=1` with no `plane_blocks` row |

The recidivism ladder is the primary path, and it is **already
channel-independent**. The counting query (`lib/store_sqlite.sh:103-119`) is:

```sql
SELECT COUNT(*) FROM actions
 WHERE ip = ?
   AND action = 'temp'
   AND dry_run = 0
   AND ts > (now - REPEAT_WINDOW_DAYS * 86400);
```

No channel predicate. A `temp/cloudflare` and a `temp/csf` count identically
toward `REPEAT_N`.

### 1.2 Evidence from the cds1 ledger

- **1460 enforced perm decisions** exist in `actions`. Perm is not rare.
- Only **4 IPs in all of history** ever recorded a 3rd enforced temp inside a
  7-day span without escalating — all mid-June, consistent with the pre-2.9
  Cloudflare `duplicate_of_existing` counter-starvation bug documented at
  `lib/block_cf.sh:208-213` and fixed 2026-07-11. The counter works today.
- The proposal's supporting observation — that every IP which reached perm shows
  `plane-upgrade` as its last action — is a `swatter top` ordering artifact, not
  a mechanism. Counter-example: `104.28.196.52` went `temp` → `temp` → **`perm`**
  on 2026-06-14/15 through the plain ladder, with no plane-upgrade involved.

### 1.3 Why `104.168.115.241` never qualified

Its complete `actions` history:

```
2026-06-11 00:30 → 2026-06-12 03:10    25 × temp/csf         dry_run=1
2026-06-18 19:45                        1 × temp/cloudflare   dry_run=0
2026-07-03 10:10                        1 × temp/cloudflare   dry_run=0
```

Two independent reasons, both correct behavior:

1. **25 of its 27 temps are `dry_run=1`.** cds1 ran in report mode until the
   enforce cutover on 2026-06-12. `swatter_store_recent_temp_count` filters
   `dry_run=0` by deliberate design (`lib/store_sqlite.sh:100-102`): a
   report-mode detection means "we watched and did nothing," so it must not
   drive a real permanent ban the moment enforce is switched on.
2. **The 2 enforced temps are 15 days apart.** With `REPEAT_WINDOW_DAYS=7`, the
   in-window count is never above 1, so `prior + 1 = 2 < REPEAT_N = 3`.

cds1's config is stock: `REPEAT_N=3`, `REPEAT_WINDOW_DAYS=7`,
`SWATTER_MODE=enforce`, `STORE=sqlite`, version 2.10.0. No override involved.

**Correction to the proposal's framing:** there is no third offense "in the
current window." `plane_blocks` is empty for this IP, and it appears zero times
in the live decision log (spanning 2026-07-19 → present). Last activity:
2026-07-03.

### 1.4 Conclusion

The requested feature already exists. The gap is the **window length**: an
offender pacing at ~15-day intervals out-runs a 7-day counting window forever.
A tuning defect, not a missing mechanism — so the proposal's
`RECIDIVISM_PERM_COUNT` / `RECIDIVISM_PERM_WINDOW_DAYS` knobs are not built.
They would be a second name for `REPEAT_N` / `REPEAT_WINDOW_DAYS`, counting the
same rows with ambiguous precedence.

---

## 2. Same-day re-temps (Task 3) — expected behavior, not a failing block

The June 11 cluster (25 temps in ~27 hours) is entirely `dry_run=1`. **No CSF
block was ever placed**, so there was nothing to hold and nothing to prevent
re-offense. Report mode working as intended — option (c) in the proposal's
taxonomy, not (a).

The broader enforced dataset contains 1139 re-temps within 24h. The channel
split identifies the cause:

| Route | ≤10 min | 10–60 min | 1–24 h |
|---|---|---|---|
| cloudflare → cloudflare | 66 | 149 | 537 |
| cloudflare → csf | 67 | 65 | 75 |
| csf → cloudflare | 26 | 16 | 66 |
| **csf → csf** | **13** | **6** | **53** |

- **CSF temps hold.** 13 back-to-back `csf→csf` re-temps in six weeks of enforce
  against ~7000 enforced temps. Consistent with ingest cursor lag — log lines
  written *before* the deny landed, ingested on the following scan — not with
  blocks being dropped by `csf -tr` expiry or restart.
- **The volume is `cloudflare→cloudflare`** (752 of 1139), inherent to the
  deployment: cds1 runs `CF_ACTION=managed_challenge`, which *challenges* rather
  than blocks. A challenged IP legitimately keeps reaching the origin and keeps
  generating log lines, so it is re-decided on the next scan.

This is also why a live temp is deliberately **not** a noop
(`lib/score.sh:243-245`) — the gate short-circuits only on perm, specifically so
the temp→perm ladder keeps running. Self-correcting: two re-temps drive the IP
to perm within minutes.

**Action:** document in the README. No code change.

---

## 3. PR 1 — unblock must forget (standalone bug fix, lands first)

A live defect today, independent of any window change, and it gets worse with
any widening.

`swatter_store_unblock` (`lib/store_sqlite.sh:219-229`) clears `offenders.perm`,
`plane_blocks`, and `pending_blocks` — but **not the historical `temp` rows in
`actions`**, which is exactly what `swatter_store_recent_temp_count` reads.

So an operator who unblocks a false positive leaves the temp history intact. The
IP's next trip over `SCORE_TEMP` computes `prior + 1 = 3` and goes **straight to
permanent**, skipping the ladder entirely — silently undoing the operator's
correction.

Live evidence: 45 IPs have been manually unblocked on cds1; 10 carried exactly 2
prior enforced temps at unblock time. `146.70.194.222` shows 1 temp before its
unblock and 3 after, and appears in the 30-day escalation candidate list.

**Fix:** `swatter_store_recent_temp_count` counts only temps newer than the IP's
most recent `unblock` record. Correct at any window length.

The new predicate is **AND-ed onto** the existing query — it does not replace the
window or the `dry_run=0` report-mode filter. Full intended statement:

```sql
SELECT COUNT(*) FROM actions
 WHERE ip='…' AND action='temp' AND dry_run=0
   AND ts > ${since}
   AND ts > (SELECT COALESCE(MAX(ts),0) FROM actions
             WHERE ip='…' AND action='unblock');
```

**Verified not a fail-open.** The chief risk was that some *automatic* path
writes an `unblock` row, which would reset the counter on every expiry and
disable escalation entirely. It does not — `swatter_store_unblock` has exactly
one production caller, `cmd_unblock` (`bin/swatter:165`). `swatter_cf_sweep_expired`
(`lib/block_cf.sh:611-617`) deletes edge refs only; CSF/ipset expiry writes no
ledger row; `cmd_allow`, `cmd_import_bans`, and swarm purge write none. Row
contract: `action='unblock'`, `channel='none'`, `ttl=0`, `score=0`, `dry_run=0`
(`lib/store_sqlite.sh:222`).

Note `swatter allow` alone does **not** stamp an `unblock` row, so it does not
reset the ladder. `swatter unblock` (or `unblock --perm-allow`) is the correct
operator path for a false positive; this goes in the README.

**The flatfile branch is not a one-line mirror.** `lib/store_sqlite.sh:111-117`
is a single-pass temp-only scan; a correct port needs a per-IP unblock watermark
carried through the scan and resolved in `END`, since file order cannot be
assumed to equal `MAX(ts)` when tests stub `swatter_now`.

**Tests:** unblock clears the counter (2 temps → unblock → next offense is
`temp`, not `perm`); an unblock older than the temps does not clear them; the
flatfile branch matches sqlite.

---

## 4. PR 2 — guardrails, then the window

Sequenced so every irreversible step is preceded by its undo and its alarm.

### 4.1 Validate the escalation knobs — **highest-priority item in this document**

Both knobs are interpolated into bash arithmetic with no validation, and the two
failure modes are opposite. `lib/store_sqlite.sh:106` does
`since=$(( now - REPEAT_WINDOW_DAYS*86400 ))`; `lib/score.sh:500` does
`(( prior + 1 >= REPEAT_N ))`. Tested by execution:

| Knob | Value | Result |
|---|---|---|
| `REPEAT_WINDOW_DAYS` | `""` / `"abc"` | window **0 days** → count always 0 → escalation silently disabled (**fail-safe**) |
| `REPEAT_WINDOW_DAYS` | `"30d"` | hard error: *value too great for base* |
| **`REPEAT_N`** | **`""` / `"abc"`** | **`(( 1 >= 0 ))` → true → every first offense is a PERMANENT BAN** |

The `REPEAT_N` case is catastrophic: one typo in `swatter.conf` converts Swatter
into a mass-perm-banning machine on a multi-tenant host that publishes to a
fleet. It is unrelated to the window change and should land in PR 2a regardless
of what is decided about 30 days.

Validate both at the **end of `swatter_load_config`** — after the conf is
sourced, so operator config cannot bypass it, and before any lib reads the
globals. This covers the sqlite and flatfile paths equally since both read the
same variables. Rules: positive integers; `REPEAT_WINDOW_DAYS` ≤ 90;
`REPEAT_N` ≤ 20; on violation `log_warn` and fall back to the shipped default.

The same silent-arithmetic hazard exists on `SCORE_TEMP`, `MAX_BLOCKS_PER_RUN`,
`WINDOW_SECONDS`, and `MIN_REQS` (`PERSIST_N` and `TTL_LADDER` already have
fallbacks). Out of scope here — recorded in `TODO.md`.

### 4.2 Perm-rate alerting (M1)

`_report_grade` **explicitly** keeps blocks GREEN (`lib/report.sh:427-428`) —
"they're Swatter working, not a problem." SMS keys on grade
(`lib/alerts.sh`); the circuit-breaker notify keys on `MAX_BLOCKS_PER_RUN`, not
perm count. A runaway wave would surface only as a larger number in a nightly
email that still reads All Clear, up to ~24h late.

Add a `swatter_notify` tripwire on permanent blocks placed per run and per
rolling 24h, thresholded via new config (`PERM_RATE_ALERT_PER_RUN`,
`PERM_RATE_ALERT_PER_DAY`). The digest count in §4.5 is observability, not a
substitute.

Specified concretely, because "add an alert" is not implementable as written:

- **Wire point:** a run-scoped perm counter incremented in `_swatter_apply_plane`'s
  success branch, evaluated at the end of `swatter_scan` alongside the existing
  circuit-breaker notify (`lib/score.sh:529-531`). Perms placed this run are not
  tracked today — `swatter_metrics_write` exposes only aggregate offender totals
  (`lib/metrics.sh:17-38`).
- **What counts:** ladder perms only (`audit_action == action == "perm"`), so a
  dual-plane second leg — which writes up to two `perm` records per IP per run —
  does not double-count.
- **Rolling 24h source:** sqlite `actions`, not the rotated decision log.
- **Rate-limit hazard.** `_notify_ratelimited` (`lib/notify.sh:14-24`) writes its
  marker *before* channels send and suppresses for `ALERT_REPEAT_TTL` — default
  **21600s = 6 hours** (`lib/common.sh:68`). A static key would fire once and go
  silent for six hours while a backlog continues, and the marker is set even if
  every channel fails. Use an hour-bucketed key (`perm_rate.<epoch_hour>`) so a
  multi-hour incident cannot be hidden by a single early alert.
- **Defaults:** `PERM_RATE_ALERT_PER_RUN=5`, `PERM_RATE_ALERT_PER_DAY=15`.
  Steady-state net-new is ~1.6/day, so these trip well before a wave but above
  normal noise.
- **Not a substitute for the offline review.** Notify is best-effort network
  delivery and may fail during the very incident it is meant to catch.

### 4.3 Rollback runbook (B2)

| Plane | Reality |
|---|---|
| DIRECT / CSF | `csf -d`, `ttl=0` → `expires_at=0`. **Never expires.** |
| VIA_CF | "perm" rewritten to ladder max via `_swatter_pick_ttl 99` = 259200s = **3 days**. Edge rule expires; ledger `offenders.perm=1` sticks. |

`swatter unblock` is one IP at a time (`bin/swatter:150-176`). Reverting
`REPEAT_WINDOW_DAYS` does **not** undo placed perms, and once `offenders.perm=1`
a later return re-applies perm through the legacy backfill in
`_swatter_perm_gate` (`lib/score.sh:285-292`) without needing 3 temps again.

A README procedure is **not sufficient** — four verified reasons:

1. **`decisions.jsonl` is rotated weekly with `compress`**
   (`install/swatter.logrotate`), so a timestamp query over the live file
   silently misses everything past a rotation boundary. The durable source is the
   sqlite `actions` table.
2. **`swatter unblock` is not bulk-safe.** It takes `swatter_with_state_lock`
   with a **30-second** wait (`lib/common.sh:584`, `flock -w 30`) and dies on
   timeout. A 67-iteration loop contends with the `*/5` cron and aborts mid-list.
   A backend failure still clears the ledger before exiting non-zero
   (`bin/swatter:160-165`), so a "failed" script can leave state half-applied.
3. **No per-IP swarm retract.** The hub exposes only host-wide `purgeHost`
   (`hub/src/index.js:125`) and `SWARM_TTL=604800` — **7 days**
   (`hub/wrangler.toml:17`). Unblocking locally stops re-publication, but the hub
   already holds the contribution and peers may have taken DIRECT temps from the
   feed (`lib/swarm.sh:161-216`).
4. It is not executable by a tired operator at 2am.

**Required mechanism:** `swatter rollback-ladder --since <iso|epoch>` that
selects ladder perms from **sqlite** (not the rotated log), takes the state lock
**once**, unblocks in-process, continues past per-IP backend failures with a
summary rc, and prints the swarm gap explicitly.

**Swarm decision — DECIDED (operator, 2026-07-24):** set `SWARM_PUBLISH=false` on
cds1 for the **first 14 days** after the 30-day flip, so a false ladder-perm
stays on-box rather than propagating with a 7-day hub TTL and no per-IP retract.
Re-enable once the candidate set is trusted. (Alternatives considered and
rejected: a per-IP hub delete API — more surface than the trial warrants; or
accepting up-to-7-day fleet poisoning — not acceptable for a multi-tenant host.)

**Config revert ≠ ban revert** must be stated explicitly in the README.

### 4.4 The escalation reason (Task 2's readable-digest requirement)

In `lib/score.sh`, at the escalation branch:

```bash
if (( prior + 1 >= REPEAT_N )); then
    action="perm"
    reason="${reason} recidivism=$(( prior + 1 ))/${REPEAT_WINDOW_DAYS}d"
    ev="$(_swatter_ev_stamp "$ev" recidivism "$(( prior + 1 ))")"
fi
```

**`_swatter_ev_stamp` contract (B1).** `lib/common.sh:8` is `set -uo pipefail`
*without* `-e` — a deliberate house convention — so a missing or failing helper
does **not** abort the run. It returns empty under `$(...)`, and
`_swatter_audit` interpolates evidence raw into hand-built JSONL
(`lib/score.sh:76-78`), producing `"evidence":` with no value: malformed JSONL
that breaks `jq` in `report.sh` and `swatter why` (`bin/swatter:142-145`). The
helper must therefore:

1. merge via `jq -c --argjson n "$val" '. + {recidivism:$n}'` (`--argjson`, not
   `--arg`, so the field is a number);
2. return `$ev` **unchanged** on any failure — no jq, invalid JSON, non-zero rc;
3. never emit empty, never `die`, never write to stderr inside the substitution;
4. refuse to stamp a non-integer value.

Pattern reference is `backend_err` / `retry:1` (`lib/score.sh:202`, `:390`) — a
merge into scorer JSON — **not** `evidence.swarm`, which is constructed whole
(`lib/swarm.sh:216`).

**`evidence.decisive_rule` is deliberately not modified.** It is a vocabulary of
*behavioral* offense types from `lib/score.awk:282`, mapped to plain-language
digest groupings by `_RPT_RULE_LABELS` (`lib/report.sh:24-31`). Writing
`recidivism` into it would corrupt the "what are they doing" grouping and fall
through the label map as raw text. Recidivism answers *why we escalated*;
`decisive_rule` answers *what they did*. This is a deliberate departure from the
proposal, which named `.evidence.decisive_rule` as the carrier.

Note `lib/block_csf.sh:17,48` truncates the firewall comment to 120 chars, so a
long `intel=`/`asn=` label can push the suffix off the csf.deny comment. The
ledger and decision log keep the full string; accepted.

### 4.5 Digest surfacing

`lib/report.sh` gains a recidivism count matching `.evidence.recidivism`, the
same way it matches `.evidence.swarm` (`lib/report.sh:586-588`). Observability
only — the safety control is §4.2.

### 4.6 The window

`REPEAT_WINDOW_DAYS` **stays at 7 in the shipped repo default.** 30 is applied
to cds1's `/etc/swatter/swatter.conf` only, after the canary in §6. `REPEAT_N`
stays 3.

Replay of the real cds1 ledger, counting distinct IPs whose 3rd enforced temp
lands inside the window. All figures from a single snapshot,
**2026-07-24T18:16:32Z** — the ledger is live and these drift upward over time:

| Window | IPs |
|---|---|
| 7d (today) | 4 |
| 14d | 85 |
| **30d** | **127** |
| 60d | 134 |
| 90d | 134 |

Flat past 30 days, so 30 captures ~95% of achievable recall without extending a
permanent-ban decision onto evidence a quarter old.

**What those 127 actually are** — the number that matters is net-new, not gross:

| Outcome | IPs |
|---|---|
| Already permed later anyway — change only **accelerates** | 56 |
| Already permed *before* the 3rd temp — **no-op** | 4 |
| **Genuinely net-new permanent bans** | **67** |

Score distribution of the 67: **53 at ≥90**, 11 at 80-89, 3 at 70-79, none below
70.

`REPEAT_N=2` was considered and rejected: at 2/30d the set jumps to **1555 IPs**,
unacceptable false-positive exposure against the client-safety constraint.

### 4.7 Known residual risk (accepted, documented)

**Allowlist coverage is thin on cds1.** `monitoring.cidr` has **0** non-comment
entries; `allow.cidr` has **4**, of which **3 are documented customer false
positives** from 2026-06-10 (a site owner on Fatbeam, a Comcast residential
owner, a T-Mobile mobile user). Real customers do get caught by scoring.
Uncovered: NAT/CGNAT egress, mobile carrier gateways, VPN exits, Cloudflare WARP
client egress, non-forward-confirmed crawlers (the PTR list is
Google/Bing/Apple/DuckDuckGo/Yahoo/Yandex only, `lib/allowlist.sh:209`), customer
office IPs, payment webhooks.

**Compounding:** a CRITICAL bad-path hit **bypasses `MIN_REQS` and floors the
score at 90** (`lib/score.awk:196`, `:240-241`). One request to `/.env` is
already a temp. So the escalation path is *three single probes over thirty days*,
not "three scanner sessions in a week" — and an attacker can drive a third
party's IP there via img-tag/CSRF without spoofing anything.

Client-IP spoofing itself is **not** a viable route: cds1's `mod_remoteip` sets
`RemoteIPHeader CF-Connecting-IP` with `RemoteIPTrustedProxy` scoped to
Cloudflare ranges, so the header is honored only from a CF socket (verified).

**Swarm propagation.** `SWARM_ENABLE="true"` on cds1, and `lib/swarm.sh:4,46`
publishes confirmed perm bans to the hub — a false ladder-perm leaves this host
and reaches every consumer of the feed.

**This is not accepted as prose — it gets one hard gate.** With the report-mode
canary deleted and rollback reduced to a subcommand still to be written,
"documented and accepted" would be the only thing between a single-probe chain
and a permanent ban.

**Gate:** when *every* in-window temp for an IP is a CRITICAL-single — evidence
carrying `badpath_cat=CRITICAL` with no multi-request or multi-signal body —
require `REPEAT_N + 1` before perm, via a dedicated `REPEAT_N_CRITICAL_SINGLE=4`.
Multi-session scanners still escalate at 3; one-hit probe chains need a fourth.
This directly raises the cost of the img-tag/CSRF third-party drive-by.

Additionally, populating `monitoring.cidr` and known payment/webhook/office
ranges is a **precondition** of the flip, not a recommendation.

---

## 5. Testing

No existing test exercises the ladder — `test/` contains only fixtures pinning
`REPEAT_WINDOW_DAYS=7` and a malformed-IP case for `recent_temp_count`. So §4.6's
guarantees are *pinned by this PR*, not pre-verified.

New `test/recidivism_test.sh` against a seeded sqlite store:

**The product regression (the case that motivated the work):**
temps at T−15d and T−1d, third offense now → **perm at 30d, temp at 7d**.

**Counting semantics:**
- exactly `REPEAT_N` in-window → `perm`; `REPEAT_N - 1` → `temp` with ladder TTL
- oldest temp just past the window → `temp` (boundary `ts > since`, exclusive)
- `dry_run=1` rows excluded — the regression behind this investigation
- `watch` / `exempt` / `failed` / `noop-perm` excluded
- mixed channels (`temp/csf` + `temp/cloudflare`) counting toward one total
- **unblock resets the counter** (PR 1)

**Gates:**
- allowlisted IP at `REPEAT_N + 1` temps → audits `exempt`, no perm, no backend call
- report mode → decision logged as would-be, `plane_blocks` untouched
- per-run cap and fail-closed unchanged

**Stamp robustness:**
- stamp against real `score.awk` output leaves valid JSON
- no-jq path preserves `ev` and still emits the reason suffix
- non-integer value refused

**Config:** `config_defaults_test.sh` pins the shipped `REPEAT_WINDOW_DAYS` and
`REPEAT_N` (it currently pins `PERSIST_N` but neither escalation knob).
Validation rejects empty / non-numeric / out-of-range with a warn and falls back
— **including the `REPEAT_N=""` case, which must not perm on first offense.**

**Safety controls (PR 2b):**
- `escalate-preview` output pinned against a seeded ledger, and asserted to
  advance no cursor and change no mode
- `rollback-ladder` selects from sqlite across a rotated/compressed log window,
  takes the lock once, and continues past a per-IP backend failure
- perm-rate alert: threshold trip, ladder-only counting (a dual-plane leg does
  not double-count), and non-suppression across consecutive runs in a burst
- CRITICAL-single gate: 3 CRITICAL singles → temp; 4 → perm; 3 mixed-evidence
  temps → perm
- digest renders `.evidence.recidivism`

**Explicit assertion** that the full count query retains window **and**
`dry_run=0` **and** the unblock watermark — the three can be dropped
independently by a careless edit.

---

## 6. Rollout

1. **PR 1** — unblock forgets (§3). Ship and deploy.
2. **PR 2a** — knob validation (§4.1), `_swatter_ev_stamp` + reason/evidence
   (§4.4), digest (§4.5), tests. Repo default stays 7. Nothing here is
   irreversible; ship freely.
3. **PR 2b** — the pre-flip controls: `swatter escalate-preview`,
   `swatter rollback-ladder` (§4.3), the perm-rate alert wired per §4.2, and the
   §4.7 CRITICAL-single gate.
4. **Offline preview:** `swatter escalate-preview --window 30` on cds1. Reads
   `actions` directly — no ingest, no cursor advance, no mode change.
5. **Human review** of the candidate list — ASN, PTR, customer mapping, DIRECT vs
   CF plane split.
6. **Swarm decision** (§4.3) applied.
7. **Enforce flip** on cds1 only (`/etc/swatter/swatter.conf`), alerting live.
8. Watch the perm-rate tripwire and the first nightly digest.

**There is no report-mode canary.** An earlier draft proposed flipping cds1 to
report mode for one cycle to "confirm the would-be escalations match the 67."
That cannot work and is actively harmful:

- Ingest is byte-cursor based (`lib/ingest.sh:5-11`, `:102-104`); one `*/5` cycle
  scores ~5 minutes of *new* log bytes, not 30 days of history.
- Measured escalation rate on cds1 is **5.37 events/day** (spikes to 16), so one
  cycle expects **~0.02 events**. A meaningful sample would need ~a week.
- Report mode **still advances the cursors** (`lib/score.sh:421`), so attack
  traffic during the canary is consumed and never re-scored after the flip.
- New attackers go unblocked for its duration on a live host.

Near-zero would-be perms would read as "clean" — false confidence in the
dangerous direction. Step 4's offline preview is the real gate.

Rollback at any point: `swatter rollback-ladder`, not a config revert.

Expected steady-state volume: ~67 net-new perms over ~6 weeks of comparable
traffic, roughly 1–2/day, against 1460 existing perms. No pressure on
`MAX_BLOCKS_PER_RUN=25`, though a day-1 backlog burst of returning 30-day
recidivists is possible and is what §4.2's per-run threshold is for.

---

## 7. Acceptance notes

The proposal required `104.168.115.241` to appear in the dry-run escalation list.
**It cannot, and the requirement is waived by decision.** The IP has 2 enforced
temps in its entire history, so no `N=3` rule reaches it.

Nor will its next return escalate it. Against the 2026-07-24T18:16:32Z snapshot:

| Temp | Age | Inside a 30-day window? |
|---|---|---|
| 2026-06-18 19:45 | **35 days** | **No** |
| 2026-07-03 10:10 | 21 days | Yes |

So `prior = 1` today, and its next return is temp #2 — still not a perm. It
would need two further returns while enough priors remain in-window (e.g. a
return within ~9 days of now, then a third before the 07-03 temp ages out).
Given its observed ~15-day cadence, that is plausible but not automatic.

The proposal also asked to count "`temp` (and `dual-plane` temp) decisions."
There is no such thing: `_swatter_maybe_dual_plane` returns early unless
`action == perm`, so a dual-plane leg is never a temp. No special handling.

---

## 8. Explicitly out of scope

- Any change to `decisive_rule` semantics.
- Any change to report-mode semantics.
- Any change to the CSF/ipset or Cloudflare backends.
- The `managed_challenge` re-temp volume (documented, not changed).
- App-signal ingest (Path A) — sequenced after this work; see
  `~/Downloads/swatter-app-signal-handoff.md`. Its own rule ("don't let app
  signals reach perm-ban authority") interacts with the ladder, so its design
  should account for the post-change escalation behavior.
