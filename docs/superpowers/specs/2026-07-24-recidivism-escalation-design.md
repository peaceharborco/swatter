# Recidivism-based temp→perm escalation — design

**Date:** 2026-07-24
**Status:** design, revised after adversarial review
**Origin:** operator proposal, "recidivism-based temp→perm escalation" (cds1, Swatter 2.10.0)
**Review:** `2026-07-24-recidivism-escalation-design-review-grok.md` — two Grok
passes (correctness / safety) plus Claude-side sweeps. Both verdicts
EXECUTE-WITH-FIXES; all Blockers folded in below.

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
most recent `unblock` record — a `ts > (SELECT COALESCE(MAX(ts), 0) FROM actions
WHERE ip = ? AND action = 'unblock')` clause, mirrored in the flatfile awk
branch. Correct at any window length.

**Tests:** unblock clears the counter (2 temps → unblock → next offense is
`temp`, not `perm`); an unblock older than the temps does not clear them; the
flatfile branch matches sqlite.

---

## 4. PR 2 — guardrails, then the window

Sequenced so every irreversible step is preceded by its undo and its alarm.

### 4.1 Validate the escalation knobs (M2)

`lib/store_sqlite.sh:106` interpolates `REPEAT_WINDOW_DAYS` into
`$(( now - REPEAT_WINDOW_DAYS*86400 ))`. Tested directly:

| Value | Result |
|---|---|
| `""` | `since = now` → window **0 days** → count always 0 → **escalation silently disabled** |
| `"abc"` | same silent 0 |
| `"30d"` | hard error: *value too great for base* |

A config typo turns the feature off with no warning. Validate `REPEAT_N` and
`REPEAT_WINDOW_DAYS` at config load as positive integers with an upper bound
(90 days), falling back to the shipped default with a `log_warn` on violation.

### 4.2 Perm-rate alerting (M1)

`_report_grade` **explicitly** keeps blocks GREEN (`lib/report.sh:426-427`,
`:457-458`) — "they're Swatter working, not a problem." SMS keys on grade
(`lib/alerts.sh`); the circuit-breaker notify keys on `MAX_BLOCKS_PER_RUN`, not
perm count. A runaway wave would surface only as a larger number in a nightly
email that still reads All Clear, up to ~24h late.

Add a `swatter_notify` tripwire on permanent blocks placed per run and per
rolling 24h, thresholded via new config (`PERM_RATE_ALERT_PER_RUN`,
`PERM_RATE_ALERT_PER_DAY`), defaulting conservatively. This is the safety
control; the digest count in §4.5 is observability, not a substitute.

### 4.3 Rollback runbook (B2)

| Plane | Reality |
|---|---|
| DIRECT / CSF | `csf -d`, `ttl=0` → `expires_at=0`. **Never expires.** |
| VIA_CF | "perm" rewritten to ladder max via `_swatter_pick_ttl 99` = 259200s = **3 days**. Edge rule expires; ledger `offenders.perm=1` sticks. |

`swatter unblock` is one IP at a time (`bin/swatter:150-176`). Reverting
`REPEAT_WINDOW_DAYS` does **not** undo placed perms, and once `offenders.perm=1`
a later return re-applies perm through the legacy backfill in
`_swatter_perm_gate` (`lib/score.sh:285-292`) without needing 3 temps again.

Document a bulk-rollback procedure in the README: select ladder perms since a
timestamp from `decisions.jsonl` by `evidence.recidivism`, then loop
`swatter unblock`. **Config revert ≠ ban revert** must be stated explicitly.

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
Google/Bing/Apple/DuckDuckGo/Yahoo/Yandex only, `lib/allowlist.sh:208`), customer
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

Mitigation is the canary in §6 plus §4.2 alerting; populating `monitoring.cidr`
with real ranges is recommended before the flip.

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

**Config:** `config_defaults_test.sh` pins the shipped `REPEAT_WINDOW_DAYS`;
validation rejects empty / non-numeric / out-of-range with a warn and falls back.

---

## 6. Rollout

1. **PR 1** — unblock forgets. Ship and deploy.
2. **PR 2** — validation, alerting, rollback runbook, reason/evidence, digest,
   tests. Ship with the repo default still at 7.
3. **Canary:** set `REPEAT_WINDOW_DAYS=30` on cds1 in **report mode**, one cycle.
   Confirm the would-be escalations match the replayed 67.
4. **Human review** of the 67 net-new candidates — ASN, PTR, customer mapping,
   DIRECT vs CF plane split — before any enforced flip.
5. **Enforce flip** on cds1 only, with §4.2 alerting live.
6. Watch the first nightly digest and the perm-rate tripwire.

Rollback at any point: the §4.3 runbook, not a config revert.

Expected steady-state volume: ~67 net-new perms over ~6 weeks of comparable
traffic, roughly 1–2/day, against 1460 existing perms. No pressure on
`MAX_BLOCKS_PER_RUN=25`, though a day-1 backlog burst of returning 30-day
recidivists is possible and is what §4.2's per-run threshold is for.

---

## 7. Acceptance notes

The proposal required `104.168.115.241` to appear in the dry-run escalation list.
**It cannot, and the requirement is waived by decision.** The IP has 2 enforced
temps in its entire history, so no `N=3` rule reaches it. Under 3/30d its next
return is its 3rd in-window temp and escalates automatically; given its ~15-day
cadence and last activity 2026-07-03, that is due.

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
