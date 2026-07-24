# Consolidated adversarial review — recidivism escalation design

**Date:** 2026-07-24
**Target:** `2026-07-24-recidivism-escalation-design.md`
**Reviewers:** Grok pass A (correctness skeptic) · Grok pass B (safety red-teamer)
· `[code-review]` / `[security-review]` / `[gap]` Claude-side sweeps
**Model roster:** single family (`grok-4.5`) → lens mode, two complementary personas
**Verdicts:** pass A **EXECUTE-WITH-FIXES** · pass B **EXECUTE-WITH-FIXES**

Both passes confirm the design's central claim: the recidivism ladder already
exists, is already channel-independent, and the operator's proposed
`RECIDIVISM_*` knobs would duplicate `REPEAT_N` / `REPEAT_WINDOW_DAYS`. Widening
the window is the right lever.

Neither pass challenges §1 or §2. Every finding below is about **blast radius
and rollout**, not about the diagnosis.

---

## Blockers

### B1 — `_swatter_ev_stamp` is underspecified, and the failure mode is silent corruption
`[pass-a]` · verified

The design invents the helper and requires it "never fail the block path" without
defining it. `lib/common.sh:8` is `set -uo pipefail` **without `-e`** — a house
convention, deliberate. So a missing or failing helper does not abort: it returns
empty under `$(...)`, and `_swatter_audit` interpolates `$7` raw into hand-built
JSONL (`lib/score.sh:76-78`), producing `"evidence":` with no value. That is
malformed JSONL, which breaks the `jq` grouping in `report.sh` and `swatter why`
(`bin/swatter:142-145`).

This runs on the **success** path, where empty evidence is worse than on the
failure path that `lib/score.sh:200-208` models.

**Required contract:** merge with `jq -c --argjson n "$val" '. + {recidivism:$n}'`
(`--argjson`, not `--arg`); on *any* failure return `$ev` unchanged; never emit
empty; never die; never write to stderr inside the command substitution; refuse
to stamp a non-integer value.

### B2 — No rollback path for a deliberately 30×-widened permanent-ban funnel
`[both]` · verified

| Plane | Behavior |
|---|---|
| DIRECT / CSF | `csf -d`, `ttl=0` → `expires_at=0`. **Never expires.** Silent until a human unblocks. |
| VIA_CF | "perm" rewritten to ladder max via `_swatter_pick_ttl 99` = 259200s = **3 days**. Edge rule expires; ledger `offenders.perm=1` sticks. |

`swatter unblock` is **one IP at a time** (`bin/swatter:150-176`). There is no
bulk undo and no "reverse ladder escalations since T0". Reverting
`REPEAT_WINDOW_DAYS` to 7 does **not** clean up placed perms — nothing re-reads
old decisions against a shorter window. Worse, once `offenders.perm=1`, a later
return re-applies perm through the legacy backfill in `_swatter_perm_gate`
(`lib/score.sh:285-292`) without needing 3 temps again.

Design §6 has no rollback step at all.

### B3 — Allowlist coverage ≠ the false-positive classes a 30-day window opens
`[pass-b]` · verified

The gate is real (`lib/score.sh:106-110`), but on cds1 it covers almost nothing:
**`monitoring.cidr` has 0 non-comment entries** and **`allow.cidr` has 4** — of
which **3 are documented customer false positives from a single day**
(2026-06-10: a site owner on Fatbeam, a Comcast residential owner, a T-Mobile
mobile user). That is direct evidence that real customers do get caught.

Uncovered classes: NAT/CGNAT egress, mobile carrier gateways, VPN exits,
Cloudflare WARP client egress, non-PTR-verified crawlers (Ahrefs/Semrush/GPTBot —
the forward-confirm list is Google/Bing/Apple/DuckDuckGo/Yahoo/Yandex only,
`lib/allowlist.sh:208`), customer office IPs with a bad plugin, payment webhooks.

**Compounding factor:** a CRITICAL bad-path hit **bypasses `MIN_REQS` and floors
the score at 90** (`lib/score.awk:196`, `:240-241`). One single request to
`/.env` or `wp-config.php.bak` is already a temp block. So the escalation path is
not "three scanner sessions in a week" — it is **three single probes over thirty
days → permanent ban**. The 127-IP cohort is disproportionately the slow,
ambiguous class; fast scanners already perm quickly under 7d.

### B4 — Unblock does not forget
`[claude]` corroborated by `[pass-a]` · verified

`swatter_store_unblock` (`lib/store_sqlite.sh:219-229`) clears `offenders.perm`,
`plane_blocks`, and `pending_blocks` — but **not the historical `temp` rows in
`actions`**, which is exactly what `swatter_store_recent_temp_count` reads.

An operator who unblocks a false positive leaves 2 temp rows behind. The IP's
next trip over `SCORE_TEMP` computes `prior+1 = 3` and goes **straight to
permanent**, skipping the ladder entirely. Under a 7-day window that trap expires
in a week; under 30 days the operator's correction is silently undone for a
month.

Live example: `146.70.194.222` — 1 temp before its unblock, 3 after, and it is in
the 30-day escalation candidate list. 45 IPs have been manually unblocked; 10 of
them carried exactly 2 prior temps.

**Fix:** count only temps newer than the IP's most recent `unblock` record.
Correct at any window length; the fix is a `WHERE ts > (SELECT MAX(ts) …
action='unblock')` clause, not new machinery.

---

## Majors

### M1 — Permanent-ban rate is invisible to anything that would wake someone
`[both]` · verified

`_report_grade` **explicitly** keeps blocks GREEN (`lib/report.sh:426-427`,
`:457-458`) — "they're Swatter working, not a problem." SMS alerting keys on
grade (`lib/alerts.sh`); the circuit-breaker notify keys on `MAX_BLOCKS_PER_RUN`,
not on perm count. So a runaway escalation wave surfaces as a larger number in a
nightly email that still reads **All Clear**, up to ~24h late.

### M2 — `REPEAT_WINDOW_DAYS` is unvalidated, and a typo silently disables escalation
`[claude]`, independently recommended by `[pass-b m1]` · verified by execution

`lib/store_sqlite.sh:106` does `since=$(( now - REPEAT_WINDOW_DAYS*86400 ))`.
Tested directly:

| Value | Result |
|---|---|
| `""` | `since = now` → window **0 days** → count always 0 → **escalation never fires, silently** |
| `"abc"` | same silent 0 |
| `"30d"` | hard error: *value too great for base* |

A config typo turns the feature off with no warning. Validate both knobs as
positive integers at load, with an upper bound.

### M3 — The design's own risk number is wrong, and the truth is milder
`[gap]` · verified against the cds1 ledger

§3.1 presented the gross escalation count (127 at the 2026-07-24T18:16:32Z snapshot) as the risk figure. Decomposed:

| Outcome | IPs |
|---|---|
| Already permed later anyway — change only **accelerates** | 56 |
| Already permed *before* the 3rd temp — **no-op** | 4 |
| **Genuinely net-new permanent bans** | **67** |

Score distribution of the 67 net-new: **53 at ≥90**, 11 at 80-89, 3 at 70-79,
**0 below 70**. The spec must be corrected — the honest figure is 67 net-new,
overwhelmingly high-scoring, not 127 new bans.

### M4 — Swarm propagates false perms to the fleet
`[claude]` · verified

`SWARM_ENABLE="true"` on cds1, and `lib/swarm.sh:4,46` publishes **confirmed perm
bans** to the hub. A false ladder-perm therefore leaves this host and reaches
every other host consuming the feed. The design never mentions this.

### M5 — "Verified by test" is false today
`[pass-a]` · verified

No current test exercises `prior + 1 >= REPEAT_N → perm`. `test/` contains only
fixtures pinning `REPEAT_WINDOW_DAYS=7` and a malformed-IP case for
`recent_temp_count`. §3.2's table is aspiration, not present verification, and
the wording should say so.

### M6 — Test list misses the actual product regression
`[pass-a]` · accepted

§4 covers mechanics but omits the case that motivated the work: temps at T−15d
and T−1d, third offense now → **perm at 30d, temp at 7d**. Also missing: pin the
default in `config_defaults_test.sh`; assert the stamp leaves valid JSON against
real `score.awk` output; assert the no-jq path preserves `ev` and the reason
suffix.

### M7 — "Permanent" is overstated for the plane cds1 mostly uses
`[pass-b]` · verified

Most ladder perms on cds1 land on the CF plane as **3-day TTL-emulated** rules.
Only DIRECT/CSF is truly never-expiring. The design's blanket "permanent bans"
language will cause mis-triage.

### M8 — §3.2 imprecision
`[pass-a]` · verified

`swatter_store_plane_set` / `pending_set` are **sqlite-only functions**; the
*callers* gate on enforce (`lib/score.sh:153`, `:220-221`). Restate accordingly.

---

## Minors

- **m1** `[pass-a]` CSF truncates the comment to 120 chars (`lib/block_csf.sh:17`,
  `:48`). A long `intel=`/`asn=` label can push the recidivism suffix off the
  firewall comment; the ledger keeps the full string. Acceptable, worth a note.
- **m2** `[pass-a]` `evidence.swarm` is *constructed whole* (`lib/swarm.sh:216`),
  not post-stamped. `backend_err` / `retry:1` (`lib/score.sh:202`, `:390`) are the
  better pattern reference for a merge-into-scorer-JSON stamp.
- **m3** `[pass-a]` `recidivism=3temp/30d` → `recidivism=3/30d` reads better.
- **m4** `[pass-a]` `decisive_rule` vocabulary also emits `honeypot` and empty;
  `_RPT_RULE_LABELS` omits `honeypot`. Pre-existing; the design's conclusion
  (don't reuse the field) is unaffected.
- **m5** `[pass-a]` Line-number drift: the decision is `lib/score.sh:500`.
- **m6** `[pass-a]` Flatfile counting works but `plane_set` no-ops; sqlite-only
  tests are acceptable if stated.

---

## Declined

- **pass-a B1 — "the escalation snippet is invalid bash."** Correct about the text
  it was given: the unbalanced-paren line appeared in the *Grok prompt file I
  wrote*, not in the spec. Spec line 186 is valid (`bash -n` clean). Nothing to
  fix, but retained as a caution for implementation.
- **pass-b M2 — outbound AbuseIPDB reputational harm.** Conditional, not live:
  `ABUSEIPDB_REPORT` is not enabled on cds1. Keep as a note for other deployments.
- **pass-b B4, spoofing half — "attacker forges the client IP."** Mitigated:
  cds1's `mod_remoteip` sets `RemoteIPHeader CF-Connecting-IP` with
  `RemoteIPTrustedProxy` scoped to Cloudflare ranges, so the header is honored
  only from a CF socket. The *non-spoofing* half — driving victim traffic to a
  CRITICAL path via img-tag/CSRF, which costs an attacker three spaced hits
  instead of three in a week — stands, and is folded into B3.

---

## Net effect on the design

The diagnosis (§1, §2) survives intact and needs no change beyond precision fixes.
The **rollout** does not. Shipping `REPEAT_WINDOW_DAYS=30` as the repo default,
with no rollback, no perm-rate alert, an empty `monitoring.cidr`, an unblock that
doesn't forget, and swarm propagation, is not a one-number tune — it is an
irreversible multi-tenant safety change.

Minimum bar both passes converge on, plus the Claude-side findings:

1. Fix B4 (unblock forgets) and M2 (validate the knobs) — both are correct at any
   window length and should land regardless.
2. Specify `_swatter_ev_stamp` to the B1 contract.
3. Add a perm-rate alert (M1) and a documented bulk-rollback runbook (B2).
4. Keep the **shipped default at 7**; treat 30 as a cds1 conf change after a
   report-mode canary and human review of the 67 net-new candidates.
5. Correct §3.1's number to 67 net-new (M3) and the "permanent" language (M7).
6. Expand §4 with the 15-day regression and the stamp/JSON cases (M6).
