# Swatter — TODO / parked items

## Metrics: wire node_exporter textfile collector into monitoring (parked 2026-07-09)

**Status:** DECIDED 2026-07-09 — **skip (option 3)**. Keeping NetData as the box
monitor; not installing node_exporter. The nightly email report + `/server-logs`
already surface everything the `.prom` metrics would show, so putting them on the
NetData dashboard is pure redundancy. Metrics step stays disabled (no-op) on cds1.
If we ever revisit (e.g. 2nd box / unified dashboards), prefer exposing the
metrics over a local HTTP endpoint scraped by NetData's `go.d/prometheus`
collector — no node_exporter daemon needed. Do NOT pick option 2 (dir-only): it
writes a `.prom` file nothing consumes.

Swatter emits node_exporter *textfile* format to
`/var/lib/node_exporter/textfile_collector/swatter.prom` (`METRICS_FILE`,
`lib/metrics.sh`). On cds1 the metrics step is a no-op — `test-config` shows
`metrics: /var/lib/node_exporter/textfile_collector missing/unwritable -> skipped`.

**Finding:** cds1 has **no node_exporter and no Prometheus** — the monitor is
**NetData** (v2.10.3). NetData can scrape a Prometheus *HTTP endpoint* but has no
collector that reads a `.prom` file off disk, so the textfile output has no
consumer as-is.

**Options when circling back:**
1. **node_exporter + NetData scrape** — install node_exporter (bind
   127.0.0.1:9100, `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`),
   create the dir, add a NetData `go.d/prometheus` job → 127.0.0.1:9100/metrics.
   Swatter metrics show in NetData. Cost: one new daemon on the box.
2. **Just create the dir** — `mkdir -p` + perms so root-cron writes `swatter.prom`
   cleanly (warning gone), metrics produced but nothing reads them yet. No daemon.
3. **Skip** — NetData + Swatter's nightly report + `/server-logs` already cover
   the box; the `.prom` is redundant. Leave the metrics step disabled.

Redundancy note: Swatter's own nightly report and `/server-logs` already surface
block / error / origin-lock counts, so #1 is mainly for putting the numbers on
the NetData dashboard specifically.

## Recidivism escalation: v2.11.0 deploy, then the cds1 window widening (open 2026-07-27)

**This is not "just widen to 30."** A release must ship and deploy first —
cds1 is running v2.10.0, which lacks the `REPEAT_ENABLE` abort lever, the
unblock watermark, the perm-gate residue fix, and the queued-perm gating that
makes the abort lever actually stop in-flight perms. Widening the window on
v2.10.0 would triple ban volume on the *least* safe version of the ladder that
exists. See `docs/superpowers/specs/2026-07-27-v2.11.0-release-and-cds1-deploy-design-v2.md`
for the full design; the work is staged across four gates, summarized here.
**`REPEAT_WINDOW_DAYS` is still 7 everywhere** — 30 is a cds1-only conf change
made at gate D, and it has not been made.

- [ ] **Gate A — build and release v2.11.0.** Local only. Grok review before
      the tag, mandatory for the residue fix and the queued-perm gating. Ends
      at a published `v2.11.0` (`make release V=2.11.0`).
- [ ] **Gate B — capture the baseline, then deploy to cds1.** Record
      `swatter version`, the enforced perm count, a sample of perm reasons,
      and the live state of `SWARM_PUBLISH`/`ABUSEIPDB_REPORT` before touching
      the box. Deploy under a maintenance hold (pause cron, install,
      `test-config`, one manual scan, re-enable). **Freeze publication here,
      not at the widen** — set `SWARM_PUBLISH=false` and
      `ABUSEIPDB_REPORT=false` before re-enabling cron, since perms flow from
      the deploy onward, not from the widen. Set a provisional
      `PERM_RATE_ALERT_PER_DAY` with headroom over cds1's known spike of 16
      (the shipped default of 15 would guarantee a false abort). The ladder
      stays ON throughout — this is not a no-op deploy, it changes ban
      arithmetic in the safer direction (watermark + residue fix).
- [ ] **Gate C — soak ~7 days, no config changes.** This is what brings the
      CRITICAL-single bar alive: it's inert until every in-window temp carries
      the `rule=` stamp, which pre-deploy temps lack. The soak also produces
      the tripwire's real numbers — record the per-day/per-run perm ceiling
      from the ledger and set `PERM_RATE_ALERT_PER_DAY`/`_PER_RUN` from that,
      not a guess.
- [ ] **Gate D — preview at 30, review, then widen.** In order: populate
      `monitoring.cidr` (still empty on cds1 — see below); run
      `swatter escalate-preview --window 30` fresh (never review a saved
      list); human-review every candidate (ASN, PTR, customer mapping, plane;
      anything resembling NAT/CGNAT, mobile carrier, VPN exit, crawler, or
      customer gets allowlisted first); confirm the gate B freeze is still
      active (nothing to change here); set `REPEAT_WINDOW_DAYS=30`; watch the
      first 48h to establish gate D's own rate baseline (abort is judged
      against *that*, not the gate C band, because gate C measured a 7-day
      window and gate D triples it — comparing against gate C's band
      guarantees either a false abort or a silently blind one). After 14
      clean days post-widen, review what accumulated during the freeze before
      restoring `SWARM_PUBLISH`/`ABUSEIPDB_REPORT` — restoring publishes the
      *entire* backlog at once (`swatter_swarm_publish` defers, it does not
      suppress), so the review is the point, not a formality.

Two items carried over as cds1-specific preconditions, still open:

- [ ] **Re-baseline any triage notes taken from `swatter top` before
      2026-07-27.** Its `OFFN`/`TEMP`/`PERM` columns used to include
      report-mode activity, and cds1 ran report mode before enforce
      (2026-06-12), so pre-fix numbers on that box are inflated by detections
      that were never enforced. `top` is not the formal gate — `escalate-preview`
      is — but the README and digest both train operators to triage from it.
      `TEMP` is a LIFETIME enforced count, not the ladder's windowed number;
      read `escalate-preview` for "how close is this IP to a perm."
- [ ] **`monitoring.cidr` is empty on cds1 — this is a gate D precondition,
      not a nicety.** `allow.cidr` holds 4 entries of which 3 are documented
      customer false positives (2026-06-10: a Fatbeam site owner, a Comcast
      residential owner, a T-Mobile mobile user). Add real monitoring,
      payment/webhook, and customer office ranges before the gate D preview.

Rollback at any point is `swatter rollback-ladder --since <ts>` — **never** a
config revert, which does not undo bans already placed. `REPEAT_ENABLE=false`
stops new ladder perms but does not stop honeypot or hard-intel perms (see
README).

## v2.11.0 deferred minors — carried from the SDD review (open 2026-07-27)

Recorded here because the per-task ledger they lived in is deleted once merged,
and the final whole-branch review triaged each as safe to defer, not as
resolved. None blocks the release; all were verified real.

- [ ] **Coverage debt: `pending_disarm_test` seeds one row per case.** Multi-row
      splitting is the behaviour the US/RS delimiter change most affects, and it
      is only manually verified (twice — by a task reviewer and by the final
      reviewer, both correct). Add a mixed multi-row case.
- [ ] **Coverage debt: the hard-intel dual-plane leg is uncovered** in
      `perm_gate_residue_test.sh` — the test drives the gate with `rep=0`, so
      `hard=0` and `_swatter_maybe_dual_plane` never fires.
- [ ] **`absent-db-also-fails-closed-redundant-with-missing-table` is a passenger
      assertion.** sqlite3 auto-creates the DB file, so that path is caught by the
      same check as the missing-table case. Already renamed to say so; delete or
      replace it with a case that can actually fail.
- [ ] **`swatter_store_record` is not transactional.** A partial write can leave
      `offenders.perm=1` with no `actions` row. Fail-safe (falls through to the
      ladder rather than banning), which is why it was deferred.

**Accepted as designed, not defects — do not "fix" without re-reading why:**

- While the ladder is disarmed, hard-intel dual-plane and plane-upgrade *retries*
  are held too, which is broader than "off gates ladder conversion only". Erring
  toward not banning is deliberate; reliably distinguishing them would need the
  substring matching that already produced one bypass (`projecthoneypot` matching
  a `*honeypot*` allowlist).
- Held rows also skip coverage and never-block cleanup while disarmed.

Both are documented in `docs/RUNBOOK.md` §2/§3.

## Validate the remaining silent-arithmetic knobs (DONE in v2.11.0)

- [x] SHIPPED 2026-07-27. The escalation knobs (`REPEAT_N`, `REPEAT_WINDOW_DAYS`,
      `REPEAT_N_CRITICAL_SINGLE`) and the tripwire knobs
      (`PERM_RATE_ALERT_PER_RUN`, `PERM_RATE_ALERT_PER_DAY`) are now validated at
      the end of `swatter_load_config`. The same hazard remains on `SCORE_TEMP`,
      `MAX_BLOCKS_PER_RUN`, `WINDOW_SECONDS`, and `MIN_REQS`: an empty or
      non-numeric value degrades silently rather than erroring, and under `set -u`
      a non-numeric value can exit the shell mid-scan. `PERSIST_N` and
      `TTL_LADDER` already have fallbacks. Apply the same `10#`-normalizing
      validation.

## App-signal ingest, Path A (next up, 2026-07-24)

Handoff at `~/Downloads/swatter-app-signal-handoff.md` (PII item withdrawn; the
no-IP-on-drop item stands). Deliberately sequenced *after* the recidivism work so
a perm-volume change has a clean baseline to be attributed against.

- [ ] Move the proposal to `docs/proposals/app-signals.md`, Grok-review it beside
      the file, fold blockers, then implement Path A behind `APP_SIGNAL_ENABLE=false`.
- [ ] Its design must account for the ladder as it now stands: the standing rule
      is "no perm-ban authority from app signals," but app signals raise scores →
      temps → and the ladder converts temps to perms. State how that indirect path
      is bounded.
- [ ] Verified 2026-07-24 and no longer open: `mod_remoteip` **is** in place on
      cds1 with `RemoteIPTrustedProxy` scoped to Cloudflare ranges, so a WP
      producer will log restored client IPs correctly.
