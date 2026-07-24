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

## Recidivism escalation: the cds1 window widening (open 2026-07-24)

The code shipped on `main` (see `docs/superpowers/specs/2026-07-24-recidivism-escalation-design.md`
§6 for the full rollout). **`REPEAT_WINDOW_DAYS` is still 7 everywhere** — 30 is a
cds1-only conf change, and it has not been made. These steps are ordered; do not
reorder them.

- [ ] **Populate `monitoring.cidr` on cds1 — this is a precondition, not a nicety.**
      It is currently empty of real ranges, and `allow.cidr` holds 4 entries of
      which 3 are documented customer false positives (2026-06-10: a Fatbeam site
      owner, a Comcast residential owner, a T-Mobile mobile user). Add real
      monitoring, payment/webhook, and customer office ranges first.
- [ ] **Run `swatter escalate-preview --window 30 > /root/escalate-30d.tsv`.**
      Read-only; safe while the `*/5` scan runs. Note the pre-fix version of this
      command under-reported by one offense, so any list captured before
      2026-07-24 is wrong and must be regenerated.
- [ ] **Human-review the candidates** — ASN, PTR, customer mapping, DIRECT vs CF
      plane. Anything resembling NAT/CGNAT, a mobile carrier, a VPN exit, a
      crawler, or a customer goes into the allowlist *before* the flip. Expect
      ~67 net-new (53 scoring ≥90) on the ledger as of 2026-07-24.
- [ ] **Set `SWARM_PUBLISH=false` on cds1 for 14 days** (operator decision,
      2026-07-24). The hub has host-wide purge only and a 7-day TTL, so a false
      ladder-perm cannot be retracted per-IP once published.
- [ ] **Set `REPEAT_WINDOW_DAYS=30` in `/etc/swatter/swatter.conf`.** cds1 only.
- [ ] Watch the perm-rate tripwire for 48h (thresholds 5/run, 15/day against an
      expected ~1-2/day net-new), then the first nightly digest.
- [ ] After 14 clean days, restore `SWARM_PUBLISH=true`.

Rollback at any point is `swatter rollback-ladder --since <ts>` — **never** a
config revert, which does not undo bans already placed.

## Validate the remaining silent-arithmetic knobs (open 2026-07-24)

- [ ] The escalation knobs (`REPEAT_N`, `REPEAT_WINDOW_DAYS`,
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
