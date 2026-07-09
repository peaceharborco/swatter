# Swatter — TODO / parked items

## Metrics: wire node_exporter textfile collector into monitoring (parked 2026-07-09)

**Status:** on hold — decision pending.

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
