# Changelog

All notable changes to Swatter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
- **README "Nightly digest" section synced with v2.2.0** — documents the opt-in
  origin-lock digest plane (`ORIGIN_LOCK_DIGEST` / `ORIGIN_LOCK_LOG`), notes the
  structured HTML report, and replaces the stale "set the cron hour" manual-edit
  framing with config-driven, DST-aware scheduling (`REPORT_CRON` /
  `REPORT_CRON_TZ`).

## [2.2.0] — 2026-06-25

### Changed
- **Nightly report redesigned as structured Direction-B HTML** — header →
  color-coded verdict line → stat tiles → per-plane sections with tables,
  replacing the old summary-pills-over-a-monospace-`<pre>` dump. Stat-tile
  labels, table column headers, section headers, and the report title are all
  Title Case.
- **"Report" wording throughout** — the subject line is now
  `Report {YYYY-MM-DD} — {summary}` (UTC date, brand in the sender name),
  replacing the old `[Swatter] … in <window> — host` format.

### Added
- **Opt-in Origin-Lock digest plane** (`ORIGIN_LOCK_DIGEST`, default `auto`):
  when the reporting window contains `ORIGIN-LOCK:` syslog hits the nightly
  report gains a dedicated section showing drop count, unique source IPs,
  `:80`/`:443` split, and top sources tagged attacker/legit. Invisible for
  operators who don't run the lock. New `ORIGIN_LOCK_LOG` config key selects
  the syslog source.
- **Config-driven, DST-aware report scheduling**: new `REPORT_CRON`
  (default `0 4`) and `REPORT_CRON_TZ` (IANA zone; empty = server/UTC). The
  installer generates `/etc/cron.d/swatter` with an optional `CRON_TZ` line,
  replacing the DST-drifting static `0 11 UTC` line.
- `test/report_test.sh` — HTML render coverage (verdict line, stat tiles,
  per-plane sections, Title Case, data-gated origin-lock block).
- `test/report_cron_test.sh` — cron scheduling coverage (TZ header, default
  time, custom time + zone, empty-zone fallback).
- Origin-lock digest coverage added to `test/origin_lock_test.sh`.

## [2.1.3] — 2026-06-25

### Changed
- **A new `skipped-novhost` action distinguishes "no nameable target vhost this
  window" from a genuine config gap.** 2.1.2 folded an empty `top_vhost` into
  `skipped-config`, but that outcome is *data-dependent* — a raw-IP / no-Host
  offender may present a blockable vhost on the next scan — so labeling it a
  deterministic misconfig was misleading (an operator "fixing" the zone map
  wouldn't change anything). `swatter_cf_block` now returns `SWATTER_RC_NOVHOST`
  for an empty vhost and `_swatter_execute_block` audits it as `skipped-novhost`;
  `skipped-config` is reserved for true config gaps (vhost not in
  `CF_DOMAINS_MAP`, missing token).
- **The backend return-code protocol is now defined once** as `SWATTER_RC_*`
  constants in `lib/common.sh` (the single source of truth) and referenced by the
  `block_*.sh` producers and `score.sh` consumer, instead of magic `2`/`3`/`4`
  scattered across four files.
- Documented the failure-vs-skip axis in `config/swatter.example.conf`:
  config/credential/zone-map gaps → `skipped-config` (quiet, per-offender);
  broken host tooling / zone-lookup / live API errors → `failed` (loud).

### Added
- `test/block_cf_test.sh` — pins the `swatter_cf_block` return-code contract
  (empty vhost → novhost, unmapped/no-token → config, tooling/zone/API → failed,
  duplicate → success), so a future edit can't silently re-break the taxonomy.
- `test/block_csf_test.sh` — pins the CSF cap (`return 2`), dry-run, enforce, and
  missing-csf return codes (the DIRECT-plane counterpart to the existing ipset
  cap test).
- `scan_wire_test.sh`: a `skipped-novhost` case, plus tighter store/channel
  assertions on the cap/precondition cases.

Credit: this round of hardening was again driven by an adversarial code review
from Grok (via Cursor 2.5).

## [2.1.2] — 2026-06-25

### Changed
- **Backend block calls now use a return-code protocol so deliberate non-blocks
  aren't mislabeled `failed`.** The 2.1.1 fix audited every non-zero backend
  return as `failed`, which lumped two *deliberate* outcomes in with real errors:
  a per-run deny cap (`MAX_CSF_DENIES_PER_RUN`, which the CSF/ipset backends
  signal with `return 2`) and deterministic Cloudflare preconditions that retrying
  can never satisfy (no target vhost, vhost absent from `CF_DOMAINS_MAP`, no token
  — now `return 3`). `_swatter_execute_block` maps `2 → skipped-cap` (mirroring the
  existing `MAX_BLOCKS_PER_RUN` skip) and `3 → skipped-config`; only genuine
  backend errors (API timeout/5xx, unresolved zone, failed `csf`/`ipset` command,
  missing tooling) remain `failed`. Keeps a misconfigured zone map or an exhausted
  cap from masquerading as a wave of firewall failures every `*/5` run.
- Documented the full decision-log action vocabulary (and which actions count
  toward the digest block tallies) in `config/swatter.example.conf` and
  `lib/report.sh`.

### Added
- `scan_wire_test.sh`: regression coverage for the VIA_CF failure path (the exact
  prod mode that produced the original `52.138.3.29` evidence), the `temp` failure
  path, and the new `skipped-cap` / `skipped-config` return-code mappings.
- `config_defaults_test.sh`: asserts origin-lock resolves to `off` when
  `ORIGIN_LOCK` is unset (guards the "shipped inert" claim).

### Notes
- Verified against the live prod CSF (cPanel build): `csf -d` on an already-denied
  IP exits `0`, so a duplicate permanent deny is recorded as success — no inverse
  "real block logged as failed" bug exists on the DIRECT plane. No code change
  needed there; documented for future reference.

Credit: hardening in this release was driven by an adversarial code review from
Grok (via Cursor 2.5).

## [2.1.1] — 2026-06-25

### Fixed
- **Failed firewall blocks are no longer logged as successful `perm`/`temp`
  decisions.** When a backend block call returned non-zero (`did=0`) — e.g. a
  Cloudflare API timeout/5xx, an unresolved zone, a missing token, or a CSF
  failure — `_swatter_execute_block` still audited the *intended* action,
  recording a block that never reached the firewall while `offenders.perm` stayed
  unset. That made the same offender re-attempt and re-log `perm` every `*/5`
  scan cycle until the call finally landed, inflating the nightly digest's block
  counts with phantom/duplicate entries and masking real block failures. Failed
  attempts are now audited as a distinct `failed` action (with the attempted
  action in the reason); the decision log and digest count only blocks that
  actually landed, and a failed block legitimately retries next run instead of
  looping. Also surfaced a latent test gap in `scan_wire_test.sh`, which stubbed
  only `swatter_csf_*` (never the `swatter_block_direct_*` the scorer calls), so
  `did=0` in every case and the `perm` assertions passed *because of* the bug;
  the test now stubs the real backends and asserts both the success and
  failed-block paths.

## [2.1.0] — 2026-06-19

### Added
- **Inline origin lock** (`swatter origin-lock`) — an optional L3 firewall
  control that restricts the web ports (`80`/`443`) to Cloudflare ranges, so
  direct-to-origin Cloudflare-bypass traffic is dropped at the socket. The
  structural complement to the reactive direct-detection classifier. Off by
  default; a three-state `off` → `log` → `drop` ladder with a drop guard
  (`apply` runs `preflight` and requires confirmation before installing a
  `DROP`), fail-open rule composition (accept-first, drop-last; no rules at all
  on an empty/missing allowlist), IPv4 + IPv6 (gated on `ip6tables`), and
  optional `/.well-known/` domain-validation passthrough (ACME HTTP-01 +
  cPanel/Sectigo AutoSSL DCV). Persists via a `csfpre.sh` hook under CSF
  or a oneshot systemd unit standalone. Subcommands: `apply` / `status` /
  `preflight` / `disable`. Reuses `CLOUDFLARE_IPS_FILE`; configured via the new
  `ORIGIN_LOCK*` keys.

## [2.0.0] — 2026-06-17

A major release consolidating the intel engine, firewall backends, alerting, and
fleet support.

### Added
- **ipset firewall backend** (`DIRECT_BACKEND=ipset`) with `swatter setup-ipset`:
  timeout-capable `swatter4`/`swatter6` sets and idempotent iptables/ip6tables
  DROP rules, as a CSF-optional alternative for direct-plane blocks.
- **Keyless threat-intel feed registry** — FireHOL level1, CINS, DShield,
  blocklist.de, Emerging Threats compromised, and GreenSnow, enabled by default,
  refreshed by `swatter refresh-feeds`, each weighted by a confidence tier.
- **Opt-in keyed intel providers** — GreyNoise, AbuseIPDB, and Project Honeypot,
  consulted (quota-limited and cached) only for IPs already past the watch
  threshold.
- **AbuseIPDB daily blocklist provider** and **opt-in outbound AbuseIPDB
  reporting** for permanent bans (deduped, backgrounded; off by default).
- **ASN / hosting-provider scoring boost**, including IPv6 origin lookups
  (`origin6` via Team Cymru).
- **Honeypot trap paths** — operator-defined decoy URLs; a hit flags the IP for
  an instant permanent ban.
- **Fleet ban-sync** — allowlist-safe `export-bans` / `import-bans` to share the
  permanent-ban list across a multi-server fleet.
- **Multi-channel alerting** — rate-limited notifications over mail, SendGrid,
  Twilio, and generic webhooks.
- **SQLite persistence backend** and **Prometheus textfile metrics**.

### Changed
- Nightly digest counts both CSF and ipset backend blocks; reporting and
  fail-closed audit lines are backend-neutral.
- `setup-ipset` saves only Swatter's own named sets (never a blanket dump that
  could clobber other tools' sets); writes via temp-and-rename so a failed save
  never truncates existing bans.
- Spamhaus EDROP fetch dropped (merged upstream into DROP).

### Fixed
- Never report to AbuseIPDB while in dry-run / report mode.
- `export-bans` exports only IPs with an enforced, still-banned permanent action.
- Blocklist hits score at the configured confidence floor.
- Loud warning when `ip6tables` is absent instead of silently leaving IPv6 blocks
  unenforced.

## [1.2.2] — 2026-06-15

### Added
- **Direct-to-origin Cloudflare-bypass detection** — a live non-Cloudflare TCP
  socket to a web port is treated as direct evidence and routed to the CSF plane,
  even when the request carries a valid `Host` header.

## [1.2.1] — 2026-06-13

### Changed
- Nightly report runs at 11:00 UTC (early-morning Pacific); Cloudflare-posture
  follow-ups.

## [1.2.0] — 2026-06-13

### Added
- **Cloudflare posture auto-detection** (`CF_MODE=auto`) and first-class support
  for non-Cloudflare servers (either/or per-host).

## [1.1.0] — 2026-06-12

### Added
- `CF_MODE=skip` — operator-owned Cloudflare plane (you run your own edge WAF
  rules; via-CF offenders are logged and left to them).
- `swatter report --print` — emit the digest body to stdout without sending mail.
- Plain-English decisive-rule rendering in the digest.

### Fixed
- Exact IPv6 CIDR matching in the allowlist; ingest IP canonicalization;
  time-bounded crawler reverse/forward DNS lookups; direct-evidence set bounded
  to the scoring window.

## [1.0.0] — 2026-06-10

First public release. Cloudflare-aware abuse scoring from web-server logs with
plane-correct blocking (CSF for direct-to-origin, Cloudflare IP Access Rules for
via-proxy), a hardcoded Cloudflare never-block set, and fail-closed behavior when
the range list is stale.

[Unreleased]: https://github.com/peaceharborco/swatter/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/peaceharborco/swatter/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/peaceharborco/swatter/compare/v1.2.2...v2.0.0
[1.2.2]: https://github.com/peaceharborco/swatter/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/peaceharborco/swatter/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/peaceharborco/swatter/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/peaceharborco/swatter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/peaceharborco/swatter/releases/tag/v1.0.0
