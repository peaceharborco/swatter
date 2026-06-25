# Changelog

All notable changes to Swatter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

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
