# Changelog

All notable changes to Swatter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **AbuseIPDB reporting is now perm-only by default** (`ABUSEIPDB_REPORT_MIN_ACTION`,
  default `perm`). A first-seen temp block — including a swarm-corroborated temp —
  is no longer auto-reported as outbound reputational harm to a third party; only
  high-confidence repeat-offender / hard-intel perm bans are. Set to `temp` for the
  old behavior. (Swarm re-publish was already perm-only, and swarm-corroborated
  blocks are temps, so this also stops a false-positive from being amplified.)

## [2.9.3] - 2026-07-17

### Fixed
- **`notify.sh` supports a Twilio Messaging Service SID.** The generic notifier
  always sent `From=`, so a `TWILIO_FROM` of `MG…` (a Messaging Service, which
  `alerts.sh` already handled) failed; it now uses `MessagingServiceSid=` for `MG…`.
- **Swarm hub rejects an oversized body with no `Content-Length`** (hub — needs
  `wrangler deploy`). The size guard read only the header, so a chunked/streamed
  body bypassed it; the hub now enforces the byte cap on the body it actually reads.
- **`import-bans` no longer stops at the per-run deny cap.** It routed through the
  same `MAX_CSF_DENIES_PER_RUN` throttle as the scan (default 10), so importing more
  than 10 bans silently dropped the rest. A deliberate operator import now lifts the
  cap (never-block still protects the allowlist; the applied count is logged).
- **`swatter top -n` validates its argument** — it was interpolated into a SQL
  `LIMIT` unchecked; a non-integer now errors instead of corrupting the query.
- **Stale SMS-grade config is surfaced.** Statuses became traffic-light
  (RED/YELLOW/GREEN) in v2.8, so a pre-2.8 `ALERT_SMS_GRADES` (e.g. `"D F"`) matched
  nothing and SMS silently never fired; the alert path now warns.
- **Turning Cloudflare off no longer strands live CF rules.** `swatter_cf_unblock`
  and `swatter_cf_sweep_expired` bailed on `swatter_cf_manages_plane` before looking
  at `cf-rules.tsv`, so flipping `CF_MODE=off` (or an `auto` box that stopped being
  CF-fronted) left every recorded rule un-swept and un-unblockable — a permanent
  edge ban. Cleanup of already-created rules is independent of the current mode, so
  both now gate on refs existing instead; with no creds the delete fails and the ref
  is kept for a later run, exactly as before.
- **`swatter list temp|perm` now works on ipset-backend boxes.** It only ever
  queried csf, so an `ipset` deployment saw `(none)` regardless of live blocks. It
  now dispatches on `DIRECT_BACKEND` and lists the `swatter4`/`swatter6` set members
  (split temp vs perm by timeout) via a new `swatter_ipset_list`.
- **Cloudflare creds/domains files load their last line without a trailing
  newline.** `_cf_load`'s `read` loops lacked the EOF guard, so a hand-edited
  one-line `cloudflare.creds` (or an unterminated last account) was silently
  dropped, disabling blocks for that account.
- **`unblock`, `import-bans`, and the swarm sweep now serialize with a running
  scan.** The `flock` re-exec was only taken by `swatter scan`, so an operator
  `unblock`/`import-bans` (or the daily `refresh-feeds` swarm sweep) could run
  concurrently with a `*/5` scan and clobber `cf-rules.tsv`, diverge the sqlite
  ledger from the firewall, or double-apply a deny. A new `swatter_with_state_lock`
  takes the same lock file (blocking, bounded wait); operator commands die with a
  "try again" message if a scan holds it, the opt-in sweep skips (non-fatal). No-op
  where `flock` is absent (macOS dev boxes).
- **`import-bans` no longer drops the last ban** when the bans file's final line
  has no trailing newline (missing `read` EOF guard).

### Security
- **Intel CIDR feeds now reject over-broad entries.** Spamhaus DROP and the
  keyless list feeds (firehol/cins/dshield/…) were installed with no validation,
  so a MITM'd or poisoned feed line like `0.0.0.0/0` would match every visitor,
  score them 100 (hard-intel), and mass-ban innocents (with AbuseIPDB + swarm
  amplification). A new `swatter_intel_cidr_feed_ok` gate rejects the whole feed
  (keeping the last-good file) if any line is not a valid IP/CIDR, is `/0`, or is
  broader than `INTEL_FEED_MIN_PREFIX4` (default /8) / `INTEL_FEED_MIN_PREFIX6`
  (/16) **within global-unicast space**. The width floor is scoped to global
  unicast so a legit feed's broad bogon/multicast/reserved supernets (e.g.
  firehol_level1's `224.0.0.0/3`) — which can never be a real visitor's source —
  are still accepted. Wired into the spamhaus and listfeeds refresh paths.

## [2.9.2] - 2026-07-17

### Fixed
- **A Cloudflare rule whose `cf-rules.tsv` ref fails to persist is no longer a
  silent permanent ban.** The ref is the only handle `swatter_cf_sweep_expired`
  and unblock have on a live edge rule (CF Access Rules carry no native TTL), but
  `_cf_tsv_upsert` swallowed mktemp/write/`mv` failures and returned success while
  the caller recorded a real block — so a lost ref left a rule that blocks forever
  and no code path could ever remove it. `_cf_tsv_upsert` now returns non-zero on
  any persistence failure (and never `mv`s a partial file over the live refs), and
  the zone/account create paths + `_cf_reconcile_dup` propagate it as `failed`. The
  durable-retry queue (above) then re-drives the block; the re-POST hits the
  existing rule as a duplicate and `_cf_reconcile_dup` heals the ref once the state
  dir is writable — bounded, so it can't loop. `_cf_reconcile_dup` also tightened:
  when the dup lookup is inconclusive (API blip / no rule returned) it now trusts
  the duplicate only if a ref is already on file (a handle exists); with no ref —
  the exact state B2 recovery is healing — it returns `failed` and keeps retrying
  rather than trusting a rule it can never reach. Regression tests in
  `block_cf_test.sh`.
- **Failed blocks are now durably retried (silent permanent-drop bug).** A block
  that hit a transient backend error (Cloudflare API 5xx/timeout, csf/ipset
  command failure) recorded `action:"failed"` and deliberately no durable state,
  relying on the offender reappearing in a later scan to be retried. But ingest is
  cursor-based — each log line is scored by exactly one scan and never re-read — so
  a single-burst / hit-and-run offender (or one whose burst outlasted a CF API
  blip) was **silently, permanently never blocked**, even seconds later within the
  600s `WINDOW_SECONDS`. The "self-heal on next scan" the comments and digest
  claimed only held for a continuously-active offender. Fix: a `failed` block now
  queues its intent (with the original evidence + audit label) in a new sqlite
  `pending_blocks` table, and every scan drains the queue through the same gated
  block path (`_swatter_retry_pending`), independent of fresh log evidence. The
  retry replays the block faithfully — a primary block records its real temp/perm
  action (so the digest counts it) and reports to AbuseIPDB on success, a secondary
  dual-plane/upgrade leg stays silent — marked `evidence.retry=1` for provenance.
  Coverage is intent-aware: a queued **perm** is retried until a live **perm**
  lands (a still-live temp does NOT satisfy it — otherwise the perm escalation
  would be silently dropped when the temp expired). Bounded three ways — given up
  after `PENDING_RETRY_MAX_ATTEMPTS` (12) or `PENDING_RETRY_MAX_AGE_HOURS` (24),
  and at most `PENDING_RETRY_MAX_PER_RUN` (10) retries per scan so a mass-outage
  queue can't starve fresh offenders' `MAX_BLOCKS_PER_RUN` budget — with a give-up
  logged and surfaced as `retry-exhausted` in the digest (the true "block never
  landed" signal). Also covers the same-shape gaps: a failed csf/ipset block and a
  failed dual-plane second leg. `swatter unblock` cancels a queued retry; a
  since-allowlisted or now-covered IP is dropped rather than re-blocked. sqlite+
  enforce only (flatfile/report no-op, like the rest of the enforcement ledger).
  New regression suites `pending_retry_test.sh` (25 cases) and
  `pending_retry_scan_test.sh` (7 cases) assert a queued block is re-driven with
  **no** re-ingested evidence — the durability the previous tests never covered.
- **Nightly digest wording corrected.** Backend failures were labelled "retried
  next scan" (text and HTML), which was false for an aged-out offender before this
  fix; now they are genuinely durably retried and labelled as such, with a
  separate `retry-exhausted` line for blocks that truly never landed.

## [2.9.1] - 2026-07-11

### Fixed
- **CF plane-upgrade storm after a Cloudflare perm (pre-release review catch).**
  A CF TTL-emulated perm was recorded in `plane_blocks` as `kind='temp'`, so
  `is_perm_on(cloudflare)` was permanently false and `_swatter_perm_gate`
  re-applied a "plane-upgrade" perm on every subsequent scan the IP appeared in,
  burning `MAX_BLOCKS_PER_RUN` and starving new offenders (`skipped-cap`). CF
  perms are now recorded as **expiring perms** (`kind='perm'` with the real
  sweep expiry): the gate noops while the edge rule is live and legitimately
  re-blocks a returning offender after the sweep. `is_perm_on`/`active_on` are
  expiry-aware; true perms (`expires_at=0`, DIRECT/import-bans) are unchanged
  and can never be shortened by a later temp.
- **Duplicate Cloudflare creates now reconcile the existing rule instead of
  trusting it blindly.** On a duplicate response, Swatter looks the existing
  rule up and (a) refreshes the `cf-rules.tsv` ref to the NEW expiry — else an
  escalated/perm block was silently swept at the first temp's expiry while the
  ledger claimed long coverage; (b) recovers a lost ref (failed append /
  restored state dir) so sweep/unblock keep a handle on the live rule; and
  (c) refuses to claim a foreign-mode rule (e.g. a manual whitelist for the
  same IP), recording a self-diagnosing `failed` instead of a phantom block.
  If the lookup itself fails, the duplicate is trusted (no retry loop).
- **Metrics warn-once stamp is keyed to the target directory**, so a stamp left
  by one outage can never suppress the warning for a different misconfigured
  `METRICS_FILE` path later.
- **`swatter_cf_sweep_expired` fails closed on mktemp failure** (matching
  unblock): the refs file is left untouched instead of being rewritten from an
  empty keep-file, which would have orphaned every live rule ref.

### Removed
- **`SCORE_PERM` (dead config).** Defined but never consulted — perm has never
  come from a single score; it comes from repeats (`REPEAT_N` within
  `REPEAT_WINDOW_DAYS`), honeypot hits, or hard intel. Removing it stops
  operators tuning a knob that does nothing. A stale `SCORE_PERM=` line in an
  existing swatter.conf is harmless (unused variable).
- **Cloudflare duplicate-rule responses (code 10009) are now idempotent success,
  not `failed`.** The account-scoped IP Access Rules endpoint reports an existing
  rule as error code 10009 `firewallaccessrules.api.duplicate_of_existing`, which
  `_cf_create_ok` did not recognize (it only matched "already exists"/"identical"
  message text). Every retried create was recorded as `failed`, which (a) looped
  the same create on every */5 scan, inflating the backend-failed count, and
  (b) starved repeat escalation: only `temp` rows count toward `REPEAT_N`, so a
  live repeat offender (e.g. 27 recorded offenses) never escalated to perm on the
  Cloudflare plane.
- **Metrics warning now fires once per outage, not once per scan.** The
  "missing or unwritable" node_exporter textfile-collector warning used an
  in-memory latch, but each cron scan is a fresh process, so boxes without
  node_exporter warned every 5 minutes. The latch is now a stamp file in
  `STATE_DIR`, cleared when the directory becomes writable again. (Setting
  `METRICS_FILE=""` still disables metrics entirely.)

## [2.9.0] - 2026-07-09

### Added
- **Per-plane enforcement ledger + dual-plane hard-intel blocking.** Swatter now
  tracks, per IP, which firewall plane (Cloudflare edge vs CSF/ipset direct) an
  offender is blocked on, in a new `plane_blocks` table. This closes a real gap:
  an IP permanently blocked only at the Cloudflare edge that then hits the origin
  **directly** (e.g. a webmail flood on cPanel port 2095, which never transits
  Cloudflare) is now escalated with a CSF deny instead of being dismissed as
  "already blocked." Three behaviors ride on it:
  - **Channel-upgrade** — a perm on one plane, seen on the other, acquires the
    missing plane (audited `plane-upgrade`).
  - **Dual-plane hard-intel** — an IP with a hard-intel reputation
    (`INTEL_HARDBLOCK_MIN`, default 100 — Spamhaus DROP / AbuseIPDB 100, never a
    legitimate visitor) gets a fresh perm on **both** planes at once, so
    direct-to-origin ports are covered proactively. New knobs
    `DUAL_PLANE_HARD_INTEL` (default true) and `INTEL_HARDBLOCK_MIN`.
  - **Swarm sweep** forces the DIRECT plane, so a fleet-corroborated IP with no
    local vhost gets a CSF deny instead of a `skipped-novhost` no-op.
  The never-block + fail-closed gates are unchanged: a Cloudflare edge range can
  never be CSF-denied, and stale ranges degrade dual-plane to CF-only.
- **Transient-failure intel caching (`INTEL_RC_TEMPFAIL`).** A provider that hits
  a quota or transport failure returns exit 75; intel caches only a short
  negative TTL (`INTEL_FAIL_TTL`, default 300s) instead of poisoning the durable
  no-data cache for a full cycle. Wired into the AbuseIPDB and GreyNoise
  providers.

### Fixed
- **Origin-lock IPv4 outage (fail-open guard bypass).** A `cloudflare.cidr` with
  only IPv6 ranges still cleared the combined `MIN_RANGES` gate, then installed a
  v4 DROP guarded by an **empty** ipset — dropping all IPv4 traffic to the web
  ports. Each family now authorizes only its own DROP from its own ranges.
- **Origin-lock teardown ordering** — the DROP is now removed before its guarding
  CF-ACCEPT, closing a brief drop-all window on every standalone apply and disable.
- **Origin-lock digest** now parses ISO-8601 rsyslog timestamps (year-aware) and
  counts unrecognized formats rather than silently reporting "no drops."
- **Cloudflare-plane perm ledger divergence** — a CF "perm" (TTL-emulated, swept
  at ~3d) was recorded as never-expiring, so after the edge rule was swept the
  offender was never re-blocked while the ledger claimed a live perm. CF perms are
  now recorded with their real emulated lifetime.
- **Local-time log parsing** — Apache/PHP-FPM/MariaDB error logs and the lfd
  direct-set window are now parsed in the host's local zone instead of being
  forced to UTC (`common.sh` exports `TZ=UTC` process-wide), fixing mis-windowed
  errors and misclassified direct-hit evidence on non-UTC hosts.
- **`ERROR_NOISE` validation** — an empty, whitespace-only, or malformed
  known-noise regex no longer silently zeros the genuine-error count and hides
  real errors.
- **Flatfile ledger correctness** — `is_perm` now honors a later unblock and
  ignores dry-run perms (parity with the SQLite path); a busy_timeout keeps a
  concurrent writer from dropping a ledger record.
- **Report-mode no longer records phantom bans** — a dry-run perm no longer sets
  `offenders.perm`.
- **Direct-set temp file** is cleaned each scan (was leaking one `/tmp` file per
  `*/5` run).
- **IPv6 ipset blocks fail closed** when `ip6tables` is absent, instead of
  reporting an unenforced block as handled.
- **Allowlist** — decimal (non-octal) octet parsing in the Cloudflare never-block
  check; IPv4-mapped (`::ffff:`, compact and expanded) and unique-local IPv6
  treated as private; a transient PTR lookup no longer negative-caches a real
  crawler for 7 days.
- Hardening across the board: sanitized CSF deny comments, integer-coerced and
  escaped SQL values, tightened `score.awk` IP validation with C0-control escaping,
  atomic Cloudflare-range refresh, `curl` secret-config cleanup traps, and cron
  output routed to a rotated log.

## [2.8.0] - 2026-07-06

### Changed
- **Nightly report grade is now a traffic light (GREEN / YELLOW / RED), replacing
  the A–F letter scale.** The old five-letter card collapsed onto three statuses
  the way an operator actually reads it: **GREEN** = A/B (nothing actionable —
  blocks and origin-lock hits live here, since they are Swatter working, not a
  problem), **YELLOW** = C/D (elevated non-fatal error volume worth a look), and
  **RED** = F (a fatal error — a service or app may be down). The underlying
  thresholds are unchanged (`REPORT_GRADE_C_ERRORS`, `REPORT_GRADE_D_ERRORS`
  keep their names and still tune the YELLOW entry point and its "investigate"
  vs "act now" wording). Both renderers updated: the text digest leads with
  `STATUS: 🟢 GREEN — All Clear`, and the HTML email shows the traffic-light
  emoji (🟢/🟡/🔴) in the hero tile, the status badge, and the legend.
- **SMS alerts now trigger on RED.** `ALERT_SMS_GRADES` default moved from
  `"D F"` to `"RED"`; the alert body leads with the status emoji — `🔴 Swatter
  <host>: Status RED (Act Now).` A custom set may still include `YELLOW`. Dedup
  and the `--test` bypass are unchanged.
  - **Upgrade note:** the trigger now matches status *words*, not letter grades.
    If your `swatter.conf` pins a custom `ALERT_SMS_GRADES` with the old letters
    (e.g. `"D F"`), it will silently stop matching — update it to `RED` (or
    `"RED YELLOW"`). The shipped default and `swatter.example.conf` are already
    correct; only hand-edited configs need the change. Note the SMS default no
    longer pages on a non-fatal error *flood* (old grade D) — that maps to YELLOW
    now; add `YELLOW` to `ALERT_SMS_GRADES` if you want floods to text you.
- **Email subject leads with the status icon** — `🟢 Report 2026-07-06 - healthy
  · …` — so the traffic light is visible at a glance in the inbox list without
  opening the message.
- **Email palette refreshed to the 2026-07-05 brand spec.** The header rule moves
  from brass `#C48A2E` to slate `#4A5568`, and the header lockup now pulls the
  refreshed R2 render (`REPORT_LOGO_URL` default →
  `…ph-lockup-stacked-studios-email-720w-v2.png`). Per
  `brand/email/email-template.md`. Fleet nodes that pin `REPORT_LOGO_URL` to the
  old key should be repointed on deploy.

### Added
- **`REPORT_GRADE_FORCE=green|yellow|red`** overrides the computed status so an
  operator can force a status for a `--test` preview — run it once per status
  (`REPORT_GRADE_FORCE=red swatter report --test`) to preview that email and, for
  red, fire the RED SMS on demand. Intended for previews and not set in normal
  operation; it has no `--test` guard, so don't leave it set in the environment
  or `swatter.conf` (it would override a real nightly run too). An unrecognized
  value is ignored with a warning.

## [2.7.1] - 2026-07-05

### Added
- **Nightly digest Swarm plane (informational).** When `SWARM_ENABLE=true`, the
  nightly report gains a fourth plane summarizing fleet reputation activity:
  fleet IPs consumed from the shared feed (with a stale-feed note when either the
  feed or its `host_count` sidecar is older than `SWARM_MAX_AGE_DAYS`),
  corroborated pre-blocks taken this window (counted from `decisions.jsonl` on the
  `evidence.swarm` marker that is stamped on every dispatched sweep row — robust
  to the reason-prefix the novhost/failed/cap paths add), confirmed bans
  contributed back this window, and the last-contributed date. Rendered in both
  text and HTML. Reads only local swarm state at report time (no hub call), and
  sets only `SWARM_*` report globals — it never escalates the report grade or
  breaks silent-when-quiet (enforced by runtime and source-level regression
  tests). Degrades to an explicit note instead of silent zeros on a box without
  `jq`.
- **Publish audit (`swarm.publish.log`).** `swatter_swarm_publish` now appends a
  bounded `{"ts","count"}` line per successful contribution, stamped with publish
  wall-clock time so a catch-up flush of old bans still counts as tonight's
  contribution. The digest reads it for an exact "contributed this window";
  `swatter swarm disable` clears it alongside the cursor.

## [2.7.0] - 2026-07-03

### Added
- **Swarm host side (subsystem 2 of 2) — fleet reputation sharing is now
  end-to-end.** New `lib/swarm.sh` + `lib/providers/swarm.sh`: each box
  publishes its CONFIRMED enforced perm bans to the operator's hub after every
  scan (timestamp-cursor delta that advances only over rows the hub positively
  acked with `enrolled:true`; four outbound gates — validator, unsafe-target,
  never-block, fleet canary; 500-entry chunks; fail-soft, never delays a scan)
  and consumes the merged fleet feed back as a normal intel provider
  (`swarm` in `INTEL_PROVIDERS`): bare feed into `feeds/swarm.txt` with
  empty-200-clears + keep-last-good-on-failure semantics, JSON sidecar for
  `host_count` (fresh-or-absent), score scaled `SWARM_BASE_SCORE`+15 per
  corroborating host (cap 100) through the standard `W_REPUTATION` fold.
  Opt-in `SWARM_ACTION=corroborated-block` proactively temp-blocks feed IPs
  corroborated by ≥`SWARM_MIN_CORROBORATION` distinct enrolled hosts — routed
  exclusively through `_swatter_execute_block` so every local gate applies.
  New CLI: `swatter swarm {enroll|status|disable|purge}`. New hub endpoint:
  `POST /purge` (bad-publish recovery, additive). Everything inert by default
  (`SWARM_ENABLE=false`). 86 new bash test assertions across 7 files + 3
  swarm cases in the curl-secrets proof; hub suite at 71. Plan + two Grok
  review records under `docs/superpowers/plans/2026-07-03-swatter-swarm-host*`.

## [2.6.0] - 2026-07-03

### Added
- **Swatter Swarm hub (subsystem 1 of 2).** New `hub/` directory: a
  self-hostable Cloudflare Worker + D1 that aggregates a fleet's confirmed
  offenders (`POST /contribute`), enrolls trusted hosts (`POST /register`),
  and serves the merged, decaying blocklist back (`GET /feed`, bare text or
  JSON with corroboration counts). Key properties: `host_count` is DERIVED at
  read time (`COUNT(DISTINCT host)` over sightings joined to the enrolled-host
  registry — no write races, forged host_ids don't count); unenrolled host_ids
  are write-gated (nothing stored); three separated bearer tokens
  (write/read/enroll); per-connecting-IP + global rate limits; IP-or-CIDR
  validation with bash parity; daily prune cron. 69 Vitest tests under
  `@cloudflare/vitest-pool-workers`. Hardened pre-merge by a two-model Grok
  review (chunked D1 batches, unified host_id rule, category sanitization,
  body-size cap — see `docs/superpowers/plans/…-swarm-hub-impl-review-grok.md`).
  The HTTP contract is frozen; the host-side `swatter swarm` CLI is subsystem 2,
  targeted for the next release. Deploy runbook: `hub/README.md`.

### Changed
- **Nightly report email adopts the Peace Harbor system-email template
  (STUDIOS).** (Shipped to prod 2026-07-03; released here.)

## [2.5.2] - 2026-07-03

### Security / hardening
- **Strict IP validation now gates every firewall sink, not just the scan
  path.** `score.awk`'s pre-filter is deliberately loose (it only guarantees no
  shell-meaningful bytes), so tokens like `999.999.999.999` or `::::` parsed from
  a hostile log line could reach `csf`/`ipset`/the CF API as a block target.
  `_swatter_execute_block` now runs the authoritative `swatter_is_valid_ip_or_cidr`
  FIRST (auditing a `skipped-invalid` decision so the skip is visible to `why`/
  report), AND the direct-plane router (`swatter_block_direct_temp`/`perm`) and
  `swatter_cf_block` each re-validate locally — so no caller (scan, `import-bans`,
  or any future one) can hand garbage to a firewall. The validator itself was
  tightened: IPv4 octets bounded 0–255, IPv6 structurally validated (single `::`,
  ≤8 groups) including the legit embedded-IPv4 form (`::ffff:192.0.2.1`), prefix
  lengths bounded per family (previously it accepted `999.999.999.999` and
  `deadbeef`). Pinned by hostile-log wire tests (`scan_wire_test.sh`), backend
  guard tests (`block_test.sh`, `block_cf_test.sh`), and expanded validator cases
  (`score_test.sh`). (No shell injection was possible — the charset was already
  constrained — but a security tool must not hand garbage to the firewall.)
- **Block sinks refuse catastrophic-but-valid targets.** `0.0.0.0/0`, `::/0`,
  any `…/0`, and the unspecified addresses (`0.0.0.0`, `::`) are syntactically
  valid IP/CIDRs — an `import-bans` file containing `0.0.0.0/0` would otherwise
  firewall the entire internet. A new `_swatter_is_unsafe_block_target` guard at
  the block sinks (direct router, `swatter_cf_block`, and the scan gate) rejects
  them while the general validator stays permissive (it also gates allow-lists,
  never-block files, and feed downloads, where those forms are harmless). Normal
  `/24`-style range blocks still work. The audit record layer also sanitizes the
  `ip` field (not just `reason`) so no caller can corrupt `decisions.jsonl`.
  Pinned in `block_test.sh`, `block_cf_test.sh`, and `scan_wire_test.sh`.
- **Threat-intel labels are sanitized before entering the ledger.** A provider
  response whose label (e.g. GreyNoise `.name`) carried a tab, newline, backslash,
  or double-quote — attacker- or MITM-influenceable — could split the intel TSV
  score contract (silently zeroing the reputation signal) and corrupt
  `decisions.jsonl` lines that `report`/`why` parse with `jq`. `intel.sh` now
  parses only the first **non-blank** line (so an injected trailing line is
  dropped AND a leading blank/CRLF line from a MITM/proxy can't swallow the real
  score) and strips control/tab/backslash/quote from labels (explicit per-char
  substitutions, not a fragile combined bracket class); `_swatter_audit` doubles
  backslashes and neutralizes quotes + control chars in the `reason` field as a
  record-layer backstop. Covered by `intel_test.sh` and `scan_wire_test.sh`.
- **`swatter allow` writes the allow file `0640`, not `0644`** — the operator /
  monitoring IP list is no longer world-readable on a shared box.

### Fixed
- **`refresh-feeds` no longer silently drops IPv6 ranges.** A run where the v4
  download succeeded but v6 came back empty (or whitespace-only, or a captive-
  portal page) installed a **v4-only** `cloudflare.cidr`, shrinking both the
  never-block set and origin-lock v6 coverage — an IPv6 CF edge could then be
  CSF-denied. Each family is now validated independently with `swatter_cidr_list_ok`
  (≥1 valid CIDR and every line valid); if either fails, the existing (last-good,
  complete) file is kept and the run exits nonzero so cron alerts. Keeping
  slightly-stale-but-complete ranges is safer than writing a fresh-but-incomplete
  set, and the allowlist freshness guard warns if it ages out. Pinned in
  `refresh_feeds_test.sh` (empty **and** whitespace-only v6 cases).
- **Nightly origin-lock digest classifies sources by CIDR containment.**
  `_ol_tag_ip` used `grep -F` against the monitoring/allow files (literal match
  only) and hardcoded `/etc/swatter` paths, so a monitoring **range** covering a
  source IP was mislabeled "uncategorized" in the report. It now uses
  `_ip_in_cidr_file` and the configured file paths. (The DROP-arming `preflight`
  already used the correct containment check — this was report-only.) Pinned in
  `origin_lock_test.sh`.
- **`store_init` surfaces a failed schema bootstrap AND the ledger-writing
  commands abort on it** instead of discarding sqlite's stderr — a corrupt/
  unwritable DB no longer starts a scan (or an `import-bans`) on a silently-empty
  ledger, which would apply firewall blocks with no record (losing caps,
  repeat-escalation, and perm tracking while the operator believes protection is
  intact). `store_init` captures stderr, logs loudly, and returns nonzero;
  `cmd_scan` and `cmd_import_bans` now `die` on that failure. Read-only commands
  (`status`, `top`, `why`, `export-bans`) deliberately still degrade rather than
  abort. Pinned in `persist_test.sh` (loudness) and `cli_test.sh` (scan +
  import-bans abort, status non-abort).
- **`swatter_cidr_list_ok` no longer drops a final line without a trailing
  newline** — the `read` loop lacked the `|| [[ -n "$line" ]]` guard, so a
  poisoned last line (captive-portal HTML with no closing newline) was silently
  skipped and the list falsely passed validation. Pinned in `score_test.sh`.

- **Installer no longer strips the report timezone on upgrade.** `install.sh`
  rendered `/etc/cron.d/swatter-report` from its own (empty) environment
  instead of the live `/etc/swatter/swatter.conf`, so every `install local`
  regenerated the cron without `CRON_TZ` — and silently ignored a custom
  `REPORT_CRON`. The v2.5.1 deploy reverted the nightly report to 04:00 UTC
  (9pm Pacific) this way. The render now subshell-sources the live conf
  (`_swatter_report_cron_from_conf`, pinned in test/report_cron_test.sh).

## [2.5.1] - 2026-07-01

### Security
- **Intel-provider API keys moved out of curl argv too.** The v2.5.0 secret
  hygiene converted the six send/report call sites but missed the intel
  lookups: AbuseIPDB per-IP check, AbuseIPDB blocklist download, and GreyNoise
  still passed keys via `-H` (visible in `ps`). All three now use the same
  `swatter_curl_cfg` `-K` pattern (pinned in test/curl_secrets_test.sh).
  Project Honey Pot's http:BL key is inherently argv/DNS-visible by that
  protocol's design (key rides in the queried hostname) — documented in the
  provider, not fixable.
- **Origin-lock stderr tempfile is now mktemp-random.** The apply-failure
  capture file used a pid-predictable `/tmp` name written by root (symlink-
  attack surface); it is now created once per run via `mktemp` and removed on
  both apply exit paths.

### Fixed
- **`refresh-feeds` write failures count as failures.** A validated Cloudflare
  range download that failed to LAND (unwritable target / disk full) logged
  nothing and exited 0; it now logs an error, keeps the existing file, and
  exits nonzero for cron.

## [2.5.0] - 2026-07-01

### Changed
- **BREAKING-ish: origin-lock defaults to `ORIGIN_LOCK_PORTS="443"` and the
  `ORIGIN_LOCK_ALLOW_ACME` carve-out is retired (ignored).** Production
  attribution (2026-07-01) proved the `/.well-known/` xt_string accept can
  never work: a payload match cannot admit a NEW connection because the TCP
  handshake carries no payload — the rule's live counter stayed at zero while
  Let's Encrypt validators were SYN-dropped on `:80` and every gray-cloud
  hostname's HTTP-01/AutoSSL DCV failed. Since validator IPs are deliberately
  unpublishable, the only sound postures are `443`-only (`:80` serves just
  redirects + challenges; content stays locked) or DNS-01. `apply` now warns
  on any port list that includes 80; teardown still removes the legacy
  `/.well-known/` rule from boxes an older version configured. Operators who
  accept broken HTTP renewals can still set `ORIGIN_LOCK_PORTS="80,443"`
  explicitly.

### Security
- **Secrets no longer ride in curl argv.** The CF bearer token, SendGrid/Brevo
  API keys, Twilio SID:token, and the AbuseIPDB key were passed as `-H`/`-u`
  command-line arguments — world-readable in `/proc/<pid>/cmdline`, so on a
  shared box any local user running `ps` during a scan could capture them. All
  credentialed curl calls now pass secrets via a mode-0600 config file
  (`curl -K`), created per call and removed immediately after
  (`swatter_curl_cfg` in lib/common.sh). Pinned by test/curl_secrets_test.sh.

### Fixed
- **Unblock failures are no longer silent (both planes).** `swatter unblock`
  previously printed "unblocked" and exited 0 even when every backend removal
  failed — worst case, `swatter_cf_unblock` dropped the IP's `cf-rules.tsv`
  refs even when the CF API delete FAILED, orphaning a live Cloudflare rule
  with no handle left to ever remove it. Now: a failed CF delete keeps the ref
  (retry + expiry sweep still own it) and logs the cause; CSF (`csf -tr/-dr`)
  and ipset (`ipset del`) unblocks capture stderr and fail loudly; ipset
  unblock dels only the family-matching set (the cross-family del was a
  guaranteed parse error); and `swatter unblock` exits nonzero with an
  "INCOMPLETE" message when any backend failed.
- **Cloudflare range refresh validates before installing.** `refresh-feeds`
  wrote ANY non-empty download straight to `cloudflare.cidr` — a 200 with an
  HTML error page (captive portal / intercepting proxy) would poison the file
  that gates the never-block set. Every line must now parse as an IP/CIDR
  (`swatter_cidr_list_ok`) or the existing file is kept and the command exits
  nonzero. `refresh-feeds` also propagates failure (CF download failed, or ALL
  intel feeds failed) as a nonzero exit so cron can alert, and the ipsum feed
  refuses to overwrite a populated list with an empty 200 body (mirrors the
  listfeeds `-s` guard).
- **Origin-lock partial applies fail loud and fail open.** iptables/ipset
  errors during `origin-lock apply` were discarded (`2>/dev/null`), so a
  mid-apply failure could leave a half-built chain — worst case a DROP whose
  CF-ACCEPT never landed (total origin outage) — while the log claimed
  "origin-lock applied". Every firewall op is now error-counted; on any
  failure the apply logs "INCOMPLETE" with the first captured stderr, tears
  its rules back down (fail-open spine), and returns 1.
- **Outbound send failures now log the response body.** Brevo/SendGrid
  (lib/mailer.sh), Twilio (lib/alerts.sh, lib/notify.sh), and webhooks logged
  only the HTTP code (`-o /dev/null`), hiding the provider's actionable cause
  ("invalid api key", "unverified sender", ...). The body/stderr is now
  captured into the error line, bounded and key/token-redacted.
- **AbuseIPDB report failures are visible and retryable.** The backgrounded
  POST swallowed all errors while the synchronously-written dedup marker
  suppressed retries — a revoked key silenced reporting per-IP for the whole
  TTL with zero trace. A failed POST now logs the cause and removes the
  marker so the next confirmed block retries.
- **Ledger writes are no longer fire-and-forget.** A failed `decisions.jsonl`
  append now logs an ERROR (blocks landing on the firewall with no audit
  record silently broke caps, repeat-escalation, and `/server-logs` counts),
  and sqlite errors (locked/corrupt/unwritable DB) log a bounded warning with
  the real sqlite stderr instead of vanishing into `2>/dev/null`. The block
  path itself is never aborted by either.

### Added
- **Direct-plane (CSF/ipset) block failures now record their cause too.** Extends
  the v2.4.1 CF diagnosability to the direct plane: `swatter_csf_temp/perm` and
  `swatter_ipset_temp/perm` capture the command's stderr (or "csf/ipset not found")
  into `SWATTER_LAST_BACKEND_ERR` on failure, so a `failed` CSF/ipset decision
  carries `evidence.backend_err` just like a CF one. Same command, same effect,
  exit code preserved — the safety-critical block path is unchanged, only stderr
  is captured instead of discarded.

## [2.4.1] - 2026-07-01

### Added
- **Cloudflare block failures are now self-diagnosing.** When a CF block fails
  (`block_failed`), the reduced CF API error is threaded into the decision record
  as `evidence.backend_err` (with the bearer token redacted), so `/server-logs`
  reading `decisions.jsonl` shows the cause (e.g. "429 too many requests") inline
  instead of dead-ending — no cron edit, no waiting for the next burst. Non-API CF
  failures (zone/account resolution, missing tooling) and jq-less hosts also record
  a cause. The nightly digest surfaces a "backend-failed: N (top cause) — retried
  next scan" line; these self-heal on the next scan, so they never escalate the
  report-card grade. Implements the 2026-06-30 diagnosability spec (Grok-reviewed).

## [2.4.0] - 2026-07-01

### Added
- **SMS alert on a severe report grade (Twilio).** A second channel alongside the
  email: when the nightly report grades **D or F**, also text the operator. Fully
  config-driven and **off by default** so the public build alerts nobody. Fail-soft
  — a Twilio outage or misconfig logs a warning and never blocks the report. The
  auth token is read from a mode-0400 file (never the conf); `swatter report --test`
  sends a `[TEST]` text to verify setup; a same-grade dedup window
  (`ALERT_SMS_DEDUP_HOURS`, default 6h) avoids repeat texts. The sender
  (`TWILIO_FROM`) may be a phone number or a Messaging Service SID. New config:
  `ALERT_SMS_METHOD`, `ALERT_SMS_GRADES`, `ALERT_SMS_TO`, `ALERT_SMS_DEDUP_HOURS`,
  `TWILIO_SID`, `TWILIO_TOKEN_FILE`, `TWILIO_FROM`.

### Changed
- **Report email redesigned as a triage report card.** The HTML email now leads
  with a **severity grade (A–F)** and a plain-language recommendation of whether to
  act, so the reader knows in one glance how bad it is and what to do. Each section
  (Bad Actors, Origin-Lock, Server Errors) gains a **generated one-line summary**
  of *who/what and how it was handled*, not just counts. The recommendation can
  name an operator's triage command via the new `REPORT_TRIAGE_HINT` config
  (shown as type-this text, never a link; blank by default so the public build
  suggests nothing bespoke). Grade thresholds are tunable
  (`REPORT_GRADE_C_ERRORS`, `REPORT_GRADE_D_ERRORS`); blocks never escalate the
  grade (they mean Swatter is working). Server-error wording changed from
  "Genuine" to **Non-Fatal** vs Fatal. Labels are Title Case; the footer credit
  (`🪰 Swatter · a Peace Harbor Studios project · GitHub`) and the self-explaining
  CLI help line (`swatter why <ip> — why an IP was flagged`) carry through both the
  HTML and text bodies.

### Fixed
- **Report sender name now shows the server, not just "Swatter".** The default
  `REPORT_FROM_NAME` used parentheses — `Swatter (host.fqdn)` — but RFC 5322 treats
  `(...)` in a From header as a comment that mail clients strip, so the sender
  displayed as bare "Swatter". Switched to brackets: `Swatter [host.fqdn]`, which
  display verbatim. A config-defaults test guards against parens regressing.
- **Nightly report now honors `REPORT_CRON_TZ` (DST-aware) and records every send.**
  The report cron is rendered into its own `/etc/cron.d/swatter-report` instead of
  being appended to the shared `/etc/cron.d/swatter`. `CRON_TZ` applies to all jobs
  that follow it in a cron file, so keeping the report in the shared file risked
  shifting the 5-min scan; a dedicated file scopes the timezone to the report alone
  (e.g. `America/Los_Angeles` → 4am Pacific, DST-adjusted). The report line now
  redirects to `/var/log/swatter/report.log`, so a failed send is logged rather
  than silently discarded by cron's `MAILTO=""`.

## [2.3.1] - 2026-07-01

### Fixed
- **Origin-lock standalone `apply` no longer takes the origin down on a mode
  transition.** Applying `log` then `drop` left the CF/ACME/LOG accepts in place
  (their `-C` guards matched) and `-I`-prepended only the new DROP to INPUT
  position 1 — **above** the Cloudflare-ACCEPT — dropping all web traffic
  including Cloudflare. Standalone `apply` now tears its own rules down first so
  the rebuild lands on a clean, correctly ordered chain. The csf-hook path is
  unchanged (CSF flushes the chain before it runs).
- **Origin-lock LOG rule is now reliably removable.** `_ol_emit_log` installs
  `--log-prefix "ORIGIN-LOCK: "` (trailing space) but teardown consumed its delete
  pattern unquoted, word-splitting the space away so `-D` never matched — the LOG
  rule lingered across reloads and orphaned on every `disable`. Teardown now
  deletes it with a quoted prefix. The operator/monitoring allow-accepts are torn
  down in a loop (was single-shot) so legacy duplicates clear.
- **Managed csfpre origin-lock hook no longer silently no-ops in DROP mode.** The
  hook ran `origin-lock apply --hook=csf` without `--yes`; at `csf -r`
  (non-interactive) DROP mode hit the confirm guard and returned 3, swallowed by
  `|| true`, installing **zero** rules and leaving the origin open. The hook now
  passes `--yes` (setting `ORIGIN_LOCK=drop` in the config is the operator's
  deliberate consent).

### Added
- **`_ol_retire_legacy_static`** (install.sh) — safely retires a legacy
  hand-written static origin-lock block by wrapping it in an inert `: <<'MARKER'`
  here-doc (keeps `csfpre.sh` valid `sh` — commenting individual matching lines
  would leave a dangling `then`/`do`). Backs up first; idempotent.

### Changed
- Origin-lock digest resolves the effective mode from the config `ORIGIN_LOCK`
  (what the managed hook enforces) first, using a legacy static `MODE=` only as a
  fallback — so reports stay correct after the static→managed reconciliation.
- Documented the origin-lock persistence model on CSF hosts as **single-carrier
  csfpre** (measured durable across `csf -r`/`csf -ra`/lfd restart under
  `FASTSTART=1`/`LF_IPSET=1`); no systemd carrier needed.

## [2.3.0] - 2026-06-30

### Added
- **`CF_SCOPE=account` — block proxied attackers across every Cloudflare account
  at once.** The Cloudflare plane can now create **account-scoped** IP Access
  Rules (`/accounts/{id}/firewall/access_rules/rules`) on every account in
  `CF_CREDS_FILE`, instead of only a zone-scoped rule on the single zone the
  attacker hit. This closes a roaming gap in the default `zone` scope: because
  Swatter's per-IP ledger marks an IP "handled" after the first block, a scanner
  that **rotated target vhosts** was only ever challenged on the first zone it
  touched and roamed free across every other zone on the account. Account scope
  makes the block scope match the ledger, needs no target vhost (so it also
  covers raw-IP / no-`Host` offenders), and is the recommended setting when
  Swatter is the main line of defense. Default stays `zone` (backward
  compatible). Account scope needs a token with `Account Firewall Access Rules:
  Edit`; a token lacking account scope makes account blocks fail and retry each
  run (logged with a scope hint) rather than silently skipping — only an empty
  creds file is `skipped-config`. A **partial** block (some accounts succeed,
  some fail) is reported as failed so the per-IP ledger does not mark the IP
  handled and the next run retries every account (succeeded ones idempotently
  dup-OK), keeping the roaming gap closed. Account ids per token are resolved via
  the API (paginated) and cached in `$STATE_DIR/cf-accounts.tsv` (ids only, no
  secrets); the cache is invalidated when `CF_CREDS_FILE` is newer.
- `cf-rules.tsv` gains an explicit **scope** column (`ip<TAB>scope<TAB>scope_id<TAB>rule<TAB>expiry`).
  The sweep/unblock/list readers parse both the new 5-field rows and legacy
  4-field zone rows, so rules written by an older Swatter keep sweeping through
  their natural expiry.

### Fixed
- **`install.sh remote` no longer exits non-zero on a clean install.** The
  origin-lock csfpre wiring set `trap 'rm -f "${tmp}"' RETURN` referencing a
  `local tmp`; under `set -euo pipefail` the RETURN trap fired with `tmp` out of
  scope (`tmp: unbound variable`) *after* all install work had completed —
  cosmetic, but it made every remote deploy exit non-zero and could mask real
  failures / break CI exit-code checks. Guarded the expansion (`${tmp:-}`).

### Changed
- **`REPORT_FROM_NAME` defaults to `Swatter (<host FQDN>)`** — the From-header
  display name now self-labels per server out of the box (templated from
  `hostname -f`), so a multi-box fleet is distinguishable in the inbox with no
  per-host edit. Override in `swatter.conf` to pin a fixed name.

### Documentation
- **Brevo promoted as a first-class free email backend alongside SendGrid** —
  README report + alerting docs and `swatter.example.conf` now call out both free
  tiers (SendGrid 100/day, Brevo 300/day) and clarify that `sendgrid`/`brevo`
  installs normally only set `REPORT_EMAIL` + `REPORT_FROM` (the From name and
  subject are defaulted). Alert email is documented as riding `REPORT_METHOD`, so
  it works with Brevo too. (Brevo delivery itself shipped earlier; this surfaces
  it.)
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

[Unreleased]: https://github.com/peaceharborco/swatter/compare/v2.9.1...HEAD
[2.9.1]: https://github.com/peaceharborco/swatter/compare/v2.9.0...v2.9.1
[2.5.1]: https://github.com/peaceharborco/swatter/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/peaceharborco/swatter/compare/v2.4.1...v2.5.0
[2.4.1]: https://github.com/peaceharborco/swatter/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/peaceharborco/swatter/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/peaceharborco/swatter/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/peaceharborco/swatter/compare/v2.2.0...v2.3.0
[2.1.0]: https://github.com/peaceharborco/swatter/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/peaceharborco/swatter/compare/v1.2.2...v2.0.0
[1.2.2]: https://github.com/peaceharborco/swatter/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/peaceharborco/swatter/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/peaceharborco/swatter/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/peaceharborco/swatter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/peaceharborco/swatter/releases/tag/v1.0.0
