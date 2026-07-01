# Swatter CF block-failure diagnosability — design

**Date:** 2026-06-30
**Status:** BUILT 2026-07-01 (core + Optional B digest line; Optional A retry deferred). Grok-reviewed — see `-review-grok.md`; the secret-redaction blocker + non-API-cause / jq-fallback majors were folded in. CSF/direct-plane `failed` rows still lack a cause (a small follow-up).
**Original status:** proposed — triggered by a 2026-06-30 prod investigation (cds1)
**Scope:** Make `failed` (`block_failed`) Cloudflare-channel decisions
*self-diagnosing from the logs*, so the root cause of a transient CF block
failure can be read after the fact without re-instrumenting cron. Secondary:
optional in-run retry/backoff for transient CF API errors, and surfacing the
`failed` count + dominant cause in the nightly digest.

> **Open this spec next time you're in the repo and decide whether to build it.**
> It exists because the diagnostic data needed to close the loop is currently
> discarded at runtime. Until this lands, every future `block_failed`
> investigation dead-ends the same way the 2026-06-30 one did.

## What prompted this (evidence — cds1, 2026-06-30, 24h window)

Running `/server-logs` surfaced **41 `failed` decisions**, every one on the
`cloudflare` channel, `reason = "block_failed action=… …"`, spread across the
day (4–5/hr peak 07:00–10:00 Pacific), coinciding with a `MAX_BLOCKS_PER_RUN=25`
circuit-breaker trip on the overnight wave (~165 `skipped-cap` at the 00:00
run). The offenders were high-confidence (`abuseipdb:confidence100`,
`spamhaus:drop`).

**Outcome of the investigation:** not a breach. Cross-checking each of the 35
distinct failed IPs against the live store showed **35/35 currently blocked,
0 slipped through** — every failed CF block was retried and landed on a
subsequent `*/5` scan. Pattern (intermittent, only under burst load, all
retried-successfully) points to **CF API rate-limiting (429) or duplicate-add
races**, not a broken token/config (which would fail 100%, not ~16%).

**The gap:** we could only *infer* the cause. The exact CF API error was
unavailable because:

- `lib/block_cf.sh` already reduces the CF error to a one-line summary via
  `_cf_err_summary()` and emits it — but only through
  `log_warn` (`lib/block_cf.sh:236` for zone scope, `:286` for account scope).
- `log_warn` → `_log` writes to **stderr only** (`lib/common.sh:217`).
- The `*/5 swatter scan` cron runs with `MAILTO=""` and **no stderr redirect**
  (`/etc/cron.d/swatter`), and nothing lands under `journalctl -t swatter`. So
  the summary is **discarded**.
- The persisted record — `_swatter_audit … "block_failed action=${action}
  ${reason}"` (`lib/score.sh:126`) — carries the *offender* `reason` but **not
  the CF error summary**. `decisions.jsonl` therefore says *that* a block failed,
  never *why*.

Net: the one field that would distinguish "429 backoff" from "token lost a
permission" from "zone unresolved" exists transiently and is thrown away.

## Goal

After this change, a future operator (or `/server-logs`) reading
`decisions.jsonl` for a `failed` record can see the CF API cause directly —
no cron edit, no waiting for the next burst, no inference.

## Non-goals

- Not changing block semantics. `failed` stays `failed`; the retry loop that
  already covers these (next `*/5` re-evaluates) is correct and stays.
- Not eliminating transient CF failures outright — only making them legible
  (and, optionally, fewer via backoff).
- No new always-on log file if the data can ride the existing decision record.

## Design

### Core: thread the CF error summary into the decision record (required)

The failure cause is already computed (`_cf_err_summary`, stdin = CF response).
Surface it to the audit layer instead of only to stderr.

1. **Capture, don't just log.** Have the CF block functions
   (`_cf_block_zone`, `_cf_block_account` in `lib/block_cf.sh`) stash the
   summarized error in a run-scoped global (e.g. `SWATTER_LAST_BACKEND_ERR`)
   alongside the existing `log_warn`. Clear it at the top of each block attempt
   so a stale value never attaches to a later IP.
2. **Record it on the `failed` branch.** In `lib/score.sh` (the `else` /
   genuine-backend-error branch at ~:122–126), append the captured summary to
   the audited reason — e.g.
   `block_failed action=${action} ${reason} cf_err="${SWATTER_LAST_BACKEND_ERR}"`
   — or add it as a dedicated `evidence` key (`evidence.backend_err`). Prefer a
   structured key so the digest/`/server-logs` can group by cause.
3. **Keep it bounded + secret-safe.** `_cf_err_summary` already truncates to
   200 chars; ensure no token/credential can appear (CF error bodies don't echo
   the token, but assert it in a test). gitleaks CI remains the backstop.

This is channel-agnostic by construction: the same `SWATTER_LAST_BACKEND_ERR`
slot works for csf/ipset backend errors too, so their `failed` rows become
diagnosable for free.

### Optional A: in-run retry/backoff for transient CF errors

If the captured cause confirms 429/5xx dominates, add a small bounded retry
(e.g. 1–2 attempts with jittered backoff) inside the CF block call for
*transient* classes only (429, 5xx, timeout) — never for deterministic ones
(`already exists` is already treated as idempotent success at
`lib/block_cf.sh:192`; config/permission errors must stay non-retried so a
misconfig doesn't spin). Gate behind a conf knob (default conservative) so it
can't worsen API pressure during a wave. **Decide this only after the core
change tells us the real cause** — don't build backoff against a guess.

### Optional B: surface in the nightly digest

`report.sh` already exact-matches `failed` out of the block tallies. Add a small
"Backend failures" line to the digest: count of `failed` + top 1–2
`backend_err` causes + a reassurance/alarm flag based on whether those IPs are
now blocked (the digest already has the store). Turns the silent 41/day into a
one-line "transient, all retried" or "N still unblocked — investigate".

## Affected files

```
lib/block_cf.sh   capture _cf_err_summary into a run-scoped global (zone + account paths)
lib/score.sh      attach the captured cause to the 'failed' audit record (~:122–126)
lib/common.sh     (only if a shared SWATTER_LAST_BACKEND_ERR helper/reset belongs here)
lib/report.sh     (Optional B) backend-failures digest line
config/swatter.conf.example  (Optional A) retry/backoff knob, default off/low
test/             new cases: failed row carries cf_err; secret never leaks; idempotent-dup still = success
```

## Acceptance

- A simulated CF API failure (mocked non-`success`, non-duplicate response)
  produces a `decisions.jsonl` `failed` record whose reason/evidence contains
  the `_cf_err_summary` text.
- An idempotent duplicate (`already exists|identical`) still records as a normal
  block, **not** `failed` (regression guard on `lib/block_cf.sh:192`).
- No token/secret appears in the recorded error under any CF response shape
  (drive `_cf_err_summary`'s tolerated shapes through the test).
- `/server-logs` on a window containing a `failed` row now reports the cause
  inline instead of "no HTTP status in any log."

## Reviewer brief (for the Grok pass before building)

Per developer-wide rules, hand the plan to Grok adversarially before executing:
confirm (1) the run-scoped global can't bleed a previous IP's error onto a
later `failed` row within the same scan; (2) no credential can reach
`decisions.jsonl`; (3) the duplicate-as-success path is untouched; (4) retry
(if built) can't amplify a 429 storm. Save findings as
`2026-06-30-cf-block-failure-diagnosability-design-review-grok.md`, fold in
blockers, then build.
