# Grok review — Swatter Swarm Phase-1 design spec

**Reviewed:** `2026-07-03-swatter-swarm-fleet-reputation-design.md`
**Models:** grok-build + grok-composer-2.5-fast (parallel, read-only)
**Verdicts:** build = *Do not plan/build as-is* · composer = *Not safe to build as-is*
**Consolidated verdict:** **Revise before implementation planning.** The safe
skeleton is sound (consume through existing gates, perm-only publish, fail-soft),
but three design-level problems must be resolved first.

Provenance tags: `[both]` = both models · `[build]`/`[composer]` = one model
(verified against code before accepting).

---

## Blockers

1. **Feed format is incompatible with `swatter_cidr_list_ok`** `[both]` — §4.2/§4.3.
   The feed is `ip<TAB>host_count<TAB>category`, but `swatter_cidr_list_ok`
   (`lib/common.sh`) does `line="${line//[[:space:]]/}"` before validating, so
   `1.2.3.4<TAB>4<TAB>cat` collapses to `1.2.3.44cat` → invalid → the whole feed
   is rejected. **Independently verified** (`1.2.3.44cat` is what the strip
   produces). The spec's "same guarantee as the CF-range fetch" claim is wrong;
   ipsum/listfeeds don't use this validator at all.
   **Fix:** the validated primary feed is **bare IP/CIDR per line**;
   `host_count`/`category` move to `GET /feed?format=json` for weighting/report.

2. **"Trusted fleet = no poison problem" is false — a single host's erroneous
   perm-ban propagates fleet-wide** `[both]` — §2/§7/§14. This is the core flaw.
   The never-block set (`lib/allowlist.sh:209`) covers CF ranges, operator/
   monitoring/csf.allow/self/RFC1918/verified-crawlers — **not** arbitrary legit
   customers, API partners, or shared-egress IPs. A perm-ban of such an IP on box
   A (corrupted logs, a bug, mis-scoring) is exported by `swatter_store_perm_ips`
   and, on box B, is NOT caught by never-block. The spec conflated "no malicious
   *contributors*" with "no bad *data*" — different things. **Verified** the fold
   path can act: `b=68` (below `SCORE_TEMP=70`) + swarm `r=100` →
   `(6800+1400)/114 = 72 ≥ 70` → blocks. So §7's "boost cannot propagate as a
   fleet-wide block" is false for an IP already behaving borderline-badly on B.
   (Nuance: a *well-behaved* customer scoring ~5 locally is NOT tipped —
   `(500+1400)/114 = 17` — so boost's risk is "borderline-local IP gets tipped,"
   not "any FP propagates." Real, but narrower than block-on-sight.)
   **Fix:** corroboration-gated action — never act on `host_count=1`; a fleet
   allowlist/canary consulted **on consume**; keep boost (needs local near-miss)
   as the safe default and be honest it is "escalation assist," not "pre-block."

3. **`SWARM_ACTION=block` is an undefined new gate-bypass path** `[both]` — §8/§4.3.
   Today the scan only acts on IPs that ingest→score.awk emitted into the WATCH+
   band; intel/feeds never cause direct action (`lib/score.sh:209`). "Block on
   sight from a swarm hit" is **new** code that must route through
   `_swatter_execute_block` (or duplicate every gate: never-block, classify,
   unsafe-target, cap, fail-closed, audit). The spec assumes inheritance it
   doesn't provide.
   **Fix:** for Phase 1, drop block-on-sight OR specify a proactive sweep that
   reuses `_swatter_execute_block` exactly (like `cmd_import_bans`), gated on
   `host_count ≥ N` corroboration.

4. **"Pre-blocked on other boxes" is not achieved by the consume design**
   `[composer]` — §1/§4.3. Swarm-as-intel-signal only weights IPs already in a
   box's logs and already ≥ `SCORE_WATCH` locally, so an attacker's *first*
   contact with box B gets no swarm weight. True pre-block needs a proactive
   feed→block step. **This is the central tradeoff the spec dodged:** the safe
   model (boost) doesn't pre-block; the pre-block model (sweep/block-on-sight)
   reintroduces Blocker #2. **Resolve explicitly** (see recommendation below).

## Majors

- **`host_count` scaling formula undefined; no minimum corroboration threshold**
  `[both]` — §4.3/§8. "Scaled by host_count" has no formula/cap/floor; the fold
  hardcodes `W_REPUTATION` (14), not `W_SWARM`. `host_count=1` can contribute
  nonzero rep. Define the math and a corroboration floor for any *action*.
- **"Within the window" for `host_count` undefined; `sightings` never pruned**
  `[both]` — §4.2/§5. Define the window; prune `sightings` too (unbounded growth
  + Phase-2 identity data).
- **Token-leak blast radius not bounded by TTL; re-poisoning defeats decay; no
  rate limits/revocation; `GET /feed` is fleet recon** `[both]` — §12/§4.2. One
  shared bearer on every root box; a leak lets an attacker re-`POST` bad IPs
  indefinitely (`expires` resets each report) and read the whole offender list.
  **Fix:** separate read vs write credentials, add rate limiting, and state the
  residual risk honestly (full mitigation — signing — is Phase 2).
- **`SWARM_TTL` authority split** `[both]` — §9/§4.2. Expiry is hub-side; make
  `SWARM_TTL` a hub config, not host config (or define reconciliation).
- **Publish cursor on `actions.id` breaks the flatfile store** `[both]` — §4.1.
  Flatfile JSONL has no `id`. Use a ts-based cursor or gate swarm on `STORE=sqlite`.
- **Phase-1 auth shortcuts need replacement, not extension, for Phase 2** `[both]`
  — §14. The *data model* (host_count, sightings, host_id) is forward-compatible;
  the *auth* (shared token, host_id-as-claim) will be torn out. Soften the claim.
- **Hub scale / feed size / failure modes thin** `[both]` — §4.2/§12. No feed
  size cap/pagination; prune is daily-cron-only with no failure alert; no D1
  budget analysis; no feed **staleness policy** (CF ranges have
  `ALLOWLIST_MAX_AGE_DAYS`; swarm has none).
- **Concurrent `POST /contribute` race on `host_count`** `[both]` — §4.2. Define
  D1 transaction boundaries (read-check-write across sightings+offenders).
- **Disable/rollback incomplete** `[both]` — §9/§13. Define: remove `swarm` from
  providers, delete `swarm.txt`, purge-hub option after a bad publish.
- **IPv6, import/export-bans interaction, metrics/report surface unspecified**
  `[both]` — §4.1/§10. Add v6 handling; avoid double-publishing vs export-bans;
  add swarm metrics + `decisions.jsonl` labeling + report line.

## Minors

- Category taxonomy (`decisive_rule`→category) undecided; store only guarantees
  `last_label`/`reason`. `[both]`
- `W_SWARM` vs `W_REPUTATION` naming/mechanism collision. `[composer]`
- `host_id` rotation/compromise recovery undefined. `[both]`
- Publish timing vs `swatter_acquire_lock` / scan completion unspecified. `[both]`
- No per-request payload size limit. `[composer]`
- Multi-hub consumption deferred (affects data model). `[both]`
- No feed schema version/header. `[build]`

## Genuinely handled (verified safe)

- Never-block/classify/unsafe-target gates apply to anything reaching
  `_swatter_execute_block` (`lib/score.sh:82`, `lib/classify.sh:281`,
  `lib/common.sh` unsafe-target).
- `_swatter_fold_reputation` cannot LOWER a strong behavioral score
  (`lib/score.sh:34`).
- `swatter_store_perm_ips` excludes dry-run + unblocked IPs.
- Publish set is perm-only (not watch/temp).
- Fail-soft on hub/feed failure preserves the last-good file.

---

## Recommended design changes before planning

1. **Feed:** bare IP/CIDR per line (validated); metadata via `?format=json`.
2. **Resolve the pre-block/safety tradeoff honestly with a corroboration model:**
   - `boost` (default): swarm raises a score but still needs local near-miss
     evidence to block. Marketed as "escalation assist," not "pre-block." Safe at
     `host_count=1`.
   - `block` (opt-in, gated): proactive block via an `import-bans`-style sweep
     through `_swatter_execute_block`, allowed **only** when `host_count ≥
     SWARM_MIN_CORROBORATION` (default e.g. 2–3). "3 of my own boxes confirmed
     it" is a defensible pre-block trigger for a trusted fleet; one box is not.
3. **Consume-side fleet allowlist / canary:** a never-swarm-block set consulted on
   consume (operator's known-good customers/partners), so a single bad publish
   can't tip a known-good IP even in boost mode.
4. **Auth:** separate read vs write tokens; rate-limit `/contribute`; state that
   TTL does not bound an active attacker; signing is explicitly Phase 2.
5. **Hub hardening:** feed size cap + pagination; prune `sightings`; prune-failure
   alerting; D1 transaction for the upsert/count; feed staleness policy mirroring
   `ALLOWLIST_MAX_AGE_DAYS`.
6. **Store/rollback:** ts-based publish cursor (flatfile-safe); full disable path;
   IPv6; export/import-bans interaction; swarm metrics + report surface.
7. **Soften the Phase-2 claim:** data model forward-compatible; auth/trust layer
   is a Phase-2 replacement, not an extension.
