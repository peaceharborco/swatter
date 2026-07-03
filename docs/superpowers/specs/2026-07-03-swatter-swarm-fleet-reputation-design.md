# Swatter Swarm — fleet reputation sharing (Phase 1 design, v2)

**Date:** 2026-07-03
**Status:** design v2 — revised after the Grok two-model review
(`…-design-review-grok.md`); awaiting operator approval of the action model (§8)
before implementation planning.
**Author:** brainstormed with the operator; review findings folded in.

> **v2 changelog:** rewrote the trust model after review Blocker #2 — Phase 1
> trust comes from *ownership of contributors*, but bad *data* from one host can
> still propagate, so action is now corroboration-gated and a consume-side fleet
> allowlist is mandatory. Fixed the feed-format/validator contract (Blocker #1).
> Defined `SWARM_ACTION` integration (Blocker #3) and resolved the
> pre-block/safety tradeoff honestly (Blocker #4). Specified hub concurrency,
> pruning, staleness, dual tokens, flatfile-safe cursor, disable path, IPv6.

## 1. Goal

Give Swatter a **network effect** (the gap vs. CrowdSec): an attacker who hits
one box in a fleet is acted on faster — or pre-emptively — on the others.

Phase 1 delivers this for a **single operator's own trusted fleet**, shipped as a
**self-hostable public feature**: any operator stands up their own private fleet
network. It is NOT one global network — that is Phase 2 (§14).

**Honest scope of the benefit (per review Blocker #4):** with the default action
model, swarm is **escalation assist** — it makes a receiving box quicker to act
on an IP that is *also* misbehaving locally. **True pre-block** (act before the
attacker misbehaves on box B) is available only via the opt-in,
corroboration-gated proactive mode (§8). We do not oversell "pre-block."

## 2. Non-goals (Phase 1)

- **No open/community contributions.** Every contributor is a box the operator
  owns. This removes malicious *contributors* — but NOT erroneous *data* (§7);
  the design must defend against a single host's mistake regardless.
- **No real-time push.** Piggybacks the `*/5` scan + daily `refresh-feeds`.
- **No dashboard.** Hub feed + nightly report cover visibility.
- **No contributor signing / per-host keys.** Phase 1 auth is shared tokens
  (§4.4); request signing + per-contributor reputation are Phase 2.

## 3. Context it builds on

- `swatter_store_perm_ips` (`lib/store_sqlite.sh`) — the confirmed-offender set
  (enforced `perm`, `dry_run=0`, still-banned; excludes dry-run + unblocked).
- `refresh-feeds` (`bin/swatter`) — fetches + validates remote feeds.
- Intel layer (`lib/intel.sh`) + `_swatter_fold_reputation` (`lib/score.sh`) —
  folds a reputation score into the behavioral score (can only *raise* it).
- never-block (`lib/allowlist.sh`), classify (`lib/classify.sh`), strict validator
  + `_swatter_is_unsafe_block_target`, `_swatter_execute_block` (the single gated
  block choke), secret-safe `swatter_curl_cfg` (`curl -K`).

## 4. Architecture

### 4.1 Publish (host → hub)

- Runs after a scan completes (inside the existing lock; never concurrent with a
  scan). Computes the **delta** of newly confirmed perm bans since the last
  successful publish.
- **Cursor is timestamp-based** (`$STATE_DIR/swarm.publish.cursor` = epoch of the
  last published action), so it works for BOTH the sqlite and flatfile stores
  (flatfile JSONL has no row id — review Major). Advanced only on a successful
  `POST` (fail-soft: a failed publish retries next cycle, never aborts a scan).
- **Source = confirmed perm bans only** (`swatter_store_perm_ips`). Watch/temp/
  dry-run never published. *(Fast-follow, deferred: high-confidence enforced
  blocks with score ≥ `SCORE_PERM` + intel/honeypot signal.)*
- Each IP is re-validated (`swatter_is_valid_ip_or_cidr`), unsafe-target-checked
  (`_swatter_is_unsafe_block_target`), and never-block-checked
  (`swatter_is_never_block`) before send. **Also checked against the consume-side
  fleet allowlist (§4.5)** so a known-good IP never leaves a box even if locally
  mis-banned.
- Payload: JSON `{host_id, entries:[{ip, category, first_local_seen}]}`, capped at
  a max batch size (chunked if larger). `POST /contribute`, **write token** via
  `curl -K`.

### 4.2 Hub (Cloudflare Worker + D1)

Operator deploys to their own CF account (§10). Endpoints:

- `POST /contribute` — **write-token** auth. Per IP, in a single D1 transaction:
  upsert `offenders` (bump `last_seen`, `expires = last_seen + SWARM_TTL`,
  `last_host`); upsert `sightings(ip, host, last_seen)`; recompute
  `host_count = COUNT(DISTINCT host) FROM sightings WHERE ip=? AND last_seen >
  now - SWARM_TTL`. Server-side revalidates each IP + rejects unsafe targets.
  **Rate-limited** per token (and per host_id) to bound a leaked-token attacker.
- `GET /feed` — **read-token** auth (a DIFFERENT token from write; see §4.4).
  Two formats:
  - default → **bare `ip` per line** (IPv4 and IPv6), which is exactly what
    `swatter_cidr_list_ok` validates (review Blocker #1). This is the file that
    feeds scoring/never-block.
  - `?format=json` → `[{ip, host_count, category, expires}]` for weighting +
    report. Bounded by a **max feed size**; paginated (`?cursor=`) if exceeded.
- **Scheduled prune** (Worker cron, daily): delete `offenders` past `expires`
  AND `sightings` past `now - SWARM_TTL` (both, per review — sightings was
  unbounded). Prune failures are surfaced (logged/metric) so a stuck prune can't
  silently grow the table + feed.

`SWARM_TTL` is **hub-authoritative** (a Worker config/binding), not host config
(review — authority split). Hosts don't set expiry.

**Store: D1** — SQL fits `host_count`, expiry, and the DISTINCT-host count. KV
would force hand-rolled counting/expiry. *(Recommended; override on review.)*

### 4.3 Consume (host → block pipeline)

- `refresh-feeds` GETs `/feed` (bare-IP) into `$STATE_DIR/feeds/swarm.txt`,
  validated by `swatter_cidr_list_ok` before install (poisoned/error body →
  rejected, last-good kept). GETs `?format=json` into a sidecar
  (`swarm.meta.json`) for `host_count`/category.
- **Feed staleness policy** mirrors the CF ranges: if `swarm.txt` is older than
  `SWARM_MAX_AGE_DAYS` (default 3), swarm signal is treated as absent + a warning
  is logged (review — no staleness policy today; CF ranges have
  `ALLOWLIST_MAX_AGE_DAYS`).
- Swarm becomes an intel provider (`provider_swarm`) returning a reputation score
  for a listed IP, folded via the existing `_swatter_fold_reputation`. **Every
  listed IP still runs the full local gate chain** — fleet allowlist (§4.5) →
  never-block → classify → unsafe-target → scoring — before any block. Swarm can
  *raise* a score; it cannot bypass a gate.

### 4.4 Auth — two tokens, not one

Review: a single shared bearer on every root box is both a poisoning key and a
recon key. Phase 1 mitigation:

- **Write token** (`SWARM_WRITE_TOKEN_FILE`, 0400) — only on boxes that publish.
- **Read token** (`SWARM_READ_TOKEN_FILE`, 0400) — on all consumers.
- A compromised *consumer* (read-only) cannot poison the hub. A leaked write
  token still allows re-poisoning within its rate limit until rotated — **stated
  honestly: TTL does NOT bound an active attacker; rotation does.** Per-host
  signing that would fully fix this is Phase 2.
- Both sent via `curl -K` (never argv).

### 4.5 Consume-side fleet allowlist (canary) — NEW, mandatory

A `SWARM_ALLOW_FILE` (operator's known-good customers / API partners / egress
IPs — the legit IPs that are NOT in the generic never-block set). Consulted on
**both** publish (don't emit) and consume (never swarm-block, never swarm-boost).
This is the direct defense against Blocker #2: a single host's erroneous perm-ban
of a known-good IP cannot tip that IP on any other box. It is the Phase-1 stand-in
for Phase 2's global canary set.

## 5. Data model (D1)

```sql
CREATE TABLE offenders (
  ip         TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  host_count INTEGER NOT NULL DEFAULT 1,   -- DISTINCT hosts within SWARM_TTL
  last_host  TEXT,
  category   TEXT,
  expires    INTEGER NOT NULL              -- last_seen + SWARM_TTL
);
CREATE INDEX ix_offenders_expires ON offenders(expires);

CREATE TABLE sightings (
  ip        TEXT NOT NULL,
  host      TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (ip, host)
);
CREATE INDEX ix_sightings_seen ON sightings(last_seen);   -- for prune
```

`host_count` = corroboration; `last_host`/`sightings` = contributor identity —
the fields Phase 2's trust layer needs. (Data model is forward-compatible; the
*auth* layer is a Phase-2 replacement — see §14.)

## 6. Host id

Opaque, stable, random per box (`$STATE_DIR/swarm.host_id`), NOT hostname/IP.
Seeds Phase-2 contributor identity. In Phase 1 the hub *trusts the claimed
host_id* (no signing) — acceptable because contributors are owned; Phase 2 binds
host_id to a signing key.

## 7. Safety (corrected after review)

- **The Phase-1 risk is bad DATA, not bad actors.** A false perm-ban on one box
  (corrupted logs, mis-score, bug) can be published. The never-block set does NOT
  cover arbitrary legit customers, so consume-side never-block alone does not
  stop propagation. Defenses, layered:
  1. **Consume-side fleet allowlist (§4.5)** — known-good IPs are never
     swarm-acted, on any box.
  2. **Corroboration gate (§8)** — a proactive block requires `host_count ≥
     SWARM_MIN_CORROBORATION`; one host's say-so never blocks pre-emptively.
  3. **Boost needs local evidence** — in `boost` mode swarm only *raises* a
     score, so a well-behaved IP (local score ~5) is never tipped; only an IP
     already misbehaving locally can cross the threshold. (Verified: local 5 +
     swarm → ~17, far below 70; local 68 + swarm → 72, blocks — which is the
     intended "escalate a local near-miss," not "block a stranger.")
  4. **TTL decay + rotation** bound stale/leaked-token damage (rotation, not TTL,
     stops an *active* attacker — stated honestly).
- Publish is perm-only + validated + unsafe-target-checked + never-block-checked
  + fleet-allow-checked before an IP leaves the box.
- Secret hygiene: dual 0400 tokens via `curl -K`.

## 8. Action model (`SWARM_ACTION`) — the key decision (confirm on review)

**Recommended: `boost` default + opt-in `corroborated-block`.**

- `boost` (default): `provider_swarm` returns a reputation **score** 0–100 for a
  listed IP (like `provider_abuseipdb` returns a confidence), computed from a base
  `SWARM_BASE_SCORE` scaled by `host_count` up to 100. That score folds through
  the existing intel path via the standard `W_REPUTATION` weight — i.e. swarm is a
  normal intel provider, NOT a new fold weight (this avoids the `W_SWARM` /
  `W_REPUTATION` mechanism confusion the review flagged). Blocks an IP ONLY if
  local behavior + swarm together cross the threshold. Safe at `host_count=1`.
  This is "escalation assist."
- `corroborated-block` (opt-in): a proactive pre-block sweep on `refresh-feeds`
  that blocks swarm IPs with `host_count ≥ SWARM_MIN_CORROBORATION` (default 2–3)
  — routed through **`_swatter_execute_block`** (or an `import-bans`-style path
  that reuses it) so it inherits EVERY gate: fleet-allow, never-block, classify,
  unsafe-target, cap, fail-closed, audit. "N of my own boxes independently
  confirmed it" is a defensible pre-block for a trusted fleet; one box is not.
  Never a raw new block path (review Blocker #3).

*Rejected:* unconditional `block` on a single-host hit — that is Blocker #2/#3.

*(Simplest alternative if the operator prefers: ship `boost`-only for Phase 1 and
defer `corroborated-block`. The recommended model is a superset of this.)*

## 9. Config surface (`swatter.conf`, all OFF by default)

| Key | Default | Meaning |
|-----|---------|---------|
| `SWARM_ENABLE` | `false` | master switch |
| `SWARM_HUB_URL` | `""` | hub base URL |
| `SWARM_WRITE_TOKEN_FILE` | `/etc/swatter/swarm.write.token` | 0400; publishers only |
| `SWARM_READ_TOKEN_FILE` | `/etc/swatter/swarm.read.token` | 0400; consumers |
| `SWARM_PUBLISH` | `true` | contribute this box's offenders |
| `SWARM_ACTION` | `boost` | `boost` \| `corroborated-block` |
| `SWARM_MIN_CORROBORATION` | `2` | min distinct hosts for a proactive block |
| `SWARM_BASE_SCORE` | `70` | base intel score a swarm hit returns (scaled by `host_count` to ≤100; folds via the standard `W_REPUTATION` path) |
| `SWARM_ALLOW_FILE` | `/etc/swatter/swarm.allow.cidr` | fleet canary (never swarm-acted) |
| `SWARM_MAX_AGE_DAYS` | `3` | swarm feed staleness cutoff |

(`SWARM_TTL` is hub-side, not here.)

## 10. Packaging — self-hostable `hub/`

New `hub/`: `worker.js`, `wrangler.toml` (D1 binding + cron trigger + rate-limit
binding), `schema.sql`, `README.md` (deploy in minutes: create D1, apply schema,
`wrangler secret put` the write + read tokens, `wrangler deploy`, point boxes at
the URL). PH is the first tenant (cds1); new boxes enroll zero-config with the URL
+ tokens.

## 11. Testing

**Host side** (`test/swarm_test.sh`, existing bash harness):
- publish selects only confirmed perm + new-since-(ts)-cursor + validated +
  non-never-block + non-fleet-allow IPs; watch/temp/dry-run excluded; cursor is
  ts-based and works with `STORE=flatfile`.
- publish failure leaves cursor unadvanced; never aborts a scan; runs inside lock.
- consume: bare-IP feed installs via `swatter_cidr_list_ok`; a tab/garbage body is
  rejected (last-good kept); stale feed (> `SWARM_MAX_AGE_DAYS`) → signal absent +
  warn.
- a swarm attacker IP raises the folded score; a fleet-allow IP is never boosted
  or blocked; a never-block IP is still exempt; an unsafe target still refused.
- `boost`: local-clean IP never blocked; local-near-miss IP tipped.
  `corroborated-block`: `host_count < N` → not proactively blocked; `≥ N` →
  blocked **through `_swatter_execute_block`** (never-block/classify still apply).
- disabled by default (no network calls); curl uses `-K` (extend
  `curl_secrets_test.sh`).

**Hub side** (new — repo's first Worker tests, vitest + miniflare/`wrangler dev`):
- `contribute`: transactional upsert; `host_count` = DISTINCT hosts within TTL;
  concurrent POSTs don't over/under-count; malformed/unsafe IP rejected; write
  token required; rate limit enforced.
- `feed`: bare-IP default + JSON variant; only non-expired rows; size cap +
  pagination; read token required; read token cannot POST.
- prune: removes expired `offenders` AND `sightings`; failure surfaced.

## 12. Failure modes

- Hub unreachable → publish + consume fail-soft (warn, last-good `swarm.txt`
  kept, cursor unadvanced). Local detection unaffected.
- Stale feed → past `SWARM_MAX_AGE_DAYS`, swarm signal treated as absent (not
  trusted indefinitely).
- Poisoned/garbage body → rejected by `swatter_cidr_list_ok`.
- Write-token leak → rotate the Worker secret + redeploy; rate limit caps
  in-window damage; TTL ages stale entries after the attacker stops (does NOT
  stop an active attacker — rotation does).
- Prune failure → surfaced; feed size cap prevents runaway responses meanwhile.

## 13. Rollback / disable (full path)

`swatter swarm disable` (or `SWARM_ENABLE=false` + a documented sequence):
remove `swarm` from the active intel providers, delete `swarm.txt` +
`swarm.meta.json` + the swarm intel cache, stop publishing. A `swatter swarm
purge` (operator-run, with the write token) deletes this operator's contributions
from the hub after a bad publish. No box remains stuck on a poisoned last-good
feed.

## 14. Phase 2 — open crowd-sourced network (the ultimate goal; NOT built here)

CrowdSec-style open contributions. Existential problem: poison-resistance under
Swatter's "only bad actors" rule. Needs a trust layer:
- per-contributor identity + **request signing** (binds `host_id` to a key);
- reputation weighting per contributor;
- consensus threshold before acting (`host_count` already models corroboration;
  Phase 2 weights it by contributor reputation);
- global canary/allowlist (Phase 1's `SWARM_ALLOW_FILE` is the local stand-in);
- abuse reporting + contributor revocation; rate/quotas per identity.

**Honest forward-compat (per review):** the *data model* (host_count, sightings,
host_id) is built to grow into this. The *auth* layer (shared tokens,
host_id-as-claim) is a Phase-2 **replacement**, not an extension. Phase 1 earns
safety from *ownership*; Phase 2 earns it from *consensus + signing*.

## 15. Decisions taken without the operator (confirm on review)

1. **Hub store = D1** (over KV).
2. **Action model = `boost` default + opt-in `corroborated-block`**
   (`SWARM_MIN_CORROBORATION=2`), rather than unconditional block-on-sight or
   boost-only. This is the §8 decision most wanting your sign-off.
3. **Dual read/write tokens** (not one shared bearer).
4. **Mandatory consume-side `SWARM_ALLOW_FILE`** as the Phase-1 canary.

## 16. Open questions for review

- Category taxonomy: reuse `decisive_rule`, or a coarser shared set?
- `SWARM_MIN_CORROBORATION` default — 2 or 3? (2 at small fleet, 3 as it grows.)
- Should `corroborated-block` ship in Phase 1 at all, or defer to keep the first
  cut boost-only?
- Multi-hub consumption (personal + partner) — a stepping stone to Phase 2, or
  out of scope now?

## 17. Review resolution (Grok, 2026-07-03)

All four Blockers and the Majors from `…-design-review-grok.md` are addressed in
this v2: feed format (Blocker #1 → §4.2 bare-IP), poison propagation (Blocker #2
→ §4.5 fleet allowlist + §8 corroboration + §7 corrected claims),
`SWARM_ACTION=block` gate path (Blocker #3 → §8 via `_swatter_execute_block`),
pre-block/safety tradeoff (Blocker #4 → §1/§8 honest split). Majors: dual tokens
+ rate limit (§4.4), hub transaction/prune/staleness/size-cap (§4.2/§4.3/§12),
ts-based flatfile-safe cursor (§4.1), disable/purge path (§13), IPv6 (§4.2),
softened Phase-2 auth claim (§14).
