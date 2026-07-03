# Swatter Swarm — fleet reputation sharing (Phase 1 design)

**Date:** 2026-07-03
**Status:** design — awaiting user review before implementation planning
**Author:** brainstormed with the operator; decisions recorded inline

## 1. Goal

Give Swatter a **network effect** — the one real capability gap vs. CrowdSec
(per the 2026-07-03 competitive read: Swatter is an elite specialist but has no
crowd signal of its own). An attacker who hits one box in a fleet should be
pre-blocked (or pre-weighted) on the others.

Phase 1 delivers this for a **single operator's own trusted fleet**, shipped as a
**self-hostable public feature**: any Swatter operator can stand up their own
private fleet network for their own boxes. It is deliberately NOT one global
shared network — that is Phase 2 (see §14).

## 2. Non-goals (Phase 1)

- **No open/community/crowd contributions.** Every contributor is a box the
  operator owns, so there is no poison-resistance problem. Opening it to
  untrusted contributors is Phase 2 and requires a trust layer we do NOT build
  here.
- **No real-time push.** Sharing piggybacks Swatter's existing cadence (`*/5`
  scan, daily `refresh-feeds`). Sub-second propagation is not a requirement.
- **No dashboard.** The hub feed plus the existing nightly report cover
  visibility.
- **No contributor signing / identity verification.** Trust in Phase 1 comes
  from fleet ownership; a shared bearer token is sufficient.

## 3. Context it builds on (existing Swatter plumbing)

- `swatter export-bans` / `swatter_store_perm_ips` — selects the IPs that are
  *actually* perm-blocked (enforced, `dry_run=0`, not later unblocked). This is
  the exact "confirmed offender" set Swarm should publish.
- `refresh-feeds` already fetches remote IP/CIDR feeds and validates the body
  (`swatter_cidr_list_ok`) before install. A swarm feed is just another such
  fetch.
- The intel layer (`lib/intel.sh`) folds a per-IP reputation score into the
  behavioral score via a provider abstraction and `$STATE_DIR/feeds/*`.
- The never-block set (`lib/allowlist.sh`), classifier (`lib/classify.sh`), the
  v2.5.2 strict-validator + unsafe-target guard, and the secret-safe
  `swatter_curl_cfg` (`curl -K`) pattern — all reused, so Swarm inherits every
  safety guarantee without re-deriving it.

## 4. Architecture — three components

### 4.1 Publish (host → hub)

- After a scan (or on `refresh-feeds`), the host computes the **delta** of newly
  confirmed offenders since the last successful publish, using a cursor at
  `$STATE_DIR/swarm.publish.cursor` (last-published max `actions.id` or ts).
- Source set (Phase 1) = **confirmed perm bans only** (`swatter_store_perm_ips`:
  enforced, `dry_run=0`, still-banned). This is the least-ambiguous "confirmed
  bad actor" set. Watch/temp/dry-run are **never** published. *(Fast-follow, not
  in this cut: also publish enforced blocks with folded score ≥ `SCORE_PERM` AND
  a positive intel/honeypot signal, to warn the fleet on first sight of an
  obvious scanner rather than after `REPEAT_N` offenses. Deferred to keep the
  Phase-1 publish set unambiguous.)*
- Each IP is re-validated with `swatter_is_valid_ip_or_cidr` and run through
  `swatter_is_never_block` before send (defense in depth — never publish an IP
  the local box would itself never block, e.g. a monitor).
- Payload: JSON array of `{ip, category, first_local_seen}`; `POST /contribute`
  with `Authorization: Bearer <fleet-token>` via `curl -K` (secret hygiene).
- Fail-soft: a publish failure logs a warning and leaves the cursor unadvanced
  (retry next cycle); it never blocks a scan.

### 4.2 Hub (Cloudflare Worker + D1)

Deployed by the operator to their own Cloudflare account (see §10). Endpoints:

- `POST /contribute` — auth via bearer fleet-token (compared against a Worker
  secret). For each IP: upsert into D1, bumping `last_seen`, extending `expires`,
  and incrementing `host_count` only when the reporting host is new for that IP
  within the window. Rejects malformed IPs (server-side revalidation) and
  unauthenticated requests.
- `GET /feed` — auth required. Returns the active set (`expires > now`) as
  `ip<TAB>host_count<TAB>category` lines (feed-file friendly) or JSON via
  `?format=json`. This is what `refresh-feeds` pulls.
- **Scheduled prune** (Worker cron trigger, daily) — deletes rows past `expires`.
  TTL decay: every re-report extends `expires = now + SWARM_TTL`, so an IP no box
  has seen in `SWARM_TTL` ages out on its own.

**Store: D1** (recommended over KV). Aggregation is naturally SQL — `host_count`,
`WHERE expires > now`, prune-by-expiry — and mirrors the host-side sqlite ledger
mental model. KV would force hand-rolled counting/expiry. *(Decision taken in the
operator's absence; override on review if KV is preferred for simplicity.)*

### 4.3 Consume (hub → host)

- `refresh-feeds` GETs `/feed` into `$STATE_DIR/feeds/swarm.txt`, validated by the
  existing `swatter_cidr_list_ok` before install (a captive-portal / error body
  never poisons the feed — the same guarantee the CF-range fetch already has).
- The swarm feed is registered as an intel signal. On scan, a swarm-listed IP
  contributes a reputation score `W_SWARM`, scaled by `host_count` (an IP flagged
  by 4 boxes weighs more than one flagged by 1). This folds through the existing
  `_swatter_fold_reputation` path.
- **The IP still passes through never-block → classify → unsafe-target → scoring
  locally before any block.** Swarm signal can raise a score; it cannot bypass a
  single safety gate. A swarm IP that is a CF edge, operator IP, monitor, or
  `/0`/unspecified is refused exactly as today.

## 5. Data model (D1)

```sql
CREATE TABLE offenders (
  ip           TEXT PRIMARY KEY,
  first_seen   INTEGER NOT NULL,   -- epoch, first time ANY host reported it
  last_seen    INTEGER NOT NULL,   -- epoch, most recent report
  host_count   INTEGER NOT NULL DEFAULT 1,  -- distinct hosts that reported it
  last_host    TEXT,               -- opaque host id of the most recent reporter
  category     TEXT,               -- e.g. critical_badpath, scanner_profile
  expires      INTEGER NOT NULL    -- last_seen + SWARM_TTL; pruned when < now
);
CREATE INDEX ix_offenders_expires ON offenders(expires);

-- Per-(ip,host) sightings so host_count is exact and Phase-2-ready.
CREATE TABLE sightings (
  ip        TEXT NOT NULL,
  host      TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (ip, host)
);
```

`host_count` and `last_host`/`sightings` are the corroboration + contributor-
identity fields Phase 2's trust layer grows into (see §14) — carried now so the
crowd model needs no re-architecture.

## 6. Host id

An opaque, stable per-host id (`$STATE_DIR/swarm.host_id`, random on first use)
— NOT the hostname/IP (avoids leaking fleet topology into the hub, and is the
seed for Phase-2 contributor identity). Sent with each contribution.

## 7. Safety (how Phase 1 stays "only bad actors")

- **Publish gate:** only enforced `perm` / high-confidence blocks; each IP
  validated + never-block-checked before it leaves the box.
- **Consume gate:** swarm feed body validated before install; every listed IP
  still runs the full local never-block → classify → unsafe-target → scoring path.
- **Action default = `boost`, not `block`** (§8) so one host's mistake cannot
  propagate as a fleet-wide block.
- **TTL decay:** a stale/erroneous entry self-expires; nothing is permanent
  hub-side.
- **Secret hygiene:** fleet token in a `0400` file, sent via `curl -K`, never in
  argv (matches SendGrid/CF/Twilio handling).

## 8. Safety knob — `SWARM_ACTION`

Ship `SWARM_ACTION` with default **`boost`** (high-weight, `host_count`-scaled
reputation contribution; the IP must still clear local scoring), per-host opt-in
to **`block`** (act on a swarm hit directly, still after never-block/classify).
*(Decision taken in the operator's absence: default `boost`, configurable to
`block`. Override on review.)*

## 9. Config surface (`swatter.conf`, all OFF by default)

| Key | Default | Meaning |
|-----|---------|---------|
| `SWARM_ENABLE` | `false` | master switch |
| `SWARM_HUB_URL` | `""` | e.g. `https://swarm.example.workers.dev` |
| `SWARM_TOKEN_FILE` | `/etc/swatter/swarm.token` | `0400` bearer token |
| `SWARM_PUBLISH` | `true` | contribute this box's offenders (a pure consumer sets false) |
| `SWARM_ACTION` | `boost` | `boost` \| `block` |
| `W_SWARM` | `16` | reputation weight when `boost` |
| `SWARM_TTL` | `604800` | hub-side expiry seconds (7d) |

## 10. Packaging — the self-hostable public feature

New top-level `hub/` in the repo:
- `hub/worker.js` — the Worker (contribute/feed/prune).
- `hub/wrangler.toml` — D1 binding + cron trigger; account-agnostic.
- `hub/schema.sql` — the D1 schema (§5).
- `hub/README.md` — deploy in minutes: `wrangler d1 create`, apply schema,
  `wrangler secret put SWARM_TOKEN`, `wrangler deploy`, then set each box's
  `SWARM_HUB_URL` + token.

Peace Harbor is the first deployment (starts at cds1). A new box enrolls
**zero-config**: drop the hub URL + fleet token into its conf (or a deploy
secret) and it publishes + consumes on the next cycle. No per-host registration
in Phase 1.

## 11. Testing

**Host side** (existing bash harness, new `test/swarm_test.sh`):
- publish selects only confirmed + new-since-cursor + validated + non-never-block
  IPs; watch/temp/dry-run excluded.
- publish failure leaves the cursor unadvanced (retry) and never aborts a scan.
- consume: a swarm-listed attacker IP raises the folded score; a swarm-listed
  never-block IP (CF edge / operator / monitor) is still exempt; a swarm-listed
  `/0`/unspecified is still refused; `SWARM_ACTION=block` acts, `boost` only
  weights.
- disabled by default (no network calls when `SWARM_ENABLE=false`).
- curl calls use `-K` (extend `curl_secrets_test.sh`).

**Hub side** (new — repo's first Worker tests, vitest + `wrangler dev`/miniflare):
- `contribute` upserts, increments `host_count` only for a new host, extends
  `expires`.
- `feed` returns only non-expired rows; prune deletes expired.
- auth: missing/wrong token → 401; malformed IP → rejected.

## 12. Failure modes

- Hub unreachable → publish + consume both fail-soft (warn, keep last-good
  `swarm.txt`, unadvanced cursor). Local detection/blocking is unaffected.
- Poisoned/garbage feed body → rejected by `swatter_cidr_list_ok`, last-good kept.
- Token leak → rotate the Worker secret + redeploy token file; TTL bounds
  exposure of any bad contributions.

## 13. Rollout

Ships OFF by default; a version bump + release per the standing process. Enable on
cds1 first (publish-only initially to seed the hub), then flip consume on once the
feed has content, then add boxes.

## 14. Phase 2 — open crowd-sourced network (the ultimate goal; NOT built here)

CrowdSec-style: anyone running Swatter contributes. The existential problem is
poison-resistance (a malicious contributor getting a legit IP blocked
crowd-wide) under Swatter's "only bad actors" constraint. It needs a **trust
layer** on top of this exact pipeline:
- contributor identity + request signing (the `host_id`/`last_host`/`sightings`
  fields already seed this);
- reputation weighting per contributor;
- a consensus threshold — an IP acts only once N distinct, sufficiently-reputable
  contributors corroborate (`host_count` already models corroboration);
- canary / global-allowlist defenses so a well-known-good IP can never be listed;
- abuse reporting + contributor revocation.

Phase 1's data model and pipeline are built to NOT preclude any of this. Phase 1
earns safety from *ownership*; Phase 2 earns it from *consensus*.

## 15. Decisions taken without the operator (flag on review)

1. **Hub store = D1** (over KV) — SQL aggregation fit.
2. **`SWARM_ACTION` default = `boost`, opt-in `block`** — safest + most flexible.

Both are easy to change and isolated to §4.2 / §8.

## 16. Open questions for review

- Category taxonomy shared to the hub — reuse `decisive_rule` values, or a
  coarser set?
- Should a pure-consumer box (publish=false) still count toward `host_count`? (No
  — it contributes nothing; leave as consumer-only.)
- One hub per operator, or allow a box to consume from multiple hubs (e.g. a
  personal fleet + a trusted partner's) — a stepping stone toward Phase 2?
