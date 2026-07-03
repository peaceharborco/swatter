# Swatter Swarm — fleet reputation sharing (Phase 1 design, v3)

**Date:** 2026-07-03
**Status:** design v3 — folds in BOTH the design review and the hub-plan review.
Operator-confirmed decisions: ship both `boost` + `corroborated-block` (§8),
per-token host registry (§6), hub accepts IP-or-CIDR (§4.2), `host_count` derived
at read time (§4.2/§5). Hub implementation plan must be rewritten to v2 against
this design before execution.
**Author:** brainstormed with the operator; two rounds of review findings folded in.

> **v3 changelog (hub-plan review):** `host_count` is now derived at feed-read
> time (kills the cross-request write race); a **per-token host registry** + a
> third **enroll token** close the forgeable-`host_id` corroboration hole; the hub
> accepts **IP or CIDR** (parity with the bash validator); the **empty-feed**
> contract (clear vs. keep-last-good) is explicit; rate limiting keys on the
> connecting IP, not the attacker-controlled `host_id`; `corroborated-block`
> requires the JSON feed; payload cap + truncation signalling added.
> **v2 changelog (design review):** corroboration-gated action + mandatory
> consume-side fleet allowlist (poison propagation); bare-IP feed format;
> `SWARM_ACTION` gate path via `_swatter_execute_block`; honest pre-block framing;
> dual tokens, prune, staleness, flatfile-safe cursor, disable path, IPv6.

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

- `POST /contribute` — **write-token** auth. Per entry: server-side re-validate
  (accept a valid **IP or CIDR** — parity with the bash validator so a host's
  CIDR perm-ban isn't silently dropped; hub-plan-review decision B) and reject
  unsafe targets (`/0`, unspecified). Then upsert `sightings(ip, host, last_seen)`
  and touch `offenders(ip, first_seen, last_seen, last_host, category, expires =
  last_seen + SWARM_TTL)`. **`host_count` is NOT stored on write** — see below.
  `entries[]` is capped (e.g. 1000/request; `413` over). Rate-limited on the
  **connecting IP + a global `/contribute` limit** (NOT on the attacker-controlled
  `host_id`; hub-plan-review Major #6).
- **`host_count` is derived at READ time** from `sightings`
  (`COUNT(DISTINCT host) WHERE ip=? AND host IN (registered) AND last_seen >
  now-SWARM_TTL`), NOT cached on write. This removes the cross-request write race
  the plan review flagged (Blocker #2) — the count always reflects the committed
  `sightings` source of truth — and lets the **host registry** (§6) gate it.
- `POST /register` — **enroll-token** auth (a THIRD credential, operator-held, NOT
  on every box; §4.4). Adds a `host_id` to the `hosts` registry. Only registered
  `host_id`s count toward `host_count`, so a leaked *write* token cannot forge
  corroboration by inventing `host_id`s (hub-plan-review Blocker #3, decision A:
  per-token host registry).
- `GET /feed` — **read-token** auth (a DIFFERENT token from write/enroll; §4.4).
  - default → **bare `ip`/`cidr` per line**, exactly what `swatter_cidr_list_ok`
    validates. Feeds scoring/never-block. **An empty active set returns an empty
    `200`** — the host MUST treat that as "valid empty → clear `swarm.txt`," NOT
    route it through `swatter_cidr_list_ok` (whose `n>0` would reject it and freeze
    decay; hub-plan-review Blocker #4). Handled in the host-side consume path.
  - `?format=json` → `[{ip, host_count, category, expires}]` for weighting +
    report. **`corroborated-block` REQUIRES this JSON feed** (the bare feed carries
    no `host_count`; hub-plan-review Major #9). Bounded by a **max feed size**; if
    truncated, a response header (`X-Swarm-Truncated`) + log signals it (silent
    lexical truncation would drop the same high-address offenders every time;
    Major #8). Cursor pagination is a fast-follow.
- **Scheduled prune** (Worker cron, daily): delete `offenders` past `expires` AND
  `sightings` past `now - SWARM_TTL`. Prune failures are surfaced (logged/metric).

`SWARM_TTL` is **hub-authoritative** (a Worker config/binding). Hosts don't set
expiry.

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

### 4.4 Auth — three tokens (write / read / enroll)

A single shared bearer would be both a poisoning key and a recon key. Phase 1
splits credentials by capability:

- **Write token** (`SWARM_WRITE_TOKEN_FILE`, 0400) — on publishing boxes; gates
  `POST /contribute`.
- **Read token** (`SWARM_READ_TOKEN_FILE`, 0400) — on all consumers; gates
  `GET /feed`.
- **Enroll token** (`SWARM_ENROLL_TOKEN`, operator-held, NOT deployed to boxes)
  — gates `POST /register`, which adds a `host_id` to the registry (§6). Because
  only *registered* host_ids count toward `host_count`, and enrolling requires
  this separate token, **a leaked write token cannot forge corroboration** (it can
  add sightings under invented host_ids, but they never count). This is the fix
  for the plan-review forgeable-host_id blocker.
- A compromised *consumer* (read-only) cannot poison the hub. A leaked *write*
  token can add sightings for real IPs (bounded by the connecting-IP + global rate
  limits) but cannot inflate `host_count` past real corroboration, cannot enroll,
  and cannot read the offender list. **Stated honestly: rotation, not TTL, stops
  an active attacker; full per-host request signing is Phase 2.**
- All sent via `curl -K` (never argv).

### 4.5 Consume-side fleet allowlist (canary) — NEW, mandatory

A `SWARM_ALLOW_FILE` (operator's known-good customers / API partners / egress
IPs — the legit IPs that are NOT in the generic never-block set). Consulted on
**both** publish (don't emit) and consume (never swarm-block, never swarm-boost).
This is the direct defense against Blocker #2: a single host's erroneous perm-ban
of a known-good IP cannot tip that IP on any other box. It is the Phase-1 stand-in
for Phase 2's global canary set.

## 5. Data model (D1)

```sql
-- offenders: NO cached host_count (derived at read time from sightings, so the
-- cross-request write race can't corrupt it). Holds only decay + metadata.
CREATE TABLE offenders (
  ip         TEXT PRIMARY KEY,          -- IP or CIDR
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  last_host  TEXT,
  category   TEXT,
  expires    INTEGER NOT NULL           -- last_seen + SWARM_TTL
);
CREATE INDEX ix_offenders_expires ON offenders(expires);

CREATE TABLE sightings (
  ip        TEXT NOT NULL,
  host      TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (ip, host)
);
CREATE INDEX ix_sightings_seen ON sightings(last_seen);   -- for prune

-- registry: only these host_ids count toward host_count (forgery defense).
CREATE TABLE hosts (
  host        TEXT PRIMARY KEY,
  enrolled_at INTEGER NOT NULL,
  label       TEXT
);
```

`host_count` is computed at read time as
`COUNT(DISTINCT s.host) FROM sightings s JOIN hosts h ON s.host=h.host
 WHERE s.ip=? AND s.last_seen > now-SWARM_TTL`. `sightings` + `hosts` are the
contributor-identity + corroboration substrate Phase 2's trust layer extends.

## 6. Host id + registry

Opaque, stable, random per box (`$STATE_DIR/swarm.host_id`), NOT hostname/IP.
A box is **enrolled once** by the operator (`swatter swarm enroll`, which
`POST /register`s with the operator-held **enroll token**, §4.4) — a deliberate
step, not auto-on-first-contribute (auto-enroll would reopen the forgery hole).
Only enrolled host_ids count toward `host_count`, so a leaked write token cannot
manufacture corroboration. host_id seeds Phase-2 contributor identity (Phase 2
binds it to a signing key).

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

## 8. Action model (`SWARM_ACTION`) — CONFIRMED (operator sign-off 2026-07-03: ship both)

**`boost` default + opt-in `corroborated-block` — both ship in Phase 1.**

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
| `SWARM_ENROLL_TOKEN_FILE` | `""` | 0400; ONLY on the box that runs `swatter swarm enroll` (operator-held; not fleet-wide) |
| `SWARM_PUBLISH` | `true` | contribute this box's offenders |
| `SWARM_ACTION` | `boost` | `boost` \| `corroborated-block` |
| `SWARM_MIN_CORROBORATION` | `2` | min distinct hosts for a proactive block |
| `SWARM_BASE_SCORE` | `70` | base intel score a swarm hit returns (scaled by `host_count` to ≤100; folds via the standard `W_REPUTATION` path) |
| `SWARM_ALLOW_FILE` | `/etc/swatter/swarm.allow.cidr` | fleet canary (never swarm-acted) |
| `SWARM_MAX_AGE_DAYS` | `3` | swarm feed staleness cutoff |

(`SWARM_TTL` is hub-side, not here.)

## 10. Packaging — self-hostable `hub/`

New `hub/`: `worker.js` (or split modules), `wrangler.toml` (D1 binding + cron
trigger + `[[ratelimits]]` binding), `schema.sql`, `README.md` (deploy in minutes:
create D1, apply schema, `wrangler secret put` the write + read + enroll tokens,
`wrangler deploy`, point boxes at the URL). PH is the first tenant (cds1). Adding a
box is **two steps**: drop the URL + write/read tokens in its conf, then
`swatter swarm enroll` once (operator runs it with the enroll token) so the box's
`host_id` counts toward corroboration. (Not fully zero-config: the deliberate
enroll step is what makes the host registry a forgery defense — §6.)

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

## 15. Decisions (operator sign-off status)

1. **Action model = `boost` default + opt-in `corroborated-block`, both shipping
   in Phase 1** — **CONFIRMED 2026-07-03.**
2. **Hub store = D1** (over KV) — default; not objected.
3. **Dual read/write tokens** (not one shared bearer) — default; not objected.
4. **Mandatory consume-side `SWARM_ALLOW_FILE`** as the Phase-1 canary — default;
   not objected.
5. **`SWARM_MIN_CORROBORATION=2`** — default (2 suits a small/growing fleet; at
   N=1 box `corroborated-block` simply never fires until a 2nd box confirms, which
   is the correct behavior). Revisit if the fleet grows large.
6. **Per-token host registry** gates `host_count` (only enrolled host_ids count) —
   **CONFIRMED 2026-07-03** (hub-plan-review decision A). Closes the forgeable-
   host_id hole: a leaked write token can't manufacture corroboration.
7. **Hub accepts IP or CIDR** (parity with the bash validator; reject `/0` +
   unspecified) — **CONFIRMED 2026-07-03** (hub-plan-review decision B). A host's
   CIDR perm-ban is shared, not silently dropped.
8. **`host_count` derived at feed-read time** (not cached on write) — removes the
   cross-request write race (hub-plan-review Blocker #2).

## 16. Open questions for review

- Category taxonomy: reuse `decisive_rule`, or a coarser shared set?
- Multi-hub consumption (personal + partner) — a stepping stone to Phase 2, or
  out of scope now?

## 17. Review resolution

**Design review (`…-design-review-grok.md`, 2026-07-03)** — all four Blockers +
Majors addressed in spec v2: feed format (§4.2 bare-IP), poison propagation (§4.5
fleet allowlist + §8 corroboration + §7 corrected claims), `SWARM_ACTION` gate
path (§8 via `_swatter_execute_block`), pre-block/safety tradeoff (§1/§8),
dual tokens (§4.4), prune/staleness (§4.2/§4.3/§12), flatfile-safe cursor (§4.1),
disable/purge (§13), IPv6, softened Phase-2 claim (§14).

**Hub plan review (`plans/…-swatter-swarm-hub-review-grok.md`, 2026-07-03)** —
folded into spec v3 (this doc): `host_count` derived at read time (Blocker #2 →
§4.2/§5), per-token host registry vs forgeable host_id (Blocker #3 → §4.4/§6),
empty-feed-clears-vs-failure-keeps (Blocker #4 → §4.2/§4.3), IP-or-CIDR parity
(Major #7 → §4.2), connecting-IP/global rate limit not host_id (Major #6 → §4.2),
dual-fetch requirement for corroborated-block (Major #9 → §4.2), payload cap +
truncation signalling (Majors #8/#10 → §4.2). The **hub implementation plan
(`plans/…-swatter-swarm-hub.md`) must be rewritten to v2** against this corrected
design + the current `cloudflareTest()`/Vitest-4.1 harness before execution.
