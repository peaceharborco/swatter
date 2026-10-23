# Swatter Swarm Hub

A self-hosted Cloudflare Worker + D1 that aggregates YOUR fleet's confirmed
offenders and serves the merged, decaying blocklist back. One hub per operator;
your boxes only talk to your hub.

## Deploy (~5 min)

```bash
cd hub
npm install
wrangler d1 create swatter-swarm            # copy database_id into wrangler.toml
wrangler d1 migrations apply swatter-swarm --remote

# three secrets — generate long random strings
wrangler secret put SWARM_WRITE_TOKEN       # publishers (POST /contribute)
wrangler secret put SWARM_READ_TOKEN        # consumers  (GET /feed)
wrangler secret put SWARM_ENROLL_TOKEN      # operator only (POST /register)

wrangler deploy
```

The printed URL is your `SWARM_HUB_URL`.

## Enroll each box (once) — per-host tokens

Each box gets its OWN write token, issued by the hub at enrollment and bound to its
`host_id`, so a leaked credential impersonates only that ONE box, not the fleet.
On each box, after setting `SWARM_HUB_URL` + the read token (and the enroll token
ONLY on a box you're enrolling):

```bash
swatter swarm enroll            # POSTs /register; stores the per-host token 0600
swatter swarm enroll --rotate   # reissue if the box lost its token (recovery)
```

The host CLI persists the token file and authenticates every publish/purge with it.
Do NOT enroll via a bare `curl` — the one-time token is returned in the response and
must be stored 0600 on the box; printing it to a terminal (scrollback) or failing to
persist it leaves the box locked out (the hub has a `token_hash`, the box has no
token → 401 on publish; recover with `swatter swarm enroll --rotate`).

**Migration from the shared write token:** hosts enrolled before per-host tokens
(`token_hash IS NULL`) keep writing via `SWARM_WRITE_TOKEN` until they re-enroll.
A migrated host can NEVER be written via the shared token. Once every host is
migrated (`SELECT host FROM hosts WHERE token_hash IS NULL` is empty), set the
Worker var `SWARM_LEGACY_WRITE_UNTIL` (a recent unix ts) to hard-retire the shared
write path, and rotate/remove `SWARM_WRITE_TOKEN`.

## Contract

- `POST /contribute` (write) — `{entries:[{ip,category?}]}` (ip = IP or CIDR). The
  writer's identity is the per-host token; a body `host_id` is IGNORED for a
  token-authenticated host (only honored on the legacy shared-token path for an
  un-migrated host).
- `POST /register` (enroll) — `{host_id, label?, rotate?}` → `{enrolled, rotated,
  token?}`. `token` is returned ONCE, on first enroll or `rotate:true`.
- `POST /purge` (write) — `{}` — removes ALL of the authenticated host's sightings +
  any offenders left uncorroborated (bad-publish recovery; host stays enrolled). The
  per-host token's host is purged; body `host_id` is ignored. Host CLI:
  `swatter swarm purge --yes`.
- `GET /feed` (read) — bare `ip`/`cidr` per line; `?format=json` for `host_count`
  (required for `corroborated-block`); `X-Swarm-Truncated: true` if capped.
  Rows are ordered by corroboration (`host_count` desc, then most recent), so
  when the feed is truncated it is the least-trusted rows that drop.
- `GET /health` — `{ok:true}`

**What the hub refuses** (counted in `rejected`, never stored): anything that is
not a syntactically valid IP/CIDR; `/0` and the unspecified address; private,
loopback, link-local, CGNAT, multicast and reserved space — and any prefix that
merely *overlaps* one of those; any IPv4 prefix shorter than `/24` or IPv6
prefix shorter than `/64`. Every row the hub serves is a firewall deny on every
consumer, so one compromised or buggy box must not be able to hand the fleet its
own LAN or an eighth of the internet. Documentation/TEST-NET ranges are allowed
(never routed, harmless). The host CLI applies the same floor independently
when it consumes the feed.

## Limits (tune in `wrangler.toml`)

All abuse caps live in `wrangler.toml`, so a self-hosted hub is bounded out of
the box:

- **Per-request** — bodies over 1 MiB and `/contribute` batches over
  `MAX_ENTRIES` (`[vars]`, 1000) are refused with **413**. The host CLI never
  sends more than the hub accepts.
- **Feed size** — `/feed` returns at most `FEED_MAX` (`[vars]`, 50k) rows
  (`?limit=N` for fewer) and sets `X-Swarm-Truncated: true` when capped.
- **Per-host quota** — one host may hold at most `HOST_MAX` (`[vars]`, 10,000)
  live sightings inside `SWARM_TTL`; over quota `/contribute` answers **429**
  and the box keeps its cursor. Without this one token could write
  `MAX_ENTRIES` × 120/min distinct rows and push every other host out of a
  truncated feed.
- **Rate limits** (`[[ratelimits]]`) — `/contribute` and `/purge` share a
  per-connecting-IP write budget (120/min); authenticated `/contribute` calls
  also draw on a global write budget (6000/min, bounds a distributed
  leaked-token holder — charged only after the token checks out, so an
  unauthenticated flood cannot drain it); `/register` is tight (20/min per IP)
  because enrollment is rare. Over budget → **429**.
- **Config is fail-loud** — every numeric `[vars]` value must be a positive
  integer; a bad one makes every request a JSON **500** rather than an open gate
  or an empty feed (consumers keep their last-good list on any non-200).

A 413/429 never breaks a box: publish is fail-soft — the cursor is kept and the
whole delta is re-sent on the next scan (hub writes are upserts, so re-sends
are harmless).

## Upgrading

Migrations are additive; apply them before deploying the code that uses them
(the same two commands as the first deploy, without the `d1 create` and the
secrets). Migration 0003 adds the `sightings(host, last_seen)` index the
per-host quota and `/purge` use.

## Maintenance

- Daily cron (04:17 UTC) prunes expired entries; `SWARM_TTL` (`[vars]`, 7d) is
  hub-authoritative. Rotate a leaked shared secret via `wrangler secret put` +
  redeploy; rotate a per-host token with `swatter swarm enroll --rotate` on that
  box.
