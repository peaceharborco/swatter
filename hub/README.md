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
  (required for `corroborated-block`); `X-Swarm-Truncated: true` if capped
- `GET /health` — `{ok:true}`

## Limits (tune in `wrangler.toml`)

All abuse caps live in `wrangler.toml`, so a self-hosted hub is bounded out of
the box:

- **Per-request** — bodies over 1 MiB and `/contribute` batches over
  `MAX_ENTRIES` (`[vars]`, 1000) are refused with **413**. The host CLI never
  sends more than the hub accepts.
- **Feed size** — `/feed` returns at most `FEED_MAX` (`[vars]`, 50k) rows
  (`?limit=N` for fewer) and sets `X-Swarm-Truncated: true` when capped.
- **Rate limits** (`[[ratelimits]]`) — `/contribute` and `/purge` share a
  per-connecting-IP write budget (120/min) plus a global write budget
  (6000/min, bounds a distributed leaked-token holder); `/register` is tight
  (20/min per IP) because enrollment is rare. Over budget → **429**.

A 413/429 never breaks a box: publish is fail-soft — the cursor is kept and the
whole delta is re-sent on the next scan (hub writes are upserts, so re-sends
are harmless).

## Maintenance

- Daily cron (04:17 UTC) prunes expired entries; `SWARM_TTL` (`[vars]`, 7d) is
  hub-authoritative. Rotate a leaked shared secret via `wrangler secret put` +
  redeploy; rotate a per-host token with `swatter swarm enroll --rotate` on that
  box.
