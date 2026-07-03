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

## Enroll each box (once)

Only ENROLLED host_ids count toward corroboration, so a leaked write token can't
fake a fleet. On each box, after setting `SWARM_HUB_URL` + the write/read tokens:

```bash
swatter swarm enroll            # POSTs /register with the enroll token
```

## Contract

- `POST /contribute` (write) — `{host_id, entries:[{ip,category?}]}` (ip = IP or CIDR)
- `POST /register` (enroll) — `{host_id, label?}`
- `GET /feed` (read) — bare `ip`/`cidr` per line; `?format=json` for `host_count`
  (required for `corroborated-block`); `X-Swarm-Truncated: true` if capped
- `GET /health` — `{ok:true}`

## Maintenance

- Daily cron (04:17 UTC) prunes expired entries; `SWARM_TTL` (`[vars]`, 7d) is
  hub-authoritative. Rotate a leaked token via `wrangler secret put` + redeploy.
