# Swarm per-host tokens — design

## Problem
`hub/src/index.js` authenticates `/contribute` and `/purge` with a single shared
`SWARM_WRITE_TOKEN`, and trusts `host_id` from the request BODY (`index.js`
handleContribute/handlePurge). So any write-token holder can publish AS ANY
enrolled `host_id` (fake corroboration toward `SWARM_MIN_CORROBORATION` → fleet-wide
bans of a victim) or `/purge` any host. Enrollment (`/register`, gated by the
operator-held `SWARM_ENROLL_TOKEN`) decides WHICH host_ids count, but not WHO may
write as them.

## Goal
Bind write identity to a per-host credential: a leaked credential impersonates only
ONE host, not the fleet. No shared write token that grants fleet-wide write.

## Design

### Hub
- **Migration 0002:** `ALTER TABLE hosts ADD COLUMN token_hash TEXT;` (nullable, so
  existing rows are "not yet migrated").
- **On `/register`** (still gated by `SWARM_ENROLL_TOKEN`): generate a random token
  (32 bytes → 64 hex via `crypto.getRandomValues`), store its SHA-256 hex in
  `hosts.token_hash` (upsert — re-enroll ROTATES the token), and return the
  PLAINTEXT token once: `{ enrolled: host, token: "<hex>" }`.
- **New `hostForToken(env, presented)`**: `sha256hex(presented)` → `SELECT host FROM
  hosts WHERE token_hash=?1`. Returns the host_id or null. (The lookup is by hash;
  the plaintext never hits the DB. No per-byte compare needed — a hash preimage is
  the secret.)
- **`/contribute` and `/purge` auth**, in order:
  1. **Per-host token (preferred):** `host = await hostForToken(env, bearer)`. If
     non-null → authenticated host = `host`; IGNORE body `host_id` entirely (use the
     token's host). This is the only path once a host is migrated.
  2. **Legacy compat (transition only):** if per-host lookup misses AND
     `checkAuth(request, env.SWARM_WRITE_TOKEN)` passes AND the body `host_id`'s row
     has `token_hash IS NULL` (not yet migrated) → allow with body `host_id`. A host
     that HAS a token_hash can NEVER be written via the legacy path (closes the
     impersonation for migrated hosts).
  3. Else → 401.
- `/register` and `/feed` unchanged (enroll token; read token).

### Host (lib/swarm.sh)
- **`SWARM_HOST_TOKEN_FILE`** (default `${STATE_DIR}/swarm.host_token`, 0600).
- **Enroll:** parse `token` from the `/register` response; write it to
  `SWARM_HOST_TOKEN_FILE` (0600). Print a reminder that the per-host token now
  authenticates this box.
- **Publish + purge:** authenticate with `SWARM_HOST_TOKEN_FILE` if it exists and is
  non-empty; else fall back to `SWARM_WRITE_TOKEN_FILE` (legacy, until re-enrolled).
  Body `host_id` is still sent (hub ignores it on the per-host path; still used on
  the legacy path).

### Migration / rollout
1. `wrangler deploy` the hub (compat window active: legacy write token still works
   for un-migrated hosts, so the prod box keeps publishing).
2. Surgical-scp the host `lib/swarm.sh`.
3. `swatter swarm enroll` on prod → issues + stores the per-host token; subsequent
   publishes use it. The box is now migrated (has token_hash) → legacy path closed
   for it.
4. Once every host is migrated, rotate/remove `SWARM_WRITE_TOKEN` to fully retire
   the shared write path. (Follow-up, not blocking.)

## Revisions (Grok design review, 2026-07-17)
- **Enroll no longer silently rotates (Blocker #1).** `/register` issues a token
  only when the host has none (`token_hash IS NULL`) OR the request sets
  `rotate:true`. A plain re-enroll of an already-tokened host updates the label only
  and returns NO token (`rotated:false`) — so an enroll-token holder can't silently
  take over / lock out an existing box. `swatter swarm enroll --rotate` sets the flag
  (used for recovery / deliberate rotation). Rate-limit `/register` (a new limiter).
- **Honest residual:** the enroll token now mints write identity, so an enroll-token
  leak = forge corroboration by minting N hosts AND rotate-takeover of any host
  (with `--rotate`). It is the crown jewel — operator-held, off-box, rate-limited.
- **Lockout recovery (Blocker #2).** Host enroll FAILS hard unless the 200 response
  carries a non-empty `token` it can persist (atomic write, 0600); it never prints
  the token. If the hub already tokened the host and the box lost its file, a plain
  enroll returns no token → the host errors with "re-run: swatter swarm enroll
  --rotate". Recovery = re-enroll `--rotate` from a machine holding the enroll token.
- **UNIQUE index (Major #4):** migration adds `CREATE UNIQUE INDEX ix_hosts_token_hash
  ON hosts(token_hash)` (SQLite/D1 allows multiple NULLs, so unmigrated rows are fine).
- **Legacy closure (Major #3):** optional `SWARM_LEGACY_WRITE_UNTIL` (unix ts) — once
  past, the legacy write-token path is refused entirely (hard cutover). Rollout
  checklist: after migrating, `SELECT host FROM hosts WHERE token_hash IS NULL` must
  be empty before retiring the shared write token.
- **Normative auth order (Major #5):** rate-limit → readBody → auth. (1) `host =
  hostForToken(bearer)` → identity=host, ignore body host_id. (2) else
  `checkAuth(WRITE)` and not past `LEGACY_WRITE_UNTIL`: legacy with body host_id, but
  only if that host's row has `token_hash IS NULL` (a migrated host → 401); a host
  with no row falls through to the existing `enrolled:false` write-gate (unchanged).
  (3) else 401. Purge: identical order; per-host path ignores body host_id.

## Edge cases
- Re-enroll rotates the token (upsert token_hash); the old token stops working
  (only one hash stored). The host overwrites its token file from the response.
- A leaked per-host token → impersonates only that host; operator re-enrolls that
  host to rotate.
- Enroll token leak → attacker can enroll new hosts (pre-existing risk; separate,
  rate-limit is a known follow-up) but each still gets a distinct token; they still
  can't write as an EXISTING migrated host.
- `token_hash` never leaves the hub; the plaintext is returned once and stored 0600
  on the host.

## Operator rollout runbook
1. **Apply the migration, THEN deploy the hub** (compat window open). `wrangler
   deploy` does NOT auto-apply D1 migrations, and `/contribute` calls `hostForToken`
   (reads `token_hash`) on every request — deploying first would 500 every write:
   ```
   cd hub
   wrangler d1 migrations apply swatter-swarm --remote   # adds token_hash + UNIQUE index
   wrangler deploy
   ```
   Confirm `token_hash` exists before cutting traffic. The prod box keeps publishing
   via the shared write token until step 3 (its host row still has `token_hash IS NULL`).
2. **Ship the host code**: surgical-scp `lib/swarm.sh` + `lib/common.sh` to
   `/usr/local/lib/swatter/`.
3. **Enroll each host** (from a box holding the enroll token):
   `swatter swarm enroll` — issues + stores the per-host token; publishes now use it.
   `swatter swarm status` shows `host token: present`. Recovery if the token file is
   lost: `swatter swarm enroll --rotate`.
4. **Verify + hard-retire** the shared token once every host is migrated: on the hub,
   `SELECT host FROM hosts WHERE token_hash IS NULL` must be empty, then set
   `SWARM_LEGACY_WRITE_UNTIL` (a recent unix ts) as a Worker var and redeploy;
   optionally rotate/remove `SWARM_WRITE_TOKEN`.
   Reverse order (host code before hub) is unsupported — enroll would get no token
   and fail closed.

## Tests
- Hub: register returns a token; contribute with the per-host token works and is
  bound to that host regardless of body host_id; contribute as a MIGRATED host via
  the legacy write token is REJECTED; contribute for an un-migrated host via legacy
  token still works; wrong/absent token → 401; purge same.
- Host: enroll stores the token file 0600; publish/purge prefer it, fall back to the
  write token when absent.
