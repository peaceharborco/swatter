# Swatter Swarm Hub Implementation Plan

> **⚠️ DO NOT EXECUTE — UNDER REVISION.** The Grok two-model review
> (`…-swatter-swarm-hub-review-grok.md`, 2026-07-03) returned *not safe to
> execute as-is*: outdated vitest API, cross-request `host_count` race, forgeable
> `host_id` corroboration, empty-feed/decay contract gap, and a non-executable
> rate-limit task. Two design decisions (host_id trust, CIDR policy) are pending
> operator sign-off. This plan will be revised to v2 before any task runs.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the self-hostable Swatter Swarm hub — a Cloudflare Worker + D1 that ingests each fleet host's confirmed offenders and serves the merged, decaying blocklist back.

**Architecture:** A single Worker with a `fetch` router (`POST /contribute`, `GET /feed`, `GET /health`) and a `scheduled` handler (daily prune). State lives in D1 (SQLite): an `offenders` table (merged, with `host_count` corroboration + `expires` decay) and a `sightings` table (per-`(ip,host)`, the exact source of `host_count`). Two separate bearer tokens gate write vs. read. All mutating work per IP runs in one atomic D1 `batch()` so concurrent publishers can't corrupt `host_count`.

**Tech Stack:** Cloudflare Workers (JS, ES modules), D1, Wrangler, Vitest with `@cloudflare/vitest-pool-workers` (runs tests inside the real Workers runtime with a live ephemeral D1).

## Global Constraints

- **This is subsystem 1 of 2.** It owns the HTTP contract that the host-side plan (`…-swatter-swarm-host.md`) consumes. The contract below is FROZEN by this plan; do not change endpoint shapes/field names without updating the host plan.
- **Feed default format is bare IP per line** (one `ip`, no other fields) — the host validates it with `swatter_cidr_list_ok`, which strips all whitespace, so a tab/space/multi-field line would be rejected. Rich metadata is `GET /feed?format=json` only.
- **Two tokens:** `SWARM_WRITE_TOKEN` gates `POST /contribute`; `SWARM_READ_TOKEN` gates `GET /feed`. A read token must NOT be accepted on `/contribute`. Both are Worker secrets (`wrangler secret put`), never in `wrangler.toml`.
- **`SWARM_TTL` is hub-authoritative** (a `wrangler.toml` `[vars]` value, seconds; default `604800` = 7 days). Hosts never set expiry.
- **Every IP is re-validated server-side** and unsafe targets (`/0`, `0.0.0.0`, `::`) are rejected on ingest — never trust the client.
- **`host_count` = `COUNT(DISTINCT host)` over `sightings` within `SWARM_TTL`** — recomputed inside the same atomic batch as the sighting upsert.
- IPv4 and IPv6 both supported end-to-end.
- Response bodies are `text/plain` for the bare feed and `application/json` elsewhere. Auth failures return `401`; malformed input `400`; rate-limited `429`.

---

### Task 1: Project scaffold + health endpoint (proves the test harness)

**Files:**
- Create: `hub/package.json`
- Create: `hub/wrangler.toml`
- Create: `hub/vitest.config.js`
- Create: `hub/schema.sql`
- Create: `hub/src/index.js`
- Test: `hub/test/health.test.js`

**Interfaces:**
- Produces: the Worker default export `{ fetch(request, env, ctx), scheduled(event, env, ctx) }`; `GET /health` → `200` `{"ok":true}`.

- [ ] **Step 1: Write `hub/package.json`**

```json
{
  "name": "swatter-swarm-hub",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "vitest run",
    "deploy": "wrangler deploy"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.5.0",
    "vitest": "^2.0.0",
    "wrangler": "^3.80.0"
  }
}
```

- [ ] **Step 2: Write `hub/schema.sql`** (the full schema; applied to the test D1 by vitest config in Step 4 and to prod in Task 9)

```sql
CREATE TABLE IF NOT EXISTS offenders (
  ip         TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  host_count INTEGER NOT NULL DEFAULT 1,
  last_host  TEXT,
  category   TEXT,
  expires    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_offenders_expires ON offenders(expires);

CREATE TABLE IF NOT EXISTS sightings (
  ip        TEXT NOT NULL,
  host      TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (ip, host)
);
CREATE INDEX IF NOT EXISTS ix_sightings_seen ON sightings(last_seen);
```

- [ ] **Step 3: Write `hub/wrangler.toml`**

```toml
name = "swatter-swarm-hub"
main = "src/index.js"
compatibility_date = "2024-11-01"

[vars]
SWARM_TTL = "604800"        # 7 days, hub-authoritative
FEED_MAX = "50000"          # max rows a single /feed page returns

[[d1_databases]]
binding = "DB"
database_name = "swatter-swarm"
database_id = "REPLACE_AFTER_wrangler_d1_create"   # set in Task 9

[triggers]
crons = ["17 4 * * *"]      # daily prune, 04:17 UTC

# Secrets (NOT here): SWARM_WRITE_TOKEN, SWARM_READ_TOKEN via `wrangler secret put`
```

- [ ] **Step 4: Write `hub/vitest.config.js`** (runs tests in the Workers runtime with an ephemeral D1 seeded from `schema.sql`)

```js
import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { readFileSync } from "node:fs";

const schema = readFileSync(new URL("./schema.sql", import.meta.url), "utf8");

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          // apply schema to the test D1 before each test file
          d1Databases: ["DB"],
          bindings: { SWARM_WRITE_TOKEN: "test-write", SWARM_READ_TOKEN: "test-read" },
        },
      },
    },
    setupFiles: ["./test/setup.js"],
  },
  define: { __SCHEMA__: JSON.stringify(schema) },
});
```

- [ ] **Step 5: Write `hub/test/setup.js`** (seed schema into the ephemeral D1 before each test)

```js
import { env } from "cloudflare:test";
import { beforeEach } from "vitest";

beforeEach(async () => {
  await env.DB.exec("DROP TABLE IF EXISTS offenders");
  await env.DB.exec("DROP TABLE IF EXISTS sightings");
  for (const stmt of __SCHEMA__.split(";").map(s => s.trim()).filter(Boolean)) {
    await env.DB.exec(stmt.replace(/\s+/g, " "));
  }
});
```

- [ ] **Step 6: Write the failing health test `hub/test/health.test.js`**

```js
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index.js";

describe("health", () => {
  it("GET /health returns 200 ok", async () => {
    const req = new Request("https://hub/health");
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});
```

- [ ] **Step 7: Run the test — verify it fails**

Run: `cd hub && npm install && npm test`
Expected: FAIL — `../src/index.js` does not exist / no default export.

- [ ] **Step 8: Write minimal `hub/src/index.js`**

```js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ ok: true });
    }
    return new Response("not found", { status: 404 });
  },
  async scheduled(event, env, ctx) {
    // prune wired in Task 8
  },
};
```

- [ ] **Step 9: Run the test — verify it passes**

Run: `cd hub && npm test`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add hub/
git commit -m "feat(swarm-hub): scaffold Worker + D1 test harness and /health"
```

---

### Task 2: Server-side IP validation + unsafe-target rejection

**Files:**
- Create: `hub/src/validate.js`
- Test: `hub/test/validate.test.js`

**Interfaces:**
- Produces: `isValidIp(s): boolean` (IPv4 octets 0–255; IPv6 structural incl. `::` and embedded-v4; no prefix — the hub stores single IPs, not CIDRs, so a `/n` is rejected); `isUnsafeTarget(s): boolean` (`0.0.0.0`, `::`, `0:0:0:0:0:0:0:0`). Mirrors Swatter's `swatter_is_valid_ip_or_cidr` intent but IP-only.

- [ ] **Step 1: Write the failing test `hub/test/validate.test.js`**

```js
import { describe, it, expect } from "vitest";
import { isValidIp, isUnsafeTarget } from "../src/validate.js";

describe("isValidIp", () => {
  it.each(["1.2.3.4", "203.0.113.9", "::1", "2001:db8::1", "::ffff:192.0.2.1"])(
    "accepts %s", (ip) => expect(isValidIp(ip)).toBe(true));
  it.each(["999.999.999.999", "256.0.0.1", "1.2.3", "deadbeef", "::::",
           "1.2.3.4/24", "", "1.2.3.4 ", "evil\"x"])(
    "rejects %s", (ip) => expect(isValidIp(ip)).toBe(false));
});

describe("isUnsafeTarget", () => {
  it.each(["0.0.0.0", "::", "0:0:0:0:0:0:0:0"])(
    "flags %s unsafe", (ip) => expect(isUnsafeTarget(ip)).toBe(true));
  it.each(["1.2.3.4", "2001:db8::1"])(
    "allows %s", (ip) => expect(isUnsafeTarget(ip)).toBe(false));
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- validate`
Expected: FAIL — `../src/validate.js` missing.

- [ ] **Step 3: Write `hub/src/validate.js`**

```js
// IPv4: four octets 0-255, no leading zeros, no prefix.
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isValidV6(a) {
  a = a.toLowerCase();
  let v4tail = 0;
  if (a.includes(".")) {
    const tail = a.slice(a.lastIndexOf(":") + 1);
    if (!a.includes(":") || !V4.test(tail)) return false;
    a = a.slice(0, a.lastIndexOf(":")) + ":0";
    v4tail = 2;
  }
  if (!/^[0-9a-f:]+$/.test(a)) return false;
  let L, R;
  if (a.includes("::")) {
    if (a.includes(":::") || a.slice(a.indexOf("::") + 2).includes("::")) return false;
    L = a.slice(0, a.indexOf("::"));
    R = a.slice(a.indexOf("::") + 2);
  } else {
    if (a.startsWith(":") || a.endsWith(":")) return false;
    L = a; R = "";
  }
  const groups = [...L.split(":").filter(Boolean), ...R.split(":").filter(Boolean)];
  for (const g of groups) if (!/^[0-9a-f]{1,4}$/.test(g)) return false;
  const n = groups.length + v4tail;
  return a.includes("::") ? n <= 7 : n === 8;
}

export function isValidIp(s) {
  if (typeof s !== "string" || s.length === 0 || s.includes("/")) return false;
  return s.includes(":") ? isValidV6(s) : V4.test(s);
}

export function isUnsafeTarget(s) {
  return s === "0.0.0.0" || s === "::" || s === "0:0:0:0:0:0:0:0";
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cd hub && npm test -- validate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/validate.js hub/test/validate.test.js
git commit -m "feat(swarm-hub): server-side IP validation + unsafe-target rejection"
```

---

### Task 3: Auth — separate write/read token checks

**Files:**
- Create: `hub/src/auth.js`
- Test: `hub/test/auth.test.js`

**Interfaces:**
- Produces: `checkAuth(request, expectedToken): boolean` — constant-time-ish compare of the `Authorization: Bearer <token>` header against `expectedToken`; false on missing/malformed/mismatch.

- [ ] **Step 1: Write the failing test `hub/test/auth.test.js`**

```js
import { describe, it, expect } from "vitest";
import { checkAuth } from "../src/auth.js";

const reqWith = (h) => new Request("https://hub/x", { headers: h ? { authorization: h } : {} });

describe("checkAuth", () => {
  it("accepts the exact bearer", () => expect(checkAuth(reqWith("Bearer sekret"), "sekret")).toBe(true));
  it("rejects a wrong token", () => expect(checkAuth(reqWith("Bearer nope"), "sekret")).toBe(false));
  it("rejects a missing header", () => expect(checkAuth(reqWith(null), "sekret")).toBe(false));
  it("rejects a non-bearer scheme", () => expect(checkAuth(reqWith("Basic sekret"), "sekret")).toBe(false));
  it("rejects when expected is empty", () => expect(checkAuth(reqWith("Bearer "), "")).toBe(false));
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- auth`
Expected: FAIL — `../src/auth.js` missing.

- [ ] **Step 3: Write `hub/src/auth.js`**

```js
export function checkAuth(request, expectedToken) {
  if (!expectedToken) return false;
  const h = request.headers.get("authorization") || "";
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return false;
  const got = m[1];
  if (got.length !== expectedToken.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expectedToken.charCodeAt(i);
  return diff === 0;
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cd hub && npm test -- auth`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/auth.js hub/test/auth.test.js
git commit -m "feat(swarm-hub): dual write/read bearer-token auth"
```

---

### Task 4: DB — atomic contribute (sighting upsert + host_count recompute + offender upsert)

**Files:**
- Create: `hub/src/db.js`
- Test: `hub/test/db-contribute.test.js`

**Interfaces:**
- Consumes: `env.DB` (D1), `env.SWARM_TTL`.
- Produces: `contributeOne(env, {ip, host, category, now}): Promise<{host_count}>` — one atomic `env.DB.batch()`: upsert `sightings`, recompute `host_count = COUNT(DISTINCT host) WHERE ip AND last_seen > now-TTL`, upsert `offenders` with that count + `expires = now + TTL`. Returns the new `host_count`.

- [ ] **Step 1: Write the failing test `hub/test/db-contribute.test.js`**

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { contributeOne } from "../src/db.js";

const now = 1_800_000_000;

describe("contributeOne", () => {
  it("first report sets host_count=1 and expiry", async () => {
    const r = await contributeOne(env, { ip: "1.2.3.4", host: "hostA", category: "scan", now });
    expect(r.host_count).toBe(1);
    const row = await env.DB.prepare("SELECT * FROM offenders WHERE ip=?").bind("1.2.3.4").first();
    expect(row.host_count).toBe(1);
    expect(row.expires).toBe(now + Number(env.SWARM_TTL));
    expect(row.last_host).toBe("hostA");
  });

  it("same ip from a SECOND host raises host_count to 2", async () => {
    await contributeOne(env, { ip: "1.2.3.4", host: "hostA", category: "scan", now });
    const r = await contributeOne(env, { ip: "1.2.3.4", host: "hostB", category: "scan", now: now + 10 });
    expect(r.host_count).toBe(2);
  });

  it("same ip from the SAME host stays host_count=1 and bumps last_seen", async () => {
    await contributeOne(env, { ip: "1.2.3.4", host: "hostA", category: "scan", now });
    const r = await contributeOne(env, { ip: "1.2.3.4", host: "hostA", category: "scan", now: now + 10 });
    expect(r.host_count).toBe(1);
    const row = await env.DB.prepare("SELECT last_seen, expires FROM offenders WHERE ip=?").bind("1.2.3.4").first();
    expect(row.last_seen).toBe(now + 10);
    expect(row.expires).toBe(now + 10 + Number(env.SWARM_TTL));
  });

  it("a sighting older than TTL does not count toward host_count", async () => {
    const ttl = Number(env.SWARM_TTL);
    await contributeOne(env, { ip: "9.9.9.9", host: "stale", category: "scan", now: now - ttl - 100 });
    const r = await contributeOne(env, { ip: "9.9.9.9", host: "fresh", category: "scan", now });
    expect(r.host_count).toBe(1); // only 'fresh' is within TTL
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- db-contribute`
Expected: FAIL — `contributeOne` not exported.

- [ ] **Step 3: Write `hub/src/db.js` (`contributeOne`)**

```js
export async function contributeOne(env, { ip, host, category, now }) {
  const ttl = Number(env.SWARM_TTL);
  const cutoff = now - ttl;

  // Atomic: D1 batch() runs as one transaction; writes are serialized per-DB,
  // so a concurrent contribute for the same ip commits fully before the next,
  // and the COUNT below always sees a consistent sightings table.
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO sightings (ip, host, last_seen) VALUES (?1, ?2, ?3)
       ON CONFLICT(ip, host) DO UPDATE SET last_seen=?3`
    ).bind(ip, host, now),
    env.DB.prepare(
      `INSERT INTO offenders (ip, first_seen, last_seen, host_count, last_host, category, expires)
       VALUES (?1, ?2, ?2,
               (SELECT COUNT(DISTINCT host) FROM sightings WHERE ip=?1 AND last_seen > ?3),
               ?4, ?5, ?2 + ?6)
       ON CONFLICT(ip) DO UPDATE SET
         last_seen=?2,
         host_count=(SELECT COUNT(DISTINCT host) FROM sightings WHERE ip=?1 AND last_seen > ?3),
         last_host=?4,
         category=?5,
         expires=?2 + ?6`
    ).bind(ip, now, cutoff, host, category ?? null, ttl),
  ]);

  const row = await env.DB.prepare("SELECT host_count FROM offenders WHERE ip=?").bind(ip).first();
  return { host_count: row.host_count };
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cd hub && npm test -- db-contribute`
Expected: PASS (all 4 cases).

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-contribute.test.js
git commit -m "feat(swarm-hub): atomic contribute upsert with DISTINCT-host host_count"
```

---

### Task 5: DB — feed query (bare + json, non-expired, size cap)

**Files:**
- Modify: `hub/src/db.js`
- Test: `hub/test/db-feed.test.js`

**Interfaces:**
- Consumes: `env.DB`, `env.FEED_MAX`.
- Produces: `feedRows(env, {now, limit}): Promise<Array<{ip, host_count, category, expires}>>` — rows with `expires > now`, ordered by `ip`, capped at `min(limit, FEED_MAX)`. (Serialization to bare/JSON happens in the handler, Task 7.)

- [ ] **Step 1: Write the failing test `hub/test/db-feed.test.js`**

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { contributeOne, feedRows } from "../src/db.js";

const now = 1_800_000_000;

describe("feedRows", () => {
  it("returns only non-expired rows, ordered by ip", async () => {
    await contributeOne(env, { ip: "2.2.2.2", host: "h", category: "a", now });
    await contributeOne(env, { ip: "1.1.1.1", host: "h", category: "b", now });
    // force one expired
    await env.DB.prepare("UPDATE offenders SET expires=? WHERE ip=?").bind(now - 1, "2.2.2.2").run();
    const rows = await feedRows(env, { now, limit: 1000 });
    expect(rows.map(r => r.ip)).toEqual(["1.1.1.1"]);
    expect(rows[0].host_count).toBe(1);
  });

  it("respects the limit cap", async () => {
    for (const ip of ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
      await contributeOne(env, { ip, host: "h", category: "a", now });
    const rows = await feedRows(env, { now, limit: 2 });
    expect(rows.length).toBe(2);
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- db-feed`
Expected: FAIL — `feedRows` not exported.

- [ ] **Step 3: Add `feedRows` to `hub/src/db.js`**

```js
export async function feedRows(env, { now, limit }) {
  const cap = Math.min(Number(limit) || Number(env.FEED_MAX), Number(env.FEED_MAX));
  const { results } = await env.DB.prepare(
    `SELECT ip, host_count, category, expires FROM offenders
     WHERE expires > ?1 ORDER BY ip LIMIT ?2`
  ).bind(now, cap).all();
  return results ?? [];
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cd hub && npm test -- db-feed`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-feed.test.js
git commit -m "feat(swarm-hub): feed query (non-expired, ordered, size-capped)"
```

---

### Task 6: DB — prune expired offenders AND sightings

**Files:**
- Modify: `hub/src/db.js`
- Test: `hub/test/db-prune.test.js`

**Interfaces:**
- Produces: `prune(env, {now}): Promise<{offenders, sightings}>` — deletes `offenders WHERE expires <= now` and `sightings WHERE last_seen <= now - TTL`; returns deleted counts.

- [ ] **Step 1: Write the failing test `hub/test/db-prune.test.js`**

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { contributeOne, prune } from "../src/db.js";

const now = 1_800_000_000;

describe("prune", () => {
  it("deletes expired offenders and stale sightings, keeps fresh", async () => {
    const ttl = Number(env.SWARM_TTL);
    await contributeOne(env, { ip: "5.5.5.5", host: "fresh", category: "a", now });
    await contributeOne(env, { ip: "6.6.6.6", host: "old", category: "a", now: now - ttl - 100 });
    const del = await prune(env, { now });
    expect(del.offenders).toBe(1);   // 6.6.6.6 expired
    expect(del.sightings).toBe(1);   // 'old' sighting stale
    const left = await env.DB.prepare("SELECT ip FROM offenders").all();
    expect(left.results.map(r => r.ip)).toEqual(["5.5.5.5"]);
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- db-prune`
Expected: FAIL — `prune` not exported.

- [ ] **Step 3: Add `prune` to `hub/src/db.js`**

```js
export async function prune(env, { now }) {
  const cutoff = now - Number(env.SWARM_TTL);
  const o = await env.DB.prepare("DELETE FROM offenders WHERE expires <= ?").bind(now).run();
  const s = await env.DB.prepare("DELETE FROM sightings WHERE last_seen <= ?").bind(cutoff).run();
  return { offenders: o.meta.changes ?? 0, sightings: s.meta.changes ?? 0 };
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cd hub && npm test -- db-prune`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-prune.test.js
git commit -m "feat(swarm-hub): prune expired offenders + stale sightings"
```

---

### Task 7: Router — POST /contribute and GET /feed wired with auth + validation

**Files:**
- Modify: `hub/src/index.js`
- Test: `hub/test/routes.test.js`

**Interfaces:**
- Consumes: `contributeOne`, `feedRows` (db.js); `checkAuth` (auth.js); `isValidIp`, `isUnsafeTarget` (validate.js); `env.SWARM_WRITE_TOKEN`, `env.SWARM_READ_TOKEN`.
- Produces the FROZEN HTTP contract:
  - `POST /contribute` body `{host_id: string, entries: [{ip, category?, first_local_seen?}]}`; write-token; returns `200 {accepted, rejected}`.
  - `GET /feed` read-token; default `text/plain` bare `ip\n` lines; `?format=json` → `[{ip,host_count,category,expires}]`; `?limit=N`.
  - `now` is `Math.floor(Date.now()/1000)`.

- [ ] **Step 1: Write the failing test `hub/test/routes.test.js`**

```js
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index.js";

const call = async (path, init) => {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request("https://hub" + path, init), env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
};
const W = { authorization: "Bearer test-write", "content-type": "application/json" };
const R = { authorization: "Bearer test-read" };

describe("routes", () => {
  it("rejects contribute without the write token", async () => {
    const res = await call("/contribute", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ host_id: "h", entries: [{ ip: "1.2.3.4" }] }) });
    expect(res.status).toBe(401);
  });

  it("rejects a READ token on contribute", async () => {
    const res = await call("/contribute", { method: "POST",
      headers: { authorization: "Bearer test-read", "content-type": "application/json" },
      body: JSON.stringify({ host_id: "h", entries: [{ ip: "1.2.3.4" }] }) });
    expect(res.status).toBe(401);
  });

  it("accepts valid entries, rejects malformed/unsafe", async () => {
    const res = await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "hostA", entries: [
        { ip: "1.2.3.4", category: "scan" }, { ip: "999.999.999.999" }, { ip: "0.0.0.0/0" }, { ip: "::" }] }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: 1, rejected: 3 });
  });

  it("feed requires the read token", async () => {
    const res = await call("/feed");
    expect(res.status).toBe(401);
  });

  it("feed returns bare IPs by default and json on request", async () => {
    await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "hostA", entries: [{ ip: "203.0.113.7", category: "scan" }] }) });
    const bare = await call("/feed", { headers: R });
    expect(bare.headers.get("content-type")).toMatch(/text\/plain/);
    expect((await bare.text()).trim()).toBe("203.0.113.7");
    const json = await call("/feed?format=json", { headers: R });
    const rows = await json.json();
    expect(rows[0]).toMatchObject({ ip: "203.0.113.7", host_count: 1 });
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- routes`
Expected: FAIL — routes return 404.

- [ ] **Step 3: Rewrite `hub/src/index.js` router**

```js
import { checkAuth } from "./auth.js";
import { isValidIp, isUnsafeTarget } from "./validate.js";
import { contributeOne, feedRows, prune } from "./db.js";

const nowSec = () => Math.floor(Date.now() / 1000);

async function handleContribute(request, env) {
  if (!checkAuth(request, env.SWARM_WRITE_TOKEN)) return json({ error: "unauthorized" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad json" }, 400); }
  const entries = Array.isArray(body?.entries) ? body.entries : null;
  const host = typeof body?.host_id === "string" ? body.host_id : null;
  if (!entries || !host) return json({ error: "host_id + entries required" }, 400);

  const now = nowSec();
  let accepted = 0, rejected = 0;
  for (const e of entries) {
    const ip = e?.ip;
    if (typeof ip !== "string" || !isValidIp(ip) || isUnsafeTarget(ip)) { rejected++; continue; }
    await contributeOne(env, { ip, host, category: e.category, now });
    accepted++;
  }
  return json({ accepted, rejected }, 200);
}

async function handleFeed(request, env) {
  if (!checkAuth(request, env.SWARM_READ_TOKEN)) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const limit = url.searchParams.get("limit");
  const rows = await feedRows(env, { now: nowSec(), limit });
  if (url.searchParams.get("format") === "json") return json(rows, 200);
  const body = rows.map(r => r.ip).join("\n") + (rows.length ? "\n" : "");
  return new Response(body, { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true }, 200);
    if (request.method === "POST" && url.pathname === "/contribute") return handleContribute(request, env);
    if (request.method === "GET" && url.pathname === "/feed") return handleFeed(request, env);
    return new Response("not found", { status: 404 });
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(prune(env, { now: nowSec() }));
  },
};
```

- [ ] **Step 4: Run — verify it passes (and re-run the whole suite)**

Run: `cd hub && npm test`
Expected: PASS (all files: health, validate, auth, db-*, routes).

- [ ] **Step 5: Commit**

```bash
git add hub/src/index.js hub/test/routes.test.js
git commit -m "feat(swarm-hub): contribute + feed routes with auth, validation, bare/json"
```

---

### Task 8: Rate limiting on /contribute

**Files:**
- Modify: `hub/wrangler.toml` (add a rate-limit binding)
- Modify: `hub/src/index.js`
- Test: `hub/test/ratelimit.test.js`

**Interfaces:**
- Consumes: `env.CONTRIBUTE_LIMITER` (Workers Rate Limiting binding).
- Produces: `POST /contribute` returns `429` when the limiter (keyed by `host_id`) is exceeded, bounding a leaked-write-token attacker.

- [ ] **Step 1: Add the binding to `hub/wrangler.toml`**

```toml
[[unsafe.bindings]]
name = "CONTRIBUTE_LIMITER"
type = "ratelimit"
namespace_id = "1001"
simple = { limit = 60, period = 60 }   # 60 contribute calls/min per host_id
```

- [ ] **Step 2: Add the test binding to `hub/vitest.config.js` miniflare bindings**

Add to the `miniflare.bindings` object a stub limiter that the test can drive:
```js
// in vitest.config.js miniflare block:
//   ratelimits are not emulated by miniflare; inject a controllable stub instead:
bindings: {
  SWARM_WRITE_TOKEN: "test-write",
  SWARM_READ_TOKEN: "test-read",
  CONTRIBUTE_LIMITER: { limit: async () => ({ success: globalThis.__RL_OK ?? true }) },
},
```

- [ ] **Step 3: Write the failing test `hub/test/ratelimit.test.js`**

```js
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, afterEach } from "vitest";
import worker from "../src/index.js";

afterEach(() => { globalThis.__RL_OK = true; });

it("returns 429 when the limiter denies", async () => {
  globalThis.__RL_OK = false;
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request("https://hub/contribute", {
    method: "POST",
    headers: { authorization: "Bearer test-write", "content-type": "application/json" },
    body: JSON.stringify({ host_id: "noisy", entries: [{ ip: "1.2.3.4" }] }),
  }), env, ctx);
  await waitOnExecutionContext(ctx);
  expect(res.status).toBe(429);
});
```

- [ ] **Step 4: Run — verify it fails**

Run: `cd hub && npm test -- ratelimit`
Expected: FAIL — currently returns 200.

- [ ] **Step 5: Enforce the limiter in `handleContribute` (after auth, before work)**

Insert into `handleContribute` in `hub/src/index.js`, immediately after the auth check:
```js
  const host = typeof (await request.clone().json().catch(() => ({})))?.host_id === "string"
    ? (await request.clone().json()).host_id : "unknown";
  if (env.CONTRIBUTE_LIMITER) {
    const { success } = await env.CONTRIBUTE_LIMITER.limit({ key: host });
    if (!success) return json({ error: "rate limited" }, 429);
  }
```
(Keep the existing body parse below; the clone avoids consuming the stream twice. If cleaner, parse the body ONCE at the top of the handler and pass `host`/`entries` down — refactor accordingly so the body is read a single time.)

- [ ] **Step 6: Run — verify it passes + full suite green**

Run: `cd hub && npm test`
Expected: PASS all.

- [ ] **Step 7: Commit**

```bash
git add hub/wrangler.toml hub/vitest.config.js hub/src/index.js hub/test/ratelimit.test.js
git commit -m "feat(swarm-hub): per-host rate limit on contribute"
```

---

### Task 9: Deploy docs + provisioning (README)

**Files:**
- Create: `hub/README.md`

**Interfaces:** none (docs). Produces the operator runbook to stand up a private hub.

- [ ] **Step 1: Write `hub/README.md`**

````markdown
# Swatter Swarm Hub

A self-hosted Cloudflare Worker + D1 that aggregates your fleet's confirmed
offenders and serves the merged, decaying blocklist back to your boxes. One hub
per operator; your boxes only ever talk to YOUR hub.

## Deploy (about 5 minutes)

```bash
cd hub
npm install

# 1. Create the D1 database and copy the printed database_id into wrangler.toml
wrangler d1 create swatter-swarm

# 2. Apply the schema
wrangler d1 execute swatter-swarm --file=./schema.sql --remote

# 3. Set the two tokens (generate long random strings; keep them safe)
wrangler secret put SWARM_WRITE_TOKEN   # publishers use this
wrangler secret put SWARM_READ_TOKEN    # consumers use this

# 4. Deploy
wrangler deploy
```

The Worker URL it prints is your `SWARM_HUB_URL`. On each Swatter box set
`SWARM_HUB_URL`, drop the write token in `SWARM_WRITE_TOKEN_FILE` (publishers)
and the read token in `SWARM_READ_TOKEN_FILE` (all consumers), then
`SWARM_ENABLE="true"`.

## Endpoints

- `POST /contribute` (write token) — `{host_id, entries:[{ip,category?}]}`
- `GET /feed` (read token) — bare `ip` per line; `?format=json` for metadata
- `GET /health` — `{ok:true}`

## Maintenance

- A daily cron (04:17 UTC) prunes expired entries. `SWARM_TTL` (wrangler.toml
  `[vars]`, default 7d) controls decay.
- Rotate a leaked token: `wrangler secret put SWARM_WRITE_TOKEN` (or READ) and
  redeploy; update the token files on your boxes.
````

- [ ] **Step 2: Commit**

```bash
git add hub/README.md
git commit -m "docs(swarm-hub): deploy runbook"
```

---

## Self-Review

- **Spec coverage:** §4.2 (contribute/feed/prune, D1, host_count, TTL, dual tokens, rate limit, size cap) → Tasks 1–8. §5 (schema) → Task 1. §10 (packaging/README) → Task 9. Server-side validation (§4.1/§7) → Task 2. IPv6 → Task 2 tests. Feed format (Blocker #1) → Task 7 bare/json split. Auth read/write split (§4.4) → Tasks 3,7. Prune sightings (Major) → Task 6. Concurrency (Major) → Task 4 atomic batch. **Gap:** feed pagination cursor (§4.2) is only size-capped here, not cursor-paginated — acceptable for Phase-1 fleet scale (FEED_MAX=50k); noted as a fast-follow, not a task.
- **Placeholder scan:** none — every code/test step has full content. Task 8 Step 5 asks the implementer to consolidate the body-parse (single read); that's a concrete refactor instruction, not a placeholder.
- **Type consistency:** `contributeOne`/`feedRows`/`prune`/`checkAuth`/`isValidIp`/`isUnsafeTarget` names + signatures are identical across the tasks that define and consume them. The HTTP contract (`{host_id, entries:[{ip,category}]}`, bare feed, `?format=json`) matches what the host-side plan will consume.

## Execution Handoff

This plan builds subsystem 1 of 2. After it's green + deployed, the host-side plan (`…-swatter-swarm-host.md`) implements the bash publish/consume/provider/allowlist against this frozen contract.
