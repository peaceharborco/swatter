# Swatter Swarm Hub Implementation Plan (v2.1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **v2.1** folds in the round-2 plan review
> (`…-swatter-swarm-hub-review-grok-rev2.md`): pool pinned `^0.13.0` (Vitest-4
> compatible); official D1 migration recipe (`readD1Migrations` in the Node config
> → `TEST_MIGRATIONS` binding → `applyD1Migrations` once); test tokens provisioned;
> validator off-by-one on the non-compressed embedded-v4 form + leading-zero
> prefix parity fixed; **unenrolled host_ids are write-gated** (no sightings/offender
> bloat); global `/contribute` limiter added; `?limit=` clamped; prune batched;
> host-consume obligations moved into the frozen contract. Both round-2 verdicts
> confirmed the core design (read-time count + registry) is sound.
>
> **v2 supersedes v1.** Rewritten after the round-1 plan review against design
> spec **v3**: `host_count` DERIVED at feed-read time (no write-race); a **host
> registry** gates the count (forgery defense); hub accepts **IP or CIDR**;
> current `cloudflareTest()` harness; connecting-IP rate limit; empty-feed +
> truncation + payload caps.

**Goal:** Build the self-hostable Swatter Swarm hub — a Cloudflare Worker + D1 that ingests each fleet host's confirmed offenders (`POST /contribute`), enrolls trusted hosts (`POST /register`), and serves the merged, decaying blocklist back (`GET /feed`), with corroboration (`host_count`) derived safely at read time.

**Architecture:** One Worker: a `fetch` router (`/health`, `/contribute`, `/register`, `/feed`) and a `scheduled` prune. D1 holds `offenders` (decay + metadata, NO cached count), `sightings` (per-`(ip,host)`), and `hosts` (the enrolled-host registry). `host_count` is computed at read time as `COUNT(DISTINCT host)` over `sightings` JOINed to `hosts` within `SWARM_TTL`, so concurrent writes can't corrupt it and forged host_ids (not in `hosts`) don't count. Three bearer tokens gate write / read / enroll.

**Tech Stack:** Cloudflare Workers (JS, ES modules), D1, Wrangler ≥ 4.36 (Rate Limiting GA binding), Vitest 4.1+ with `@cloudflare/vitest-pool-workers` (`cloudflareTest()` API). Pure-logic modules (validation, auth) are tested under plain Vitest; D1 logic runs in the Workers pool with `applyD1Migrations`.

## Global Constraints

- **Subsystem 1 of 2.** This FREEZES the HTTP contract the host-side plan consumes. Contract (do not change field names/shapes without updating the host plan):
  - `POST /contribute` — write token — `{host_id: string, entries: [{ip: string, category?: string}]}` → `200 {accepted, rejected, enrolled}`; `413` if `entries.length > MAX_ENTRIES`. **`enrolled:false` + `accepted:0`** if the `host_id` isn't registered — the host must `swatter swarm enroll` first (nothing is stored for an unenrolled host).
  - `POST /register` — enroll token — `{host_id: string, label?: string}` → `200 {enrolled: host_id}`.
  - `GET /feed` — read token — default `text/plain` bare `ip`/`cidr` per line (empty body if none); `?format=json` → `[{ip, host_count, category, expires}]`; `?limit=N` clamped to `[1, FEED_MAX]`. Response header `X-Swarm-Truncated: true` when the row cap was hit.
  - `GET /health` — no auth — `{ok:true}`.
- **HOST-SIDE consume obligations this contract imposes (the host plan MUST honor these — they are part of the freeze, not footnotes):**
  1. An **empty `200` bare feed means "no active offenders" → the host CLEARS `swarm.txt`** (and the swarm signal for this cycle). It must NOT pass an empty body through `swatter_cidr_list_ok` (whose `n>0` would reject it and freeze decay). "Keep last-good" applies ONLY to a fetch *failure* (non-200 / transport error), never to a valid empty 200.
  2. **`corroborated-block` REQUIRES the `?format=json` feed** — the bare feed carries no `host_count`. A host in `boost` may use bare; a host in `corroborated-block` MUST fetch JSON.
- **`host_count` is DERIVED at read time** (`COUNT(DISTINCT s.host) FROM sightings s JOIN hosts h ON s.host=h.host WHERE s.ip=? AND s.last_seen > now-SWARM_TTL`). It is NEVER stored on `offenders`. Only ENROLLED hosts count.
- **Feed accepts IP or CIDR**; rejects `/0` and unspecified (`0.0.0.0`, `::`). Parity with the bash `swatter_is_valid_ip_or_cidr` + `_swatter_is_unsafe_block_target`.
- **Three tokens** (Worker secrets, never in `wrangler.toml`): `SWARM_WRITE_TOKEN` (contribute), `SWARM_READ_TOKEN` (feed), `SWARM_ENROLL_TOKEN` (register). A read token must NOT work on write/enroll paths; a write token must NOT work on enroll.
- **`SWARM_TTL`** hub-authoritative (`[vars]`, seconds, default `604800`). **`MAX_ENTRIES`** default `1000`. **`FEED_MAX`** default `50000`.
- Rate limiting keys on `request.headers.get("cf-connecting-ip")` (NOT the attacker-controlled `host_id`).
- Auth failures `401`; malformed input `400`; oversized `413`; rate-limited `429`.

---

### Task 1: Scaffold + health + D1 harness proof

**Files:**
- Create: `hub/package.json`, `hub/wrangler.toml`, `hub/vitest.config.js`
- Create: `hub/migrations/0001_init.sql`
- Create: `hub/test/apply-migrations.js` (setup)
- Create: `hub/src/index.js`
- Test: `hub/test/health.test.js`

**Interfaces:**
- Produces: default export `{ fetch(request, env, ctx), scheduled(event, env, ctx) }`; `GET /health` → `200 {ok:true}`; a working Workers-pool + D1 test harness (proven by a smoke query).

- [ ] **Step 1: `hub/package.json`**

```json
{
  "name": "swatter-swarm-hub",
  "private": true,
  "type": "module",
  "scripts": { "test": "vitest run", "deploy": "wrangler deploy" },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.13.0",
    "vitest": "^4.1.0",
    "wrangler": "^4.36.0"
  }
}
```

> **Version note (round-2 review):** pool `^0.8.0` peers Vitest 2–3 and will NOT
> install with Vitest 4.1 — it must be `^0.13.0`+ (current `0.18`). If `npm install`
> still complains about peers, bump pool to the latest and re-run Task 1 Step 8
> BEFORE any other task; the harness-proof gate exists precisely to absorb this
> ecosystem churn.

- [ ] **Step 2: `hub/migrations/0001_init.sql`** (schema; applied to test D1 by setup, to prod by `wrangler d1 migrations apply`)

```sql
-- offenders: NO host_count (derived at read time). Decay + metadata only.
CREATE TABLE offenders (
  ip         TEXT PRIMARY KEY,          -- IP or CIDR
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  last_host  TEXT,
  category   TEXT,
  expires    INTEGER NOT NULL
);
CREATE INDEX ix_offenders_expires ON offenders(expires);

CREATE TABLE sightings (
  ip        TEXT NOT NULL,
  host      TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (ip, host)
);
CREATE INDEX ix_sightings_seen ON sightings(last_seen);

-- registry: only enrolled host_ids count toward host_count.
CREATE TABLE hosts (
  host        TEXT PRIMARY KEY,
  enrolled_at INTEGER NOT NULL,
  label       TEXT
);
```

- [ ] **Step 3: `hub/wrangler.toml`**

```toml
name = "swatter-swarm-hub"
main = "src/index.js"
compatibility_date = "2024-11-01"

[vars]
SWARM_TTL = "604800"
MAX_ENTRIES = "1000"
FEED_MAX = "50000"

[[d1_databases]]
binding = "DB"
database_name = "swatter-swarm"
# Zero-UUID works for the local/test harness; replace with the real id from
# `wrangler d1 create` before `wrangler deploy` (round-2 review: a non-UUID
# placeholder can break Miniflare D1 init).
database_id = "00000000-0000-0000-0000-000000000000"
migrations_dir = "migrations"

# Per-connecting-IP limiter AND a global limiter (spec §4.2: "connecting IP + a
# global /contribute limit") — the global one bounds a distributed leaked-token
# holder that the per-IP one alone can't.
[[ratelimits]]
name = "CONTRIBUTE_LIMITER"
namespace_id = "1001"
simple = { limit = 120, period = 60 }

[[ratelimits]]
name = "GLOBAL_LIMITER"
namespace_id = "1002"
simple = { limit = 6000, period = 60 }

[triggers]
crons = ["17 4 * * *"]

# Secrets (NOT here): SWARM_WRITE_TOKEN, SWARM_READ_TOKEN, SWARM_ENROLL_TOKEN
```

- [ ] **Step 4: `hub/vitest.config.js`** — the OFFICIAL D1 recipe: read migrations
  in Node (config context), pass them + the three test tokens through
  `miniflare.bindings`. (Round-2 review: reading migrations inside the setup file
  and dropping tables per-test is the wrong wiring.)

```js
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import { defineConfig } from "vitest/config";
import path from "node:path";

const migrations = await readD1Migrations(path.join(__dirname, "migrations"));

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        // migrations array handed to the worker context for the setup file;
        // test tokens provisioned here (wrangler.toml deliberately omits secrets).
        bindings: {
          TEST_MIGRATIONS: migrations,
          SWARM_WRITE_TOKEN: "test-write",
          SWARM_READ_TOKEN: "test-read",
          SWARM_ENROLL_TOKEN: "test-enroll",
        },
      },
    }),
  ],
  test: { setupFiles: ["./test/apply-migrations.js"] },
});
```

- [ ] **Step 5: `hub/test/apply-migrations.js`** — apply migrations ONCE; isolated
  storage resets writes between tests (no per-test DROP/re-apply).

```js
import { env, applyD1Migrations } from "cloudflare:test";
import { beforeAll } from "vitest";

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});
```

> If the installed pool version doesn't export `cloudflareTest`/`readD1Migrations`
> as shown, THIS is the first thing to reconcile against the version's own docs —
> run Step 8 immediately to confirm the harness loads before any other task. The
> per-test isolation comes from the pool's default isolated storage; do not add
> `beforeEach` DROPs (they fight the migration bookkeeping).

- [ ] **Step 6: `hub/src/index.js`** (health only for now)

```js
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true });
    return new Response("not found", { status: 404 });
  },
  async scheduled(event, env, ctx) { /* prune wired in Task 9 */ },
};
```

- [ ] **Step 7: `hub/test/health.test.js`** (health + a D1 smoke query proving the harness)

```js
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index.js";

describe("harness", () => {
  it("GET /health returns ok", async () => {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request("https://hub/health"), env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("D1 schema is applied (tables queryable)", async () => {
    // Fails loudly if migrations didn't apply — guards against silent-empty-DB.
    await env.DB.prepare("INSERT INTO hosts (host, enrolled_at) VALUES ('h', 1)").run();
    const row = await env.DB.prepare("SELECT host FROM hosts WHERE host='h'").first();
    expect(row.host).toBe("h");
  });
});
```

- [ ] **Step 8: Install + run — verify health passes and the D1 smoke test proves the harness**

Run: `cd hub && npm install && npm test`
Expected: both tests PASS. If the config/migrations API errors, fix the harness (Step 4/5) NOW before any other task.

- [ ] **Step 9: Commit**

```bash
git add hub/
git commit -m "feat(swarm-hub): scaffold Worker + D1 (cloudflareTest/Vitest4.1) + /health"
```

---

### Task 2: Validation — IP or CIDR, reject unsafe (pure module)

**Files:**
- Create: `hub/src/validate.js`
- Test: `hub/test/validate.test.js`

**Interfaces:**
- Produces: `isValidIpOrCidr(s): boolean` (valid IPv4/IPv6, optional `/len` bounded 0–32 v4 / 0–128 v6, incl. `::ffff:` embedded-v4; rejects garbage); `isUnsafeTarget(s): boolean` (`/0`, `0.0.0.0`, `::`, `0:0:0:0:0:0:0:0`). Mirrors the bash validator + unsafe-target rules so hub and host agree.

- [ ] **Step 1: `hub/test/validate.test.js`** (parity cases with the bash validator)

```js
import { describe, it, expect } from "vitest";
import { isValidIpOrCidr, isUnsafeTarget } from "../src/validate.js";

describe("isValidIpOrCidr", () => {
  it.each(["1.2.3.4", "203.0.113.9", "198.51.100.0/24", "::1", "2001:db8::1",
           "2001:db8::/48", "::ffff:192.0.2.1", "0:0:0:0:0:ffff:192.0.2.1",
           "2400:cb00::/32", "1.2.3.4/0", "::/0"])(
    "accepts %s", (s) => expect(isValidIpOrCidr(s)).toBe(true));
  it.each(["999.999.999.999", "256.0.0.1", "1.2.3", "deadbeef", "::::",
           "1.2.3.4/33", "2001:db8::/129", "", "1.2.3.4 ", "evil\"x", "1.2.3.4/1/2",
           "1.2.3.4/00", "1.2.3.4/03", "2001:db8::/033", "1:2:3:4:5:6:7:8:9"])(
    "rejects %s", (s) => expect(isValidIpOrCidr(s)).toBe(false));
});

describe("isUnsafeTarget", () => {
  it.each(["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "0.0.0.0/0", "1.2.3.4/0", "::/0"])(
    "flags %s", (s) => expect(isUnsafeTarget(s)).toBe(true));
  it.each(["1.2.3.4", "2001:db8::1", "198.51.100.0/24"])(
    "allows %s", (s) => expect(isUnsafeTarget(s)).toBe(false));
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `cd hub && npm test -- validate`
Expected: FAIL — module missing.

- [ ] **Step 3: `hub/src/validate.js`**

```js
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function validV6(a) {
  a = a.toLowerCase();
  let v4tail = 0;
  if (a.includes(".")) {
    if (!a.includes(":")) return false;
    const tail = a.slice(a.lastIndexOf(":") + 1);
    if (!V4.test(tail)) return false;
    a = a.slice(0, a.lastIndexOf(":")) + ":0";
    v4tail = 2;
  }
  if (!/^[0-9a-f:]+$/.test(a)) return false;
  let L, R = "";
  if (a.includes("::")) {
    if (a.includes(":::") || a.slice(a.indexOf("::") + 2).includes("::")) return false;
    L = a.slice(0, a.indexOf("::"));
    R = a.slice(a.indexOf("::") + 2);
  } else {
    if (a.startsWith(":") || a.endsWith(":")) return false;
    L = a;
  }
  const groups = [...L.split(":").filter(Boolean), ...R.split(":").filter(Boolean)];
  for (const g of groups) if (!/^[0-9a-f]{1,4}$/.test(g)) return false;
  // The embedded-v4 tail was replaced with a single ":0" placeholder group above,
  // so subtract that 1 placeholder before adding the quad's 2 groups — matching
  // the bash validator (round-2 review: `0:0:0:0:0:ffff:192.0.2.1` must pass).
  const n = groups.length + v4tail - (v4tail ? 1 : 0);
  return a.includes("::") ? n <= 7 : n === 8;
}

export function isValidIpOrCidr(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  let addr = s, plen = null;
  const slash = s.indexOf("/");
  if (slash !== -1) {
    addr = s.slice(0, slash);
    plen = s.slice(slash + 1);
    if (addr.length === 0 || plen.includes("/") || !/^\d+$/.test(plen)) return false;
  }
  // Prefix regexes copied EXACTLY from the bash validator so a leading-zero plen
  // (`/00`, `/03`, `/033`) is rejected on both sides (round-2 review parity gap).
  if (addr.includes(":")) {
    if (!validV6(addr)) return false;
    return plen === null || /^([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$/.test(plen);
  }
  if (!V4.test(addr)) return false;
  return plen === null || /^([0-9]|[12][0-9]|3[0-2])$/.test(plen);
}

export function isUnsafeTarget(s) {
  if (typeof s !== "string") return true;
  const slash = s.indexOf("/");
  if (slash !== -1 && s.slice(slash + 1) === "0") return true;   // /0
  const addr = slash === -1 ? s : s.slice(0, slash);
  return addr === "0.0.0.0" || addr === "::" || addr === "0:0:0:0:0:0:0:0";
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cd hub && npm test -- validate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/validate.js hub/test/validate.test.js
git commit -m "feat(swarm-hub): IP-or-CIDR validation + unsafe-target (bash parity)"
```

---

### Task 3: Auth — three-token bearer check (pure module)

**Files:**
- Create: `hub/src/auth.js`
- Test: `hub/test/auth.test.js`

**Interfaces:**
- Produces: `checkAuth(request, expectedToken): boolean` — length-safe XOR compare of `Authorization: Bearer <token>`; false on missing/malformed/empty-expected.

- [ ] **Step 1: `hub/test/auth.test.js`**

```js
import { describe, it, expect } from "vitest";
import { checkAuth } from "../src/auth.js";
const req = (h) => new Request("https://hub/x", { headers: h ? { authorization: h } : {} });

describe("checkAuth", () => {
  it("accepts exact", () => expect(checkAuth(req("Bearer sekret"), "sekret")).toBe(true));
  it("rejects wrong", () => expect(checkAuth(req("Bearer nope"), "sekret")).toBe(false));
  it("rejects missing", () => expect(checkAuth(req(null), "sekret")).toBe(false));
  it("rejects non-bearer", () => expect(checkAuth(req("Basic sekret"), "sekret")).toBe(false));
  it("rejects empty expected", () => expect(checkAuth(req("Bearer x"), "")).toBe(false));
});
```

- [ ] **Step 2: Run — verify it fails.** `cd hub && npm test -- auth` → FAIL (missing).

- [ ] **Step 3: `hub/src/auth.js`**

```js
export function checkAuth(request, expectedToken) {
  if (!expectedToken) return false;
  const m = (request.headers.get("authorization") || "").match(/^Bearer (.+)$/);
  if (!m) return false;
  const got = m[1];
  if (got.length !== expectedToken.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expectedToken.charCodeAt(i);
  return diff === 0;
}
```

- [ ] **Step 4: Run — verify it passes.** `cd hub && npm test -- auth` → PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/auth.js hub/test/auth.test.js
git commit -m "feat(swarm-hub): three-token bearer auth check"
```

---

### Task 4: DB — register a host (registry)

**Files:**
- Create: `hub/src/db.js`
- Test: `hub/test/db-register.test.js`

**Interfaces:**
- Produces: `registerHost(env, {host, label, now}): Promise<void>` — upsert into `hosts` (idempotent; re-enroll updates `label`, keeps `enrolled_at`). `isEnrolled(env, host): Promise<boolean>` — true iff `host` is in the registry (the contribute write-gate).

- [ ] **Step 1: `hub/test/db-register.test.js`**

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { registerHost, isEnrolled } from "../src/db.js";

it("enrolls a host idempotently", async () => {
  await registerHost(env, { host: "boxA", label: "cds1", now: 100 });
  await registerHost(env, { host: "boxA", label: "cds1-renamed", now: 200 });
  const row = await env.DB.prepare("SELECT * FROM hosts WHERE host='boxA'").first();
  expect(row.enrolled_at).toBe(100);          // preserved
  expect(row.label).toBe("cds1-renamed");     // updated
  const cnt = await env.DB.prepare("SELECT COUNT(*) c FROM hosts").first();
  expect(cnt.c).toBe(1);
});

it("isEnrolled reflects the registry", async () => {
  await registerHost(env, { host: "boxA", now: 100 });
  expect(await isEnrolled(env, "boxA")).toBe(true);
  expect(await isEnrolled(env, "forged")).toBe(false);
});
```

- [ ] **Step 2: Run — verify it fails.** `cd hub && npm test -- db-register` → FAIL.

- [ ] **Step 3: `hub/src/db.js` (`registerHost`, `isEnrolled`)**

```js
export async function registerHost(env, { host, label, now }) {
  await env.DB.prepare(
    `INSERT INTO hosts (host, enrolled_at, label) VALUES (?1, ?2, ?3)
     ON CONFLICT(host) DO UPDATE SET label=?3`
  ).bind(host, now, label ?? null).run();
}

export async function isEnrolled(env, host) {
  const row = await env.DB.prepare("SELECT 1 FROM hosts WHERE host=?").bind(host).first();
  return row !== null;
}
```

- [ ] **Step 4: Run — verify it passes.** `cd hub && npm test -- db-register` → PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-register.test.js
git commit -m "feat(swarm-hub): host registry (idempotent enroll)"
```

---

### Task 5: DB — contribute (sighting + offender, NO cached count)

**Files:**
- Modify: `hub/src/db.js`
- Test: `hub/test/db-contribute.test.js`

**Interfaces:**
- Produces: `contributeOne(env, {ip, host, category, now}): Promise<void>` — upsert `sightings(ip,host,last_seen=now)` and upsert `offenders(ip, first_seen, last_seen, last_host, category, expires=now+TTL)`. NO host_count written. Two sequentially-awaited statements (each commits; no reliance on undocumented intra-batch visibility).

- [ ] **Step 1: `hub/test/db-contribute.test.js`**

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { contributeOne } from "../src/db.js";
const now = 1_800_000_000;

describe("contributeOne", () => {
  it("records a sighting and an offender with expiry", async () => {
    await contributeOne(env, { ip: "1.2.3.4", host: "boxA", category: "scan", now });
    const s = await env.DB.prepare("SELECT * FROM sightings WHERE ip='1.2.3.4'").first();
    expect(s.host).toBe("boxA");
    const o = await env.DB.prepare("SELECT * FROM offenders WHERE ip='1.2.3.4'").first();
    expect(o.expires).toBe(now + Number(env.SWARM_TTL));
    expect(o.last_host).toBe("boxA");
  });

  it("same (ip,host) stays one sighting row and bumps last_seen", async () => {
    await contributeOne(env, { ip: "1.2.3.4", host: "boxA", category: "scan", now });
    await contributeOne(env, { ip: "1.2.3.4", host: "boxA", category: "scan", now: now + 10 });
    const c = await env.DB.prepare("SELECT COUNT(*) c FROM sightings WHERE ip='1.2.3.4'").first();
    expect(c.c).toBe(1);
    const s = await env.DB.prepare("SELECT last_seen FROM sightings WHERE ip='1.2.3.4'").first();
    expect(s.last_seen).toBe(now + 10);
  });

  it("accepts a CIDR as the ip key", async () => {
    await contributeOne(env, { ip: "198.51.100.0/24", host: "boxA", category: "import", now });
    const o = await env.DB.prepare("SELECT ip FROM offenders WHERE ip='198.51.100.0/24'").first();
    expect(o.ip).toBe("198.51.100.0/24");
  });
});
```

- [ ] **Step 2: Run — verify it fails.** `cd hub && npm test -- db-contribute` → FAIL.

- [ ] **Step 3: Add `contributeOne` to `hub/src/db.js`**

```js
export async function contributeOne(env, { ip, host, category, now }) {
  const ttl = Number(env.SWARM_TTL);
  // Sequential awaited statements: each commits before the next. host_count is
  // NOT stored here (derived at read time), so there is no cross-request count
  // race to protect against.
  await env.DB.prepare(
    `INSERT INTO sightings (ip, host, last_seen) VALUES (?1, ?2, ?3)
     ON CONFLICT(ip, host) DO UPDATE SET last_seen=?3`
  ).bind(ip, host, now).run();
  await env.DB.prepare(
    `INSERT INTO offenders (ip, first_seen, last_seen, last_host, category, expires)
     VALUES (?1, ?2, ?2, ?3, ?4, ?2 + ?5)
     ON CONFLICT(ip) DO UPDATE SET last_seen=?2, last_host=?3, category=?4, expires=?2 + ?5`
  ).bind(ip, now, host, category ?? null, ttl).run();
}
```

- [ ] **Step 4: Run — verify it passes.** `cd hub && npm test -- db-contribute` → PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-contribute.test.js
git commit -m "feat(swarm-hub): contribute (sighting + offender, no cached count)"
```

---

### Task 6: DB — feed with read-time host_count (registry-gated) + concurrency proof

**Files:**
- Modify: `hub/src/db.js`
- Test: `hub/test/db-feed.test.js`

**Interfaces:**
- Produces: `feedRows(env, {now, limit}): Promise<{rows, truncated}>` — non-expired offenders ordered by ip, capped at `min(limit, FEED_MAX)`; each row `{ip, host_count, category, expires}` where `host_count = COUNT(DISTINCT s.host) FROM sightings s JOIN hosts h ON s.host=h.host WHERE s.ip=offenders.ip AND s.last_seen > now-TTL`. `truncated=true` if the cap was hit.

- [ ] **Step 1: `hub/test/db-feed.test.js`** (includes the registry gate + a concurrency case)

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { contributeOne, feedRows, registerHost } from "../src/db.js";
const now = 1_800_000_000;

describe("feedRows / host_count", () => {
  it("counts only ENROLLED distinct hosts", async () => {
    await registerHost(env, { host: "boxA", now });
    await registerHost(env, { host: "boxB", now });
    // boxA + boxB enrolled; 'forged' is NOT enrolled
    await contributeOne(env, { ip: "1.2.3.4", host: "boxA", category: "scan", now });
    await contributeOne(env, { ip: "1.2.3.4", host: "boxB", category: "scan", now });
    await contributeOne(env, { ip: "1.2.3.4", host: "forged", category: "scan", now });
    const { rows } = await feedRows(env, { now, limit: 100 });
    const r = rows.find(x => x.ip === "1.2.3.4");
    expect(r.host_count).toBe(2);   // forged does not count
  });

  it("a sighting older than TTL does not count", async () => {
    await registerHost(env, { host: "boxA", now });
    await registerHost(env, { host: "boxB", now });
    await contributeOne(env, { ip: "9.9.9.9", host: "boxA", category: "x", now: now - Number(env.SWARM_TTL) - 5 });
    await contributeOne(env, { ip: "9.9.9.9", host: "boxB", category: "x", now });
    const { rows } = await feedRows(env, { now, limit: 100 });
    // offender.last_seen was bumped by boxB (fresh); host_count counts only fresh boxB
    expect(rows.find(x => x.ip === "9.9.9.9").host_count).toBe(1);
  });

  // NOTE: this proves the DERIVED count is correct when two hosts report the same
  // ip — it does NOT prove cross-request race freedom (the pool serializes these
  // in one isolate). Race freedom comes from the DESIGN: host_count is never
  // written, only computed from committed `sightings` at read time, so there is no
  // write to race. (round-2 review: honest labelling.)
  it("two hosts reporting one ip => derived host_count is 2", async () => {
    await registerHost(env, { host: "boxA", now });
    await registerHost(env, { host: "boxB", now });
    await contributeOne(env, { ip: "7.7.7.7", host: "boxA", category: "scan", now });
    await contributeOne(env, { ip: "7.7.7.7", host: "boxB", category: "scan", now });
    const { rows } = await feedRows(env, { now, limit: 100 });
    expect(rows.find(x => x.ip === "7.7.7.7").host_count).toBe(2);
  });

  it("excludes expired offenders, orders by ip, flags truncation at the cap", async () => {
    await registerHost(env, { host: "boxA", now });
    for (const ip of ["10.0.0.3", "10.0.0.1", "10.0.0.2"])
      await contributeOne(env, { ip, host: "boxA", category: "a", now });
    await env.DB.prepare("UPDATE offenders SET expires=? WHERE ip='10.0.0.2'").bind(now - 1).run();
    const { rows, truncated } = await feedRows(env, { now, limit: 1 });
    expect(rows.length).toBe(1);
    expect(rows[0].ip).toBe("10.0.0.1");   // lowest non-expired, ordered
    expect(truncated).toBe(true);
  });
});
```

- [ ] **Step 2: Run — verify it fails.** `cd hub && npm test -- db-feed` → FAIL.

- [ ] **Step 3: Add `feedRows` to `hub/src/db.js`**

```js
export async function feedRows(env, { now, limit }) {
  const ttl = Number(env.SWARM_TTL);
  const cutoff = now - ttl;
  const max = Number(env.FEED_MAX);
  // Clamp to [1, FEED_MAX]: a garbage/negative/zero ?limit must never yield a
  // negative LIMIT or a silently-empty feed (a consumer may treat empty as
  // "clear my blocks"). round-2 review.
  const req = Number(limit);
  const cap = Number.isFinite(req) && req >= 1 ? Math.min(Math.floor(req), max) : max;
  const { results } = await env.DB.prepare(
    `SELECT o.ip AS ip,
            (SELECT COUNT(DISTINCT s.host) FROM sightings s
              JOIN hosts h ON s.host = h.host
             WHERE s.ip = o.ip AND s.last_seen > ?2) AS host_count,
            o.category AS category, o.expires AS expires
       FROM offenders o
      WHERE o.expires > ?1
      ORDER BY o.ip
      LIMIT ?3`
  ).bind(now, cutoff, cap + 1).all();
  const rows = (results ?? []).slice(0, cap);
  return { rows, truncated: (results ?? []).length > cap };
}
```

- [ ] **Step 4: Run — verify it passes.** `cd hub && npm test -- db-feed` → PASS (incl. the concurrency case).

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-feed.test.js
git commit -m "feat(swarm-hub): read-time registry-gated host_count + feed (race-proof)"
```

---

### Task 7: DB — prune (offenders + sightings), returns counts

**Files:**
- Modify: `hub/src/db.js`
- Test: `hub/test/db-prune.test.js`

**Interfaces:**
- Produces: `prune(env, {now}): Promise<{offenders, sightings}>` — delete `offenders WHERE expires <= now` and `sightings WHERE last_seen <= now-TTL`; return deleted counts (for surfacing).

- [ ] **Step 1: `hub/test/db-prune.test.js`**

```js
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { contributeOne, prune, registerHost } from "../src/db.js";
const now = 1_800_000_000;

it("prunes expired offenders and stale sightings, keeps fresh", async () => {
  const ttl = Number(env.SWARM_TTL);
  await registerHost(env, { host: "boxA", now });
  await contributeOne(env, { ip: "5.5.5.5", host: "boxA", category: "a", now });
  await contributeOne(env, { ip: "6.6.6.6", host: "boxA", category: "a", now: now - ttl - 100 });
  const del = await prune(env, { now });
  expect(del.offenders).toBe(1);
  expect(del.sightings).toBe(1);
  const left = await env.DB.prepare("SELECT ip FROM offenders").all();
  expect(left.results.map(r => r.ip)).toEqual(["5.5.5.5"]);
});
```

- [ ] **Step 2: Run — verify it fails.** `cd hub && npm test -- db-prune` → FAIL.

- [ ] **Step 3: Add `prune` to `hub/src/db.js`**

```js
export async function prune(env, { now }) {
  const cutoff = now - Number(env.SWARM_TTL);
  // One batch (atomic transaction) so a concurrent feed can't observe offenders
  // and sightings out of sync between the two DELETEs (round-2 review).
  const [o, s] = await env.DB.batch([
    env.DB.prepare("DELETE FROM offenders WHERE expires <= ?").bind(now),
    env.DB.prepare("DELETE FROM sightings WHERE last_seen <= ?").bind(cutoff),
  ]);
  return { offenders: o.meta.changes ?? 0, sightings: s.meta.changes ?? 0 };
}
```

- [ ] **Step 4: Run — verify it passes.** `cd hub && npm test -- db-prune` → PASS.

- [ ] **Step 5: Commit**

```bash
git add hub/src/db.js hub/test/db-prune.test.js
git commit -m "feat(swarm-hub): prune expired offenders + stale sightings"
```

---

### Task 8: Router — /contribute, /register, /feed (auth, validation, caps, bare/json/empty/truncation)

**Files:**
- Modify: `hub/src/index.js`
- Test: `hub/test/routes.test.js`

**Interfaces:**
- Consumes: db.js (`contributeOne`, `registerHost`, `feedRows`, `prune`), auth.js (`checkAuth`), validate.js (`isValidIpOrCidr`, `isUnsafeTarget`); `env.SWARM_WRITE_TOKEN`/`SWARM_READ_TOKEN`/`SWARM_ENROLL_TOKEN`, `env.MAX_ENTRIES`, `env.CONTRIBUTE_LIMITER` (optional).
- Produces the frozen contract (Global Constraints). Body is parsed ONCE per request. `now = Math.floor(Date.now()/1000)`.

- [ ] **Step 1: `hub/test/routes.test.js`**

```js
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index.js";

const call = async (path, init, envOverride) => {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request("https://hub" + path, init), envOverride ?? env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
};
const W = { authorization: "Bearer " + env.SWARM_WRITE_TOKEN, "content-type": "application/json" };
const R = { authorization: "Bearer " + env.SWARM_READ_TOKEN };
const E = { authorization: "Bearer " + env.SWARM_ENROLL_TOKEN, "content-type": "application/json" };

describe("routes", () => {
  it("contribute rejects a read token; register rejects a write token", async () => {
    expect((await call("/contribute", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_READ_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "h", entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(401);
    expect((await call("/register", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_WRITE_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "h" }) })).status).toBe(401);
  });

  it("register then contribute makes the host count", async () => {
    expect((await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA", label: "cds1" }) })).status).toBe(200);
    const res = await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "boxA", entries: [
        { ip: "1.2.3.4", category: "scan" }, { ip: "999.999.999.999" }, { ip: "0.0.0.0/0" }] }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: 1, rejected: 2 });   // CIDR ok, garbage+unsafe rejected
    const feed = await (await call("/feed?format=json", { headers: R })).json();
    expect(feed.find(r => r.ip === "1.2.3.4").host_count).toBe(1);
  });

  it("an UNENROLLED host_id writes nothing (no sightings/offenders bloat)", async () => {
    const res = await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "never-enrolled", entries: [{ ip: "8.8.8.8" }] }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: 0, rejected: 1, enrolled: false });
    const feed = await (await call("/feed", { headers: R })).text();
    expect(feed).toBe("");   // 8.8.8.8 never entered the feed
  });

  it("enroll token can't contribute or read; write/read tokens can't enroll", async () => {
    const eOnW = await call("/contribute", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_ENROLL_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "x", entries: [] }) });
    expect(eOnW.status).toBe(401);
    const wOnFeed = await call("/feed", { headers: { authorization: "Bearer " + env.SWARM_WRITE_TOKEN } });
    expect(wOnFeed.status).toBe(401);
    const rOnReg = await call("/register", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_READ_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "x" }) });
    expect(rOnReg.status).toBe(401);
  });

  it("bare feed lists ip/cidr; empty feed is an empty 200", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "203.0.113.7" }, { ip: "198.51.100.0/24" }] }) });
    const bare = await call("/feed", { headers: R });
    expect(bare.headers.get("content-type")).toMatch(/text\/plain/);
    expect((await bare.text()).trim().split("\n").sort()).toEqual(["198.51.100.0/24", "203.0.113.7"]);
  });

  it("empty feed returns empty 200 (not 404/error)", async () => {
    const res = await call("/feed", { headers: R });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("");
  });

  it("rejects an oversized entries batch with 413", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    const many = Array.from({ length: Number(env.MAX_ENTRIES) + 1 }, (_, i) => ({ ip: "10.0." + ((i>>8)&255) + "." + (i&255) }));
    const res = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: many }) });
    expect(res.status).toBe(413);
  });

  it("returns 429 when the injected limiter denies", async () => {
    const denyEnv = { ...env, CONTRIBUTE_LIMITER: { limit: async () => ({ success: false }) } };
    const res = await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.2.3.4" }] }) }, denyEnv);
    expect(res.status).toBe(429);
  });
});
```

> Note: the 429 test injects a stub `CONTRIBUTE_LIMITER` by passing a custom
> `env` to `worker.fetch` (the handler receives `env` as a parameter) — this
> avoids the unsupported "function value in miniflare bindings" path.

- [ ] **Step 2: Run — verify it fails.** `cd hub && npm test -- routes` → FAIL (routes 404).

- [ ] **Step 3: Rewrite `hub/src/index.js`**

```js
import { checkAuth } from "./auth.js";
import { isValidIpOrCidr, isUnsafeTarget } from "./validate.js";
import { contributeOne, registerHost, isEnrolled, feedRows, prune } from "./db.js";

const nowSec = () => Math.floor(Date.now() / 1000);
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });
}
async function readJson(request) { try { return await request.json(); } catch { return null; } }

async function handleContribute(request, env) {
  if (!checkAuth(request, env.SWARM_WRITE_TOKEN)) return json({ error: "unauthorized" }, 401);
  // Per-connecting-IP AND global limits (spec §4.2) — global bounds a distributed
  // leaked-token holder the per-IP one can't.
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.CONTRIBUTE_LIMITER && !(await env.CONTRIBUTE_LIMITER.limit({ key: ip })).success)
    return json({ error: "rate limited" }, 429);
  if (env.GLOBAL_LIMITER && !(await env.GLOBAL_LIMITER.limit({ key: "global" })).success)
    return json({ error: "rate limited" }, 429);
  const body = await readJson(request);
  const entries = Array.isArray(body?.entries) ? body.entries : null;
  const host = typeof body?.host_id === "string" && body.host_id.length > 0 && body.host_id.length <= 128
    ? body.host_id : null;
  if (!entries || !host) return json({ error: "valid host_id + entries required" }, 400);
  if (entries.length > Number(env.MAX_ENTRIES)) return json({ error: "too many entries" }, 413);
  // WRITE-GATE on enrollment: an unenrolled host_id must NOT create sightings /
  // offenders (round-2 review: a leaked write token spamming random host_ids
  // would otherwise bloat sightings + emit count-0 IPs to every consumer).
  if (!(await isEnrolled(env, host))) return json({ accepted: 0, rejected: entries.length, enrolled: false }, 200);
  const now = nowSec();
  let accepted = 0, rejected = 0;
  for (const e of entries) {
    const eip = e?.ip;
    if (typeof eip !== "string" || !isValidIpOrCidr(eip) || isUnsafeTarget(eip)) { rejected++; continue; }
    await contributeOne(env, { ip: eip, host, category: e.category, now });
    accepted++;
  }
  return json({ accepted, rejected, enrolled: true }, 200);
}

async function handleRegister(request, env) {
  if (!checkAuth(request, env.SWARM_ENROLL_TOKEN)) return json({ error: "unauthorized" }, 401);
  const body = await readJson(request);
  const host = typeof body?.host_id === "string" ? body.host_id : null;
  if (!host) return json({ error: "host_id required" }, 400);
  await registerHost(env, { host, label: body.label, now: nowSec() });
  return json({ enrolled: host }, 200);
}

async function handleFeed(request, env) {
  if (!checkAuth(request, env.SWARM_READ_TOKEN)) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const { rows, truncated } = await feedRows(env, { now: nowSec(), limit: url.searchParams.get("limit") });
  const headers = truncated ? { "x-swarm-truncated": "true" } : {};
  if (url.searchParams.get("format") === "json") return json(rows, 200, headers);
  const body = rows.map(r => r.ip).join("\n") + (rows.length ? "\n" : "");
  return new Response(body, { status: 200, headers: { "content-type": "text/plain; charset=utf-8", ...headers } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const m = request.method;
    if (m === "GET" && url.pathname === "/health") return json({ ok: true });
    if (m === "POST" && url.pathname === "/contribute") return handleContribute(request, env);
    if (m === "POST" && url.pathname === "/register") return handleRegister(request, env);
    if (m === "GET" && url.pathname === "/feed") return handleFeed(request, env);
    return new Response("not found", { status: 404 });
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(prune(env, { now: nowSec() }).then(
      (d) => console.log(`swarm prune: ${d.offenders} offenders, ${d.sightings} sightings`),
      (err) => console.error(`swarm prune FAILED: ${err?.message || err}`)   // surfaced, not swallowed
    ));
  },
};
```

- [ ] **Step 4: Run — verify it passes + full suite green**

Run: `cd hub && npm test`
Expected: PASS (health, validate, auth, db-register, db-contribute, db-feed, db-prune, routes).

- [ ] **Step 5: Commit**

```bash
git add hub/src/index.js hub/test/routes.test.js
git commit -m "feat(swarm-hub): routes (contribute/register/feed) with auth, caps, empty/truncation, IP-keyed rate limit + surfaced prune"
```

---

### Task 9: Deploy runbook (README)

**Files:**
- Create: `hub/README.md`

**Interfaces:** none (docs).

- [ ] **Step 1: `hub/README.md`**

````markdown
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
````

- [ ] **Step 2: Commit**

```bash
git add hub/README.md
git commit -m "docs(swarm-hub): deploy + enroll runbook"
```

---

## Self-Review

- **Spec coverage (v3):** contribute/register/feed/prune → Tasks 4–8. Read-time registry-gated `host_count` (§4.2/§5/§6) → Task 6 (+ concurrency + registry-gate + TTL tests). IP-or-CIDR (§4.2) → Task 2 + Task 5/8. Three tokens (§4.4) → Tasks 3,8 + README. Empty-feed-is-empty-200 (§4.2) → Task 8. Payload cap + truncation signalling (§4.2) → Task 8/6. Connecting-IP rate limit (§4.2) → Task 8. Prune + failure surfacing (§4.2/§12) → Tasks 7,8. Schema (§5) → Task 1 migration. Packaging/enroll (§10) → Task 9. **Gap:** cursor pagination beyond `FEED_MAX` is signalled (`X-Swarm-Truncated`) but not implemented — documented fast-follow, acceptable at single-operator fleet scale.
- **Placeholder scan:** none. Task 1 Step 5 has an explicit fallback note (not a placeholder — a concrete alternative if the migration API differs). The 429 test uses env-injection (a real, supported mechanism), not the unsupported function-binding.
- **Type consistency:** `registerHost`/`contributeOne`/`feedRows`(`{rows,truncated}`)/`prune`(`{offenders,sightings}`)/`checkAuth`/`isValidIpOrCidr`/`isUnsafeTarget` names + shapes are identical across defining and consuming tasks. Contract (`{host_id, entries:[{ip,category}]}`, `{host_id,label}`, bare/json feed, `X-Swarm-Truncated`) matches what the host-side plan will consume.

## Execution Handoff

Subsystem 1 of 2. After green + deployed + a box enrolled, the host-side plan
(`…-swatter-swarm-host.md`, to be written) implements the bash `provider_swarm`,
publish, consume (bare feed → clear-on-empty; json → `host_count`), the fleet
allowlist, and `swatter swarm enroll`/`disable` against this frozen contract.
