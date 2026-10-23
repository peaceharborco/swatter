import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src/index.js";

// 2026-10-23 audit: feed poisoning, feed eviction, pre-auth limiter drain, and
// numeric [vars] that failed open. Each case here reproduced on the old code.
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings"),
    env.DB.prepare("DELETE FROM offenders"),
    env.DB.prepare("DELETE FROM hosts"),
  ]);
});
const call = async (path, init, envOverride) => {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request("https://hub" + path, init), envOverride ?? env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
};
const R = { authorization: "Bearer " + env.SWARM_READ_TOKEN };
const E = { authorization: "Bearer " + env.SWARM_ENROLL_TOKEN, "content-type": "application/json" };
async function enroll(host) {
  const j = await (await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: host }) })).json();
  return { authorization: "Bearer " + j.token, "content-type": "application/json" };
}
const post = (T, entries, e) => call("/contribute", { method: "POST", headers: T, body: JSON.stringify({ entries }) }, e);
const feed = async (e) => (await (await call("/feed", { headers: R }, e)).text()).split("\n").filter(Boolean);

describe("feed poisoning", () => {
  it("one enrolled host cannot push reserved space or a wide prefix into the fleet feed", async () => {
    const T = await enroll("boxA");
    const bad = ["10.0.0.0/8", "127.0.0.1", "192.168.0.0/16", "169.254.0.0/16", "128.0.0.0/1",
                 "1.0.0.0/1", "32.0.0.0/3", "fc00::/7", "::1", "fe80::/10", "100.64.0.0/10"];
    const res = await post(T, [...bad.map((ip) => ({ ip })), { ip: "203.0.113.9" }]);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: 1, rejected: bad.length, enrolled: true });
    expect(await feed()).toEqual(["203.0.113.9"]);
  });
  it("a /24 (the floor) is still publishable; a /23 is not", async () => {
    const T = await enroll("boxA");
    expect(await (await post(T, [{ ip: "45.33.0.0/24" }, { ip: "45.33.0.0/23" }, { ip: "2001:db8::/64" }, { ip: "2001:db8::/63" }])).json())
      .toEqual({ accepted: 2, rejected: 2, enrolled: true });
  });
});

describe("feed truncation keeps the most corroborated rows", () => {
  it("a host publishing lexically low addresses cannot evict another host's corroborated row", async () => {
    const small = { ...env, FEED_MAX: "3" };
    const A = await enroll("boxA"), B = await enroll("boxB");
    await post(B, [{ ip: "9.9.9.9" }], small);
    await post(A, [{ ip: "9.9.9.9" }, { ip: "1.1.1.1" }, { ip: "1.1.1.2" }, { ip: "1.1.1.3" }, { ip: "1.1.1.4" }], small);
    const res = await call("/feed?format=json", { headers: R }, small);
    expect(res.headers.get("x-swarm-truncated")).toBe("true");
    const rows = await res.json();
    expect(rows.length).toBe(3);
    expect(rows[0].ip).toBe("9.9.9.9");          // host_count 2 sorts first
    expect(rows[0].host_count).toBe(2);
  });
  it("sightings from an un-enrolled host do not count toward host_count", async () => {
    const A = await enroll("boxA");
    await post(A, [{ ip: "9.9.9.9" }]);
    await env.DB.prepare("INSERT INTO sightings (ip, host, last_seen) VALUES ('9.9.9.9', 'ghost', ?)").bind(Math.floor(Date.now() / 1000)).run();
    const rows = await (await call("/feed?format=json", { headers: R })).json();
    expect(rows[0].host_count).toBe(1);
  });
});

describe("per-host live-row quota", () => {
  it("a host at HOST_MAX gets 429 (cursor kept); other hosts are unaffected", async () => {
    const q = { ...env, HOST_MAX: "3" };
    const A = await enroll("boxA"), B = await enroll("boxB");
    expect((await post(A, [{ ip: "5.5.5.1" }, { ip: "5.5.5.2" }, { ip: "5.5.5.3" }], q)).status).toBe(200);
    const over = await post(A, [{ ip: "5.5.5.4" }], q);
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: "host quota exceeded", live: 3, max: 3 });
    expect((await post(B, [{ ip: "5.5.5.4" }], q)).status).toBe(200);
    expect((await feed(q)).sort()).toEqual(["5.5.5.1", "5.5.5.2", "5.5.5.3", "5.5.5.4"]);
  });
  it("the whole batch has to fit under HOST_MAX (no overshoot by one body)", async () => {
    const q = { ...env, HOST_MAX: "3" };
    const A = await enroll("boxA");
    expect((await post(A, [{ ip: "5.5.6.1" }, { ip: "5.5.6.2" }], q)).status).toBe(200);   // live 2
    const over = await post(A, [{ ip: "5.5.6.3" }, { ip: "5.5.6.4" }], q);                 // 2 + 2 > 3
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: "host quota exceeded", live: 2, max: 3, batch: 2 });
    expect((await post(A, [{ ip: "5.5.6.3" }], q)).status).toBe(200);                        // 2 + 1 = 3 fits
    expect((await feed(q)).sort()).toEqual(["5.5.6.1", "5.5.6.2", "5.5.6.3"]);
  });
});

describe("rate limiters", () => {
  const spy = () => { const s = { n: 0, limit: async () => { s.n++; return { success: true }; } }; return s; };
  it("an unauthenticated POST charges the per-IP limiter but never the global one", async () => {
    const ipL = spy(), gL = spy();
    const e = { ...env, CONTRIBUTE_LIMITER: ipL, GLOBAL_LIMITER: gL };
    const res = await call("/contribute", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, e);
    expect(res.status).toBe(401);
    expect(ipL.n).toBe(1);
    expect(gL.n).toBe(0);
  });
  it("an authenticated POST charges both", async () => {
    const ipL = spy(), gL = spy();
    const e = { ...env, CONTRIBUTE_LIMITER: ipL, GLOBAL_LIMITER: gL };
    const T = await enroll("boxA");
    expect((await post(T, [{ ip: "6.6.6.6" }], e)).status).toBe(200);
    expect(ipL.n).toBe(1);
    expect(gL.n).toBe(1);
  });
});

describe("numeric [vars] fail loud, not open", () => {
  it.each([["MAX_ENTRIES", "abc"], ["MAX_ENTRIES", ""], ["MAX_ENTRIES", "1e3"], ["SWARM_TTL", ""],
           ["SWARM_TTL", "0"], ["HOST_MAX", "-1"], ["FEED_MAX", "50 000"]])(
    "%s=%j makes /contribute and /feed a 500, never a 200 (and never an empty feed)", async (k, v) => {
      const e = { ...env, [k]: v };
      const T = await enroll("boxA");
      await post(T, [{ ip: "7.7.7.7" }]);                 // a real row, with the good config
      const c = await post(T, [{ ip: "7.7.7.8" }], e);
      expect(c.status).toBe(500);
      expect(await c.json()).toEqual({ error: "hub error" });   // no config value in the body
      const f = await call("/feed", { headers: R }, e);
      expect(f.status).toBe(500);                          // NOT a 200 with an empty body
      expect(await feed()).toEqual(["7.7.7.7"]);           // nothing was written under the bad config
    });
  it("a 1001-entry batch is refused when MAX_ENTRIES is garbage, not accepted", async () => {
    const T = await enroll("boxA");
    const many = Array.from({ length: 1001 }, (_, i) => ({ ip: "198.18." + ((i >> 8) & 255) + "." + (i & 255) }));
    expect((await post(T, many, { ...env, MAX_ENTRIES: "abc" })).status).toBe(500);
    expect(await feed()).toEqual([]);
  });
});

describe("legacy /purge", () => {
  it("a never-enrolled legacy host_id purges nothing", async () => {
    const W = { authorization: "Bearer " + env.SWARM_WRITE_TOKEN, "content-type": "application/json" };
    const A = await enroll("boxA");
    await post(A, [{ ip: "8.8.8.8" }]);
    const res = await call("/purge", { method: "POST", headers: W, body: JSON.stringify({ host_id: "never-enrolled" }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ purged_sightings: 0, purged_offenders: 0 });
    expect(await feed()).toEqual(["8.8.8.8"]);
  });
});
