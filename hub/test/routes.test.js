import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src/index.js";

// Pool 0.13.x isolates storage per test FILE, not per test — reset tables so
// each test starts from the clean slate the plan's assertions assume.
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
    // Frozen contract: /contribute returns {accepted, rejected, enrolled}.
    expect(await res.json()).toEqual({ accepted: 1, rejected: 2, enrolled: true });   // garbage+unsafe rejected
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

describe("routes (grok-review hardening)", () => {
  it("register and contribute share ONE host_id rule (no brickable enrolls)", async () => {
    const long = "x".repeat(129);
    expect((await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: long }) })).status).toBe(400);
    expect((await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "   " }) })).status).toBe(400);
    expect((await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "x".repeat(128) }) })).status).toBe(200);
  });

  it("non-string category does not 500 — stored as null", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    const res = await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.2.3.4", category: { bad: 1 } }, { ip: "5.6.7.8", category: 123 }] }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: 2, rejected: 0, enrolled: true });
    const feed = await (await call("/feed?format=json", { headers: R })).json();
    expect(feed.find(r => r.ip === "1.2.3.4").category).toBe(null);
    expect(feed.find(r => r.ip === "5.6.7.8").category).toBe(null);
  });

  it("rejects an oversized body with 413 before parsing", async () => {
    // workerd's test Request doesn't auto-set content-length; real clients do.
    const res = await call("/contribute", { method: "POST",
      headers: { ...W, "content-length": String(2_000_000) },
      body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.2.3.4" }] }) });
    expect(res.status).toBe(413);
  });

  it("rejects an oversized body with NO content-length (chunked) with 413", async () => {
    // The header-only check missed a chunked/streamed body; the byte cap in
    // readBody must still reject it even with no content-length set.
    const big = "x".repeat(1_100_000);
    const res = await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "boxA", pad: big, entries: [{ ip: "1.2.3.4" }] }) });
    expect(res.status).toBe(413);
  });

  it("malformed JSON body returns 400", async () => {
    const res = await call("/contribute", { method: "POST", headers: W, body: "{not json" });
    expect(res.status).toBe(400);
  });

  it("?limit clamps and signals truncation over HTTP", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }] }) });
    const capped = await call("/feed?limit=1", { headers: R });
    expect((await capped.text()).trim()).toBe("1.1.1.1");
    expect(capped.headers.get("x-swarm-truncated")).toBe("true");
    const garbage = await call("/feed?limit=0", { headers: R });   // clamps to FEED_MAX
    expect((await garbage.text()).trim().split("\n").length).toBe(2);
    expect(garbage.headers.get("x-swarm-truncated")).toBe(null);
  });

  it("json feed rows carry the exact frozen shape", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    await call("/contribute", { method: "POST", headers: W,
      body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "9.9.9.9", category: "scan" }] }) });
    const rows = await (await call("/feed?format=json", { headers: R })).json();
    expect(rows.length).toBe(1);
    expect(Object.keys(rows[0]).sort()).toEqual(["category", "expires", "host_count", "ip"]);
    expect(rows[0].ip).toBe("9.9.9.9");
    expect(rows[0].host_count).toBe(1);
    expect(rows[0].category).toBe("scan");
    expect(typeof rows[0].expires).toBe("number");
  });

  it("full MAX_ENTRIES batch succeeds (chunked, no per-entry round trips)", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    const many = Array.from({ length: Number(env.MAX_ENTRIES) }, (_, i) => ({ ip: "10.2." + ((i>>8)&255) + "." + (i&255) }));
    const res = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: many }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: many.length, rejected: 0, enrolled: true });
  });
});
