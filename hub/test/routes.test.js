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
// Enroll a host and return its per-host write headers (the shared write token is
// refused for a migrated host). Registered hosts now authenticate by their token.
async function enroll(host, label) {
  const j = await (await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: host, label }) })).json();
  return { authorization: "Bearer " + j.token, "content-type": "application/json" };
}

describe("routes", () => {
  it("contribute rejects a read token; register rejects a write token", async () => {
    expect((await call("/contribute", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_READ_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "h", entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(401);
    expect((await call("/register", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_WRITE_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "h" }) })).status).toBe(401);
  });

  it("register then contribute makes the host count", async () => {
    const T = await enroll("boxA", "cds1");
    const res = await call("/contribute", { method: "POST", headers: T,
      body: JSON.stringify({ entries: [
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
    const T = await enroll("boxA");
    await call("/contribute", { method: "POST", headers: T, body: JSON.stringify({ entries: [{ ip: "203.0.113.7" }, { ip: "198.51.100.0/24" }] }) });
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
    const T = await enroll("boxA");
    const many = Array.from({ length: Number(env.MAX_ENTRIES) + 1 }, (_, i) => ({ ip: "10.0." + ((i>>8)&255) + "." + (i&255) }));
    const res = await call("/contribute", { method: "POST", headers: T, body: JSON.stringify({ entries: many }) });
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
    const T = await enroll("boxA");
    const res = await call("/contribute", { method: "POST", headers: T,
      body: JSON.stringify({ entries: [{ ip: "1.2.3.4", category: { bad: 1 } }, { ip: "5.6.7.8", category: 123 }] }) });
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
    const T = await enroll("boxA");
    await call("/contribute", { method: "POST", headers: T,
      body: JSON.stringify({ entries: [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }] }) });
    const capped = await call("/feed?limit=1", { headers: R });
    expect((await capped.text()).trim()).toBe("1.1.1.1");
    expect(capped.headers.get("x-swarm-truncated")).toBe("true");
    const garbage = await call("/feed?limit=0", { headers: R });   // clamps to FEED_MAX
    expect((await garbage.text()).trim().split("\n").length).toBe(2);
    expect(garbage.headers.get("x-swarm-truncated")).toBe(null);
  });

  it("json feed rows carry the exact frozen shape", async () => {
    const T = await enroll("boxA");
    await call("/contribute", { method: "POST", headers: T,
      body: JSON.stringify({ entries: [{ ip: "9.9.9.9", category: "scan" }] }) });
    const rows = await (await call("/feed?format=json", { headers: R })).json();
    expect(rows.length).toBe(1);
    expect(Object.keys(rows[0]).sort()).toEqual(["category", "expires", "host_count", "ip"]);
    expect(rows[0].ip).toBe("9.9.9.9");
    expect(rows[0].host_count).toBe(1);
    expect(rows[0].category).toBe("scan");
    expect(typeof rows[0].expires).toBe("number");
  });

  it("full MAX_ENTRIES batch succeeds (chunked, no per-entry round trips)", async () => {
    const T = await enroll("boxA");
    const many = Array.from({ length: Number(env.MAX_ENTRIES) }, (_, i) => ({ ip: "10.2." + ((i>>8)&255) + "." + (i&255) }));
    const res = await call("/contribute", { method: "POST", headers: T, body: JSON.stringify({ entries: many }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: many.length, rejected: 0, enrolled: true });
  });
});

describe("per-host tokens", () => {
  const bearerHdr = (t) => ({ authorization: "Bearer " + t, "content-type": "application/json" });

  it("register issues a token once; plain re-enroll returns none; --rotate reissues + invalidates", async () => {
    const r1 = await (await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA", label: "a" }) })).json();
    expect(typeof r1.token).toBe("string");
    expect(r1.rotated).toBe(false);
    const tok1 = r1.token;
    // Plain re-enroll: label update, NO new token (can't silently rotate/take over).
    const r2 = await (await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA", label: "b" }) })).json();
    expect(r2.token).toBeUndefined();
    expect(r2.rotated).toBe(false);
    expect((await call("/contribute", { method: "POST", headers: bearerHdr(tok1), body: JSON.stringify({ entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(200);
    // Explicit rotate: new token, old token now 401s.
    const r3 = await (await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA", rotate: true }) })).json();
    expect(typeof r3.token).toBe("string");
    expect(r3.token).not.toBe(tok1);
    expect(r3.rotated).toBe(true);
    expect((await call("/contribute", { method: "POST", headers: bearerHdr(tok1), body: JSON.stringify({ entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(401);
    expect((await call("/contribute", { method: "POST", headers: bearerHdr(r3.token), body: JSON.stringify({ entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(200);
  });

  it("a per-host token is bound to its host regardless of body host_id", async () => {
    const A = await enroll("boxA");
    const B = await enroll("boxB");
    await call("/contribute", { method: "POST", headers: B, body: JSON.stringify({ entries: [{ ip: "7.7.7.7" }] }) });
    // boxA's token but a body forging boxB: if the token wins, host_count becomes 2.
    await call("/contribute", { method: "POST", headers: A, body: JSON.stringify({ host_id: "boxB", entries: [{ ip: "7.7.7.7" }] }) });
    const rows = await (await call("/feed?format=json", { headers: R })).json();
    expect(rows.find(r => r.ip === "7.7.7.7").host_count).toBe(2);   // boxA + boxB, forged id ignored
  });

  it("the shared write token is REFUSED for a migrated host", async () => {
    await enroll("boxA");   // boxA has a token_hash -> migrated
    const res = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.2.3.4" }] }) });
    expect(res.status).toBe(401);
  });

  it("the shared write token still works for an UN-migrated (legacy) host", async () => {
    await env.DB.prepare("INSERT INTO hosts (host, enrolled_at, label, token_hash) VALUES (?1, ?2, NULL, NULL)").bind("legacyBox", 1000).run();
    const res = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "legacyBox", entries: [{ ip: "1.2.3.4" }] }) });
    expect(res.status).toBe(200);
    expect((await res.json()).enrolled).toBe(true);
  });

  it("a bad or absent write credential is 401", async () => {
    expect((await call("/contribute", { method: "POST", headers: bearerHdr("nope"), body: JSON.stringify({ entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(401);
    expect((await call("/contribute", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ entries: [{ ip: "1.2.3.4" }] }) })).status).toBe(401);
  });

  it("purge with a per-host token cannot purge another host", async () => {
    const A = await enroll("boxA");
    const B = await enroll("boxB");
    await call("/contribute", { method: "POST", headers: A, body: JSON.stringify({ entries: [{ ip: "1.1.1.1" }] }) });
    await call("/contribute", { method: "POST", headers: B, body: JSON.stringify({ entries: [{ ip: "2.2.2.2" }] }) });
    await call("/purge", { method: "POST", headers: A, body: JSON.stringify({ host_id: "boxB" }) });   // A's token, forges boxB
    const ips = (await (await call("/feed", { headers: R })).text()).trim().split("\n").sort();
    expect(ips).toEqual(["2.2.2.2"]);   // boxA's own IP purged; boxB untouched
  });

  it("SWARM_LEGACY_WRITE_UNTIL in the past refuses the shared write token", async () => {
    await env.DB.prepare("INSERT INTO hosts (host, enrolled_at, label, token_hash) VALUES (?1, ?2, NULL, NULL)").bind("legacyBox", 1000).run();
    const pastEnv = { ...env, SWARM_LEGACY_WRITE_UNTIL: "1" };
    const res = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "legacyBox", entries: [{ ip: "1.2.3.4" }] }) }, pastEnv);
    expect(res.status).toBe(401);
  });
});
