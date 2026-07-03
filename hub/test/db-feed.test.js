import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { contributeOne, feedRows, registerHost } from "../src/db.js";
const now = 1_800_000_000;

// Pool 0.13.x (Vitest-4 rewrite) has no per-test isolatedStorage — storage is
// isolated per test FILE only. Reset tables so each test starts clean.
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings"),
    env.DB.prepare("DELETE FROM offenders"),
    env.DB.prepare("DELETE FROM hosts"),
  ]);
});

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
