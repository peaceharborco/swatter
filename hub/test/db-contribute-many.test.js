import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { contributeMany, registerHost, feedRows } from "../src/db.js";
const now = 1_800_000_000;

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings"),
    env.DB.prepare("DELETE FROM offenders"),
    env.DB.prepare("DELETE FROM hosts"),
  ]);
});

describe("contributeMany (chunked batches)", () => {
  it("writes a batch larger than one chunk (120 entries) completely", async () => {
    await registerHost(env, { host: "boxA", now });
    const entries = Array.from({ length: 120 }, (_, i) => ({
      ip: "10.1." + ((i >> 8) & 255) + "." + (i & 255), category: "scan",
    }));
    await contributeMany(env, { entries, host: "boxA", now });
    const o = await env.DB.prepare("SELECT COUNT(*) c FROM offenders").first();
    const s = await env.DB.prepare("SELECT COUNT(*) c FROM sightings").first();
    expect(o.c).toBe(120);
    expect(s.c).toBe(120);
    const { rows } = await feedRows(env, { now, limit: 200 });
    expect(rows.length).toBe(120);
    expect(rows.every(r => r.host_count === 1)).toBe(true);
  });

  it("upserts within one call (same ip twice stays one row)", async () => {
    await registerHost(env, { host: "boxA", now });
    await contributeMany(env, {
      entries: [{ ip: "1.2.3.4", category: "a" }, { ip: "1.2.3.4", category: "b" }],
      host: "boxA", now,
    });
    const o = await env.DB.prepare("SELECT COUNT(*) c, MAX(category) cat FROM offenders").first();
    expect(o.c).toBe(1);
  });
});
