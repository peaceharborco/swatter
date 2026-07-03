import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { contributeOne } from "../src/db.js";
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
