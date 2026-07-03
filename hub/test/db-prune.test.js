import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { contributeOne, prune, registerHost } from "../src/db.js";
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
