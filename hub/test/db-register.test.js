import { env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { registerHost, isEnrolled } from "../src/db.js";

// Pool 0.13.x (Vitest-4 rewrite) has no per-test isolatedStorage — storage is
// isolated per test FILE only. Reset tables so each test starts clean.
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings"),
    env.DB.prepare("DELETE FROM offenders"),
    env.DB.prepare("DELETE FROM hosts"),
  ]);
});

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
