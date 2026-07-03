import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src/index.js";

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings"),
    env.DB.prepare("DELETE FROM offenders"),
    env.DB.prepare("DELETE FROM hosts"),
  ]);
});

const call = async (path, init) => {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request("https://hub" + path, init), env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
};
const W = { authorization: "Bearer " + env.SWARM_WRITE_TOKEN, "content-type": "application/json" };
const E = { authorization: "Bearer " + env.SWARM_ENROLL_TOKEN, "content-type": "application/json" };
const R = { authorization: "Bearer " + env.SWARM_READ_TOKEN };

describe("POST /purge", () => {
  it("removes the host's sightings and orphaned offenders, keeps corroborated ones", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxB" }) });
    await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }] }) });
    await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxB", entries: [{ ip: "2.2.2.2" }] }) });

    const res = await call("/purge", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA" }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ purged_sightings: 2, purged_offenders: 1 });

    // 1.1.1.1 (boxA-only) is gone; 2.2.2.2 survives via boxB's sighting.
    const feed = (await (await call("/feed", { headers: R })).text()).trim();
    expect(feed).toBe("2.2.2.2");
    // boxA stays ENROLLED (purge is data-removal, not unenrollment).
    const again = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "3.3.3.3" }] }) });
    expect((await again.json()).enrolled).toBe(true);
  });

  it("rejects read/enroll tokens and bad host_ids", async () => {
    expect((await call("/purge", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_READ_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "x" }) })).status).toBe(401);
    expect((await call("/purge", { method: "POST", headers: W, body: JSON.stringify({ host_id: "" }) })).status).toBe(400);
  });
});
