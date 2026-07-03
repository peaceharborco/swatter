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
