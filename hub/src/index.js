import { checkAuth } from "./auth.js";
import { isValidIpOrCidr, isUnsafeTarget } from "./validate.js";
import { contributeOne, registerHost, isEnrolled, feedRows, prune } from "./db.js";

const nowSec = () => Math.floor(Date.now() / 1000);
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });
}
async function readJson(request) { try { return await request.json(); } catch { return null; } }

async function handleContribute(request, env) {
  if (!checkAuth(request, env.SWARM_WRITE_TOKEN)) return json({ error: "unauthorized" }, 401);
  // Per-connecting-IP AND global limits (spec §4.2) — global bounds a distributed
  // leaked-token holder the per-IP one can't.
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.CONTRIBUTE_LIMITER && !(await env.CONTRIBUTE_LIMITER.limit({ key: ip })).success)
    return json({ error: "rate limited" }, 429);
  if (env.GLOBAL_LIMITER && !(await env.GLOBAL_LIMITER.limit({ key: "global" })).success)
    return json({ error: "rate limited" }, 429);
  const body = await readJson(request);
  const entries = Array.isArray(body?.entries) ? body.entries : null;
  const host = typeof body?.host_id === "string" && body.host_id.length > 0 && body.host_id.length <= 128
    ? body.host_id : null;
  if (!entries || !host) return json({ error: "valid host_id + entries required" }, 400);
  if (entries.length > Number(env.MAX_ENTRIES)) return json({ error: "too many entries" }, 413);
  // WRITE-GATE on enrollment: an unenrolled host_id must NOT create sightings /
  // offenders (round-2 review: a leaked write token spamming random host_ids
  // would otherwise bloat sightings + emit count-0 IPs to every consumer).
  if (!(await isEnrolled(env, host))) return json({ accepted: 0, rejected: entries.length, enrolled: false }, 200);
  const now = nowSec();
  let accepted = 0, rejected = 0;
  for (const e of entries) {
    const eip = e?.ip;
    if (typeof eip !== "string" || !isValidIpOrCidr(eip) || isUnsafeTarget(eip)) { rejected++; continue; }
    await contributeOne(env, { ip: eip, host, category: e.category, now });
    accepted++;
  }
  return json({ accepted, rejected, enrolled: true }, 200);
}

async function handleRegister(request, env) {
  if (!checkAuth(request, env.SWARM_ENROLL_TOKEN)) return json({ error: "unauthorized" }, 401);
  const body = await readJson(request);
  const host = typeof body?.host_id === "string" ? body.host_id : null;
  if (!host) return json({ error: "host_id required" }, 400);
  await registerHost(env, { host, label: body.label, now: nowSec() });
  return json({ enrolled: host }, 200);
}

async function handleFeed(request, env) {
  if (!checkAuth(request, env.SWARM_READ_TOKEN)) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const { rows, truncated } = await feedRows(env, { now: nowSec(), limit: url.searchParams.get("limit") });
  const headers = truncated ? { "x-swarm-truncated": "true" } : {};
  if (url.searchParams.get("format") === "json") return json(rows, 200, headers);
  const body = rows.map(r => r.ip).join("\n") + (rows.length ? "\n" : "");
  return new Response(body, { status: 200, headers: { "content-type": "text/plain; charset=utf-8", ...headers } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const m = request.method;
    if (m === "GET" && url.pathname === "/health") return json({ ok: true });
    if (m === "POST" && url.pathname === "/contribute") return handleContribute(request, env);
    if (m === "POST" && url.pathname === "/register") return handleRegister(request, env);
    if (m === "GET" && url.pathname === "/feed") return handleFeed(request, env);
    return new Response("not found", { status: 404 });
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(prune(env, { now: nowSec() }).then(
      (d) => console.log(`swarm prune: ${d.offenders} offenders, ${d.sightings} sightings`),
      (err) => console.error(`swarm prune FAILED: ${err?.message || err}`)   // surfaced, not swallowed
    ));
  },
};
