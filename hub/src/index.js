import { checkAuth } from "./auth.js";
import { isValidIpOrCidr, isUnsafeTarget } from "./validate.js";
import { contributeMany, registerHost, isEnrolled, feedRows, prune, purgeHost } from "./db.js";

const nowSec = () => Math.floor(Date.now() / 1000);
// ONE host_id rule for /register AND /contribute (Grok review: register
// accepted ids contribute then 400-rejected, bricking the enroll→publish
// lifecycle). Printable ASCII, no spaces, 1-128 chars.
const validHostId = (h) => typeof h === "string" && /^[\x21-\x7e]{1,128}$/.test(h);
// Refuse to parse oversized bodies: entries are COUNT-capped only after a full
// request.json(), so cap bytes first (Grok review).
const MAX_BODY_BYTES = 1_048_576;
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...headers } });
}
// Read the JSON body, enforcing MAX_BODY_BYTES with OR without a Content-Length
// header — a chunked/streamed body carries no CL and would bypass a header-only
// check. request.text() is itself bounded by the Workers platform request-size
// limit, so this can't buffer unboundedly. Returns { tooLarge, body }; body is
// null on oversize or malformed JSON.
async function readBody(request) {
  const clen = Number(request.headers.get("content-length"));
  if (Number.isFinite(clen) && clen > MAX_BODY_BYTES) return { tooLarge: true, body: null };
  let text;
  try { text = await request.text(); } catch { return { tooLarge: false, body: null }; }
  if (text.length > MAX_BODY_BYTES) return { tooLarge: true, body: null };
  try { return { tooLarge: false, body: JSON.parse(text) }; } catch { return { tooLarge: false, body: null }; }
}

async function handleContribute(request, env) {
  if (!checkAuth(request, env.SWARM_WRITE_TOKEN)) return json({ error: "unauthorized" }, 401);
  // Per-connecting-IP AND global limits (spec §4.2) — global bounds a distributed
  // leaked-token holder the per-IP one can't.
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.CONTRIBUTE_LIMITER && !(await env.CONTRIBUTE_LIMITER.limit({ key: ip })).success)
    return json({ error: "rate limited" }, 429);
  if (env.GLOBAL_LIMITER && !(await env.GLOBAL_LIMITER.limit({ key: "global" })).success)
    return json({ error: "rate limited" }, 429);
  const { tooLarge, body } = await readBody(request);
  if (tooLarge) return json({ error: "body too large" }, 413);
  const entries = Array.isArray(body?.entries) ? body.entries : null;
  const host = validHostId(body?.host_id) ? body.host_id : null;
  if (!entries || !host) return json({ error: "valid host_id + entries required" }, 400);
  if (entries.length > Number(env.MAX_ENTRIES)) return json({ error: "too many entries" }, 413);
  // WRITE-GATE on enrollment: an unenrolled host_id must NOT create sightings /
  // offenders (round-2 review: a leaked write token spamming random host_ids
  // would otherwise bloat sightings + emit count-0 IPs to every consumer).
  if (!(await isEnrolled(env, host))) return json({ accepted: 0, rejected: entries.length, enrolled: false }, 200);
  const now = nowSec();
  const valid = [];
  let rejected = 0;
  for (const e of entries) {
    const eip = e?.ip;
    if (typeof eip !== "string" || !isValidIpOrCidr(eip) || isUnsafeTarget(eip)) { rejected++; continue; }
    // Sanitize category: a non-string would throw D1_TYPE_ERROR (a bare 500 —
    // outside the frozen error set); an unbounded string bloats offenders.
    const category = typeof e.category === "string" && e.category.length <= 64 ? e.category : null;
    valid.push({ ip: eip, category });
  }
  await contributeMany(env, { entries: valid, host, now });
  return json({ accepted: valid.length, rejected, enrolled: true }, 200);
}

async function handleRegister(request, env) {
  if (!checkAuth(request, env.SWARM_ENROLL_TOKEN)) return json({ error: "unauthorized" }, 401);
  const { tooLarge, body } = await readBody(request);
  if (tooLarge) return json({ error: "body too large" }, 413);
  const host = validHostId(body?.host_id) ? body.host_id : null;
  if (!host) return json({ error: "valid host_id required (1-128 printable chars)" }, 400);
  const label = typeof body.label === "string" && body.label.length <= 256 ? body.label : null;
  await registerHost(env, { host, label, now: nowSec() });
  return json({ enrolled: host }, 200);
}

async function handlePurge(request, env) {
  if (!checkAuth(request, env.SWARM_WRITE_TOKEN)) return json({ error: "unauthorized" }, 401);
  const { tooLarge, body } = await readBody(request);
  if (tooLarge) return json({ error: "body too large" }, 413);
  const host = validHostId(body?.host_id) ? body.host_id : null;
  if (!host) return json({ error: "valid host_id required" }, 400);
  const d = await purgeHost(env, { host });
  return json({ purged_sightings: d.sightings, purged_offenders: d.offenders }, 200);
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
    if (m === "POST" && url.pathname === "/purge") return handlePurge(request, env);
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
