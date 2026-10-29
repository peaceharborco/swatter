import { checkAuth } from "./auth.js";
import { isValidIpOrCidr, isUnsafeTarget } from "./validate.js";
import { cfg } from "./config.js";
import { contributeMany, registerHost, hostForToken, hostTokenState, isEnrolled, hostLiveCount, feedRows, prune, purgeHost } from "./db.js";
import { guardWorker } from "./coastguard.ts"; // toolbox/coastguard halt guard

const nowSec = () => Math.floor(Date.now() / 1000);
const bearer = (request) => {
  const m = (request.headers.get("authorization") || "").match(/^Bearer (.+)$/);
  return m ? m[1] : null;
};
// The shared write token is retired once SWARM_LEGACY_WRITE_UNTIL (unix ts) passes.
const legacyWriteExpired = (env) => {
  const until = Number(env.SWARM_LEGACY_WRITE_UNTIL);
  return Number.isFinite(until) && until > 0 && nowSec() > until;
};
// Resolve the authenticated writer host for /contribute and /purge:
//   1. a per-host token -> that host (body host_id IGNORED);
//   2. else the legacy shared write token -> body host_id, but ONLY while it is
//      un-migrated (token_hash NULL) and the legacy window is open — a migrated
//      host can never be written via the shared token;
//   3. else unauthorized.
// Returns { host } on success, or { status, error } to return directly.
async function authWriteIdentity(request, env, body) {
  const tokHost = await hostForToken(env, bearer(request));
  if (tokHost) return { host: tokHost };
  if (checkAuth(request, env.SWARM_WRITE_TOKEN)) {
    if (legacyWriteExpired(env)) return { status: 401, error: { error: "shared write token retired — use a per-host token" } };
    const bodyHost = validHostId(body?.host_id) ? body.host_id : null;
    if (!bodyHost) return { status: 400, error: { error: "valid host_id required" } };
    if ((await hostTokenState(env, bodyHost)).migrated)
      return { status: 401, error: { error: "host uses a per-host token; shared write token refused" } };
    return { host: bodyHost };   // un-migrated or no row (isEnrolled gate handles no-row)
  }
  return { status: 401, error: { error: "unauthorized" } };
}
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
  // Byte length, not char count — a multi-byte body can exceed the cap on the wire
  // while text.length (UTF-16 code units) stays under it.
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return { tooLarge: true, body: null };
  try { return { tooLarge: false, body: JSON.parse(text) }; } catch { return { tooLarge: false, body: null }; }
}

async function handleContribute(request, env) {
  const { ttl, maxEntries, hostMax } = cfg(env);   // throws on a bad var -> 500, never an open gate
  // Per-connecting-IP limit first (cheap, no DB), then authenticate, and only
  // THEN charge the GLOBAL limit (spec §4.2: it bounds a distributed holder of a
  // LEAKED token — i.e. requests that authenticate). Charging it before auth let
  // anyone who knew the URL drain the fleet-wide budget with unauthenticated
  // POSTs and 429 every real box's publish.
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.CONTRIBUTE_LIMITER && !(await env.CONTRIBUTE_LIMITER.limit({ key: ip })).success)
    return json({ error: "rate limited" }, 429);
  const { tooLarge, body } = await readBody(request);
  if (tooLarge) return json({ error: "body too large" }, 413);
  const auth = await authWriteIdentity(request, env, body);
  if (auth.status) return json(auth.error, auth.status);
  if (env.GLOBAL_LIMITER && !(await env.GLOBAL_LIMITER.limit({ key: "global" })).success)
    return json({ error: "rate limited" }, 429);
  const host = auth.host;   // identity from the token (or legacy body host_id)
  const entries = Array.isArray(body?.entries) ? body.entries : null;
  if (!entries) return json({ error: "valid entries[] required" }, 400);
  if (entries.length > maxEntries) return json({ error: "too many entries" }, 413);
  // WRITE-GATE on enrollment: an unenrolled host_id must NOT create sightings /
  // offenders (round-2 review: a leaked write token spamming random host_ids
  // would otherwise bloat sightings + emit count-0 IPs to every consumer).
  if (!(await isEnrolled(env, host))) return json({ accepted: 0, rejected: entries.length, enrolled: false }, 200);
  const now = nowSec();
  // Per-host quota on LIVE rows. Without it one token could write
  // MAX_ENTRIES x 120/min distinct rows and push every other host's entries out
  // of a FEED_MAX-truncated feed. 429 (not a 200 with accepted:0) so the client
  // keeps its publish cursor and retries once rows have aged out.
  const live = await hostLiveCount(env, { host, now, ttl });
  if (live >= hostMax) return json({ error: "host quota exceeded", live, max: hostMax }, 429);
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
  // The whole batch has to fit: `live >= hostMax` alone let a host at 9,500
  // land one more 1,000-entry body. Re-sightings of IPs the host already holds
  // do not add rows, so this over-counts them — the conservative direction.
  if (live + valid.length > hostMax) return json({ error: "host quota exceeded", live, max: hostMax, batch: valid.length }, 429);
  await contributeMany(env, { entries: valid, host, now });
  return json({ accepted: valid.length, rejected, enrolled: true }, 200);
}

async function handleRegister(request, env) {
  if (!checkAuth(request, env.SWARM_ENROLL_TOKEN)) return json({ error: "unauthorized" }, 401);
  // Rate-limit register: the enroll token now mints write identity, so throttle
  // token minting per connecting IP (a leaked enroll token's blast radius).
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.REGISTER_LIMITER && !(await env.REGISTER_LIMITER.limit({ key: ip })).success)
    return json({ error: "rate limited" }, 429);
  const { tooLarge, body } = await readBody(request);
  if (tooLarge) return json({ error: "body too large" }, 413);
  const host = validHostId(body?.host_id) ? body.host_id : null;
  if (!host) return json({ error: "valid host_id required (1-128 printable chars)" }, 400);
  const label = typeof body?.label === "string" && body.label.length <= 256 ? body.label : null;
  const rotate = body?.rotate === true;
  const { token, rotated } = await registerHost(env, { host, label, now: nowSec(), rotate });
  const resp = { enrolled: host, rotated };
  if (token) resp.token = token;   // returned ONCE — on first issue or an explicit rotate
  return json(resp, 200);
}

async function handlePurge(request, env) {
  // Rate-limit purge (a destructive op) per connecting IP — reuses the write
  // limiter, so purge shares a budget with contribute.
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.CONTRIBUTE_LIMITER && !(await env.CONTRIBUTE_LIMITER.limit({ key: ip })).success)
    return json({ error: "rate limited" }, 429);
  const { tooLarge, body } = await readBody(request);
  if (tooLarge) return json({ error: "body too large" }, 413);
  const auth = await authWriteIdentity(request, env, body);
  if (auth.status) return json(auth.error, auth.status);
  // Per-host path purges the TOKEN's host (body host_id ignored) — can't purge
  // another host; legacy path purges the un-migrated body host_id. Same
  // enrollment gate as /contribute: a never-enrolled legacy host_id must not
  // reach the orphan-offender DELETE.
  if (!(await isEnrolled(env, auth.host))) return json({ purged_sightings: 0, purged_offenders: 0 }, 200);
  const d = await purgeHost(env, { host: auth.host });
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

// `return await` (not a bare `return`) on every handler: a handler that throws
// before its first await rejects synchronously, and returning that promise
// unawaited leaves it handler-less for one microtask — workerd reports that as
// an unhandled rejection even though fetch() below catches it.
async function route(request, env) {
  const url = new URL(request.url);
  const m = request.method;
  if (m === "GET" && url.pathname === "/health") return json({ ok: true });
  if (m === "POST" && url.pathname === "/contribute") return await handleContribute(request, env);
  if (m === "POST" && url.pathname === "/register") return await handleRegister(request, env);
  if (m === "POST" && url.pathname === "/purge") return await handlePurge(request, env);
  if (m === "GET" && url.pathname === "/feed") return await handleFeed(request, env);
  return new Response("not found", { status: 404 });
}

export default guardWorker({
  async fetch(request, env, ctx) {
    // Anything that throws (a bad [vars] value from cfg(), a D1 failure) is a
    // 500 with a JSON body — never a 200, never an empty feed. The bash client
    // treats any non-200 as "hub broken": it keeps its last-good feed and its
    // publish cursor. The message is logged, not returned, so a config value
    // can't leak to an unauthenticated caller.
    try {
      return await route(request, env);
    } catch (err) {
      console.error(`swarm hub error on ${request.method} ${new URL(request.url).pathname}: ${err?.message || err}`);
      return json({ error: "hub error" }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(prune(env, { now: nowSec() }).then(
      (d) => console.log(`swarm prune: ${d.offenders} offenders, ${d.sightings} sightings`),
      (err) => console.error(`swarm prune FAILED: ${err?.message || err}`)   // surfaced, not swallowed
    ));
  },
});
