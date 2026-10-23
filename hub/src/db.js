import { cfg } from "./config.js";

// SHA-256 hex of a string (Web Crypto; available in Workers).
export async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function randomTokenHex() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// Register or update a host. Issues a NEW per-host token (and stores its hash) when
// the host is new (no token_hash) OR rotate===true; otherwise updates the label
// only and returns no token — so a plain re-enroll can't silently rotate/take over
// an already-tokened box. Returns { token: <hex>|null, rotated: bool }.
export async function registerHost(env, { host, label, now, rotate }) {
  const existing = await env.DB.prepare("SELECT token_hash FROM hosts WHERE host=?").bind(host).first();
  const hasToken = !!existing && existing.token_hash != null;
  if (hasToken && rotate !== true) {
    await env.DB.prepare("UPDATE hosts SET label=?2 WHERE host=?1").bind(host, label ?? null).run();
    return { token: null, rotated: false };
  }
  const token = randomTokenHex();
  const token_hash = await sha256Hex(token);
  // Issue path (first enroll OR --rotate). First enroll guards the SELECT->write
  // TOCTOU with `WHERE token_hash IS NULL` (first writer wins); rotate overwrites
  // unconditionally (last writer wins). EITHER way, re-read and hand back the
  // plaintext ONLY when our hash is the one stored — so a concurrent issue/rotate of
  // the same host can never return a token that wasn't persisted (the loser gets no
  // token and re-enrolls). One hash always wins; there is no dual-auth window.
  const cond = rotate === true ? "" : " WHERE hosts.token_hash IS NULL";
  await env.DB.prepare(
    `INSERT INTO hosts (host, enrolled_at, label, token_hash) VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(host) DO UPDATE SET label=?3, token_hash=?4${cond}`
  ).bind(host, now, label ?? null, token_hash).run();
  const after = await env.DB.prepare("SELECT token_hash FROM hosts WHERE host=?").bind(host).first();
  return after && after.token_hash === token_hash ? { token, rotated: hasToken } : { token: null, rotated: false };
}

// Resolve the host_id a per-host token authenticates as (or null). Lookup by hash;
// the plaintext token is never stored. A NULL token_hash can never match (the
// presented token hashes to a non-null hex).
export async function hostForToken(env, presented) {
  if (!presented) return null;
  const token_hash = await sha256Hex(presented);
  const row = await env.DB.prepare("SELECT host FROM hosts WHERE token_hash=?").bind(token_hash).first();
  return row ? row.host : null;
}

// For the legacy shared-write-token path: does this host row exist, and has it been
// migrated to a per-host token? A migrated host must NOT be writable via the shared
// token (that would re-open impersonation).
export async function hostTokenState(env, host) {
  const row = await env.DB.prepare("SELECT token_hash FROM hosts WHERE host=?").bind(host).first();
  if (!row) return { exists: false, migrated: false };
  return { exists: true, migrated: row.token_hash != null };
}

export async function isEnrolled(env, host) {
  const row = await env.DB.prepare("SELECT 1 FROM hosts WHERE host=?").bind(host).first();
  return row !== null;
}

// Chunked D1 batches: 2 statements per entry, CHUNK entries per batch() call.
// A full MAX_ENTRIES publish costs ~20 D1 round trips instead of 2000 awaited
// ones (Grok review: sequential per-entry writes blow the Workers subrequest
// budget and wall-clock at the contract's advertised batch size). host_count is
// NOT stored here (derived at read time), so there is no count race to protect.
const CHUNK = 50;
export async function contributeMany(env, { entries, host, now }) {
  const { ttl } = cfg(env);
  for (let i = 0; i < entries.length; i += CHUNK) {
    const stmts = [];
    for (const e of entries.slice(i, i + CHUNK)) {
      stmts.push(env.DB.prepare(
        `INSERT INTO sightings (ip, host, last_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT(ip, host) DO UPDATE SET last_seen=?3`
      ).bind(e.ip, host, now));
      stmts.push(env.DB.prepare(
        `INSERT INTO offenders (ip, first_seen, last_seen, last_host, category, expires)
         VALUES (?1, ?2, ?2, ?3, ?4, ?2 + ?5)
         ON CONFLICT(ip) DO UPDATE SET last_seen=?2, last_host=?3, category=?4, expires=?2 + ?5`
      ).bind(e.ip, now, host, e.category ?? null, ttl));
    }
    await env.DB.batch(stmts);
  }
}

export async function contributeOne(env, { ip, host, category, now }) {
  return contributeMany(env, { entries: [{ ip, category }], host, now });
}

// Live sightings this host currently holds (the per-host quota's measure).
// Uses ix_sightings_host_seen (migration 0003).
export async function hostLiveCount(env, { host, now, ttl }) {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM sightings WHERE host = ?1 AND last_seen > ?2"
  ).bind(host, now - ttl).first();
  return Number(row?.n ?? 0);
}

export async function feedRows(env, { now, limit }) {
  const { ttl, feedMax: max } = cfg(env);
  const cutoff = now - ttl;
  // Clamp to [1, FEED_MAX]: a garbage/negative/zero ?limit must never yield a
  // negative LIMIT or a silently-empty feed (a consumer may treat empty as
  // "clear my blocks"). round-2 review.
  const req = Number(limit);
  const cap = Number.isFinite(req) && req >= 1 ? Math.min(Math.floor(req), max) : max;
  // host_count counts ENROLLED hosts only (the hosts join), as before, but as one
  // grouped join instead of a correlated subquery per row. Ordering is by
  // corroboration first, then recency, so when the feed is truncated at FEED_MAX
  // it drops the least-trusted rows — not whichever IPs happen to sort last as
  // strings, which let a single host evict everyone else's rows by publishing
  // lexically low addresses.
  const { results } = await env.DB.prepare(
    `SELECT o.ip AS ip,
            COUNT(DISTINCT CASE WHEN h.host IS NOT NULL THEN s.host END) AS host_count,
            o.category AS category, o.expires AS expires
       FROM offenders o
       LEFT JOIN sightings s ON s.ip = o.ip AND s.last_seen > ?2
       LEFT JOIN hosts h ON h.host = s.host
      WHERE o.expires > ?1
      GROUP BY o.ip
      ORDER BY host_count DESC, o.last_seen DESC, o.ip
      LIMIT ?3`
  ).bind(now, cutoff, cap + 1).all();
  const rows = (results ?? []).slice(0, cap);
  return { rows, truncated: (results ?? []).length > cap };
}

export async function prune(env, { now }) {
  const cutoff = now - cfg(env).ttl;
  // One batch (atomic transaction) so a concurrent feed can't observe offenders
  // and sightings out of sync between the two DELETEs (round-2 review).
  const [o, s] = await env.DB.batch([
    env.DB.prepare("DELETE FROM offenders WHERE expires <= ?").bind(now),
    env.DB.prepare("DELETE FROM sightings WHERE last_seen <= ?").bind(cutoff),
  ]);
  return { offenders: o.meta.changes ?? 0, sightings: s.meta.changes ?? 0 };
}

// Bad-publish recovery (spec §13): drop every sighting this host contributed,
// then any offenders left with no sightings at all. One atomic batch so a
// concurrent feed never sees a half-purged state. The host stays enrolled.
export async function purgeHost(env, { host }) {
  const [s, o] = await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings WHERE host = ?").bind(host),
    env.DB.prepare(
      "DELETE FROM offenders WHERE ip NOT IN (SELECT DISTINCT ip FROM sightings)"
    ),
  ]);
  return { sightings: s.meta.changes ?? 0, offenders: o.meta.changes ?? 0 };
}
