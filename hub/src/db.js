export async function registerHost(env, { host, label, now }) {
  await env.DB.prepare(
    `INSERT INTO hosts (host, enrolled_at, label) VALUES (?1, ?2, ?3)
     ON CONFLICT(host) DO UPDATE SET label=?3`
  ).bind(host, now, label ?? null).run();
}

export async function isEnrolled(env, host) {
  const row = await env.DB.prepare("SELECT 1 FROM hosts WHERE host=?").bind(host).first();
  return row !== null;
}

export async function contributeOne(env, { ip, host, category, now }) {
  const ttl = Number(env.SWARM_TTL);
  // Sequential awaited statements: each commits before the next. host_count is
  // NOT stored here (derived at read time), so there is no cross-request count
  // race to protect against.
  await env.DB.prepare(
    `INSERT INTO sightings (ip, host, last_seen) VALUES (?1, ?2, ?3)
     ON CONFLICT(ip, host) DO UPDATE SET last_seen=?3`
  ).bind(ip, host, now).run();
  await env.DB.prepare(
    `INSERT INTO offenders (ip, first_seen, last_seen, last_host, category, expires)
     VALUES (?1, ?2, ?2, ?3, ?4, ?2 + ?5)
     ON CONFLICT(ip) DO UPDATE SET last_seen=?2, last_host=?3, category=?4, expires=?2 + ?5`
  ).bind(ip, now, host, category ?? null, ttl).run();
}

export async function feedRows(env, { now, limit }) {
  const ttl = Number(env.SWARM_TTL);
  const cutoff = now - ttl;
  const max = Number(env.FEED_MAX);
  // Clamp to [1, FEED_MAX]: a garbage/negative/zero ?limit must never yield a
  // negative LIMIT or a silently-empty feed (a consumer may treat empty as
  // "clear my blocks"). round-2 review.
  const req = Number(limit);
  const cap = Number.isFinite(req) && req >= 1 ? Math.min(Math.floor(req), max) : max;
  const { results } = await env.DB.prepare(
    `SELECT o.ip AS ip,
            (SELECT COUNT(DISTINCT s.host) FROM sightings s
              JOIN hosts h ON s.host = h.host
             WHERE s.ip = o.ip AND s.last_seen > ?2) AS host_count,
            o.category AS category, o.expires AS expires
       FROM offenders o
      WHERE o.expires > ?1
      ORDER BY o.ip
      LIMIT ?3`
  ).bind(now, cutoff, cap + 1).all();
  const rows = (results ?? []).slice(0, cap);
  return { rows, truncated: (results ?? []).length > cap };
}

export async function prune(env, { now }) {
  const cutoff = now - Number(env.SWARM_TTL);
  // One batch (atomic transaction) so a concurrent feed can't observe offenders
  // and sightings out of sync between the two DELETEs (round-2 review).
  const [o, s] = await env.DB.batch([
    env.DB.prepare("DELETE FROM offenders WHERE expires <= ?").bind(now),
    env.DB.prepare("DELETE FROM sightings WHERE last_seen <= ?").bind(cutoff),
  ]);
  return { offenders: o.meta.changes ?? 0, sightings: s.meta.changes ?? 0 };
}
