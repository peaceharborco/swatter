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
