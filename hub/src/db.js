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
