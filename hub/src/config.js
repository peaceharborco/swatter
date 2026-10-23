// Worker [vars] are strings. Every numeric knob is parsed HERE, once, and a
// value that is not a positive integer THROWS — the request becomes a 500 and
// the bash client keeps its last-good feed / its publish cursor. The previous
// `Number(env.X)` reads failed OPEN: MAX_ENTRIES="abc" made `len > NaN` false
// (no batch cap), and SWARM_TTL="" made every row expire on write, so /feed
// served a valid-looking EMPTY 200 that consumers read as "no active offenders"
// (the same class as the numeric-knob rule in the repo CLAUDE.md).
function intVar(env, name) {
  const v = env[name];
  if (typeof v !== "string" || !/^[1-9][0-9]{0,9}$/.test(v)) {
    throw new Error(`hub misconfigured: ${name}=${JSON.stringify(v ?? null)} must be a positive integer`);
  }
  return Number(v);
}

export function cfg(env) {
  return {
    ttl: intVar(env, "SWARM_TTL"),              // seconds an offender stays in the feed after its last sighting
    maxEntries: intVar(env, "MAX_ENTRIES"),     // entries per /contribute body
    feedMax: intVar(env, "FEED_MAX"),           // rows per /feed response
    hostMax: intVar(env, "HOST_MAX"),           // live sightings one host may hold (see handleContribute)
  };
}
