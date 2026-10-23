const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function validV6(a) {
  a = a.toLowerCase();
  let v4tail = 0;
  if (a.includes(".")) {
    if (!a.includes(":")) return false;
    const tail = a.slice(a.lastIndexOf(":") + 1);
    if (!V4.test(tail)) return false;
    a = a.slice(0, a.lastIndexOf(":")) + ":0";
    v4tail = 2;
  }
  if (!/^[0-9a-f:]+$/.test(a)) return false;
  let L, R = "";
  if (a.includes("::")) {
    if (a.includes(":::") || a.slice(a.indexOf("::") + 2).includes("::")) return false;
    L = a.slice(0, a.indexOf("::"));
    R = a.slice(a.indexOf("::") + 2);
  } else {
    if (a.startsWith(":") || a.endsWith(":")) return false;
    L = a;
  }
  const groups = [...L.split(":").filter(Boolean), ...R.split(":").filter(Boolean)];
  for (const g of groups) if (!/^[0-9a-f]{1,4}$/.test(g)) return false;
  // The embedded-v4 tail was replaced with a single ":0" placeholder group above,
  // so subtract that 1 placeholder before adding the quad's 2 groups — matching
  // the bash validator (round-2 review: `0:0:0:0:0:ffff:192.0.2.1` must pass).
  const n = groups.length + v4tail - (v4tail ? 1 : 0);
  return a.includes("::") ? n <= 7 : n === 8;
}

export function isValidIpOrCidr(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  let addr = s, plen = null;
  const slash = s.indexOf("/");
  if (slash !== -1) {
    addr = s.slice(0, slash);
    plen = s.slice(slash + 1);
    if (addr.length === 0 || plen.includes("/") || !/^\d+$/.test(plen)) return false;
  }
  // Prefix regexes copied EXACTLY from the bash validator so a leading-zero plen
  // (`/00`, `/03`, `/033`) is rejected on both sides (round-2 review parity gap).
  if (addr.includes(":")) {
    if (!validV6(addr)) return false;
    return plen === null || /^([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$/.test(plen);
  }
  if (!V4.test(addr)) return false;
  return plen === null || /^([0-9]|[12][0-9]|3[0-2])$/.test(plen);
}

// --- Unsafe targets ---------------------------------------------------------
// Every entry the hub accepts is served to EVERY consumer, which then places a
// firewall deny for it. One compromised or buggy box must not be able to make the
// whole fleet deny its own LAN, loopback, link-local, CGNAT or multicast space,
// or a prefix so wide it takes a chunk of the internet with it. The bash client
// re-checks its never-block set locally, but that covers only the ranges it
// knows (RFC1918, loopback, Cloudflare); an arbitrary public /8 would land.
//
// Refused: anything that OVERLAPS a range below, plus any v4 prefix shorter than
// /24 and any v6 prefix shorter than /64 — the same floor the bash client applies
// to the feed it consumes (lib/swarm.sh sweep). Documentation/TEST-NET ranges are NOT
// here: they are never routed, so a deny for them harms nobody, and the test
// suites on both sides use them as fixtures. Cloudflare's edge ranges change
// and are never-block on every client, so they are left to the client.
function v4ToInt(a) {
  const p = a.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const q of p) {
    if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(q)) return null;
    n = n * 256 + Number(q);
  }
  return n;
}
// Full 128-bit value of a (syntactically valid) v6 address, embedded-v4 tail
// included. Returns null on anything it cannot expand — callers treat null as
// unsafe (fail closed).
function v6ToBigInt(a) {
  a = a.toLowerCase();
  let tailGroups = [];
  if (a.includes(".")) {
    const i = a.lastIndexOf(":");
    const v4 = v4ToInt(a.slice(i + 1));
    if (v4 === null) return null;
    tailGroups = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    a = a.slice(0, i + 1);           // keep the trailing ':' so "::1.2.3.4" splits cleanly
    if (a.endsWith("::")) a = a.slice(0, -1) + ":";   // "::" + tail -> "::" stays "::"
    a = a.replace(/:$/, "");
    if (a === "" ) a = "::";
  }
  let left, right;
  if (a.includes("::")) {
    const i = a.indexOf("::");
    left = a.slice(0, i); right = a.slice(i + 2);
  } else { left = a; right = ""; }
  const L = left ? left.split(":") : [];
  const R = right ? right.split(":") : [];
  const groups = [...L, ...R.map(String)];
  for (const g of groups) if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
  const have = L.length + R.length + tailGroups.length;
  if (have > 8) return null;
  if (!a.includes("::") && have !== 8) return null;
  const fill = a.includes("::") ? 8 - have : 0;
  const all = [...L.map((g) => parseInt(g, 16)), ...Array(fill).fill(0), ...R.map((g) => parseInt(g, 16)), ...tailGroups];
  if (all.length !== 8) return null;
  let n = 0n;
  for (const g of all) n = (n << 16n) | BigInt(g);
  return n;
}
const V4_MAX = 0xffffffff;
const V6_MAX = (1n << 128n) - 1n;
function v4Range(addr, plen) {
  const base = v4ToInt(addr); if (base === null) return null;
  const span = plen >= 32 ? 0 : (V4_MAX >>> plen);
  const lo = (base & ~span) >>> 0;
  return [lo, (lo | span) >>> 0];
}
function v6Range(addr, plen) {
  const base = v6ToBigInt(addr); if (base === null) return null;
  const span = plen >= 128 ? 0n : (V6_MAX >> BigInt(plen));
  const lo = base & ~span & V6_MAX;
  return [lo, lo | span];
}
const RESERVED_V4 = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([a, p]) => v4Range(a, p));
const RESERVED_V6 = [
  ["::", 128], ["::1", 128], ["::ffff:0:0", 96], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
].map(([a, p]) => v6Range(a, p));
export const MIN_V4_PLEN = 24;
export const MIN_V6_PLEN = 64;

export function isUnsafeTarget(s) {
  if (typeof s !== "string" || s.length === 0) return true;
  const slash = s.indexOf("/");
  const addr = slash === -1 ? s : s.slice(0, slash);
  const plenStr = slash === -1 ? null : s.slice(slash + 1);
  if (plenStr !== null && !/^\d+$/.test(plenStr)) return true;
  if (addr.includes(":")) {
    const plen = plenStr === null ? 128 : Number(plenStr);
    if (plen < MIN_V6_PLEN || plen > 128) return true;
    const r = v6Range(addr, plen); if (r === null) return true;
    return RESERVED_V6.some(([lo, hi]) => r[0] <= hi && r[1] >= lo);
  }
  const plen = plenStr === null ? 32 : Number(plenStr);
  if (plen < MIN_V4_PLEN || plen > 32) return true;
  const r = v4Range(addr, plen); if (r === null) return true;
  return RESERVED_V4.some(([lo, hi]) => r[0] <= hi && r[1] >= lo);
}
