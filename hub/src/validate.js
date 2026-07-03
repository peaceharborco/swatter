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

export function isUnsafeTarget(s) {
  if (typeof s !== "string") return true;
  const slash = s.indexOf("/");
  if (slash !== -1 && s.slice(slash + 1) === "0") return true;   // /0
  const addr = slash === -1 ? s : s.slice(0, slash);
  return addr === "0.0.0.0" || addr === "::" || addr === "0:0:0:0:0:0:0:0";
}
