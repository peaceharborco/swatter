#!/usr/bin/env bash
# Gate for the CoastGuard module (SPEC.md). Vendor verbatim into a Worker repo
# as tests/coastguard/check.sh and run it in that repo's CI.
#
#   check.sh <wrangler config>...  every Worker with code:
#       - carries [limits] cpu_ms <= 5000 and subrequests <= 1000
#       - declares the marker var COASTGUARD (top level and in any env that
#         sets its own vars)
#       - carries the halt guard (src/coastguard.rs, or coastguard.ts next to
#         `main`) byte-identical to the toolbox
#       - calls it first in EVERY handler: Rust #[event(...)] functions; TS/JS
#         `export default guardWorker(...)` and every Durable Object or
#         container class wrapped by guardDurableObject
#   check.sh --fleet               the same for every config in ADOPTERS
#   check.sh --self-test           the toolbox's own fixtures (toolbox only)
#
# Reads wrangler.toml, wrangler.jsonc and wrangler.json (by extension).
#
# An assets-only Worker (no `main`) runs no code and is exempt. Two
# exemptions are written as their own comment line in the config:
#   # coastguard: subrequests default — <why>   a fleet-walking cron
#   # coastguard: workers free — <why>          a Workers Free account, where
#                                              Cloudflare refuses [limits]
#                                              (code 100328); the guard and
#                                              marker are still required
# (`//` instead of `#` in JSONC.)
#
# WHY A GATE. A [limits] block, a guard call or a marker is one deletion away
# from gone, and nothing else notices: the Worker deploys and passes every
# other test. The guard is what lets phcloudflare stop a runaway Worker; a
# handler without it keeps billing through a halt.
set -uo pipefail

MAX_CPU=5000
MAX_SUB=1000
# sha256 of the canonical guard files. The toolbox self-test fails when these
# fall behind the files; a vendored copy that differs fails its repo's CI.
GUARD_RS_SHA=84ed7cb069cc604a4b221f7adf62b94426a69c82503edbe1d135c1f9d9762237
GUARD_TS_SHA=428abecce898600e25d720d581d8622e96f5c9ecb89263062e76d2f117c5249b
here="$(cd "$(dirname "$0")" && pwd)"

check_one() {
  python3 -I - "$1" "$MAX_CPU" "$MAX_SUB" "$GUARD_RS_SHA" "$GUARD_TS_SHA" <<'PY'
import sys, tomllib, json, re, os, hashlib
path, max_cpu, max_sub, rs_sha, ts_sha = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
try:
    src = open(path).read()
except OSError as e:
    sys.exit(f"FAIL {path}: {e}")

def jsonc(text):
    # Drop // and /* */ comments and trailing commas, never inside a string.
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n: out.append(text[i + 1]); i += 1
            elif c == '"': in_str = False
        elif c == '"':
            in_str = True; out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n": i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c in "}]":
            k = len(out) - 1
            while k >= 0 and out[k].isspace(): k -= 1
            if k >= 0 and out[k] == ",": del out[k]
            out.append(c)
        else:
            out.append(c)
        i += 1
    return json.loads("".join(out))

try:
    cfg = jsonc(src) if path.endswith((".jsonc", ".json")) else tomllib.loads(src)
except ValueError as e:
    sys.exit(f"FAIL {path}: does not parse: {e}")
if "main" not in cfg:
    print(f"ok   {path} (assets-only, exempt)"); sys.exit(0)

errs = []
base = os.path.dirname(os.path.abspath(path))

# --- [limits] -------------------------------------------------------------
free = re.search(r"^\s*(#|//)\s*coastguard:\s*workers free\b", src, re.M)
exempt_sub = re.search(r"^\s*(#|//)\s*coastguard:\s*subrequests default\b", src, re.M)
lim = cfg.get("limits") or {}
cpu, sub = lim.get("cpu_ms"), lim.get("subrequests")
if cpu is None and not free:
    errs.append("no [limits] cpu_ms")
elif cpu is not None and cpu > max_cpu:
    errs.append(f"cpu_ms {cpu} > {max_cpu}")
if sub is None and not (exempt_sub or free):
    errs.append("no [limits] subrequests (or a 'coastguard: subrequests default' comment line)")
elif sub is not None and sub > max_sub:
    errs.append(f"subrequests {sub} > {max_sub}")
# An [env.*] that sets its own limits replaces the top-level block whole (no
# per-key merge), so it must carry both keys inside the same bounds.
for name, env in (cfg.get("env") or {}).items():
    if "limits" in env:
        el = env.get("limits") or {}
        if "cpu_ms" not in el: errs.append(f"env.{name} limits without cpu_ms")
        elif el["cpu_ms"] > max_cpu: errs.append(f"env.{name} cpu_ms {el['cpu_ms']} > {max_cpu}")
        if "subrequests" not in el and not exempt_sub: errs.append(f"env.{name} limits without subrequests")
        elif el.get("subrequests", 0) > max_sub: errs.append(f"env.{name} subrequests {el['subrequests']} > {max_sub}")
    # vars are NOT inherited by an env that declares its own.
    if "vars" in env and "COASTGUARD" not in (env.get("vars") or {}):
        errs.append(f"env.{name} vars without COASTGUARD")

# --- marker ---------------------------------------------------------------
if "COASTGUARD" not in (cfg.get("vars") or {}):
    errs.append("no COASTGUARD var (the marker the fleet audit reads)")

def sha(p):
    with open(p, "rb") as fh: return hashlib.sha256(fh.read()).hexdigest()

def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh: return fh.read()

def strip_comments(text, quotes):
    # Blank out // and /* */ comments so a commented-out guard does not count,
    # stepping over string literals: a route string like "/api/*" must not
    # open a comment. `quotes` is the language's string delimiters (Rust: '"'
    # only, since ' also marks lifetimes; TS/JS: ' " and `).
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in quotes:
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1]); i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2); j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j])); i = j
        else:
            out.append(c); i += 1
    return "".join(out)

def files(root, exts):
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in ("node_modules", "target", "build", "dist", ".wrangler", "test", "tests", "__tests__")]
        for n in names:
            if n.endswith(exts) and not re.search(r"\.(test|spec)\.", n):
                yield os.path.join(d, n)

# --- guard ----------------------------------------------------------------
if os.path.exists(os.path.join(base, "Cargo.toml")):
    srcdir = os.path.join(base, "src")
    guard = os.path.join(srcdir, "coastguard.rs")
    if not os.path.exists(guard):
        errs.append("no src/coastguard.rs")
    elif sha(guard) != rs_sha:
        errs.append("src/coastguard.rs differs from the toolbox (re-vendor it)")
    handlers = 0
    for f in files(srcdir, (".rs",)):
        if os.path.abspath(f) == os.path.abspath(guard): continue
        text = strip_comments(read(f), "\"")
        for m in re.finditer(r"#\[event\(\s*(\w+)[^\]]*\)\]", text):
            kind = m.group(1)
            if kind == "start": continue          # runs once at load, bills nothing
            handlers += 1
            fn = text.find("fn ", m.end())
            brace = text.find("{", fn)
            body = [l.strip() for l in text[brace + 1:].split("\n")]
            stmts = [l for l in body if l]
            if stmts and stmts[0].startswith("console_error_panic_hook::set_once"):
                stmts = stmts[1:]
            first = stmts[0] if stmts else ""
            if not re.match(r"if\s+coastguard::halted\(\s*&\s*\w+\s*\)", first):
                rel = os.path.relpath(f, base)
                errs.append(f"{rel}: #[event({kind})] does not start with `if coastguard::halted(&env)`")
        if re.search(r"#\[durable_object\]", text):
            errs.append(f"{os.path.relpath(f, base)}: Rust Durable Objects are not covered by the guard yet (add a rule to the toolbox)")
    if handlers == 0:
        errs.append("no #[event(...)] handler found to check")
else:
    main = os.path.normpath(os.path.join(base, cfg["main"]))
    root = os.path.dirname(main)
    guard = os.path.join(root, "coastguard.ts")
    if not os.path.exists(guard):
        errs.append(f"no {os.path.relpath(guard, base)}")
    elif sha(guard) != ts_sha:
        errs.append(f"{os.path.relpath(guard, base)} differs from the toolbox (re-vendor it)")
    try:
        mtext = strip_comments(read(main), "'\"`")
    except OSError:
        mtext = ""
        errs.append(f"main {cfg['main']} not found")
    if mtext:
        if not re.search(r"export\s+default\s+guardWorker\s*\(", mtext):
            errs.append(f"{cfg['main']}: default export is not wrapped in guardWorker(...)")
        if len(re.findall(r"export\s+default\b", mtext)) != 1:
            errs.append(f"{cfg['main']}: expected exactly one `export default`")
    classes = set()
    for b in ((cfg.get("durable_objects") or {}).get("bindings") or []):
        if not b.get("script_name"): classes.add(b["class_name"])
    for c in (cfg.get("containers") or []):
        if c.get("class_name"): classes.add(c["class_name"])
    if classes:
        alltext = "\n".join(strip_comments(read(f), "'\"`") for f in files(root, (".ts", ".js", ".mjs")) if os.path.abspath(f) != os.path.abspath(guard))
        for name in sorted(classes):
            if not re.search(rf"export\s+const\s+{re.escape(name)}\s*=\s*guardDurableObject\s*\(", alltext):
                errs.append(f"Durable Object class {name} is not exported as `export const {name} = guardDurableObject(...)`")

if errs:
    print(f"FAIL {path}: " + "; ".join(errs)); sys.exit(1)
lim_s = "workers free, exempt" if (free and cpu is None) else f"cpu_ms={cpu}, subrequests={sub if sub is not None else 'default, exempted'}"
print(f"ok   {path} ({lim_s}; guarded)")
PY
}

self_test() {
  local rc=0 rs ts
  rs="$(shasum -a 256 "$here/worker-rs/coastguard.rs" | cut -d' ' -f1)"
  ts="$(shasum -a 256 "$here/worker-ts/coastguard.ts" | cut -d' ' -f1)"
  [[ "$rs" == "$GUARD_RS_SHA" ]] || { echo "FAIL GUARD_RS_SHA is stale: run ./stamp-guard.sh"; rc=1; }
  [[ "$ts" == "$GUARD_TS_SHA" ]] || { echo "FAIL GUARD_TS_SHA is stale: run ./stamp-guard.sh"; rc=1; }
  "$here/test/fixtures.sh" "$0" || rc=1
  node --test "$here/worker-ts/coastguard.test.ts" >/dev/null 2>&1 || { echo "FAIL worker-ts tests (node --test worker-ts/coastguard.test.ts)"; rc=1; }
  [[ $rc == 0 ]] && echo "ok   self-test"
  return $rc
}

case "${1:-}" in
  --fleet)
    rc=0
    while read -r f _; do
      [[ -z "$f" || "$f" == \#* ]] && continue
      check_one "$HOME/Developer/$f" || rc=1
    done < "$here/ADOPTERS"
    exit $rc
    ;;
  --self-test)
    self_test; exit $?
    ;;
  ""|-h|--help)
    sed -n '2,25p' "$0"; exit 2
    ;;
  *)
    rc=0
    for f in "$@"; do check_one "$f" || rc=1; done
    exit $rc
    ;;
esac
