#!/usr/bin/env bash
# Gate for the CoastGuard module (SPEC.md). Vendor verbatim into a site as
# tests/coastguard/check.sh and run it in that site's CI.
#
#   check.sh <wrangler.toml>...   every Worker with code carries [limits] with
#                                 cpu_ms <= 5000 and subrequests <= 1000
#   check.sh --fleet              the same for every wrangler.toml in ADOPTERS
#                                 (toolbox only)
#
# An assets-only Worker (no `main`) runs no code and is exempt. A Worker that
# genuinely needs Cloudflare's default subrequest ceiling (a cron walking the
# whole fleet) says so on its own line, which this gate then accepts:
#   # coastguard: subrequests default — <why>
#
# WHY A GATE. A [limits] block is one deletion away from gone, and nothing
# else notices: the Worker deploys, serves and passes every other test with
# Cloudflare's 30 s CPU / 10,000-subrequest defaults back in force. On a
# Workers Paid account that is the difference between a loop that errors and
# a loop that bills.
set -uo pipefail

MAX_CPU=5000
MAX_SUB=1000
here="$(cd "$(dirname "$0")" && pwd)"

check_one() {
  python3 -I - "$1" "$MAX_CPU" "$MAX_SUB" <<'PY'
import sys, tomllib, re
path, max_cpu, max_sub = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    src = open(path).read()
except OSError as e:
    sys.exit(f"FAIL {path}: {e}")
cfg = tomllib.loads(src)
if "main" not in cfg:
    print(f"ok   {path} (assets-only, exempt)"); sys.exit(0)
lim = cfg.get("limits") or {}
errs = []
cpu = lim.get("cpu_ms")
if cpu is None:
    errs.append("no [limits] cpu_ms")
elif cpu > max_cpu:
    errs.append(f"cpu_ms {cpu} > {max_cpu}")
sub = lim.get("subrequests")
exempt = re.search(r"^#\s*coastguard:\s*subrequests default\b", src, re.M)
if sub is None and not exempt:
    errs.append("no [limits] subrequests (or a '# coastguard: subrequests default' line)")
elif sub is not None and sub > max_sub:
    errs.append(f"subrequests {sub} > {max_sub}")
# An [env.*] that sets its own limits must stay inside the same bounds.
for name, env in (cfg.get("env") or {}).items():
    el = env.get("limits") or {}
    if el.get("cpu_ms", 0) > max_cpu: errs.append(f"env.{name} cpu_ms {el['cpu_ms']} > {max_cpu}")
    if el.get("subrequests", 0) > max_sub: errs.append(f"env.{name} subrequests {el['subrequests']} > {max_sub}")
if errs:
    print(f"FAIL {path}: " + "; ".join(errs)); sys.exit(1)
print(f"ok   {path} (cpu_ms={cpu}, subrequests={sub if sub is not None else 'default, exempted'})")
PY
}

case "${1:-}" in
  --fleet)
    rc=0
    while read -r f; do
      [[ -z "$f" || "$f" == \#* ]] && continue
      check_one "$HOME/Developer/$f" || rc=1
    done < "$here/ADOPTERS"
    exit $rc
    ;;
  ""|-h|--help)
    sed -n '2,9p' "$0"; exit 2
    ;;
  *)
    rc=0
    for f in "$@"; do check_one "$f" || rc=1; done
    exit $rc
    ;;
esac
