# Swatter v1.3 — Intel + Engine Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five operator-grade capabilities to Swatter — two new threat-intel providers (GreyNoise with a benign/RIOT suppression verdict, Project Honey Pot http:BL), a Team Cymru hosting-ASN conditional-boost signal, honeypot instant-perm trap paths, low-and-slow cross-window persistence escalation, and Prometheus textfile metrics — all default-off and safe.

**Architecture:** New lookups (GreyNoise, http:BL, Cymru ASN) run only for IPs already past WATCH and are cached, so the cron path stays cheap. The intel provider contract gains an optional 4th `verdict` field so a "known-good" verdict can route an IP through the existing never-block/exempt path (a dynamic soft-allowlist) without breaking the "scoring only ever raises" invariant. The honeypot and persistence signals are decisive — they act with little or no volume — and reuse the existing plane-classification, allowlist, and circuit-breaker rails. Metrics are emitted best-effort at the end of each scan via an atomic textfile write.

**Tech Stack:** Bash 4+, gawk, sqlite3 (with flatfile fallback), curl + jq (HTTP providers), a DNS client (`dig`/`host`/`nslookup`, for http:BL + Cymru). No daemon, no compiled deps. Test harness is plain self-contained bash scripts under `test/`, run by `make test`.

## Global Constraints

- **A failed or absent lookup NEVER blocks.** Every provider/module returns "no data" (exit 1, or a 0/empty result) on timeout, error, missing key, missing dependency, or unparseable response.
- **New lookups run only for IPs already past WATCH** (the scan loop already gates this; do not add per-request network calls).
- **Suppression is total:** a suppressed IP is exempt everywhere — no block, no sighting accrual, no persistence escalation — and wins over any malicious score and over the CRITICAL/honeypot floors. `score.sh` checks the suppress flag before any action and before sighting accrual.
- **Provider output contract:** `score_0_100 \t ttl_seconds \t label \t verdict` (verdict ∈ `""` | `suppress`). 3-field legacy providers remain valid (verdict reads empty).
- **Commit identity** (public repo, already configured locally): author `Peace Harbor Studios <142285318+peaceharborco@users.noreply.github.com>`. Every commit message ends with the trailer:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- **Branch:** all work on `feature/intel-engine-expansion-v1.3` (already checked out). Push reaches both GitHub and GitLab via dual-push `origin`.
- **Style:** match surrounding bash — `set`-safe (`${VAR:-}`), `log_warn`/`log_debug`/`log_info` for messages, providers sourced lazily, `printf` not `echo -e`. Keep each new file single-responsibility.
- **Version:** bump `SWATTER_VERSION` to `1.3.0` in the final task; per the project's release rule a tag + GitHub/GitLab release is required to publish (push alone does not).
- **No live keys in tests:** mock `curl`/`dig` by defining shell functions of the same name (providers are sourced into the test shell, so a function named `curl` shadows the binary).

---

## File Structure

**New files:**
- `lib/providers/greynoise.sh` — GreyNoise Community API provider (`provider_greynoise`).
- `lib/providers/projecthoneypot.sh` — http:BL DNS provider (`provider_projecthoneypot`).
- `lib/asn.sh` — Team Cymru IP→ASN resolve + hosting-set match + attack-shaped gate.
- `lib/metrics.sh` — Prometheus textfile emitter (`swatter_metrics_emit`, `swatter_metrics_write`).
- `config/hosting-asns.txt` — default hosting/bulletproof ASN list (tunable).
- `config/honeypot.paths.example` — commented example trap file (live file is operator-authored).
- `test/intel_test.sh`, `test/greynoise_test.sh`, `test/projecthoneypot_test.sh`, `test/asn_test.sh`, `test/persist_test.sh`, `test/metrics_test.sh`, `test/honeypot_test.sh` — new test files (one per unit). `test/score_test.sh` gains honeypot cases.

**Modified files:**
- `lib/intel.sh` — 4-field contract, suppress flag in return + cache.
- `lib/score.awk` — honeypot detection/floor/MIN_REQS-bypass + evidence flag.
- `lib/score.sh` — `_swatter_execute_block` refactor; suppress→exempt; ASN boost; honeypot perm; persistence escalation; metrics hook.
- `lib/store_sqlite.sh` — `sightings` table + add/count/clear/sweep + offender-state counts.
- `lib/common.sh` — DNS-client probe (`SWATTER_HAVE_DNS`), new config defaults.
- `bin/swatter` — `honeypot` + `metrics` subcommands; `test-config` readiness checks; `SWATTER_VERSION=1.3.0`.
- `config/swatter.example.conf` — document all new keys.
- `README.md` — provider/signal/command sections.
- `install/install.sh` (and the deploy helpers) — install the two config files; note the metrics dir.

---

## Task 1: Intel provider contract — `verdict` field + suppress flag

**Files:**
- Modify: `lib/intel.sh` (`_intel_cache_get`, `_intel_cache_put`, `swatter_intel_score`)
- Test: `test/intel_test.sh` (new)

**Interfaces:**
- Produces: `swatter_intel_score <ip>` now echoes `best_score \t best_label \t suppress_flag` (suppress_flag ∈ `0`|`1`). Cache files hold `score \t label \t verdict`.
- Consumes: provider functions printing `score \t ttl \t label [\t verdict]`.

- [ ] **Step 1: Write the failing test** — create `test/intel_test.sh`:

```bash
#!/usr/bin/env bash
# test/intel_test.sh — intel dispatch: max score, suppress verdict, legacy 3-field.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/intel.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-intel.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/intel"
INTEL_CACHE_TTL=86400

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Fake providers (4-field, 3-field legacy, and a suppress verdict).
provider_high()    { printf '90\t%s\thigh\t\n'      "$INTEL_CACHE_TTL"; }
provider_legacy()  { printf '40\t%s\tlegacy\n'      "$INTEL_CACHE_TTL"; }   # 3-field
provider_riot()    { printf '0\t%s\triot:google\tsuppress\n' "$INTEL_CACHE_TTL"; }
provider_nodata()  { return 1; }

# Max across providers, no suppress.
INTEL_PROVIDERS="legacy high"
out="$(swatter_intel_score 1.2.3.4)"
check max-score   "$(printf '%s' "$out" | cut -f1)" "90"
check max-supp0   "$(printf '%s' "$out" | cut -f3)" "0"

# Suppress flag set when any provider suppresses, even alongside a high score.
INTEL_PROVIDERS="high riot"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 5.6.7.8)"
check supp-flag   "$(printf '%s' "$out" | cut -f3)" "1"

# No-data provider contributes nothing.
INTEL_PROVIDERS="nodata"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 9.9.9.9)"
check nodata      "$(printf '%s' "$out" | cut -f1)" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/intel_test.sh`
Expected: FAIL on `supp-flag` (current `swatter_intel_score` returns only 2 fields; `cut -f3` is empty, not `1`).

- [ ] **Step 3: Implement the contract change** in `lib/intel.sh`. Replace `_intel_cache_put` and `swatter_intel_score`:

```bash
_intel_cache_put() {
    local prov="$1" ip="$2" score="$3" label="$4" verdict="${5:-}"
    local d="${STATE_DIR}/intel/${prov}"
    mkdir -p "$d" 2>/dev/null || return 0
    printf '%s\t%s\t%s\n' "$score" "$label" "$verdict" > "${d}/${ip}" 2>/dev/null || true
}

# swatter_intel_score <ip> : echoes "best_score \t best_label \t suppress_flag".
swatter_intel_score() {
    local ip="$1" best=0 bestlabel="" suppress=0
    local prov out cached score ttl label verdict
    for prov in ${INTEL_PROVIDERS}; do
        if cached="$(_intel_cache_get "$prov" "$ip")"; then
            score="$(printf '%s' "$cached" | cut -f1)"
            label="$(printf '%s' "$cached" | cut -f2)"
            verdict="$(printf '%s' "$cached" | cut -f3)"
        else
            if ! declare -F "provider_${prov}" >/dev/null; then continue; fi
            if out="$(provider_"${prov}" "$ip" 2>/dev/null)"; then
                score="$(printf '%s' "$out" | cut -f1)"
                ttl="$(printf '%s' "$out" | cut -f2)"
                label="$(printf '%s' "$out" | cut -f3)"
                verdict="$(printf '%s' "$out" | cut -f4)"
                [[ "$score" =~ ^[0-9]+$ ]] || score=0
                _intel_cache_put "$prov" "$ip" "$score" "$label" "$verdict"
            else
                score=0; label=""; verdict=""
                _intel_cache_put "$prov" "$ip" 0 "nodata" ""
            fi
        fi
        [[ "$verdict" == "suppress" ]] && { suppress=1; [[ -z "$bestlabel" ]] && bestlabel="${prov}:${label}"; }
        if (( score > best )); then best="$score"; bestlabel="${prov}:${label}"; fi
    done
    printf '%s\t%s\t%s\n' "$best" "$bestlabel" "$suppress"
}
```

Also update `_intel_cache_get`'s header comment to note the 3-field format. The function body (a `cat` of the file) is unchanged — a legacy 2-field cache file yields an empty `cut -f3`, which is correct.

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/intel_test.sh`
Expected: `Total: 4 passed, 0 failed`

- [ ] **Step 5: Confirm the existing suite still parses the new providers’ absence**

Run: `make test`
Expected: every existing `*_test.sh` still ends `0 failed` (no provider is enabled by default, so nothing changed for them).

- [ ] **Step 6: Commit**

```bash
git add lib/intel.sh test/intel_test.sh
git commit -m "feat(intel): 4-field provider contract + suppress flag

swatter_intel_score now returns score<TAB>label<TAB>suppress_flag; a
provider may emit a 4th 'suppress' verdict (known-good soft-allowlist).
3-field legacy providers (ipsum/spamhaus/abuseipdb) remain valid.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: GreyNoise provider

**Files:**
- Create: `lib/providers/greynoise.sh`
- Test: `test/greynoise_test.sh` (new)

**Interfaces:**
- Produces: `provider_greynoise <ip>` printing `score \t ttl \t label \t verdict`, or exit 1 for no-data. Reads `GREYNOISE_KEY`, `GREYNOISE_DAILY_QUOTA`, `INTEL_CACHE_TTL`, `STATE_DIR`, `SWATTER_HAVE_CURL`, `SWATTER_HAVE_JQ`.

- [ ] **Step 1: Write the failing test** — create `test/greynoise_test.sh`:

```bash
#!/usr/bin/env bash
# test/greynoise_test.sh — GreyNoise mapping with mocked curl.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/providers/greynoise.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-gn.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; GREYNOISE_KEY="testkey"; GREYNOISE_DAILY_QUOTA=1000
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=1

# Mock curl: echo whatever $GN_RESP holds, exit per $GN_RC.
GN_RESP='{}'; GN_RC=0
curl() { printf '%s' "$GN_RESP"; return "$GN_RC"; }

field() { provider_greynoise "$1" 2>/dev/null | cut -f"$2"; }
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

GN_RESP='{"classification":"malicious","riot":false,"name":"Mirai"}'
check mal-score "$(field 1.1.1.1 1)" "100"
check mal-supp  "$(field 1.1.1.1 4)" ""

GN_RESP='{"classification":"benign","riot":true,"name":"Google"}'
check riot-score "$(field 2.2.2.2 1)" "0"
check riot-supp  "$(field 2.2.2.2 4)" "suppress"

GN_RESP='{"classification":"benign","riot":false,"name":"Censys"}'
check ben-score "$(field 3.3.3.3 1)" "0"
check ben-supp  "$(field 3.3.3.3 4)" ""

GN_RESP='{"classification":"unknown","riot":false}'
if provider_greynoise 4.4.4.4 >/dev/null 2>&1; then echo "FAIL unknown-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

# Transport failure -> no-data.
GN_RC=7; GN_RESP=''
if provider_greynoise 5.5.5.5 >/dev/null 2>&1; then echo "FAIL curlfail-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
GN_RC=0

# Empty key -> no-data.
GREYNOISE_KEY=""
if provider_greynoise 6.6.6.6 >/dev/null 2>&1; then echo "FAIL nokey-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/greynoise_test.sh`
Expected: FAIL — `provider_greynoise` does not exist yet (`command not found` → all cases fail/printf empty).

- [ ] **Step 3: Implement** `lib/providers/greynoise.sh`:

```bash
#!/usr/bin/env bash
# providers/greynoise.sh — GreyNoise Community API reputation + RIOT suppress.
#
# GET https://api.greynoise.io/v3/community/{ip} with header "key: <KEY>".
# Free Community tier. classification=malicious -> 100; riot=true -> suppress
# (known business service, soft-allowlist); benign -> 0 (label only); unknown
# or 404 -> no data. A per-day quota guard mirrors abuseipdb. Any transport
# failure is treated as no-data, never a block.

GREYNOISE_URL="https://api.greynoise.io/v3/community"

_greynoise_quota_file() { printf '%s/feeds/greynoise.quota.%s' "${STATE_DIR}" "$(date -u +%Y%m%d)"; }
_greynoise_quota_ok() {
    local qf used; qf="$(_greynoise_quota_file)"; used="$(cat "$qf" 2>/dev/null || echo 0)"
    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    (( used < ${GREYNOISE_DAILY_QUOTA:-100} ))
}
_greynoise_quota_inc() {
    local qf used; qf="$(_greynoise_quota_file)"; used="$(cat "$qf" 2>/dev/null || echo 0)"
    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    printf '%s' "$(( used + 1 ))" > "$qf" 2>/dev/null || true
}

provider_greynoise() {
    local ip="$1"
    [[ -n "${GREYNOISE_KEY:-}" ]] || return 1
    [[ "${SWATTER_HAVE_CURL}" -eq 1 && "${SWATTER_HAVE_JQ}" -eq 1 ]] || return 1
    _greynoise_quota_ok || { log_debug "greynoise daily quota exhausted"; return 1; }

    local resp; resp="$(curl --max-time 5 -fsS "${GREYNOISE_URL}/${ip}" \
        -H "key: ${GREYNOISE_KEY}" -H "Accept: application/json" 2>/dev/null)" || return 1
    _greynoise_quota_inc
    [[ -n "$resp" ]] || return 1

    local cls riot name ttl="${INTEL_CACHE_TTL}"
    cls="$(printf '%s' "$resp"  | jq -r '.classification // empty' 2>/dev/null)"
    riot="$(printf '%s' "$resp" | jq -r '.riot // false'          2>/dev/null)"
    name="$(printf '%s' "$resp" | jq -r '.name // empty'          2>/dev/null)"

    if [[ "$riot" == "true" ]]; then
        printf '0\t%s\triot:%s\tsuppress\n' "$ttl" "${name:-riot}"; return 0
    fi
    case "$cls" in
        malicious) printf '100\t%s\tmalicious:%s\t\n' "$ttl" "${name:-gn}"; return 0 ;;
        benign)    printf '0\t%s\tbenign:%s\t\n'      "$ttl" "${name:-gn}"; return 0 ;;
        *)         return 1 ;;
    esac
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/greynoise_test.sh`
Expected: `Total: 7 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add lib/providers/greynoise.sh test/greynoise_test.sh
git commit -m "feat(intel): GreyNoise provider (malicious raises, RIOT suppresses)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Project Honey Pot http:BL provider

**Files:**
- Create: `lib/providers/projecthoneypot.sh`
- Modify: `lib/common.sh` (add `SWATTER_HAVE_DNS` probe + `_swatter_dns_a` helper)
- Test: `test/projecthoneypot_test.sh` (new)

**Interfaces:**
- Produces: `provider_projecthoneypot <ip>` printing `score \t ttl \t label \t` (no suppress) or exit 1. Uses `HTTPBL_KEY`, `INTEL_CACHE_TTL`, and `_swatter_dns_a <name>` (resolves first A record via dig/host/nslookup).
- Produces (common.sh): `SWATTER_HAVE_DNS` (0/1), `_swatter_dns_a <hostname>` echoing the first A-record dotted-quad or nothing.

- [ ] **Step 1: Write the failing test** — create `test/projecthoneypot_test.sh`:

```bash
#!/usr/bin/env bash
# test/projecthoneypot_test.sh — http:BL decode with a mocked DNS resolver.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/providers/projecthoneypot.sh"

PASS=0; FAIL=0
INTEL_CACHE_TTL=86400; HTTPBL_KEY="abcdefghijkl"; SWATTER_HAVE_DNS=1

# Mock the resolver: return $HBL_A for any query.
HBL_A=""
_swatter_dns_a() { [[ -n "$HBL_A" ]] && printf '%s\n' "$HBL_A"; }

field() { provider_projecthoneypot "$1" 2>/dev/null | cut -f"$2"; }
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# 127.<days>.<threat>.<type>: comment-spammer, threat 255 -> score 100.
HBL_A="127.2.255.4"; check spammer-max "$(field 1.2.3.4 1)" "100"
# harvester, threat 128 -> ~50.
HBL_A="127.1.128.2"; check harvester-mid "$(field 1.2.3.4 1)" "50"
# search-engine type 0: octet3 is an SE id, not a threat -> no-data.
HBL_A="127.0.7.0"
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL se-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
# non-127 first octet -> no-data.
HBL_A="0.0.0.0"
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL non127-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
# IPv6 -> no-data (http:BL is v4 only).
HBL_A="127.2.255.4"
if provider_projecthoneypot 2001:db8::1 >/dev/null 2>&1; then echo "FAIL v6-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
# No DNS client -> no-data.
SWATTER_HAVE_DNS=0
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL nodns-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi
SWATTER_HAVE_DNS=1
# Empty key -> no-data.
HTTPBL_KEY=""
if provider_projecthoneypot 1.2.3.4 >/dev/null 2>&1; then echo "FAIL nokey-nodata"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/projecthoneypot_test.sh`
Expected: FAIL — provider undefined.

- [ ] **Step 3a: Add the DNS helper to `lib/common.sh`.** In the dependency-probe block (near where `SWATTER_HAVE_CURL`/`SWATTER_HAVE_JQ` are set), add:

```bash
# DNS client for the DNS-based lookups (http:BL, Team Cymru ASN). Optional.
if have dig; then SWATTER_HAVE_DNS=1; SWATTER_DNS_TOOL="dig"
elif have host; then SWATTER_HAVE_DNS=1; SWATTER_DNS_TOOL="host"
elif have nslookup; then SWATTER_HAVE_DNS=1; SWATTER_DNS_TOOL="nslookup"
else SWATTER_HAVE_DNS=0; SWATTER_DNS_TOOL=""; fi

# _swatter_dns_a <hostname> : echo the first A-record dotted-quad, or nothing.
_swatter_dns_a() {
    local name="$1"
    case "${SWATTER_DNS_TOOL}" in
        dig)      dig +short +time=3 +tries=1 A "$name" 2>/dev/null | awk '/^[0-9]+\./{print; exit}' ;;
        host)     host -W 3 -t A "$name" 2>/dev/null | awk '/has address/{print $NF; exit}' ;;
        nslookup) nslookup -type=A "$name" 2>/dev/null | awk '/^Address: /{print $2; exit}' ;;
    esac
}

# _swatter_dns_txt <hostname> : echo the first TXT record (quotes stripped), or nothing.
_swatter_dns_txt() {
    local name="$1"
    case "${SWATTER_DNS_TOOL}" in
        dig)      dig +short +time=3 +tries=1 TXT "$name" 2>/dev/null | head -1 | sed 's/^"//; s/"$//' ;;
        host)     host -W 3 -t TXT "$name" 2>/dev/null | sed -n 's/.*descriptive text "\(.*\)"$/\1/p' | head -1 ;;
        nslookup) nslookup -type=TXT "$name" 2>/dev/null | sed -n 's/.*text = "\(.*\)"$/\1/p' | head -1 ;;
    esac
}
```

(`_swatter_dns_txt` is consumed by Task 4; add it here so the DNS helpers live together.)

- [ ] **Step 3b: Implement** `lib/providers/projecthoneypot.sh`:

```bash
#!/usr/bin/env bash
# providers/projecthoneypot.sh — Project Honey Pot http:BL (DNS blocklist).
#
# Query <KEY>.<reversed-octets>.dnsbl.httpbl.org A. A hit answers 127.D.S.T:
# D=days-since-activity, S=threat 0-255, T=visitor-type bitmask
# (0=search engine, 1=suspicious, 2=harvester, 4=comment spammer). IPv4 only.
# Type 0 means octet3 is a SEARCH-ENGINE ID, not a threat -> no data. Any DNS
# failure, NXDOMAIN, or non-127 answer -> no data.

provider_projecthoneypot() {
    local ip="$1"
    [[ -n "${HTTPBL_KEY:-}" ]] || return 1
    [[ "${SWATTER_HAVE_DNS:-0}" -eq 1 ]] || return 1
    # IPv4 only.
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1

    local o1 o2 o3 o4; IFS=. read -r o1 o2 o3 o4 <<<"$ip"
    local query="${HTTPBL_KEY}.${o4}.${o3}.${o2}.${o1}.dnsbl.httpbl.org"
    local a; a="$(_swatter_dns_a "$query")"
    [[ -n "$a" ]] || return 1

    local a1 days threat vtype; IFS=. read -r a1 days threat vtype <<<"$a"
    [[ "$a1" == "127" ]] || return 1
    [[ "$vtype" =~ ^[0-9]+$ && "$threat" =~ ^[0-9]+$ ]] || return 1
    (( vtype == 0 )) && return 1     # pure search engine: octet3 is an SE id

    local score=$(( threat * 100 / 255 )); (( score > 100 )) && score=100
    printf '%s\t%s\thttpbl:t%s:s%s:d%s\t\n' "$score" "${INTEL_CACHE_TTL}" "$vtype" "$threat" "$days"
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/projecthoneypot_test.sh`
Expected: `Total: 8 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add lib/providers/projecthoneypot.sh lib/common.sh test/projecthoneypot_test.sh
git commit -m "feat(intel): Project Honey Pot http:BL provider + DNS helpers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Hosting-ASN signal — `lib/asn.sh`

**Files:**
- Create: `lib/asn.sh`, `config/hosting-asns.txt`
- Test: `test/asn_test.sh` (new)

**Interfaces:**
- Produces:
  - `swatter_asn_resolve <ip>` → echoes the origin ASN number (no `AS` prefix) or nothing; caches under `$STATE_DIR/asn/<ip>`.
  - `swatter_asn_is_hosting <ip>` → if the resolved ASN is in `HOSTING_ASNS_FILE`, echoes `AS<n>(<name>)` and returns 0; else returns 1.
  - `_swatter_asn_attack_shaped <evidence_json>` → returns 0 if the evidence is attack-shaped (decisive_rule set, or hibad_fail>0, or burst sub-score ≥ 50), else 1.
- Consumes: `ASN_SIGNAL_ENABLE`, `HOSTING_ASNS_FILE`, `W_ASN`, `INTEL_CACHE_TTL`, `STATE_DIR`, `SWATTER_HAVE_DNS`, `_swatter_dns_txt`.

- [ ] **Step 1: Write the failing test** — create `test/asn_test.sh`:

```bash
#!/usr/bin/env bash
# test/asn_test.sh — Cymru ASN resolve/match (mocked DNS) + attack-shaped gate.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/asn.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-asn.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/asn"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_DNS=1; ASN_SIGNAL_ENABLE="true"; W_ASN=12
HOSTING_ASNS_FILE="$STATE_DIR/hosting.txt"
printf '16276 # OVH\n14061 # DigitalOcean\n' > "$HOSTING_ASNS_FILE"

# Mock TXT resolver: Cymru origin format "ASN | prefix | CC | registry | date".
CYMRU_TXT=""
_swatter_dns_txt() { [[ -n "$CYMRU_TXT" ]] && printf '%s\n' "$CYMRU_TXT"; }

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

CYMRU_TXT='16276 | 51.222.0.0/16 | FR | ripencc | 2015-01-01'
check resolve-ovh "$(swatter_asn_resolve 51.222.1.1)" "16276"
if swatter_asn_is_hosting 51.222.1.1 >/dev/null; then PASS=$((PASS+1)); else echo "FAIL ovh-is-hosting"; FAIL=$((FAIL+1)); fi

CYMRU_TXT='15169 | 8.8.8.0/24 | US | arin | 2000-01-01'
rm -f "$STATE_DIR/asn/8.8.8.8"
if swatter_asn_is_hosting 8.8.8.8 >/dev/null; then echo "FAIL google-not-hosting"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

# Attack-shaped gate.
if _swatter_asn_attack_shaped '{"sub":{"burst":10},"hibad_fail":12,"decisive_rule":""}'; then PASS=$((PASS+1)); else echo "FAIL shaped-hibad"; FAIL=$((FAIL+1)); fi
if _swatter_asn_attack_shaped '{"sub":{"burst":80},"hibad_fail":0,"decisive_rule":""}'; then PASS=$((PASS+1)); else echo "FAIL shaped-burst"; FAIL=$((FAIL+1)); fi
if _swatter_asn_attack_shaped '{"sub":{"burst":5},"hibad_fail":0,"decisive_rule":"scanner_profile"}'; then PASS=$((PASS+1)); else echo "FAIL shaped-rule"; FAIL=$((FAIL+1)); fi
if _swatter_asn_attack_shaped '{"sub":{"burst":5},"hibad_fail":0,"decisive_rule":""}'; then echo "FAIL clean-not-shaped"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/asn_test.sh`
Expected: FAIL — `lib/asn.sh` does not exist.

- [ ] **Step 3a: Create the default list** `config/hosting-asns.txt`:

```
# hosting-asns.txt — datacenter / hosting / bulletproof ASNs.
# One AS number per line; '#' starts a comment (name kept for the audit label).
# Edit freely. Used only when ASN_SIGNAL_ENABLE="true". The signal adds a small
# bounded boost ONLY when an offender's behavior is already attack-shaped, so a
# legitimate visitor from one of these networks is never penalized on origin
# alone. AWS EC2 (14618/16509) is intentionally omitted by default — huge legit
# traffic; uncomment if your box is a pure API/origin with no AWS-based users.
16276   # OVH
14061   # DigitalOcean
24940   # Hetzner
20473   # Vultr / Choopa
63949   # Akamai / Linode
51167   # Contabo
9009    # M247
49981   # WorldStream
#14618  # AWS EC2 (legacy) — high legit traffic; opt in deliberately
#16509  # AWS EC2 — high legit traffic; opt in deliberately
```

- [ ] **Step 3b: Implement** `lib/asn.sh`:

```bash
#!/usr/bin/env bash
# lib/asn.sh — Team Cymru IP->ASN origin lookup + hosting-set match.
#
# Resolves an IP's origin ASN via Cymru DNS (origin.asn.cymru.com /
# origin6.asn.cymru.com), cached under $STATE_DIR/asn/<ip>. The hosting match is
# evaluated LIVE against HOSTING_ASNS_FILE each call, so editing the list takes
# effect without re-resolving. Only ever called for IPs past WATCH.

# Reverse IPv4 octets: 1.2.3.4 -> 4.3.2.1
_asn_rev_v4() { local a b c d; IFS=. read -r a b c d <<<"$1"; printf '%s.%s.%s.%s' "$d" "$c" "$b" "$a"; }

# swatter_asn_resolve <ip> : echo origin ASN (digits) or nothing.
swatter_asn_resolve() {
    local ip="$1" cache="${STATE_DIR}/asn/$1" now mtime age txt asn
    [[ "${SWATTER_HAVE_DNS:-0}" -eq 1 ]] || return 1
    if [[ -f "$cache" ]]; then
        now="$(swatter_now)"; mtime="$(stat_mtime "$cache" 2>/dev/null || echo 0)"
        age=$(( now - mtime ))
        if (( age < INTEL_CACHE_TTL )); then cat "$cache" 2>/dev/null; return 0; fi
    fi
    local query
    if [[ "$ip" == *:* ]]; then
        return 1   # IPv6 origin6 nibble-reverse: see note below; v4 covers the default list
    else
        query="$(_asn_rev_v4 "$ip").origin.asn.cymru.com"
    fi
    txt="$(_swatter_dns_txt "$query")" || return 1
    [[ -n "$txt" ]] || return 1
    # "13335 | 1.1.1.0/24 | US | arin | ..." ; first field, first token (multi-origin).
    asn="$(printf '%s' "$txt" | cut -d'|' -f1 | tr -d ' ' )"
    asn="${asn%% *}"
    [[ "$asn" =~ ^[0-9]+$ ]] || return 1
    mkdir -p "${STATE_DIR}/asn" 2>/dev/null && printf '%s' "$asn" > "$cache" 2>/dev/null
    printf '%s' "$asn"
}

# swatter_asn_is_hosting <ip> : echo "AS<n>(<name>)" + return 0 if hosting, else 1.
swatter_asn_is_hosting() {
    local ip="$1" asn line fasn name
    [[ -f "${HOSTING_ASNS_FILE:-}" ]] || return 1
    asn="$(swatter_asn_resolve "$ip")" || return 1
    [[ -n "$asn" ]] || return 1
    while IFS= read -r line; do
        line="${line%%#*}"; fasn="$(printf '%s' "$line" | tr -d ' ')"
        [[ -z "$fasn" ]] && continue
        if [[ "$fasn" == "$asn" ]]; then
            name="$(awk -v a="$asn" '$1==a{sub(/^[^#]*#[ ]*/,""); print; exit}' "${HOSTING_ASNS_FILE}")"
            printf 'AS%s(%s)' "$asn" "${name:-hosting}"; return 0
        fi
    done < "${HOSTING_ASNS_FILE}"
    return 1
}

# _swatter_asn_attack_shaped <evidence_json> : 0 if attack-shaped, else 1.
_swatter_asn_attack_shaped() {
    local ev="$1" rule hibad burst
    rule="$(printf '%s' "$ev"  | sed -n 's/.*"decisive_rule":"\([^"]*\)".*/\1/p')"
    hibad="$(printf '%s' "$ev" | sed -n 's/.*"hibad_fail":\([0-9]*\).*/\1/p')"
    burst="$(printf '%s' "$ev" | sed -n 's/.*"burst":\([0-9]*\).*/\1/p')"
    [[ -n "$rule" ]] && return 0
    [[ "$hibad" =~ ^[0-9]+$ ]] && (( hibad > 0 )) && return 0
    [[ "$burst" =~ ^[0-9]+$ ]] && (( burst >= 50 )) && return 0
    return 1
}
```

> IPv6 note: the default hosting list is AS-number based and the Cymru v6 path (`origin6` + nibble-reverse) is a clean follow-up, but v4 covers the shipped default set; `swatter_asn_resolve` returns no-data for v6 today (safe — no boost), and a `# TODO(v1.3.1): origin6 nibble-reverse` comment marks it. This is an intentional, documented scope edge, not a placeholder in the code path.

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/asn_test.sh`
Expected: `Total: 8 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add lib/asn.sh config/hosting-asns.txt test/asn_test.sh
git commit -m "feat(asn): Team Cymru hosting-ASN signal (resolve, match, gate)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Honeypot detection in `score.awk`

**Files:**
- Modify: `lib/score.awk` (BEGIN loader, per-request scan, MIN_REQS guard, evidence)
- Modify: `lib/score.sh` (`_swatter_run_scorer` passes `-v HONEYPOTS=`)
- Test: `test/honeypot_test.sh` (new)

**Interfaces:**
- Produces: when a request path matches a honeypot pattern, the IP's emitted line has `score=100`, `decisive_rule="honeypot"`, and `"honeypot":1` in the evidence JSON, regardless of request volume.
- Consumes: `HONEYPOT_PATHS_FILE` (via `-v HONEYPOTS=<path>`).

- [ ] **Step 1: Write the failing test** — create `test/honeypot_test.sh`:

```bash
#!/usr/bin/env bash
# test/honeypot_test.sh — a single honeypot-path hit perm-floors at 100.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/ingest.sh"

PASS=0; FAIL=0
NOW_EPOCH=1749557400
tmp="$(mktemp -d "${TMPDIR:-/tmp}/swatter-hp.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
tstamp() { date -u -d "@$1" '+%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null || date -u -r "$1" '+%d/%b/%Y:%H:%M:%S +0000'; }

printf '/__trap_a7f3(/|$)\n' > "$tmp/honeypot.paths"

run() { # <logfile> -> "score<TAB>evidence" for first IP
  _swatter_parse example.com < "$1" \
    | gawk -v NOW="$NOW_EPOCH" -v WINDOW=600 -v MIN_REQS=15 -v RATE_SAT=8 -v SCORE_WATCH=50 \
           -v W_RATE=18 -v W_ERR_RATIO=16 -v W_ERR_BURST=12 -v W_FANOUT=12 \
           -v W_BADPATH=22 -v W_UA=6 -v W_POST_FLOOD=8 -v W_NOVHOST=6 \
           -v BADPATHS="${ROOT}/config/badpaths.conf" -v HONEYPOTS="$tmp/honeypot.paths" \
           -f "${ROOT}/lib/score.awk" | awk -F'\t' 'NR==1{print $2"\t"$4}'
}
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# ONE hit on the trap, well below MIN_REQS, must score 100.
: > "$tmp/trap.log"
printf '%s - - [%s] "GET /__trap_a7f3/ HTTP/1.1" 404 0 "-" "curl/8"\n' "66.66.66.66" "$(tstamp "$NOW_EPOCH")" >> "$tmp/trap.log"
line="$(run "$tmp/trap.log")"
check trap-score "$(printf '%s' "$line" | cut -f1)" "100"
case "$(printf '%s' "$line" | cut -f2)" in
  *'"honeypot":1'*) PASS=$((PASS+1));;
  *) echo "FAIL trap-evidence-flag"; FAIL=$((FAIL+1));;
esac
case "$(printf '%s' "$line" | cut -f2)" in
  *'"decisive_rule":"honeypot"'*) PASS=$((PASS+1));;
  *) echo "FAIL trap-decisive-rule"; FAIL=$((FAIL+1));;
esac

# A normal visitor NOT hitting the trap is unaffected (no honeypot flag).
: > "$tmp/clean.log"
for i in $(seq 1 18); do printf '%s - - [%s] "GET /page%s HTTP/1.1" 200 0 "-" "Mozilla/5.0"\n' "70.0.0.1" "$(tstamp "$NOW_EPOCH")" "$i" >> "$tmp/clean.log"; done
case "$(run "$tmp/clean.log" | cut -f2)" in
  *'"honeypot":1'*) echo "FAIL clean-no-flag"; FAIL=$((FAIL+1));;
  *) PASS=$((PASS+1));;
esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/honeypot_test.sh`
Expected: FAIL — score.awk ignores `HONEYPOTS`; the single sub-MIN_REQS hit yields `NONE`/no line.

- [ ] **Step 3: Implement honeypot in `lib/score.awk`.** Make four edits:

(a) In `BEGIN`, after the badpaths loader `close(BADPATHS)` block, add a honeypot loader:

```awk
    # Load honeypot trap patterns (operator-defined; a hit = instant perm).
    nhp = 0
    if (HONEYPOTS != "") {
        while ((getline hpl < HONEYPOTS) > 0) {
            if (hpl ~ /^[ \t]*#/) continue
            if (hpl ~ /^[ \t]*$/) continue
            hp_rx[nhp] = hpl; nhp++
        }
        close(HONEYPOTS)
    }
```

(b) In the per-request block, after the bad-path scan loop (`break` ... end of the `for (i...)`), add:

```awk
    # Honeypot trap: any hit flags the IP for an instant-perm decision.
    for (h = 0; h < nhp; h++) {
        if (path ~ hp_rx[h]) { honeypot[ip] = 1; break }
    }
```

(c) In the `END` scoring loop, change the MIN_REQS floor-guard so a honeypot hit bypasses it. Replace:

```awk
        if (n < MIN_REQS && bm < 100) continue   # below floor, unless CRITICAL
```

with:

```awk
        hp = honeypot[ip] + 0
        if (n < MIN_REQS && bm < 100 && hp == 0) continue   # below floor (CRITICAL/honeypot bypass)
```

(d) In the decisive-floor section, add the honeypot floor as the highest-priority rule (right after `floor = 0; frule = ""`):

```awk
        if (hp)                                              { floor = 100; frule = "honeypot" }
```

and add the evidence field — in the evidence JSON build, after the `decisive_rule` line, add:

```awk
        ev = ev ",\"honeypot\":" hp
```

- [ ] **Step 4: Pass `HONEYPOTS` from `lib/score.sh`.** In `_swatter_run_scorer`, add the `-v` after the `BADPATHS` line:

```bash
         -v BADPATHS="${BADPATHS_CONF}" \
         -v HONEYPOTS="${HONEYPOT_PATHS_FILE:-}" \
```

- [ ] **Step 5: Run it, verify it passes**

Run: `bash test/honeypot_test.sh`
Expected: `Total: 4 passed, 0 failed`

- [ ] **Step 6: Run the full scorer suite (regression — honeypot off by default)**

Run: `bash test/score_test.sh`
Expected: still `0 failed` (no `HONEYPOTS` passed there → `nhp=0`, no behavior change).

- [ ] **Step 7: Commit**

```bash
git add lib/score.awk lib/score.sh test/honeypot_test.sh
git commit -m "feat(honeypot): instant-perm trap-path detection in the scorer

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Low-and-slow persistence — store layer

**Files:**
- Modify: `lib/store_sqlite.sh` (schema + `swatter_store_sighting_*`, `swatter_store_counts`)
- Test: `test/persist_test.sh` (new)

**Interfaces:**
- Produces:
  - `swatter_store_sighting_add <ip> <score> <bucket_seconds>` — upsert one `(ip, bucket=floor(now/bucket_seconds))` row, `hits+1`, `worst_score=MAX`.
  - `swatter_store_sighting_buckets <ip> <window_days>` — echo the count of distinct buckets for the IP within the window (numeric, `0` on flatfile).
  - `swatter_store_sighting_clear <ip>` — delete the IP's sighting rows.
  - `swatter_store_sighting_sweep <window_days>` — delete rows older than the window.
  - `swatter_store_counts` — echo `temp_offenders \t perm_offenders` (for metrics; `0\t0` on flatfile).

- [ ] **Step 1: Write the failing test** — create `test/persist_test.sh`:

```bash
#!/usr/bin/env bash
# test/persist_test.sh — sightings: distinct-bucket counting, dedup, clear, sweep.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-persist.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=7
swatter_store_init
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# swatter_now is real time; bucket=3600. Two adds in the same hour = ONE bucket.
swatter_store_sighting_add 1.2.3.4 55 3600
swatter_store_sighting_add 1.2.3.4 60 3600
check same-bucket-dedup "$(swatter_store_sighting_buckets 1.2.3.4 3)" "1"

# Inject 5 older distinct buckets directly, all within 3 days -> 6 total.
db="$STATE_DIR/swatter.db"
now=$(swatter_now)
for k in 1 2 3 4 5; do
  b=$(( (now - k*7200) / 3600 ))
  sqlite3 "$db" "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts) VALUES('1.2.3.4',$b,1,55,$((now-k*7200)));"
done
check six-buckets "$(swatter_store_sighting_buckets 1.2.3.4 3)" "6"

# Clear removes them all.
swatter_store_sighting_clear 1.2.3.4
check cleared "$(swatter_store_sighting_buckets 1.2.3.4 3)" "0"

# Sweep drops rows older than the window.
oldb=$(( (now - 10*86400) / 3600 ))
sqlite3 "$db" "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts) VALUES('9.9.9.9',$oldb,1,55,$((now-10*86400)));"
swatter_store_sighting_sweep 3
check swept "$(swatter_store_sighting_buckets 9.9.9.9 30)" "0"

# Counts.
swatter_store_record 5.5.5.5 temp csf 3600 80 "r" 0
swatter_store_record 6.6.6.6 perm csf 0 95 "r" 0
counts="$(swatter_store_counts)"
check temp-count "$(printf '%s' "$counts" | cut -f1)" "1"
check perm-count "$(printf '%s' "$counts" | cut -f2)" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/persist_test.sh`
Expected: FAIL — `sightings` table + functions don’t exist.

- [ ] **Step 3: Implement in `lib/store_sqlite.sh`.**

(a) In `swatter_store_init`'s sqlite heredoc, add the table + index before `SQL`:

```sql
CREATE TABLE IF NOT EXISTS sightings(
  ip TEXT, bucket INTEGER, hits INTEGER DEFAULT 0,
  worst_score INTEGER DEFAULT 0, last_ts INTEGER,
  PRIMARY KEY (ip, bucket));
CREATE INDEX IF NOT EXISTS ix_sightings_ip ON sightings(ip);
```

(b) Append the new functions at the end of the file:

```bash
# --- low-and-slow persistence (sqlite only; flatfile no-ops) ----------------
swatter_store_sighting_add() {
    local ip="$1" score="$2" bsec="${3:-3600}"
    _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local now bucket sip; now="$(swatter_now)"; bucket=$(( now / bsec ))
    sip="$(_sql_escape "$ip")"
    _sql "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts)
          VALUES('${sip}',${bucket},1,${score:-0},${now})
          ON CONFLICT(ip,bucket) DO UPDATE SET
            hits=hits+1, worst_score=MAX(worst_score,${score:-0}), last_ts=${now};"
}

swatter_store_sighting_buckets() {
    local ip="$1" wdays="${2:-3}"
    _store_ip_ok "$ip" || { echo 0; return 0; }
    if [[ "${STORE}" != "sqlite" ]]; then echo 0; return 0; fi
    local cutoff sip; cutoff=$(( $(swatter_now) - wdays*86400 )); sip="$(_sql_escape "$ip")"
    local c; c="$(_sqlq "SELECT COUNT(*) FROM sightings WHERE ip='${sip}' AND last_ts>${cutoff};")"
    [[ "$c" =~ ^[0-9]+$ ]] && echo "$c" || echo 0
}

swatter_store_sighting_clear() {
    local ip="$1"; _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local sip; sip="$(_sql_escape "$ip")"
    _sql "DELETE FROM sightings WHERE ip='${sip}';"
}

swatter_store_sighting_sweep() {
    local wdays="${1:-3}"
    [[ "${STORE}" == "sqlite" ]] || return 0
    local cutoff; cutoff=$(( $(swatter_now) - wdays*86400 ))
    _sql "DELETE FROM sightings WHERE last_ts<${cutoff};"
}

# Echo "temp_offenders <TAB> perm_offenders" (for metrics).
swatter_store_counts() {
    if [[ "${STORE}" != "sqlite" ]]; then printf '0\t0\n'; return 0; fi
    local t p
    t="$(_sqlq "SELECT COUNT(*) FROM offenders WHERE temp_count>0 AND perm=0;")"
    p="$(_sqlq "SELECT COUNT(*) FROM offenders WHERE perm=1;")"
    [[ "$t" =~ ^[0-9]+$ ]] || t=0; [[ "$p" =~ ^[0-9]+$ ]] || p=0
    printf '%s\t%s\n' "$t" "$p"
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/persist_test.sh`
Expected: `Total: 8 passed, 0 failed` (or `SKIP` if sqlite3 absent).

- [ ] **Step 5: Commit**

```bash
git add lib/store_sqlite.sh test/persist_test.sh
git commit -m "feat(persist): sightings table for low-and-slow escalation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Prometheus textfile metrics — `lib/metrics.sh`

**Files:**
- Create: `lib/metrics.sh`
- Test: `test/metrics_test.sh` (new)

**Interfaces:**
- Produces:
  - `swatter_metrics_emit` — print the full `.prom` exposition to stdout (HELP/TYPE + samples).
  - `swatter_metrics_write [path]` — atomically write the exposition to `${1:-$METRICS_FILE}` (no-op when empty; warns once + skips when the dir is missing/unwritable).
- Consumes: `SWATTER_VERSION`, `SWATTER_MODE`, `STATE_DIR`, feed file paths, `swatter_store_counts`, quota files, run counters via globals `SWATTER_RUN_WATCHED`/`SWATTER_RUN_ACTED`/`SWATTER_RUN_BREAKER` (set by the scan; default 0).

- [ ] **Step 1: Write the failing test** — create `test/metrics_test.sh`:

```bash
#!/usr/bin/env bash
# test/metrics_test.sh — exposition format + atomic write + empty-disables.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/metrics.sh"

PASS=0; FAIL=0
STORE=flatfile
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-metrics.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
SWATTER_VERSION="1.3.0"; SWATTER_MODE="enforce"
SWATTER_RUN_WATCHED=3; SWATTER_RUN_ACTED=1; SWATTER_RUN_BREAKER=0
swatter_store_init
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

out="$(swatter_metrics_emit)"
case "$out" in *'# TYPE swatter_build_info gauge'*) PASS=$((PASS+1));; *) echo "FAIL has-type"; FAIL=$((FAIL+1));; esac
case "$out" in *'swatter_build_info{version="1.3.0"} 1'*) PASS=$((PASS+1));; *) echo "FAIL build-info"; FAIL=$((FAIL+1));; esac
case "$out" in *'swatter_scan_watched 3'*) PASS=$((PASS+1));; *) echo "FAIL watched"; FAIL=$((FAIL+1));; esac
case "$out" in *'swatter_mode{mode="enforce"} 1'*) PASS=$((PASS+1));; *) echo "FAIL mode"; FAIL=$((FAIL+1));; esac

# Atomic write produces a readable file.
swatter_metrics_write "$STATE_DIR/swatter.prom"
[[ -s "$STATE_DIR/swatter.prom" ]] && PASS=$((PASS+1)) || { echo "FAIL wrote-file"; FAIL=$((FAIL+1)); }

# Empty path disables (no error, no file).
swatter_metrics_write ""
PASS=$((PASS+1))  # reaching here without error is the assertion

# Missing dir warns + skips, never errors.
swatter_metrics_write "/nonexistent-dir-xyz/swatter.prom" 2>/dev/null && true
PASS=$((PASS+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/metrics_test.sh`
Expected: FAIL — `lib/metrics.sh` missing.

- [ ] **Step 3: Implement** `lib/metrics.sh`:

```bash
#!/usr/bin/env bash
# lib/metrics.sh — node_exporter textfile-collector exposition for Swatter.
#
# swatter_metrics_emit  -> prints the .prom text to stdout.
# swatter_metrics_write -> atomically writes it to $METRICS_FILE (or $1).
# Best-effort: never fails the scan; a missing/unwritable dir warns once + skips.

_metric_feed_age() {  # <feed_file> -> seconds since mtime, or -1
    local f="$1" now mtime
    [[ -f "$f" ]] || { echo "-1"; return; }
    now="$(swatter_now)"; mtime="$(stat_mtime "$f" 2>/dev/null || echo 0)"
    echo $(( now - mtime ))
}

swatter_metrics_emit() {
    local now; now="$(swatter_now)"
    local counts t p; counts="$(swatter_store_counts 2>/dev/null)"
    t="$(printf '%s' "$counts" | cut -f1)"; p="$(printf '%s' "$counts" | cut -f2)"
    [[ "$t" =~ ^[0-9]+$ ]] || t=0; [[ "$p" =~ ^[0-9]+$ ]] || p=0
    local failed=0; declare -F swatter_failclosed_active >/dev/null && { swatter_failclosed_active && failed=1; }

    printf '# HELP swatter_build_info Swatter version.\n# TYPE swatter_build_info gauge\n'
    printf 'swatter_build_info{version="%s"} 1\n' "${SWATTER_VERSION:-unknown}"
    printf '# HELP swatter_mode Active mode.\n# TYPE swatter_mode gauge\n'
    printf 'swatter_mode{mode="%s"} 1\n' "${SWATTER_MODE:-report}"
    printf '# HELP swatter_scan_timestamp_seconds Last scan completion (unix).\n# TYPE swatter_scan_timestamp_seconds gauge\n'
    printf 'swatter_scan_timestamp_seconds %s\n' "$now"
    printf '# HELP swatter_scan_watched IPs over WATCH last run.\n# TYPE swatter_scan_watched gauge\n'
    printf 'swatter_scan_watched %s\n' "${SWATTER_RUN_WATCHED:-0}"
    printf '# HELP swatter_scan_acted Blocks issued last run.\n# TYPE swatter_scan_acted gauge\n'
    printf 'swatter_scan_acted %s\n' "${SWATTER_RUN_ACTED:-0}"
    printf '# HELP swatter_circuit_breaker_tripped 1 if the breaker tripped last run.\n# TYPE swatter_circuit_breaker_tripped gauge\n'
    printf 'swatter_circuit_breaker_tripped %s\n' "${SWATTER_RUN_BREAKER:-0}"
    printf '# HELP swatter_failclosed 1 if CSF denies are disabled (allowlist unhealthy).\n# TYPE swatter_failclosed gauge\n'
    printf 'swatter_failclosed %s\n' "$failed"
    printf '# HELP swatter_offenders Current offenders by state.\n# TYPE swatter_offenders gauge\n'
    printf 'swatter_offenders{state="temp"} %s\n' "$t"
    printf 'swatter_offenders{state="perm"} %s\n' "$p"
    printf '# HELP swatter_feed_age_seconds Age of an intel/range feed file.\n# TYPE swatter_feed_age_seconds gauge\n'
    printf 'swatter_feed_age_seconds{feed="cloudflare"} %s\n' "$(_metric_feed_age "${CLOUDFLARE_IPS_FILE:-/etc/swatter/cloudflare.cidr}")"
    printf 'swatter_feed_age_seconds{feed="ipsum"} %s\n'      "$(_metric_feed_age "${STATE_DIR}/feeds/ipsum.txt")"
    printf 'swatter_feed_age_seconds{feed="spamhaus"} %s\n'   "$(_metric_feed_age "${STATE_DIR}/feeds/spamhaus.cidr")"
    local qf used
    for prov in abuseipdb greynoise; do
        qf="${STATE_DIR}/feeds/${prov}.quota.$(date -u +%Y%m%d)"
        used="$(cat "$qf" 2>/dev/null || echo 0)"; [[ "$used" =~ ^[0-9]+$ ]] || used=0
        printf '# TYPE swatter_intel_quota_used gauge\nswatter_intel_quota_used{provider="%s"} %s\n' "$prov" "$used"
    done
}

_SW_METRICS_WARNED=0
swatter_metrics_write() {
    local target="${1:-${METRICS_FILE:-}}"
    [[ -n "$target" ]] || return 0
    local dir; dir="$(dirname "$target")"
    if [[ ! -d "$dir" || ! -w "$dir" ]]; then
        (( _SW_METRICS_WARNED == 0 )) && { log_warn "metrics: ${dir} missing or unwritable; skipping"; _SW_METRICS_WARNED=1; }
        return 0
    fi
    local tmp; tmp="$(mktemp "${dir}/.swatter-metrics.XXXXXX")" || return 0
    swatter_metrics_emit > "$tmp" 2>/dev/null && mv -f "$tmp" "$target" 2>/dev/null || rm -f "$tmp" 2>/dev/null
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/metrics_test.sh`
Expected: `Total: 9 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add lib/metrics.sh test/metrics_test.sh
git commit -m "feat(metrics): Prometheus textfile exporter (atomic, best-effort)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Scan-loop wiring (`score.sh`) — suppress, ASN boost, honeypot perm, persistence, metrics

This is the integration task. It refactors the inline block body into a reusable helper and threads the four new behaviors through `swatter_scan`.

**Files:**
- Modify: `lib/score.sh` (`swatter_scan`, new `_swatter_execute_block`)
- Modify: `bin/swatter` (source `lib/asn.sh` + `lib/metrics.sh`; init `swatter_intel`/store already done — confirm asn/metrics sourced)
- Test: `test/scan_wire_test.sh` (new)

**Interfaces:**
- Consumes: `swatter_intel_score` (3-field), `swatter_asn_is_hosting`, `_swatter_asn_attack_shaped`, `swatter_store_sighting_*`, `swatter_metrics_write`, existing `swatter_classify`/`swatter_csf_*`/`swatter_cf_*`/`swatter_store_*`.
- Produces: per-run globals `SWATTER_RUN_WATCHED`, `SWATTER_RUN_ACTED`, `SWATTER_RUN_BREAKER` (read by metrics).

- [ ] **Step 1: Write the failing integration test** — create `test/scan_wire_test.sh`. It stubs the firewall + classifier + intel and drives `swatter_scan` over a synthetic scored stream by replacing `_swatter_run_scorer`, then asserts the audit log:

```bash
#!/usr/bin/env bash
# test/scan_wire_test.sh — swatter_scan routing: suppress->exempt, honeypot->perm,
# asn boost, persistence escalation. Firewall + classify + intel are stubbed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

# Load real modules under test.
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/metrics.sh"
source "${ROOT}/lib/score.sh"

PASS=0; FAIL=0
STORE=sqlite; SWATTER_MODE="enforce"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-wire.XXXXXX")"
LOG_DIR="$STATE_DIR/log"; mkdir -p "$LOG_DIR"
trap 'rm -rf "$STATE_DIR"' EXIT
# thresholds + caps + weights
SCORE_WATCH=50; SCORE_TEMP=70; SCORE_PERM=85
TTL_LADDER="3600 21600 86400"; REPEAT_N=3; REPEAT_WINDOW_DAYS=7; CRITICAL_TTL_FLOOR=86400
MAX_BLOCKS_PER_RUN=25; MAX_CSF_DENIES_PER_RUN=10; W_REPUTATION=14
ASN_SIGNAL_ENABLE="true"; W_ASN=12; HOSTING_ASNS_FILE="$STATE_DIR/hosting.txt"
printf '16276 # OVH\n' > "$HOSTING_ASNS_FILE"
PERSIST_ENABLE="true"; PERSIST_N=3; PERSIST_WINDOW_DAYS=3; PERSIST_BUCKET_SECONDS=3600
METRICS_FILE=""; CF_MODE="off"; DIRECT_WEB_PORTS=""
swatter_store_init

# --- stubs ---
swatter_failclosed_active() { return 1; }     # healthy
swatter_build_direct_set()  { :; }
swatter_cf_sweep_expired()  { :; }
swatter_intel_available()   { return 1; }     # intel off unless a test re-defines score
swatter_classify()          { echo "DIRECT"; }   # everything direct -> CSF
swatter_is_never_block()    { return 1; }
swatter_cf_manages_plane()  { return 1; }
LAST_CSF=""
swatter_csf_temp() { LAST_CSF="temp $1 $2"; return 0; }
swatter_csf_perm() { LAST_CSF="perm $1"; return 0; }
swatter_cf_block() { return 0; }
swatter_notify()   { :; }
# ASN: 1.2.3.4 is OVH; resolve mock via asn.sh's resolver -> stub the resolver.
swatter_asn_resolve() { [[ "$1" == "1.2.3.4" ]] && echo 16276; return 0; }

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
last_action() { tail -1 "$LOG_DIR/decisions.jsonl" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p'; }

# Helper: feed one synthetic scored line by overriding _swatter_run_scorer.
feed() { local line="$1"; _swatter_run_scorer() { printf '%s\n' "$line"; }; }

# 1) honeypot evidence -> perm regardless of low score.
feed $'8.8.4.4\t100\t1\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"honeypot","honeypot":1,"top_vhost":""}'
swatter_intel_score() { printf '0\t\t0\n'; }
swatter_scan >/dev/null 2>&1
check honeypot-perm "$(last_action)" "perm"

# 2) suppress flag -> exempt even with a high score.
feed $'9.9.9.9\t95\t40\t{"sub":{"burst":0},"novhost":0,"hibad_fail":0,"decisive_rule":"high_badpath_repeat","honeypot":0,"top_vhost":"x.com"}'
swatter_intel_score() { printf '95\triot:google\t1\n'; }     # suppress=1
swatter_scan >/dev/null 2>&1
check suppress-exempt "$(last_action)" "exempt"

# 3) ASN boost: behavioral 64 (< TEMP 70) + OVH + attack-shaped -> boosted to temp.
feed $'1.2.3.4\t64\t30\t{"sub":{"burst":0},"novhost":0,"hibad_fail":12,"decisive_rule":"","honeypot":0,"top_vhost":"x.com"}'
swatter_intel_score() { printf '0\t\t0\n'; }
swatter_scan >/dev/null 2>&1
check asn-boost-temp "$(last_action)" "temp"

# 4) Same IP/score but NOT hosting (5.5.5.5) -> stays watch.
swatter_asn_resolve() { return 1; }
feed $'5.5.5.5\t64\t30\t{"sub":{"burst":0},"novhost":0,"hibad_fail":12,"decisive_rule":"","honeypot":0,"top_vhost":"x.com"}'
swatter_scan >/dev/null 2>&1
check no-asn-watch "$(last_action)" "watch"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/scan_wire_test.sh`
Expected: FAIL — honeypot still goes through the temp ladder (not forced perm), suppress isn’t honored (the 3-field intel return isn’t parsed), and no ASN boost is applied.

- [ ] **Step 3: Refactor the block body into `_swatter_execute_block` in `lib/score.sh`.** Add this function above `swatter_scan`:

```bash
# Execute a decided block on the right plane. Reads/updates the run-scoped
# globals _SW_TOTAL_BLOCKS / SWATTER_RUN_ACTED. Echoes nothing; audits + records.
#   _swatter_execute_block <ip> <action> <ttl> <folded> <reason> <ev> <rep> <novhost> <top_vhost> <healthy>
_swatter_execute_block() {
    local ip="$1" action="$2" ttl="$3" folded="$4" reason="$5" ev="$6" rep="$7" novhost="$8" top_vhost="$9" healthy="${10}"
    # never-block, LAST, right before acting.
    local nb
    if nb="$(swatter_is_never_block "$ip")"; then
        log_info "exempt ${ip} (${nb}) score=${folded}"
        _swatter_audit "$ip" "$folded" "exempt" "none" 0 "exempt:${nb}" "$ev" "$rep"; return 1
    fi
    if (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )); then
        log_warn "circuit_breaker: MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN} reached; ${ip} skipped"
        SWATTER_RUN_BREAKER=1
        _swatter_audit "$ip" "$folded" "skipped-cap" "none" 0 "circuit_breaker" "$ev" "$rep"; return 1
    fi
    local plane; plane="$(swatter_classify "$ip" "$novhost")"
    local channel="none" did=0
    if [[ "$plane" == "DIRECT" ]]; then
        channel="csf"
        if (( ! healthy )); then
            log_warn "fail-closed: not CSF-denying ${ip} (allowlist unhealthy)"
            _swatter_audit "$ip" "$folded" "skipped-failclosed" "csf" "$ttl" "$reason" "$ev" "$rep"; return 1
        fi
        if [[ "$action" == "perm" ]]; then swatter_csf_perm "$ip" "$reason" && did=1
        else swatter_csf_temp "$ip" "$ttl" "$reason" && did=1; fi
    else
        channel="cloudflare"
        if ! swatter_cf_manages_plane; then
            _swatter_audit "$ip" "$folded" "skipped-cf-plane" "$channel" 0 "${reason} cf_mode=${CF_MODE}" "$ev" "$rep"; return 1
        fi
        [[ "$action" == "perm" ]] && ttl="$(_swatter_pick_ttl 99)"
        swatter_cf_block "$ip" "$ttl" "$reason" "$top_vhost" && did=1
    fi
    if (( did )); then
        _SW_TOTAL_BLOCKS=$(( _SW_TOTAL_BLOCKS + 1 )); SWATTER_RUN_ACTED=$(( SWATTER_RUN_ACTED + 1 ))
        swatter_store_sighting_clear "$ip"
        swatter_store_record "$ip" "$action" "$channel" "$ttl" "$folded" "$reason" \
            "$([[ "${SWATTER_MODE}" == "enforce" ]] && echo 0 || echo 1)"
    fi
    _swatter_audit "$ip" "$folded" "$action" "$channel" "$ttl" "$reason" "$ev" "$rep"
    return 0
}
```

- [ ] **Step 4: Rewrite the body of `swatter_scan`’s per-IP loop** to use the helper and add the four behaviors. Replace the loop (from `local ip score reqs ev novhost rep replabel folded` through the end of the `while` loop) with:

```bash
    local ip score reqs ev novhost rep replabel suppress folded
    _SW_TOTAL_BLOCKS=0; SWATTER_RUN_WATCHED=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
    while IFS=$'\t' read -r ip score reqs ev; do
        [[ -n "$ip" ]] || continue
        SWATTER_RUN_WATCHED=$(( SWATTER_RUN_WATCHED + 1 ))

        novhost="$(printf '%s' "$ev" | sed -n 's/.*"novhost":\([0-9]*\).*/\1/p')"
        [[ "$novhost" =~ ^[0-9]+$ ]] || novhost=0
        local top_vhost; top_vhost="$(printf '%s' "$ev" | sed -n 's/.*"top_vhost":"\([^"]*\)".*/\1/p')"
        local is_honeypot=0
        printf '%s' "$ev" | grep -q '"honeypot":1' && is_honeypot=1

        # Reputation enrichment (now 3-field: score, label, suppress).
        rep=0; replabel=""; suppress=0
        if swatter_intel_available; then
            local ir; ir="$(swatter_intel_score "$ip")"
            rep="$(printf '%s' "$ir" | cut -f1)"; replabel="$(printf '%s' "$ir" | cut -f2)"
            suppress="$(printf '%s' "$ir" | cut -f3)"
            [[ "$rep" =~ ^[0-9]+$ ]] || rep=0; [[ "$suppress" =~ ^[01]$ ]] || suppress=0
        fi

        folded="$score"
        if [[ "$suppress" != "1" ]] && (( rep > 0 )); then
            folded="$(_swatter_fold_reputation "$score" "$rep")"
        fi

        # ASN conditional boost (only when not suppressed and behavior is attack-shaped).
        local asn_label=""
        if [[ "$suppress" != "1" && "${ASN_SIGNAL_ENABLE:-false}" == "true" ]] \
           && _swatter_asn_attack_shaped "$ev"; then
            if asn_label="$(swatter_asn_is_hosting "$ip")"; then
                folded=$(( folded + ${W_ASN:-12} )); (( folded > 100 )) && folded=100
            else asn_label=""; fi
        fi

        local reason="score=${folded}"
        [[ -n "$replabel" ]] && reason="${reason} intel=${replabel}(${rep})"
        [[ -n "$asn_label" ]] && reason="${reason} asn=${asn_label}+${W_ASN:-12}"

        # Suppression is total: exempt everywhere, before any action or sighting.
        if [[ "$suppress" == "1" ]]; then
            log_info "exempt ${ip} (intel:${replabel}) score=${folded}"
            _swatter_audit "$ip" "$folded" "exempt" "none" 0 "intel:${replabel}" "$ev" "$rep"
            continue
        fi

        # Honeypot -> instant perm (skip the ladder).
        if (( is_honeypot )); then
            if swatter_store_is_perm "$ip"; then
                _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"; continue
            fi
            _swatter_execute_block "$ip" "perm" 0 "$folded" "honeypot ${reason}" "$ev" "$rep" "$novhost" "$top_vhost" "$healthy"
            continue
        fi

        if (( folded >= SCORE_TEMP )); then
            if swatter_store_is_perm "$ip"; then
                log_debug "${ip} already perm-blocked; skipping"
                _swatter_audit "$ip" "$folded" "noop-perm" "none" 0 "$reason" "$ev" "$rep"; continue
            fi
            local prior; prior="$(swatter_store_recent_temp_count "$ip")"
            [[ "$prior" =~ ^[0-9]+$ ]] || prior=0
            local action ttl=0
            if (( prior + 1 >= REPEAT_N )); then action="perm"
            else
                action="temp"; ttl="$(_swatter_pick_ttl "$prior")"
                if printf '%s' "$ev" | grep -q '"badpath_cat":"CRITICAL"'; then
                    (( ttl < CRITICAL_TTL_FLOOR )) && ttl="${CRITICAL_TTL_FLOOR}"
                fi
            fi
            _swatter_execute_block "$ip" "$action" "$ttl" "$folded" "$reason" "$ev" "$rep" "$novhost" "$top_vhost" "$healthy"
        else
            # WATCH band: low-and-slow accrual + escalation.
            _swatter_audit "$ip" "$folded" "watch" "none" 0 "$reason" "$ev" "$rep"
            if [[ "${PERSIST_ENABLE:-true}" == "true" && "${STORE}" == "sqlite" ]]; then
                swatter_store_sighting_add "$ip" "$folded" "${PERSIST_BUCKET_SECONDS:-3600}"
                local nb; nb="$(swatter_store_sighting_buckets "$ip" "${PERSIST_WINDOW_DAYS:-3}")"
                if [[ "$nb" =~ ^[0-9]+$ ]] && (( nb >= ${PERSIST_N:-6} )); then
                    _swatter_execute_block "$ip" "temp" "$(_swatter_pick_ttl 0)" "$folded" \
                        "low_and_slow_persist buckets=${nb} ${reason}" "$ev" "$rep" "$novhost" "$top_vhost" "$healthy"
                fi
            fi
        fi
    done < "$scored"

    [[ "${PERSIST_ENABLE:-true}" == "true" ]] && swatter_store_sighting_sweep "${PERSIST_WINDOW_DAYS:-3}"

    log_info "scan complete: ${SWATTER_RUN_WATCHED} over-watch, ${SWATTER_RUN_ACTED} acted (mode=${SWATTER_MODE}, cap=${MAX_BLOCKS_PER_RUN})"
    swatter_metrics_write

    if (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )) && [[ -n "${NOTIFY_EMAIL}" ]]; then
        swatter_notify "swatter circuit breaker tripped on $(hostname -s 2>/dev/null)" \
            "Reached MAX_BLOCKS_PER_RUN=${MAX_BLOCKS_PER_RUN}. Review ${LOG_DIR}/decisions.jsonl." || true
    fi
```

> The old `total_blocks`/`watched`/`acted` locals are replaced by `_SW_TOTAL_BLOCKS` and the `SWATTER_RUN_*` globals (so metrics can read them). The `intel_on` local is gone — `swatter_intel_available` is called inline. Keep the `parsed`/`scored` mktemp + trap setup and the `swatter_build_direct_set`/`swatter_cf_sweep_expired`/`healthy` preamble exactly as-is above this loop.

- [ ] **Step 5: Source the new modules in `bin/swatter`.** Find the block that sources `lib/*.sh` (near `lib/intel.sh`/`lib/score.sh`) and add, in dependency order:

```bash
source "${SWATTER_LIB_DIR}/asn.sh"
source "${SWATTER_LIB_DIR}/metrics.sh"
```

- [ ] **Step 6: Run the integration test, verify it passes**

Run: `bash test/scan_wire_test.sh`
Expected: `Total: 4 passed, 0 failed` (or SKIP without sqlite3).

- [ ] **Step 7: Full regression**

Run: `make test`
Expected: every suite `0 failed`.

- [ ] **Step 8: Commit**

```bash
git add lib/score.sh bin/swatter test/scan_wire_test.sh
git commit -m "feat(scan): wire suppress, ASN boost, honeypot-perm, persistence, metrics

Refactors the block body into _swatter_execute_block and threads the new
behaviors through swatter_scan: suppress->exempt (total), honeypot->instant
perm, attack-shaped hosting-ASN boost, low-and-slow sighting accrual +
escalation, and an end-of-scan metrics write.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: CLI subcommands — `swatter honeypot` + `swatter metrics`

**Files:**
- Modify: `bin/swatter` (`cmd_honeypot`, `cmd_metrics`, dispatch + usage)
- Test: `test/cli_test.sh` (new)

**Interfaces:**
- Produces: `swatter honeypot` prints a robots.txt line + an invisible-anchor snippet for the configured trap (or a suggested path); `swatter metrics [--print]` writes the textfile (or prints to stdout with `--print`).

- [ ] **Step 1: Write the failing test** — create `test/cli_test.sh`:

```bash
#!/usr/bin/env bash
# test/cli_test.sh — honeypot + metrics subcommands.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-cli-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-cli.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
HONEYPOT_PATHS_FILE="$state/honeypot.paths"
METRICS_FILE=""
STORE="flatfile"
EOF

out="$(bash "${ROOT}/bin/swatter" honeypot 2>/dev/null)"
case "$out" in *'Disallow:'*) PASS=$((PASS+1));; *) echo "FAIL honeypot-robots"; FAIL=$((FAIL+1));; esac
case "$out" in *'display:none'*|*'hidden'*) PASS=$((PASS+1));; *) echo "FAIL honeypot-anchor"; FAIL=$((FAIL+1));; esac

out="$(bash "${ROOT}/bin/swatter" metrics --print 2>/dev/null)"
case "$out" in *'swatter_build_info'*) PASS=$((PASS+1));; *) echo "FAIL metrics-print"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/cli_test.sh`
Expected: FAIL — unknown subcommands `honeypot`/`metrics`.

- [ ] **Step 3: Implement the commands in `bin/swatter`.** Add the two functions (near the other `cmd_*` definitions):

```bash
cmd_honeypot() {
    local path
    path="$(awk 'NF && $1 !~ /^#/ {print; exit}' "${HONEYPOT_PATHS_FILE:-/nonexistent}" 2>/dev/null)"
    if [[ -z "$path" ]]; then
        path="/__trap_$(head -c4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo a7f3c1d9)/"
        echo "# No HONEYPOT_PATHS_FILE entry found — suggested trap path: ${path}"
        echo "# Add it (anchored) to ${HONEYPOT_PATHS_FILE:-/etc/swatter/honeypot.paths}:"
        printf '#   %s(/|$)\n\n' "${path%/}"
    fi
    local clean="${path%(/\|$)}"; clean="${clean%/}"
    cat <<EOF
# --- robots.txt (advertise the trap so only path-scanning bots find it) ---
User-agent: *
Disallow: ${clean}/

# --- invisible anchor (drop into a shared template; humans never see it) ---
<a href="${clean}/" style="display:none" aria-hidden="true" rel="nofollow">do-not-follow</a>

# Any IP that requests ${clean}/ is scored 100 and permanently banned on its
# next Swatter scan (plane-classified + allowlist-checked as always).
EOF
}

cmd_metrics() {
    if [[ "${1:-}" == "--print" ]]; then swatter_metrics_emit; else swatter_metrics_write; fi
}
```

- [ ] **Step 4: Add dispatch + usage.** In the `case "$cmd"` dispatch, add:

```bash
        honeypot)      cmd_honeypot ;;
        metrics)       cmd_metrics "$@" ;;
```

and add two lines to the usage/help text:

```
  honeypot               print robots.txt + invisible-anchor snippet for the trap path
  metrics [--print]      write the Prometheus textfile (or print it)
```

- [ ] **Step 5: Run it, verify it passes**

Run: `bash test/cli_test.sh`
Expected: `Total: 3 passed, 0 failed`

- [ ] **Step 6: Commit**

```bash
git add bin/swatter test/cli_test.sh
git commit -m "feat(cli): swatter honeypot + swatter metrics subcommands

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: `test-config` readiness checks

**Files:**
- Modify: `bin/swatter` (`cmd_test_config`)
- Test: `test/testconfig_test.sh` (new)

**Interfaces:**
- Produces: advisory lines (never a non-zero exit) reporting provider/key/DNS/file/metrics-dir readiness.

- [ ] **Step 1: Write the failing test** — create `test/testconfig_test.sh`:

```bash
#!/usr/bin/env bash
# test/testconfig_test.sh — readiness advisories surface in test-config output.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-tc-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-tc.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
STORE="flatfile"
INTEL_PROVIDERS="greynoise"
GREYNOISE_KEY=""
ASN_SIGNAL_ENABLE="true"
HOSTING_ASNS_FILE="$state/does-not-exist.txt"
EOF

out="$(bash "${ROOT}/bin/swatter" test-config 2>&1)"
case "$out" in *greynoise*) PASS=$((PASS+1));; *) echo "FAIL mentions-greynoise"; FAIL=$((FAIL+1));; esac
case "$out" in *[Kk]ey*) PASS=$((PASS+1));; *) echo "FAIL warns-empty-key"; FAIL=$((FAIL+1));; esac
case "$out" in *hosting*|*ASN*|*asn*) PASS=$((PASS+1));; *) echo "FAIL warns-asn-file"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/testconfig_test.sh`
Expected: FAIL — no readiness advisories yet.

- [ ] **Step 3: Implement.** In `cmd_test_config` (in `bin/swatter`), before its final summary, add an advisories block:

```bash
    echo
    echo "  --- v1.3 feature readiness (advisory) ---"
    local p
    for p in ${INTEL_PROVIDERS:-}; do
        case "$p" in
            greynoise)       [[ -n "${GREYNOISE_KEY:-}" ]] && echo "  intel greynoise: key set" || echo "  intel greynoise: GREYNOISE_KEY empty -> provider inert" ;;
            projecthoneypot) [[ -n "${HTTPBL_KEY:-}" ]] && echo "  intel projecthoneypot: key set" || echo "  intel projecthoneypot: HTTPBL_KEY empty -> provider inert" ;;
            abuseipdb)       [[ -n "${ABUSEIPDB_KEY:-}" ]] && echo "  intel abuseipdb: key set" || echo "  intel abuseipdb: ABUSEIPDB_KEY empty -> provider inert" ;;
        esac
    done
    if [[ "${ASN_SIGNAL_ENABLE:-false}" == "true" || " ${INTEL_PROVIDERS:-} " == *" projecthoneypot "* ]]; then
        [[ "${SWATTER_HAVE_DNS:-0}" -eq 1 ]] \
            && echo "  dns client: ${SWATTER_DNS_TOOL} (http:BL + ASN ok)" \
            || echo "  dns client: NONE -> http:BL + ASN inert (install dig/host)"
    fi
    if [[ "${ASN_SIGNAL_ENABLE:-false}" == "true" ]]; then
        [[ -s "${HOSTING_ASNS_FILE:-}" ]] && echo "  asn signal: hosting list ${HOSTING_ASNS_FILE} ($(grep -cE '^[0-9]' "${HOSTING_ASNS_FILE}" 2>/dev/null) ASNs)" \
            || echo "  asn signal: HOSTING_ASNS_FILE ${HOSTING_ASNS_FILE:-unset} missing/empty -> no boost"
    fi
    if [[ -n "${HONEYPOT_PATHS_FILE:-}" ]]; then
        [[ -s "${HONEYPOT_PATHS_FILE}" ]] && echo "  honeypot: ${HONEYPOT_PATHS_FILE} active (run 'swatter honeypot' to advertise)" \
            || echo "  honeypot: ${HONEYPOT_PATHS_FILE} empty/missing -> trap disabled"
    fi
    if [[ -n "${METRICS_FILE:-}" ]]; then
        local md; md="$(dirname "${METRICS_FILE}")"
        [[ -d "$md" && -w "$md" ]] && echo "  metrics: ${METRICS_FILE} writable" || echo "  metrics: ${md} missing/unwritable -> metrics skipped"
    fi
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/testconfig_test.sh`
Expected: `Total: 3 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add bin/swatter test/testconfig_test.sh
git commit -m "feat(test-config): readiness advisories for v1.3 features

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Config defaults + example config + honeypot example

**Files:**
- Modify: `lib/common.sh` (defaults for all new keys)
- Modify: `config/swatter.example.conf` (documented keys)
- Create: `config/honeypot.paths.example`
- Test: extend `test/detect_test.sh` *or* add a tiny `test/config_defaults_test.sh`

**Interfaces:**
- Produces: every new config key has a built-in default so an un-updated `swatter.conf` keeps working.

- [ ] **Step 1: Write the failing test** — create `test/config_defaults_test.sh`:

```bash
#!/usr/bin/env bash
# test/config_defaults_test.sh — new keys have safe built-in defaults.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
check asn-default       "${ASN_SIGNAL_ENABLE}" "false"
check wasn-default      "${W_ASN}" "12"
check persist-default   "${PERSIST_ENABLE}" "true"
check persist-n         "${PERSIST_N}" "6"
check bucket-default    "${PERSIST_BUCKET_SECONDS}" "3600"
check gn-quota-default  "${GREYNOISE_DAILY_QUOTA}" "100"
check intel-has-gn      "$(case " ${INTEL_PROVIDERS} " in *' greynoise '*) echo yes;; *) echo no;; esac)" "yes"
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/config_defaults_test.sh`
Expected: FAIL — defaults unset.

- [ ] **Step 3: Add defaults to `lib/common.sh`** (in the section where other defaults like `GREYNOISE_KEY=""` and `INTEL_PROVIDERS` live — use `:` parameter-expansion so a config-set value wins):

```bash
: "${INTEL_PROVIDERS:=ipsum spamhaus abuseipdb greynoise projecthoneypot}"
: "${GREYNOISE_KEY:=}"
: "${GREYNOISE_DAILY_QUOTA:=100}"
: "${HTTPBL_KEY:=}"
: "${ASN_SIGNAL_ENABLE:=false}"
: "${HOSTING_ASNS_FILE:=/etc/swatter/hosting-asns.txt}"
: "${W_ASN:=12}"
: "${HONEYPOT_PATHS_FILE:=/etc/swatter/honeypot.paths}"
: "${HONEYPOT_OVERRIDES_SUPPRESS:=false}"
: "${PERSIST_ENABLE:=true}"
: "${PERSIST_N:=6}"
: "${PERSIST_WINDOW_DAYS:=3}"
: "${PERSIST_BUCKET_SECONDS:=3600}"
: "${METRICS_FILE:=/var/lib/node_exporter/textfile_collector/swatter.prom}"
```

> If `INTEL_PROVIDERS` already has a default assignment in `common.sh`, replace that line rather than adding a second one (grep first: `grep -n 'INTEL_PROVIDERS' lib/common.sh`).

- [ ] **Step 4: Create `config/honeypot.paths.example`:**

```
# honeypot.paths — operator-defined trap paths (one extended-regex per line).
# A request matching ANY line scores 100 and earns an instant permanent ban on
# the next scan (plane-classified + allowlist-checked as always). Bypasses
# MIN_REQS: one hit is enough.
#
# Pick a SECRET path nobody legitimately requests, advertise it only where bots
# look (run `swatter honeypot` for a robots.txt + invisible-anchor snippet), and
# copy this file to /etc/swatter/honeypot.paths. Keep patterns anchored-loose
# (no ^/$), matched case-insensitively like badpaths.
#
# Example (CHANGE THE TOKEN to something unique to your site):
# /__trap_a7f3c1d9(/|$)
```

- [ ] **Step 5: Document all new keys in `config/swatter.example.conf`.** Append, after the existing `# ---- threat intel ----` block (extend it) and as new sections:

```sh
# GreyNoise Community API (classification + RIOT suppression). Free key from
# greynoise.io. malicious -> raises; RIOT (known business services) -> soft
# allowlist (capped at WATCH); benign -> logged only.
GREYNOISE_KEY=""
GREYNOISE_DAILY_QUOTA=100
# Project Honey Pot http:BL 12-char access key (DNS lookup; needs dig/host).
HTTPBL_KEY=""

# ---- hosting-ASN signal ---------------------------------------------------
# A small bounded boost (W_ASN) added ONLY when an offender's behavior is
# already attack-shaped AND its origin ASN is a datacenter/hosting net. Needs a
# DNS client (Team Cymru lookup). A clean visitor from a hosting ASN is never
# penalized. Off by default.
ASN_SIGNAL_ENABLE="false"
HOSTING_ASNS_FILE="/etc/swatter/hosting-asns.txt"
W_ASN=12

# ---- honeypot trap --------------------------------------------------------
# Operator-defined secret paths; a single hit = score 100 = instant permanent
# ban (still plane-classified + allowlist-checked). No default (a published trap
# is useless). See config/honeypot.paths.example; run `swatter honeypot`.
HONEYPOT_PATHS_FILE="/etc/swatter/honeypot.paths"
# If a GreyNoise RIOT verdict and a honeypot hit collide, suppression wins by
# default (never perm-ban a known Google/Slack range off a forged log line).
HONEYPOT_OVERRIDES_SUPPRESS="false"

# ---- low-and-slow persistence ---------------------------------------------
# Escalate an IP that lingers in the WATCH band across many windows (SQLite
# only). Counts distinct PERSIST_BUCKET_SECONDS buckets within the window so the
# overlapping crons aren't double-counted.
PERSIST_ENABLE="true"
PERSIST_N=6
PERSIST_WINDOW_DAYS=3
PERSIST_BUCKET_SECONDS=3600

# ---- prometheus metrics ---------------------------------------------------
# node_exporter textfile-collector path. Written atomically at the end of each
# scan and via `swatter metrics`. Empty disables.
METRICS_FILE="/var/lib/node_exporter/textfile_collector/swatter.prom"
```

(Also change the existing `INTEL_PROVIDERS=` line in the example to
`INTEL_PROVIDERS="ipsum spamhaus abuseipdb greynoise projecthoneypot"`.)

- [ ] **Step 6: Run it, verify it passes**

Run: `bash test/config_defaults_test.sh`
Expected: `Total: 7 passed, 0 failed`

- [ ] **Step 7: Full regression**

Run: `make test`
Expected: all suites `0 failed`.

- [ ] **Step 8: Commit**

```bash
git add lib/common.sh config/swatter.example.conf config/honeypot.paths.example test/config_defaults_test.sh
git commit -m "feat(config): defaults + documented keys for v1.3 features

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Installer, README, version bump → 1.3.0

**Files:**
- Modify: `install/install.sh` (install `hosting-asns.txt` + `honeypot.paths.example`)
- Modify: `README.md` (provider/signal/command docs)
- Modify: `bin/swatter` (`SWATTER_VERSION="1.3.0"`)
- Test: `test/release_test.sh` already asserts version wiring — re-run it.

- [ ] **Step 1: Bump the version.** In `bin/swatter`, change `SWATTER_VERSION="1.2.2"` → `SWATTER_VERSION="1.3.0"`.

- [ ] **Step 2: Install the new config files.** In `install/install.sh`, where `badpaths.conf`/`monitoring.cidr` are copied into `/etc/swatter/`, add (don't clobber an operator-edited live file):

```bash
install -m 0644 -o root -g root "${SRC}/config/hosting-asns.txt" /etc/swatter/hosting-asns.txt 2>/dev/null || true
# honeypot is operator-authored; ship only the example, never overwrite a live file.
install -m 0644 -o root -g root "${SRC}/config/honeypot.paths.example" /etc/swatter/honeypot.paths.example 2>/dev/null || true
```

(Match the existing installer's variable names — grep for how `badpaths.conf` is installed and mirror it exactly.)

- [ ] **Step 3: Document in `README.md`.** Extend the "Threat-intel enrichment" list with GreyNoise + Project Honey Pot, and add short sections for the hosting-ASN signal, the honeypot trap (with the `swatter honeypot` helper), low-and-slow persistence, and Prometheus metrics. Add `swatter honeypot` and `swatter metrics` to the command table. Keep the tone of the existing README. Concretely, under "Threat-intel enrichment (optional, free)" replace the bullet list with:

```markdown
- **IPsum** — aggregated blocklist, no key needed.
- **Spamhaus DROP/EDROP** — hijacked/criminal netblocks, no key needed.
- **AbuseIPDB** — confidence score, free tier (1,000 checks/day), cached + quota-limited.
- **GreyNoise** — Community API classification. `malicious` raises; **RIOT**
  (known business services — Google/Slack/CDNs) is a soft never-block guard;
  `benign` scanners are logged but still judged on behavior.
- **Project Honey Pot http:BL** — DNS reputation (harvesters, comment spammers,
  suspicious hosts). Needs a free member access key and a DNS client.
```

and add a new top-level section after it:

```markdown
## Beyond reputation: ASN, traps, persistence, metrics

- **Hosting-ASN signal** *(`ASN_SIGNAL_ENABLE`)* — when an offender is already
  behaving like an attack, originating from a datacenter/bulletproof ASN
  (Team Cymru lookup) adds a small bounded boost. Legit visitors from those
  networks are never penalized on origin alone.
- **Honeypot traps** *(`HONEYPOT_PATHS_FILE`)* — define a secret path no human
  hits; one request = score 100 = instant permanent ban. `swatter honeypot`
  prints a robots.txt + invisible-anchor snippet to advertise it to bots only.
- **Low-and-slow persistence** — an IP that lingers just under the block
  threshold across many hours is escalated once it recurs in
  `PERSIST_N` distinct buckets within `PERSIST_WINDOW_DAYS`.
- **Prometheus metrics** *(`METRICS_FILE`)* — a node_exporter textfile with
  block counts, current offender counts, feed-staleness ages, quota use, and
  fail-closed state, written atomically each scan and via `swatter metrics`.
```

Add to the command table:

```markdown
| `swatter honeypot` | print robots.txt + invisible-anchor snippet for the trap path |
| `swatter metrics [--print]` | write (or print) the Prometheus textfile |
```

- [ ] **Step 4: Run the release/version test + full suite**

Run: `bash test/release_test.sh && make test`
Expected: all `0 failed`; the release test sees `1.3.0`.

- [ ] **Step 5: Commit**

```bash
git add bin/swatter install/install.sh README.md
git commit -m "release(v1.3.0): install configs, document features, bump version

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Push both remotes (does not publish a release on its own)**

```bash
git push -u origin feature/intel-engine-expansion-v1.3
```

> Per the project release rule, cutting the actual GitHub/GitLab release is a
> separate, deliberate step (`make release V=1.3.0`) done after this branch is
> reviewed and merged to `main` — push alone does not publish. Do NOT cut the
> release as part of plan execution unless the user asks.

---

## Self-Review

**1. Spec coverage** — every spec section maps to a task:
- §0 intel contract/suppress → Task 1 (return value) + Task 8 (consumption).
- §1 GreyNoise → Task 2. §2 Project Honey Pot → Task 3 (+ DNS helpers in common.sh).
- §3 ASN signal → Task 4 (module) + Task 8 (boost wiring).
- §4 honeypot → Task 5 (detection) + Task 8 (perm) + Task 9 (`swatter honeypot`).
- §5 persistence → Task 6 (store) + Task 8 (escalation).
- §6 metrics → Task 7 (emitter) + Task 8 (scan hook) + Task 9 (`swatter metrics`).
- §7 test-config/report → Task 10 (test-config); report.sh needs no change (confirmed, no task — surfaces via existing grouping).
- Config keys/files/installer/README/version → Tasks 11–12.

**2. Placeholder scan** — no "TBD/TODO-as-work"; the two `TODO(v1.3.1)` markers (IPv6 origin6) are explicitly-scoped future edges with a safe no-data code path today, not unfinished steps. All code steps carry real code.

**3. Type/signature consistency** — verified across tasks: `swatter_intel_score` 3-field (Task 1 ↔ Task 8); `provider_*` 4-field contract (Tasks 2–3 ↔ Task 1); `swatter_asn_is_hosting`/`_swatter_asn_attack_shaped` (Task 4 ↔ Task 8); `swatter_store_sighting_add/buckets/clear/sweep` + `swatter_store_counts` (Task 6 ↔ Tasks 7–8); `swatter_metrics_emit`/`swatter_metrics_write` + `SWATTER_RUN_*` globals (Task 7 ↔ Task 8); `_swatter_dns_a`/`_swatter_dns_txt` (Task 3 ↔ Tasks 3–4). `_SW_TOTAL_BLOCKS` replaces the old `total_blocks` local consistently within Task 8.

**4. Ambiguity** — "attack-shaped" is defined concretely (decisive_rule set, or hibad_fail>0, or burst≥50). Suppression precedence is explicit (total, checked first). Honeypot-vs-suppress default (suppress wins) is encoded by checking suppress before the honeypot branch in Task 8's loop.
