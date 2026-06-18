# Swatter v1.4 — Feeds + Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 6 keyless threat-intel list feeds via a generic data-driven registry, an opt-in AbuseIPDB daily blocklist provider, IPv6 ASN lookups, and the Spamhaus EDROP-deprecation fix.

**Architecture:** A single `lib/providers/listfeeds.sh` holds a registry (one row per feed: url, confidence score, kind) plus two generic handlers (`_listfeed_refresh`, `_listfeed_lookup`); `provider_<name>`/`provider_<name>_refresh` are generated per row at source time. `swatter_intel_init` sources this aggregate so the intel layer dispatches each feed by name, and `refresh-feeds` loops over `INTEL_PROVIDERS` to refresh any provider that defines a `_refresh`. The AbuseIPDB blocklist, IPv6 ASN (origin6), and Spamhaus EDROP fix are independent edits.

**Tech Stack:** Bash 4+, gawk, curl, a DNS client (`dig`/`host`), sqlite3 optional. Tests are plain self-contained bash scripts under `test/`, run with `make test`; network is mocked by shadowing `curl`/`_swatter_dns_txt` with shell functions.

## Global Constraints

- A failed/absent lookup NEVER blocks: missing key, missing curl, download failure, or missing feed file all return no-data (exit 1). Refresh writes to a `.tmp` and `mv`s **only on success**, so a transient feed outage keeps the prior file.
- List feeds are downloaded by `refresh-feeds`, not per scan; lookups run only for IPs already past WATCH and are cached. The never-block allowlist is checked last and wins over any feed hit.
- Provider output contract on a hit: `score \t INTEL_CACHE_TTL \t <name>` (3-field, **no** suppress verdict — feeds never suppress).
- Confidence tiers (exact scores): FireHOL level1 = 95, CINS = 95, DShield = 95, blocklist.de = 80, ET compromised = 80, GreenSnow = 70, AbuseIPDB blocklist = 90. Spamhaus stays 100, ipsum stays level-scaled.
- New default `INTEL_PROVIDERS` = `ipsum spamhaus abuseipdb greynoise projecthoneypot firehol_level1 blocklist_de cins greensnow dshield et_compromised`. `abuseipdb_blocklist` is OPT-IN (not in the default).
- `SWATTER_VERSION` → `1.4.0` (final task). Per the release rule, the tag + GitHub/GitLab release is a separate deliberate step after merge.
- Commit identity is configured locally (do not touch git config). End every commit message with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Branch: `feature/feeds-maintenance-v1.4` (already checked out). Push reaches both GitHub and GitLab via dual-push `origin`.
- Match surrounding bash style: `${VAR:-}` safety, `printf` not `echo -e`, tab field separators, `log_info`/`log_warn`, atomic `.tmp`+`mv` refresh idiom (see `lib/providers/ipsum.sh`).

---

## File Structure

**New files:**
- `lib/providers/listfeeds.sh` — registry + `_listfeed_refresh`/`_listfeed_lookup` + generated `provider_<name>`/`provider_<name>_refresh` for the 6 keyless feeds.
- `lib/providers/abuseipdb_blocklist.sh` — opt-in daily-blocklist provider (`provider_abuseipdb_blocklist`, `_refresh`).
- `test/listfeeds_test.sh`, `test/abuseipdb_blocklist_test.sh` — new test files.

**Modified files:**
- `lib/intel.sh` — `swatter_intel_init` sources aggregates + suppresses spurious "not found" warn; new `swatter_intel_refresh_all` helper.
- `bin/swatter` — `cmd_refresh_feeds` calls `swatter_intel_refresh_all` (replaces hardcoded lines); `SWATTER_VERSION=1.4.0`.
- `lib/asn.sh` — origin6 IPv6 path in `swatter_asn_resolve`.
- `lib/providers/spamhaus.sh` — drop the dead EDROP fetch.
- `lib/common.sh` — new `INTEL_PROVIDERS` default + `ABUSEIPDB_BLOCKLIST_CONFIDENCE`.
- `config/swatter.example.conf`, `README.md` — document the feeds.
- `test/asn_test.sh`, `test/config_defaults_test.sh` — extended.

---

## Task 1: Generic list-feed registry — `lib/providers/listfeeds.sh`

**Files:**
- Create: `lib/providers/listfeeds.sh`
- Test: `test/listfeeds_test.sh` (new)

**Interfaces:**
- Produces: at source time, defines `provider_<name>` (echoes `score \t ttl \t name` on hit, exit 1 on miss) and `provider_<name>_refresh` (downloads + parses the feed) for each name in `firehol_level1 cins dshield blocklist_de et_compromised greensnow`. Also `_listfeed_row <name>` (echoes `url|score|kind`), `_listfeed_file <name> <kind>`, `_listfeed_refresh <name>`, `_listfeed_lookup <name> <ip>`.
- Consumes: `STATE_DIR`, `INTEL_CACHE_TTL`, `SWATTER_HAVE_CURL`, and `_ip_in_cidr_file` (from `lib/allowlist.sh`, for cidr-kind lookups).

- [ ] **Step 1: Write the failing test** — create `test/listfeeds_test.sh`:

```bash
#!/usr/bin/env bash
# test/listfeeds_test.sh — registry generation, per-kind refresh/parse, lookup.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"          # for _ip_in_cidr_file (cidr lookups)
source "${ROOT}/lib/providers/listfeeds.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-lf.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_CURL=1
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Mock curl: emit $FEED_DATA.
FEED_DATA=""
curl() { printf '%s' "$FEED_DATA"; }

# (a) registry generates a provider + refresh fn for every feed name.
for n in firehol_level1 cins dshield blocklist_de et_compromised greensnow; do
  declare -F "provider_${n}" >/dev/null && declare -F "provider_${n}_refresh" >/dev/null \
    && PASS=$((PASS+1)) || { echo "FAIL gen ${n}"; FAIL=$((FAIL+1)); }
done

# (b) ip-kind feed (cins): parse strips comments, lookup hit returns tier score 95.
FEED_DATA=$'1.2.3.4\n5.6.7.8\n# comment line\n'
_listfeed_refresh cins
check cins-lines "$(grep -c . "$STATE_DIR/feeds/cins.txt")" "2"
out="$(provider_cins 1.2.3.4)"
check cins-score "$(printf '%s' "$out" | cut -f1)" "95"
check cins-name  "$(printf '%s' "$out" | cut -f3)" "cins"
provider_cins 9.9.9.9 >/dev/null 2>&1 && { echo "FAIL cins-miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# (c) cidr-kind feed (firehol_level1): membership match, score 95.
FEED_DATA=$'1.10.16.0/20\n0.0.0.0/8\n'
_listfeed_refresh firehol_level1
check fh-score "$(provider_firehol_level1 1.10.16.5 | cut -f1)" "95"
provider_firehol_level1 8.8.8.8 >/dev/null 2>&1 && { echo "FAIL fh-miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# (d) dshield-kind: 'start end prefixlen ...' -> start/prefixlen CIDR, score 95.
FEED_DATA=$'69.5.169.0\t69.5.169.255\t24\t303\tOMNIS\tUS\n'
_listfeed_refresh dshield
check ds-cidr "$(cat "$STATE_DIR/feeds/dshield.cidr")" "69.5.169.0/24"
check ds-score "$(provider_dshield 69.5.169.5 | cut -f1)" "95"

# (e) tier scores: blocklist.de=80, greensnow=70.
FEED_DATA=$'1.1.1.1\n'; _listfeed_refresh blocklist_de
check bde-score "$(provider_blocklist_de 1.1.1.1 | cut -f1)" "80"
FEED_DATA=$'2.2.2.2\n'; _listfeed_refresh greensnow
check gs-score "$(provider_greensnow 2.2.2.2 | cut -f1)" "70"

# (f) missing feed file -> no-data.
rm -f "$STATE_DIR/feeds/et_compromised.txt"
provider_et_compromised 1.2.3.4 >/dev/null 2>&1 && { echo "FAIL et-nofile"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/listfeeds_test.sh`
Expected: FAIL — `lib/providers/listfeeds.sh` does not exist.

- [ ] **Step 3: Implement** `lib/providers/listfeeds.sh`:

```bash
#!/usr/bin/env bash
# providers/listfeeds.sh — data-driven keyless list-feed providers.
#
# One registry row per feed: name -> "url|score|kind" (kind: ip | cidr | dshield).
# Two generic handlers do the work; provider_<name> and provider_<name>_refresh are
# generated per row at source time, so the intel layer dispatches each by name and
# refresh-feeds finds each _refresh. Feeds download (via `swatter refresh-feeds`)
# to $STATE_DIR/feeds/<name>.{txt|cidr}; lookup is a grep (ip) or CIDR match. A hit
# emits "score\tINTEL_CACHE_TTL\tname" (3-field; feeds never suppress).
#
# Confidence tiers: 95 = near-zero-FP (firehol_level1, cins, dshield); 80 = high
# (blocklist_de, et_compromised); 70 = moderate (greensnow). The score bounds how
# hard a feed can push a borderline (already past-WATCH) IP over TEMP.
#
# Bogon note: firehol_level1 includes reserved/bogon ranges by design — safe here,
# since intel only sees IPs past WATCH and the never-block allowlist wins last.

_LISTFEED_NAMES="firehol_level1 cins dshield blocklist_de et_compromised greensnow"

# name -> "url|score|kind"
_listfeed_row() {
    case "$1" in
        firehol_level1) echo 'https://iplists.firehol.org/files/firehol_level1.netset|95|cidr' ;;
        cins)           echo 'https://cinsscore.com/list/ci-badguys.txt|95|ip' ;;
        dshield)        echo 'https://feeds.dshield.org/block.txt|95|dshield' ;;
        blocklist_de)   echo 'https://lists.blocklist.de/lists/all.txt|80|ip' ;;
        et_compromised) echo 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt|80|ip' ;;
        greensnow)      echo 'https://blocklist.greensnow.co/greensnow.txt|70|ip' ;;
        *) return 1 ;;
    esac
}

# ip-kind feeds store one IP per line (.txt); cidr/dshield store CIDRs (.cidr).
_listfeed_file() {
    local ext="cidr"; [[ "$2" == "ip" ]] && ext="txt"
    printf '%s/feeds/%s.%s' "${STATE_DIR}" "$1" "$ext"
}

# _listfeed_refresh <name> : download + parse to the feed file (atomic).
_listfeed_refresh() {
    local name="$1" row url score kind out parse
    row="$(_listfeed_row "$name")" || { log_warn "listfeed unknown: ${name}"; return 1; }
    IFS='|' read -r url score kind <<<"$row"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "${name} refresh needs curl"; return 1; }
    out="$(_listfeed_file "$name" "$kind")"
    case "$kind" in
        ip)      parse='/^[0-9A-Fa-f]/{print $1}' ;;
        cidr)    parse='/^[0-9]/{print $1}' ;;
        dshield) parse='/^[0-9]/ && $3>=0 && $3<=32 {print $1"/"$3}' ;;
    esac
    if curl --max-time 30 -fsS "$url" 2>/dev/null | awk "$parse" > "${out}.tmp" 2>/dev/null && [[ -s "${out}.tmp" ]]; then
        mv "${out}.tmp" "$out"
        log_info "${name} feed refreshed ($(wc -l < "$out" 2>/dev/null | tr -d ' ') entries)"
    else
        rm -f "${out}.tmp" 2>/dev/null; log_warn "${name} feed download failed"; return 1
    fi
}

# _listfeed_lookup <name> <ip> : emit "score\tttl\tname" on hit, else return 1.
_listfeed_lookup() {
    local name="$1" ip="$2" row url score kind feed
    row="$(_listfeed_row "$name")" || return 1
    IFS='|' read -r url score kind <<<"$row"
    feed="$(_listfeed_file "$name" "$kind")"
    [[ -f "$feed" ]] || return 1
    if [[ "$kind" == "ip" ]]; then
        awk -v ip="$ip" '$1==ip{f=1; exit} END{exit !f}' "$feed" 2>/dev/null || return 1
    else
        declare -F _ip_in_cidr_file >/dev/null && _ip_in_cidr_file "$ip" "$feed" || return 1
    fi
    printf '%s\t%s\t%s\n' "$score" "${INTEL_CACHE_TTL}" "$name"
}

# Generate provider_<name> + provider_<name>_refresh for each registry row.
_listfeed_generate() {
    local n
    for n in ${_LISTFEED_NAMES}; do
        eval "provider_${n}()         { _listfeed_lookup ${n} \"\$1\"; }"
        eval "provider_${n}_refresh() { _listfeed_refresh ${n}; }"
    done
}
_listfeed_generate
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/listfeeds_test.sh`
Expected: `Total: 14 passed, 0 failed` (6 generation + 8 behavior assertions).

- [ ] **Step 5: Commit**

```bash
git add lib/providers/listfeeds.sh test/listfeeds_test.sh
git commit -m "feat(intel): generic keyless list-feed registry (firehol/cins/dshield/blocklist.de/et/greensnow)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Wire the registry into intel_init + refresh-feeds

**Files:**
- Modify: `lib/intel.sh` (`swatter_intel_init`; new `swatter_intel_refresh_all`)
- Modify: `bin/swatter` (`cmd_refresh_feeds`)
- Test: `test/intel_test.sh` (extend the existing file)

**Interfaces:**
- Consumes: `lib/providers/listfeeds.sh` (Task 1) defining `provider_<name>` for registry names.
- Produces: `swatter_intel_init` resolves a registry feed name to its (aggregate-defined) provider without a spurious "not found" warn; `swatter_intel_refresh_all` calls every defined `provider_<p>_refresh` for `p` in `INTEL_PROVIDERS`.

- [ ] **Step 1: Write the failing test** — append to `test/intel_test.sh` (before the final `Total:` print). It checks the init/refresh wiring with stub providers:

```bash
# --- registry wiring: intel_init sources aggregates + refresh loop ---
SWATTER_LIB_DIR="${ROOT}/lib"
# A fake aggregate provider file would normally define provider_<name>; emulate by
# pre-defining one, then assert intel_init does NOT warn for it and DOES warn for a
# genuinely-missing provider.
provider_fakefeed() { printf '50\t%s\tfakefeed\n' "$INTEL_CACHE_TTL"; }
INTEL_PROVIDERS="ipsum fakefeed totallymissing"
warns="$(swatter_intel_init 2>&1 1>/dev/null)"
case "$warns" in *fakefeed*) echo "FAIL init-warns-defined"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac
case "$warns" in *totallymissing*) PASS=$((PASS+1));; *) echo "FAIL init-missing-no-warn"; FAIL=$((FAIL+1));; esac

# swatter_intel_refresh_all calls _refresh for providers that define one, skips others.
RAN=""
provider_aaa_refresh() { RAN="${RAN}aaa "; }
provider_bbb_refresh() { RAN="${RAN}bbb "; }
provider_ccc()         { :; }   # no _refresh -> must be skipped
INTEL_PROVIDERS="aaa bbb ccc"
swatter_intel_refresh_all
check refresh-all "$RAN" "aaa bbb "
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/intel_test.sh`
Expected: FAIL — `swatter_intel_refresh_all` undefined, and `swatter_intel_init` warns for `fakefeed` (current loop warns whenever `providers/<name>.sh` is absent).

- [ ] **Step 3: Modify `lib/intel.sh`.** Replace `swatter_intel_init` and add `swatter_intel_refresh_all`:

```bash
swatter_intel_init() {
    # Aggregate provider files define multiple named providers (registry feeds);
    # source them first so per-name resolution can find them.
    local agg
    for agg in listfeeds; do
        local af="${SWATTER_LIB_DIR}/providers/${agg}.sh"
        # shellcheck disable=SC1090
        [[ -f "$af" ]] && source "$af"
    done
    local p
    for p in ${INTEL_PROVIDERS}; do
        local f="${SWATTER_LIB_DIR}/providers/${p}.sh"
        if [[ -f "$f" ]]; then
            # shellcheck disable=SC1090
            source "$f"
        elif declare -F "provider_${p}" >/dev/null; then
            :   # already defined by an aggregate (e.g. listfeeds)
        else
            log_warn "intel provider not found: ${p} (${f})"
        fi
    done
    SWATTER_INTEL_QUOTA_USED=0
}

# Refresh every list feed: call provider_<p>_refresh for each configured provider
# that defines one (per-IP providers define none and are skipped).
swatter_intel_refresh_all() {
    local p
    for p in ${INTEL_PROVIDERS}; do
        if declare -F "provider_${p}_refresh" >/dev/null; then
            provider_"${p}"_refresh || true
        fi
    done
}
```

- [ ] **Step 4: Modify `bin/swatter`.** In `cmd_refresh_feeds`, replace the two hardcoded lines

```bash
    declare -F provider_ipsum_refresh    >/dev/null && provider_ipsum_refresh || true
    declare -F provider_spamhaus_refresh >/dev/null && provider_spamhaus_refresh || true
```

with:

```bash
    swatter_intel_refresh_all
```

(`swatter_intel_init` is already called just above this in `cmd_refresh_feeds`, so all providers — including the registry aggregate — are sourced before the refresh loop runs.)

- [ ] **Step 5: Run it, verify it passes**

Run: `bash test/intel_test.sh`
Expected: all assertions pass (the original 4 plus the new wiring checks), `0 failed`.

- [ ] **Step 6: Full regression**

Run: `make test`
Expected: every suite `0 failed`.

- [ ] **Step 7: Commit**

```bash
git add lib/intel.sh bin/swatter test/intel_test.sh
git commit -m "feat(intel): source aggregate providers + self-extending refresh loop

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: AbuseIPDB daily blocklist provider (opt-in)

**Files:**
- Create: `lib/providers/abuseipdb_blocklist.sh`
- Test: `test/abuseipdb_blocklist_test.sh` (new)

**Interfaces:**
- Produces: `provider_abuseipdb_blocklist <ip>` (echoes `90 \t ttl \t abuseipdb_blocklist` on hit, exit 1 otherwise) and `provider_abuseipdb_blocklist_refresh` (downloads the blacklist to `$STATE_DIR/feeds/abuseipdb_blocklist.txt`).
- Consumes: `ABUSEIPDB_KEY`, `ABUSEIPDB_BLOCKLIST_CONFIDENCE` (default 90), `INTEL_CACHE_TTL`, `STATE_DIR`, `SWATTER_HAVE_CURL`.

- [ ] **Step 1: Write the failing test** — create `test/abuseipdb_blocklist_test.sh`:

```bash
#!/usr/bin/env bash
# test/abuseipdb_blocklist_test.sh — opt-in daily blocklist: refresh + lookup.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/providers/abuseipdb_blocklist.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-abl.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_CURL=1; ABUSEIPDB_KEY="testkey"; ABUSEIPDB_BLOCKLIST_CONFIDENCE=90
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

FEED_DATA=$'1.2.3.4\n5.6.7.8\n'
curl() { printf '%s' "$FEED_DATA"; }

provider_abuseipdb_blocklist_refresh
check abl-lines "$(grep -c . "$STATE_DIR/feeds/abuseipdb_blocklist.txt")" "2"
check abl-score "$(provider_abuseipdb_blocklist 1.2.3.4 | cut -f1)" "90"
check abl-name  "$(provider_abuseipdb_blocklist 1.2.3.4 | cut -f3)" "abuseipdb_blocklist"
provider_abuseipdb_blocklist 9.9.9.9 >/dev/null 2>&1 && { echo "FAIL abl-miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# No key -> refresh no-ops (no fetch, no file), lookup no-data.
rm -f "$STATE_DIR/feeds/abuseipdb_blocklist.txt"
ABUSEIPDB_KEY=""
provider_abuseipdb_blocklist_refresh >/dev/null 2>&1
[[ -f "$STATE_DIR/feeds/abuseipdb_blocklist.txt" ]] && { echo "FAIL abl-nokey-file"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
provider_abuseipdb_blocklist 1.2.3.4 >/dev/null 2>&1 && { echo "FAIL abl-nokey-lookup"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/abuseipdb_blocklist_test.sh`
Expected: FAIL — provider undefined.

- [ ] **Step 3: Implement** `lib/providers/abuseipdb_blocklist.sh`:

```bash
#!/usr/bin/env bash
# providers/abuseipdb_blocklist.sh — AbuseIPDB daily blocklist (opt-in).
#
# Downloads the GET /api/v2/blacklist plaintext list (IPs at/above
# ABUSEIPDB_BLOCKLIST_CONFIDENCE) once per `refresh-feeds` into
# $STATE_DIR/feeds/abuseipdb_blocklist.txt; lookup is a grep -> score 90. Reuses
# ABUSEIPDB_KEY. Opt-in: add 'abuseipdb_blocklist' to INTEL_PROVIDERS. Inert (no
# fetch, no-data) without the key or curl; any HTTP failure keeps the prior file.

ABUSEIPDB_BLOCKLIST_URL="https://api.abuseipdb.com/api/v2/blacklist"

provider_abuseipdb_blocklist_refresh() {
    local out="${STATE_DIR}/feeds/abuseipdb_blocklist.txt"
    [[ -n "${ABUSEIPDB_KEY:-}" ]] || { log_warn "abuseipdb_blocklist needs ABUSEIPDB_KEY"; return 1; }
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "abuseipdb_blocklist needs curl"; return 1; }
    if curl --max-time 30 -fsS -G "${ABUSEIPDB_BLOCKLIST_URL}" \
        --data-urlencode "confidenceMinimum=${ABUSEIPDB_BLOCKLIST_CONFIDENCE:-90}" \
        -H "Key: ${ABUSEIPDB_KEY}" -H "Accept: text/plain" 2>/dev/null \
        | awk '/^[0-9A-Fa-f]/{print $1}' > "${out}.tmp" 2>/dev/null && [[ -s "${out}.tmp" ]]; then
        mv "${out}.tmp" "$out"
        log_info "abuseipdb_blocklist refreshed ($(wc -l < "$out" 2>/dev/null | tr -d ' ') IPs)"
    else
        rm -f "${out}.tmp" 2>/dev/null; log_warn "abuseipdb_blocklist download failed"; return 1
    fi
}

provider_abuseipdb_blocklist() {
    local ip="$1" feed="${STATE_DIR}/feeds/abuseipdb_blocklist.txt"
    [[ -f "$feed" ]] || return 1
    awk -v ip="$ip" '$1==ip{f=1; exit} END{exit !f}' "$feed" 2>/dev/null || return 1
    printf '90\t%s\tabuseipdb_blocklist\n' "${INTEL_CACHE_TTL}"
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/abuseipdb_blocklist_test.sh`
Expected: `Total: 7 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add lib/providers/abuseipdb_blocklist.sh test/abuseipdb_blocklist_test.sh
git commit -m "feat(intel): opt-in AbuseIPDB daily blocklist provider

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: IPv6 ASN lookups (origin6) — `lib/asn.sh`

**Files:**
- Modify: `lib/asn.sh` (`swatter_asn_resolve` v6 branch)
- Test: `test/asn_test.sh` (extend)

**Interfaces:**
- Consumes: `_ipv6_expand` (from `lib/allowlist.sh`, already sourced by `bin/swatter`), `_swatter_dns_txt`.
- Produces: `swatter_asn_resolve <v6-ip>` resolves the origin ASN via `origin6.asn.cymru.com` (previously returned no-data for v6).

- [ ] **Step 1: Write the failing test** — append to `test/asn_test.sh` (before the final `Total:` print). It mocks the TXT resolver and records the query name:

```bash
# --- IPv6 ASN via origin6 ---
source "${ROOT}/lib/allowlist.sh"   # for _ipv6_expand
LAST_TXT_Q=""
_swatter_dns_txt() { LAST_TXT_Q="$1"; [[ -n "$CYMRU_TXT" ]] && printf '%s\n' "$CYMRU_TXT"; }
rm -f "$STATE_DIR/asn/2001:db8::1"
CYMRU_TXT='13335 | 2001:db8::/32 | US | arin | 2010-01-01'
check v6-resolve "$(swatter_asn_resolve 2001:db8::1)" "13335"
# query must target origin6 with the reversed nibble labels (ends with the high nibbles).
case "$LAST_TXT_Q" in
  *origin6.asn.cymru.com) PASS=$((PASS+1));;
  *) echo "FAIL v6-query-origin6: ${LAST_TXT_Q}"; FAIL=$((FAIL+1));;
esac
case "$LAST_TXT_Q" in
  1.0.0.0.*.8.b.d.0.1.0.0.2.origin6.asn.cymru.com) PASS=$((PASS+1));;
  *) echo "FAIL v6-query-nibbles: ${LAST_TXT_Q}"; FAIL=$((FAIL+1));;
esac
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/asn_test.sh`
Expected: FAIL — `swatter_asn_resolve` returns nothing for a v6 IP (current early-return), so `v6-resolve` fails.

- [ ] **Step 3: Implement in `lib/asn.sh`.** In `swatter_asn_resolve`, replace the IPv6 early-return block:

```bash
    if [[ "$ip" == *:* ]]; then
        return 1   # IPv6 origin6 nibble-reverse: see note below; v4 covers the default list
    else
        query="$(_asn_rev_v4 "$ip").origin.asn.cymru.com"
    fi
```

with:

```bash
    if [[ "$ip" == *:* ]]; then
        # IPv6: expand to 32 hex nibbles, reverse + dot-separate, query origin6.
        declare -F _ipv6_expand >/dev/null || return 1
        local nib rev
        nib="$(_ipv6_expand "$ip")" || return 1
        rev="$(printf '%s' "$nib" | rev | sed 's/./&./g; s/\.$//')"
        query="${rev}.origin6.asn.cymru.com"
    else
        query="$(_asn_rev_v4 "$ip").origin.asn.cymru.com"
    fi
```

Also update the file header comment that mentions the v6 TODO to note origin6 is now implemented (remove the `TODO(v1.3.1)` line near the v6 handling if present).

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/asn_test.sh`
Expected: all assertions pass (the prior v4 ones plus the new v6 ones), `0 failed`.

- [ ] **Step 5: Commit**

```bash
git add lib/asn.sh test/asn_test.sh
git commit -m "feat(asn): IPv6 origin6 ASN lookups (hosting boost now works for v6)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Spamhaus EDROP fix — `lib/providers/spamhaus.sh`

**Files:**
- Modify: `lib/providers/spamhaus.sh`
- Test: `test/spamhaus_test.sh` (new — small)

**Interfaces:**
- Produces: `provider_spamhaus_refresh` fetches only `drop.txt` (the dead `edrop.txt` is removed); `provider_spamhaus` lookup unchanged.

- [ ] **Step 1: Write the failing test** — create `test/spamhaus_test.sh`:

```bash
#!/usr/bin/env bash
# test/spamhaus_test.sh — EDROP removed: a single drop.txt fetch populates the feed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/providers/spamhaus.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sh.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/feeds"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_CURL=1
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Mock curl: count calls; emit drop.txt-format lines.
CURL_CALLS=0
curl() { CURL_CALLS=$((CURL_CALLS+1)); printf '%s' $'1.10.16.0/20 ; SBL256894\n2.56.0.0/24 ; SBL999\n'; }

provider_spamhaus_refresh
check sh-single-fetch "$CURL_CALLS" "1"
check sh-cidrs "$(grep -c . "$STATE_DIR/feeds/spamhaus.cidr")" "2"
check sh-lookup "$(provider_spamhaus 1.10.16.5 | cut -f1)" "100"
# no SPAMHAUS_EDROP_URL variable should remain
[[ -z "${SPAMHAUS_EDROP_URL:-}" ]] && PASS=$((PASS+1)) || { echo "FAIL sh-edrop-var-gone"; FAIL=$((FAIL+1)); }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/spamhaus_test.sh`
Expected: FAIL — `sh-single-fetch` is 2 (current code loops over DROP + EDROP), and `SPAMHAUS_EDROP_URL` still set.

- [ ] **Step 3: Implement in `lib/providers/spamhaus.sh`.** Remove the `SPAMHAUS_EDROP_URL` line and rewrite `provider_spamhaus_refresh` to fetch only DROP:

```bash
SPAMHAUS_DROP_URL="https://www.spamhaus.org/drop/drop.txt"

provider_spamhaus_refresh() {
    local out="${STATE_DIR}/feeds/spamhaus.cidr"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "spamhaus refresh needs curl"; return 1; }
    if curl --max-time 30 -fsS "${SPAMHAUS_DROP_URL}" 2>/dev/null \
        | awk '/^[0-9]/{print $1}' > "${out}.tmp" 2>/dev/null && [[ -s "${out}.tmp" ]]; then
        sort -u "${out}.tmp" > "$out"; rm -f "${out}.tmp"
        log_info "spamhaus feed refreshed ($(wc -l < "$out" 2>/dev/null | tr -d ' ') CIDRs)"
    else
        rm -f "${out}.tmp" 2>/dev/null; log_warn "spamhaus feed download failed"; return 1
    fi
}
```

Update the file's header comment: drop the EDROP reference (the list is now just DROP, which absorbed EDROP). Leave `provider_spamhaus` (the lookup) unchanged.

- [ ] **Step 4: Run it, verify it passes**

Run: `bash test/spamhaus_test.sh`
Expected: `Total: 4 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add lib/providers/spamhaus.sh test/spamhaus_test.sh
git commit -m "fix(intel): drop deprecated Spamhaus EDROP fetch (merged into DROP)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Config defaults + example + README + version bump 1.4.0

**Files:**
- Modify: `lib/common.sh` (INTEL_PROVIDERS default + ABUSEIPDB_BLOCKLIST_CONFIDENCE)
- Modify: `bin/swatter` (`SWATTER_VERSION=1.4.0`)
- Modify: `config/swatter.example.conf`, `README.md`
- Test: `test/config_defaults_test.sh` (extend); `test/release_test.sh` (existing, re-run)

**Interfaces:**
- Produces: the 6 keyless feeds are on by default; `ABUSEIPDB_BLOCKLIST_CONFIDENCE` defaults to 90; version is 1.4.0.

- [ ] **Step 1: Write the failing test** — append to `test/config_defaults_test.sh` (before the final `Total:` print):

```bash
check intel-has-firehol "$(case " ${INTEL_PROVIDERS} " in *' firehol_level1 '*) echo yes;; *) echo no;; esac)" "yes"
check intel-has-dshield "$(case " ${INTEL_PROVIDERS} " in *' dshield '*) echo yes;; *) echo no;; esac)" "yes"
check intel-has-blde    "$(case " ${INTEL_PROVIDERS} " in *' blocklist_de '*) echo yes;; *) echo no;; esac)" "yes"
check abl-conf-default   "${ABUSEIPDB_BLOCKLIST_CONFIDENCE}" "90"
# abuseipdb_blocklist is OPT-IN: must NOT be in the default list.
check abl-optin "$(case " ${INTEL_PROVIDERS} " in *' abuseipdb_blocklist '*) echo in;; *) echo out;; esac)" "out"
```

- [ ] **Step 2: Run it, verify it fails**

Run: `bash test/config_defaults_test.sh`
Expected: FAIL — `firehol_level1` not in the default `INTEL_PROVIDERS`, `ABUSEIPDB_BLOCKLIST_CONFIDENCE` unset.

- [ ] **Step 3: Update `lib/common.sh` defaults.** Replace the existing `INTEL_PROVIDERS` default line and add the new key (grep first: `grep -n 'INTEL_PROVIDERS\|ABUSEIPDB' lib/common.sh`):

```bash
: "${INTEL_PROVIDERS:=ipsum spamhaus abuseipdb greynoise projecthoneypot firehol_level1 blocklist_de cins greensnow dshield et_compromised}"
: "${ABUSEIPDB_BLOCKLIST_CONFIDENCE:=90}"
```

- [ ] **Step 4: Bump the version** in `bin/swatter`: `SWATTER_VERSION="1.3.0"` → `SWATTER_VERSION="1.4.0"`.

- [ ] **Step 5: Document in `config/swatter.example.conf`.** Update the `INTEL_PROVIDERS` example line to the new default, and add under the threat-intel block:

```sh
# Keyless aggregated list feeds (downloaded by `swatter refresh-feeds`, no key):
#   firehol_level1 (near-zero-FP) · cins · dshield · blocklist_de · et_compromised
#   · greensnow. On by default above. Confidence-tiered: a feed hit only raises an
#   already-suspicious IP's score (intel is consulted only past WATCH).
# Opt-in AbuseIPDB daily blocklist (reuses ABUSEIPDB_KEY; add to INTEL_PROVIDERS):
#   INTEL_PROVIDERS="... abuseipdb_blocklist"
ABUSEIPDB_BLOCKLIST_CONFIDENCE=90
```

- [ ] **Step 6: Document in `README.md`.** Extend the threat-intel feed list (after the existing GreyNoise/Project Honey Pot bullets) with:

```markdown
- **Keyless list feeds** — **FireHOL level1** (near-zero-FP aggregate), **CINS Army**,
  **DShield** top attacker netblocks, **blocklist.de** (brute-force reporters),
  **Emerging Threats** compromised hosts, and **GreenSnow** (scanners) — all no-key,
  refreshed by `swatter refresh-feeds`, confidence-tiered so noisier feeds corroborate
  less. On by default.
- **AbuseIPDB daily blocklist** *(opt-in)* — a once-a-day download of the top abusive
  IPs (reuses your `ABUSEIPDB_KEY`); add `abuseipdb_blocklist` to `INTEL_PROVIDERS`.
```

And add a one-line note near the install/upgrade section: "After upgrading, run `swatter refresh-feeds` so the new feeds download."

- [ ] **Step 7: Run the tests**

Run: `bash test/config_defaults_test.sh && bash test/release_test.sh && make test`
Expected: all `0 failed`; release test sees `1.4.0`.

- [ ] **Step 8: Commit**

```bash
git add lib/common.sh bin/swatter config/swatter.example.conf README.md test/config_defaults_test.sh
git commit -m "release(v1.4.0): enable keyless feeds by default, document, bump version

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage** — every spec section maps to a task:
- §1 registry → Task 1. §2 intel_init + refresh loop → Task 2. §3 AbuseIPDB blocklist → Task 3. §4 origin6 IPv6 ASN → Task 4. §5 Spamhaus EDROP → Task 5. Config/default/example/README/version → Task 6.

**2. Placeholder scan** — no "TBD/TODO-as-work"; all code blocks are complete. (Task 4 *removes* a stale `TODO(v1.3.1)` comment — that's cleanup, not a placeholder.)

**3. Type/name consistency** — `provider_<name>` / `provider_<name>_refresh` naming is consistent across Tasks 1–3; `swatter_intel_refresh_all` defined in Task 2 and called from `bin/swatter` in the same task; registry feed names (`firehol_level1 cins dshield blocklist_de et_compromised greensnow`) identical in the registry (Task 1), the default list (Task 6), and the tests; scores (95/95/95/80/80/70, blocklist=90) match the Global Constraints. `_listfeed_file`/`_listfeed_row`/`_listfeed_lookup`/`_listfeed_refresh` signatures are consistent between the implementation and the test.

**4. Ambiguity** — kind→parse/ext mapping is explicit (ip→`.txt`/flat, cidr→`.cidr`/first-token, dshield→`.cidr`/`col1/col3`+0–32 guard). origin6 nibble-reversal is shown with the exact `rev | sed` pipeline and asserted against a concrete query name. The opt-in vs default distinction for `abuseipdb_blocklist` is asserted (`abl-optin` = out).
