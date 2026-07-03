# Swatter Swarm Host-Side Implementation Plan (v1.1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **v1.1** folds in the two-model Grok plan review
> (`…-swarm-host-review-grok.md`, both verdicts REVISE-BEFORE-EXECUTE):
> publish cursor now advances only over ACTUALLY-PUBLISHED rows; `rejected>0`
> surfaced; Task 6's test stubs `_swatter_pick_ttl` (TDD ordering was broken);
> enroll `label` sanitized to a safe charset; meta sidecar INVALIDATED (not
> kept stale) when its fetch fails; `stat_mtime` helper used everywhere;
> `INTEL_PROVIDERS` opt-in documented in conf + surfaced by `swarm status` +
> `test-config`; Task 8 shows the exact import/route diff; Task 9 rewritten
> against the REAL `curl_secrets_test.sh` pattern (`argv_clean`/`cfg_has` +
> `MOCK_STDOUT` mock — the v1 `run_case` helper did not exist); boost-fold
> numeric tests added (spec §11).

**Goal:** Implement subsystem 2 of 2 of the Swatter Swarm — the bash host side: publish confirmed offenders to the deployed hub, consume the fleet feed as an intel provider (`provider_swarm`), the fleet allowlist, the opt-in `corroborated-block` sweep, and the `swatter swarm {enroll,disable,purge,status}` CLI — against the FROZEN hub contract.

**Architecture:** One new host lib (`lib/swarm.sh`: enable-gate, host_id, token→curl-cfg helper, publish, sweep, `cmd_swarm`) + one new provider (`lib/providers/swarm.sh`: refresh/consume + per-IP lookup), one new store helper (`swatter_store_perm_ips_since`), and small hooks in `bin/swatter` (source list + dispatch + publish-after-scan + sweep-after-refresh-feeds + test-config advisory). Plus ONE additive hub endpoint (`POST /purge`) that the spec's `swatter swarm purge` requires and subsystem 1 omitted.

**Tech Stack:** bash (repo house style: `set -uo pipefail`, `log_*`/`die`, `swatter_curl_cfg` + `curl -K`, `stat_mtime`, function-override test mocks), sqlite3 + flatfile store parity, jq optional (`SWATTER_HAVE_JQ`), existing `test/*_test.sh` harness. Hub side: the existing `hub/` Worker (Vitest 4.1 + pool 0.13.5).

## Global Constraints

- **The hub contract is FROZEN** (hub plan "Global Constraints", deployed 2026-07-03 at `https://swatter-swarm-hub.peace-harbor-web.workers.dev`, custom domain `swarm.peaceharbor.com` pending operator deploy):
  - `POST /contribute` — write token — `{host_id, entries:[{ip, category?}]}` → `200 {accepted, rejected, enrolled}`; `413` over `MAX_ENTRIES` (hub default 1000); **`enrolled:false` + `accepted:0`** = host not registered, nothing stored.
  - `POST /register` — enroll token — `{host_id, label?}` → `200 {enrolled: host_id}`.
  - `GET /feed` — read token — bare `ip`/`cidr` per line (EMPTY body legal); `?format=json` → `[{ip, host_count, category, expires}]`; header `X-Swarm-Truncated: true` when capped.
  - Errors: `401` auth, `400` malformed, `413` oversized, `429` rate-limited. Any non-200 on feed = transport failure.
- **FROZEN consume obligation 1:** an **empty 200 bare feed CLEARS `swarm.txt`** (and the meta sidecar) — it must NOT be passed through `swatter_cidr_list_ok` (its `n>0` gate would reject it and freeze decay). Keep-last-good applies ONLY to non-200/transport failures.
- **FROZEN consume obligation 2:** `corroborated-block` REQUIRES the `?format=json` feed (bare has no `host_count`). `boost` may run from bare alone. Corollary (review): if the sidecar fetch FAILS while the bare feed installed, the stale sidecar is DELETED — corroboration data is either fresh or absent, never silently stale.
- **Config keys (spec §9, ALL inert by default):** `SWARM_ENABLE=false`, `SWARM_HUB_URL=""`, `SWARM_WRITE_TOKEN_FILE=/etc/swatter/swarm.write.token`, `SWARM_READ_TOKEN_FILE=/etc/swatter/swarm.read.token`, `SWARM_ENROLL_TOKEN_FILE=""`, `SWARM_PUBLISH=true`, `SWARM_ACTION=boost` (enum `boost|corroborated-block`), `SWARM_MIN_CORROBORATION=2`, `SWARM_BASE_SCORE=70`, `SWARM_ALLOW_FILE=/etc/swatter/swarm.allow.cidr`, `SWARM_MAX_AGE_DAYS=3`. `SWARM_TTL` is hub-authoritative — the host never sets expiry. **Consume additionally requires the operator to add `swarm` to `INTEL_PROVIDERS`** — documented in the example conf and surfaced by `swatter swarm status` + `test-config`.
- **Publish source set:** confirmed enforced perm bans only (`swatter_store_perm_ips` semantics: `action='perm'`, `dry_run=0`, still banned). Watch/temp/dry-run never publish. Timestamp cursor `$STATE_DIR/swarm.publish.cursor` advances ONLY on full success and ONLY to the max ts of rows actually SENT (review: gate-filtered rows must not consume the cursor). Publish runs inside the scan lock (`cmd_scan` after `swatter_scan`), fail-soft, never aborts a scan.
- **Every IP leaving the box passes:** `swatter_is_valid_ip_or_cidr` → `!_swatter_is_unsafe_block_target` → `!swatter_is_never_block` → not in `SWARM_ALLOW_FILE`. Every consumed IP re-runs the full local gate chain — swarm raises scores, never bypasses a gate; `corroborated-block` routes through `_swatter_execute_block` ONLY (never a raw block path).
- **Secrets:** tokens live in 0400 files, sent ONLY via `swatter_curl_cfg` + `curl -K` (never argv — `/proc/*/cmdline` is world-readable). `test/curl_secrets_test.sh` MUST gain swarm cases (Task 9, using its real `argv_clean`/`cfg_has` pattern).
- **House rules:** all curl calls use `--max-time` (30s feeds, 15s API POSTs), `-sS`, NO `--retry`, no custom User-Agent, `stat_mtime` for portable mtimes. Logs to stderr via `log_info/warn/error`; `die` only in CLI arg parsing. Tests: `test/swarm*_test.sh` auto-discovered; final line `[[ "$FAIL" -eq 0 ]]`; must run green with stdin closed (`</dev/null`); no network (curl always overridden).
- **Decisions locked by this plan** (spec gaps + review dispositions):
  - Publish `entries[].category` OMITTED in Phase 1 (contract-optional; taxonomy is spec open question §16).
  - Score scaling = `min(100, SWARM_BASE_SCORE + 15*(host_count-1))` for both boost and sweep.
  - `corroborated-block` issues **temp** blocks on the TTL ladder. It re-issues on each daily `refresh-feeds` while an IP stays corroborated — that is the keep-alive/decay semantic (ladder TTLs cap at 3d > daily cadence), bounded per sweep by `MAX_BLOCKS_PER_RUN` via `_SW_TOTAL_BLOCKS`. In report mode the sweep dry-runs through the backends exactly like `scan`/`import-bans` do (records `dry_run=1`) — consistent preview behavior, not a leak.
  - `rejected>0` in a 200 contribute response is loudly warned (bash/hub validator drift signal) but the cursor still advances — hub validation is deterministic, so wedging the cursor would retry forever without progress.
  - A chunked publish that fails mid-way re-sends the whole delta next cycle; hub upserts make that idempotent (accepted).
  - CIDR feed rows: a contained single IP scores at the conservative base (its meta `host_count` is keyed by the CIDR string, not the IP). Under-scoring is safe; the SWEEP is unaffected because it iterates meta rows directly and blocks the CIDR itself with the correct count.
  - `swatter swarm status` verb included (operator visibility for §13 disable verification).
  - `purge` requires the new additive hub endpoint (Task 8).
  - Never-block-under-swarm is proven by composition: the sweep-routes-through-`_swatter_execute_block` invariant is pinned by Task 6's stub test, and `_swatter_execute_block`'s own never-block gate is pinned by the existing `block_test.sh` — no duplicate integration harness.

---

### Task 1: Config keys + `lib/swarm.sh` core (gate, host_id, token helper) + registration

**Files:**
- Modify: `lib/common.sh` (config block, after line 138 `: "${METRICS_FILE:=...}"`)
- Modify: `config/swatter.example.conf` (append swarm section)
- Create: `lib/swarm.sh`
- Modify: `bin/swatter` (usage header ~line 28; source list line 62; dispatch ~line 440; test-config advisory loop ~line 324)
- Test: `test/swarm_test.sh`

**Interfaces:**
- Produces: `_swarm_enabled() -> 0/1` (true iff `SWARM_ENABLE=true` and `SWARM_HUB_URL` non-empty); `swatter_swarm_host_id() -> prints 32-hex id` (creates `$STATE_DIR/swarm.host_id` 0600 on first call, stable after); `_swarm_curl_cfg_token <token_file> -> prints curl -K cfg path` (caller must `rm -f`; fails 1 + warn if file missing/empty); `cmd_swarm` stub dispatched from `bin/swatter`.

- [ ] **Step 1: Write the failing test — `test/swarm_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_test.sh — host-side swarm core: gate, host_id, token cfg helper.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swarm.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
STORE="flatfile"; SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0; INTEL_CACHE_TTL=86400

# --- gate: disabled by default, and disabled => publish is a silent no-op
SWARM_ENABLE="false"; SWARM_HUB_URL=""
_swarm_enabled && { echo "FAIL gate-default-off"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
SWARM_ENABLE="true"
_swarm_enabled && { echo "FAIL gate-needs-url"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
SWARM_HUB_URL="https://hub.example"
_swarm_enabled && PASS=$((PASS+1)) || { echo "FAIL gate-on"; FAIL=$((FAIL+1)); }

# disabled => no curl ever (mock counts calls)
CURL_CALLS=0
curl() { CURL_CALLS=$((CURL_CALLS+1)); return 0; }
SWARM_ENABLE="false"
swatter_swarm_publish; check pub-disabled-nocurl "$CURL_CALLS" "0"
SWARM_ENABLE="true"

# --- host_id: created once, 32 hex, 0600, stable
id1="$(swatter_swarm_host_id)"; id2="$(swatter_swarm_host_id)"
check hostid-stable "$id1" "$id2"
[[ "$id1" =~ ^[0-9a-f]{32}$ ]] && PASS=$((PASS+1)) || { echo "FAIL hostid-hex: '$id1'"; FAIL=$((FAIL+1)); }
check hostid-perms "$(stat -c %a "${STATE_DIR}/swarm.host_id" 2>/dev/null || stat -f %Lp "${STATE_DIR}/swarm.host_id")" "600"

# --- token->cfg helper: missing file fails, real file lands token in cfg not argv
check tokcfg-missing "$(_swarm_curl_cfg_token "${STATE_DIR}/nope" >/dev/null 2>&1; echo $?)" "1"
printf 'sekret-token-123' > "${STATE_DIR}/tok"; chmod 0400 "${STATE_DIR}/tok"
cfg="$(_swarm_curl_cfg_token "${STATE_DIR}/tok")"
grep -q 'Authorization: Bearer sekret-token-123' "$cfg" && PASS=$((PASS+1)) || { echo "FAIL tokcfg-content"; FAIL=$((FAIL+1)); }
rm -f "$cfg"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_test.sh` → FAIL (`lib/swarm.sh` missing → source error / functions undefined).

- [ ] **Step 3: Add config defaults to `lib/common.sh`** — insert after the `: "${METRICS_FILE:=...}"` line (line 138), before `INTEL_CACHE_TTL=86400`:

```bash
# --- Swarm (fleet reputation sharing; subsystem 2 host side; ALL inert by default)
# Consume additionally requires adding `swarm` to INTEL_PROVIDERS.
: "${SWARM_ENABLE:=false}"
: "${SWARM_HUB_URL:=}"
: "${SWARM_WRITE_TOKEN_FILE:=/etc/swatter/swarm.write.token}"
: "${SWARM_READ_TOKEN_FILE:=/etc/swatter/swarm.read.token}"
: "${SWARM_ENROLL_TOKEN_FILE:=}"
: "${SWARM_PUBLISH:=true}"
: "${SWARM_ACTION:=boost}"
: "${SWARM_MIN_CORROBORATION:=2}"
: "${SWARM_BASE_SCORE:=70}"
: "${SWARM_ALLOW_FILE:=/etc/swatter/swarm.allow.cidr}"
: "${SWARM_MAX_AGE_DAYS:=3}"
```

- [ ] **Step 4: Append the swarm section to `config/swatter.example.conf`**

```bash
# ---------------------------------------------------------------------------
# Swarm — share confirmed offenders across YOUR fleet via a self-hosted hub
# (Cloudflare Worker + D1; see hub/README.md). Everything below is inert until
# SWARM_ENABLE="true" AND SWARM_HUB_URL is set AND the box is enrolled once
# with: swatter swarm enroll   (operator-run, needs the enroll token file).
#
# To CONSUME the fleet feed (boost/corroborated-block) you must ALSO add
# `swarm` to INTEL_PROVIDERS, e.g.:
#   INTEL_PROVIDERS="ipsum spamhaus abuseipdb greynoise projecthoneypot swarm"
# Publishing works without that; consuming does not.
# ---------------------------------------------------------------------------
# SWARM_ENABLE="false"
# SWARM_HUB_URL=""                                     # e.g. https://swarm.peaceharbor.com
# SWARM_WRITE_TOKEN_FILE="/etc/swatter/swarm.write.token"   # 0400; publish (POST /contribute)
# SWARM_READ_TOKEN_FILE="/etc/swatter/swarm.read.token"     # 0400; consume (GET /feed)
# SWARM_ENROLL_TOKEN_FILE=""                           # 0400; operator-held, ONLY on the box running `swatter swarm enroll`
# SWARM_PUBLISH="true"                                 # contribute this box's confirmed perm bans
# SWARM_ACTION="boost"                                 # boost | corroborated-block
# SWARM_MIN_CORROBORATION="2"                          # distinct hosts required for a proactive block
# SWARM_BASE_SCORE="70"                                # intel score for a 1-host swarm hit (scales +15/extra host, cap 100)
# SWARM_ALLOW_FILE="/etc/swatter/swarm.allow.cidr"     # fleet canary: never published, never swarm-acted
# SWARM_MAX_AGE_DAYS="3"                               # stale swarm feed => signal ignored + warn
```

- [ ] **Step 5: Create `lib/swarm.sh`** (core only; publish/sweep/CLI bodies land in Tasks 5–7 — the file starts with the shared helpers plus no-op stubs so sourcing is always safe):

```bash
#!/usr/bin/env bash
# lib/swarm.sh — fleet reputation sharing, host side (subsystem 2 of 2).
#
# Publishes this box's CONFIRMED perm bans to the operator's self-hosted hub
# (POST /contribute) and consumes the merged fleet feed back as the intel
# provider `swarm` (lib/providers/swarm.sh). Opt-in corroborated-block sweeps
# route through _swatter_execute_block so every local gate still applies.
# All inert unless SWARM_ENABLE=true + SWARM_HUB_URL set (see spec §9).

_swarm_enabled() {
    [[ "${SWARM_ENABLE:-false}" == "true" && -n "${SWARM_HUB_URL:-}" ]]
}

# Opaque, stable, random per box — NOT hostname/IP (spec §6). Created 0600 on
# first use; only enrolled ids count toward hub corroboration.
swatter_swarm_host_id() {
    local f="${STATE_DIR}/swarm.host_id" id
    if [[ -s "$f" ]]; then printf '%s' "$(tr -d '[:space:]' < "$f")"; return 0; fi
    id="$(od -vAn -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    [[ "$id" =~ ^[0-9a-f]{32}$ ]] || { log_error "swarm: host_id generation failed"; return 1; }
    ( umask 0177; printf '%s' "$id" > "$f" ) || { log_error "swarm: cannot write ${f}"; return 1; }
    printf '%s' "$id"
}

# Bearer-token curl config from a 0400 token file (secret NEVER in argv —
# same rule every credentialed curl in this repo follows; curl_secrets_test).
# Caller MUST rm -f the printed path right after curl returns.
_swarm_curl_cfg_token() {
    local tf="$1" tok
    [[ -r "$tf" ]] || { log_warn "swarm: token file missing/unreadable: ${tf}"; return 1; }
    tok="$(tr -d '[:space:]' < "$tf")"
    [[ -n "$tok" ]] || { log_warn "swarm: token file empty: ${tf}"; return 1; }
    swatter_curl_cfg "header = \"Authorization: Bearer ${tok}\""
}

# --- stubs replaced by later tasks (keep sourcing safe in any order) ---
swatter_swarm_publish() { return 0; }
swatter_swarm_sweep()   { return 0; }
cmd_swarm()             { log_error "swarm: not yet implemented"; return 2; }
```

- [ ] **Step 6: Register in `bin/swatter`** — four edits:

(a) usage header: after the `import-bans` line (line 28) add:
```
#   swatter swarm {enroll|status|disable|purge}  fleet reputation sharing (see SWARM_* config)
```
(b) source list (line 62): add `swarm` after `score`:
```bash
for m in allowlist classify ingest store_sqlite block_csf block_ipset block block_cf origin_lock intel asn metrics errors mailer notify report_abuseipdb score swarm alerts report; do
```
(c) dispatch, next to `import-bans)` (~line 440):
```bash
        swarm)         cmd_swarm "$@" ;;
```
(d) test-config advisory (the `for p in ${INTEL_PROVIDERS:-}` loop, ~line 324-329): add a `swarm)` case so the operator sees readiness (this is where every keyed provider gets its advisory line):
```bash
            swarm)           if [[ "${SWARM_ENABLE:-false}" == "true" && -n "${SWARM_HUB_URL:-}" ]]; then
                                 [[ -r "${SWARM_READ_TOKEN_FILE:-}" ]] && echo "  intel swarm: enabled (hub ${SWARM_HUB_URL})" \
                                     || echo "  intel swarm: read token MISSING (${SWARM_READ_TOKEN_FILE}) -> consume inert"
                             else echo "  intel swarm: SWARM_ENABLE/SWARM_HUB_URL not set -> provider inert"; fi ;;
```

- [ ] **Step 7: Run to verify it passes.** `bash test/swarm_test.sh` → all PASS. Also `bash test/cli_test.sh` → still green (source-list change is load-order-safe).

- [ ] **Step 8: Commit**

```bash
git add lib/common.sh lib/swarm.sh config/swatter.example.conf bin/swatter test/swarm_test.sh
git commit -m "feat(swarm): host core — config keys, enable gate, host_id, token curl-cfg helper"
```

---

### Task 2: Store — `swatter_store_perm_ips_since` (sqlite + flatfile parity)

**Files:**
- Modify: `lib/store_sqlite.sh` (append after `swatter_store_perm_ips`, ~line 242)
- Test: `test/swarm_store_test.sh`

**Interfaces:**
- Consumes: `_sqlq`, `_swatter_jsonl`, `swatter_store_record <ip> <action> <channel> <ttl> <score> <reason> <dry_run>` (existing).
- Produces: `swatter_store_perm_ips_since <epoch> -> lines "ip<TAB>ts"` — same still-banned/enforced semantics as `swatter_store_perm_ips`, restricted to IPs whose latest enforced perm action is NEWER than `<epoch>`; `ts` = that latest enforced-perm epoch. Ordered by ip. (Flatfile awk mirrors the existing `swatter_store_perm_ips` replay style — accepted parity risk, same ledger-shape coupling as the existing function.)

- [ ] **Step 1: Write the failing test — `test/swarm_store_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_store_test.sh — swatter_store_perm_ips_since: delta of confirmed perm bans.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

run_suite() {   # $1 = sqlite|flatfile
    STORE="$1"
    STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sst.XXXXXX")"
    swatter_store_init
    # Fixed clock per record so the cursor math is deterministic.
    swatter_now() { echo "$FAKE_NOW"; }
    FAKE_NOW=1000; swatter_store_record 1.1.1.1 perm csf 0 90 "old ban" 0        # before cursor
    FAKE_NOW=2000; swatter_store_record 2.2.2.2 perm csf 0 90 "new ban" 0        # after cursor
    FAKE_NOW=2100; swatter_store_record 3.3.3.3 perm csf 0 90 "dry ban" 1        # dry-run: excluded
    FAKE_NOW=2200; swatter_store_record 4.4.4.4 temp csf 3600 75 "temp" 0        # temp: excluded
    FAKE_NOW=2300; swatter_store_record 5.5.5.5 perm csf 0 90 "unbanned later" 0
    FAKE_NOW=2400; swatter_store_record 5.5.5.5 unblock csf 0 0 "manual" 0       # unblocked: excluded
    if [[ "$STORE" == "sqlite" ]]; then
        _sql "UPDATE offenders SET perm=0 WHERE ip='5.5.5.5';"                   # unblock clears perm state
    fi
    local out; out="$(swatter_store_perm_ips_since 1500)"
    check "${STORE}-only-new" "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" "2.2.2.2 "
    check "${STORE}-ts"       "$(printf '%s\n' "$out" | cut -f2)" "2000"
    check "${STORE}-since0-includes-old" "$(swatter_store_perm_ips_since 0 | cut -f1 | grep -c .)" "2"
    unset -f swatter_now
    rm -rf "$STATE_DIR"
}

run_suite flatfile
if command -v sqlite3 >/dev/null 2>&1; then SWATTER_HAVE_SQLITE=1; run_suite sqlite; fi

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_store_test.sh` → FAIL (`swatter_store_perm_ips_since: command not found`).

- [ ] **Step 3: Append to `lib/store_sqlite.sh`** (right after `swatter_store_perm_ips`):

```bash
# Delta variant for the swarm publisher: perm ips (same still-banned, enforced
# semantics as swatter_store_perm_ips) whose LATEST enforced perm action is
# newer than <since>. Prints "ip<TAB>ts" per line; ts drives the publish cursor.
swatter_store_perm_ips_since() {
    local since="${1:-0}"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT a.ip || char(9) || MAX(a.ts) FROM actions a
                 JOIN offenders o ON o.ip = a.ip
                WHERE o.perm=1 AND a.action='perm' AND a.dry_run=0
                GROUP BY a.ip HAVING MAX(a.ts) > ${since}
                ORDER BY a.ip;"
    else
        awk -v since="$since" '
            { ip=""; act=""; dr=1; ts=0 }
            match($0, /"ip":"[^"]*"/)     { ip=substr($0, RSTART+6, RLENGTH-7) }
            match($0, /"action":"[^"]*"/) { act=substr($0, RSTART+10, RLENGTH-11) }
            match($0, /"ts":[0-9]+/)      { ts=substr($0, RSTART+5, RLENGTH-5)+0 }
            /"dry_run":0/                 { dr=0 }
            ip!="" && act=="perm" && dr==0 { banned[ip]=1; if (ts>last[ip]) last[ip]=ts }
            ip!="" && act=="unblock"       { banned[ip]=0 }
            END { for (i in banned) if (banned[i] && last[i]>since) print i "\t" last[i] }
        ' "$(_swatter_jsonl)" 2>/dev/null | sort
    fi
}
```

- [ ] **Step 4: Run to verify it passes.** `bash test/swarm_store_test.sh` → PASS (both stores). Also `bash test/persist_test.sh` and `bash test/fleet_test.sh` → still green.

- [ ] **Step 5: Commit**

```bash
git add lib/store_sqlite.sh test/swarm_store_test.sh
git commit -m "feat(swarm): store delta query — perm bans since cursor (sqlite + flatfile)"
```

---

### Task 3: Consume — `provider_swarm_refresh` (bare feed + JSON sidecar, frozen obligations)

**Files:**
- Create: `lib/providers/swarm.sh`
- Test: `test/swarm_consume_test.sh`

**Interfaces:**
- Consumes: `_swarm_enabled`, `_swarm_curl_cfg_token` (Task 1), `swatter_cidr_list_ok` (`lib/common.sh:346`), `SWATTER_HAVE_CURL/JQ`, config keys.
- Produces: `provider_swarm_refresh() -> 0 ok-or-inert / 1 failure` — installs `${STATE_DIR}/feeds/swarm.txt` (validated bare list, atomically) + `${STATE_DIR}/feeds/swarm.meta.json` (JSON rows, jq-validated); **empty 200 clears both**; non-200/invalid keeps last-good and returns 1; a FAILED sidecar fetch DELETES any prior meta (fresh-or-absent invariant); logs `X-Swarm-Truncated`. Auto-invoked by `swatter_intel_refresh_all` when `swarm` ∈ `INTEL_PROVIDERS`.

- [ ] **Step 1: Write the failing test — `test/swarm_consume_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_consume_test.sh — swarm feed consume: install/empty-clears/keep-last-good.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swc.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_READ_TOKEN_FILE="${STATE_DIR}/read.tok"; printf 'read-tok' > "$SWARM_READ_TOKEN_FILE"
FEED="${STATE_DIR}/feeds/swarm.txt"; META="${STATE_DIR}/feeds/swarm.meta.json"

# curl mock: honors -o <file> / -D <file>; prints $CURL_CODE (-w); body from $CURL_BODY.
CURL_CALLS=0; CURL_BODY=""; CURL_CODE="200"; CURL_HDRS=""; CURL_RC=0
curl() {
    CURL_CALLS=$((CURL_CALLS+1))
    local prev="" a out="" dfile=""
    for a in "$@"; do
        [[ "$prev" == "-o" ]] && out="$a"
        [[ "$prev" == "-D" ]] && dfile="$a"
        prev="$a"
    done
    [[ -n "$out"  ]] && printf '%s' "$CURL_BODY" > "$out"
    [[ -n "$dfile" ]] && printf '%s' "$CURL_HDRS" > "$dfile"
    printf '%s' "$CURL_CODE"
    return "$CURL_RC"
}

# 1) good bare feed installs
CURL_BODY=$'203.0.113.7\n198.51.100.0/24\n'; CURL_CODE="200"
provider_swarm_refresh 2>/dev/null; check inst-rc "$?" "0"
check inst-lines "$(grep -c . "$FEED")" "2"

# 2) transport failure keeps last-good
CURL_CODE=""; CURL_RC=7
provider_swarm_refresh 2>/dev/null; check fail-rc "$?" "1"
check fail-kept "$(grep -c . "$FEED")" "2"
CURL_RC=0

# 3) non-200 keeps last-good
CURL_CODE="500"
provider_swarm_refresh 2>/dev/null; check n200-rc "$?" "1"
check n200-kept "$(grep -c . "$FEED")" "2"

# 4) poisoned body (HTML) rejected, last-good kept
CURL_BODY=$'<html>error</html>\n'; CURL_CODE="200"
provider_swarm_refresh 2>/dev/null; check poison-rc "$?" "1"
check poison-kept "$(grep -c . "$FEED")" "2"

# 5) FROZEN OBLIGATION 1: valid EMPTY 200 CLEARS the feed (not keep-last-good)
CURL_BODY=""; CURL_CODE="200"
provider_swarm_refresh 2>/dev/null; check empty-rc "$?" "0"
check empty-cleared "$(grep -c . "$FEED" || true)" "0"

# 6) truncation header warns (message reaches stderr)
CURL_BODY=$'203.0.113.7\n'; CURL_HDRS=$'HTTP/2 200\r\nx-swarm-truncated: true\r\n'
warn="$(provider_swarm_refresh 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -qi 'truncat' && PASS=$((PASS+1)) || { echo "FAIL trunc-warn"; FAIL=$((FAIL+1)); }
CURL_HDRS=""

# 7) sidecar failure INVALIDATES prior meta (fresh-or-absent; jq boxes only)
if command -v jq >/dev/null 2>&1; then
    SWATTER_HAVE_JQ=1
    printf '[{"ip":"203.0.113.7","host_count":9}]' > "$META"   # stale prior meta
    CURL_BODY=$'203.0.113.7\n'
    # bare fetch 200 OK, but the json fetch (2nd call) returns garbage:
    _CALL=0
    curl() {
        _CALL=$(( _CALL + 1 ))
        local prev="" a out=""
        for a in "$@"; do [[ "$prev" == "-o" ]] && out="$a"; prev="$a"; done
        if (( _CALL == 1 )); then [[ -n "$out" ]] && printf '203.0.113.7\n' > "$out"; printf '200'
        else [[ -n "$out" ]] && printf 'not json' > "$out"; printf '200'; fi
        return 0
    }
    provider_swarm_refresh 2>/dev/null; check sidecar-fail-rc "$?" "0"
    [[ ! -e "$META" ]] && PASS=$((PASS+1)) || { echo "FAIL sidecar-fail-meta-invalidated"; FAIL=$((FAIL+1)); }
    SWATTER_HAVE_JQ=0
fi

# 8) disabled => rc 0 and NO curl call
CURL_CALLS=0
curl() { CURL_CALLS=$((CURL_CALLS+1)); return 0; }
SWARM_ENABLE="false"
provider_swarm_refresh 2>/dev/null; check disabled-rc "$?" "0"
check disabled-nocurl "$CURL_CALLS" "0"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_consume_test.sh` → FAIL (`lib/providers/swarm.sh` missing).

- [ ] **Step 3: Create `lib/providers/swarm.sh`** (refresh half; lookup lands Task 4):

```bash
#!/usr/bin/env bash
# lib/providers/swarm.sh — fleet feed as an intel provider.
#
# refresh: GET /feed (bare) -> feeds/swarm.txt via swatter_cidr_list_ok with
# TWO frozen consume obligations (hub plan Global Constraints):
#   1. a VALID EMPTY 200 means "no active offenders" -> CLEAR swarm.txt + meta
#      (must NOT go through swatter_cidr_list_ok, whose n>0 would reject it);
#      keep-last-good applies ONLY to non-200/transport failures.
#   2. corroborated-block needs host_count -> the ?format=json sidecar
#      (feeds/swarm.meta.json). Fresh-or-absent invariant: a FAILED sidecar
#      fetch DELETES prior meta so corroboration never acts on stale counts.
# lookup: provider_swarm "$ip" (Task 4) — score scaled by host_count.

provider_swarm_refresh() {
    _swarm_enabled || return 0
    local out="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || { log_warn "swarm refresh needs curl"; return 1; }
    local cfg hdrs code
    cfg="$(_swarm_curl_cfg_token "${SWARM_READ_TOKEN_FILE}")" || return 1
    hdrs="$(mktemp "${TMPDIR:-/tmp}/swatter-swarmhdr.XXXXXX")" || { rm -f "$cfg"; return 1; }
    code="$(curl --max-time 30 -sS -K "$cfg" -D "$hdrs" -o "${out}.raw" -w '%{http_code}' \
                 "${SWARM_HUB_URL%/}/feed" 2>/dev/null)"
    local crc=$?
    rm -f "$cfg"
    if (( crc != 0 )) || [[ "$code" != "200" ]]; then
        rm -f "${out}.raw" "$hdrs"
        log_warn "swarm feed fetch failed (http ${code:-none} rc=${crc}) — keeping last-good"
        return 1
    fi
    grep -qi '^x-swarm-truncated: *true' "$hdrs" \
        && log_warn "swarm feed TRUNCATED at the hub row cap — high addresses may be missing every cycle"
    rm -f "$hdrs"

    # Frozen obligation 1: valid empty 200 = "no active offenders" -> CLEAR.
    if ! grep -q '[^[:space:]]' "${out}.raw" 2>/dev/null; then
        : > "$out"; printf '[]' > "$meta"
        rm -f "${out}.raw"
        log_info "swarm feed empty (no active offenders) — cleared"
        return 0
    fi

    if tr -d '\r' < "${out}.raw" > "${out}.tmp" && swatter_cidr_list_ok < "${out}.tmp"; then
        mv "${out}.tmp" "$out"; rm -f "${out}.raw"
        log_info "swarm feed refreshed ($(grep -c . "$out" 2>/dev/null | tr -d ' ') entries)"
    else
        rm -f "${out}.raw" "${out}.tmp"
        log_warn "swarm feed INVALID (poisoned/garbled body) — keeping last-good"
        return 1
    fi

    # JSON sidecar for host_count. Fresh-or-absent: any sidecar failure removes
    # prior meta so corroboration/scaling never runs on stale counts. The bare
    # feed already installed, so refresh still returns 0 (boost unaffected).
    if [[ "${SWATTER_HAVE_JQ}" -eq 1 ]]; then
        cfg="$(_swarm_curl_cfg_token "${SWARM_READ_TOKEN_FILE}")" || { rm -f "$meta"; return 0; }
        code="$(curl --max-time 30 -sS -K "$cfg" -o "${meta}.raw" -w '%{http_code}' \
                     "${SWARM_HUB_URL%/}/feed?format=json" 2>/dev/null)"
        rm -f "$cfg"
        if [[ "$code" == "200" ]] && jq -e 'type=="array"' "${meta}.raw" >/dev/null 2>&1; then
            mv "${meta}.raw" "$meta"
        else
            rm -f "${meta}.raw" "$meta"
            log_warn "swarm meta (json feed) fetch failed — host_count unavailable (stale meta removed)"
            [[ "${SWARM_ACTION:-boost}" == "corroborated-block" ]] \
                && log_warn "swarm: corroborated-block REQUIRES the json feed — sweep will be skipped"
        fi
    elif [[ "${SWARM_ACTION:-boost}" == "corroborated-block" ]]; then
        log_warn "swarm: corroborated-block requires jq for the json feed — install jq or use SWARM_ACTION=boost"
    fi
    return 0
}
```

- [ ] **Step 4: Run to verify it passes.** `bash test/swarm_consume_test.sh` → PASS. `bash test/intel_test.sh` → still green.

- [ ] **Step 5: Commit**

```bash
git add lib/providers/swarm.sh test/swarm_consume_test.sh
git commit -m "feat(swarm): consume — bare feed install, EMPTY-200-CLEARS, keep-last-good, fresh-or-absent meta"
```

---

### Task 4: Lookup — `provider_swarm` (IP + CIDR hit, host_count scaling, staleness, fleet-allow) + boost-fold proof

**Files:**
- Modify: `lib/providers/swarm.sh` (append)
- Test: `test/swarm_lookup_test.sh`

**Interfaces:**
- Consumes: `_ip_in_cidr_file <ip> <file>` (`lib/allowlist.sh`), `stat_mtime <file>` (`lib/common.sh:367`), `swatter_now`, `SWARM_*` keys, `INTEL_CACHE_TTL`; for the fold proof: `_swatter_fold_reputation <behavioral> <reputation>` (`lib/score.sh:25`), `W_REPUTATION` (default 14).
- Produces: `provider_swarm <ip> -> "score\tttl\tlabel"` per the provider contract (`lib/intel.sh:4-8`); no-data exit 1 when: disabled, no/empty feed, feed stale (> `SWARM_MAX_AGE_DAYS`, warn once per process), ip in `SWARM_ALLOW_FILE`, or no hit. Score = `min(100, SWARM_BASE_SCORE + 15*(host_count-1))`; label `hosts=N`. **CIDR-contained single IPs score at the conservative base** (meta is keyed by the CIDR string — locked decision; the sweep is unaffected because it iterates meta rows directly).

- [ ] **Step 1: Write the failing test — `test/swarm_lookup_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_lookup_test.sh — provider_swarm: hit/miss, CIDR, scaling, stale, fleet-allow, fold.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/score.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swl.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_BASE_SCORE=70; SWARM_MAX_AGE_DAYS=3; INTEL_CACHE_TTL=86400; SWATTER_HAVE_JQ=0
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; : > "$SWARM_ALLOW_FILE"
FEED="${STATE_DIR}/feeds/swarm.txt"; META="${STATE_DIR}/feeds/swarm.meta.json"

printf '203.0.113.7\n198.51.100.0/24\n' > "$FEED"

# exact-IP hit at base score
check hit "$(provider_swarm 203.0.113.7 | cut -f1)" "70"
check hit-label "$(provider_swarm 203.0.113.7 | cut -f3)" "hosts=1"
# CIDR containment hit
check cidr-hit "$(provider_swarm 198.51.100.99 | cut -f1)" "70"
# miss
provider_swarm 8.8.8.8 >/dev/null 2>&1 && { echo "FAIL miss"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

if command -v jq >/dev/null 2>&1; then
    SWATTER_HAVE_JQ=1
    # host_count scaling via meta
    printf '[{"ip":"203.0.113.7","host_count":3,"category":null,"expires":99}]' > "$META"
    check scaled "$(provider_swarm 203.0.113.7 | cut -f1)" "100"   # 70 + 15*2 = 100 (capped)
    check scaled-label "$(provider_swarm 203.0.113.7 | cut -f3)" "hosts=3"
    # LOCKED DECISION: a CIDR-contained IP stays at base even when the CIDR row
    # is corroborated — meta is keyed by the CIDR string (conservative).
    printf '[{"ip":"198.51.100.0/24","host_count":3,"category":null,"expires":99}]' > "$META"
    check cidr-conservative "$(provider_swarm 198.51.100.99 | cut -f1)" "70"
    SWATTER_HAVE_JQ=0; rm -f "$META"
fi

# fleet-allow: never boosted
printf '203.0.113.7\n' > "$SWARM_ALLOW_FILE"
provider_swarm 203.0.113.7 >/dev/null 2>&1 && { echo "FAIL fleet-allow"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))
: > "$SWARM_ALLOW_FILE"

# stale feed -> signal absent
touch -d '@1000' "$FEED" 2>/dev/null || touch -t 202001010000 "$FEED"
provider_swarm 203.0.113.7 >/dev/null 2>&1 && { echo "FAIL stale"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# --- spec §11 boost-fold proof (W_REPUTATION path, lib/score.sh):
# a local-clean box (behavioral 5) + swarm 70 must stay FAR below SCORE_TEMP;
# a local near-miss (behavioral 68) + swarm 85 must tip over it.
W_REPUTATION=14; SCORE_TEMP=70
low="$(_swatter_fold_reputation 5 70)"
(( low < 70 )) && PASS=$((PASS+1)) || { echo "FAIL fold-clean-not-tipped: $low"; FAIL=$((FAIL+1)); }
high="$(_swatter_fold_reputation 68 85)"
(( high >= 70 )) && PASS=$((PASS+1)) || { echo "FAIL fold-nearmiss-tipped: $high"; FAIL=$((FAIL+1)); }
# fold can only RAISE, never lower a strong behavioral score
raised="$(_swatter_fold_reputation 95 10)"
(( raised >= 95 )) && PASS=$((PASS+1)) || { echo "FAIL fold-never-lowers: $raised"; FAIL=$((FAIL+1)); }

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_lookup_test.sh` → FAIL (`provider_swarm: command not found`).

- [ ] **Step 3: Append `provider_swarm` to `lib/providers/swarm.sh`:**

```bash
# Per-IP lookup against the local swarm feed. Free (no network): exact-IP line
# match, then CIDR containment via the allowlist matcher. Score scales with the
# fleet's corroboration: base SWARM_BASE_SCORE at host_count=1, +15 per extra
# distinct host, capped 100 (folds through the standard W_REPUTATION path —
# swarm is a NORMAL intel provider, not a new fold weight; spec §8).
# NOTE (locked decision): an IP contained in a corroborated CIDR row scores at
# the conservative BASE — meta host_count is keyed by the CIDR string. The
# corroborated-block sweep is unaffected (it iterates meta rows directly).
provider_swarm() {
    local ip="$1" feed="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    _swarm_enabled || return 1
    [[ -s "$feed" ]] || return 1

    # Staleness (spec §4.3): older than SWARM_MAX_AGE_DAYS => signal ABSENT
    # (+ one warn per process, not per IP).
    local age
    age=$(( $(swatter_now) - $(stat_mtime "$feed" || echo 0) ))
    if (( age > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )); then
        if [[ -z "${_SWARM_STALE_WARNED:-}" ]]; then
            log_warn "swarm feed stale (>${SWARM_MAX_AGE_DAYS}d old) — swarm signal ignored (run: swatter refresh-feeds)"
            _SWARM_STALE_WARNED=1
        fi
        return 1
    fi

    # Fleet canary: a fleet-allow IP is never swarm-boosted (spec §4.5).
    [[ -s "${SWARM_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${SWARM_ALLOW_FILE}" && return 1

    local hit=0
    awk -v ip="$ip" '$1==ip{f=1; exit} END{exit !f}' "$feed" && hit=1
    if (( ! hit )) && declare -F _ip_in_cidr_file >/dev/null; then
        _ip_in_cidr_file "$ip" "$feed" && hit=1
    fi
    (( hit )) || return 1

    local hc=1
    if [[ "${SWATTER_HAVE_JQ}" -eq 1 && -s "$meta" ]]; then
        hc="$(jq -r --arg ip "$ip" '[.[] | select(.ip==$ip)][0].host_count // 1' "$meta" 2>/dev/null)"
        [[ "$hc" =~ ^[0-9]+$ ]] || hc=1
    fi
    local score=$(( ${SWARM_BASE_SCORE:-70} + 15 * (hc - 1) ))
    (( score > 100 )) && score=100
    printf '%s\t%s\thosts=%s\n' "$score" "${INTEL_CACHE_TTL}" "$hc"
}
```

- [ ] **Step 4: Run to verify it passes.** `bash test/swarm_lookup_test.sh` → PASS. `bash test/intel_test.sh` and `bash test/score_test.sh` → still green.

- [ ] **Step 5: Commit**

```bash
git add lib/providers/swarm.sh test/swarm_lookup_test.sh
git commit -m "feat(swarm): provider_swarm lookup — CIDR-aware, host_count-scaled, stale-guarded, canary-exempt + fold proof"
```

---

### Task 5: Publish — `swatter_swarm_publish` + `cmd_scan` hook

**Files:**
- Modify: `lib/swarm.sh` (replace the `swatter_swarm_publish` stub)
- Modify: `bin/swatter` (`cmd_scan`, after `swatter_scan` line 84)
- Test: `test/swarm_publish_test.sh`

**Interfaces:**
- Consumes: `swatter_store_perm_ips_since <epoch>` (Task 2), `swatter_swarm_host_id`, `_swarm_curl_cfg_token` (Task 1), `swatter_is_valid_ip_or_cidr`, `_swatter_is_unsafe_block_target`, `swatter_is_never_block`, `_ip_in_cidr_file`.
- Produces: `swatter_swarm_publish() -> 0 ok-or-inert / 1 soft-failure` — POSTs the delta of confirmed perm bans to `/contribute` in ≤500-entry chunks; cursor `$STATE_DIR/swarm.publish.cursor` advances **only to the max ts of rows actually SENT** (review: policy-filtered rows never consume the cursor — they are re-read and re-filtered until a later publishable ban advances past them, which is cheap and self-healing if the policy changes) and ONLY when every chunk got a 200 with `enrolled:true`; `rejected>0` is warned loudly (validator-drift signal); `enrolled:false` warns "run swatter swarm enroll" and keeps the cursor; NEVER dies. Called from `cmd_scan` inside the scan lock, only in enforce mode.

- [ ] **Step 1: Write the failing test — `test/swarm_publish_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_publish_test.sh — publish: delta, filters, cursor-over-sent-only, chunking, enrolled:false.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swp.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
STORE="flatfile"; swatter_store_init
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0; SWATTER_MODE="enforce"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"; SWARM_PUBLISH="true"
SWARM_WRITE_TOKEN_FILE="${STATE_DIR}/write.tok"; printf 'write-tok' > "$SWARM_WRITE_TOKEN_FILE"
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; printf '9.9.9.9\n' > "$SWARM_ALLOW_FILE"
CURSOR="${STATE_DIR}/swarm.publish.cursor"

# never-block stub: 10.0.0.0/8 is "operator-allow"
swatter_is_never_block() { [[ "$1" == 10.* ]] && { echo operator-allow; return 0; }; return 1; }

# curl mock: capture each POST payload (--data-binary @file), reply $CURL_RESP via -o, code via -w.
POSTS="${STATE_DIR}/posts"; : > "$POSTS"
CURL_RESP='{"accepted":1,"rejected":0,"enrolled":true}'; CURL_CODE="200"
curl() {
    local prev="" a out="" data=""
    for a in "$@"; do
        [[ "$prev" == "-o" ]] && out="$a"
        [[ "$prev" == "--data-binary" ]] && data="$a"
        prev="$a"
    done
    [[ -n "$data" ]] && cat "${data#@}" >> "$POSTS" && printf '\n' >> "$POSTS"
    [[ -n "$out" ]] && printf '%s' "$CURL_RESP" > "$out"
    printf '%s' "$CURL_CODE"
    return 0
}

# Seed the ledger: 2 good bans, 1 never-block, 1 fleet-allow — the FILTERED
# rows carry the HIGHEST timestamps, so the cursor test below proves filtered
# rows do NOT consume the cursor.
swatter_now() { echo 5000; }
swatter_store_record 203.0.113.7 perm csf 0 90 "ban a" 0
swatter_store_record 198.51.100.9 perm csf 0 90 "ban b" 0
unset -f swatter_now
swatter_now() { echo 5600; }
swatter_store_record 10.1.2.3 perm csf 0 90 "never-block leak test" 0
swatter_store_record 9.9.9.9 perm csf 0 90 "fleet-allow leak test" 0
unset -f swatter_now

# 1) publishes only the filtered delta; cursor = max ts of SENT rows (5000, not 5600)
swatter_swarm_publish 2>/dev/null; check pub-rc "$?" "0"
check pub-has-a "$(grep -c '203.0.113.7' "$POSTS")" "1"
check pub-has-b "$(grep -c '198.51.100.9' "$POSTS")" "1"
check pub-no-neverblock "$(grep -c '10.1.2.3' "$POSTS")" "0"
check pub-no-fleetallow "$(grep -c '"9.9.9.9"' "$POSTS")" "0"
check pub-hostid "$(grep -c "\"host_id\":\"$(swatter_swarm_host_id)\"" "$POSTS")" "1"
check cursor-sent-only "$(cat "$CURSOR")" "5000"

# 2) idempotent for SENT rows: re-run re-reads the filtered rows (cursor 5000 <
#    their ts 5600) but sends nothing new
: > "$POSTS"
swatter_swarm_publish 2>/dev/null
check pub-idempotent "$(grep -c '"host_id"' "$POSTS" || true)" "0"

# 3) failure keeps cursor (new ban, hub 500)
swatter_now() { echo 6000; }; swatter_store_record 203.0.113.99 perm csf 0 90 "ban c" 0; unset -f swatter_now
CURL_CODE="500"
swatter_swarm_publish 2>/dev/null; check fail-rc "$?" "1"
check fail-cursor-kept "$(cat "$CURSOR")" "5000"

# 4) enrolled:false warns + keeps cursor (retry after enroll)
CURL_CODE="200"; CURL_RESP='{"accepted":0,"rejected":1,"enrolled":false}'
warn="$(swatter_swarm_publish 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -q 'swarm enroll' && PASS=$((PASS+1)) || { echo "FAIL enroll-warn"; FAIL=$((FAIL+1)); }
check enroll-cursor-kept "$(cat "$CURSOR")" "5000"

# 5) rejected>0 with enrolled:true is WARNED (validator drift) but advances
CURL_RESP='{"accepted":0,"rejected":1,"enrolled":true}'
warn="$(swatter_swarm_publish 2>&1 >/dev/null)"
printf '%s' "$warn" | grep -qi 'reject' && PASS=$((PASS+1)) || { echo "FAIL rejected-warn"; FAIL=$((FAIL+1)); }
check rejected-cursor-advanced "$(cat "$CURSOR")" "6000"

# 6) report mode publishes nothing
CURL_RESP='{"accepted":1,"rejected":0,"enrolled":true}'; : > "$POSTS"; SWATTER_MODE="report"
swatter_swarm_publish 2>/dev/null
check reportmode-silent "$(grep -c . "$POSTS" || true)" "0"
SWATTER_MODE="enforce"

# 7) chunking: 501 fresh bans -> 2 POSTs
rm -f "$CURSOR"; : > "$POSTS"; : > "$(_swatter_jsonl)"
swatter_now() { echo 7000; }
for i in $(seq 1 501); do
    swatter_store_record "172.16.$(( i / 256 )).$(( i % 256 ))" perm csf 0 90 "bulk" 0
done
unset -f swatter_now
swatter_swarm_publish 2>/dev/null
check chunk-posts "$(grep -c '"host_id"' "$POSTS")" "2"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_publish_test.sh` → FAIL (stub publishes nothing → `pub-has-a` fails).

- [ ] **Step 3: Replace the `swatter_swarm_publish` stub in `lib/swarm.sh`:**

```bash
# Publish the delta of CONFIRMED perm bans (enforced, still banned) to the hub.
# Runs after a scan inside the scan lock; FAIL-SOFT: any failure warns, keeps
# the cursor, returns 1 — it must never abort or delay a scan (spec §4.1/§12).
# Frozen contract: POST /contribute {host_id, entries:[{ip}]} — category omitted
# in Phase 1 (taxonomy is spec open question §16; the field is contract-optional).
# Cursor discipline (Grok review): max_ts is computed ONLY over rows actually
# sent. Policy-filtered rows (never-block/canary/unsafe/invalid) never consume
# the cursor — they get re-read + re-filtered until a later publishable ban
# advances past them (cheap, and self-healing if the policy changes). A chunk
# failure mid-publish re-sends the whole delta next cycle; hub upserts are
# idempotent, so duplicates are harmless.
_SWARM_CHUNK=500   # hub MAX_ENTRIES defaults to 1000; stay comfortably under

swatter_swarm_publish() {
    _swarm_enabled || return 0
    [[ "${SWARM_PUBLISH:-true}" == "true" ]] || return 0
    # Mirror the AbuseIPDB reporter guard: never publish a ban we didn't make.
    [[ "${SWATTER_MODE:-report}" == "enforce" ]] || return 0
    [[ "${SWATTER_HAVE_CURL}" -eq 1 ]] || return 0

    local cursor_file="${STATE_DIR}/swarm.publish.cursor" since=0
    [[ -s "$cursor_file" ]] && since="$(tr -d '[:space:]' < "$cursor_file")"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0

    # Delta + the four outbound gates (validate / unsafe / never-block / canary).
    # max_ts tracks SENT rows only (see header comment).
    local ip ts max_ts="$since" ips=()
    while IFS=$'\t' read -r ip ts; do
        [[ -n "$ip" ]] || continue
        swatter_is_valid_ip_or_cidr "$ip" || continue
        _swatter_is_unsafe_block_target "$ip" && continue
        swatter_is_never_block "$ip" >/dev/null && continue
        [[ -s "${SWARM_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${SWARM_ALLOW_FILE}" && continue
        ips+=("$ip")
        [[ "$ts" =~ ^[0-9]+$ ]] && (( ts > max_ts )) && max_ts="$ts"
    done < <(swatter_store_perm_ips_since "$since")
    (( ${#ips[@]} )) || return 0

    local host_id; host_id="$(swatter_swarm_host_id)" || return 1

    local i chunk payload cfg rtmp code
    for (( i = 0; i < ${#ips[@]}; i += _SWARM_CHUNK )); do
        chunk=("${ips[@]:i:_SWARM_CHUNK}")
        # Hand-built JSON is safe here: every ip passed the validator (charset
        # [0-9a-fA-F:./]) and host_id is our own 32-hex.
        payload="{\"host_id\":\"${host_id}\",\"entries\":["
        local first=1 e
        for e in "${chunk[@]}"; do
            (( first )) && first=0 || payload+=","
            payload+="{\"ip\":\"${e}\"}"
        done
        payload+="]}"

        cfg="$(_swarm_curl_cfg_token "${SWARM_WRITE_TOKEN_FILE}")" || return 1
        rtmp="$(mktemp "${TMPDIR:-/tmp}/swatter-swarmresp.XXXXXX")" || { rm -f "$cfg"; return 1; }
        printf 'header = "Content-Type: application/json"\n' >> "$cfg"
        code="$(printf '%s' "$payload" > "${rtmp}.req" && \
                curl --max-time 15 -sS -K "$cfg" -o "$rtmp" -w '%{http_code}' \
                     --data-binary "@${rtmp}.req" "${SWARM_HUB_URL%/}/contribute" 2>/dev/null)"
        local crc=$?
        rm -f "$cfg" "${rtmp}.req"
        if (( crc != 0 )) || [[ "$code" != "200" ]]; then
            rm -f "$rtmp"
            log_warn "swarm publish failed (http ${code:-none} rc=${crc}) — cursor kept, retry next scan"
            return 1
        fi
        if grep -q '"enrolled":false' "$rtmp" 2>/dev/null; then
            rm -f "$rtmp"
            log_warn "swarm publish REJECTED: this host_id is not enrolled — run: swatter swarm enroll (cursor kept)"
            return 1
        fi
        # Validator-drift visibility (review): the hub silently dropping entries
        # must not be silent HERE. Cursor still advances — hub validation is
        # deterministic, so retrying the same entries can never succeed.
        local nrej
        nrej="$(grep -o '"rejected":[0-9]*' "$rtmp" 2>/dev/null | cut -d: -f2)"
        [[ "$nrej" =~ ^[0-9]+$ ]] && (( nrej > 0 )) \
            && log_warn "swarm publish: hub rejected ${nrej} entr(ies) — bash/hub validator drift? (not retried)"
        rm -f "$rtmp"
    done

    printf '%s' "$max_ts" > "$cursor_file"
    log_info "swarm publish: ${#ips[@]} confirmed ban(s) contributed (cursor=${max_ts})"
}
```

- [ ] **Step 4: Hook into `cmd_scan`** in `bin/swatter` — after `swatter_scan` (line 84):

```bash
    swatter_scan
    # Fleet publish: delta of this run's confirmed perm bans, inside the scan
    # lock (spec §4.1). Fail-soft — a hub outage must never fail the scan.
    swatter_swarm_publish || true
```

- [ ] **Step 5: Run to verify it passes.** `bash test/swarm_publish_test.sh` → PASS. Full suite spot check: `bash test/cli_test.sh && bash test/scan_wire_test.sh` → green.

- [ ] **Step 6: Commit**

```bash
git add lib/swarm.sh bin/swatter test/swarm_publish_test.sh
git commit -m "feat(swarm): publish — sent-rows-only cursor, 4 outbound gates, chunked, fail-soft, in-lock"
```

---

### Task 6: `corroborated-block` sweep + `cmd_refresh_feeds` hook

**Files:**
- Modify: `lib/swarm.sh` (replace the `swatter_swarm_sweep` stub)
- Modify: `bin/swatter` (`cmd_refresh_feeds`, after `swatter_intel_refresh_all` line 254)
- Test: `test/swarm_sweep_test.sh`

**Interfaces:**
- Consumes: `_swatter_execute_block <ip> <action> <ttl> <folded> <reason> <ev> <rep> <novhost> <top_vhost> <healthy>` (`lib/score.sh:74`), `_swatter_pick_ttl <prior>`, `swatter_store_recent_temp_count`, `swatter_store_is_perm`, `swatter_failclosed_active`, `stat_mtime`, meta sidecar from Task 3.
- Produces: `swatter_swarm_sweep() -> 0` — when `SWARM_ACTION=corroborated-block`: temp-blocks (TTL ladder) every fresh-feed IP with `host_count >= SWARM_MIN_CORROBORATION`, EXCLUSIVELY via `_swatter_execute_block` (inherits never-block/classify/unsafe/cap/audit; `_SW_TOTAL_BLOCKS` reset so `MAX_BLOCKS_PER_RUN` caps the sweep). No-ops for `boost`, missing jq, missing/stale meta. Locked decisions: daily re-issue for still-corroborated IPs is the keep-alive/decay semantic (ladder TTL 3d > daily cadence, breaker-bounded); report mode dry-runs through the backends exactly like `scan`/`import-bans` (records `dry_run=1` — consistent preview, and dry temps never publish or escalate). With no local traffic there is no `top_vhost`, so CF-plane targets audit `skipped-novhost` — the sweep protects the DIRECT plane (matches `import-bans` semantics). Never-block safety is by composition: this test pins routes-through-choke; `block_test.sh` pins the choke's never-block gate.

- [ ] **Step 1: Write the failing test — `test/swarm_sweep_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_sweep_test.sh — corroborated-block: threshold, routing through the gate choke.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"

command -v jq >/dev/null 2>&1 || { echo "Total: 0 passed, 0 failed (jq missing — sweep is jq-gated; skipping)"; exit 0; }

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-sws.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${LOG_DIR}"
STORE="flatfile"; swatter_store_init
SWATTER_HAVE_JQ=1; SWATTER_MODE="enforce"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
SWARM_ACTION="corroborated-block"; SWARM_MIN_CORROBORATION=2; SWARM_BASE_SCORE=70; SWARM_MAX_AGE_DAYS=3
SWARM_ALLOW_FILE="${STATE_DIR}/swarm.allow.cidr"; printf '5.5.5.5\n' > "$SWARM_ALLOW_FILE"
META="${STATE_DIR}/feeds/swarm.meta.json"

# The sweep must route EVERY block through the gate choke — stub records calls.
# score.sh is NOT sourced here (it drags the whole scan surface), so stub its
# two helpers the sweep uses (Grok review: v1 forgot _swatter_pick_ttl).
BLOCKS="${STATE_DIR}/blocks"; : > "$BLOCKS"
_swatter_execute_block() { printf '%s %s %s %s\n' "$1" "$2" "$3" "$5" >> "$BLOCKS"; return 0; }
_swatter_pick_ttl() { echo 3600; }
swatter_failclosed_active() { return 1; }   # healthy

cat > "$META" <<'EOF'
[
 {"ip":"1.2.3.4","host_count":3,"category":null,"expires":99},
 {"ip":"2.3.4.5","host_count":1,"category":null,"expires":99},
 {"ip":"5.5.5.5","host_count":5,"category":null,"expires":99}
]
EOF
touch "$META"

swatter_swarm_sweep 2>/dev/null; check sweep-rc "$?" "0"
check sweep-corroborated "$(grep -c '^1.2.3.4 temp' "$BLOCKS")" "1"     # hc=3 >= 2 -> temp block
check sweep-below-threshold "$(grep -c '^2.3.4.5' "$BLOCKS")" "0"       # hc=1 < 2 -> untouched
check sweep-fleet-allow "$(grep -c '^5.5.5.5' "$BLOCKS")" "0"           # canary never swept
check sweep-reason "$(grep -c 'swarm-corroborated hosts=3' "$BLOCKS")" "1"

# already-perm IPs are skipped (no churn)
swatter_now() { echo 100; }; swatter_store_record 1.2.3.4 perm csf 0 90 "already" 0; unset -f swatter_now
: > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-skips-perm "$(grep -c . "$BLOCKS" || true)" "0"

# stale meta -> sweep skipped
printf '[{"ip":"7.7.7.7","host_count":9}]' > "$META"
touch -d '@1000' "$META" 2>/dev/null || touch -t 202001010000 "$META"
: > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-stale-noop "$(grep -c . "$BLOCKS" || true)" "0"

# boost mode: sweep is a no-op
SWARM_ACTION="boost"; : > "$BLOCKS"
swatter_swarm_sweep 2>/dev/null
check sweep-boost-noop "$(grep -c . "$BLOCKS" || true)" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_sweep_test.sh` → FAIL (stub sweeps nothing).

- [ ] **Step 3: Replace the `swatter_swarm_sweep` stub in `lib/swarm.sh`:**

```bash
# Opt-in proactive sweep (SWARM_ACTION=corroborated-block): temp-block feed IPs
# corroborated by >= SWARM_MIN_CORROBORATION distinct enrolled hosts. EVERY
# block routes through _swatter_execute_block — never a raw block path — so
# never-block/classify/unsafe/cap/fail-closed/audit ALL apply (spec §8).
# Requires the json sidecar (frozen obligation 2); jq-gated.
# Cadence (locked): re-issues temp for still-corroborated IPs each daily
# refresh — keep-alive while corroborated, natural decay when dropped from the
# feed (ladder TTL caps at 3d > daily cadence). Report mode dry-runs through
# the backends exactly like scan/import-bans (dry_run=1 records — a preview,
# and dry temps never escalate or publish).
swatter_swarm_sweep() {
    _swarm_enabled || return 0
    [[ "${SWARM_ACTION:-boost}" == "corroborated-block" ]] || return 0
    [[ "${SWATTER_HAVE_JQ}" -eq 1 ]] || { log_warn "swarm sweep: corroborated-block requires jq — skipped"; return 0; }
    local meta="${STATE_DIR}/feeds/swarm.meta.json"
    [[ -s "$meta" ]] || { log_info "swarm sweep: no corroboration data (empty feed or meta fetch failed)"; return 0; }

    # Same staleness policy as the provider (spec §4.3).
    local age
    age=$(( $(swatter_now) - $(stat_mtime "$meta" || echo 0) ))
    if (( age > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )); then
        log_warn "swarm sweep: meta stale (>${SWARM_MAX_AGE_DAYS}d) — skipped"
        return 0
    fi

    # Mirror swatter_scan's health gate + per-run breaker scope: the sweep gets
    # its own MAX_BLOCKS_PER_RUN budget via _SW_TOTAL_BLOCKS (score.sh:93-97).
    local healthy=1
    swatter_failclosed_active && healthy=0
    _SW_TOTAL_BLOCKS=0

    local ip hc n=0 score ttl prior
    while IFS=$'\t' read -r ip hc; do
        [[ -n "$ip" ]] || continue
        [[ "$hc" =~ ^[0-9]+$ ]] || continue
        swatter_is_valid_ip_or_cidr "$ip" || continue
        # Fleet canary consult (spec §4.5) — cheap pre-filter; never-block and
        # the rest are re-checked inside _swatter_execute_block.
        [[ -s "${SWARM_ALLOW_FILE:-}" ]] && _ip_in_cidr_file "$ip" "${SWARM_ALLOW_FILE}" && continue
        swatter_store_is_perm "$ip" && continue
        score=$(( ${SWARM_BASE_SCORE:-70} + 15 * (hc - 1) )); (( score > 100 )) && score=100
        prior="$(swatter_store_recent_temp_count "$ip")"
        ttl="$(_swatter_pick_ttl "$prior")"
        # No local traffic => no top_vhost: CF-plane targets audit skipped-novhost;
        # the sweep protects the DIRECT plane (same posture as import-bans).
        # rep=$score: the swarm score IS this block's reputation input.
        _swatter_execute_block "$ip" temp "$ttl" "$score" \
            "swarm-corroborated hosts=${hc}" "{\"swarm\":true,\"hosts\":${hc}}" \
            "$score" 0 "" "$healthy" && n=$(( n + 1 ))
    done < <(jq -r --argjson n "${SWARM_MIN_CORROBORATION:-2}" \
                '.[] | select((.host_count // 0) >= $n) | [.ip, .host_count] | @tsv' "$meta" 2>/dev/null)
    (( n > 0 )) && log_info "swarm sweep: ${n} corroborated block(s) applied"
    return 0
}
```

- [ ] **Step 4: Hook into `cmd_refresh_feeds`** in `bin/swatter` — after `swatter_intel_refresh_all || rc=1` (line 254):

```bash
    swatter_intel_refresh_all || rc=1

    # Corroborated-block sweep (opt-in): acts on the JUST-refreshed swarm meta,
    # entirely through _swatter_execute_block. No-op unless configured.
    swatter_swarm_sweep || true
```

- [ ] **Step 5: Run to verify it passes.** `bash test/swarm_sweep_test.sh` → PASS. `bash test/block_test.sh && bash test/score_test.sh` → still green.

- [ ] **Step 6: Commit**

```bash
git add lib/swarm.sh bin/swatter test/swarm_sweep_test.sh
git commit -m "feat(swarm): corroborated-block sweep — threshold-gated, choke-routed, breaker-capped"
```

---

### Task 7: CLI — `cmd_swarm {enroll|status|disable|purge}`

**Files:**
- Modify: `lib/swarm.sh` (replace the `cmd_swarm` stub)
- Test: `test/swarm_cli_test.sh`

**Interfaces:**
- Consumes: everything above; `SWATTER_CONF` (status display only); `stat_mtime`.
- Produces: `cmd_swarm <verb>`:
  - `enroll` — POST `/register` `{host_id, label}` with the enroll token (label = `hostname -f` fallback `hostname`, SANITIZED to `[A-Za-z0-9._-]` max 64 — review: hand-built JSON must never see raw hostname bytes); prints the confirmed host_id; rc 1 on missing token/transport/non-200.
  - `status` — prints enabled/hub/host_id/publish-cursor/feed age+entries/meta rows/action mode; warns when `swarm` ∉ `INTEL_PROVIDERS` (consume dead); live `GET /health` when curl available. rc 0 always.
  - `disable` — deletes `swarm.txt`, `swarm.meta.json`, `${STATE_DIR}/intel/swarm/` cache, publish cursor; loud reminder to set `SWARM_ENABLE="false"` AND remove `swarm` from `INTEL_PROVIDERS` in the conf (conf is never edited programmatically). "No box remains stuck on a poisoned last-good feed" (spec §13).
  - `purge` — destructive on the hub: POST `/purge` `{host_id}` with the WRITE token (Task 8 endpoint). Requires `--yes` or interactive TTY confirm (`[[ -t 0 ]]` guard — release gate runs stdin-closed). rc 3 unconfirmed, rc 2 unknown verb.

- [ ] **Step 1: Write the failing test — `test/swarm_cli_test.sh`**

```bash
#!/usr/bin/env bash
# test/swarm_cli_test.sh — swatter swarm enroll/status/disable/purge.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"

PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-swcli.XXXXXX")"
LOG_DIR="${STATE_DIR}/log"; trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "${STATE_DIR}/feeds" "${STATE_DIR}/intel/swarm" "${LOG_DIR}"
SWATTER_HAVE_CURL=1; SWATTER_HAVE_JQ=0
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"
INTEL_PROVIDERS="ipsum"
SWARM_ENROLL_TOKEN_FILE="${STATE_DIR}/enroll.tok"; printf 'enroll-tok' > "$SWARM_ENROLL_TOKEN_FILE"
SWARM_WRITE_TOKEN_FILE="${STATE_DIR}/write.tok";   printf 'write-tok'  > "$SWARM_WRITE_TOKEN_FILE"
SWARM_READ_TOKEN_FILE="${STATE_DIR}/read.tok";     printf 'read-tok'   > "$SWARM_READ_TOKEN_FILE"

POSTS="${STATE_DIR}/posts"; : > "$POSTS"
CURL_RESP=""; CURL_CODE="200"
curl() {
    local prev="" a out="" data="" url=""
    for a in "$@"; do
        [[ "$prev" == "-o" ]] && out="$a"
        [[ "$prev" == "--data-binary" ]] && data="$a"
        prev="$a"; url="$a"
    done
    printf 'URL=%s\n' "$url" >> "$POSTS"
    [[ -n "$data" ]] && cat "${data#@}" >> "$POSTS" && printf '\n' >> "$POSTS"
    [[ -n "$out" ]] && printf '%s' "$CURL_RESP" > "$out"
    printf '%s' "$CURL_CODE"
    return 0
}

# --- enroll happy path: POSTs /register with host_id + SANITIZED label
hid="$(swatter_swarm_host_id)"
CURL_RESP="{\"enrolled\":\"${hid}\"}"
hostname() { printf 'host"with\\evil\nbytes.example.com'; }   # hostile hostname
cmd_swarm enroll </dev/null >/dev/null 2>&1; check enroll-rc "$?" "0"
check enroll-url "$(grep -c 'URL=https://hub.example/register' "$POSTS")" "1"
check enroll-hostid "$(grep -c "\"host_id\":\"${hid}\"" "$POSTS")" "1"
# label was sanitized to [A-Za-z0-9._-]: no quote/backslash/newline in payload
grep -q 'hostwithevilbytes.example.com' "$POSTS" && PASS=$((PASS+1)) || { echo "FAIL enroll-label-sanitized"; FAIL=$((FAIL+1)); }
unset -f hostname

# --- enroll without token file -> rc 1
SWARM_ENROLL_TOKEN_FILE="${STATE_DIR}/missing.tok"
cmd_swarm enroll </dev/null >/dev/null 2>&1; check enroll-notok-rc "$?" "1"
SWARM_ENROLL_TOKEN_FILE="${STATE_DIR}/enroll.tok"

# --- status runs clean with stdin closed, mentions the hub, and warns about
#     the missing INTEL_PROVIDERS wiring (consume would be dead)
out="$(cmd_swarm status </dev/null 2>&1)"; check status-rc "$?" "0"
printf '%s' "$out" | grep -q 'hub.example' && PASS=$((PASS+1)) || { echo "FAIL status-hub"; FAIL=$((FAIL+1)); }
printf '%s' "$out" | grep -q 'INTEL_PROVIDERS' && PASS=$((PASS+1)) || { echo "FAIL status-intel-warn"; FAIL=$((FAIL+1)); }
INTEL_PROVIDERS="ipsum swarm"
out="$(cmd_swarm status </dev/null 2>&1)"
printf '%s' "$out" | grep -q 'INTEL_PROVIDERS' && { echo "FAIL status-intel-ok-nowarn"; FAIL=$((FAIL+1)); } || PASS=$((PASS+1))

# --- disable removes feed + meta + intel cache + cursor
printf '1.2.3.4\n' > "${STATE_DIR}/feeds/swarm.txt"
printf '[]' > "${STATE_DIR}/feeds/swarm.meta.json"
printf '100' > "${STATE_DIR}/swarm.publish.cursor"
printf 'cached' > "${STATE_DIR}/intel/swarm/1.2.3.4"
cmd_swarm disable </dev/null >/dev/null 2>&1; check disable-rc "$?" "0"
[[ ! -e "${STATE_DIR}/feeds/swarm.txt" && ! -e "${STATE_DIR}/feeds/swarm.meta.json" \
   && ! -e "${STATE_DIR}/swarm.publish.cursor" && ! -e "${STATE_DIR}/intel/swarm/1.2.3.4" ]] \
    && PASS=$((PASS+1)) || { echo "FAIL disable-clean"; FAIL=$((FAIL+1)); }

# --- purge: stdin closed + no --yes -> rc 3, NO request sent
: > "$POSTS"
cmd_swarm purge </dev/null >/dev/null 2>&1; check purge-noconfirm-rc "$?" "3"
check purge-noconfirm-sent "$(grep -c 'URL=' "$POSTS" || true)" "0"

# --- purge --yes POSTs /purge with the write token's host_id
CURL_RESP='{"purged_sightings":4,"purged_offenders":2}'
cmd_swarm purge --yes </dev/null >/dev/null 2>&1; check purge-rc "$?" "0"
check purge-url "$(grep -c 'URL=https://hub.example/purge' "$POSTS")" "1"

# --- unknown verb -> rc 2
cmd_swarm bogus </dev/null >/dev/null 2>&1; check unknown-rc "$?" "2"
unset -f curl

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run to verify it fails.** `bash test/swarm_cli_test.sh` → FAIL (stub returns 2 for every verb).

- [ ] **Step 3: Replace the `cmd_swarm` stub in `lib/swarm.sh`:**

```bash
# swatter swarm {enroll|status|disable|purge} — lives in the lib (not bin/) so
# tests can drive it directly, same as cmd_origin_lock.
cmd_swarm() {
    local action="${1:-status}"; shift || true
    local assume_yes=0 arg
    for arg in "$@"; do
        case "$arg" in
            --yes|--force) assume_yes=1 ;;
            *) log_warn "swarm: ignoring unknown flag '${arg}'" ;;
        esac
    done

    case "$action" in
        enroll)
            _swarm_enabled || { log_error "swarm: set SWARM_ENABLE=true + SWARM_HUB_URL first"; return 1; }
            [[ -n "${SWARM_ENROLL_TOKEN_FILE:-}" ]] || { log_error "swarm enroll: SWARM_ENROLL_TOKEN_FILE not set (operator-held token)"; return 1; }
            local host_id label cfg rtmp code
            host_id="$(swatter_swarm_host_id)" || return 1
            # Sanitize before hand-built JSON: hostnames can carry bytes JSON
            # can't (review). Safe charset only, bounded length.
            label="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
            label="$(printf '%s' "$label" | tr -cd 'A-Za-z0-9._-' | cut -c1-64)"
            [[ -n "$label" ]] || label="unknown"
            cfg="$(_swarm_curl_cfg_token "${SWARM_ENROLL_TOKEN_FILE}")" || return 1
            printf 'header = "Content-Type: application/json"\n' >> "$cfg"
            rtmp="$(mktemp "${TMPDIR:-/tmp}/swatter-swarmreg.XXXXXX")" || { rm -f "$cfg"; return 1; }
            printf '{"host_id":"%s","label":"%s"}' "$host_id" "$label" > "${rtmp}.req"
            code="$(curl --max-time 15 -sS -K "$cfg" -o "$rtmp" -w '%{http_code}' \
                         --data-binary "@${rtmp}.req" "${SWARM_HUB_URL%/}/register" 2>/dev/null)"
            local crc=$?
            rm -f "$cfg" "${rtmp}.req"
            if (( crc != 0 )) || [[ "$code" != "200" ]]; then
                rm -f "$rtmp"; log_error "swarm enroll FAILED (http ${code:-none} rc=${crc})"; return 1
            fi
            rm -f "$rtmp"
            log_info "swarm enroll ok — host_id ${host_id} registered"
            echo "enrolled: ${host_id} (label: ${label})"
            echo "This box now counts toward fleet corroboration. Keep the enroll token OFF this box unless it re-enrolls."
            ;;
        status)
            local feed="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
            local cursor_file="${STATE_DIR}/swarm.publish.cursor"
            echo "Swarm (fleet reputation sharing)"
            if _swarm_enabled; then echo "  enabled:     true"; else echo "  enabled:     ${SWARM_ENABLE:-false} (inert)"; fi
            echo "  hub:         ${SWARM_HUB_URL:-<unset>}"
            echo "  action:      ${SWARM_ACTION:-boost} (min corroboration: ${SWARM_MIN_CORROBORATION:-2})"
            echo "  publish:     ${SWARM_PUBLISH:-true} (cursor: $( [[ -s "$cursor_file" ]] && cat "$cursor_file" || echo none))"
            echo "  host_id:     $( [[ -s "${STATE_DIR}/swarm.host_id" ]] && tr -d '[:space:]' < "${STATE_DIR}/swarm.host_id" || echo '<not created — created on first publish/enroll>')"
            if [[ " ${INTEL_PROVIDERS:-} " != *" swarm "* ]]; then
                echo "  consume:     INACTIVE — add 'swarm' to INTEL_PROVIDERS in ${SWATTER_CONF} to consume the feed" >&2
            fi
            if [[ -s "$feed" ]]; then
                local age
                age=$(( ($(swatter_now) - $(stat_mtime "$feed" || echo 0)) / 3600 ))
                echo "  feed:        $(grep -c . "$feed") entries, ${age}h old (${feed})"
            else
                echo "  feed:        empty/absent"
            fi
            [[ -s "$meta" && "${SWATTER_HAVE_JQ}" -eq 1 ]] \
                && echo "  meta:        $(jq 'length' "$meta" 2>/dev/null || echo '?') rows (host_count sidecar)"
            if _swarm_enabled && [[ "${SWATTER_HAVE_CURL}" -eq 1 ]]; then
                local hcode
                hcode="$(curl --max-time 10 -sS -o /dev/null -w '%{http_code}' "${SWARM_HUB_URL%/}/health" 2>/dev/null)"
                echo "  hub health:  $( [[ "$hcode" == "200" ]] && echo ok || echo "UNREACHABLE (http ${hcode:-none})" )"
            fi
            ;;
        disable)
            rm -f "${STATE_DIR}/feeds/swarm.txt" "${STATE_DIR}/feeds/swarm.meta.json" \
                  "${STATE_DIR}/swarm.publish.cursor"
            rm -rf "${STATE_DIR}/intel/swarm"
            log_info "swarm disable: feed, meta, intel cache and publish cursor removed"
            echo "swarm state cleared — no stale/poisoned feed can act on this box."
            if [[ "${SWARM_ENABLE:-false}" == "true" ]]; then
                echo "NOTE: SWARM_ENABLE is still \"true\" in ${SWATTER_CONF} — set it to \"false\" (and remove 'swarm' from INTEL_PROVIDERS) to stop refresh/publish re-creating state." >&2
            fi
            ;;
        purge)
            # Destructive ON THE HUB: removes every sighting this host_id ever
            # contributed (spec §13, bad-publish recovery). Needs the WRITE token.
            _swarm_enabled || { log_error "swarm: set SWARM_ENABLE=true + SWARM_HUB_URL first"; return 1; }
            if (( ! assume_yes )); then
                if [[ -t 0 ]]; then
                    local reply
                    read -r -p "Purge ALL of this host's contributions from the hub? Type 'yes' to confirm: " reply
                    [[ "$reply" == "yes" ]] || { log_error "swarm purge: not confirmed — nothing sent"; return 3; }
                else
                    log_error "swarm purge requires --yes (or an interactive confirm)"
                    return 3
                fi
            fi
            local host_id cfg rtmp code
            host_id="$(swatter_swarm_host_id)" || return 1
            cfg="$(_swarm_curl_cfg_token "${SWARM_WRITE_TOKEN_FILE}")" || return 1
            printf 'header = "Content-Type: application/json"\n' >> "$cfg"
            rtmp="$(mktemp "${TMPDIR:-/tmp}/swatter-swarmpurge.XXXXXX")" || { rm -f "$cfg"; return 1; }
            printf '{"host_id":"%s"}' "$host_id" > "${rtmp}.req"
            code="$(curl --max-time 15 -sS -K "$cfg" -o "$rtmp" -w '%{http_code}' \
                         --data-binary "@${rtmp}.req" "${SWARM_HUB_URL%/}/purge" 2>/dev/null)"
            local crc=$?
            rm -f "$cfg" "${rtmp}.req"
            if (( crc != 0 )) || [[ "$code" != "200" ]]; then
                rm -f "$rtmp"; log_error "swarm purge FAILED (http ${code:-none} rc=${crc})"; return 1
            fi
            cat "$rtmp"; echo; rm -f "$rtmp"
            log_info "swarm purge ok — this host's contributions removed from the hub"
            ;;
        *)
            log_error "swarm: unknown subcommand '${action}' (enroll|status|disable|purge)"
            return 2
            ;;
    esac
}
```

- [ ] **Step 4: Run to verify it passes.** `bash test/swarm_cli_test.sh` → PASS. `bash test/swarm_test.sh` → still green (stubs replaced compatibly).

- [ ] **Step 5: Commit**

```bash
git add lib/swarm.sh test/swarm_cli_test.sh
git commit -m "feat(swarm): CLI — enroll (sanitized label), status (+INTEL_PROVIDERS check), disable, purge"
```

---

### Task 8: Hub — additive `POST /purge` endpoint (spec §13 prerequisite)

**Files:**
- Modify: `hub/src/index.js` (import + handler + route)
- Modify: `hub/src/db.js` (new `purgeHost`)
- Modify: `hub/README.md` (contract section)
- Test: `hub/test/purge.test.js`

**Interfaces:**
- Produces: `POST /purge` — WRITE token — `{host_id: string}` → `200 {purged_sightings: n, purged_offenders: m}`; `400` invalid host_id; `401` wrong/missing token. Deletes ALL sightings for that host_id and any offenders left with zero sightings (atomic batch — same `DB.batch` transaction semantics `prune` already relies on at `hub/src/db.js`). Does NOT unregister the host. **Additive** to the frozen contract (no existing shape changes).

- [ ] **Step 1: Write the failing test — `hub/test/purge.test.js`**

```js
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import worker from "../src/index.js";

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings"),
    env.DB.prepare("DELETE FROM offenders"),
    env.DB.prepare("DELETE FROM hosts"),
  ]);
});

const call = async (path, init) => {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request("https://hub" + path, init), env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
};
const W = { authorization: "Bearer " + env.SWARM_WRITE_TOKEN, "content-type": "application/json" };
const E = { authorization: "Bearer " + env.SWARM_ENROLL_TOKEN, "content-type": "application/json" };
const R = { authorization: "Bearer " + env.SWARM_READ_TOKEN };

describe("POST /purge", () => {
  it("removes the host's sightings and orphaned offenders, keeps corroborated ones", async () => {
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxA" }) });
    await call("/register", { method: "POST", headers: E, body: JSON.stringify({ host_id: "boxB" }) });
    await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "1.1.1.1" }, { ip: "2.2.2.2" }] }) });
    await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxB", entries: [{ ip: "2.2.2.2" }] }) });

    const res = await call("/purge", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA" }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ purged_sightings: 2, purged_offenders: 1 });

    // 1.1.1.1 (boxA-only) is gone; 2.2.2.2 survives via boxB's sighting.
    const feed = (await (await call("/feed", { headers: R })).text()).trim();
    expect(feed).toBe("2.2.2.2");
    // boxA stays ENROLLED (purge is data-removal, not unenrollment).
    const again = await call("/contribute", { method: "POST", headers: W, body: JSON.stringify({ host_id: "boxA", entries: [{ ip: "3.3.3.3" }] }) });
    expect((await again.json()).enrolled).toBe(true);
  });

  it("rejects read/enroll tokens and bad host_ids", async () => {
    expect((await call("/purge", { method: "POST", headers: { authorization: "Bearer " + env.SWARM_READ_TOKEN, "content-type": "application/json" }, body: JSON.stringify({ host_id: "x" }) })).status).toBe(401);
    expect((await call("/purge", { method: "POST", headers: W, body: JSON.stringify({ host_id: "" }) })).status).toBe(400);
  });
});
```

- [ ] **Step 2: Run to verify it fails.** `cd hub && npm test -- purge` → FAIL (404).

- [ ] **Step 3: Add `purgeHost` to `hub/src/db.js`** (append after `prune`):

```js
// Bad-publish recovery (spec §13): drop every sighting this host contributed,
// then any offenders left with no sightings at all. One atomic batch so a
// concurrent feed never sees a half-purged state. The host stays enrolled.
export async function purgeHost(env, { host }) {
  const [s, o] = await env.DB.batch([
    env.DB.prepare("DELETE FROM sightings WHERE host = ?").bind(host),
    env.DB.prepare(
      "DELETE FROM offenders WHERE ip NOT IN (SELECT DISTINCT ip FROM sightings)"
    ),
  ]);
  return { sightings: s.meta.changes ?? 0, offenders: o.meta.changes ?? 0 };
}
```

- [ ] **Step 4: Wire it into `hub/src/index.js`** — exact edits (review: v1 left the import implicit):

(a) the db import line at the top of the file changes FROM:
```js
import { contributeMany, registerHost, isEnrolled, feedRows, prune } from "./db.js";
```
TO:
```js
import { contributeMany, registerHost, isEnrolled, feedRows, prune, purgeHost } from "./db.js";
```
(b) add the handler (after `handleRegister`):
```js
async function handlePurge(request, env) {
  if (!checkAuth(request, env.SWARM_WRITE_TOKEN)) return json({ error: "unauthorized" }, 401);
  if (bodyTooLarge(request)) return json({ error: "body too large" }, 413);
  const body = await readJson(request);
  const host = validHostId(body?.host_id) ? body.host_id : null;
  if (!host) return json({ error: "valid host_id required" }, 400);
  const d = await purgeHost(env, { host });
  return json({ purged_sightings: d.sightings, purged_offenders: d.offenders }, 200);
}
```
(c) add the route inside the `fetch` router, directly after the `/register` line:
```js
    if (m === "POST" && url.pathname === "/register") return handleRegister(request, env);
    if (m === "POST" && url.pathname === "/purge") return handlePurge(request, env);
```

- [ ] **Step 5: Update `hub/README.md` Contract section** — add:

```markdown
- `POST /purge` (write) — `{host_id}` — removes ALL of that host's sightings +
  any offenders left uncorroborated (bad-publish recovery; host stays enrolled).
  Host CLI: `swatter swarm purge --yes`.
```

- [ ] **Step 6: Run the full hub suite.** `cd hub && npm test` → all green (71+ tests).

- [ ] **Step 7: Commit.** Note: the hub REDEPLOY (`cd hub && npx wrangler deploy`) is **operator-run** — the wrangler.toml carries the `swarm.peaceharbor.com` custom-domain route, and zone-touching deploys are operator-run per the Developer-wide terminal-scripts rule.

```bash
git add hub/src/db.js hub/src/index.js hub/test/purge.test.js hub/README.md
git commit -m "feat(swarm-hub): POST /purge — bad-publish recovery (additive to the frozen contract)"
```

---

### Task 9: Secrets proof + full-suite gate

**Files:**
- Modify: `test/curl_secrets_test.sh` (add swarm cases 10–12)
- Test: full `test/*_test.sh` + `hub` suite

**Interfaces:** none new — this task PROVES the security constraint (spec §11: "curl uses `-K` — extend `curl_secrets_test.sh`"). The blocks below follow the file's REAL pattern (verified): its mock curl logs `ARGS:` + dumps any `-K` file into `$LOG` and prints `MOCK_STDOUT`; assertions are `argv_clean <name> <secret>` + `cfg_has <name> <pattern>`. `MOCK_STDOUT='200'` doubles as the `-w '%{http_code}'` output; `-o` files are never written by the mock, which every swarm path tolerates (empty response body ⇒ empty-feed clear / no `enrolled:false` match / success).

- [ ] **Step 1: Append to `test/curl_secrets_test.sh`** (after case 9, before the footer):

```bash
# 10-12) Swarm: three tokens (write/read/enroll), all via -K, never argv.
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/swarm.sh"
source "${ROOT}/lib/providers/swarm.sh"
SWARM_ENABLE="true"; SWARM_HUB_URL="https://hub.example"; SWARM_PUBLISH="true"
mkdir -p "$TMP/feeds"
SWARM_WRITE_TOKEN_FILE="$TMP/sw.tok";  printf 'SWARMWRITESECRET'  > "$SWARM_WRITE_TOKEN_FILE"
SWARM_READ_TOKEN_FILE="$TMP/sr.tok";   printf 'SWARMREADSECRET'   > "$SWARM_READ_TOKEN_FILE"
SWARM_ENROLL_TOKEN_FILE="$TMP/se.tok"; printf 'SWARMENROLLSECRET' > "$SWARM_ENROLL_TOKEN_FILE"
swatter_store_perm_ips_since() { printf '203.0.113.7\t100\n'; }
swatter_is_never_block() { return 1; }

# 10) publish (POST /contribute, write token)
: > "$LOG"; MOCK_STDOUT='200'
swatter_swarm_publish >/dev/null 2>&1
argv_clean swarm-publish "SWARMWRITESECRET"
cfg_has swarm-publish 'header = "Authorization: Bearer SWARMWRITESECRET"'

# 11) feed refresh (GET /feed, read token)
: > "$LOG"; MOCK_STDOUT='200'
provider_swarm_refresh >/dev/null 2>&1
argv_clean swarm-feed "SWARMREADSECRET"
cfg_has swarm-feed 'header = "Authorization: Bearer SWARMREADSECRET"'

# 12) enroll (POST /register, enroll token)
: > "$LOG"; MOCK_STDOUT='200'
cmd_swarm enroll </dev/null >/dev/null 2>&1
argv_clean swarm-enroll "SWARMENROLLSECRET"
cfg_has swarm-enroll 'header = "Authorization: Bearer SWARMENROLLSECRET"'
```

(Note: `STATE_DIR="$TMP"` is already set by case 6; the publish cursor and host_id land under `$TMP` and are cleaned by the existing EXIT trap.)

- [ ] **Step 2: Run.** `bash test/curl_secrets_test.sh` → PASS with 6 new assertions in its count.

- [ ] **Step 3: Full gates.**

```bash
for t in test/*_test.sh; do bash "$t" >/dev/null 2>&1 </dev/null || echo "FAIL $t"; done   # expect no output
cd hub && npm test && cd ..
```

- [ ] **Step 4: Commit**

```bash
git add test/curl_secrets_test.sh
git commit -m "test(swarm): secrets proof — all three swarm tokens via curl -K, never argv"
```

---

## Self-Review

- **Spec coverage (design v3):** §4.1 publish (Task 5: sent-rows-only cursor, 4 gates, chunking, fail-soft, in-lock, enforce-only, rejected-drift warn) ✓. §4.2/§4.3 consume + BOTH frozen obligations (Task 3: empty-200-clears + keep-last-good + fresh-or-absent meta; Task 4 lookup + staleness) ✓. §4.4 tokens (Task 1 helper, 0400 files, `curl -K`; Task 9 proof against the real harness) ✓. §4.5 fleet allowlist on BOTH paths (Task 5 publish filter; Task 4 lookup exempt; Task 6 sweep pre-filter) ✓. §6 host_id + operator enroll (Tasks 1, 7) ✓. §8 boost via standard `W_REPUTATION` intel fold — now PROVEN numerically (Task 4 fold tests: clean-not-tipped, near-miss-tipped, never-lowers) — + corroborated-block through `_swatter_execute_block` only (Task 6; never-block by composition with `block_test.sh`) ✓. §9 config keys verbatim + inert defaults + `INTEL_PROVIDERS` opt-in documented in conf, `swarm status`, and `test-config` ✓. §10 two-step box add (Task 7 enroll + example conf) ✓. §11 test list mapped (incl. the boost-fold cases the v1 plan missed) ✓. §12 failure modes ✓. §13 disable (state purge + conf reminder incl. INTEL_PROVIDERS) + purge (Tasks 7, 8) ✓.
- **Placeholder scan:** none. Task 9 now pastes blocks written against the verified real harness (mock behavior + `argv_clean`/`cfg_has` helpers quoted from the actual file).
- **Type consistency:** `_swarm_enabled`/`swatter_swarm_host_id`/`_swarm_curl_cfg_token` (Task 1) used identically in Tasks 3–7. `swatter_store_perm_ips_since` shape (`ip\tts`) matches Task 5's reader. `provider_swarm` output matches the `lib/intel.sh:4-8` contract. `_swatter_execute_block` 10-arg signature matches `lib/score.sh:73-75` (rep=$score documented). Hub `purgeHost` return `{sightings, offenders}` matches `handlePurge`'s mapping; the import diff is explicit.

## Execution Handoff

Subsystem 2 of 2. Prereqs already live: hub deployed (Peace Harbor Web, workers.dev URL; `swarm.peaceharbor.com` pending the operator's `wrangler deploy`), tokens in `~/.swatter-swarm-tokens` (move to Proton Pass). After this plan is green: (1) operator redeploys the hub (Task 8 endpoint), (2) prod rollout is the usual surgical scp (lib/swarm.sh, lib/providers/swarm.sh, lib/store_sqlite.sh, lib/common.sh, bin/swatter + conf keys + token files 0400 + `swarm` added to INTEL_PROVIDERS on consuming boxes), (3) `swatter swarm enroll` on each box, (4) release as v2.7.0.
