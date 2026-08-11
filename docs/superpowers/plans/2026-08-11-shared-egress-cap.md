# Shared Consumer-VPN Egress Perm Cap — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop swatter from placing *permanent* bans on shared consumer-VPN egress addresses (Cloudflare WARP, consumer-VPN ASNs) — cap them at a ladder-maximum temp instead, which also suppresses both publication arms.

**Architecture:** A single veto inside `_swatter_apply_plane` (`lib/score.sh`), the chokepoint all four *scan* perm paths reach, downgrading `action` **and** `audit_action` to `temp`. Identification lives in `lib/asn.sh` as `swatter_is_shared_egress`, CIDR-first (no DNS dependency) with an ASN fallback and fail-open. `import-bans` is a fifth perm path outside the chokepoint and gets its own gate. A read-only-by-default `shared-egress-audit` subcommand sweeps perms already on the books.

**Tech Stack:** Plain bash 4+, sqlite3, awk. No new dependencies. Tests are standalone `test/*_test.sh` scripts run by `make test`.

**Spec:** `docs/superpowers/specs/2026-08-11-shared-vpn-egress-policy-design.md` (revision 2)
**Review:** `docs/superpowers/specs/2026-08-11-shared-vpn-egress-policy-design-review-grok.md`

## Global Constraints

- **Repo is PUBLIC.** No customer IPs, domains, or real evidence in code, config defaults, or commit messages. Test fixtures use documentation ranges (`192.0.2.0/24`, `2001:db8::/32`) or the WARP range itself, which is public fact.
- **Commit identity:** the global noreply address. Never set a real email locally here.
- **Shipped defaults are CIDR-only.** `shared-egress-asns.txt` ships empty/commented. Do **not** ship `13335` — review established that non-edge AS13335 is not equivalent to WARP.
- **Fail open everywhere.** Missing, empty, unreadable, or rejected files, and any ASN resolution failure, mean *no veto* — the perm proceeds. Never fail closed; that would make third-party DNS a global availability lever on the ladder.
- **`_swatter_ev_stamp` accepts integers only** (`lib/score.sh:98`). Use `shared_egress 1`. A string value silently no-ops.
- **Existing suites must stay green**, especially `perm_gate_residue_test.sh`, `scan_wire_test.sh`, `honeypot_test.sh`, `pending_retry_scan_test.sh`.
- **Style:** match surrounding code — comments explain *why*, not *what*; no new helper files unless the plan says so.
- **Branch:** all work on `feat/shared-egress-cap`, FF-merged to `main` at the end (repo convention).

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `lib/common.sh` | `SHARED_EGRESS_*` config defaults | 1 |
| `lib/asn.sh` | `swatter_is_shared_egress` + CIDR-file validation + cache-read hardening | 1 |
| `config/shared-egress.cidr` | shipped static ranges (WARP) | 1 |
| `config/shared-egress-asns.txt` | shipped empty template | 1 |
| `test/shared_egress_test.sh` | identification unit tests | 1 |
| `lib/score.sh` | the veto in `_swatter_apply_plane` + AbuseIPDB guard | 2 |
| `test/shared_egress_cap_test.sh` | veto behavior at the chokepoint | 2 |
| `bin/swatter` | `import-bans` gate | 3 |
| `bin/swatter` | `shared-egress-audit` subcommand + dispatch + help | 4 |
| `test/shared_egress_audit_test.sh` | audit/sweep tests | 4 |
| `install/install.sh` | install the two new config files (if-absent + `.example`) | 5 |
| `config/swatter.example.conf`, `docs/RUNBOOK.md`, `CHANGELOG.md` | operator-facing docs | 5 |

---

### Task 0: Branch

- [ ] **Step 1: Create the working branch**

```bash
cd ~/Developer/apps/swatter
git checkout main && git pull --ff-only
git checkout -b feat/shared-egress-cap
git status --short   # expect clean
```

---

### Task 1: Identify shared consumer-VPN egress

**Files:**
- Modify: `lib/common.sh` (config block near `HOSTING_ASNS_FILE`, ~line 196)
- Modify: `lib/asn.sh` (add functions; harden the cache read at `:16-20`)
- Create: `config/shared-egress.cidr`
- Create: `config/shared-egress-asns.txt`
- Test: `test/shared_egress_test.sh`

**Interfaces:**
- Consumes: `_ip_in_cidr_file` (`lib/allowlist.sh:90`), `swatter_intel_cidr_feed_ok` (`lib/common.sh:597`), `swatter_asn_resolve` (`lib/asn.sh:13`), `log_warn`.
- Produces:
  - `swatter_is_shared_egress <ip>` → echoes a label (`cidr` or `AS<n>(<name>)`), returns **0** if shared egress, **1** otherwise. Never echoes on a non-match.
  - `_swatter_shared_egress_cidr_usable` → 0 if the CIDR file exists and passes validation. Memoized per process in `_SW_SHARED_CIDR_OK`.
  - Config: `SHARED_EGRESS_ENABLE` (default `true`), `SHARED_EGRESS_CIDR_FILE`, `SHARED_EGRESS_ASNS_FILE`, `SHARED_EGRESS_MIN_PREFIX4` (16), `SHARED_EGRESS_MIN_PREFIX6` (32).

- [ ] **Step 1: Write the failing test**

Create `test/shared_egress_test.sh`:

```bash
#!/usr/bin/env bash
# test/shared_egress_test.sh — shared consumer-VPN egress identification:
# CIDR-first, ASN fallback, fail-open, and the /0 poison guard.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"   # _ip_in_cidr_file, _ipv6_expand
source "${ROOT}/lib/asn.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
yes_() { local name="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); else echo "FAIL ${name}"; FAIL=$((FAIL+1)); fi; }
no_()  { local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL ${name}"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi; }

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-se.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/asn"
INTEL_CACHE_TTL=86400; SWATTER_HAVE_DNS=1
SHARED_EGRESS_ENABLE="true"
SHARED_EGRESS_CIDR_FILE="$STATE_DIR/se.cidr"
SHARED_EGRESS_ASNS_FILE="$STATE_DIR/se-asns.txt"

CYMRU_TXT=""
_swatter_dns_txt() { [[ -n "$CYMRU_TXT" ]] && printf '%s\n' "$CYMRU_TXT"; }
reset() { _SW_SHARED_CIDR_OK=""; rm -rf "${STATE_DIR:?}/asn"; mkdir -p "$STATE_DIR/asn"; }

# --- CIDR arm: matches with NO DNS at all ---
printf '104.28.0.0/16 # WARP\n' > "$SHARED_EGRESS_CIDR_FILE"
: > "$SHARED_EGRESS_ASNS_FILE"
SWATTER_HAVE_DNS=0; reset
check cidr-match "$(swatter_is_shared_egress 104.28.1.1)" "cidr"
no_ cidr-nonmatch swatter_is_shared_egress 192.0.2.5
SWATTER_HAVE_DNS=1

# --- /0 poison guard: one bad line disables the whole CIDR arm ---
printf '0.0.0.0/0\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
no_ zeroslash-rejected swatter_is_shared_egress 192.0.2.5
no_ zeroslash-no-selfmatch swatter_is_shared_egress 104.28.1.1

# --- over-broad guard: /8 is narrower than /0 but still far too wide ---
printf '104.0.0.0/8\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
no_ overbroad-rejected swatter_is_shared_egress 104.28.1.1

# --- ASN arm ---
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"
printf '206092 # VPN Consumer\n' > "$SHARED_EGRESS_ASNS_FILE"; reset
CYMRU_TXT='206092 | 45.157.112.0/24 | CY | ripencc | 2019-01-01'
check asn-match "$(swatter_is_shared_egress 45.157.112.64)" "AS206092(VPN Consumer)"
reset; CYMRU_TXT='16276 | 51.222.0.0/16 | FR | ripencc | 2015-01-01'
no_ asn-unlisted swatter_is_shared_egress 51.222.1.1

# --- fail open: DNS dead + no CIDR match ---
reset; CYMRU_TXT=""
no_ dns-fail-open swatter_is_shared_egress 51.222.1.1

# --- disable switch ---
reset; SHARED_EGRESS_ENABLE="false"
no_ disabled swatter_is_shared_egress 104.28.1.1
SHARED_EGRESS_ENABLE="true"

# --- missing / empty files fail open ---
reset; rm -f "$SHARED_EGRESS_CIDR_FILE" "$SHARED_EGRESS_ASNS_FILE"
no_ missing-files swatter_is_shared_egress 104.28.1.1
reset; : > "$SHARED_EGRESS_CIDR_FILE"; : > "$SHARED_EGRESS_ASNS_FILE"
no_ empty-files swatter_is_shared_egress 104.28.1.1

# --- poisoned ASN cache is rejected on READ, not just on write ---
printf '206092 # VPN Consumer\n' > "$SHARED_EGRESS_ASNS_FILE"
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"; reset
printf 'not-an-asn' > "$STATE_DIR/asn/203.0.113.9"
CYMRU_TXT=""   # cache is the only source; a corrupt entry must not be trusted
no_ poisoned-cache-rejected swatter_is_shared_egress 203.0.113.9

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `bash test/shared_egress_test.sh`
Expected: FAIL — `swatter_is_shared_egress: command not found` on every case.

- [ ] **Step 3: Add the config defaults**

In `lib/common.sh`, immediately after the `HOSTING_ASNS_FILE` default (~line 196):

```bash
# Shared consumer-VPN egress (Cloudflare WARP et al). An address here is used by
# many ordinary people at once, so a PERMANENT ban on it is collateral against
# everyone sharing it — the offense is real, the identifier is not the offender.
# Matching caps enforcement at a ladder-max temp; see lib/score.sh's veto.
# CIDR is checked first and needs no DNS; the ASN list is the fallback.
: "${SHARED_EGRESS_ENABLE:=true}"
: "${SHARED_EGRESS_CIDR_FILE:=/etc/swatter/shared-egress.cidr}"
: "${SHARED_EGRESS_ASNS_FILE:=/etc/swatter/shared-egress-asns.txt}"
# Width floor for the CIDR file. Tighter than the intel-feed floor (/8) on
# purpose: a too-broad line here fails toward NOT banning, which is silent.
: "${SHARED_EGRESS_MIN_PREFIX4:=16}"
: "${SHARED_EGRESS_MIN_PREFIX6:=32}"
```

- [ ] **Step 4: Harden the ASN cache read**

In `lib/asn.sh`, replace the cache-hit branch (currently `:19`):

```bash
        if (( age < INTEL_CACHE_TTL )); then
            # Re-validate on READ, not just on write (:37). A corrupt or
            # hand-written cache entry must not become an enforcement input now
            # that a matched ASN can DOWNGRADE a block.
            local cached; cached="$(cat "$cache" 2>/dev/null)"
            if [[ "$cached" =~ ^[0-9]+$ ]]; then printf '%s' "$cached"; return 0; fi
        fi
```

- [ ] **Step 5: Add the identification functions**

Append to `lib/asn.sh`:

```bash
# --- shared consumer-VPN egress -------------------------------------------
# Memoized per process: "" unchecked, 1 usable, 0 rejected.
_SW_SHARED_CIDR_OK=""

# _swatter_shared_egress_cidr_usable : 0 if the CIDR file exists and every line
# is a valid, not-absurdly-broad prefix.
#
# _ip_in_cidr_file treats a /0 as match-everything (lib/allowlist.sh), so ONE
# bad line here would cap every perm on the host — silently, and in the
# direction nobody notices. Reuse the intel-feed poison guard with a tighter
# floor rather than inventing a second validator.
_swatter_shared_egress_cidr_usable() {
    local f="${SHARED_EGRESS_CIDR_FILE:-}"
    if [[ -n "$_SW_SHARED_CIDR_OK" ]]; then (( _SW_SHARED_CIDR_OK )); return; fi
    if [[ ! -s "$f" ]]; then _SW_SHARED_CIDR_OK=0; return 1; fi
    if INTEL_FEED_MIN_PREFIX4="${SHARED_EGRESS_MIN_PREFIX4:-16}" \
       INTEL_FEED_MIN_PREFIX6="${SHARED_EGRESS_MIN_PREFIX6:-32}" \
       swatter_intel_cidr_feed_ok < "$f"; then
        _SW_SHARED_CIDR_OK=1; return 0
    fi
    log_warn "shared-egress: ${f} rejected (invalid or over-broad line) — CIDR arm off this run"
    _SW_SHARED_CIDR_OK=0; return 1
}

# swatter_is_shared_egress <ip> : echo a label + return 0 if the IP is shared
# consumer-VPN egress, else return 1 silently.
#
# CIDR first: it needs no network, so the known ranges stay protected even with
# DNS down. ASN second, and fail-open on any resolution failure — failing closed
# would make a third-party DNS service an availability lever on the whole ladder.
# Callers MUST have validated the IP already (the ASN cache key is the raw
# string); _swatter_apply_plane does this at :135, before the veto.
swatter_is_shared_egress() {
    local ip="$1" asn line fasn name
    [[ "${SHARED_EGRESS_ENABLE:-true}" == "true" ]] || return 1
    if _swatter_shared_egress_cidr_usable \
       && _ip_in_cidr_file "$ip" "${SHARED_EGRESS_CIDR_FILE}"; then
        printf 'cidr'; return 0
    fi
    [[ -s "${SHARED_EGRESS_ASNS_FILE:-}" ]] || return 1
    asn="$(swatter_asn_resolve "$ip")" || return 1
    [[ -n "$asn" ]] || return 1
    while IFS= read -r line; do
        line="${line%%#*}"; fasn="$(printf '%s' "$line" | tr -d ' ')"
        [[ -z "$fasn" ]] && continue
        if [[ "$fasn" == "$asn" ]]; then
            name="$(awk -v a="$asn" '$1==a{sub(/^[^#]*#[ ]*/,""); print; exit}' "${SHARED_EGRESS_ASNS_FILE}")"
            printf 'AS%s(%s)' "$asn" "${name:-shared-egress}"; return 0
        fi
    done < "${SHARED_EGRESS_ASNS_FILE}"
    return 1
}
```

- [ ] **Step 6: Create the shipped config files**

`config/shared-egress.cidr`:

```
# Shared consumer-VPN egress ranges — matching addresses are capped at a
# ladder-max TEMP ban and can never become permanent or published.
#
# This is NOT an allowlist. Addresses here are still banned; they just cannot be
# banned FOREVER, because one address is shared by many unrelated people.
#
# Every line must be a real, narrow range with evidence. Lines broader than a
# /16 (v4) or /32 (v6) are rejected and disable this file entirely — a wide
# entry here silently stops ALL permanent banning on the host.
104.28.0.0/16  # Cloudflare consumer WARP egress (1.1.1.1 app); NOT in the published CDN edge list
```

`config/shared-egress-asns.txt`:

```
# Shared consumer-VPN egress ASNs — the fallback arm of the shared-egress cap,
# used only when the CIDR file does not match. Format: "<asn> # name".
#
# EMPTY BY DEFAULT, deliberately. An ASN is a blunt instrument: it caps every
# address that AS originates. Add an entry only with documented evidence that
# the AS is consumer-VPN egress, and prefer a precise CIDR whenever one exists.
#
# Do NOT add 13335 (Cloudflare). Its published CDN edge ranges are already
# never-blocked earlier, but the AS also originates non-edge, non-WARP space —
# listing it wholesale caps more than the measured problem.
#
# Example (add locally if it applies to your host):
# 206092 # F.N.S. Holdings / "VPN Consumer" — consumer VPN exits
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `bash test/shared_egress_test.sh`
Expected: `Total: 14 passed, 0 failed`

- [ ] **Step 8: Confirm no existing suite regressed**

Run: `make test`
Expected: every suite reports `0 failed`.

- [ ] **Step 9: Commit**

```bash
git add lib/common.sh lib/asn.sh config/shared-egress.cidr \
        config/shared-egress-asns.txt test/shared_egress_test.sh
git commit -m "feat(asn): identify shared consumer-VPN egress (CIDR-first, ASN fallback)

CIDR arm needs no DNS so known ranges stay protected with the resolver down;
ASN arm is the fallback and fails open. The CIDR file is validated with the
existing intel-feed poison guard at a tighter floor, because _ip_in_cidr_file
treats /0 as match-everything and one bad line would silently cap every perm.

Cache reads are now re-validated too: a matched ASN can DOWNGRADE enforcement,
so a corrupt cache entry must not be trusted the way it could when the only
effect was a score boost."
```

---

### Task 2: The perm veto at the chokepoint

**Files:**
- Modify: `lib/score.sh` — `_swatter_apply_plane`, insert after the never-block check (`:145`); AbuseIPDB guard at `:208-209`
- Test: `test/shared_egress_cap_test.sh`

**Interfaces:**
- Consumes: `swatter_is_shared_egress` (Task 1), `_swatter_pick_ttl`, `_swatter_ev_stamp`.
- Produces: `SWATTER_RUN_SHARED_CAPS` — run-scoped counter of capped perms, readable by callers/tests.

- [ ] **Step 1: Write the failing test**

Create `test/shared_egress_cap_test.sh`:

```bash
#!/usr/bin/env bash
# test/shared_egress_cap_test.sh — the perm veto inside _swatter_apply_plane.
# Asserts the three sinks that must agree (backend, ledger, AUDIT) plus the
# publication and tripwire side effects.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/asn.sh"
source "${ROOT}/lib/store_sqlite.sh"
source "${ROOT}/lib/score.sh"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-secap.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
STORE=sqlite; SWATTER_MODE=enforce; SWATTER_HAVE_DNS=0
swatter_store_init
db="$STATE_DIR/swatter.db"

SHARED_EGRESS_ENABLE="true"
SHARED_EGRESS_CIDR_FILE="$STATE_DIR/se.cidr"
SHARED_EGRESS_ASNS_FILE="$STATE_DIR/se-asns.txt"
printf '104.28.0.0/16\n' > "$SHARED_EGRESS_CIDR_FILE"
: > "$SHARED_EGRESS_ASNS_FILE"
CLOUDFLARE_IPS_FILE="$STATE_DIR/cf.cidr"; : > "$CLOUDFLARE_IPS_FILE"
OPERATOR_ALLOW_FILE="$STATE_DIR/allow.cidr"; : > "$OPERATOR_ALLOW_FILE"
MONITORING_RANGES_FILE="$STATE_DIR/mon.cidr"; : > "$MONITORING_RANGES_FILE"
OPERATOR_IPS=""

# Record what each sink saw.
BACKEND="$STATE_DIR/backend.log"; AUDIT="$STATE_DIR/audit.log"; ABUSE="$STATE_DIR/abuse.log"
: > "$BACKEND"; : > "$AUDIT"; : > "$ABUSE"
swatter_block_direct_perm() { echo "perm $1" >> "$BACKEND"; return 0; }
swatter_block_direct_temp() { echo "temp $1 ttl=$2" >> "$BACKEND"; return 0; }
swatter_cf_manages_plane()  { return 1; }   # DIRECT plane only in this test
swatter_abuseipdb_report()  { echo "$1" >> "$ABUSE"; }
_swatter_audit() { echo "$3" >> "$AUDIT"; }   # $3 = audit_action
swatter_is_good_crawler() { return 1; }
_swatter_is_good_crawler() { return 1; }
_swatter_self_ips() { :; }

apply() {  # <ip> [audit_action]
  : > "$BACKEND"; : > "$AUDIT"; : > "$ABUSE"
  _SW_TOTAL_BLOCKS=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_PERMS=0; SWATTER_RUN_SHARED_CAPS=0
  _swatter_apply_plane "$1" DIRECT perm 0 "score=91 rule=critical_badpath" "" 1 91 '{}' 100 ${2:+"$2"}
}
led() { sqlite3 "$db" "SELECT action FROM actions WHERE ip='$1' ORDER BY id DESC LIMIT 1;"; }
permflag() { sqlite3 "$db" "SELECT COALESCE((SELECT perm FROM offenders WHERE ip='$1'),'norow');"; }

# --- shared-egress perm is capped: backend, ledger AND audit must all say temp ---
apply 104.28.5.5
check cap-backend "$(cut -d' ' -f1 < "$BACKEND")"       "temp"
check cap-ttl     "$(grep -o 'ttl=[0-9]*' "$BACKEND")"  "ttl=259200"
check cap-ledger  "$(led 104.28.5.5)"                   "temp"
check cap-audit   "$(cat "$AUDIT")"                     "temp"
check cap-permflag "$(permflag 104.28.5.5)"             "0"
check cap-counter "${SWATTER_RUN_SHARED_CAPS}"          "1"
check cap-tripwire "${SWATTER_RUN_PERMS}"               "0"
check cap-no-abuse "$(wc -l < "$ABUSE" | tr -d ' ')"    "0"
check cap-not-published "$(swatter_store_perm_ips_since 0 | wc -l | tr -d ' ')" "0"

# --- the AbuseIPDB guard must not depend on the perm/temp distinction ---
ABUSEIPDB_REPORT_MIN_ACTION="temp"
apply 104.28.6.6
check cap-no-abuse-mintemp "$(wc -l < "$ABUSE" | tr -d ' ')" "0"
ABUSEIPDB_REPORT_MIN_ACTION="perm"

# --- a secondary leg keeps its own label but is still capped ---
apply 104.28.7.7 plane-upgrade
check leg-backend "$(cut -d' ' -f1 < "$BACKEND")" "temp"
check leg-audit   "$(cat "$AUDIT")"               "plane-upgrade"
check leg-ledger  "$(led 104.28.7.7)"             "temp"

# --- a normal IP is untouched (regression guard) ---
apply 192.0.2.50
check normal-backend "$(cut -d' ' -f1 < "$BACKEND")" "perm"
check normal-ledger  "$(led 192.0.2.50)"             "perm"
check normal-audit   "$(cat "$AUDIT")"               "perm"
check normal-permflag "$(permflag 192.0.2.50)"       "1"
check normal-tripwire "${SWATTER_RUN_PERMS}"         "1"
check normal-abuse   "$(wc -l < "$ABUSE" | tr -d ' ')" "1"

# --- disable switch restores today's behavior ---
SHARED_EGRESS_ENABLE="false"; _SW_SHARED_CIDR_OK=""
apply 104.28.8.8
check disabled-backend "$(cut -d' ' -f1 < "$BACKEND")" "perm"
SHARED_EGRESS_ENABLE="true"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `bash test/shared_egress_cap_test.sh`
Expected: FAIL on `cap-backend` (`want='temp' got='perm'`), `cap-audit`, `cap-ledger`, and the counter cases.

- [ ] **Step 3: Insert the veto**

In `lib/score.sh`, immediately after the never-block block that ends at `:145` and **before** the `MAX_BLOCKS_PER_RUN` check:

```bash
    # Shared consumer-VPN egress: cap at a ladder-max temp, never a perm.
    # The offense is real, but the identifier is shared by many unrelated
    # people, so a PERMANENT ban is collateral against all of them — and a
    # published one recommends that every other host do the same.
    #
    # audit_action MUST move with action. It is bound once at entry (:128) and
    # is what the success audit writes (:212) — and the nightly digest counts
    # perms from the AUDIT log, not the ledger (lib/report.sh). Downgrading
    # only `action` would report a permanent ban that was never placed.
    # A secondary leg's own label (dual-plane / plane-upgrade) is preserved.
    local shared_egress=""
    if [[ "$action" == "perm" && "${SHARED_EGRESS_ENABLE:-true}" == "true" ]] \
       && shared_egress="$(swatter_is_shared_egress "$ip")"; then
        action="temp"
        [[ "$audit_action" == "perm" ]] && audit_action="temp"
        ttl="$(_swatter_pick_ttl 99)"   # ladder max; :168's CF rewrite is skipped now
        reason="${reason} shared-egress=${shared_egress} perm-capped"
        ev="$(_swatter_ev_stamp "$ev" shared_egress 1)"   # integer only — a label here no-ops
        SWATTER_RUN_SHARED_CAPS=$(( ${SWATTER_RUN_SHARED_CAPS:-0} + 1 ))
        log_warn "shared-egress cap: ${ip} (${shared_egress}) perm -> temp ttl=${ttl}"
    fi
    # No else branch is needed: swatter_is_shared_egress echoes nothing when it
    # returns 1, and a short-circuit on the `action`/enable test never runs the
    # assignment at all — `shared_egress` is "" in both cases. It stays in scope
    # for the AbuseIPDB guard below.
```

- [ ] **Step 4: Add the explicit AbuseIPDB guard**

In the same function, change the reporting condition (currently `:208-209`) to lead with the veto flag:

```bash
        # `shared_egress` is checked FIRST and explicitly: the protection must
        # not rest on the perm/temp distinction. With
        # ABUSEIPDB_REPORT_MIN_ACTION=temp the clauses below are both true for a
        # capped IP, which would report the very address the cap exists to keep
        # off a public blocklist.
        if [[ -z "$shared_egress" ]] \
           && [[ "$audit_action" == "$action" ]] \
           && { [[ "${ABUSEIPDB_REPORT_MIN_ACTION:-perm}" == "temp" ]] || [[ "$action" == "perm" ]]; }; then
            swatter_abuseipdb_report "$ip" "$ev" "$reason"
        fi
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `bash test/shared_egress_cap_test.sh`
Expected: `Total: 20 passed, 0 failed`

- [ ] **Step 6: Confirm the neighbouring suites still pass**

Run: `bash test/perm_gate_residue_test.sh && bash test/scan_wire_test.sh && bash test/honeypot_test.sh && bash test/pending_retry_scan_test.sh && bash test/perm_rate_alert_test.sh`
Expected: each prints `0 failed`.

- [ ] **Step 7: Commit**

```bash
git add lib/score.sh test/shared_egress_cap_test.sh
git commit -m "feat(score): cap shared-egress perms at a ladder-max temp

One veto inside _swatter_apply_plane covers all four scan perm paths --
honeypot, ladder, dual-plane and plane-upgrade all reach a backend only
through it, as does the pending-retry drain.

audit_action moves with action: it is bound at entry and is what the success
audit writes, and the digest counts perms from the audit log rather than the
ledger, so downgrading only action would report a perm that never happened.

The AbuseIPDB guard is explicit rather than resting on the perm/temp
distinction -- with ABUSEIPDB_REPORT_MIN_ACTION=temp a capped IP would
otherwise be reported irreversibly."
```

---

### Task 3: Gate `import-bans` — the fifth perm path

**Files:**
- Modify: `bin/swatter` — `cmd_import_bans`, after the never-block check (`:467`)
- Test: `test/shared_egress_audit_test.sh` (created here, extended in Task 4)

**Interfaces:**
- Consumes: `swatter_is_shared_egress` (Task 1).
- Produces: nothing new; `import-bans` now skips shared-egress IPs.

`cmd_import_bans` calls `swatter_block_direct_perm` directly and writes the perm rows itself, so the Task 2 veto never sees it. Skip-and-log is the right semantic here rather than a silent downgrade: imports are operator-run and bulk, so a quiet change of meaning would be worse than a visible refusal.

- [ ] **Step 1: Write the failing test**

Create `test/shared_egress_audit_test.sh`:

```bash
#!/usr/bin/env bash
# test/shared_egress_audit_test.sh — import-bans gate + shared-egress-audit.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/swatter-seaudit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/etc" "$WORK/state"
printf '104.28.0.0/16\n' > "$WORK/etc/shared-egress.cidr"
: > "$WORK/etc/shared-egress-asns.txt"
: > "$WORK/etc/allow.cidr"; : > "$WORK/etc/cloudflare.cidr"; : > "$WORK/etc/monitoring.cidr"

cat > "$WORK/etc/swatter.conf" <<CONF
STORE=sqlite
SWATTER_MODE=enforce
STATE_DIR="$WORK/state"
SHARED_EGRESS_ENABLE=true
SHARED_EGRESS_CIDR_FILE="$WORK/etc/shared-egress.cidr"
SHARED_EGRESS_ASNS_FILE="$WORK/etc/shared-egress-asns.txt"
OPERATOR_ALLOW_FILE="$WORK/etc/allow.cidr"
CLOUDFLARE_IPS_FILE="$WORK/etc/cloudflare.cidr"
MONITORING_RANGES_FILE="$WORK/etc/monitoring.cidr"
CF_MODE=off
CONF

sw() { SWATTER_CONF="$WORK/etc/swatter.conf" bash "${ROOT}/bin/swatter" "$@" 2>&1; }

printf '104.28.9.9\n192.0.2.77\n' > "$WORK/bans.txt"
out="$(sw import-bans "$WORK/bans.txt")"
db="$WORK/state/swatter.db"
imported() { sqlite3 "$db" "SELECT COUNT(*) FROM actions WHERE ip='$1' AND action='perm';" 2>/dev/null || echo 0; }

check import-skips-shared "$(imported 104.28.9.9)" "0"
check import-keeps-normal "$(imported 192.0.2.77)" "1"
case "$out" in *"skip shared-egress"*) PASS=$((PASS+1));;
  *) echo "FAIL import-logs-skip: ${out}"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `bash test/shared_egress_audit_test.sh`
Expected: FAIL `import-skips-shared` (`want='0' got='1'`) and `import-logs-skip`.

- [ ] **Step 3: Add the gate**

In `bin/swatter`, in `cmd_import_bans`, directly after the existing never-block line (`:467`):

```bash
        # import-bans writes perms itself and never reaches _swatter_apply_plane,
        # so the shared-egress veto there cannot see it. Skip rather than
        # silently downgrade: an operator importing a list should be told the
        # entry was refused, not quietly given something else.
        if [[ "${SHARED_EGRESS_ENABLE:-true}" == "true" ]] && se="$(swatter_is_shared_egress "$ip")"; then
            log_info "import-bans: skip shared-egress ${ip} (${se}) — permanent bans on shared consumer VPN egress are policy-capped"
            continue
        fi
```

Declare `se` alongside the existing `nb` local at the top of the function.

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/shared_egress_audit_test.sh`
Expected: `Total: 3 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add bin/swatter test/shared_egress_audit_test.sh
git commit -m "fix(import-bans): gate the fifth perm path on shared egress

cmd_import_bans calls swatter_block_direct_perm and writes the perm rows
directly, so it never reaches _swatter_apply_plane and the veto there could
not see it. A fleet export-bans -> import-bans could reintroduce exactly the
permanent WARP bans this work removes.

Skips and logs rather than downgrading: a bulk operator import should refuse
visibly, not quietly mean something else."
```

---

### Task 4: `shared-egress-audit` — sweep the perms already on the books

**Files:**
- Modify: `bin/swatter` — new `cmd_shared_egress_audit`, dispatch entry, help text
- Test: `test/shared_egress_audit_test.sh` (extend)

**Interfaces:**
- Consumes: `swatter_store_perm_ips_since` (`lib/store_sqlite.sh:705`, pass `0` for all perms), `swatter_store_is_perm_on`, `swatter_block_direct_unblock`, `swatter_cf_unblock`, `swatter_store_unblock`, `swatter_with_state_lock`.
- Produces: `swatter shared-egress-audit [--fix] [--force]`. Exit 0 clean, 1 if any IP verified dirty or `--fix` refused.

**`--fix` never allowlists.** WARP addresses rotate between clients, so a per-IP never-block becomes a standing free pass for whoever receives that address next — the same hazard the design rejects for the whole range, at smaller scale. Unblock only; the Task 2 veto handles future offenses.

- [ ] **Step 1: Write the failing test**

Append to `test/shared_egress_audit_test.sh`, before the summary block:

```bash
# --- shared-egress-audit ---
now="$(date +%s)"
seed() {  # <ip>
  sqlite3 "$db" "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
                 VALUES('$1',${now},${now},91,1,0,1,'x','csf');
                 INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
                 VALUES('$1',${now},'perm','csf',0,91,'seeded',0);"
}
seed 104.28.11.11
seed 192.0.2.99

out="$(sw shared-egress-audit)"
case "$out" in *104.28.11.11*) PASS=$((PASS+1));;
  *) echo "FAIL audit-lists-shared: ${out}"; FAIL=$((FAIL+1));; esac
case "$out" in *192.0.2.99*) echo "FAIL audit-lists-normal: ${out}"; FAIL=$((FAIL+1));;
  *) PASS=$((PASS+1));; esac
permflag() { sqlite3 "$db" "SELECT perm FROM offenders WHERE ip='$1';"; }
check audit-readonly-no-change "$(permflag 104.28.11.11)" "1"

out="$(sw shared-egress-audit --fix)"
check audit-fix-clears     "$(permflag 104.28.11.11)" "0"
check audit-fix-spares     "$(permflag 192.0.2.99)"   "1"
# --fix must NOT allowlist: allow.cidr stays empty.
check audit-fix-no-allow   "$(grep -c . "$WORK/etc/allow.cidr" | tr -d ' ')" "0"
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `bash test/shared_egress_audit_test.sh`
Expected: FAIL — `unknown command 'shared-egress-audit'`.

- [ ] **Step 3: Implement the subcommand**

Add to `bin/swatter`, near the other `cmd_*` definitions:

```bash
# swatter shared-egress-audit [--fix] [--force]
#
# Lists permanent bans that the shared-egress policy would now refuse to place.
# The veto in _swatter_apply_plane is forward-only: it stops new perms, it does
# not clear perms already on the books.
#
# --fix UNBLOCKS ONLY. It deliberately does not allowlist: these addresses
# rotate between clients, so a per-IP never-block would become a standing free
# pass for whoever receives the address next. Future offenses are the veto's job.
cmd_shared_egress_audit() {
    local fix=0 force=0 max="${SHARED_EGRESS_AUDIT_MAX:-25}"
    while (( $# )); do
        case "$1" in
            --fix)   fix=1 ;;
            --force) force=1 ;;
            *) die "usage: swatter shared-egress-audit [--fix] [--force]" ;;
        esac; shift
    done
    [[ "${STORE}" == "sqlite" ]] || die "shared-egress-audit needs the sqlite store"

    local ip ts label ips=() labels=()
    while IFS=$'\t' read -r ip ts; do
        [[ -n "$ip" ]] || continue
        label="$(swatter_is_shared_egress "$ip")" || continue
        ips+=("$ip"); labels+=("$label")
    done < <(swatter_store_perm_ips_since 0)

    if (( ${#ips[@]} == 0 )); then
        echo "shared-egress-audit: no permanent bans match the shared-egress policy."
        return 0
    fi

    local i
    if (( ! fix )); then
        printf 'shared-egress-audit: %d permanent ban(s) match (read-only)\n\n' "${#ips[@]}"
        for i in "${!ips[@]}"; do printf '  %-39s %s\n' "${ips[$i]}" "${labels[$i]}"; done
        printf '\nRe-run with --fix to unblock these. --fix does NOT allowlist.\n'
        return 0
    fi

    # Count gate: an over-broad list must not mass-lift silently.
    if (( ${#ips[@]} > max && ! force )); then
        die "shared-egress-audit: ${#ips[@]} IPs selected, over the ${max} safety limit — review the list first, then re-run with --force"
    fi

    local rc=0
    swatter_with_state_lock 60 || die "shared-egress-audit: could not take the state lock"
    for i in "${!ips[@]}"; do
        ip="${ips[$i]}"
        local failed=0
        SWATTER_LAST_BACKEND_ERR=""
        swatter_block_direct_unblock "$ip" || failed=1
        swatter_cf_unblock "$ip"           || failed=1
        swatter_store_unblock "$ip"
        # Verify on BOTH planes — the exit code is not enough. swatter_store_unblock
        # runs before any failure check, so the ledger says "clear" even when a
        # backend refused; the IP then looks remediated while a deny may be live.
        local dirty=0
        swatter_store_is_perm_on "$ip" csf        && dirty=1
        swatter_store_is_perm_on "$ip" cloudflare && dirty=1
        if (( failed || dirty )); then
            printf '  %-39s PARTIAL%s\n' "$ip" "${SWATTER_LAST_BACKEND_ERR:+ (${SWATTER_LAST_BACKEND_ERR})}"
            rc=1
        else
            printf '  %-39s ok (%s)\n' "$ip" "${labels[$i]}"
        fi
    done
    (( rc == 0 )) \
        && printf '\nshared-egress-audit: %d unblocked, all verified clear on both planes.\n' "${#ips[@]}" \
        || printf '\nshared-egress-audit: FINISHED WITH FAILURES — re-run and check `swatter list perm` / `csf -g <ip>`.\n' >&2
    return "$rc"
}
```

Wire it into the dispatch `case` beside `import-bans)`:

```bash
        shared-egress-audit) cmd_shared_egress_audit "$@" ;;
```

And add to the usage block at the top of the file, beside the other commands:

```bash
#   swatter shared-egress-audit [--fix]  list (or unblock) perms on shared VPN egress
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/shared_egress_audit_test.sh`
Expected: `Total: 9 passed, 0 failed`

- [ ] **Step 5: Confirm the CLI suite still passes**

Run: `bash test/cli_test.sh && make test`
Expected: every suite `0 failed`.

- [ ] **Step 6: Commit**

```bash
git add bin/swatter test/shared_egress_audit_test.sh
git commit -m "feat(cli): add shared-egress-audit to sweep pre-existing perms

The veto is forward-only, so perms already on the books need a sweep.
Read-only by default; --fix unblocks under one state lock, continues past
partial failures, and verifies both planes because swatter_store_unblock runs
before any failure check and would otherwise leave an IP looking remediated
while a deny is still live.

--fix does NOT allowlist. These addresses rotate between clients, so a per-IP
never-block would hand a standing free pass to whoever gets the address next."
```

---

### Task 5: Packaging and operator documentation

**Files:**
- Modify: `install/install.sh` (config install block, ~`:232`; header manifest comment ~`:19`)
- Modify: `config/swatter.example.conf`
- Modify: `docs/RUNBOOK.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the config names from Task 1 and the subcommand from Task 4.
- Produces: nothing code-facing.

- [ ] **Step 1: Add the install rules**

In `install/install.sh`, beside the `hosting-asns.txt` block (~`:232`) — same
if-absent + always-ship-`.example` pattern, so an upgrade neither clobbers
operator edits nor withholds updates:

```bash
    # shared-egress lists are operator-editable; install live only if absent,
    # always ship .example to diff.
    [[ -f /etc/swatter/shared-egress.cidr ]] || install -m 0644 "${SRC}"/config/shared-egress.cidr /etc/swatter/shared-egress.cidr 2>/dev/null \
        || echo "warning: could not install /etc/swatter/shared-egress.cidr — shared-egress CIDR arm disabled until it exists" >&2
    install -m 0644 "${SRC}"/config/shared-egress.cidr /etc/swatter/shared-egress.cidr.example 2>/dev/null || true
    [[ -f /etc/swatter/shared-egress-asns.txt ]] || install -m 0644 "${SRC}"/config/shared-egress-asns.txt /etc/swatter/shared-egress-asns.txt 2>/dev/null || true
    install -m 0644 "${SRC}"/config/shared-egress-asns.txt /etc/swatter/shared-egress-asns.txt.example 2>/dev/null || true
```

Add both live paths to the manifest comment at the top of the file (~`:19`),
matching the existing `hosting-asns.txt` lines.

- [ ] **Step 2: Document the knobs**

Append to `config/swatter.example.conf`, near the ASN settings:

```bash
# --- Shared consumer-VPN egress ------------------------------------------
# Addresses used by many people at once (Cloudflare WARP, consumer VPN exits).
# A match caps enforcement at a ladder-max TEMP: the IP is still banned, it just
# cannot be banned permanently, and is therefore never published to the swarm or
# reported to AbuseIPDB. This is NOT an allowlist.
# Review with: swatter shared-egress-audit
#SHARED_EGRESS_ENABLE="true"
#SHARED_EGRESS_CIDR_FILE="/etc/swatter/shared-egress.cidr"
#SHARED_EGRESS_ASNS_FILE="/etc/swatter/shared-egress-asns.txt"
# Width floor for the CIDR file. A line broader than this is rejected and turns
# the whole CIDR arm off — a wide entry would silently stop ALL permanent bans.
#SHARED_EGRESS_MIN_PREFIX4="16"
#SHARED_EGRESS_MIN_PREFIX6="32"
# Safety limit on `shared-egress-audit --fix`; above this it demands --force.
#SHARED_EGRESS_AUDIT_MAX="25"
```

- [ ] **Step 3: Add the RUNBOOK section**

Append a new section to `docs/RUNBOOK.md`:

```markdown
## Shared consumer-VPN egress

Some addresses are used by many unrelated people at once — Cloudflare WARP
(`104.28.0.0/16`, the 1.1.1.1 app) and consumer VPN exits. Offenses from them
are real, but the *identifier* is not the offender, so swatter caps them at a
ladder-maximum temp (72h) and never a permanent ban. That also keeps them off
the swarm and out of AbuseIPDB, since both arms key on perms.

**This is not an allowlist.** The IP is still blocked, repeatedly, for as long
as it misbehaves. Do **not** add these ranges to `allow.cidr` or
`cloudflare.cidr` — everything in those files is a never-block, so that would
hand anyone a bypass by switching on a free consumer VPN.

- Review what the policy would refuse: `swatter shared-egress-audit`
- Clear pre-existing perms: `swatter shared-egress-audit --fix`
  (unblocks only — it does not allowlist, because these addresses rotate
  between clients)
- Disable entirely: `SHARED_EGRESS_ENABLE="false"` (takes effect next scan;
  does not re-ban anything already capped)

**Adding entries.** Prefer a precise CIDR over an ASN — an ASN caps everything
that AS originates. Any line broader than `/16` (v4) or `/32` (v6) is rejected
and disables the whole CIDR file, because a wide entry would silently stop all
permanent banning. Check `swatter test-config` after editing.

**Residual risk, accepted knowingly.** Permanent bans are impossible on these
ranges, so a patient attacker can rotate through the pool and return within 72h.
On the Cloudflare plane this costs nothing — a CF "perm" is already TTL-emulated
at the same ladder maximum — so the real change is confined to the CSF plane.
```

- [ ] **Step 4: Add the CHANGELOG entry**

At the top of `CHANGELOG.md`, under a new Unreleased heading:

```markdown
### Added
- Shared consumer-VPN egress policy: permanent bans are capped at a ladder-max
  temp on known shared egress (Cloudflare WARP ships by default), which also
  keeps those addresses off the swarm and out of AbuseIPDB. New
  `swatter shared-egress-audit [--fix]` sweeps perms already on the books.

### Changed
- **`SHARED_EGRESS_ENABLE` defaults to `true`**, so upgrading changes behavior
  without opt-in: existing permanent bans are untouched, but new ones can no
  longer be placed on the shipped WARP range. Set it to `false` to keep the old
  behavior. `import-bans` now skips shared-egress addresses.
```

- [ ] **Step 5: Verify the packaging**

Run: `bash test/install_nocron_test.sh && bash test/config_defaults_test.sh && make test`
Expected: every suite `0 failed`.

- [ ] **Step 6: Commit**

```bash
git add install/install.sh config/swatter.example.conf docs/RUNBOOK.md CHANGELOG.md
git commit -m "docs: package and document the shared-egress cap

Install follows the hosting-asns.txt pattern (if-absent + always ship
.example) so upgrades neither clobber operator edits nor withhold updates.
RUNBOOK states plainly that this is not an allowlist, and records the accepted
residual risk."
```

---

### Task 6: Pre-merge review gate

- [ ] **Step 1: Full suite**

Run: `make test`
Expected: every suite `0 failed`. Do not proceed otherwise.

- [ ] **Step 2: Adversarial review of the implementation**

The spec was reviewed; the code has not been. Per the developer-wide rule, run
`/grok` over the branch diff before merging:

```bash
git diff main...feat/shared-egress-cap
```

Focus the brief on: whether the veto really covers every path in practice,
whether `audit_action` handling is right for all three leg labels, whether
`--fix` can strand state mid-run, and whether the `/0` guard can be bypassed.

Fold blockers; then re-run `make test`.

- [ ] **Step 3: Merge**

```bash
git checkout main && git merge --ff-only feat/shared-egress-cap
git push origin main   # dual-pushes GitHub + GitLab
git branch -d feat/shared-egress-cap
```

---

### Task 7: Deploy and the operational fallout (OPERATOR-RUN)

**This task changes production state. It is the operator's to run**, not an
agent's, unless full auth is granted for the session.

- [ ] **Step 1: Release and deploy**

`make release V=<next>` then surgical-scp `bin/swatter` + `lib/{asn,common,score}.sh`
to `/usr/local/{bin,lib/swatter}`, keeping `.bak-<sha>-<stamp>` copies alongside.
**Never** `install.sh remote` (it clobbers the cron timing fix and rewrites the
origin-lock csfpre hook). Then install the two new config files by hand and run
`swatter test-config`.

- [ ] **Step 2: Verify the cap is live**

```bash
swatter test-config          # expect the shared-egress lines
swatter shared-egress-audit  # read-only; expect the 9 live WARP perms
```

- [ ] **Step 3: Sweep the 9 live WARP perms**

```bash
swatter shared-egress-audit --fix
swatter list perm | grep '^104\.28\.' || echo "clean"
```

- [ ] **Step 4: Undo the 2026-08-11 over-remediation**

The 7 IPs cleared during the unfreeze (4 WARP + 3 AS206092) were unblocked with
`--perm-allow`, so they are permanent **never-blocks** today — the same hazard at
smaller scale. With the cap live they no longer need the exemption. Remove those
7 entries from `/etc/swatter/allow.cidr` and their `csf.allow` lines, then
confirm with `swatter shared-egress-audit` that they are capped rather than
exempt.

- [ ] **Step 5: Then, and only then, flip the AbuseIPDB arm**

This whole plan exists because `ABUSEIPDB_REPORT` reports new perms
irreversibly and WARP was actively producing them. With the cap live:

```bash
sqlite3 /var/lib/swatter/swatter.db "SELECT COUNT(*) FROM pending_blocks WHERE action='perm';"  # expect 0
# then set ABUSEIPDB_REPORT="true" in /etc/swatter/swatter.conf
```

- [ ] **Step 6: Update the trackers**

Mark the WARP section in `TODO.md` done, note the deployed version in the
handoff, and record the outcome in memory.

---

## Self-Review

**Spec coverage.** §1 identification → Task 1. §1 `/0` guard → Task 1 steps 5, and tested. §1 CIDR-only defaults → Task 1 step 6. §1 IPv6 → covered by shipping no v6 range and documenting it (RUNBOOK, Task 5). §1 DNS residual + cache re-validation → Task 1 step 4 and RUNBOOK. §2 veto incl. `audit_action` → Task 2. §2 AbuseIPDB explicit guard → Task 2 step 4. §3 five perm paths → Tasks 2 and 3. §4 sweep, unblock-only, one lock, continue-on-partial, count gate, verify → Task 4. §5 packaging → Task 5. §6 test matrix → distributed across Tasks 1–4. Gate D interaction and rollback → RUNBOOK, Task 5. BL1 fallout → Task 7 step 4.

Two spec test-matrix rows are deliberately **not** implemented as automated tests, and are called out here rather than silently dropped: "second honeypot after TTL expiry still cannot perm" (identical assertion to the cap test — the veto is stateless, so expiry adds no new code path) and "AS13335 IP outside `104.28/16`" (documents scope only; with CIDR-only defaults there is no shipped AS13335 entry to exercise). Both are noted in the spec as scope documentation.

**Placeholder scan.** No TBD/TODO; every code step has real code; no "similar to Task N" references.

**Type consistency.** `swatter_is_shared_egress` echoes a label and returns 0/1 — used identically in Tasks 2, 3, 4. `SWATTER_RUN_SHARED_CAPS` defined in Task 2, asserted in Task 2's test only. `_SW_SHARED_CIDR_OK` defined and reset consistently in Task 1's test and Task 2's test. Config names identical across Tasks 1, 3, 4, 5.
