# Recidivism Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Swatter's existing temp→perm recidivism ladder correct, safe to widen, and self-explanatory — then widen its counting window on cds1 behind real preview, rollback, and alerting controls.

**Architecture:** The ladder already exists (`lib/score.sh:500`, `prior + 1 >= REPEAT_N`) and is already channel-independent. No new escalation mechanism is built. Phase 1 fixes a live counting bug; Phase 2 makes the knobs safe and the decisions legible; Phase 3 builds the three controls that gate an irreversible config change; Phase 4 is the operator rollout. Full rationale and evidence: `docs/superpowers/specs/2026-07-24-recidivism-escalation-design.md`.

**Tech Stack:** Bash 4+ (`set -uo pipefail`, **no `-e`**), sqlite3, gawk, jq (optional — every jq path must degrade), curl. No new dependencies.

## Global Constraints

- **House shell convention:** `set -uo pipefail` without `-e`. A failing command does **not** abort the run. Every helper must therefore return a usable value on failure rather than relying on the shell to stop.
- **jq is optional.** `SWATTER_HAVE_JQ` gates it. Any jq path needs a fallback that keeps the run correct.
- **Two stores.** `STORE=sqlite` (production) and `STORE=flatfile`. Every store function change must be made in both branches.
- **Report mode must never mutate.** `dry_run=1` rows must not drive real bans; `swatter_store_plane_set` / `pending_set` are called only under `SWATTER_MODE=enforce`.
- **Shipped default `REPEAT_WINDOW_DAYS` stays `7`.** The 30-day value is applied to cds1's `/etc/swatter/swatter.conf` in Phase 4 only. `REPEAT_N` stays `3`.
- **Test idiom:** `bash test/<name>_test.sh`, sourcing libs directly. `check <name> <got> <want>` increments `PASS`/`FAIL`. Last line must be `Total: N passed, M failed`, and the script exits non-zero on failure (`[[ "$FAIL" -eq 0 ]]`). sqlite-dependent suites skip cleanly: `command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }`.
- **`make test`** runs every `test/*_test.sh` and fails if any suite exits non-zero.
- **Commit email:** this repo is public; `git config user.email` is already the noreply address. Do not change it.
- **Never mutate Cloudflare zone state from this repo** (developer-wide rule) — Phase 3's rollback command uses only existing Swatter unblock paths.

## File Structure

| File | Responsibility | Phase |
|---|---|---|
| `lib/store_sqlite.sh` | `swatter_store_recent_temp_count` gains the unblock watermark (both store branches) | 1 |
| `test/recidivism_test.sh` | **New.** All counting semantics: window, `dry_run`, action filtering, watermark, flatfile parity | 1, 2 |
| `lib/common.sh` | Knob validation at the end of `swatter_load_config`; new alert/gate defaults | 2, 3 |
| `lib/score.sh` | `_swatter_ev_stamp` helper; recidivism reason + evidence stamp; CRITICAL-single gate; run-scoped perm counter + end-of-scan tripwire | 2, 3 |
| `lib/report.sh` | Digest recidivism count | 2 |
| `bin/swatter` | `escalate-preview` and `rollback-ladder` subcommands | 3 |
| `test/config_defaults_test.sh` | Pin escalation-knob defaults and validation behavior | 2 |
| `test/report_test.sh` | Digest recidivism line | 2 |
| `test/escalate_preview_test.sh` | **New.** Preview correctness and read-only guarantees | 3 |
| `test/rollback_ladder_test.sh` | **New.** Bulk rollback selection and failure tolerance | 3 |
| `test/perm_rate_alert_test.sh` | **New.** Threshold trip, ladder-only counting, burst non-suppression | 3 |
| `config/swatter.example.conf`, `README.md`, `TODO.md`, `CHANGELOG.md` | Documentation | 2, 3 |

---

# Phase 1 — PR 1: unblock must forget

Standalone bug fix. Ships and deploys before anything else.

### Task 1: Unblock watermark on the recidivism counter

**Files:**
- Modify: `lib/store_sqlite.sh:103-119` (`swatter_store_recent_temp_count`)
- Test: `test/recidivism_test.sh` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `swatter_store_recent_temp_count <ip>` → echoes an integer. Unchanged signature; changed semantics — temps at or before the IP's most recent `unblock` row no longer count.

**Background:** `swatter_store_unblock` (`lib/store_sqlite.sh:219-229`) clears `offenders.perm`, `plane_blocks`, and `pending_blocks`, but leaves the historical `temp` rows in `actions` — which is exactly what this counter reads. So an operator who unblocks a false positive leaves 2 temps behind, and the IP's next offense computes `prior + 1 = 3` and goes straight to permanent, skipping the ladder.

Only `cmd_unblock` (`bin/swatter:165`) writes an `unblock` row — verified: `swatter_cf_sweep_expired` deletes edge refs only, CSF/ipset expiry writes no ledger row, and `cmd_allow` / `cmd_import_bans` / swarm purge write none. So this cannot fail open.

- [ ] **Step 1: Write the failing test**

Create `test/recidivism_test.sh`:

```bash
#!/usr/bin/env bash
# test/recidivism_test.sh — temp->perm escalation counting semantics: the
# REPEAT_WINDOW_DAYS window, the dry_run filter, action filtering, and the
# unblock watermark (an operator correction must reset the ladder).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${ROOT}/lib/common.sh"
# shellcheck source=../lib/store_sqlite.sh
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-recid.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=30
REPEAT_N=3
swatter_store_init
db="$STATE_DIR/swatter.db"
NOW="$(swatter_now)"
DAY=86400

# seed <ip> <days_ago> <action> [dry_run] [channel]
# Direct INSERT so timestamps can be backdated deterministically.
seed() {
  local ip="$1" days="$2" action="$3" dry="${4:-0}" ch="${5:-csf}"
  sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
    VALUES('${ip}',$(( NOW - days*DAY )),'${action}','${ch}',3600,80,'seed',${dry});"
}

# --- the unblock watermark -------------------------------------------------
# 2 enforced temps, then an operator unblock, then nothing: the ladder resets,
# so the next offense must be temp #1 (count 0), not the 3rd strike.
seed 10.0.0.1 20 temp
seed 10.0.0.2 20 temp   # unrelated IP, must not interfere
seed 10.0.0.1 10 temp
seed 10.0.0.1  5 unblock
check watermark-resets     "$(swatter_store_recent_temp_count 10.0.0.1)" "0"

# A temp AFTER the unblock counts again.
seed 10.0.0.1 2 temp
check watermark-post-count "$(swatter_store_recent_temp_count 10.0.0.1)" "1"

# An unblock OLDER than the temps clears nothing.
seed 10.0.0.3 20 unblock
seed 10.0.0.3 10 temp
seed 10.0.0.3  5 temp
check watermark-old-unblock "$(swatter_store_recent_temp_count 10.0.0.3)" "2"

# No unblock row at all -> full in-window history counts.
check watermark-absent     "$(swatter_store_recent_temp_count 10.0.0.2)" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/recidivism_test.sh`
Expected: FAIL on `watermark-resets` (want `0`, got `2`) and `watermark-post-count` (want `1`, got `3`).

- [ ] **Step 3: Add the watermark to the sqlite branch**

In `lib/store_sqlite.sh`, replace the sqlite query in `swatter_store_recent_temp_count`. The new predicate is **AND-ed onto** the existing ones — it must not replace the window or the `dry_run=0` filter:

```bash
        _sqlq "SELECT COUNT(*) FROM actions
                WHERE ip='${sip}' AND action='temp' AND dry_run=0 AND ts>${since}
                  AND ts > (SELECT COALESCE(MAX(ts),0) FROM actions
                             WHERE ip='${sip}' AND action='unblock');"
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/recidivism_test.sh`
Expected: PASS, `Total: 5 passed, 0 failed`.

- [ ] **Step 5: Update the function's doc comment**

Replace the comment above `swatter_store_recent_temp_count` (`lib/store_sqlite.sh:99-102`):

```bash
# Count REAL temp blocks for an IP within the repeat window (used for
# escalation). Only enforced blocks (dry_run=0) count — a report-mode detection
# means "we watched and did nothing," so it must not drive a real permanent ban
# the moment enforce is switched on.
#
# Temps at or before the IP's most recent `unblock` are EXCLUDED. An operator
# who unblocks a false positive is correcting our decision; leaving those temps
# in the count meant the IP's next offense computed prior+1 >= REPEAT_N and went
# straight to perm, silently undoing the correction. Only cmd_unblock writes an
# `unblock` row (CF sweep/CSF expiry write none), so natural expiry never resets
# the ladder.
```

- [ ] **Step 6: Add the flatfile branch**

The flatfile branch is a single-pass temp-only scan; a correct port needs a per-IP unblock watermark resolved in `END`, because file order cannot be assumed to equal `MAX(ts)` when a test stubs `swatter_now`. Replace the `else` branch's awk:

```bash
        awk -v ip="$ip" -v since="$since" '
            # Exact IP match. index() not regex — an IP contains dots, which a
            # regex would treat as wildcards and over-match neighbouring IPs.
            index($0, "\"ip\":\"" ip "\"") == 0 { next }
            {
                ts = 0
                if (match($0, /"ts":[0-9]+/)) ts = substr($0, RSTART+5, RLENGTH-5) + 0
            }
            /"action":"unblock"/ { if (ts > ub) ub = ts; next }
            /"action":"temp"/ && /"dry_run":0/ { if (ts > since) { n++; t[n] = ts } }
            END { c = 0; for (i = 1; i <= n; i++) if (t[i] > ub) c++; print c + 0 }
        ' "$(_swatter_jsonl)"
```

- [ ] **Step 7: Add a flatfile-parity test**

Append to `test/recidivism_test.sh`, before the totals block:

```bash
# --- flatfile parity -------------------------------------------------------
# Same history, flatfile store: the watermark must behave identically.
(
  STORE=flatfile
  STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-recid-ff.XXXXXX")"
  jsonl="$(_swatter_jsonl)"
  : > "$jsonl"
  ff() { printf '{"ip":"%s","ts":%s,"action":"%s","channel":"csf","ttl":0,"score":80,"reason":"seed","dry_run":%s}\n' \
           "$1" "$(( NOW - $2*DAY ))" "$3" "${4:-0}" >> "$jsonl"; }
  ff 10.0.0.1 20 temp
  ff 10.0.0.1 10 temp
  ff 10.0.0.1  5 unblock
  ff 10.0.0.1  2 temp
  got="$(swatter_store_recent_temp_count 10.0.0.1)"
  rm -rf "$STATE_DIR"
  [[ "$got" == "1" ]] && exit 0 || { echo "FAIL flatfile-watermark: want='1' got='${got}'"; exit 1; }
) && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
```

- [ ] **Step 8: Run the full suite**

Run: `make test`
Expected: every suite passes. `recidivism_test.sh` reports `Total: 6 passed, 0 failed`. Confirm `plane_blocks_test.sh`, `persist_test.sh`, `fleet_test.sh`, and `score_test.sh` still pass — they exercise the store and the unblock path.

- [ ] **Step 9: Commit**

```bash
git add lib/store_sqlite.sh test/recidivism_test.sh
git commit -m "fix(escalation): unblock resets the recidivism ladder

swatter_store_unblock cleared offenders.perm, plane_blocks and
pending_blocks but left the historical temp rows in actions — the exact
rows swatter_store_recent_temp_count reads. An operator unblocking a
false positive therefore left 2 temps behind, and the IP's next offense
computed prior+1 >= REPEAT_N and went straight to permanent, silently
undoing the correction.

Count only temps newer than the IP's most recent unblock, in both the
sqlite and flatfile branches. Correct at any window length.

Verified not a fail-open: only cmd_unblock writes an unblock row. The CF
sweep deletes edge refs only, CSF/ipset expiry writes no ledger row, and
allow/import-bans/swarm-purge write none — so natural expiry can never
reset the ladder.

On cds1: 45 IPs have been manually unblocked, 10 carrying exactly 2 prior
enforced temps.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

# Phase 2 — PR 2a: safe knobs, legible decisions

Nothing here is irreversible. Repo default stays `REPEAT_WINDOW_DAYS=7`.

### Task 2: Validate the escalation knobs

**Files:**
- Modify: `lib/common.sh` (end of `swatter_load_config`, ~line 288-313)
- Test: `test/config_defaults_test.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: after `swatter_load_config` returns, `REPEAT_N` and `REPEAT_WINDOW_DAYS` are guaranteed positive integers within bounds.

**Background — this is the highest-priority item in the whole plan.** Both knobs land in bash arithmetic unvalidated, and the two failure modes are opposite:

| Knob | Bad value | Result |
|---|---|---|
| `REPEAT_WINDOW_DAYS` | `""` / `"abc"` | window becomes 0 days → count always 0 → escalation silently disabled (fail-safe) |
| **`REPEAT_N`** | **`""` / `"abc"`** | **`(( prior + 1 >= 0 ))` is true → every first offense is a PERMANENT BAN** |

Verified by execution. One typo in `swatter.conf` turns Swatter into a mass-perm-banning machine on a multi-tenant host that publishes to a fleet.

- [ ] **Step 1: Write the failing test**

Append to `test/config_defaults_test.sh`, before its totals block:

```bash
# --- escalation knob defaults + validation ---------------------------------
check repeat-n-default   "${REPEAT_N}" "3"
check repeat-window-def  "${REPEAT_WINDOW_DAYS}" "7"

# Validation runs at the END of swatter_load_config, after the conf is sourced,
# so an operator typo cannot bypass it. An empty REPEAT_N is the dangerous one:
# unvalidated it makes (( prior+1 >= REPEAT_N )) true on the FIRST offense, so
# every IP is permanently banned. Each case must fall back to the shipped value.
_vconf="$(mktemp "${TMPDIR:-/tmp}/swatter-vconf.XXXXXX")"
trap 'rm -f "$_vconf"' EXIT

vcheck() { # vcheck <name> <conf-line> <var> <want>
  local name="$1" line="$2" var="$3" want="$4"
  printf '%s\n' "$line" > "$_vconf"
  ( SWATTER_CONF="$_vconf"; swatter_load_config >/dev/null 2>&1
    printf '%s' "${!var}" ) > "${_vconf}.out"
  check "$name" "$(cat "${_vconf}.out")" "$want"
}

vcheck repeat-n-empty     'REPEAT_N=""'                REPEAT_N            "3"
vcheck repeat-n-alpha     'REPEAT_N="abc"'             REPEAT_N            "3"
vcheck repeat-n-zero      'REPEAT_N=0'                 REPEAT_N            "3"
vcheck repeat-n-huge      'REPEAT_N=999'               REPEAT_N            "3"
vcheck repeat-n-valid     'REPEAT_N=4'                 REPEAT_N            "4"
vcheck window-empty       'REPEAT_WINDOW_DAYS=""'      REPEAT_WINDOW_DAYS  "7"
vcheck window-suffix      'REPEAT_WINDOW_DAYS="30d"'   REPEAT_WINDOW_DAYS  "7"
vcheck window-over-cap    'REPEAT_WINDOW_DAYS=365'     REPEAT_WINDOW_DAYS  "7"
vcheck window-valid       'REPEAT_WINDOW_DAYS=30'      REPEAT_WINDOW_DAYS  "30"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/config_defaults_test.sh`
Expected: FAIL on `repeat-n-empty` (got empty, want `3`), `repeat-n-alpha`, `repeat-n-zero`, `repeat-n-huge`, `window-empty`, `window-suffix`, `window-over-cap`.

- [ ] **Step 3: Implement the validation**

In `lib/common.sh`, add immediately before the closing `}` of `swatter_load_config` (after the `BADPATHS_CONF` block):

> **The snippet below is OUT OF DATE — the shipped code in `lib/common.sh` is authoritative.** This
> version predates the octal fix: a leading-zero numeral like `"020"` passes `^[0-9]+$` but bash
> `(( ))` reads it as OCTAL (16), and `"089"`/`"099"` throw "value too great for base", aborting the
> bounds check with no `log_warn` and letting the raw string through. The shipped validator forces
> base 10 with `10#` *and* reassigns the canonical decimal value, so no downstream plain `(( ))` can
> re-parse the padded string. It also validates `REPEAT_N_CRITICAL_SINGLE`, `PERM_RATE_ALERT_PER_RUN`
> and `PERM_RATE_ALERT_PER_DAY`, and clamps `REPEAT_N_CRITICAL_SINGLE` up to `REPEAT_N` (that knob
> only ever raises the bar). Do not re-apply this snippet verbatim on a re-run of the plan.

```bash
    # Escalation knobs are interpolated straight into bash arithmetic
    # (lib/score.sh's `prior + 1 >= REPEAT_N`, lib/store_sqlite.sh's window
    # subtraction), where a malformed value fails SILENTLY and in opposite
    # directions: an empty REPEAT_WINDOW_DAYS yields a 0-day window (escalation
    # never fires — fail-safe), but an empty REPEAT_N makes (( 1 >= 0 )) true, so
    # EVERY first offense becomes a permanent ban. Validate here — the end of the
    # conf load — so an operator typo cannot bypass it, and both the sqlite and
    # flatfile counting paths are covered (they read the same globals).
    local _n
    _n="${REPEAT_N:-}"
    if ! [[ "$_n" =~ ^[0-9]+$ ]] || (( _n < 1 || _n > 20 )); then
        log_warn "REPEAT_N='${_n}' invalid (want integer 1-20); using 3"
        REPEAT_N=3
    fi
    _n="${REPEAT_WINDOW_DAYS:-}"
    if ! [[ "$_n" =~ ^[0-9]+$ ]] || (( _n < 1 || _n > 90 )); then
        log_warn "REPEAT_WINDOW_DAYS='${_n}' invalid (want integer 1-90); using 7"
        REPEAT_WINDOW_DAYS=7
    fi
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/config_defaults_test.sh`
Expected: PASS on all 11 new checks.

- [ ] **Step 5: Record the out-of-scope siblings**

Append to `TODO.md`:

```markdown
- [ ] Same silent-arithmetic hazard as the escalation knobs (validated 2026-07-24)
      exists on `SCORE_TEMP`, `MAX_BLOCKS_PER_RUN`, `WINDOW_SECONDS`, and
      `MIN_REQS`: an empty or non-numeric value degrades silently rather than
      erroring. `PERSIST_N` and `TTL_LADDER` already have fallbacks. Apply the
      same end-of-`swatter_load_config` validation.
```

- [ ] **Step 6: Run the full suite and commit**

```bash
make test
git add lib/common.sh test/config_defaults_test.sh TODO.md
git commit -m "fix(config): validate escalation knobs — empty REPEAT_N permed everything

REPEAT_N and REPEAT_WINDOW_DAYS are interpolated into bash arithmetic with
no validation, and fail silently in opposite directions. An empty or
non-numeric REPEAT_WINDOW_DAYS yields a 0-day window, so escalation never
fires — fail-safe. But an empty REPEAT_N makes (( prior + 1 >= REPEAT_N ))
evaluate (( 1 >= 0 )) — true on the FIRST offense — so a single typo in
swatter.conf permanently bans every IP the scanner sees, on a host that
publishes its perm bans to a fleet.

Validate both at the end of swatter_load_config, after the conf is sourced
so an operator cannot bypass it and before any lib reads the globals; this
covers the sqlite and flatfile paths equally. Out-of-range or malformed
values warn and fall back to the shipped defaults.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 3: `_swatter_ev_stamp` and the recidivism reason

**Files:**
- Modify: `lib/score.sh` (new helper near `_swatter_audit`; escalation branch at `:497-506`)
- Test: `test/recidivism_test.sh`

**Interfaces:**
- Consumes: `swatter_store_recent_temp_count` from Task 1.
- Produces: `_swatter_ev_stamp <ev_json> <key> <int_value>` → echoes JSON on stdout. Returns the **original `$ev` unchanged** on any failure. Never echoes empty. Ladder perms gain `reason` suffix `recidivism=<n>/<days>d` and `evidence.recidivism = <n>` (a JSON number).

**Background:** `_swatter_audit` interpolates evidence **raw** into hand-built JSONL (`lib/score.sh:76-78`). Because the house convention is `set -uo pipefail` **without `-e`**, a missing or failing helper does not abort — it returns empty, producing `"evidence":` with no value. That is malformed JSONL, which breaks jq in `report.sh` and `swatter why` (`bin/swatter:142-145`). The fallback must live **inside** the helper, following `backend_err` / `retry:1` (`lib/score.sh:202`, `:390`) — not `evidence.swarm`, which is constructed whole.

`evidence.decisive_rule` is deliberately **not** touched: it is a behavioral offense-type vocabulary mapped by `_RPT_RULE_LABELS` (`lib/report.sh:24-31`), and writing `recidivism` into it would corrupt the digest's "what are they doing" grouping.

- [ ] **Step 1: Write the failing test**

Append to `test/recidivism_test.sh`, before the totals block:

```bash
# --- _swatter_ev_stamp -----------------------------------------------------
# shellcheck source=../lib/score.sh
source "${ROOT}/lib/score.sh"
SWATTER_HAVE_JQ=0
command -v jq >/dev/null 2>&1 && SWATTER_HAVE_JQ=1

if (( SWATTER_HAVE_JQ )); then
  # Merges as a JSON NUMBER (not a string) into real scorer-shaped evidence.
  ev='{"sub":{"rate":10},"reqs":5,"decisive_rule":"scanner_profile"}'
  got="$(_swatter_ev_stamp "$ev" recidivism 3)"
  check stamp-number      "$(printf '%s' "$got" | jq -r '.recidivism')" "3"
  check stamp-is-number   "$(printf '%s' "$got" | jq -r '.recidivism|type')" "number"
  check stamp-keeps-rule  "$(printf '%s' "$got" | jq -r '.decisive_rule')" "scanner_profile"
  check stamp-valid-json  "$(printf '%s' "$got" | jq -e . >/dev/null 2>&1 && echo ok)" "ok"
  # Invalid input JSON must pass through untouched, never empty.
  check stamp-bad-json    "$(_swatter_ev_stamp 'not json' recidivism 3)" "not json"
  # Non-integer value refused; evidence returned unchanged.
  check stamp-bad-value   "$(_swatter_ev_stamp "$ev" recidivism "3.0")" "$ev"
  check stamp-empty-value "$(_swatter_ev_stamp "$ev" recidivism "")" "$ev"
fi
# Empty evidence must not produce empty output (that would corrupt the JSONL).
check stamp-empty-ev  "$(_swatter_ev_stamp "" recidivism 3)" "{}"
# No-jq path returns the original untouched.
check stamp-nojq      "$(SWATTER_HAVE_JQ=0 _swatter_ev_stamp '{"a":1}' recidivism 3)" '{"a":1}'
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/recidivism_test.sh`
Expected: FAIL — `_swatter_ev_stamp: command not found`, every stamp check empty.

- [ ] **Step 3: Implement the helper**

In `lib/score.sh`, insert immediately after `_swatter_audit`'s closing `}`:

```bash
# Merge one integer field into a scorer-built evidence JSON blob.
#
# Safety contract — this runs on the SUCCESS path, where a bad return is worse
# than on the failure path _swatter_apply_plane's backend_err merge models:
# _swatter_audit interpolates evidence RAW into hand-built JSONL, and the house
# convention is `set -uo pipefail` WITHOUT -e, so a failure here does not abort
# the run — it would emit `"evidence":` with no value, corrupting the record and
# breaking jq in report.sh / `swatter why`. Therefore: never echo empty, never
# die, and return the ORIGINAL evidence on any failure.
#   _swatter_ev_stamp <ev_json> <key> <int_value>  -> echoes JSON
_swatter_ev_stamp() {
    local ev="${1:-}" key="${2:-}" val="${3:-}"
    # Empty evidence would make `printf '' | jq` fail and the fallback echo
    # nothing; normalize to an empty object so the record stays well-formed.
    [[ -n "$ev" ]] || ev='{}'
    # Guard the value BEFORE --argjson: a non-integer would make jq fail (or, for
    # a bare word, parse as something unintended).
    [[ "$val" =~ ^[0-9]+$ ]] || { printf '%s' "$ev"; return 0; }
    [[ -n "$key" ]] || { printf '%s' "$ev"; return 0; }
    [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]] || { printf '%s' "$ev"; return 0; }
    # --argjson (not --arg) so the field lands as a JSON number. The fallback is
    # INSIDE the substitution so any jq failure still yields the original.
    printf '%s' "$ev" | jq -c --arg k "$key" --argjson n "$val" '. + {($k): $n}' 2>/dev/null \
        || printf '%s' "$ev"
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/recidivism_test.sh`
Expected: PASS on all stamp checks.

- [ ] **Step 5: Wire the escalation branch**

In `lib/score.sh`, in `swatter_scan`, replace the action decision (currently `if (( prior + 1 >= REPEAT_N )); then action="perm"`):

```bash
            local action ttl=0
            if (( prior + 1 >= REPEAT_N )); then
                action="perm"
                # Make the escalation self-explanatory: without this a ladder
                # perm's reason reads only `score=91 intel=...`, so neither the
                # digest nor `swatter why` can say WHY it went permanent.
                # decisive_rule is deliberately untouched — it is the behavioral
                # offense-type vocabulary the digest groups on (report.sh
                # _RPT_RULE_LABELS); recidivism is a different axis.
                reason="${reason} recidivism=$(( prior + 1 ))/${REPEAT_WINDOW_DAYS}d"
                ev="$(_swatter_ev_stamp "$ev" recidivism "$(( prior + 1 ))")"
            else
```

Leave the `else` body (temp + `CRITICAL_TTL_FLOOR`) unchanged.

- [ ] **Step 6: Verify the wiring**

Run: `bash -n lib/score.sh && bash test/scan_wire_test.sh && bash test/score_test.sh`
Expected: syntax clean, both suites pass.

Note `lib/block_csf.sh:17,48` truncates the firewall comment to 120 chars, so a long `intel=`/`asn=` label can push the suffix off the csf.deny comment. The ledger and decision log keep the full string — accepted, no action.

- [ ] **Step 7: Commit**

```bash
make test
git add lib/score.sh test/recidivism_test.sh
git commit -m "feat(escalation): ladder perms explain themselves

A recidivism perm's reason read only 'score=91 intel=...', so neither the
nightly digest nor 'swatter why' could say why the ban went permanent.

Stamp reason with 'recidivism=<n>/<days>d' and merge evidence.recidivism
as a JSON number via a new _swatter_ev_stamp helper.

The helper's contract matters: it runs on the SUCCESS path, and
_swatter_audit interpolates evidence raw into hand-built JSONL under
'set -uo pipefail' without -e. A failing merge would not abort the run —
it would emit '\"evidence\":' with no value and corrupt the record, breaking
jq in report.sh and 'swatter why'. So the fallback lives inside the helper:
empty evidence normalizes to {}, a non-integer value is refused, and any jq
failure returns the original evidence unchanged. Never empty, never fatal.

evidence.decisive_rule is deliberately untouched — it is the behavioral
offense-type vocabulary report.sh groups the digest on.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 4: Digest recidivism count

**Files:**
- Modify: `lib/report.sh` (counts block ~`:160-176`, and the summary text)
- Test: `test/report_test.sh`

**Interfaces:**
- Consumes: `evidence.recidivism` from Task 3.
- Produces: `RPT_RECID` — count of in-window decisions carrying `evidence.recidivism`.

**Background:** match on the **evidence field**, not `.reason` — the same idiom as `evidence.swarm` (`lib/report.sh:586-588`), which is matched that way precisely because `.reason` is prefixed on some paths. This is observability; the safety control is Task 7.

- [ ] **Step 1: Write the failing test**

Append to `test/report_test.sh`, before its totals block:

```bash
# --- recidivism count in the digest ----------------------------------------
# Matches evidence.recidivism (stamped on every ladder perm), NOT .reason.
recid_log="$(mktemp "${TMPDIR:-/tmp}/swatter-recid-log.XXXXXX")"
now_r="$(swatter_now)"
printf '{"ts":%s,"ip":"1.2.3.4","score":91,"action":"perm","channel":"csf","ttl":0,"reason":"score=91 recidivism=3/30d","reputation":0,"mode":"enforce","evidence":{"recidivism":3}}\n' "$now_r" >> "$recid_log"
printf '{"ts":%s,"ip":"1.2.3.5","score":80,"action":"temp","channel":"csf","ttl":3600,"reason":"score=80","reputation":0,"mode":"enforce","evidence":{}}\n' "$now_r" >> "$recid_log"
if [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
  got_r="$(jq -c "select(.ts >= $(( now_r - 3600 )) and (.evidence.recidivism != null))" "$recid_log" | grep -c . )"
  check digest-recid-count "$got_r" "1"
fi
rm -f "$recid_log"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/report_test.sh`
Expected: this assertion passes standalone (it tests the jq expression), but the digest itself does not yet report the number — verified in Step 4.

- [ ] **Step 3: Add the count and surface it**

In `lib/report.sh`, beside the other `RPT_*` counts (~`:160-166`):

```bash
    # Ladder perms in-window. Match evidence.recidivism (stamped on every ladder
    # perm by lib/score.sh), NOT .reason — same rule as evidence.swarm below.
    RPT_RECID=$(printf '%s\n' "$recs" | jq -rc 'select(.evidence.recidivism != null)' | grep -c . || true)
```

Then, in the actions-summary body where `RPT_PERM` is rendered, append a clause shown only when non-zero:

```bash
    (( ${RPT_RECID:-0} > 0 )) && printf '  %s of those permanent block(s) came from repeat offenses (recidivism ladder).\n' "${RPT_RECID}"
```

- [ ] **Step 4: Verify the digest renders it**

Run: `bash test/report_test.sh`
Expected: PASS. Then eyeball a render against a seeded log:
Run: `SWATTER_CONF=/dev/null bash -c 'source lib/common.sh; source lib/report.sh; ...'` — or simpler, confirm on cds1 read-only in Phase 4 step 8.

- [ ] **Step 5: Commit**

```bash
make test
git add lib/report.sh test/report_test.sh
git commit -m "feat(report): count recidivism-driven perms in the nightly digest

Matches evidence.recidivism rather than .reason, the same idiom used for
evidence.swarm — .reason is prefixed on some paths and is not a reliable
key. Rendered only when non-zero so a quiet window stays quiet.

Observability, not a safety control; the perm-rate tripwire is separate.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

# Phase 3 — PR 2b: the controls that gate the flip

None of these may be skipped before Phase 4. Each replaces something an earlier draft assumed prose could do.

### Task 5: `swatter escalate-preview`

**Files:**
- Modify: `bin/swatter` (new subcommand + usage block ~`:18-30`)
- Test: `test/escalate_preview_test.sh` (create)

**Interfaces:**
- Consumes: `swatter_store_recent_temp_count` semantics from Task 1.
- Produces: `swatter escalate-preview [--window N]` → TSV on stdout, `ip<TAB>temps_in_window<TAB>last_temp_iso`, sorted by count descending. Exit 0 even when empty.

**Background — why not a report-mode canary.** An earlier draft proposed flipping cds1 to report mode for one cycle to confirm the would-be escalations. That cannot work: ingest is byte-cursor based (`lib/ingest.sh:5-11`), so one `*/5` cycle scores ~5 minutes of *new* log bytes, not history. At cds1's measured 5.37 escalation events/day, one cycle expects ~0.02 events — near-zero results would read as "clean." Worse, report mode still advances the cursors (`lib/score.sh:421`), so canary-window attacks are consumed and never re-scored after the flip, and new attackers go unblocked meanwhile.

This command is the real gate: it reads the ledger directly, ingests nothing, advances no cursor, and changes no mode.

- [ ] **Step 1: Write the failing test**

Create `test/escalate_preview_test.sh`:

```bash
#!/usr/bin/env bash
# test/escalate_preview_test.sh — offline escalation preview: correct candidate
# selection, and the read-only guarantees that make it safe to run on prod.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-prev.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_N=3; REPEAT_WINDOW_DAYS=30
swatter_store_init
db="$STATE_DIR/swatter.db"; NOW="$(swatter_now)"; DAY=86400
seed() { sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('$1',$(( NOW - $2*DAY )),'$3','csf',3600,80,'seed',${4:-0});"; }

# Escalates at 30d (3 temps in-window), not at 7d.
seed 10.1.0.1 25 temp; seed 10.1.0.1 12 temp; seed 10.1.0.1 1 temp
# Only 2 in-window -> not a candidate.
seed 10.1.0.2 25 temp; seed 10.1.0.2 1 temp
# 3 temps but one is dry_run=1 -> not a candidate.
seed 10.1.0.3 25 temp; seed 10.1.0.3 12 temp 1; seed 10.1.0.3 1 temp
# 3 temps but unblocked after the first two -> watermark drops them.
seed 10.1.0.4 25 temp; seed 10.1.0.4 20 temp; seed 10.1.0.4 15 unblock; seed 10.1.0.4 1 temp

out="$(REPEAT_WINDOW_DAYS=30 swatter_escalate_preview 30)"
check prev-includes    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="10.1.0.1"{print $2}')" "3"
check prev-excl-two    "$(printf '%s\n' "$out" | grep -c '^10\.1\.0\.2' || true)" "0"
check prev-excl-dryrun "$(printf '%s\n' "$out" | grep -c '^10\.1\.0\.3' || true)" "0"
check prev-excl-unblk  "$(printf '%s\n' "$out" | grep -c '^10\.1\.0\.4' || true)" "0"
check prev-7d-empty    "$(REPEAT_WINDOW_DAYS=7 swatter_escalate_preview 7 | grep -c . || true)" "0"

# Read-only: no cursor file created, ledger row count unchanged.
before="$(sqlite3 "$db" 'SELECT COUNT(*) FROM actions;')"
swatter_escalate_preview 30 >/dev/null
after="$(sqlite3 "$db" 'SELECT COUNT(*) FROM actions;')"
check prev-readonly-rows "$after" "$before"
check prev-no-cursor     "$([[ -e "${STATE_DIR}/cursors.tsv" ]] && echo yes || echo no)" "no"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/escalate_preview_test.sh`
Expected: FAIL — `swatter_escalate_preview: command not found`.

- [ ] **Step 3: Implement the query function**

In `lib/store_sqlite.sh`, after `swatter_store_recent_temp_count`:

```bash
# Offline escalation preview: which IPs would reach REPEAT_N temps inside a
# candidate window, computed from the LEDGER ONLY. No ingest, no cursor
# advance, no mode change — safe to run against a live production host, which
# is the whole point (a report-mode "canary" cannot see history, because ingest
# is byte-cursor based and only ever reads new log bytes).
# Echoes: ip \t temps_in_window \t last_temp_iso
#   swatter_escalate_preview [window_days]
swatter_escalate_preview() {
    local win="${1:-${REPEAT_WINDOW_DAYS}}"
    [[ "$win" =~ ^[0-9]+$ ]] && (( win >= 1 )) || win="${REPEAT_WINDOW_DAYS}"
    local n="${REPEAT_N}"
    [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 )) || n=3
    [[ "${STORE}" == "sqlite" ]] || { log_warn "escalate-preview requires STORE=sqlite"; return 1; }
    local since; since=$(( $(swatter_now) - win*86400 ))
    # Mirrors swatter_store_recent_temp_count exactly: enforced temps only,
    # inside the window, after any operator unblock.
    _sqlq "SELECT a.ip, COUNT(*) AS c, datetime(MAX(a.ts),'unixepoch')
             FROM actions a
            WHERE a.action='temp' AND a.dry_run=0 AND a.ts > ${since}
              AND a.ts > (SELECT COALESCE(MAX(u.ts),0) FROM actions u
                           WHERE u.ip = a.ip AND u.action='unblock')
            GROUP BY a.ip
           HAVING c >= ${n}
            ORDER BY c DESC, a.ip;" | tr '|' '\t'
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/escalate_preview_test.sh`
Expected: PASS, `Total: 7 passed, 0 failed`.

- [ ] **Step 5: Wire the subcommand**

In `bin/swatter`, add to the usage block:

```
#   swatter escalate-preview [--window N]  who WOULD escalate (read-only)
```

and the dispatcher case:

```bash
cmd_escalate_preview() {
    local win="${REPEAT_WINDOW_DAYS}"
    while (( $# )); do
        case "$1" in
            --window) win="${2:-}"; shift 2 ;;
            *) die "usage: swatter escalate-preview [--window N]" ;;
        esac
    done
    [[ "$win" =~ ^[0-9]+$ ]] || die "escalate-preview: --window must be an integer"
    # Read-only: no state lock needed, and deliberately not taken so this can be
    # run while the */5 scan is mid-flight.
    printf 'ip\ttemps\tlast_temp_utc\n'
    swatter_escalate_preview "$win"
}
```

Register `escalate-preview) shift; cmd_escalate_preview "$@" ;;` in the main `case`.

- [ ] **Step 6: Smoke-test the CLI**

Run: `bash -n bin/swatter && bash test/cli_test.sh`
Expected: syntax clean, CLI suite passes (it asserts usage/dispatch coverage).

- [ ] **Step 7: Commit**

```bash
make test
git add bin/swatter lib/store_sqlite.sh test/escalate_preview_test.sh
git commit -m "feat(cli): swatter escalate-preview — offline candidate list

Answers 'who would go permanent if the window were N days' from the ledger
alone: no ingest, no cursor advance, no mode change, no state lock. Safe to
run against a live enforcing host.

This replaces a report-mode canary, which cannot work: ingest is byte-cursor
based, so one */5 cycle scores ~5 minutes of new log bytes rather than
history. At the measured 5.37 escalation events/day on cds1 a single cycle
expects ~0.02 events, so a near-empty result would read as 'clean'. Report
mode also still advances the cursors, so traffic seen during such a canary
would be consumed and never re-scored after the flip.

Selection mirrors swatter_store_recent_temp_count exactly — enforced temps
only, in-window, after any operator unblock.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 6: `swatter rollback-ladder`

**Files:**
- Modify: `bin/swatter` (new subcommand + usage)
- Test: `test/rollback_ladder_test.sh` (create)

**Interfaces:**
- Consumes: `evidence.recidivism` (Task 3) — but selects from **sqlite**, matching `reason LIKE '%recidivism=%'`.
- Produces: `swatter rollback-ladder --since <epoch|iso> [--dry-run]` → unblocks each ladder perm placed since that time, prints a per-IP result and a summary. Exit 0 if all succeeded, 1 if any failed.

**Background — why a README procedure is not enough.** Four verified problems with "jq the decision log and loop `swatter unblock`": `decisions.jsonl` rotates weekly **with compress** (`install/swatter.logrotate`), so a timestamp query over the live file silently misses everything past a rotation; `cmd_unblock` takes `swatter_with_state_lock` with a **30-second** wait (`lib/common.sh:584`) and dies on timeout, so a 67-iteration loop contends with the `*/5` cron and aborts mid-list; a backend failure still clears the ledger before exiting non-zero (`bin/swatter:160-165`), so "the script failed" can mean state is half-applied; and none of it is executable at 2am.

The hub keeps published perms for `SWARM_TTL=604800` (7 days) with only host-wide `purgeHost` — **no per-IP retract**. The command must say so out loud.

- [ ] **Step 1: Write the failing test**

Create `test/rollback_ladder_test.sh`:

```bash
#!/usr/bin/env bash
# test/rollback_ladder_test.sh — bulk rollback of ladder perms: selection from
# sqlite (not the rotated log), single lock acquisition, and tolerance of a
# per-IP backend failure.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/store_sqlite.sh"

command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

STORE=sqlite
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rb.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_N=3; REPEAT_WINDOW_DAYS=30
swatter_store_init
db="$STATE_DIR/swatter.db"; NOW="$(swatter_now)"; DAY=86400
seedp() { sqlite3 "$db" "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
  VALUES('$1',$(( NOW - $2*DAY )),'perm','csf',0,91,'$3',0);"; }

# Two ladder perms inside the window, one outside, one non-ladder perm.
seedp 10.2.0.1 2 'score=91 recidivism=3/30d'
seedp 10.2.0.2 1 'score=95 recidivism=4/30d'
seedp 10.2.0.3 9 'score=91 recidivism=3/30d'   # older than --since
seedp 10.2.0.4 1 'honeypot score=100'          # not a ladder perm

sel="$(swatter_ladder_perms_since $(( NOW - 5*DAY )))"
check rb-selects-two   "$(printf '%s\n' "$sel" | grep -c . )" "2"
check rb-has-1         "$(printf '%s\n' "$sel" | grep -c '^10\.2\.0\.1$')" "1"
check rb-excl-old      "$(printf '%s\n' "$sel" | grep -c '^10\.2\.0\.3$' || true)" "0"
check rb-excl-honeypot "$(printf '%s\n' "$sel" | grep -c '^10\.2\.0\.4$' || true)" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/rollback_ladder_test.sh`
Expected: FAIL — `swatter_ladder_perms_since: command not found`.

- [ ] **Step 3: Implement the selector**

In `lib/store_sqlite.sh`, after `swatter_escalate_preview`:

```bash
# IPs whose most recent enforced PERM since <ts> came from the recidivism ladder.
# Selects from the sqlite ledger, NOT decisions.jsonl: the decision log rotates
# weekly with compress (install/swatter.logrotate), so a timestamp scan of the
# live file silently misses any incident spanning a rotation boundary.
#   swatter_ladder_perms_since <epoch>
swatter_ladder_perms_since() {
    local since="${1:-0}"
    [[ "$since" =~ ^[0-9]+$ ]] || return 1
    [[ "${STORE}" == "sqlite" ]] || { log_warn "rollback-ladder requires STORE=sqlite"; return 1; }
    _sqlq "SELECT DISTINCT ip FROM actions
            WHERE action='perm' AND dry_run=0 AND ts > ${since}
              AND reason LIKE '%recidivism=%'
            ORDER BY ip;"
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `bash test/rollback_ladder_test.sh`
Expected: PASS, `Total: 4 passed, 0 failed`.

- [ ] **Step 5: Implement the subcommand**

In `bin/swatter`, usage line:

```
#   swatter rollback-ladder --since <epoch|iso> [--dry-run]   undo ladder perms
```

and:

```bash
cmd_rollback_ladder() {
    local since="" dry=0
    while (( $# )); do
        case "$1" in
            --since)   since="${2:-}"; shift 2 ;;
            --dry-run) dry=1; shift ;;
            *) die "usage: swatter rollback-ladder --since <epoch|iso> [--dry-run]" ;;
        esac
    done
    [[ -n "$since" ]] || die "usage: swatter rollback-ladder --since <epoch|iso> [--dry-run]"
    if ! [[ "$since" =~ ^[0-9]+$ ]]; then
        since="$(date -u -d "$since" +%s 2>/dev/null)" || die "rollback-ladder: unparseable --since"
    fi
    local ips; ips="$(swatter_ladder_perms_since "$since")" || die "rollback-ladder: ledger query failed"
    if [[ -z "$ips" ]]; then echo "no ladder perms since ${since}"; return 0; fi
    local total=0 ok=0 bad=0
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        total=$(( total + 1 ))
        if (( dry )); then echo "would unblock ${ip}"; ok=$(( ok + 1 )); continue; fi
        # Unblock in-process under ONE lock acquisition (see below) and keep going
        # on a per-IP backend failure — a partial undo that stops halfway is worse
        # than one that finishes and reports which IPs need a retry.
        if swatter_block_direct_unblock "$ip" && swatter_cf_unblock "$ip"; then
            swatter_store_unblock "$ip"; ok=$(( ok + 1 ))
        else
            swatter_store_unblock "$ip"; bad=$(( bad + 1 ))
            echo "PARTIAL ${ip}: a backend failed; ledger cleared, firewall may still hold" >&2
        fi
    done <<< "$ips"
    printf 'rollback-ladder: %d selected, %d unblocked, %d partial\n' "$total" "$ok" "$bad"
    # The swarm gap is real and must not be silent.
    if [[ "${SWARM_ENABLE:-false}" == "true" ]]; then
        cat >&2 <<'EOS'
NOTE: perm bans already published to the swarm hub are NOT retracted by this
      command. The hub has only a host-wide purge and a 7-day TTL, so peers may
      act on these IPs until the entries expire. Run `swatter swarm purge` only
      if you intend to drop ALL of this host's contributions.
EOS
    fi
    (( bad == 0 ))
}
```

Register `rollback-ladder) shift; swatter_with_state_lock 120 cmd_rollback_ladder "$@" ;;` — **one** lock acquisition for the whole run, with a longer wait than `unblock`'s 30s default, so the loop cannot abort mid-list against the `*/5` cron.

> **That dispatch line is NON-FUNCTIONAL as written — see the shipped `bin/swatter`.** Two defects:
> `swatter_with_state_lock` only *gates* entry (it acquires the lock and returns; it does not run a
> command under it, unlike a `flock -c`-style wrapper), so `cmd_rollback_ladder` would never execute
> and the subcommand would silently do nothing; and `main()` has already consumed the subcommand
> (`local sub="${1:-}"; shift`), so the extra `shift` eats the first real argument. The shipped code
> dispatches plainly — `rollback-ladder) cmd_rollback_ladder "$@" ;;` — and takes the lock *inside*
> the command, once, before any work, skipping it for `--dry-run`. Do not re-apply this line.

- [ ] **Step 6: Verify and commit**

```bash
bash -n bin/swatter && make test
git add bin/swatter lib/store_sqlite.sh test/rollback_ladder_test.sh
git commit -m "feat(cli): swatter rollback-ladder — real bulk undo for ladder perms

A README procedure ('jq decisions.jsonl and loop swatter unblock') is not a
recovery path: the decision log rotates weekly with compress so a timestamp
scan misses anything past a boundary; cmd_unblock dies on a 30s lock wait and
would abort a 67-IP loop mid-list against the */5 cron; and a backend failure
still clears the ledger before exiting non-zero, so a 'failed' script can
leave state half-applied.

Select from sqlite, take the state lock ONCE for the whole run with a 120s
wait, continue past per-IP backend failures, and report selected/unblocked/
partial with a non-zero exit if any were partial.

Prints the swarm gap explicitly: published perms cannot be retracted per-IP —
the hub has only host-wide purge and a 7-day TTL.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 7: Perm-rate tripwire

**Files:**
- Modify: `lib/common.sh` (defaults), `lib/score.sh` (`_swatter_apply_plane` counter, end of `swatter_scan`)
- Test: `test/perm_rate_alert_test.sh` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `SWATTER_RUN_PERMS` (run-scoped integer, ladder perms only); a `swatter_notify` call keyed `perm_rate.<epoch_hour>`.

**Background:** `_report_grade` **explicitly** keeps blocks GREEN (`lib/report.sh:427-428`) — "they're Swatter working, not a problem" — and SMS keys on grade, so a runaway wave surfaces only as a bigger number in an email that still reads All Clear, up to 24h late. The circuit breaker keys on `_SW_TOTAL_BLOCKS`, not perms.

Critical detail: `_notify_ratelimited` (`lib/notify.sh:14-24`) writes its marker **before** channels send and suppresses for `ALERT_REPEAT_TTL` — default **21600s = 6 hours** (`lib/common.sh:68`). A static key would fire once and go silent for six hours *while the backlog continues*, and the marker is set even if every channel fails. Hence the hour-bucketed key.

- [ ] **Step 1: Write the failing test**

Create `test/perm_rate_alert_test.sh`:

```bash
#!/usr/bin/env bash
# test/perm_rate_alert_test.sh — the perm-rate tripwire: ladder-only counting,
# threshold trip, and an alert key that cannot hide a multi-hour incident.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

check perm-alert-run-default "${PERM_RATE_ALERT_PER_RUN}" "5"
check perm-alert-day-default "${PERM_RATE_ALERT_PER_DAY}" "15"

# The alert key must vary by hour. A static key would be suppressed by
# _notify_ratelimited for ALERT_REPEAT_TTL (6h by default), silencing exactly
# the multi-hour burst the tripwire exists to catch.
k1="$(_swatter_perm_rate_key 1000000000)"
k2="$(_swatter_perm_rate_key 1000003600)"   # +1h
k3="$(_swatter_perm_rate_key 1000000060)"   # +1m, same hour
check perm-key-differs-hour "$([[ "$k1" != "$k2" ]] && echo yes || echo no)" "yes"
check perm-key-stable-hour  "$([[ "$k1" == "$k3" ]] && echo yes || echo no)" "yes"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/perm_rate_alert_test.sh`
Expected: FAIL — unbound `PERM_RATE_ALERT_PER_RUN`, `_swatter_perm_rate_key` not found.

- [ ] **Step 3: Add the defaults**

In `lib/common.sh`, beside the other alert defaults:

```bash
# Perm-rate tripwire. The nightly digest is NOT a safety control: _report_grade
# deliberately keeps blocks GREEN, so a runaway escalation wave would surface
# only as a larger number in a mail that still reads All Clear, up to 24h late.
# Steady-state net-new ladder perms on a busy shared host run ~1-2/day, so these
# trip well before a wave but above normal noise.
: "${PERM_RATE_ALERT_PER_RUN:=5}"
: "${PERM_RATE_ALERT_PER_DAY:=15}"
```

- [ ] **Step 4: Implement the key helper and the counter**

In `lib/score.sh`, above `_swatter_apply_plane`:

```bash
# Alert key for the perm-rate tripwire, bucketed by HOUR. _notify_ratelimited
# marks its key before channels send and suppresses for ALERT_REPEAT_TTL (6h by
# default), so a static key would fire once and then stay silent through exactly
# the multi-hour burst this exists to catch — and the marker is written even when
# every channel fails.
_swatter_perm_rate_key() { printf 'perm_rate.%s' "$(( ${1:-$(swatter_now)} / 3600 ))"; }
```

In `_swatter_apply_plane`'s success branch (`if (( did ))`), beside the existing counter bumps:

```bash
        # Ladder perms only: a dual-plane / plane-upgrade second leg carries a
        # distinct audit_action and would otherwise double-count one IP.
        [[ "$action" == "perm" && "$audit_action" == "$action" ]] \
            && SWATTER_RUN_PERMS=$(( ${SWATTER_RUN_PERMS:-0} + 1 ))
```

In `swatter_scan`, initialise beside the other run-scoped counters:

```bash
    _SW_TOTAL_BLOCKS=0; SWATTER_RUN_WATCHED=0; SWATTER_RUN_ACTED=0; SWATTER_RUN_BREAKER=0
    SWATTER_RUN_PERMS=0
```

and evaluate at the end, beside the circuit-breaker notify:

```bash
    # Perm-rate tripwire — same run that placed them, not the next digest.
    local _pday
    _pday="$(swatter_store_perm_count_since $(( $(swatter_now) - 86400 )) )"
    [[ "$_pday" =~ ^[0-9]+$ ]] || _pday=0
    if (( SWATTER_RUN_PERMS >= PERM_RATE_ALERT_PER_RUN || _pday >= PERM_RATE_ALERT_PER_DAY )); then
        swatter_notify "swatter perm-rate tripwire on $(hostname -s 2>/dev/null)" \
            "Placed ${SWATTER_RUN_PERMS} permanent block(s) this run; ${_pday} in the last 24h (thresholds ${PERM_RATE_ALERT_PER_RUN}/run, ${PERM_RATE_ALERT_PER_DAY}/day). Review: swatter escalate-preview; undo: swatter rollback-ladder --since <ts>." \
            "$(_swatter_perm_rate_key)"
    fi
```

In `lib/store_sqlite.sh`, add the rolling counter beside the other queries:

```bash
# Enforced perm decisions since <ts> — the durable rolling source for the
# perm-rate tripwire (decisions.jsonl rotates; the ledger does not).
swatter_store_perm_count_since() {
    local since="${1:-0}"
    [[ "$since" =~ ^[0-9]+$ ]] || { echo 0; return 0; }
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT COUNT(*) FROM actions WHERE action='perm' AND dry_run=0 AND ts>${since};"
    else
        echo 0
    fi
}
```

- [ ] **Step 5: Run the tests**

Run: `bash test/perm_rate_alert_test.sh && bash test/notify_test.sh && bash test/alerts_test.sh`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
make test
git add lib/common.sh lib/score.sh lib/store_sqlite.sh test/perm_rate_alert_test.sh
git commit -m "feat(alerts): perm-rate tripwire, fired on the run that places them

The nightly digest is not a safety control: _report_grade deliberately keeps
blocks GREEN ('Swatter working, not a problem') and SMS keys on grade, so a
runaway escalation wave would surface only as a bigger number in a mail that
still reads All Clear, up to 24h late. The circuit breaker keys on total
blocks, not perms.

Count ladder perms in _swatter_apply_plane's success branch (audit_action ==
action, so a dual-plane second leg cannot double-count one IP) and evaluate
per-run and rolling-24h thresholds at the end of swatter_scan.

The alert key is bucketed by hour on purpose: _notify_ratelimited marks its
key BEFORE channels send and suppresses for ALERT_REPEAT_TTL (6h default), so
a static key would fire once and then stay silent through exactly the
multi-hour burst this exists to catch — and the marker is written even if
every channel fails.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 8: CRITICAL-single gate

**Files:**
- Modify: `lib/common.sh` (default), `lib/score.sh` (escalation branch)
- Test: `test/recidivism_test.sh`

**Interfaces:**
- Consumes: `evidence.badpath_cat` from `lib/score.awk:282`; the escalation branch from Task 3.
- Produces: `REPEAT_N_CRITICAL_SINGLE` (default 4) — the threshold used when every in-window temp was a single CRITICAL probe.

**Background:** a CRITICAL bad-path hit **bypasses `MIN_REQS` and floors the score at 90** (`lib/score.awk:196`, `:240-241`), so one request to `/.env` is already a temp block. Without a gate, the escalation path is *three single probes over thirty days → permanent ban* — a very different risk model from "three scanner sessions in a week", and cheap for an attacker to drive against a third party's IP via an img-tag or CSRF. cds1's `monitoring.cidr` is empty and `allow.cidr` holds 4 entries, 3 of which are documented customer false positives, so the allowlist will not catch this.

- [ ] **Step 1: Write the failing test**

Append to `test/recidivism_test.sh`, before the totals block:

```bash
# --- CRITICAL-single gate --------------------------------------------------
# A one-request CRITICAL probe is already a temp (score.awk floors it at 90 and
# bypasses MIN_REQS). Three such singles must NOT be enough for a permanent ban;
# a fourth is. Multi-signal offenders still escalate at REPEAT_N.
check crit-gate-default "${REPEAT_N_CRITICAL_SINGLE}" "4"
check crit-all-raises  "$(_swatter_recid_threshold 1)" "4"   # all-critical -> 4
check crit-mixed-normal "$(_swatter_recid_threshold 0)" "3"  # any non-critical -> REPEAT_N
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/recidivism_test.sh`
Expected: FAIL — unbound `REPEAT_N_CRITICAL_SINGLE`, `_swatter_recid_threshold` not found.

- [ ] **Step 3: Add the default**

In `lib/common.sh`, beside `REPEAT_N`:

```bash
# A CRITICAL bad-path hit is a temp at ANY volume (score.awk floors it at 90 and
# bypasses MIN_REQS), so a chain of single probes would otherwise reach a
# permanent ban in REPEAT_N hits — cheap for an attacker to drive against a third
# party's IP. When EVERY in-window temp was such a single, require this many.
: "${REPEAT_N_CRITICAL_SINGLE:=4}"
```

- [ ] **Step 4: Implement the threshold selector**

In `lib/score.sh`, above `swatter_scan`:

```bash
# Escalation threshold for this IP. Normally REPEAT_N; raised when EVERY
# in-window temp was a single-request CRITICAL probe (see REPEAT_N_CRITICAL_SINGLE).
#   _swatter_recid_threshold <all_critical:0|1>
_swatter_recid_threshold() {
    if [[ "${1:-0}" == "1" ]]; then printf '%s' "${REPEAT_N_CRITICAL_SINGLE:-4}"
    else printf '%s' "${REPEAT_N}"; fi
}
```

In `lib/store_sqlite.sh`, add the evidence check:

```bash
# 1 when EVERY enforced in-window temp for this IP was a single-request CRITICAL
# probe (reason carries badpath CRITICAL and the request count is 1), else 0.
# Used to raise the escalation bar — see _swatter_recid_threshold.
swatter_store_temps_all_critical_single() {
    local ip="$1" since="$2"
    [[ "${STORE}" == "sqlite" ]] || { echo 0; return 0; }
    _store_ip_ok "$ip" || { echo 0; return 0; }
    local sip; sip="$(_sql_escape "$ip")"
    local tot crit
    tot="$(_sqlq "SELECT COUNT(*) FROM actions WHERE ip='${sip}' AND action='temp' AND dry_run=0 AND ts>${since};")"
    crit="$(_sqlq "SELECT COUNT(*) FROM actions WHERE ip='${sip}' AND action='temp' AND dry_run=0 AND ts>${since} AND reason LIKE '%critical_badpath%';")"
    [[ "$tot" =~ ^[0-9]+$ && "$crit" =~ ^[0-9]+$ ]] || { echo 0; return 0; }
    (( tot > 0 && tot == crit )) && echo 1 || echo 0
}
```

For this to work, the escalation reason must carry the decisive rule. In `swatter_scan`, extend the reason assembly (near `local reason="score=${folded}"`):

```bash
        local drule; drule="$(printf '%s' "$ev" | sed -n 's/.*"decisive_rule":"\([^"]*\)".*/\1/p')"
        [[ -n "$drule" ]] && reason="${reason} rule=${drule}"
```

**This changes the reason string for EVERY decision, not just perms** — it is the
one edit in this plan with blast radius outside the escalation branch. Before
implementing, grep the suite for assertions on exact reason text
(`grep -rn 'score=' test/ | grep -i reason`) and check `test/report_test.sh`,
`test/scan_wire_test.sh`, and `test/notify_test.sh`. Fix any that break by
matching a substring rather than the whole string. If a large number break,
report DONE_WITH_CONCERNS rather than rewriting many assertions — the
alternative is to read `decisive_rule` from `$ev` inside
`swatter_store_temps_all_critical_single`'s caller instead of persisting it to
`reason`, and that tradeoff is the controller's call.

- [ ] **Step 5: Wire the gate into the escalation branch**

Replace the Task 3 escalation condition:

```bash
            local allcrit thresh
            allcrit="$(swatter_store_temps_all_critical_single "$ip" "$(( $(swatter_now) - REPEAT_WINDOW_DAYS*86400 ))")"
            thresh="$(_swatter_recid_threshold "$allcrit")"
            local action ttl=0
            if (( prior + 1 >= thresh )); then
                action="perm"
                reason="${reason} recidivism=$(( prior + 1 ))/${REPEAT_WINDOW_DAYS}d"
                (( allcrit )) && reason="${reason} crit-single"
                ev="$(_swatter_ev_stamp "$ev" recidivism "$(( prior + 1 ))")"
            else
```

- [ ] **Step 6: Run the tests and commit**

```bash
bash test/recidivism_test.sh && make test
git add lib/common.sh lib/score.sh lib/store_sqlite.sh test/recidivism_test.sh
git commit -m "feat(escalation): raise the bar for all-CRITICAL single probes

A CRITICAL bad-path hit is a temp at any volume — score.awk floors it at 90
and bypasses MIN_REQS — so one request to /.env is already a block. Without a
gate the ladder reads 'three single probes over thirty days -> permanent ban',
which is a very different risk model from three scanner sessions in a week and
is cheap for an attacker to drive against a third party via an img-tag or CSRF.

When EVERY in-window temp was such a single, require REPEAT_N_CRITICAL_SINGLE
(4) instead of REPEAT_N (3). Multi-signal offenders are unaffected.

This matters because the allowlist will not catch the false positives: cds1's
monitoring.cidr is empty and allow.cidr holds 4 entries, 3 of which are
documented customer false positives.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 9: Documentation

**Files:**
- Modify: `config/swatter.example.conf`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: Document the new knobs in the sample conf**

In `config/swatter.example.conf`, in the escalation block:

```bash
REPEAT_N=3                              # this many temp blocks...
REPEAT_WINDOW_DAYS=7                    # ...within this many days -> permanent
                                        # Counting excludes report-mode (dry-run)
                                        # blocks, and resets at a manual
                                        # `swatter unblock` — an operator
                                        # correction clears the ladder.
REPEAT_N_CRITICAL_SINGLE=4              # ...but this many when EVERY in-window
                                        # temp was a single CRITICAL probe (one
                                        # /.env hit is already a temp, so a bare
                                        # REPEAT_N would perm on 3 single probes)
```

and beside the safety rails:

```bash
PERM_RATE_ALERT_PER_RUN=5               # notify above this many perms in one run
PERM_RATE_ALERT_PER_DAY=15              # ...or this many in a rolling 24h
```

- [ ] **Step 2: Document the operator-facing behavior in the README**

Add to the escalation section:

- `swatter unblock` (not `swatter allow`) is the correct way to clear a false positive: only `unblock` resets the recidivism ladder. `allow` prevents future blocks but leaves the temp history counting.
- **Config revert ≠ ban revert.** Lowering `REPEAT_WINDOW_DAYS` does not undo perms already placed; use `swatter rollback-ladder --since <ts>`.
- Perms already published to the swarm hub cannot be retracted per-IP (host-wide purge only, 7-day TTL).
- On a Cloudflare-fronted host running `CF_ACTION=managed_challenge`, a challenged IP keeps reaching the origin, so repeated `temp/cloudflare` decisions for the same IP within a day are expected and self-correcting — two re-temps drive it to perm.
- `swatter escalate-preview [--window N]` answers "who would escalate at N days" from the ledger, read-only and safe on a live host.

- [ ] **Step 3: Update the CHANGELOG and commit**

```bash
make test
git add config/swatter.example.conf README.md CHANGELOG.md
git commit -m "docs: recidivism escalation — knobs, operator paths, and the two 'not reverts'

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

# Phase 4 — Rollout (operator steps, cds1)

Not code. Do not start until Phases 1-3 are merged and deployed, and do not reorder.

- [ ] **Step 1: Deploy** Phases 1-3 to cds1. Confirm `swatter --version` and that `make test` passed in CI.
- [ ] **Step 2: Populate the allowlist.** `monitoring.cidr` is currently empty; add real monitoring, payment/webhook, and customer office ranges. **This is a precondition of the flip, not a recommendation** — with `allow.cidr` holding only 4 entries (3 of them documented customer false positives), it is the only thing standing between a legitimate NAT/VPN/office IP and a permanent ban.
- [ ] **Step 3: Preview.** `swatter escalate-preview --window 30 > /root/escalate-30d.tsv`. Read-only; safe while the `*/5` scan runs.
- [ ] **Step 4: Human review** of that list — ASN, PTR, customer mapping, DIRECT vs CF plane split. Anything that looks like NAT, CGNAT, a mobile carrier, a VPN exit, a crawler, or a customer goes into the allowlist **before** the flip. Expect ~67 net-new candidates (53 scoring ≥90).
- [ ] **Step 5: Freeze swarm publication.** Set `SWARM_PUBLISH=false` in `/etc/swatter/swatter.conf` for the first **14 days**, so a false ladder-perm stays on-box rather than propagating with a 7-day hub TTL and no per-IP retract. (Operator decision, 2026-07-24.)
- [ ] **Step 6: Flip.** Set `REPEAT_WINDOW_DAYS=30` in `/etc/swatter/swatter.conf`. **cds1 only** — the shipped repo default stays 7.
- [ ] **Step 7: Watch the tripwire** for the first 48h. Thresholds are 5/run and 15/day against a steady-state expectation of ~1-2/day net-new.
- [ ] **Step 8: Check the first nightly digest** for the recidivism count and confirm it matches the ledger.
- [ ] **Step 9: After 14 clean days**, re-enable `SWARM_PUBLISH=true`.

**Rollback at any point:** `swatter rollback-ladder --since <ts>` — never a config revert.

---

## Plan Self-Review

**Spec coverage.** Every spec section maps to a task: §3 → Task 1; §4.1 → Task 2; §4.4 → Task 3; §4.5 → Task 4; §4.3 → Task 6; §4.2 → Task 7; §4.7 → Task 8; §4.6 + §6 → Phase 4; §2 README note → Task 9. §1 and §7 are findings already committed in the spec, with no code deliverable. §5's test list is distributed across the tasks that own each behavior.

**Deliberate omissions, called out rather than hidden:**
- The spec's §5 asks for an assertion that the count query keeps window **and** `dry_run=0` **and** the watermark simultaneously. Task 1's `watermark-old-unblock` and `prev-excl-dryrun` cover the pairs; a combined three-way case should be added during Task 1 if the implementer sees an easy fixture for it.
- `escalate-preview` is sqlite-only (it warns and returns 1 on flatfile). cds1 is sqlite; a flatfile port is not worth the awk complexity for a preview tool.
- `swatter_store_perm_count_since` returns 0 on flatfile, so the per-day tripwire arm is sqlite-only. The per-run arm works on both.

**Type consistency.** `swatter_escalate_preview`, `swatter_ladder_perms_since`, `swatter_store_perm_count_since`, and `swatter_store_temps_all_critical_single` live in `lib/store_sqlite.sh` and are called from `bin/swatter` and `lib/score.sh`, both of which source it. `_swatter_ev_stamp`, `_swatter_perm_rate_key`, and `_swatter_recid_threshold` live in `lib/score.sh` and are used only there and in tests that source it. `SWATTER_RUN_PERMS` is initialised in `swatter_scan` before `_swatter_apply_plane` can increment it.

**One risk the implementer must not paper over:** Task 8 adds `rule=${drule}` to the reason string, which lengthens it — and `lib/block_csf.sh:17,48` truncates the csf.deny comment to 120 chars. The ledger keeps the full string, so `swatter_store_temps_all_critical_single`'s `LIKE '%critical_badpath%'` still matches. If a future change makes the *firewall comment* the source of truth for that query, it will silently under-count. Keep the query on the ledger.
