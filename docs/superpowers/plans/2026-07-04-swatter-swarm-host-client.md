# Swatter Swarm — Nightly Digest Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> ## ⚠️ STATUS / SCOPE CORRECTION (2026-07-04)
>
> This plan was **rewritten** after discovering the original premise was wrong.
> The **entire host-side swarm client already shipped on `main` as v2.7.0**
> (2026-07-03): `lib/swarm.sh` (publish, consume, corroborated-block sweep,
> `swatter swarm` CLI), `lib/providers/swarm.sh`, the store cursor delta, the hub
> (`hub/`), and the `POST /purge` route. The earlier version of this file planned
> to *build all of that* on a stale `feat/swarm-hub` branch — redundant work.
>
> **The one genuinely unbuilt piece** — and the answer to the original question
> ("should we add a Swarm section to the nightly email digest?") — is the
> **digest Swarm plane**. `main`'s `lib/report.sh` has zero swarm code. This plan
> covers only that, grounded in `main` v2.7.0's real state files and signatures.
>
> **Branch:** `feat/swarm-digest-plane` (cut from `origin/main`). The old
> `feat/swarm-hub` branch is superseded — do not merge it.

**Goal:** Add an informational **Swarm** plane to the nightly digest that shows what the fleet gave and got — intel received, contribution made, corroborated pre-blocks — without ever escalating the grade or breaking silent-when-quiet.

**Architecture:** A fourth report plane parallel to Bad Actors / Origin-Lock / Server Errors, gated on `_swarm_enabled`. It reads only local swarm state at report time (no hub call). Because `main`'s `swarm.sh` persists no per-run publish audit, Task 1 adds a tiny append-only publish log so "contributed N tonight" is exact; Task 2 renders the plane.

**Tech Stack:** bash 3.2 (macOS-safe), `jq` (optional, with fallbacks), the existing `test/*_test.sh` harness (`check name got want` → `PASS`/`FAIL`, summary as last line).

## Global Constraints

- **Bash 3.2-safe** — no `${x^}`, no associative arrays, no `mapfile`.
- **The Swarm plane is informational.** It sets only `SWARM_*` report globals. It must **never** be read by `_report_grade` (report.sh:375), `_report_verdict` (report.sh:361), or the silent-when-quiet check (report.sh:476). A swarm-only night sends no email; the plane rides along whenever an email is already being sent (real activity, `--test`, `--print`).
- **Stale feed** (`swarm.txt`/`meta.json` mtime > `SWARM_MAX_AGE_DAYS`, default 3) → an amber note *inside the section only*; never a grade change.
- **No hub calls at report time** — read local state only.
- **`SWARM_*` config already exists** in `lib/common.sh` (shipped with v2.7.0): `SWARM_ENABLE`, `SWARM_MAX_AGE_DAYS`, `SWARM_ACTION`, `SWARM_MIN_CORROBORATION`, etc. No new config keys.
- **Commit** after each task. Trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## Data contract — what `main` v2.7.0 actually persists (verified)

| Signal | Source (real, on `main`) | How to read it |
|--------|--------------------------|----------------|
| Fleet IPs consumed | `${STATE_DIR}/feeds/swarm.txt` (bare feed) | `grep -c .`; mtime → freshness |
| Corroboration rows | `${STATE_DIR}/feeds/swarm.meta.json` `[{ip,host_count,…}]` | `jq length`; `jq` sort for top-corroborated |
| Feed staleness | mtime of `swarm.txt` / `swarm.meta.json` | `> SWARM_MAX_AGE_DAYS*86400` old → stale |
| Last publish time | `${STATE_DIR}/swarm.publish.cursor` (max_ts of last success) | single epoch int |
| **Corroborated pre-blocks** | `${LOG_DIR}/decisions.jsonl` — sweep records reason `swarm-corroborated hosts=N`, ev `{"swarm":true,"hosts":N}` (`lib/swarm.sh:180`) | window by `.ts >= cutoff` + reason match |
| **Contribution made** | *not persisted on main* — publish writes only the cursor + log lines | **Task 1 adds `${STATE_DIR}/swarm.publish.log`** |

`swatter_swarm_publish` **runs only in enforce mode** (`lib/swarm.sh:53`), so "contributed tonight" is a report-mode-agnostic historical fact read from the audit log, not recomputed.

## File Structure

- **Modify** `lib/swarm.sh` — append one audit line per successful publish (Task 1).
- **Modify** `lib/report.sh` — `SWARM_*` globals in the builder; `swatter_swarm_report_section`; `_report_summary_swarm`; HTML block; text plane block (Task 2).
- **Modify** `test/swarm_test.sh` — publish-audit assertion (Task 1).
- **Modify** `test/report_test.sh` — plane present/absent + grade/verdict/silence invariants (Task 2).

---

### Task 1: Persist a minimal publish audit (`swarm.publish.log`)

**Why:** `main`'s publish records only the cursor timestamp — there is no count of what was contributed, so the digest cannot honestly say "contributed N tonight." Add one append-only JSONL line per *successful* publish. Tiny, bounded, and the single source the report needs.

**Files:**
- Modify: `lib/swarm.sh` (in `swatter_swarm_publish`, right after the cursor write, `:125-126`)
- Modify: `test/swarm_test.sh`

**Interfaces:**
- Produces: `${STATE_DIR}/swarm.publish.log` — append-only JSONL, one line per successful publish: `{"ts":<max_ts>,"count":<n_ips>}`. Trimmed to the last 2000 lines to stay bounded.

- [ ] **Step 1: Write the failing test** — add to `test/swarm_test.sh` (a block that drives publish with a fake `curl` returning an `enrolled:true` ack; follow the file's existing publish-test scaffolding for store seeding and the curl stub). Assert the audit line lands:

```bash
# --- publish writes an audit line on success (for the digest plane) ---
# (reuse this file's existing enforce-mode + enrolled-ack publish fixture)
PUBLOG="${STATE_DIR}/swarm.publish.log"
rm -f "$PUBLOG"
swatter_swarm_publish >/dev/null 2>&1
check pub-audit-exists "$( [[ -s "$PUBLOG" ]] && echo yes || echo no )" "yes"
check pub-audit-count  "$(tail -1 "$PUBLOG" | grep -c '"count":')" "1"
```

- [ ] **Step 2: Run it, verify it fails** — `bash test/swarm_test.sh`
Expected: FAIL — `pub-audit-exists: want='yes' got='no'`.

- [ ] **Step 3: Implement** — in `lib/swarm.sh`, immediately after the success cursor write (`:125`):

```bash
    printf '%s' "$max_ts" > "$cursor_file"
    # Digest audit (read by the nightly Swarm plane; never on the hot path).
    local plog="${STATE_DIR}/swarm.publish.log"
    printf '{"ts":%s,"count":%s}\n' "$max_ts" "${#ips[@]}" >> "$plog"
    # Bound it: keep the last 2000 lines (years of nightly publishes).
    if [[ "$(wc -l < "$plog" 2>/dev/null || echo 0)" -gt 2000 ]]; then
        tail -2000 "$plog" > "${plog}.tmp" 2>/dev/null && mv "${plog}.tmp" "$plog"
    fi
    log_info "swarm publish: ${#ips[@]} confirmed ban(s) contributed (cursor=${max_ts})"
```

(Replace the existing single `log_info` line so the audit write sits between the cursor write and the log line.)

- [ ] **Step 4: Run tests, verify pass** — `bash test/swarm_test.sh`
Expected: all pass, including `pub-audit-*`.

- [ ] **Step 5: Commit**

```bash
git add lib/swarm.sh test/swarm_test.sh
git commit -m "$(cat <<'EOF'
feat(swarm): persist a minimal publish audit for the digest plane

swatter_swarm_publish appends {"ts","count"} to swarm.publish.log on each
successful contribution (bounded to 2000 lines). The nightly Swarm plane reads
it for an exact "contributed N tonight"; nothing else depends on it.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: The nightly digest Swarm plane

**Files:**
- Modify: `lib/report.sh` (globals in `swatter_report_build` `:53-55`; new `swatter_swarm_report_section` + `_report_summary_swarm` near `_report_summary_origin` `:422`; text block in the builder after Server Errors `:108`; HTML block in `_report_render_html` after the Server-Errors card)
- Modify: `test/report_test.sh`

**Interfaces:**
- Consumes: `_swarm_enabled` (from `lib/swarm.sh`, already sourced by `bin/swatter`), `swatter_now`, `_report_window_secs`, `SWARM_MAX_AGE_DAYS`, `${STATE_DIR}`, `${LOG_DIR}`.
- Produces: `swatter_swarm_report_section [window] [cutoff] [log]` (emits the text plane on stdout, sets `SWARM_FEED_N`, `SWARM_STALE`, `SWARM_PREBLOCKED`, `SWARM_CONTRIB`, `SWARM_LAST_PUB` globals via the redirection pattern); `_report_summary_swarm` (one-liner). **None of these globals are read by grade/verdict/silence.**

- [ ] **Step 0: Verify the decisions.jsonl reason field** (30-second grounding — the sweep's audit shape). On a box with swarm history, or from a unit fixture: `grep -m1 swarm-corroborated "${LOG_DIR}/decisions.jsonl"` and confirm the reason text sits on a top-level `.reason` field. If it is nested (e.g. under `.evidence`), adjust the jq selector in Step 3 accordingly. The marker string is `swarm-corroborated` (`lib/swarm.sh:180`).

- [ ] **Step 1: Write the failing test** — add to `test/report_test.sh` (mirrors its hermetic style; it already stubs `swatter_now` to `1782396000` and sets `SWATTER_HAVE_JQ=1`):

```bash
# --- Swarm plane: present only when enabled; never touches grade/verdict/silence ---
source "${ROOT}/lib/swarm.sh"
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rptsw.XXXXXX")"; mkdir -p "${STATE_DIR}/feeds"
NOW="$(swatter_now)"
printf '198.51.100.7\n198.51.100.8\n' > "${STATE_DIR}/feeds/swarm.txt"
printf '[{"ip":"198.51.100.7","host_count":3}]\n' > "${STATE_DIR}/feeds/swarm.meta.json"
printf '{"ts":%s,"count":4}\n' "$NOW" > "${STATE_DIR}/swarm.publish.log"
SW_LOG="${STATE_DIR}/decisions.jsonl"
printf '{"ts":%s,"ip":"185.220.101.1","action":"temp","reason":"swarm-corroborated hosts=3"}\n' "$NOW" > "$SW_LOG"
CUT=$(( NOW - 86400 ))

SWARM_ENABLE=false
check swplane-off "$(swatter_swarm_report_section 24h "$CUT" "$SW_LOG" | grep -c Swarm)" "0"
SWARM_ENABLE=true SWARM_HUB_URL="https://hub.example" SWARM_MAX_AGE_DAYS=3
out="$(swatter_swarm_report_section 24h "$CUT" "$SW_LOG")"
check swplane-feed    "$(printf '%s' "$out" | grep -c '2 fleet IP')" "1"
check swplane-contrib "$(printf '%s' "$out" | grep -c '4 ')" "1"
check swplane-preblk  "$(printf '%s' "$out" | grep -c '1 ')" "1"

# grade/verdict/silence identical with the plane's globals set vs unset
RPT_ACTED=0 RPT_EXEMPT=0 ERR_GENUINE=0 ERR_FATAL=0 OL_HITS=0
_report_grade; g0="$RPT_GRADE"; v0="$(_report_verdict | cut -f1)"
SWARM_FEED_N=99 SWARM_PREBLOCKED=99 SWARM_CONTRIB=99
_report_grade; check swplane-nograde "$RPT_GRADE" "$g0"
check swplane-noverdict "$(_report_verdict | cut -f1)" "$v0"
```

- [ ] **Step 2: Run it, verify it fails** — `bash test/report_test.sh`
Expected: FAIL — `swatter_swarm_report_section: command not found`.

- [ ] **Step 3: Add the emitter + summary** to `lib/report.sh` (near `_report_summary_origin`, `:422`):

```bash
# Swarm plane (informational — never escalates the grade, never breaks silence).
# Reads only local swarm state; no hub call at report time. $2/$3 optional so the
# builder can pass its own cutoff/log; standalone callers get sane defaults.
swatter_swarm_report_section() {
    _swarm_enabled || return 0
    local window="${1:-${REPORT_WINDOW:-24h}}" cutoff="${2:-}" log="${3:-${LOG_DIR}/decisions.jsonl}"
    [[ -n "$cutoff" ]] || cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    local feed="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    local plog="${STATE_DIR}/swarm.publish.log" cur="${STATE_DIR}/swarm.publish.cursor"

    # Intel received: feed size + staleness.
    SWARM_FEED_N=0; [[ -s "$feed" ]] && SWARM_FEED_N="$(grep -c . "$feed" 2>/dev/null)"
    SWARM_STALE=0
    if [[ -s "$feed" ]]; then
        local age; age=$(( $(swatter_now) - $(stat_mtime "$feed" 2>/dev/null || echo 0) ))
        (( age > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )) && SWARM_STALE=1
    fi
    # Corroborated pre-blocks in-window (from the sweep's decisions.jsonl rows).
    SWARM_PREBLOCKED=0
    if [[ -s "$log" ]] && [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
        SWARM_PREBLOCKED="$(jq -c "select(.ts >= ${cutoff} and ((.reason // \"\") | startswith(\"swarm-corroborated\")))" "$log" 2>/dev/null | grep -c . )"
    fi
    # Contribution made in-window (sum of counts from the publish audit).
    SWARM_CONTRIB=0
    if [[ -s "$plog" ]] && [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
        SWARM_CONTRIB="$(jq -s "map(select(.ts >= ${cutoff}))|map(.count)|add // 0" "$plog" 2>/dev/null)"
    fi
    SWARM_LAST_PUB="none"; [[ -s "$cur" ]] && SWARM_LAST_PUB="$(tr -d '[:space:]' < "$cur")"

    echo "Swarm"
    echo
    _report_summary_swarm
    (( ${SWARM_STALE:-0} )) && echo "  NOTE: feed stale (> ${SWARM_MAX_AGE_DAYS:-3}d) — fleet intel treated as absent by the scorer"
}

_report_summary_swarm() {
    printf 'Consuming %s fleet IP(s) · %s pre-blocked (corroborated) · %s contributed this window.\n' \
        "${SWARM_FEED_N:-0}" "${SWARM_PREBLOCKED:-0}" "${SWARM_CONTRIB:-0}"
}
```

(`stat_mtime` is the repo's portable mtime helper used by `swarm.sh:152` and `report`'s origin-lock path; reuse it.)

- [ ] **Step 4: Declare the globals** in `swatter_report_build` (`lib/report.sh:55`, next to the `OL_*` line):

```bash
    SWARM_FEED_N=0 SWARM_STALE=0 SWARM_PREBLOCKED=0 SWARM_CONTRIB=0 SWARM_LAST_PUB="none"
```

- [ ] **Step 5: Render the text plane** in the builder, after the Server-Errors block (`:108`, before the footer `:110`). Gather-and-render inline (the emitter both sets globals and prints, and `_swarm_enabled` gates it):

```bash
    if _swarm_enabled; then
        echo
        echo "========================  Swarm  ================================"
        echo
        swatter_swarm_report_section "$window" "$cutoff" "$log"
    fi
```

- [ ] **Step 6: Render the HTML plane** in `_report_render_html`, after the Server-Errors card. Match the existing card markup (the brass/lake border used elsewhere); populate from the globals the text emitter already set:

```bash
    if _swarm_enabled; then
        cat <<HTML
<tr><td style="padding:12px 16px;border-left:3px solid #2a5a6b;">
  <div style="font-weight:600;">Swarm</div>
  <div style="color:#4a5568;font-size:13px;">$(_report_summary_swarm)</div>
  $( (( ${SWARM_STALE:-0} )) && echo '<div style="color:#c48a2e;font-size:12px;">Feed stale — fleet intel treated as absent</div>' )
</td></tr>
HTML
    fi
```

- [ ] **Step 7: Confirm the invariant.** Do NOT edit `_report_grade` (`:375`), `_report_verdict` (`:361`), or the silence check (`:476`). Grep them to be sure no `SWARM_*` sneaks in.

- [ ] **Step 8: Run tests, verify pass** — `bash test/report_test.sh`; then `bash test/swarm_test.sh`, `bash test/report_cron_test.sh`.
Expected: all pass; the plane renders when enabled, is absent when off, and grade/verdict are identical with `SWARM_*` set vs unset.

- [ ] **Step 9: Commit**

```bash
git add lib/report.sh test/report_test.sh
git commit -m "$(cat <<'EOF'
feat(report): nightly digest Swarm plane (informational)

Fourth report plane from local swarm state: fleet IPs consumed (+staleness),
corroborated pre-blocks (windowed decisions.jsonl), contributed-this-window
(swarm.publish.log). Gated on _swarm_enabled; sets only SWARM_* globals so it
never escalates the grade or breaks silent-when-quiet. Text + HTML.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Docs + version bump

**Files:**
- Modify: `README.md` (Swarm section — note the nightly digest now carries a Swarm plane)
- Modify: `CHANGELOG.md` + `bin/swatter` `SWATTER_VERSION` (bump 2.7.0 → 2.7.1; a digest-only feature is a patch/minor per the version-bump memory)

- [ ] **Step 1:** Add a paragraph to the README Swarm section: the nightly digest shows a Swarm plane (fleet IPs consumed, corroborated pre-blocks, contributed-this-window, stale-feed note) whenever `SWARM_ENABLE=true`; it is informational and never changes the report grade.
- [ ] **Step 2:** Follow the version-bump runbook (see the `swatter-version-bump` memory): bump `SWATTER_VERSION`, add a CHANGELOG entry, tag, and cut the GitHub + GitLab release. Pushing alone does not publish.
- [ ] **Step 3:** `make test` — every `*_test.sh` ends in `0 failed`.
- [ ] **Step 4: Commit** the docs/version bump per the release runbook.

---

## Self-Review

**1. Scope coverage:** Original ask = "Swarm section in the nightly digest." Delivered by Task 2 (plane) + Task 1 (the missing data it needs). Host client itself is already shipped on `main` v2.7.0 — explicitly out of scope (see status banner).

**2. Grounded in reality:** Every path and function is verified against `main` v2.7.0 — `swatter_swarm_publish` cursor write (`lib/swarm.sh:125`), sweep reason `swarm-corroborated` (`:180`), builder `cutoff`/`log` (`lib/report.sh:50-51`), grade/verdict/silence anchors (`:375`/`:361`/`:476`). The one gap in main's persistence (no publish audit) is closed by Task 1, not assumed away.

**3. Placeholder scan:** No TBD/"handle errors"/"similar to". Real bash + real tests + exact commands. The only deliberate verify-first step (Task 2 Step 0) is a 30-second field-name confirmation, with the fallback stated.

**4. Invariant integrity:** The grade/verdict/silence non-interference is asserted by an explicit regression test (Task 2 Step 1), not just asserted in prose.

---

## Execution Handoff

**Plan saved to `docs/superpowers/plans/2026-07-04-swatter-swarm-host-client.md` on branch `feat/swarm-digest-plane` (off `main` v2.7.0).** Three small tasks: (1) publish audit line, (2) the digest plane, (3) docs + version bump. Pick up with subagent-driven-development or executing-plans. **Do not merge the old `feat/swarm-hub` branch** — it is superseded.
