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

**Architecture:** A fourth report plane parallel to Bad Actors / Origin-Lock / Server Errors, gated on `_swarm_enabled`. It reads only local swarm state at report time (no hub call). Because `main`'s `swarm.sh` persists no per-run publish audit, Task 1 adds a tiny append-only publish log — **keyed to publish wall-clock time, not the ban ledger's `max_ts`** — so "contributed N tonight" is exact even when a catch-up publish flushes old bans; Task 2 renders the plane.

**Tech Stack:** bash 3.2 (macOS-safe), `jq`, the existing `test/*_test.sh` harness (`check name got want` → `PASS`/`FAIL`, summary as last line). **jq honesty:** feed size (`grep -c`) and staleness (`stat`) need no jq and always render; the two JSON-derived counts (`SWARM_PREBLOCKED`, `SWARM_CONTRIB`) require jq. When `SWATTER_HAVE_JQ != 1` the plane renders feed/staleness and a `counts unavailable (jq not installed)` note instead of silently showing `0`. (Prod ships jq; this only degrades gracefully on a jq-less box.)

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
| Corroboration rows | `${STATE_DIR}/feeds/swarm.meta.json` `[{ip,host_count,…}]` | `jq length` (count only — we do not render top-corroborated) |
| Feed staleness | **max** age of `swarm.txt` **and** `swarm.meta.json` mtimes | `> SWARM_MAX_AGE_DAYS*86400` old → stale (the sweep skips on stale *meta*, so meta must be checked too — `lib/swarm.sh:152`) |
| Last publish time | `${STATE_DIR}/swarm.publish.cursor` (max_ts of last success) | single epoch int |
| **Corroborated pre-blocks** | `${LOG_DIR}/decisions.jsonl` — every dispatched sweep row carries ev `{"swarm":true,"hosts":N}` (`lib/swarm.sh:180`) | window by `.ts >= cutoff` **+ `.evidence.swarm == true`**. Do **not** match on `.reason`: the novhost/failed/cap paths prefix it (`"no_target_vhost … swarm-corroborated …"`, `"block_failed … "` — `lib/score.sh:131/140/153`), so `startswith("swarm-corroborated")` silently under-counts. The `evidence` field is stamped verbatim on every path. |
| **Contribution made** | *not persisted on main* — publish writes only the cursor + log lines | **Task 1 adds `${STATE_DIR}/swarm.publish.log`** |

`swatter_swarm_publish` **runs only in enforce mode** (`lib/swarm.sh:53`), so "contributed tonight" is a report-mode-agnostic historical fact read from the audit log, not recomputed.

## File Structure

- **Modify** `lib/swarm.sh` — append one audit line per successful publish, and clear it on `disable` (Task 1).
- **Modify** `lib/report.sh` — `SWARM_*` globals in the builder; `swatter_swarm_section` (content-only) + `_report_summary_swarm`; gather call; text render block; HTML card (Task 2).
- **Modify** `test/swarm_publish_test.sh` — publish-audit assertion (Task 1).
- **Modify** `test/report_test.sh` — plane present/absent + evidence-based pre-block count + grade/verdict/silence invariants (Task 2).

---

### Task 1: Persist a minimal publish audit (`swarm.publish.log`)

**Why:** `main`'s publish records only the cursor timestamp — there is no count of what was contributed, so the digest cannot honestly say "contributed N tonight." Add one append-only JSONL line per *successful* publish. Tiny, bounded, and the single source the report needs.

**Files:**
- Modify: `lib/swarm.sh` (in `swatter_swarm_publish`, right after the cursor write, `:125-126`; and the disable cleanup, `:259-260`)
- Modify: `test/swarm_publish_test.sh` — **not** `swarm_test.sh`. The enforce-mode + POST-capturing `curl` mock + ledger seed + `enrolled:true` ack fixture lives here (`:18-56`); `swarm_test.sh` has only gate/token tests (its `curl` merely counts calls) and cannot drive a success-path publish.

**Interfaces:**
- Produces: `${STATE_DIR}/swarm.publish.log` — append-only JSONL, one line per successful publish: `{"ts":<publish_wall_clock>,"count":<n_ips>}`. **`ts` is `$(swatter_now)` at publish time, not the ban ledger's `max_ts`** — the digest windows on "now − 24h", so a catch-up publish flushing week-old bans must still register as tonight's contribution. Trimmed to the last 2000 lines to stay bounded.

- [ ] **Step 1: Write the failing test** — add a **self-contained case** to `test/swarm_publish_test.sh`, inserted **before the `unset -f curl` on the last line of case 7** (`:113`) so the curl mock + `enforce` mode are still live. Critical: the fixture `unset -f swatter_now` after every seed (`:49/:53/:110`), so you must **re-stub `swatter_now` yourself** — and deliberately stub the *ledger* ts and the *publish* ts to **different** values so the assertion proves the audit records publish-time, not `max_ts`:

```bash
# 8) the publish audit line: exists, counts sent IPs, and stamps PUBLISH time
#    (swatter_now at publish), NOT the ledger max_ts of the sent rows.
#    Case 7 wiped the ledger (: > jsonl) and left the cursor at 7000, so seed one
#    fresh ban above the cursor at an OLD ledger ts, then publish LATER.
PUBLOG="${STATE_DIR}/swarm.publish.log"; rm -f "$PUBLOG"; : > "$POSTS"
swatter_now() { echo 7200; }   # ledger ts of the new ban (> cursor 7000 => sent)
swatter_store_record 203.0.113.200 perm csf 0 90 "ban audit" 0
unset -f swatter_now
swatter_now() { echo 9999; }   # publish wall-clock — LATER than any ledger ts
swatter_swarm_publish 2>/dev/null
unset -f swatter_now
check pub-audit-exists     "$( [[ -s "$PUBLOG" ]] && echo yes || echo no )" "yes"
check pub-audit-count      "$(tail -1 "$PUBLOG" | grep -c '"count":1')"     "1"
check pub-audit-ts-publish "$(tail -1 "$PUBLOG" | grep -c '"ts":9999')"     "1"
check pub-audit-not-maxts  "$(tail -1 "$PUBLOG" | grep -c '"ts":7200')"     "0"
```

- [ ] **Step 2: Run it, verify it fails** — `bash test/swarm_publish_test.sh`
Expected: FAIL — `pub-audit-exists: want='yes' got='no'` (the audit write does not exist yet). Note: the case must sit **above** `unset -f curl` (`:113`); if placed after, `swatter_swarm_publish` finds no `curl` mock and never reaches the cursor/audit write.

- [ ] **Step 3: Implement** — in `lib/swarm.sh`, immediately after the success cursor write (`:125`):

```bash
    printf '%s' "$max_ts" > "$cursor_file"
    # Digest audit (read by the nightly Swarm plane; never on the hot path).
    # ts = publish wall-clock so the digest's "now − window" filter counts a
    # catch-up flush of old bans as tonight's contribution (NOT max_ts, which is
    # the ledger ts of the sent rows).
    local plog="${STATE_DIR}/swarm.publish.log"
    printf '{"ts":%s,"count":%s}\n' "$(swatter_now)" "${#ips[@]}" >> "$plog"
    # Bound it: keep the last 2000 lines (years of nightly publishes).
    if [[ "$(wc -l < "$plog" 2>/dev/null || echo 0)" -gt 2000 ]]; then
        tail -2000 "$plog" > "${plog}.tmp" 2>/dev/null && mv "${plog}.tmp" "$plog"
    fi
    log_info "swarm publish: ${#ips[@]} confirmed ban(s) contributed (cursor=${max_ts})"
```

(Replace the existing single `log_info` line so the audit write sits between the cursor write and the log line.)

- [ ] **Step 3b: Clear the audit on `disable`** — in the `disable` verb's cleanup (`lib/swarm.sh:259-260`, next to the cursor `rm`), add `"${STATE_DIR}/swarm.publish.log"` to the removed paths so a disabled node doesn't leave a stale contribution count behind. Update the adjacent `log_info` wording to mention the publish log.

- [ ] **Step 4: Run tests, verify pass** — `bash test/swarm_publish_test.sh`
Expected: all pass, including `pub-audit-*`.

- [ ] **Step 5: Commit**

```bash
git add lib/swarm.sh test/swarm_publish_test.sh
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
- Modify: `lib/report.sh` (globals in `swatter_report_build` `:55`, next to `OL_*`; new `swatter_swarm_section` + `_report_summary_swarm` near `_report_summary_origin` `:422`; **gather** call in the build's gather block near the origin-lock gather `:66`; **render** block in the text body after Server Errors `:108`; HTML block in `_report_render_html` after the Server-Errors card `:334`)
- Modify: `test/report_test.sh`

**Design — mirror the origin-lock plane exactly.** The builder already splits every plane into (1) a **gather** call `swatter_X_section "$window" > "$Xfile"` that sets the plane's globals via redirection and emits only the *detail body*, and (2) a **render** step that prints `separator + _report_summary_X + cat "$Xfile"` (`lib/report.sh:66` gather, `:91-99` render for origin-lock). The Swarm plane follows the same split — this is what removes the duplicate-heading problem: the section emitter is **content-only** (no "Swarm" title), the builder owns the separator, and `_report_summary_swarm` prints the one-liner once.

**Interfaces:**
- Consumes: `_swarm_enabled` (from `lib/swarm.sh`, already sourced by `bin/swatter`), `swatter_now`, `_report_window_secs`, `stat_mtime`, `SWARM_MAX_AGE_DAYS`, `SWATTER_HAVE_JQ`, `${STATE_DIR}`, `${LOG_DIR}`.
- Produces: `swatter_swarm_section [window] [cutoff] [log]` — sets `SWARM_FEED_N`, `SWARM_STALE`, `SWARM_PREBLOCKED`, `SWARM_CONTRIB`, `SWARM_LAST_PUB`, `SWARM_COUNTS_OK` (via the redirection pattern) and emits the detail body (a stale note, if any). `_report_summary_swarm` — the one-line summary. **None of these globals are read by grade/verdict/silence.**

- [ ] **Step 0: Verify the pre-block marker is `evidence.swarm`** (30-second grounding). The sweep dispatches every corroborated candidate through `_swatter_execute_block` with `ev={"swarm":true,"hosts":N}` (`lib/swarm.sh:180`), which `_swatter_audit` writes verbatim to the top-level `.evidence` field (`lib/score.sh:66`). Confirm on a box with swarm history: `jq -c 'select(.evidence.swarm==true) | {reason,evidence}' "${LOG_DIR}/decisions.jsonl" | head`. **Do not filter on `.reason`** — the novhost/failed/cap paths prefix it (`"no_target_vhost … swarm-corroborated …"`, `"block_failed …"` — `lib/score.sh:131/140/153`), so a `startswith("swarm-corroborated")` selector silently under-counts. `.evidence.swarm` is stamped on every dispatched row.

- [ ] **Step 1a: Stub `_swarm_enabled` in the shared setup** (REQUIRED, do this first). `report_test.sh` sources only `common.sh` + `report.sh` (`:6-7`) and drives `swatter_report_build` in its *earliest* cases (`:40`, `:48`, …) — but once Task 2 wires `_swarm_enabled` into the builder, those pre-existing cases would hit `_swarm_enabled: command not found` (it lives in `swarm.sh`, which the harness never sources). Mirror how the harness already stubs the other planes (`swatter_errors_section` / `swatter_originlock_section` at `:34-36`): add, right beside them, a stub identical to the real gate (`lib/swarm.sh:10-12`) so it defaults **off** (SWARM_ENABLE unset) and existing cases are unaffected:

```bash
_swarm_enabled() { [[ "${SWARM_ENABLE:-false}" == "true" && -n "${SWARM_HUB_URL:-}" ]]; }
```

- [ ] **Step 1b: Write the failing test** — add the swarm-plane block to `test/report_test.sh` (mirrors its hermetic style; it already stubs `swatter_now` to `1782396000` at `:14` and sets `SWATTER_HAVE_JQ=1` at `:33`). No `source lib/swarm.sh` needed — `swatter_swarm_section` and `_report_summary_swarm` live in `report.sh` (already sourced), and `_swarm_enabled` is the Step 1a stub, toggled via `SWARM_ENABLE`:

```bash
# --- Swarm plane: present only when enabled; never touches grade/verdict/silence ---
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rptsw.XXXXXX")"; mkdir -p "${STATE_DIR}/feeds"
NOW="$(swatter_now)"
printf '198.51.100.7\n198.51.100.8\n' > "${STATE_DIR}/feeds/swarm.txt"
printf '[{"ip":"198.51.100.7","host_count":3}]\n' > "${STATE_DIR}/feeds/swarm.meta.json"
printf '{"ts":%s,"count":4}\n' "$NOW" > "${STATE_DIR}/swarm.publish.log"
SW_LOG="${STATE_DIR}/decisions.jsonl"
# Two dispatched sweep rows: one clean reason, one novhost-PREFIXED reason. Both
# carry evidence.swarm=true, so the evidence-based selector must count BOTH (2);
# a .reason startswith would wrongly count only the clean one (regression guard).
printf '{"ts":%s,"ip":"185.220.101.1","action":"temp","reason":"swarm-corroborated hosts=3","evidence":{"swarm":true,"hosts":3}}\n' "$NOW"  > "$SW_LOG"
printf '{"ts":%s,"ip":"185.220.101.2","action":"temp","reason":"no_target_vhost action=temp swarm-corroborated hosts=2","evidence":{"swarm":true,"hosts":2}}\n' "$NOW" >> "$SW_LOG"
CUT=$(( NOW - 86400 ))

# Disabled → the section is a silent no-op (empty body).
SWARM_ENABLE=false
check swplane-off "$(swatter_swarm_section 24h "$CUT" "$SW_LOG" | grep -c .)" "0"

# Enabled → section sets globals; the summary line renders them. Assert on full,
# fixed-string phrases (grep -Fc) so digits can't false-match a substring.
SWARM_ENABLE=true SWARM_HUB_URL="https://hub.example" SWARM_MAX_AGE_DAYS=3
swatter_swarm_section 24h "$CUT" "$SW_LOG" >/dev/null   # sets SWARM_* globals
sum="$(_report_summary_swarm)"
check swplane-feed    "$(printf '%s' "$sum" | grep -Fc 'Consuming 2 fleet IP(s)')" "1"
check swplane-preblk  "$(printf '%s' "$sum" | grep -Fc '2 pre-blocked')"           "1"
check swplane-contrib "$(printf '%s' "$sum" | grep -Fc '4 contributed')"           "1"

# grade/verdict identical with the plane's globals set vs unset
RPT_ACTED=0 RPT_EXEMPT=0 ERR_GENUINE=0 ERR_FATAL=0 OL_HITS=0
_report_grade; g0="$RPT_GRADE"; v0="$(_report_verdict | cut -f1)"
SWARM_FEED_N=99 SWARM_PREBLOCKED=99 SWARM_CONTRIB=99
_report_grade; check swplane-nograde "$RPT_GRADE" "$g0"
check swplane-noverdict "$(_report_verdict | cut -f1)" "$v0"
# Silence invariant as a SOURCE-level guard (robust to line drift): the silence
# gate's body must reference no SWARM_* global.
check swplane-silence-clean "$(awk '/Stay silent only when BOTH planes/,/return 0/' "${ROOT}/lib/report.sh" | grep -c SWARM)" "0"
```

- [ ] **Step 2: Run it, verify it fails** — `bash test/report_test.sh`
Expected: FAIL — `swatter_swarm_section: command not found`.

- [ ] **Step 3: Add the emitter + summary** to `lib/report.sh` (near `_report_summary_origin`, `:422`). The section is **content-only** (mirrors `swatter_originlock_section`): it sets globals and emits only the stale note; the summary line is printed separately by `_report_summary_swarm` in the render step.

```bash
# Swarm plane (informational — never escalates the grade, never breaks silence).
# Reads only local swarm state; no hub call at report time. Content-only like
# swatter_originlock_section: sets SWARM_* globals + emits the stale note (if any);
# _report_summary_swarm prints the one-liner in the render step. $2/$3 optional so
# standalone callers get sane defaults.
swatter_swarm_section() {
    _swarm_enabled || return 0
    local window="${1:-${REPORT_WINDOW:-24h}}" cutoff="${2:-}" log="${3:-${LOG_DIR}/decisions.jsonl}"
    [[ -n "$cutoff" ]] || cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    local feed="${STATE_DIR}/feeds/swarm.txt" meta="${STATE_DIR}/feeds/swarm.meta.json"
    local plog="${STATE_DIR}/swarm.publish.log" cur="${STATE_DIR}/swarm.publish.cursor"
    local now; now="$(swatter_now)"

    # Intel received: feed size + staleness. Staleness = the OLDER of swarm.txt
    # and swarm.meta.json (the sweep skips on stale META — swarm.sh:152 — so a
    # fresh feed alone is not "fresh"). stat_mtime is the repo's portable helper
    # (common.sh:382; also used at swarm.sh:152, providers/swarm.sh:90).
    SWARM_FEED_N=0; [[ -s "$feed" ]] && SWARM_FEED_N="$(grep -c . "$feed" 2>/dev/null)"
    SWARM_STALE=0
    local f m oldest=0
    for f in "$feed" "$meta"; do
        [[ -s "$f" ]] || continue
        m="$(stat_mtime "$f" 2>/dev/null || echo "$now")"
        (( m < now )) || continue          # future mtime (test stubs a past now) => treat as fresh
        (( now - m > oldest )) && oldest=$(( now - m ))
    done
    (( oldest > ${SWARM_MAX_AGE_DAYS:-3} * 86400 )) && SWARM_STALE=1

    # The two JSON-derived counts require jq. Without it, flag them unavailable
    # rather than silently showing 0 (feed size + staleness still render).
    SWARM_PREBLOCKED=0 SWARM_CONTRIB=0 SWARM_COUNTS_OK=1
    if [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
        # Corroborated pre-blocks in-window. Match evidence.swarm (stamped on
        # EVERY dispatched row), NOT .reason (prefixed on novhost/failed paths).
        [[ -s "$log" ]] && SWARM_PREBLOCKED="$(jq -c "select(.ts >= ${cutoff} and (.evidence.swarm == true))" "$log" 2>/dev/null | grep -c . )"
        # Contribution made in-window (sum of counts from the publish audit).
        [[ -s "$plog" ]] && SWARM_CONTRIB="$(jq -s "map(select(.ts >= ${cutoff}))|map(.count)|add // 0" "$plog" 2>/dev/null)"
        [[ -n "$SWARM_CONTRIB" ]] || SWARM_CONTRIB=0   # empty jq output => 0
    else
        SWARM_COUNTS_OK=0
    fi
    SWARM_LAST_PUB="none"; [[ -s "$cur" ]] && SWARM_LAST_PUB="$(tr -d '[:space:]' < "$cur")"

    # Body: an amber note only when stale (information only — grade is unaffected).
    (( ${SWARM_STALE:-0} )) && echo "  NOTE: feed stale (> ${SWARM_MAX_AGE_DAYS:-3}d) — shown for information only; the report grade is unaffected."
}

_report_summary_swarm() {
    if (( ${SWARM_COUNTS_OK:-1} )); then
        printf 'Consuming %s fleet IP(s) · %s pre-blocked (corroborated) · %s contributed this window' \
            "${SWARM_FEED_N:-0}" "${SWARM_PREBLOCKED:-0}" "${SWARM_CONTRIB:-0}"
    else
        printf 'Consuming %s fleet IP(s) · pre-block/contribution counts unavailable (jq not installed)' \
            "${SWARM_FEED_N:-0}"
    fi
    # Last contribution, when we have ever published — portable epoch->date
    # (the dual GNU/BSD form the tests already use, report_test.sh:15).
    if [[ "${SWARM_LAST_PUB:-none}" != "none" ]]; then
        local when; when="$(date -u -d "@${SWARM_LAST_PUB}" '+%Y-%m-%d' 2>/dev/null || date -u -r "${SWARM_LAST_PUB}" '+%Y-%m-%d' 2>/dev/null)"
        [[ -n "$when" ]] && printf ' · last contributed %s' "$when"
    fi
    printf '.\n'
}
```

- [ ] **Step 4: Declare the globals** in `swatter_report_build` (`lib/report.sh:55`, next to the `OL_*` line):

```bash
    SWARM_FEED_N=0 SWARM_STALE=0 SWARM_PREBLOCKED=0 SWARM_CONTRIB=0 SWARM_LAST_PUB="none" SWARM_COUNTS_OK=1
```

- [ ] **Step 5a: Gather** in the build's gather block (next to `swatter_originlock_section … > "$olfile"`, `:66`), so the `SWARM_*` globals persist in this shell for the HTML render (a command-substitution would lose them):

```bash
    local swfile=""
    if _swarm_enabled; then
        swfile="$(mktemp "${TMPDIR:-/tmp}/swatter-swsec.XXXXXX")"
        swatter_swarm_section "$window" "$cutoff" "$log" > "$swfile"
    fi
```

- [ ] **Step 5b: Render the text plane** in the body, after the Server-Errors block (`:108`, before the footer `:110`) — separator + summary + body, exactly like origin-lock (`:91-99`):

```bash
    if _swarm_enabled; then
        echo
        echo "========================  Swarm  ================================"
        echo
        _report_summary_swarm
        [[ -s "$swfile" ]] && cat "$swfile"
    fi
    rm -f "$swfile"
```

- [ ] **Step 6: Render the HTML plane** in `_report_render_html`, after the Server-Errors card (`lib/report.sh:334`). Copy the Server-Errors card verbatim and swap the label/value — the in-scope style vars there are **`$bdr`** (row border), **`$h3`** (label style), **`$f_h`** (value font), **`$pine`** (value color), **`$ink`** (summary text), **`$slate`**/**`$ember`** (muted / warning) — there is **no** `$line`/`$f_muted`/`$amber`. Run the summary through `esc()` like the siblings do. Headline number = fleet IPs consumed; the full summary rides as a sub-line (reuses `_report_summary_swarm`, so text and HTML never drift):

```bash
    if _swarm_enabled; then
        printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;border-top:1px solid %s;"><tr><td style="padding-top:14px;%s">Swarm</td><td style="padding-top:14px;%s;font-weight:700;font-size:20px;color:%s;text-align:right;">%s</td></tr></table>' \
            "$bdr" "$h3" "$f_h" "$pine" "${SWARM_FEED_N:-0}"
        printf '<div style="font-size:13px;color:%s;margin-top:5px;line-height:1.55;">%s</div>' \
            "$ink" "$(_report_summary_swarm | esc)"
        (( ${SWARM_STALE:-0} )) && printf '<div style="font-size:12px;color:%s;margin-top:6px;">Feed stale &mdash; shown for information only.</div>' "$ember"
    fi
```

(All six vars — `$bdr`, `$h3`, `$f_h`, `$pine`, `$ink`, `$ember` — and `esc()` are declared at the top of `_report_render_html` and used by the existing plane cards; do not hardcode a hex.)

- [ ] **Step 7: Confirm the invariant.** Do NOT edit `_report_grade` (`:375`), `_report_verdict` (`:361`), or the silence check (`:476`). Grep them to be sure no `SWARM_*` sneaks in.

- [ ] **Step 8: Run tests, verify pass** — `bash test/report_test.sh`; then `bash test/swarm_publish_test.sh`, `bash test/report_cron_test.sh`.
Expected: all pass; the plane renders when enabled, is absent when off, `swplane-preblk` is `2` (evidence-based count includes the novhost-prefixed row), and grade/verdict are identical with `SWARM_*` set vs unset.

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

**2. Grounded in reality:** Every path and function is verified against `main` v2.7.0 — `swatter_swarm_publish` cursor write (`lib/swarm.sh:125-126`), sweep dispatch with `ev={"swarm":true,…}` (`:180`), the `.evidence` field in the decision writer (`lib/score.sh:66`), builder `cutoff`/`log` (`lib/report.sh:50-51`), the per-plane gather/render split (`:66`/`:91-99`), grade/verdict/silence anchors (`:375`/`:361`/`:476`). The one gap in main's persistence (no publish audit) is closed by Task 1, not assumed away.

**3. Grok-review corrections folded in** (`…-review-grok.md`, two models, both verdicts "not safe as written" — now addressed): Task 1 targets `test/swarm_publish_test.sh` (the only file with the enforce/curl/enrolled fixture), not `swarm_test.sh`; the publish audit stamps **publish wall-clock** `ts`, not the ledger `max_ts` (catch-up-flush correctness); pre-blocks count on **`.evidence.swarm`**, not the prefix-fragile `.reason startswith`; staleness checks **both** `swarm.txt` and `swarm.meta.json`; the section is content-only with the builder owning the separator (no duplicate heading); jq-absence degrades to a note instead of silent zeros; the HTML plane uses the real `printf '<table role=presentation>'` card, not an orphan `<tr>`; `SWARM_LAST_PUB` is rendered; `disable` clears the audit.

**4. Placeholder scan:** No TBD/"handle errors"/"similar to". Real bash + real tests + exact commands. The one deliberate verify-first step (Task 2 Step 0) is a 30-second `.evidence.swarm` confirmation, with the rationale stated.

**5. Invariant integrity:** Grade/verdict non-interference is asserted by a runtime regression test (SWARM_* set vs unset), and the silence-gate non-interference by a source-level guard (`awk` slice of the gate body must contain no `SWARM_`) — both tested, not just prose. The evidence-based pre-block count is locked by a fixture row whose `.reason` is prefixed (would fail under the old selector).

---

## Execution Handoff

**Plan saved to `docs/superpowers/plans/2026-07-04-swatter-swarm-digest-plane.md` on branch `feat/swarm-digest-plane` (off `main` v2.7.0).** Three small tasks: (1) publish audit line, (2) the digest plane, (3) docs + version bump. Pick up with subagent-driven-development or executing-plans. **Do not merge the old `feat/swarm-hub` branch** — it is superseded.
