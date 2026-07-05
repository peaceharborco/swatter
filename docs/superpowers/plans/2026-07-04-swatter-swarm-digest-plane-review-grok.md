# Grok adversarial review — swarm digest plane plan

**Target:** `docs/superpowers/plans/2026-07-04-swatter-swarm-digest-plane.md`
**Models:** `grok-build` + `grok-composer-2.5-fast`, run in parallel, read-only.
**Both VERDICTs:** *Not safe to execute as written.* (high agreement)
**Provenance tags:** `[both]` = flagged by both models; `[composer]` / `[build]` = single-source (verified against real code by Claude before accepting).

The plan's **factual grounding is sound** — line anchors, the "no publish audit on main" gap, the reason-field shape, and the grade/verdict/silence non-interference invariant all verified correct. The failures are in the **executable mechanics**: wrong test file, broken HTML, an undercounting selector, and wrong timestamp semantics.

---

## Blockers (must fix before execution)

- **B1 — Task 1 targets the wrong test file.** `[both, verified]`
  Task 1 Step 1 says add the test to `test/swarm_test.sh` and "reuse this file's existing publish-test scaffolding." That scaffolding does not exist there — `swarm_test.sh` has only gate/host_id/token tests (curl mock at `:30` merely *counts* calls; `unset -f curl` at `:47`). The real enforce-mode + curl-mock-capturing-POST + store-seed + `enrolled:true` ack fixture lives in **`test/swarm_publish_test.sh:18-56`**. As written the `pub-audit-*` test can never reach the cursor write and pass.
  **Fix:** add the audit assertion to `test/swarm_publish_test.sh` (after its existing successful-publish case), not `swarm_test.sh`.

- **B2 — HTML plane is structurally broken.** `[both, verified]`
  Step 6 emits a bare `<tr><td style="…border-left:3px…">…</tr>` heredoc. Every real plane (`lib/report.sh:309`, `:316`, `:334`) is a `printf '<table role="presentation" …border-top…><tr><td>Name</td><td>value</td></tr></table>'` block inside the body `<td>` at `:292`. A bare `<tr>` dropped there is orphaned/mis-nested.
  **Fix:** mirror the existing `printf` `<table>` card; use the theme vars (`$bdr`, brass `#C48A2E`) rather than hardcoded `#2a5a6b`/`#c48a2e`.

- **B3 — Pre-block count silently under-reports.** `[both, verified]`
  Step 3's selector `((.reason // "") | startswith("swarm-corroborated"))` matches only *successful* applies. The novhost / failed / cap paths **prefix** the reason (`"no_target_vhost action=temp swarm-corroborated …"`, `"block_failed action=temp …"` — `lib/score.sh:131/140/153`), so they're excluded — even though every dispatched row carries `evidence={"swarm":true,…}` (`lib/swarm.sh:180`). The sweep logs "dispatched," so the count diverges from reality.
  **Fix:** filter on the evidence field — `select(.evidence.swarm == true)` — which is stamped on every dispatched row. (Task 2 Step 0 should verify `.evidence.swarm`, not `.reason`.)

## Majors

- **M1 — "Contributed this window" uses ban timestamps, not publish time.** `[composer, verified]`
  Task 1 writes `"ts":$max_ts`, but `max_ts` is the max perm-ban ledger ts of *sent* rows (`swarm_publish_test.sh` proves cursor = max ts of sent rows = 5000, not wall-clock). Task 2 windows on `.ts >= now−window` (`lib/report.sh:50`). A catch-up publish of old bans tonight → shows **0 contributed**; in-window bans count even if the publish failed until later.
  **Fix:** stamp the audit with `$(swatter_now)` (publish wall-clock), keep `count`.

- **M2 — No jq fallback; jq-less boxes silently zero the plane.** `[composer, verified]`
  Tech-stack line (plan:26) claims "jq (optional, with fallbacks)," but `SWARM_PREBLOCKED`/`SWARM_CONTRIB` have no non-jq path and stay 0 when `SWATTER_HAVE_JQ != 1`. `report_test.sh:33` runs with `SWATTER_HAVE_JQ=1`, hiding it; production without jq gets a permanently zeroed numeric plane while feed/staleness still render.
  **Fix:** add a grep/awk fallback for the two counts, or drop the "with fallbacks" claim and explicitly render "counts need jq" when absent.

- **M3 — Stale detection ignores `swarm.meta.json`.** `[composer, verified]`
  Staleness stats only `swarm.txt` (plan:183-185), but the sweep skips on stale *meta* (`lib/swarm.sh:152-155`). Meta can be stale while the feed looks fresh → wrong/absent amber note.
  **Fix:** take the max age across both `swarm.txt` and `swarm.meta.json`.

- **M4 — Duplicate "Swarm" heading / inconsistent emitter contract.** `[both, verified]`
  The emitter does `echo "Swarm"` *and* the builder prints a `===== Swarm =====` separator → two headings. Other `*_section` emitters are content-only (origin-lock starts at "Direct-to-origin drops:", no title).
  **Fix:** make the emitter content-only (drop its `echo "Swarm"` + blank), matching origin-lock/errors — the builder owns the separator.

- **M5 — `SWARM_LAST_PUB` is a dead global.** `[both, verified]`
  Declared (plan:216) and computed from the cursor (plan:197) but never rendered in text, the NOTE, or HTML.
  **Fix:** render it ("last contributed: …") or drop it (and the data-contract row).

## Minors

- **Fragile grep assertions** `[both]` — `grep -c '4 '`, `'1 '`, `'2 fleet IP'` (plan:152-154) false-positive on `14`, `21`, `12 fleet…`. Assert the full rendered phrase with `grep -Fq` instead.
- **`SWARM_CONTRIB=""` on empty jq output** `[build]` — overwrites the `=0`; only saved by `:-0` in the printf. Append `|| echo 0`.
- **`swatter swarm disable` won't clear `swarm.publish.log`** `[composer]` — stale contrib survives disable; add it to the cleanup at `lib/swarm.sh:259-260`.
- **Silence invariant claimed but not exercised** `[composer]` — Step 1's comment says "grade/verdict/silence" but only `_report_grade`/`_report_verdict` are called; the silence gate (`lib/report.sh:476`) is untested. Add an assertion or fix the comment.
- **Data-contract promises "top-corroborated from meta"** `[composer]` (plan:42) — emitter never reads/sorts `swarm.meta.json`. Drop the promise or implement.
- **Stale-note wording implies grade impact** `[composer]` — "treated as absent by the scorer" (plan:202); grade never reads `SWARM_*`. Reword as informational.
- **`stat_mtime` mis-cited to origin-lock** `[composer]` (plan:211) — helper is `lib/common.sh:382`, used in `swarm.sh:152` / `providers/swarm.sh:90`, not origin_lock.sh.
- **tail-2000/mv trim race** `[build]` — harmless under the scan lock; noted for completeness.

## Rejected (not folding)

- **build-model: "cursor write is at `:122`, anchors stale."** REJECTED — `grep -n lib/swarm.sh` confirms cursor write at **`:125`**, log_info at `:126`, exactly as the plan states. Composer's anchor table independently confirms `:125-126` and all other anchors (`:53/:180/:422/:375/:361/:476/:50-51`). Build miscounted; the plan's line anchors are accurate.

---

## Confirmed-correct (both models + Claude)

- Line anchors: `swarm.sh` cursor `:125-126`, enforce gate `:53`, sweep reason `:180`, `stat_mtime` `:152`; `report.sh` cutoff/log `:50-51`, summary_origin `:422`, grade `:375`, verdict `:361`, silence `:476`, text insert `:108/:110`.
- Task 1 gap is real: publish writes only the cursor + a `log_info`; no audit/count persisted anywhere.
- `.reason` is a top-level field in `decisions.jsonl` (`lib/score.sh:66`); `startswith` *would* match successful rows (the problem is it misses the prefixed ones — B3).
- Non-interference invariant holds: `_report_grade` reads only `ERR_*`/`RPT_ACTED`/`OL_HITS`; the silence gate reads only `RPT_ACTED`/`RPT_EXEMPT`/`ERR_GENUINE`. No `SWARM_*` leaks in. A swarm-only night stays silent.
