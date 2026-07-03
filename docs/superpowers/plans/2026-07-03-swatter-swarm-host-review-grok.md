# Swarm HOST plan review — Grok two-model pass (v1 → v1.1)

Adversarial review of `2026-07-03-swatter-swarm-host.md` v1 before execution.
Both models ran headless, read-only, same brief, verifying the plan's code
against the actual repo. **Both verdicts: REVISE-BEFORE-EXECUTE.** All blockers
and actionable majors folded into **v1.1** (same file).

Provenance: `[both]` / `[build]` / `[composer]`. Single-source findings were
verified against the code before acting.

## Fixed in v1.1

- **[both] Publish cursor advanced over UNSENT rows** — `max_ts` was computed
  from every delta row before the four outbound gates, so a gate-filtered ban
  (or a same-window race) permanently consumed the cursor. → cursor now tracks
  ONLY actually-sent rows; filtered rows are re-read + re-filtered until a later
  publishable ban passes them (cheap, self-healing on policy change). Test
  seeds filtered rows with the HIGHEST timestamps to pin it.
- **[composer] 200 + `rejected>0` advanced silently** — bash/hub validator
  drift would drop entries with no signal. → parsed and loudly warned; cursor
  still advances (hub validation is deterministic — wedging retries forever).
  Documented as a locked decision + test.
- **[composer] Task 6's test could not run its own implementation** — it never
  sourced `lib/score.sh` but the sweep calls `_swatter_pick_ttl`. → the test
  stubs `_swatter_pick_ttl` (and documents why score.sh isn't sourced). TDD
  ordering restored; stale-meta no-op case added.
- **[both] Enroll `label` JSON injection** — `hostname -f` output went into
  hand-built JSON with only `"` stripped; backslashes/newlines ⇒ malformed body
  ⇒ opaque 400. → sanitized to `[A-Za-z0-9._-]` max 64; hostile-hostname test.
- **[composer] Meta sidecar split-brain** — bare feed fresh + json fetch failed
  left STALE `swarm.meta.json` for the sweep/scaling. → fresh-or-absent
  invariant: any sidecar failure DELETES prior meta; test added; obligation-2
  corollary added to Global Constraints.
- **[both] `INTEL_PROVIDERS` opt-in never wired or documented** — consume was
  dead-on-arrival: `provider_swarm*` only runs when `swarm` ∈ INTEL_PROVIDERS,
  and nothing told the operator. → example-conf instruction with a concrete
  line, `swatter swarm status` warns when missing (tested), `test-config`
  advisory `swarm)` case added (Task 1), disable message mentions removing it.
- **[both] Task 9 invented a `run_case` helper that does not exist** —
  `curl_secrets_test.sh` uses `argv_clean`/`cfg_has` + a `MOCK_STDOUT` curl
  mock. → Task 9 rewritten against the verified real pattern, including why
  `MOCK_STDOUT='200'` satisfies the `-w '%{http_code}'` paths.
- **[build] Task 8 purge diff left the import/route edits implicit** → exact
  FROM/TO import line and route insertion point now shown.
- **[both] Raw `stat -c || stat -f` instead of the repo's `stat_mtime`**
  (common.sh:367) → all lib code uses `stat_mtime` (tests keep raw stat for
  the perms check only, where no helper exists).
- **[composer] Spec §11 boost-fold tests missing** — local-clean-never-tipped /
  near-miss-tipped / fold-never-lowers now proven numerically in Task 4 via
  `_swatter_fold_reputation` with `W_REPUTATION=14`.
- **[composer] Disabled-consume test didn't assert zero curl calls** → asserted.
- **[composer] `hc` non-numeric could reach hand-built evidence JSON** → sweep
  now `continue`s on non-numeric host_count.

## Accepted / declined (with reasons)

- **[composer] Sweep needs a SWATTER_MODE guard** — declined as a guard, locked
  as a decision: in report mode the sweep dry-runs through the backends exactly
  like `scan` and `import-bans` (both record `dry_run=1`; composer's claim that
  import-bans gates on mode is wrong — bin/swatter:400 sets the dry flag and
  proceeds). Consistent preview semantics; dry temps never escalate or publish.
- **[composer] Sweep re-blocks active temp bans each refresh** — accepted and
  documented as the keep-alive/decay semantic: daily re-issue while an IP stays
  corroborated, ladder TTL (caps 3d) > daily cadence, breaker-bounded, decays
  naturally when the feed drops the IP. There is no "active temp ban" store
  helper to gate on, and adding one isn't worth the churn it prevents.
- **[composer] CIDR-contained IPs under-score (host_count keyed by CIDR string)**
  — accepted, documented, and TESTED as the conservative choice: under-boosting
  is safe, and the corroborated-block sweep is unaffected (it iterates meta
  rows directly, blocking the CIDR itself with the right count).
- **[build] Mid-publish chunk failure re-sends the whole delta** — accepted:
  hub `contributeMany` upserts are idempotent; noted in the code comment.
- **[build] Flatfile awk parity is approximate** — accepted: it mirrors the
  existing `swatter_store_perm_ips` replay style; both share the same
  ledger-shape coupling, tested on both stores.
- **[build] mktemp leak risk on early returns** — matches existing house style
  (per-call rm on every path, no global lib traps); the added paths all rm.
- **[build] `_SWARM_CHUNK`/+15 scaling not config knobs** — locked plan
  decisions (YAGNI); documented in Global Constraints.
- **[both] No `cmd_status`/`test-config` swarm surface** — partially reversed:
  `test-config` advisory + `swarm status` added; a `cmd_status` line remains a
  deliberate deferral (the dedicated `swarm status` verb covers it).

Raw outputs: scratchpad `grok-host-plan-{build,composer}.md` (session-local;
substance captured above).
