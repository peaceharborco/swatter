# Grok review — csf-channel-enforcement sketch (consolidated)

Two models, parallel, read-only: **grok-4.5** (`[build]`) and
**grok-composer-2.5-fast** (`[composer]`). `[both]` = flagged by both. Every
finding below verified against the actual code before acceptance.

Both VERDICTs: **do not implement as written.** Root-cause direction is right;
the ledger semantics and dual-plane mechanism are wrong.

## Blockers

- **B1 [both] `is_perm_on` counts live temps as "perm on plane" → breaks the
  temp→perm escalation ladder.** The `active_planes` set includes unexpired
  `temp` rows; the scan sketch short-circuits `noop-perm` on it. Today only a
  true global perm short-circuits (`lib/score.sh:254`); a live temp still
  re-enters the ladder and escalates via `recent_temp_count`
  (`lib/store_sqlite.sh:87`). Fix: `is_perm_on` must query **`action='perm'`
  only**, never the temp-inclusive set.
- **B2 [both] `active_planes` ignores `unblock` → cannot re-block after unblock.**
  `swatter_store_unblock` sets `offenders.perm=0` but leaves the historical
  `perm` action row (`lib/store_sqlite.sh:174-179`). Deriving plane state from
  the append-only `actions` log returns the stale plane forever →
  `noop-perm` while the firewall is clear. `swatter_store_perm_ips`
  (`:222-228`) avoids this by requiring `offenders.perm=1`; the sketch had no
  equivalent.
- **B3 [both] Dual-plane can't force a plane through `_swatter_execute_block`.**
  That function always re-runs `swatter_classify` (`lib/score.sh:99`) with no
  force argument, so a second call re-picks the **same** plane. Intel-100 with
  only via-CF evidence → primary CF rule → "second plane" re-classifies VIA_CF →
  a second CF call, **never a CSF deny**. Dual-plane as sketched is a no-op.
- **B4 [both] `active_planes` omits `dry_run=0` → report-mode rows poison it.**
  Report mode records the action with `dry_run=1` (`lib/score.sh:123`). Every
  other real-block query filters `dry_run=0` (`lib/store_sqlite.sh:92,226`).
  Without it, a dry-run perm makes `is_perm_on` true after the enforce flip →
  **never places a real block.**
- **B5 [both] `channel IN ('csf','cloudflare')` drops the `ipset` backend.**
  Channel is `${DIRECT_BACKEND:-csf}` = `csf|ipset|cloudflare`
  (`lib/score.sh:104`, `lib/report.sh:160`). On `DIRECT_BACKEND=ipset` the query
  never returns `ipset` → broken noop/upgrade semantics.
- **B6 [composer Blocker / build Major → Blocker] Source 3 must mirror Source
  2's health gate + CF-range filter.** Source 2 only folds socket peers when
  `swatter_allowlist_healthy` and excludes CF peers (`lib/classify.sh:255-260`).
  If Source 3 skips that, a CF-edge-ish peer lands in the DIRECT set → misclassify
  DIRECT; combined with any un-gated CSF write that's the outage mode. Must
  reuse Source 2's guard exactly.

## Majors

- **M1 [both] Dual-plane second leg must pass the `never_block` + unsafe-target
  gates**, not just fail-closed + caps. Those gates (incl. Cloudflare ranges) sit
  at the top of `_swatter_execute_block` (`lib/score.sh:82-92`,
  `lib/allowlist.sh:218-221`). A forced-plane helper that calls the backends
  directly would skip them — CSF of a CF edge is still the outage.
- **M2 [both] The dual-plane safety rationale is stated wrong.** The invariant is
  "never CSF-deny a **Cloudflare edge IP**," enforced by `never_block` — not
  "intel-100 is never a visitor." Swatter denies the **logged client IP**, not
  the TCP socket, so CSF-denying a via-CF-only intel-100 does **not** firewall
  the proxy. The real residual risk is a **false-positive intel-100** getting
  locked off origin service ports (user lockout), which the rationale must own.
- **M3 [both] Caps described incorrectly.** *Every* successful block increments
  `_SW_TOTAL_BLOCKS`/`MAX_BLOCKS_PER_RUN` (`lib/score.sh:93,120`); CSF *also*
  increments `SWATTER_CSF_DENIES_THIS_RUN`/`MAX_CSF_DENIES_PER_RUN`
  (`lib/block_csf.sh:14`). Dual-plane = up to 2× toward the breaker; a leg that
  bypasses `_swatter_execute_block` skips the breaker entirely.
- **M4 [both] Honeypot path still global-`noop-perm`s** (`lib/score.sh:246-248`) —
  same incident-class bug, not updated by the sketch.
- **M5 [both] Unblock-symmetry claim is false.** `cmd_unblock` already drops both
  planes (`bin/swatter:157-158`). Nothing to extend; test 7 is coverage, not
  behavior. The real unblock bug is B2 (ledger).
- **M6 [both] Audit-label contradiction.** Upgrade calls `_swatter_execute_block
  … "perm"` → audits `action=perm`, but tests/digest expect `plane-upgrade`
  (`report.sh` keys on `.action`). Pick one and test it.
- **M7 [both] Flatfile fallback is wrong** — perm-only grep with no unblock
  replay, temp expiry, or `dry_run` filter (same bugs as B1/B2/B4).
- **M8 [both] Global `offenders.perm`/`channel` last-write-wins is unchanged.**
  Per-plane tracking is query-only, so `swatter_store_perm_ips`, export, and
  swarm stay global and can desync from "blocked on both planes."
- **M9 [build] Fail-closed + DIRECT + intel-100 is incompatible with Test 4
  without restructuring.** On DIRECT + unhealthy, `_swatter_execute_block`
  returns before any CF work (`lib/score.sh:105-107`), so a post-`did=1`
  dual-plane leg never runs. Verified. Needs an explicit "attempt CF for
  hard-intel even when CSF is fail-closed" path.
- **M10 [build] Swarm path keeps the global short-circuit** (`lib/swarm.sh:182`)
  — fleet-consumed CF-perm IPs never upgrade. Verified.
- **M11 [both] Source 3 legit-session hazard + IPv6 gap + sampling.** Operator
  WHM, backup, monitoring, or a customer on a direct webmail IP:port folds into
  the DIRECT set exactly like a flooder; only the existing operator/monitoring
  allowlists (`lib/allowlist.sh:223-239`) save them. `_swatter_websocket_peers`
  is IPv4-only (`lib/classify.sh:195`); `ss` is a point-in-time sample (short
  floods can miss a window — detection lag, not an invariant break).

## Minors

- **[both] Schema/`_sqlq` assumptions are fine** — `actions` has
  `ts,ttl,channel,action,dry_run` (`lib/store_sqlite.sh:34-36,65`); it's the
  WHERE semantics that were wrong.
- **[both] `rep` is in scope** in `_swatter_execute_block` (`lib/score.sh:75`) —
  that part of the dual-plane placement is OK.
- **[composer] abuseipdb double-report** on dual success (`lib/score.sh:125`) —
  guard it.
- **[build] Dual-plane gate needs `action==perm`** too — prose says "at first
  perm" but the sketched gate only checks `rep`, so temps would dual-plane.
- **[both] New config** `DUAL_PLANE_HARD_INTEL`/`INTEL_HARDBLOCK_MIN` must ship
  with defaults + docs (Spamhaus DROP already emits 100,
  `lib/providers/spamhaus.sh:31`).
- **[both] flock** serializes scans (`lib/common.sh:453`); cross-run race is low.
- **[both] Dry-run must not increment the CSF counter** — dual-plane dry-run
  must match (`lib/block_csf.sh:18`).

## Disposition
All Blockers + M1–M8, M10, M11 accepted and folded into sketch v2. M9 accepted
(drives the restructure to a forced-plane helper). M10 (swarm) folded in scope
(§2b). Minors folded or noted.
