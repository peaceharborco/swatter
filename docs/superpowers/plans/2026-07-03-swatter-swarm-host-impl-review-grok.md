# Swarm HOST implementation review — Grok two-model pre-ship pass

Adversarial review of the `feat/swarm-host` implementation (all 9 plan tasks)
before merge. Both models ran headless, read-only, same brief, verifying the
branch diff against plan v1.1's invariants. **Both verdicts:
REVISE-BEFORE-SHIP** — no blockers; the majors below were fixed on the branch
(commit "harden swarm host per pre-ship review"), full bash + hub suites green
after.

Provenance: `[both]` / `[build]` / `[composer]`.

## Fixed

- **[both] `cmd_swarm` never called `swatter_init_dirs`** — `swatter swarm
  enroll` as the FIRST command on a fresh box failed writing
  `$STATE_DIR/swarm.host_id`. → init_dirs at the top of `cmd_swarm` (exposed a
  test-env gap in `curl_secrets_test.sh`, which now sets `LOG_DIR`).
- **[composer] Cursor advanced on a bare 200 without a positive ack** — an
  empty/truncated/garbled response body passed the `enrolled:false` check and
  advanced the cursor past undelivered bans (probe-confirmed with a body-less
  200). → publish now requires the hub's literal `"enrolled":true` ack; new
  tests: no-ack keeps cursor, retry after real ack advances.
- **[build] Sweep not gated on `swarm ∈ INTEL_PROVIDERS`** — removing `swarm`
  from the provider list (the documented way to stop consuming) left lingering
  fresh meta proactively blocking until it aged out. → membership gate added;
  test: fresh corroborated meta + provider removed ⇒ zero dispatches.
- **[composer] JSON sidecar fetch ignored curl's transport rc** — a partial
  code with transport failure could keep bad meta. → `mcrc` checked alongside
  the HTTP code.
- **[composer/build] Empty-200 stubbed meta as `[]` while sidecar failure
  deleted it** — asymmetric fresh-or-absent. → empty-200 now `rm -f`s meta too.
- **[build] Sweep log claimed "N blocks applied"** — `_swatter_execute_block`
  returns 0 on skipped-novhost/failed paths too. → reworded to "dispatched
  through the block gate (outcomes in decisions.jsonl)".
- **[composer] No secrets case for purge** — `curl_secrets_test.sh` case 13
  added (write token via `-K` on `--yes` path). 24 → 26 assertions.

## Accepted / declined (with reasons)

- **[composer] sweep test exits 0 when jq is absent (false-green in the
  release gate)** — accepted: dev (macOS) and prod both have jq; the skip
  prints a distinct message; making it fail would break the gate on jq-less
  boxes for a feature that is itself jq-gated with a warn.
- **[build] bash-4.2 `${ips[@]:i:_SWARM_CHUNK}` slice** — accepted: the slice
  is only reached after `(( ${#ips[@]} )) || return 0` and under
  `i < ${#ips[@]}`, so the empty-array-under-`set -u` case cannot occur.
- **[build] purge batch intra-batch visibility pinned only by the endpoint
  test** — accepted: D1 `batch()` is documented as a sequential transaction;
  the endpoint test asserts the exact observable contract.
- **[composer] `swarm status` pings /health unauthenticated (noise on
  air-gapped boxes)** — cosmetic, declined.
- **[build] mktemp cleanup lacks traps on exotic signal paths** — matches the
  repo's established per-call `rm -f` pattern at every curl site.

## What both models verified as holding

Frozen consume obligations (empty-200-clears without `swatter_cidr_list_ok`;
keep-last-good only on non-200/transport/poison; fresh-or-absent meta); four
outbound publish gates; sweep exclusively via `_swatter_execute_block` with the
correct 10-arg signature and `_SW_TOTAL_BLOCKS` breaker scope; no secret in
argv/logs/decisions; zero behavior change for operators who never set
`SWARM_*`; all tests stdin-closed-safe with no ordering dependence.

Raw outputs: scratchpad `grok-host-impl-{build,composer}.md` (session-local).
