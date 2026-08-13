# Design review — foghorn liveness cross-check

Consolidated from two adversarial passes (grok-4.6 and grok-4.5, plan-review
lens) over **rev 1** of `2026-08-12-foghorn-liveness-design.md`, 2026-08-13.

**Both verdicts: RETHINK.** The feature survives; three of rev 1's four
structural choices did not. Rev 2 answered part of it and was itself
insufficient; rev 3 in the design doc is the response.

## Blockers, both passes agreeing

1. **The same-window request count cannot separate `absent` from "could not
   look".** Foghorn may be a primary writer of ACCESS_LOG, so its death
   empties the window and suppresses the finding. Decisive framing: *you
   cannot have "no false alarm on idle" and "catch foghorn dying as the only
   writer" from one same-window total.* Rotation mid-window adds a false
   `absent`; rotation to an empty inode adds a miss.
   → **Rev 3:** coverage window (24h, satisfied by foghorn's own earlier
   lines) decoupled from the probe window (1h). Rotated siblings read.

2. **The silence gate swallows it on the night it is the only news.**
   `lib/report.sh:720-731` sends nothing when abuse, origin-lock and errors
   are all quiet — i.e. the cleanest "monitor died" night.
   → **Rev 3:** all verdicts break silence; status subline and subject too.

3. **Rev 1 named the timezone trap and proposed walking into it.** Two
   correct parsers already exist in-tree; a third is how v2.15.0 regressed.
   `ingest.sh` needs gawk's `mktime`, which BSD awk lacks.
   → **Rev 3:** adopt `corroborate.sh`'s mktime-free minute keys.

4. **`lib/watchdog.sh` "surfaced by report.sh" misread the digest.**
   `bin/swatter:67` is an explicit source list; `install.sh` copies `lib/*.sh`,
   so the file can be installed and never sourced. A fifth plane needs a
   tempfile + `declare -F` guard, HTML rendering, a `cmd_test_config`
   readiness line, and a stub in the hermetic `report_test.sh`.
   → **Rev 3:** §6 rewritten as the actual touchpoint list.

## Majors

- **`ENABLE=false` makes the release a no-op on cds1.** Open question in §8.5.
- **Escalation:** do not create a RED; force the mail and put it on the
  status line. Matches the operator's decision, sharpens where it lands.
- **Cost:** ACCESS_LOG is 554,485 lines; a nightly full scan is out.

## Measured, not assumed

Non-foghorn lines/hour in cds1's ACCESS_LOG, 2026-08-13: 911, 527, 387, 456,
606, 292. Foghorn is ~60/hour — 6-17% of the channel. Blocker 1's mechanism
is real; its magnitude on this host is not fatal today. Rev 3 removes the
dependence anyway rather than betting on traffic staying that way.

## Raw passes

Scratchpad only, not committed: `sw-design-grok-4.6.md`, `sw-design-grok-4.5.md`.
