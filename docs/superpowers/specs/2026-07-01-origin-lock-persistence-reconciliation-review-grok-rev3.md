Adversarial pass on rev2 blockers — I'll trace the real code paths and run the tests, not the commit messages.
## Blockers

- **LOG quoted `-D` still unproven on real iptables-legacy** — `lib/origin_lock.sh:217-220` has the fix; no test exercises it; `test/origin_lock_transition_test.sh` never models that `-D`; Task 3 Step 2 is procedural-only — `disable`/off-teardown remains a gamble until Step 2 passes (not on the csf-hook migration path, but rev2 blocker not closed in tree).
- **`_ol_append`/`_ol_build_set` still swallow all errors** — `lib/origin_lock.sh:103-107,112-114` — CF-ACCEPT can fail silently while DROP still appends; rev2 fail-open-integrity blocker unchanged by `1b9de30`.
- **Post-retire `csf -r` + unhealthy `cloudflare.cidr` installs nothing with no static fallback** — `lib/origin_lock.sh:311-314,326-328` — inherent fail-open-by-design; worse after Step 5; rev2 blocker unchanged.

## Majors

- **`SWATTER_MODE≠enforce` still silently dry-runs at `csf -r`** — `lib/origin_lock.sh:296-302` — `--yes` does not help; plan states verify at `docs/superpowers/plans/2026-07-01-origin-lock-persistence-reconciliation.md:85` but code does not enforce; Step 4 can false-pass on static-only if operator skips the check.
- **Retire breaks `sh` when a control opener precedes the first signature line** — `install/install.sh:127-147` — opener at `lo` leaves outer `if … then` with `fi` swallowed into the here-doc (`sh -n` fails); prod-like ground-truth shape (MODE top-level, `if` only around final DROP) passes; **not tested against the live 56-line csfpre**.
- **Step 4 duplicate-owner trap persists** — `docs/superpowers/plans/2026-07-01-origin-lock-persistence-reconciliation.md:86` — must see *two* CF-ACCEPT/LOG/DROP sets; checking order alone still passes if managed hook silently no-opped.
- **Managed-block placement still unspecified** — plan Step 3 / `install/install.sh:69-94` — static must precede managed in csfpre source order; not mandated in Step 3 text.

## Minors

- **`MODE="DROP"` stays live outside the here-doc after retire** — confirmed prod-like; bare assignment only, nothing post-retire reads it — harmless.
- **LOG rate `10/min` → `5/min`** on migration — `lib/origin_lock.sh:156` vs live ground truth — behavior change, not called out in steps.
- **No test asserts teardown emits quoted LOG `-D`** — `test/origin_lock_test.sh:210` only checks generic `iptables -D INPUT`.
- **Preamble loop `-D` (Task-0 `e0572cb`)** — `lib/origin_lock.sh:234-238`; covered by `test/origin_lock_transition_test.sh:160-168`; no interaction with `1b9de30` code.

### Rev2 blocker disposition (code-traced)

| # | Rev2 blocker | Status |
|---|-------------|--------|
| 1 | `--yes` at `csf -r` | **Closed** — `install/install.sh:91` → `assume_yes=1` at `lib/origin_lock.sh:469` → guard skipped at `:478` → `swatter_origin_lock_apply` at `:496`; `test/install_origin_lock_test.sh:23`, `test/origin_lock_test.sh:126-132` |
| 2 | `SWATTER_MODE` dry-run | **Procedural only** — plan `:85`; code path at `lib/origin_lock.sh:296` unchanged |
| 3 | `_ol_retire_legacy_static` missing | **Closed** — `install/install.sh:117-151`; behavioral test `test/install_origin_lock_test.sh:30-85` (PATH stubs + `sh -n`) |
| 4 | Unsafe line-comment retire | **Closed for here-doc approach** on prod-like fixture; edge case above if opener precedes `lo` |
| 5 | Partial-emit swallow | **Open** (see Blockers) |
| 6 | Unhealthy flush fail-open | **Open** (see Blockers) |
| 7 | LOG `-D` unproven | **Open** (see Blockers) |
| 8 | Digest `^MODE=` | **Closed** — `lib/origin_lock.sh:592-597`; `test/origin_lock_test.sh:319-327` |

**Tests:** `bash test/origin_lock_transition_test.sh` PASS=6; `bash test/install_origin_lock_test.sh` PASS=14; `bash test/origin_lock_test.sh` 60/60. No new regressions from `e0572cb`/`1b9de30`.

**Task 3 sequencing:** Static enforces through Steps 3–4; Step 5 `sh -n` before `csf -r` is a real gate; Step 3 `csf -r` mutates prod before Step 4 but static remains the safety net; duplicate-owner window Steps 3–5 is acceptable if Step 4 confirms managed duplicates before Step 5.

**VERDICT:** Migration-critical rev2 fixes (`--yes`, retire impl, digest) hold in code and tests; execute Task 3 only after Step 2 LOG `-D` validation and explicit `SWATTER_MODE=enforce` + managed-duplicate verification at Step 4 — latent partial-emit and post-retire fail-open blockers remain unchanged and are outside the migration path only while `cloudflare.cidr` stays healthy.
