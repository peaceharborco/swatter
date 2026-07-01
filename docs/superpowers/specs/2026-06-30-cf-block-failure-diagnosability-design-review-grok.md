## Blockers

- **Spec-mandated secret-never-leaks test is missing and `_cf_err_summary` has no redaction** — `lib/block_cf.sh:319-322`, `test/score_test.sh:336-340` — `_cf_err_summary` copies `errors[].message` verbatim (then `cut -c1-200`); if that field ever contains a bearer token or other secret (crafted/proxied body, not just “real CF never echoes”), it is written unchanged to `evidence.backend_err` in `decisions.jsonl`. Acceptance requires driving tolerated shapes through a test that asserts no secret appears; `score_test.sh` covers shapes only, and there is no redaction layer.

## Majors

- **Channel-agnostic slot is CF-only in practice** — `lib/block_csf.sh:30,53`, `lib/score.sh:85-86` — spec says `SWATTER_LAST_BACKEND_ERR` should make CSF/ipset `failed` rows diagnosable “for free,” but only `_cf_block_zone` / `_cf_block_account` set the global; direct-plane failures still produce `failed` rows with no `backend_err`.
- **Several CF `return 1` paths never capture a cause** — `lib/block_cf.sh:222,224,272-274,308` — zone-resolve failure, account-resolve failure, missing jq/curl, and `swatter_cf_manages_plane` belt-return all hit the `failed` branch in `score.sh` with `SWATTER_LAST_BACKEND_ERR` still empty, so those rows dead-end the same way the spec is trying to fix.
- **`backend_err` merge is jq-gated end-to-end** — `lib/score.sh:130-131` — when `SWATTER_HAVE_JQ=0`, the `failed` record is written without `backend_err` even if the global were set; no fallback append to `reason`, so diagnosability silently drops on degraded hosts.

## Minors

- **Text digest `backend-failed:` line has no integration test** — `test/report_test.sh:76-85` — HTML backend-failed is tested only via manually injected `RPT_FAILED`/`RPT_FAIL_CAUSE`; `swatter_report_build` is never fed synthetic `action=="failed"` rows with `evidence.backend_err`.
- **Cross-plane bleed is untested** — `test/backend_err_test.sh:33-39` — code clears at `_swatter_execute_block:62` before the plane dispatch, so CF→CSF cross-IP bleed looks safe, but there is no test for “IP1 CF fail, IP2 direct CSF fail” (would expect empty `backend_err`, not IP1’s error).
- **`test/backend_err_test.sh` is untracked** — not in the committed diff; `make test` will run it locally but CI won’t until it’s added.
- **Account partial failure keeps last hash-order error only** — `lib/block_cf.sh:281-291` — sane for retry semantics, but which `backend_err` is recorded/digested is nondeterministic across bash associative-array iteration order when multiple accounts fail differently.

## Mandated-check notes (not elevated)

1. **Cross-IP bleed:** Dual reset at `score.sh:62` and `block_cf.sh:304` is sufficient for CF↔CF, CF success→CF fail, and CF fail→CSF fail across IPs; no path reaches the `failed` branch with a prior IP’s global without a fresh clear first.
2. **Duplicate-as-success:** `_cf_create_ok` (`block_cf.sh:186-195`) is untouched; dup path still returns 0 and never sets the global (`block_cf_test.sh:61-62`).
3. **Account scope:** Partial success correctly returns 1; last failing account’s summary is kept — representative enough.
4. **Grade:** `_report_grade` (`report.sh:323-334`) ignores `RPT_FAILED`; failures do not escalate the report card.
5. **`set -u`:** `${RPT_FAILED:-0}`, `${RPT_FAIL_CAUSE:-}`, `${SWATTER_LAST_BACKEND_ERR:-}` are guarded.

**VERDICT:** Core CF API-error threading and cross-IP isolation look sound, but shipping without a secret-scrubbing guarantee (or the spec’s leak test) risks credentials in `decisions.jsonl`, and half the failure surface (non-API CF paths, CSF/direct) still won’t self-diagnose.
