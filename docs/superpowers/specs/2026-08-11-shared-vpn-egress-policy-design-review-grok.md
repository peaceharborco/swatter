# Consolidated adversarial review — shared consumer-VPN egress policy

**Target:** `2026-08-11-shared-vpn-egress-policy-design.md`
**Date:** 2026-08-11
**Reviewers:** grok-4.5 ×2 (lens mode — only one model family on the roster:
Pass A = correctness skeptic, Pass B = safety/edge-case red-teamer), plus
Claude-side `[code-review]` / `[security-review]` / `[gap]` sweeps.
**Grok verdicts:** Pass A **EXECUTE-WITH-FIXES** · Pass B **EXECUTE-WITH-FIXES**
**Read-only guard:** `git status --short` clean before and after both passes.

Provenance tags: `[both]` = both Grok passes · `[pass-a]` / `[pass-b]` = one pass
· `[gap]` / `[security-review]` = Claude-side sweep · `[claude]` = found only in
the final adjudication pass.

---

## Blockers

### BL1 `[both]` — the sweep remediates with **never-block**, contradicting the design's own rejected alternative

`--fix` was specified as `swatter allow` + `swatter unblock --perm-allow`.
`cmd_allow` appends to `OPERATOR_ALLOW_FILE`, which `swatter_is_never_block`
honors as a **full exemption** (`lib/allowlist.sh:260-261`). The design elsewhere
rejects exactly this control for the WARP range.

WARP egress addresses **rotate between clients**. A per-IP never-block therefore
becomes a standing free pass for whichever future client receives that address —
disabling temps too, which the forward veto never intended.

Compounding it: `cmd_allow` runs *before* the failure check, and
`swatter_store_unblock` (`bin/swatter:168`) runs before the check at `:175`. A
partial backend failure leaves the IP allowlisted **and** flagged remediated
while CSF or CF may still deny it.

`rollback-ladder` (`bin/swatter:571-603`) already models the right bulk pattern:
unblock **without** allowlisting, continue past partial failures, report PARTIAL.

**Fix:** `--fix` is unblock-only. Allowlisting requires a separate explicit flag
with a printed never-block warning. Forward enforcement is the veto's job.

**Operational consequence — carried out of this review:** the 7 IPs allowlisted
during the 2026-08-11 unfreeze (4 WARP + 3 AS206092) are currently permanent
never-blocks and should be converted to plain unblocks once the veto ships.

### BL2 `[pass-a]` — downgrading `action` alone desyncs `audit_action`, and the digest reads the audit log

`audit_action` is bound once at entry (`lib/score.sh:128`,
`audit_action="${11:-$3}"`) and is **not** updated by a later `action="temp"`.
The success audit uses it (`lib/score.sh:212`), and the nightly digest counts
perms from those audit records, not the ledger:

```
lib/report.sh:160   RPT_PERM=$(... 'select(.action=="perm")' ...)
```

So a capped shared-egress hit would write `temp` to the firewall and the ledger
while `decisions.jsonl` says `perm` — inflating the digest's permanent-block and
repeat-offense counts, and making `swatter why` lie.

Verified independently at both file:line references.

The design's claim that the AbuseIPDB and tripwire sinks stay correct is *true
but accidental*: both currently pass only because `audit_action != action` after
the downgrade. That is a fragile reason to be right.

**Fix:** the veto sets **both** `action` and `audit_action`. Tests assert the
audit field, not just backend + ledger.

### BL3 `[both]` + `[gap]` — `import-bans` is a fifth perm path, outside the chokepoint

`cmd_import_bans` calls `swatter_block_direct_perm` directly and writes the perm
rows itself (`bin/swatter:468-473`), never touching `_swatter_apply_plane`:

```
if swatter_block_direct_perm "$ip" "imported ban"; then
    swatter_store_record "$ip" perm "$channel" 0 90 "imported ban" "$dry"
    [[ "$dry" == 0 ]] && swatter_store_plane_set "$ip" "$channel" perm 0
```

It sets `offenders.perm=1` and writes an enforced `actions.action='perm'` row —
precisely what `swatter_store_perm_ips_since` publishes. So the design's "every
perm path is covered" and "swarm cannot see it" are both false for imports, and
a fleet `export-bans` → `import-bans` can reintroduce WARP perms.

It checks `swatter_is_never_block` (`:467`) but nothing else.

**Fix:** gate `import-bans` with the same shared-egress check, or route it
through `_swatter_apply_plane`. Either way the prose stops claiming "every path"
until it is true.

### BL4 `[pass-b]` + `[gap]` — no `/0` guard on `shared-egress.cidr`; one line disables all permanent banning

`_ip_in_cidr_file` treats a zero-length prefix as match-everything:

```
lib/allowlist.sh:121   if (len == 0) { found=1; exit }
```

A single `0.0.0.0/0` (or `::/0`) line in the new file silently caps **every**
perm host-wide — honeypot and ladder both defanged, for all traffic. It fails in
the "don't ban" direction, which is the direction nobody notices, and the only
signal is a per-IP `log_warn`.

The repo already solved this class for intel feeds:
`swatter_intel_cidr_feed_ok` (`lib/common.sh:597`) rejects `/0` and anything
broader than `/8` v4 / `/16` v6 in global unicast.

**Fix:** validate `shared-egress.cidr` with that guard (or a tighter floor — the
failure direction here differs from the intel case, so a `/8` is still far too
broad). Consider a rate alert on caps-per-run, mirroring `PERM_RATE_ALERT_*`.

### BL5 `[pass-b]` — residual evasion is real and was never quantified

With perms impossible on shared egress, measured against the live knobs
(`TTL_LADDER="3600 21600 86400 259200"` → cap = **72h**; scan `*/5`;
`MAX_BLOCKS_PER_RUN=25`):

| Path | Today | After the design |
|---|---|---|
| Honeypot (single request) | permanent | **72h temp**, no publish, no report |
| Ladder at `REPEAT_N` | permanent | 72h temp, then clean |
| Rotation inside `104.28.0.0/16` | each address eventually dies permanently | 65,536 independent clocks, each returning within 72h |

This is not equivalent to unbanned for a noisy attacker — temps still land every
5 minutes — but the one-shot permanent honeypot path is genuinely defanged on
shared egress, and patient rotation across the /16 becomes a recurring free pass.

**Fix:** state this explicitly as accepted residual risk, and decide deliberately
whether 72h is the right cap or a shared-egress-specific longer floor is
warranted.

---

## Majors

| # | Source | Finding |
|---|---|---|
| M1 | `[both]` | **AS13335 wholesale ≠ "precisely WARP."** Never-block covers only the published edge lists, so any AS13335 address outside them — new edge ranges before a refresh, other Cloudflare product egress, multi-origin first-ASN quirks (`asn_test.sh:29-31` takes the first) — gets the same cap. Ship **CIDR-only** defaults; add ASNs only with documented evidence (AS206092 has it). |
| M2 | `[both]` | **`_swatter_ev_stamp` is integer-only** (`lib/score.sh:98`: `[[ "$val" =~ ^[0-9]+$ ]] \|\| return original`). A string label silently no-ops. Use `shared_egress=1`; keep the label in `reason`. |
| M3 | `[claude]` | **New hole created by fixing BL2.** Once `audit_action` is also set to `temp`, the guard at `lib/score.sh:208-209` becomes `audit_action == action` → true, and with `ABUSEIPDB_REPORT_MIN_ACTION=temp` the second clause is also true — so a capped shared-egress temp **would be reported**. The publication protection must not rest on the perm/temp distinction; add an explicit shared-egress guard on the AbuseIPDB call. |
| M4 | `[both]` | **Test plan does not pin the load-bearing invariants** — missing: audit-field assertion, `import-bans`, dual-plane/plane-upgrade legs, pending-retry of a queued perm, `/0` rejection, poisoned ASN cache, second honeypot after expiry, `--fix` partial failure, AS13335-outside-`104.28/16`, IPv6. |
| M5 | `[pass-a]` + `[gap]` | **Packaging unspecified.** Peer pattern (`install/install.sh:232-235`) installs `hosting-asns.txt` only if absent and always ships a `.example` to diff. Design must also cover `SHARED_EGRESS_*` in `lib/common.sh` + the example conf, and CLI dispatch wiring for `shared-egress-audit`. |
| M6 | `[pass-b]` | **`--fix` lacks bulk safety** `rollback-ladder` already has: one `swatter_with_state_lock` for the whole run, continue-on-partial with an ok/bad summary, hard-fail if verification fails, and a count gate requiring confirmation above N. |
| M7 | `[pass-b]` | **Rollback honesty.** `SHARED_EGRESS_ENABLE=false` does not re-perm anything already capped or swept, and with BL1 unfixed it cannot re-enable enforcement on allowlisted IPs until the allow entries are removed. |
| M8 | `[both]` | **IPv6 shared egress is DNS-only** — no static v6 range ships, so an offline resolver plus fail-open leaves IPv6 WARP uncapped. |
| M9 | `[pass-b]` + `[security-review]` | **DNS is an unauthenticated downgrade oracle.** ASN resolution is plain TXT with no DNSSEC (`lib/common.sh:680-686`), cached 24h (`INTEL_CACHE_TTL=86400`). Today a forged answer can only *raise* an IP's score (hosting → `+W_ASN`); this design makes a forged answer able to *lower* enforcement for the first time. Blast radius is per-IP and `STATE_DIR` is `0750`, so this is bounded — but it is a new property and must be stated. CIDR-first ordering removes DNS from the WARP IPv4 path, which is the main mitigation. |

---

## Minors

| # | Source | Finding |
|---|---|---|
| m1 | `[both]` | **Line drift.** `swatter_store_unblock` is `bin/swatter:168` and the failure check `:175` — the design (and `TODO.md`) say `:167` / `:174`. Fix both. |
| m2 | `[pass-b]` + `[security-review]` | ASN cache **read** (`lib/asn.sh:19`) `cat`s the file with no re-validation, while the write path validates `^[0-9]+$` (`:37`). Cheap hardening. |
| m3 | `[pass-a]` | The preceding `swatter allow` is partly redundant — `unblock --perm-allow` already calls `cmd_allow` (`bin/swatter:169`). Nuance: the explicit call preserves a richer note, since the inner call no-ops as "already allowed". Moot once BL1 removes allowlisting from `--fix`. |
| m4 | `[pass-a]` | **Positive, design was silent:** `_swatter_retry_pending` re-enters `_swatter_apply_plane` with the stored action (`lib/score.sh:484`), so queued pre-deploy WARP perms get capped on drain. Add a note and a test. |
| m5 | `[claude]` | **Positive, strengthens the design:** on the Cloudflare plane a "perm" is already TTL-emulated at ladder max (`lib/score.sh:168` → `_swatter_pick_ttl 99` → 259200s). So capping a CF-plane perm to a ladder-max temp yields the **identical enforcement duration** — the change there is ledger/publication only. The real behavioral change is confined to the DIRECT/CSF plane (never-expiring → 72h). This materially narrows BL5's residual risk and should be stated. |
| m6 | `[pass-b]` | `SHARED_EGRESS_ENABLE=true` by default is an immediate behavior change on upgrade; RUNBOOK/CHANGELOG must call it out. |
| m7 | `[pass-b]` | Specify that `shared-egress-audit` takes the state lock, as `rollback-ladder` does. |

---

## Verified-correct claims (no action)

- Ordering: `swatter_is_never_block` runs at `lib/score.sh:142-145`, before the
  proposed insertion point. `[pass-a]`
- The four **scan** perm paths do all funnel through `_swatter_apply_plane`
  (honeypot `:588`, ladder `:608`, dual-plane `:312`/`:364`, plane-upgrade
  `:323`/`:341`), as does pending retry. `[both]`
- `_swatter_pick_ttl 99` clamps to the last ladder rung = 259200s. `[both]`
- Suppressing `offenders.perm` does remove an IP from
  `swatter_store_perm_ips_since` — for the forward scan path. `[both]`
- Degraded modes (missing/empty/unreadable files, DNS failure) fail open.
  `[pass-b]`
- Measurement gap closed during review: all 11 IPv6 at-bar IPs resolve to
  hosting/VPS ASNs, zero shared consumer VPN — the 8-of-106 sizing holds.
  `[claude]`

---

## Disposition

All 5 blockers and all 9 majors accepted; none declined. The core approach —
identify shared egress, veto at `_swatter_apply_plane`, CIDR-first with a short
evidence-backed ASN list, no never-block of the range — survived both passes
intact. What failed review was the **completeness** of the claims around it and
the **sweep's** remediation mechanism.

BL1 carries a live operational consequence requiring an operator decision (the 7
IPs allowlisted 2026-08-11).
