# Design — shared consumer-VPN egress policy (perm cap)

**Status:** revision 2, 2026-08-11 — **post adversarial review**. Review at
`2026-08-11-shared-vpn-egress-policy-design-review-grok.md` (two grok-4.5 passes,
both EXECUTE-WITH-FIXES, plus Claude-side sweeps). All 5 blockers and 9 majors
folded below; none declined. Revision 1's completeness claims were wrong in three
places — see "What review changed" at the end.
**Origin:** found during the 2026-08-10/11 publication unfreeze (see
`docs/handoff-2026-08-04-unfreeze-and-gate-d.md` §1 and the `TODO.md` section
"Cloudflare WARP + shared consumer VPN exits").

## Problem

Swatter permanently bans IPs that are **shared consumer VPN egress** — addresses
used simultaneously by many ordinary people. A permanent ban on one blocks every
legitimate user assigned that egress IP from every customer site, forever, and
publishing it recommends that other hosts do the same.

The trigger case is `104.28.0.0/16`, Cloudflare's **consumer WARP** egress pool
(the 1.1.1.1 app). It is announced by AS13335 but is **not** in Cloudflare's
published edge IP list, so it is not in `cloudflare.cidr` — that file covers
`104.16.0.0/13` + `104.24.0.0/14` (104.16–104.27) and stops one block short.

This is **not** a detection false positive. Most of these carry
`abuseipdb confidence100` and `rule=critical_badpath` at score 91; someone
genuinely probed critical paths from behind the VPN. The defect is that the
*response* — a permanent, published ban — is disproportionate to a **shared**
identifier.

### Measurements (cds1, 2026-08-11)

| Measure | Value |
|---|---|
| `104.28.0.0/16` distinct IPs temp-banned, lifetime | 77 |
| `104.28.0.0/16` distinct IPs perm-banned, lifetime | 13 (4 cleared 2026-08-11, **9 still live**) |
| WARP IPs temp-banned, last 14d | **22 distinct** (33 rows), ~1.6/day |
| WARP IPs perm-banned by month | 6 (Jun), 6 (Jul), 4 (Aug) |
| IPs at/over `REPEAT_N=3` in a 30d window | 106 |
| …of those, shared consumer VPN | **8 (7.5%)** — 6 WARP + 2 AS206092 |
| …of those, IPv6 | 11, **all** hosting/VPS ASNs, zero shared VPN |

The problem is **live and recurring**. Four fresh WARP IPs and two more AS206092
IPs are at or over the escalation bar now.

The shared-VPN slice is small (8 of 106) and ASN-identifiable, so this is a
**curated-list problem, not a feed problem**. A short hand-vetted list suffices.

### Why this gates the AbuseIPDB unfreeze

`ABUSEIPDB_REPORT` has no backlog — it reports perms placed *after* the flip, and
AbuseIPDB has no delete API. With WARP producing ~4 perm IPs/month and six
shared-VPN IPs already at the bar, flipping that arm first makes an irreversible
report of shared consumer VPN egress near-certain within weeks. **Land this
first, then flip `ABUSEIPDB_REPORT`.**

## Non-goals

- Tuning `request_flood` — separate `TODO.md` item, unrelated rule.
- Gate D / `REPEAT_WINDOW_DAYS` — see "Interaction with gate D".
- Changing what gets **scored**. This caps what gets **enforced**.
- Any blanket allowlist of a VPN range. Every CIDR in `allow.cidr` /
  `cloudflare.cidr` / `monitoring.cidr` is a **never-block**, so allowlisting the
  WARP pool would let any attacker bypass swatter entirely via the 1.1.1.1 app.
  **This applies per-IP too** — see §4.

## Accepted residual risk

Capping at temp is a real reduction in enforcement, and the design accepts it
knowingly. Measured against the live knobs (`TTL_LADDER="3600 21600 86400
259200"` → cap **72h**; scan `*/5`; `MAX_BLOCKS_PER_RUN=25`):

| Path | Today | After |
|---|---|---|
| Honeypot (single request) | permanent | **72h temp**, unpublished, unreported |
| Ladder at `REPEAT_N` | permanent | 72h temp, then clean |
| Rotation inside `104.28.0.0/16` | each address eventually dies permanently | 65,536 independent clocks, each returning within 72h |

Not equivalent to unbanned — temps still land every 5 minutes against a noisy
attacker. But the one-shot permanent honeypot path is genuinely defanged on
shared egress, and patient rotation across the /16 becomes a recurring free pass.

**Two facts narrow this materially:**

1. **On the Cloudflare plane the cap costs nothing.** A CF "perm" is already
   TTL-emulated at ladder max (`lib/score.sh:168` rewrites ttl via
   `_swatter_pick_ttl 99` → 259200s). So a capped CF perm and an uncapped one
   have the **identical enforcement duration**; only the ledger row and
   publication change. The real behavioral change is confined to the DIRECT/CSF
   plane, where a perm never expires.
2. The measured population is 8 of 106 at-bar IPs, all on two ASNs.

72h (ladder max) is the deliberate choice, not an accident of reuse. A
shared-egress-specific longer floor was considered and rejected as premature —
revisit if rotation abuse is actually observed.

## Design

### 1. Identification — `lib/asn.sh`

```
swatter_is_shared_egress <ip>
  -> echoes a short label, returns 0 if shared consumer egress
  -> returns 1 otherwise
```

Checked in cost order:

1. **`SHARED_EGRESS_CIDR_FILE`** (default `/etc/swatter/shared-egress.cidr`) —
   static ranges via the existing `_ip_in_cidr_file`. **No network dependency.**
2. **`SHARED_EGRESS_ASNS_FILE`** (default `/etc/swatter/shared-egress-asns.txt`)
   — `<asn> # name`, identical in format and parsing to `HOSTING_ASNS_FILE`,
   resolved through the existing `swatter_asn_resolve` (per-IP cache under
   `$STATE_DIR/asn/`, IPv6 via `origin6.asn.cymru.com`).
3. **Fail open** — no CIDR match and no ASN answer returns 1 (today's behavior).

Gated by `SHARED_EGRESS_ENABLE` (default `true`).

Callers must have validated the IP first. `_swatter_apply_plane` does
(`:135`, before the insertion point), which matters because the ASN cache key is
the raw IP string.

#### Mandatory `/0` guard

`_ip_in_cidr_file` treats a zero-length prefix as match-everything
(`lib/allowlist.sh:121`: `if (len == 0) { found=1; exit }`). A single `0.0.0.0/0`
line would silently cap **every** perm host-wide, failing in the direction nobody
notices.

`shared-egress.cidr` is therefore validated with the existing
`swatter_intel_cidr_feed_ok` (`lib/common.sh:597`) — which already rejects `/0`
and anything broader than `/8` v4 / `/16` v6 in global unicast — **with a
tightened floor**, because the failure direction here is under-banning rather
than over-banning and a `/8` would still be catastrophic. A file that fails
validation is rejected whole and logged loudly; the veto then behaves as if the
file were absent (fail open).

Additionally, the run emits a **cap count** so mass-capping is visible rather
than silent, mirroring the intent of `PERM_RATE_ALERT_*`.

#### Shipped defaults — CIDR-only

```
# shared-egress.cidr
104.28.0.0/16  # Cloudflare consumer WARP egress
```

```
# shared-egress-asns.txt  — empty by default; entries require documented evidence
# 206092 # F.N.S. Holdings / "VPN Consumer" — consumer VPN exits (cds1: add locally)
```

Revision 1 shipped `13335` (all of Cloudflare) on the argument that only WARP
reaches this check. **Review falsified that.** `swatter_is_never_block` covers
only the *published edge lists*, so any AS13335 address outside them — a new edge
range before a refresh, other Cloudflare product egress, or a multi-origin prefix
where `swatter_asn_resolve` takes the first ASN (`test/asn_test.sh:29-31`) —
would get the same cap. The `/16` is the precise instrument; the ASN is a coarse
second factor. Shipping it by default in a public repo would widen the evasion
surface beyond the measured problem.

`206092` is evidence-backed (whois: netname `PARIS-FR-45-157-112-0`, org
"VPN Consumer Paris, France") but is a **cds1-local** entry, not a default,
because it is one host's observation.

#### IPv6

No static v6 range ships, because none is known for WARP egress. IPv6 shared
egress therefore depends on ASN resolution alone, and fail-open means an offline
resolver leaves IPv6 WARP uncapped. Accepted: the measured IPv6 at-bar cohort is
11 IPs, **all** hosting/VPS, zero shared VPN.

#### DNS residual risk

ASN resolution is plain unauthenticated TXT (`lib/common.sh:680-686`), cached 24h
(`INTEL_CACHE_TTL`). Today a forged answer can only *raise* an IP's score
(hosting ASN → `+W_ASN`); this design makes a forged answer able to *lower*
enforcement for the first time. Bounded — per-IP blast radius, `STATE_DIR` is
`0750` — and CIDR-first ordering removes DNS from the WARP IPv4 path entirely,
which is the main reason defaults are CIDR-only. The cache **read** path
(`lib/asn.sh:19`) additionally gains the `^[0-9]+$` validation that currently
guards only the write path (`:37`).

### 2. The veto — `lib/score.sh`, inside `_swatter_apply_plane`

Inserted after the never-block check (`:145`) and before the
`MAX_BLOCKS_PER_RUN` check (`:146`):

> If `action == "perm"` **and** `SHARED_EGRESS_ENABLE` **and**
> `swatter_is_shared_egress "$ip"`:
> - `action="temp"`
> - **`audit_action="temp"`** — see below; omitting this was a blocker
> - `ttl="$(_swatter_pick_ttl 99)"` — ladder maximum
> - append `shared-egress=<label> perm-capped` to `reason`
> - `ev="$(_swatter_ev_stamp "$ev" shared_egress 1)"` — **integer only**;
>   `_swatter_ev_stamp` silently returns the original evidence for a non-integer
>   value (`lib/score.sh:98`), so the label lives in `reason`, not the stamp
> - `log_warn` once; increment the run's cap counter

**`audit_action` must be set too.** It is bound once at entry
(`:128`, `audit_action="${11:-$3}"`) and is not updated by assigning `action`.
The success audit uses it (`:212`), and the nightly digest counts perms from
those audit records rather than the ledger (`lib/report.sh:160`,
`select(.action=="perm")`). Setting only `action` would write `temp` to the
firewall and ledger while `decisions.jsonl` said `perm` — inflating the digest
and making `swatter why` lie.

Downstream consequences, each verified:

| Consequence | Mechanism |
|---|---|
| Backend places a temp | `:161` / `:169` branch on `action` |
| Ledger records `temp` | `swatter_store_record` at `:184` |
| `offenders.perm` never set | swarm delta requires `perm=1` (`store_sqlite.sh:711`) |
| Perm tripwire not incremented | `:181` requires `action == "perm"` |

**AbuseIPDB needs an explicit guard, not the perm/temp distinction.** The call at
`:208-209` fires when `audit_action == action` **and** either the action is perm
*or* `ABUSEIPDB_REPORT_MIN_ACTION == "temp"`. Once `audit_action` is correctly
set to `temp`, the first clause becomes true, so a host configured with
`MIN_ACTION=temp` **would report the capped IP**. The publication protection must
therefore be explicit: skip `swatter_abuseipdb_report` when the shared-egress
veto fired, regardless of action.

TTL is the ladder **maximum**. Note `:168`'s CF-plane TTL rewrite is skipped once
the action is `temp`, so the veto must set `ttl` itself — do not rely on `:168`.

### 3. Coverage — five perm paths, not four

| # | Path | Site | Covered by |
|---|---|---|---|
| 1 | Honeypot — immediate, bypasses the ladder | `score.sh:588` | `_swatter_apply_plane` |
| 2 | Ladder escalation (`recidivism`) | `score.sh:608` | `_swatter_apply_plane` |
| 3 | Dual-plane mirror | `score.sh:312`, `:364` | calls with literal `"perm"`; same guard |
| 4 | Plane-upgrade | `score.sh:323`, `:341` | same |
| 5 | **`import-bans`** | `bin/swatter:468-473` | **needs its own gate** |

Path 5 was missed in revision 1. `cmd_import_bans` calls
`swatter_block_direct_perm` directly and writes `swatter_store_record … perm` and
`swatter_store_plane_set … perm` itself, never touching `_swatter_apply_plane`.
It sets `offenders.perm=1` and an enforced perm row — exactly what
`swatter_store_perm_ips_since` publishes — so a fleet `export-bans` →
`import-bans` could reintroduce WARP perms. It checks `swatter_is_never_block`
(`:467`) and nothing else.

**Fix:** add the shared-egress check beside that never-block check, skipping (and
logging) rather than importing. `import-bans` is operator-run and bulk, so
skip-with-a-log is the right semantic there rather than a silent downgrade.

Path 1 is why the veto is not on the ladder branch alone: honeypot perms a
first-seen IP on one request, and `REPEAT_ENABLE=false` already does not stop it.

Paths 3 and 4 only ever act on an IP that already has a perm — with one
correction: a fresh hard-intel dual-plane leg fires on the *same* scan as the
first perm (`:364`), so it is not purely historical. Both re-enter the chokepoint
with a literal `"perm"` and are downgraded there.

**Pending retry is covered** (positive): `_swatter_retry_pending` re-enters
`_swatter_apply_plane` with the stored action (`:484`), so any pre-deploy queued
WARP perm is capped on drain rather than landing.

### 4. The sweep — `bin/swatter shared-egress-audit [--fix]`

The veto is forward-only; nine WARP perms are live today.

**`--fix` is unblock-only. It does NOT allowlist.** Revision 1 specified
`allow` + `unblock --perm-allow`, which review correctly identified as
contradicting this design's own non-goal: `cmd_allow` writes
`OPERATOR_ALLOW_FILE`, which `swatter_is_never_block` honors as a full exemption
(`lib/allowlist.sh:260-261`). WARP addresses **rotate between clients**, so a
per-IP never-block becomes a standing free pass for whoever receives that address
next — disabling temps too, which the veto never intended.

Semantics, following `rollback-ladder` (`bin/swatter:571-603`), which already
learned these:

- Default **read-only**: list matching perm IPs with ASN label, ban date, evidence.
- `--fix` takes **one** `swatter_with_state_lock` for the whole run, not N nested
  per-IP locks.
- **Continue on partial failure**, reporting `ok` / `PARTIAL` per IP and a summary.
- **Hard-fail** — never print success — if dual-plane verification fails.
- **Count gate**: refuse `--fix` above N selected IPs without explicit
  confirmation, so an over-broad list cannot mass-lift silently.
- Allowlisting requires a separate explicit flag and prints a never-block warning.

Verification is mandatory: `swatter_store_unblock` runs at `bin/swatter:168`,
**before** the failure check at `:175`, so a partial backend failure still clears
`offenders.perm` — the IP drops out of the publish delta and looks remediated
while CSF or CF may still deny it. Confirm `offenders.perm=0`, no `plane_blocks`
row, no `cf-rules.tsv` ref, no `csf.deny` line.

> **Carried from review — needs an operator decision.** The 7 IPs allowlisted
> during the 2026-08-11 unfreeze (4 WARP + 3 AS206092) were cleared with
> `--perm-allow` and are therefore permanent never-blocks today. Under this
> design they should be converted to plain unblocks once the veto ships, so the
> cap protects them instead of a free pass.

### 5. Packaging

Following the `hosting-asns.txt` pattern (`install/install.sh:232-235`):

- `config/shared-egress.cidr` and `config/shared-egress-asns.txt` templates.
- Installed `0644`, **only if absent**; a `.example` always shipped to diff, so
  upgrades neither clobber operator edits nor withhold updates.
- `SHARED_EGRESS_ENABLE` / `SHARED_EGRESS_CIDR_FILE` / `SHARED_EGRESS_ASNS_FILE`
  defaults in `lib/common.sh` plus entries in the example conf.
- `shared-egress-audit` wired into the `bin/swatter` dispatch and help text.
- RUNBOOK + CHANGELOG must call out that `SHARED_EGRESS_ENABLE` defaults **true**,
  so an upgrade changes behavior without opt-in.

### 6. Testing — `test/shared_egress_test.sh`

| Case | Asserts |
|---|---|
| CIDR match | `104.28.1.1` matches with no DNS |
| ASN match | listed ASN matches via stubbed `swatter_asn_resolve` |
| ASN resolution fails | **fails open** — perm proceeds |
| `SHARED_EGRESS_ENABLE=false` | veto disabled cleanly |
| Missing / empty CIDR + ASN files | fail open |
| **`/0` and over-broad CIDR** | file rejected whole, veto inert |
| Poisoned non-numeric ASN cache file | rejected on read |
| **Honeypot hit on shared-egress IP** | backend `temp`, ledger `temp`, **and audit field `temp`** |
| Ladder escalation on shared-egress IP | same three |
| Post-cap side effects | `offenders.perm=0`; `swatter_store_perm_ips_since` empty; `swatter_abuseipdb_report` **not** called **even with `ABUSEIPDB_REPORT_MIN_ACTION=temp`**; `SWATTER_RUN_PERMS` not incremented |
| Dual-plane + plane-upgrade legs after a cap | both capped, plane state symmetric |
| Pending retry of a queued `action=perm` | capped on drain |
| `import-bans` of a shared-egress IP | skipped and logged |
| Second honeypot after TTL expiry | still cannot create `perm=1` |
| AS13335 IP outside `104.28/16` and outside CF never-block | documents current scope |
| `--fix` with a partial backend failure | does **not** report success |
| Non-shared IP | perm path entirely unchanged (regression guard) |

`perm_gate_residue_test.sh` and `scan_wire_test.sh` must stay green.

## Interaction with gate D

Gate D widens `REPEAT_WINDOW_DAYS` 7 → 30, a 4.3× longer window for every cohort
to accumulate temps into perms. (Distinct from the **4.9×** figure elsewhere,
which is the measured *candidate count* ratio, 615 vs 125 — not window length.)
The WARP cohort accrues ~1.6 temps/day, so the widen increases shared-VPN perms
specifically.

**This should land before the widen**, so the 615-row review need not carry the
shared-VPN question by hand. It does not change the gate D date floor
(2026-08-26 22:40 UTC), which concerns `rule=` stamping.

## Rejected alternatives

**Blanket-allowlist `104.28.0.0/16`** — a never-block hands any attacker a
complete bypass via a free one-click consumer VPN. Same hazard already documented
for `monitoring.cidr`, but with a mass-market client.

**Per-IP allowlist as the remediation** (revision 1's `--fix`) — the same hazard
at smaller scale, made worse by WARP address rotation. Replaced by unblock-only.

**Veto at the two originating sites only** — leaves the derivative legs able to
re-mirror a pre-existing perm; correct only if the sweep was exhaustive. An
invariant depending on an operational step is the failure mode that stays
invisible for months.

**Suppress publication but keep perms** — leaves the larger harm, a permanent
customer-facing ban, in place.

**Fail closed on ASN resolution failure** — makes a third-party DNS service a
global availability lever on the entire ladder. The static CIDR backstop gives
the known ranges unconditional protection without that coupling.

## Rollback

- `SHARED_EGRESS_ENABLE=false` disables the veto on the next `*/5` scan. It does
  **not** re-perm anything already capped or swept; those were temps and expire.
- Emptying either file narrows scope without a code change.
- Prior temp counts survive, so after disabling, the next offense can escalate
  immediately — expected, stated here so it is not a surprise.
- Historical published perms are not withdrawn by any of this (same class as the
  `rollback-ladder` caveat).

## What review changed

Revision 1 asserted three things that were false, all found at the code:

1. "`_swatter_apply_plane` is the single chokepoint; there are four perm paths."
   — `import-bans` is a fifth and bypasses it entirely.
2. "Downgrading `action` leaves every sink consistent." — `audit_action` desyncs,
   corrupting the nightly digest; and the AbuseIPDB sink was correct only *by
   accident*, breaking once `audit_action` is fixed.
3. "Non-edge AS13335 is precisely WARP." — it is not, which made the shipped
   default list wider than the measured problem.

Plus two safety gaps: no `/0` guard on a file whose match disables all permanent
banning, and a sweep that remediated by never-blocking rotating addresses.
