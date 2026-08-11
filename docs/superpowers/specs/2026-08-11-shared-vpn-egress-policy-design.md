# Design — shared consumer-VPN egress policy (perm cap)

**Status:** proposed, 2026-08-11. Awaiting adversarial review.
**Origin:** found during the 2026-08-10/11 publication unfreeze (see
`docs/handoff-2026-08-04-unfreeze-and-gate-d.md` §1 and the `TODO.md` section
"Cloudflare WARP + shared consumer VPN exits").

## Problem

Swatter permanently bans IPs that are **shared consumer VPN egress** — addresses
used simultaneously by many ordinary people. A permanent ban on one of those
blocks every legitimate user assigned that egress IP from every customer site,
forever, and publishing it recommends that other hosts do the same.

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

The problem is **live and recurring**, not historical. Four fresh WARP IPs
(`104.28.217.138`, `.217.139`, `.249.140`, `.215.225`) and two more AS206092 IPs
(`158.173.77.190`, `173.239.196.109`) are at or over the escalation bar now.

Because the shared-VPN slice of the at-bar cohort is small (8 of 106) and
identifiable by ASN, this is a **curated-list problem, not a feed problem**. A
short hand-vetted list suffices; no subscription or automated ingest is needed.

### Why this gates the AbuseIPDB unfreeze

`ABUSEIPDB_REPORT` has no backlog — it reports perms placed *after* the flip, and
AbuseIPDB has no delete API. With WARP producing ~4 perm IPs/month and six shared
-VPN IPs already at the bar, flipping that arm before this lands makes an
irreversible report of a shared consumer VPN egress IP a near-certainty within
weeks. **Land this first, then flip `ABUSEIPDB_REPORT`.**

## Non-goals

- Tuning `request_flood` — separate `TODO.md` item, unrelated rule.
- Gate D / `REPEAT_WINDOW_DAYS` — unaffected, though see "Interaction with gate D".
- Changing what gets **scored**. This caps what gets **enforced**.
- Any blanket allowlist of a VPN range. Every CIDR in `allow.cidr` /
  `cloudflare.cidr` / `monitoring.cidr` is a **never-block**, so allowlisting the
  WARP pool would let any attacker bypass swatter entirely by switching on the
  1.1.1.1 app. Rejected explicitly; see "Rejected alternatives".

## Design

### 1. Identification — `lib/asn.sh`

New function:

```
swatter_is_shared_egress <ip>
  -> echoes a short label, returns 0 if shared consumer egress
  -> returns 1 otherwise
```

Checked in cost order:

1. **`SHARED_EGRESS_CIDR_FILE`** (default `/etc/swatter/shared-egress.cidr`) —
   static ranges, matched with the existing `_ip_in_cidr_file`. **No network
   dependency.** Ships with `104.28.0.0/16`.
2. **`SHARED_EGRESS_ASNS_FILE`** (default `/etc/swatter/shared-egress-asns.txt`)
   — `<asn> # name` per line, identical in format and parsing to the existing
   `HOSTING_ASNS_FILE`. Resolved through the existing `swatter_asn_resolve`,
   which already caches per-IP under `$STATE_DIR/asn/<ip>` and already handles
   IPv6 via `origin6.asn.cymru.com`.
3. **Fail open** — no CIDR match and no ASN answer returns 1 (today's behavior).

Gated by `SHARED_EGRESS_ENABLE` (default `true`).

Shipped defaults, deliberately short — every entry needs evidence, because a
wrong entry weakens the host of every operator of this public repo:

```
# shared-egress-asns.txt
13335  # Cloudflare — consumer WARP egress (104.28.0.0/16 et al)
206092 # F.N.S. Holdings / "VPN Consumer" — consumer VPN exits
```

```
# shared-egress.cidr
104.28.0.0/16  # Cloudflare consumer WARP egress
```

**On listing all of AS13335:** broader than WARP, and intentionally so. The CDN
edge ranges are already never-blocked earlier by `cloudflare.cidr`
(`swatter_is_never_block` runs before this check and returns `cloudflare-range`),
so the only AS13335 addresses that ever reach this check are non-edge ones —
which is precisely WARP.

**No compiled-in fallback constant** analogous to `SWATTER_CF_FALLBACK_V4`. That
exists because banning the Cloudflare edge is a total outage; missing a
shared-egress entry is bounded, self-expiring collateral. The duplication is not
warranted.

### 2. The veto — `lib/score.sh`, inside `_swatter_apply_plane`

`_swatter_apply_plane` is the single chokepoint: it is the only place a block
reaches a backend, and it also owns the ledger write, the per-plane ledger, the
AbuseIPDB call, and the perm-rate tripwire counter.

Insert after the never-block check (`:145`) and before the `MAX_BLOCKS_PER_RUN`
check (`:146`):

> If `action == "perm"` **and** `SHARED_EGRESS_ENABLE` is true **and**
> `swatter_is_shared_egress "$ip"` matches:
> - `action="temp"`
> - `ttl="$(_swatter_pick_ttl 99)"` — the ladder **maximum**
> - append `shared-egress=<label> perm-capped` to `reason`
> - stamp evidence via `_swatter_ev_stamp` so `swatter why` can explain it
> - `log_warn` once

Placed after never-block so an already-exempt IP short-circuits first; placed
before the cap so the veto is a policy decision about the target rather than a
budget decision.

Every downstream consequence then follows without further edits:

| Consequence | Mechanism |
|---|---|
| Backend places a temp | `:161` / `:169` branch on `action` |
| Ledger records `temp` | `swatter_store_record` at `:184` receives the downgraded action |
| `offenders.perm` never set | **swarm publication cannot see it** — the delta requires `perm=1` |
| AbuseIPDB not called | `:209` requires `action == "perm"` under the default `ABUSEIPDB_REPORT_MIN_ACTION=perm` |
| Perm tripwire not incremented | `:181` requires `action == "perm"` |

Both publication arms are therefore handled for free; no separate
"never publish" flag is needed.

**TTL = ladder maximum, not a fresh 1h.** An IP that earned a perm should receive
the longest temp available. This also avoids the TTL-coupling trap recorded in
`TODO.md` (`prior` drives both perm conversion and `_swatter_pick_ttl`, so
filtering `prior` would freeze the ladder at 1h) — we do not filter `prior` at
all, we cap the outcome.

### 3. Coverage of every perm path

There are four ways an IP becomes perm. All are covered:

| # | Path | Site | Covered by |
|---|---|---|---|
| 1 | Honeypot — immediate, bypasses the ladder | `:588` | calls `_swatter_apply_plane` |
| 2 | Ladder escalation (`recidivism`) | `:608` | calls `_swatter_apply_plane` |
| 3 | Dual-plane mirror | `:312`, `:364` | calls `_swatter_apply_plane` with a literal `"perm"` — same guard downgrades it |
| 4 | Plane-upgrade | `:323`, `:341` | same |

Path 1 is the reason the veto is **not** placed on the ladder branch alone:
honeypot perms a first-seen IP on a single request, and `REPEAT_ENABLE=false`
already does not stop it (documented in `TODO.md` / README).

Paths 3 and 4 are derivative — they act only on an IP that already has a perm.
Since no perm is ever recorded for a shared-egress IP, `swatter_store_is_perm_on`
stays false, `_swatter_perm_gate` falls through to the ladder on every scan, and
the result is a temp. No loop, no stranded state.

### 4. The sweep — `bin/swatter`

The veto is **forward-only**. It prevents new perms; it does not clear existing
ones. Nine WARP perms are live today.

New operator-run subcommand:

```
swatter shared-egress-audit [--fix]
```

- Default is **read-only**: lists every IP with `offenders.perm=1` matching the
  shared-egress rules, with ASN label, ban date, and evidence.
- `--fix` performs, per IP, `swatter allow <ip> "<label> — shared egress"` then
  `swatter unblock <ip> --perm-allow`, then **re-verifies on both planes**.

Verification is mandatory, not decorative: `swatter_store_unblock` runs at
`bin/swatter:167` **before** the failure check at `:174`, so a partial backend
failure still clears `offenders.perm` — the IP drops out of the publish delta and
looks remediated while CSF or CF may still be denying it. The audit must confirm
`offenders.perm=0`, no `plane_blocks` row, no `cf-rules.tsv` ref, no `csf.deny`
line, and presence in `csf.allow`.

### 5. Testing — `test/shared_egress_test.sh`

| Case | Asserts |
|---|---|
| CIDR match | `104.28.1.1` matches with no DNS available |
| ASN match | listed ASN matches via a stubbed `swatter_asn_resolve` |
| ASN resolution fails | **fails open** — returns 1, perm proceeds |
| `SHARED_EGRESS_ENABLE=false` | veto disabled cleanly, perm proceeds |
| Unlisted ASN | returns 1 |
| **Honeypot hit on a shared-egress IP** | backend called with `temp`, **and** ledger row is `temp` — the case that catches the whole class |
| Ladder escalation on a shared-egress IP | same |
| Downgrade side effects | `swatter_abuseipdb_report` **not** invoked; `SWATTER_RUN_PERMS` **not** incremented |
| Non-shared IP | perm path entirely unchanged (regression guard) |

Existing suites must stay green — particularly `perm_gate_residue_test.sh` and
`scan_wire_test.sh`, which exercise the same function.

## Interaction with gate D

Gate D widens `REPEAT_WINDOW_DAYS` 7 → 30, a 4.3× longer window for every cohort
to accumulate temps into perms. (Distinct from the **4.9×** figure elsewhere in
the docs, which is the measured *candidate count* ratio, 615 at window=30 vs 125
at window=7 — not the window length.) The WARP cohort accrues ~1.6 temps/day, so
the widen would increase shared-VPN perms specifically. Gate D's own review rule
already says VPN exits get allowlisted first.

**This should land before the widen**, so the 615-row human review does not have
to carry the shared-VPN question by hand.

It does not change the gate D date floor (2026-08-26 22:40 UTC), which is about
`rule=` stamping, an unrelated mechanism.

## Rejected alternatives

**Blanket-allowlist `104.28.0.0/16`.** Every CIDR in the allow/never-block files
is a never-block, so this hands any attacker a complete swatter bypass via a
free, one-click consumer VPN. This is the same hazard already documented for
`monitoring.cidr` ("never pre-populate with well-known monitor ranges"), but with
a mass-market client. Rejected.

**Veto at the two originating sites only** (honeypot + ladder) rather than the
chokepoint. Reads more naturally at each site, but leaves the derivative
dual-plane / plane-upgrade legs able to re-mirror a pre-existing perm — correct
only if the sweep was exhaustive. An invariant that depends on an operational
step having been done right is the failure mode that stays invisible for months.
Rejected in favor of correct-by-construction.

**Suppress publication but keep perms.** Avoids defaming shared infrastructure
but leaves the larger harm — a permanent, customer-facing ban — in place.
Rejected.

**Fail closed when ASN resolution fails.** Safest for collateral, but makes a
third-party DNS service a global availability lever on the entire ladder: a Cymru
outage would stop every perm on the host. The static CIDR backstop gives the
known ranges unconditional protection without that coupling. Rejected.

## Rollback

- `SHARED_EGRESS_ENABLE=false` disables the veto; config is read per-process, so
  it takes effect on the next `*/5` scan. It does **not** restore perms already
  capped — those were temps and will simply expire.
- Emptying `shared-egress.cidr` / `shared-egress-asns.txt` narrows scope without
  a code change.
- Bans cleared by `--fix` are restored the same way any allowlisting is undone:
  remove the `allow.cidr` entry and the `csf.allow` line. Note the ladder count
  was reset by the unblock, so the IP starts from zero.
