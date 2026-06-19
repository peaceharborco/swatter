# Swatter origin-lock — design

**Date:** 2026-06-19
**Status:** approved (pending spec review)
**Scope:** Add an optional inline firewall control, `swatter origin-lock`, that
restricts the web ports (80/443) to Cloudflare ranges so direct-to-origin
Cloudflare-bypass traffic is dropped at L3 — the structural complement to the
existing reactive `classify.sh` direct-detection.

## Why

Swatter's headline defense is stopping the direct-to-origin Cloudflare-bypass
attack. Today it ships only the **reactive** half: `classify.sh` scores an
offender *after* it appears in the logs, which a fast valid-`Host` flood can
outrun. The **structural** fix is an inline L3 rule that only lets Cloudflare
edges reach the web ports — closing the door instead of scoring who walked
through it. This brings that control into the public tool, fully generalized and
config-driven, with no deployment-specific assumptions.

## Public / private boundary

The generic mechanism is public; all policy and deployment specifics stay
private (server config + the operator's private overlay). The public code carries
**no** real IPs, hostnames, customer domains, or `csf.allow` assumptions. An
operator's decision to enforce, their grey-cloud handling, and their real CF list
live in `/etc/swatter/` on the server. Folding this in is itself the act of
drawing that line: by making the lock config-driven, the Peace-Harbor specifics
fall out into private config automatically. gitleaks (CI) remains the backstop.

## Architecture & components

```
lib/origin_lock.sh                      one module; idempotent builders + teardown
bin/swatter origin-lock {apply|status|preflight|disable}
install/                                csfpre hook drop-in + optional systemd unit
```

### Config surface (swatter.conf; all defaults safe/off)

```sh
ORIGIN_LOCK="off"               # off | log | drop   (default off)
ORIGIN_LOCK_PORTS="80,443"
ORIGIN_LOCK_ALLOW_ACME="true"   # allow /.well-known/acme-challenge/ on :80 from any src
ORIGIN_LOCK_SET="cf_origin"     # ipset basename -> cf_origin4 / cf_origin6
# range source reuses CLOUDFLARE_IPS_FILE (/etc/swatter/cloudflare.cidr); no new list
```

## Rule composition (what `apply` builds)

For each address family present in `cloudflare.cidr` (v4 → `iptables`/`cf_origin4`;
v6 → `ip6tables`/`cf_origin6`):

1. `ACCEPT` Cloudflare edges (ipset `src` match) → web ports.
2. (if `ORIGIN_LOCK_ALLOW_ACME`) `ACCEPT` `/.well-known/acme-challenge/` on :80
   via `-m string` (HTTP-01; soft-fail + warn if `xt_string` is unavailable).
3. `LOG` (rate-limited) the remainder on the web ports, prefix `ORIGIN-LOCK: `.
4. if `ORIGIN_LOCK=drop`: `DROP` the remainder.

**Order is accept-first, drop-last**, so a mid-build failure never leaves a DROP
without its preceding ACCEPTs (fail-open spine).

### IPv6 (in v1)

`cloudflare.cidr` already contains both v4 and v6 ranges (`refresh-feeds` fetches
`ips-v4` + `ips-v6`). `apply` builds the v6 path with `ip6tables` + `cf_origin6`
**gated on `ip6tables` being present** — if absent, it logs a loud warning (the
`setup-ipset` pattern) and leaves v6 web ports uncovered rather than failing.
Skipping v6 on a dual-stack host would leave a silent direct-to-origin hole, so
v6 is covered by default whenever the kernel supports it.

## Delivery & persistence (one apply, both worlds)

`swatter origin-lock apply` is the single idempotent code path. The execution
context is **explicit, not guessed**: the csfpre drop-in calls `apply --hook=csf`;
the systemd unit / CLI calls plain `apply` (standalone).

- **CSF present (`--hook=csf`):** install writes a one-line `swatter origin-lock
  apply --hook=csf` into `/etc/csf/csfpre.sh` (created if absent). `csfpre.sh` runs
  before CSF builds its chains on every `csf -r`, so the rule re-applies and is
  correctly ordered ahead of CSF's blanket TCP_IN accept. CSF already provides
  loopback, established/related, and `csf.allow` accepts above csfpre, so in this
  context `apply` adds **only** the CF/ACME accept + LOG/DROP — adding a redundant
  established accept here is explicitly avoided (it leaks handshakes under
  `nf_conntrack_tcp_loose=1`).
- **No CSF (standalone):** install writes a small systemd unit (oneshot,
  `WantedBy=multi-user`) that runs `apply` at boot; the README also documents the
  rc.local equivalent. Here `apply` lays a **safe preamble** before the DROP:
  `ACCEPT -i lo` to web ports (local self-calls / health checks) and `ACCEPT`
  `allow.cidr` + `monitoring.cidr` → web ports (the portable `csf.allow`
  equivalent). It does **not** add an established/related accept: outbound-initiated
  traffic returns on ephemeral ports (never `dports 80,443`, so never matched by the
  DROP), and a standing established accept would both let pre-existing non-CF
  connections survive the lock and risk the conntrack-loose handshake leak.
  (`allow.cidr`/`monitoring.cidr` are existing Swatter files.)

`swatter origin-lock status` reports which persistence mode is active.

### Idempotency

Under `csfpre` the chain is flushed by `csf -r` before each run, so plain inserts
never stack. In the standalone path there is no flush, so `apply` uses
`-C`-guarded inserts (check-then-insert) — the same approach `setup-ipset` uses —
so re-running converges instead of duplicating.

### Fail-open

If `cloudflare.cidr` is missing, empty, or yields fewer than a sane minimum of
ranges, `apply` installs **no** restriction at all and logs why (a missing file
means `refresh-feeds` never ran). It deliberately does **not** fall back to the
compiled-in CF set for the enforcing lock: unlike the allowlist's never-block use
(where an over-broad set is harmless), a stale builtin DROP could drop newly-added
Cloudflare edges and take sites offline. A populated-but-stale file still locks
(with a loud freshness warning). An empty allowlist plus DROP would firewall the
entire internet — never acceptable.

## Safety model

- **Default `off`.** A fresh install enforces nothing.
- **Log-before-drop.** `log` mode installs only LOG; the operator validates before
  `drop`. Post-apply output reuses the loud "run log mode first / read the
  would-be-drops / allowlist legit sources, THEN enforce" banner.
- **Drop guard.** When `ORIGIN_LOCK=drop`, `apply` runs `preflight` first and
  prints the would-be-drop classification; it proceeds to install DROP only with
  an interactive confirmation or `--yes`/`--force`. This bakes the grey-cloud
  lesson into the tool, not just the docs — it is hard to enforce blind by
  accident.

### `preflight` — generalized grey-cloud guard

Reads what LOG mode has logged (the `ORIGIN-LOCK:` source IPs) and classifies each
against Swatter's intel feeds + allowlist, printing a verdict table:

- in an intel feed → **confirmed attacker** (safe to drop);
- in `monitoring.cidr` / `allow.cidr` → **legit — allowlist before DROP**;
- in neither → **unknown — review** (could be a real visitor to a non-CF site).

**Log-source portability:** preflight detects the kernel-LOG source — `journalctl
-k` on journald boxes, else `/var/log/{messages,syslog,kern.log}` — and notes it is
reading a rate-limited sample, not every packet.

## Subcommands

| Command | Behavior |
|---|---|
| `apply` | Converge the firewall to `ORIGIN_LOCK` mode (incl. removing rules if `off`). Drop guard applies. |
| `status` | Mode, ipset health (v4/v6 entry counts), live ACCEPT/DROP counters, persistence mode (csfpre vs systemd), hook installed? |
| `preflight` | Classify would-be-drops from the LOG sample (above). Read-only. |
| `disable` | Full teardown: remove iptables/ip6tables rules, the `cf_origin4`/`cf_origin6` sets, **and** the persistence hooks (csfpre line + systemd unit), so nothing re-applies on reboot or `csf -r`. |

## Integration

- `swatter test-config` and `swatter status` surface origin-lock state (mode,
  ipset health, hook installed) alongside existing readiness checks.
- Coexists with `DIRECT_BACKEND=ipset`: the offender `swatter4/6` sets and the
  `cf_origin4/6` sets are independent (different names, different purpose); both
  live in INPUT without conflict.
- Complements `classify.sh`: the lock drops bypass traffic at L3; the classifier
  still scores offenders from logs. No overlap, no conflict.

## Error handling / edge cases

- **Broken/missing `swatter` at `csf -r` time:** the csfpre drop-in guards the
  call so a failure leaves the chain without a DROP (fail-open), never a DROP
  without the CF ACCEPT.
- **`xt_string` absent:** the ACME accept soft-fails with a warning; operator can
  disable `ORIGIN_LOCK_ALLOW_ACME` or use DNS-01.
- **ACME scope:** only HTTP-01 (:80) is accommodated. TLS-ALPN-01 (:443) is not
  covered — documented; DNS-01 needs no port access.
- **Mode change:** editing `ORIGIN_LOCK` then re-running `apply` converges
  (including tearing down when set to `off`); `disable` is the explicit full
  uninstall.

## Testing

`test/origin_lock_test.sh`, with injected `iptables`/`ip6tables`/`ipset` via PATH
stubs (the pattern `block_ipset_test.sh` uses); no live firewall touched. Asserts:

- rule composition per mode (`off`/`log`/`drop`) for v4 and v6;
- fail-open thresholds (missing/empty/<min ranges → no rules installed);
- standalone preamble present (lo + allow/monitoring; **no** established accept)
  and absent under the `--hook=csf` context;
- idempotent re-apply (no duplicate rules via `-C` guard);
- ACME toggle + `xt_string`-absent soft-fail;
- drop guard blocks DROP without confirmation/`--force`;
- `preflight` classification against a fixture feed + allowlist;
- `disable` removes rules, sets, **and** persistence hooks.

CI additions: `shellcheck` already covers `lib/*.sh`; add `bash
test/origin_lock_test.sh` to the workflow.

## Out of scope (v1)

- Nightly-digest origin-lock section (fast follow-up).
- cPanel domain-map preflight (`/etc/userdatadomains`) — non-portable; the
  feed-classified preflight is the portable core.
- TLS-ALPN-01 ACME.

## Documentation

- New README "Origin lock" section under the firewall material: what it does, the
  log-before-drop workflow, the drop guard, v6 note, and the CSF vs standalone
  persistence paths.
- `CHANGELOG.md` entry under `## [Unreleased]`.
- `swatter.example.conf` block documenting the `ORIGIN_LOCK*` keys.
