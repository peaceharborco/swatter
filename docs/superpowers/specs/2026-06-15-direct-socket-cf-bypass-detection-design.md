# Direct-socket evidence for Cloudflare-bypass detection

**Date:** 2026-06-15
**Status:** Approved — ready for implementation
**Version target:** 1.2.1 → 1.2.2 (patch)

## Problem

Swatter's plane classifier (`lib/classify.sh`, `swatter_classify`) routes a
confirmed offender to either the Cloudflare plane (`VIA_CF` → managed_challenge
IP Access Rule) or the origin firewall (`DIRECT` → CSF deny). It recognizes
"direct-to-origin" evidence by only two signals:

1. The offender appears in `SWATTER_DIRECT_SET` — IPs seen hitting cPanel
   service ports (2082/2083/2086/2087/2095/2096/2077/2078) in `lfd.log` within
   the scoring window.
2. `novhost > 0` — the request hit the raw IP / carried no usable `Host`.

An attacker who hits the origin **web ports** (`:80`/`:443`) directly, bypassing
Cloudflare, but sends a **valid `Host` header**, trips neither signal:
`novhost = 0` (valid Host) and web ports are not cPanel service ports. Swatter
mis-classifies it as `VIA_CF`, places a managed_challenge rule that never fires
(the traffic never transits Cloudflare), and on later cron cycles emits
`noop-perm`/`channel:none` because that useless rule already exists. The one
channel that would stop it — CSF — never runs.

**Observed incident (2026-06-14):** `178.128.102.23` (DigitalOcean) POSTed
`//xmlrpc.php` to the origin IP `67.225.133.76:443` with `Host: plugscrub.com`
(a CF-proxied property), ~1 req/sec for 3+ hours, fully unblocked, while Swatter
believed it had acted. Confirmed direct via a live socket: `ss -tn` showed
`67.225.133.76:443 ← 178.128.102.23`. Resolved manually with `csf -d`.

## The signal

At the kernel TCP layer, a Cloudflare-proxied request always arrives from a
Cloudflare **edge** IP — `mod_remoteip` restores the visitor IP only at the
Apache/L7 layer; the socket peer is unchanged. Therefore: **a live TCP
connection to a local web port whose remote peer is NOT in the Cloudflare ranges
is, by definition, hitting the origin directly.** This is the same class of
evidence the existing direct set already represents (a non-proxied socket), just
sourced from live web-port connections instead of `lfd.log` cPanel-port lines.

## Design

Approach A (live-socket snapshot). Smallest change, fits the existing
`swatter_build_direct_set` pattern, network-free, portable, injectable for tests.
Point-in-time: catches in-progress floods (the harmful case — a sustained
~1/sec flood always has a live socket during the 5-minute scan). Attacks that
ended before the scan fall back to today's `VIA_CF` behavior. Purely additive —
it never removes evidence the current code finds.

Rejected: B (log & parse `CF-Ray`) — window-accurate but requires server-wide
Apache `LogFormat` changes across 231 cPanel-templated domlogs; invasive and
non-portable. C (`/proc/net/nf_conntrack`) — slightly wider coverage than A but
heavier and less portable; a possible later widening.

### Components (all in `lib/classify.sh` + one config knob)

1. **`_swatter_websocket_peers()`** — new, dependency-injectable helper (modeled
   on `_swatter_resolve_host`). Prints the remote IPv4 addresses of TCP
   connections whose local port is in `DIRECT_WEB_PORTS`, using `ss -Htn`.
   Returns nothing if `ss` is absent or `DIRECT_WEB_PORTS` is empty (graceful
   no-op). Tests override this function to inject fixture output.

2. **`swatter_build_direct_set()`** — extended. After the existing `lfd.log`
   cPanel-port pass, union in the web-socket peers **with Cloudflare-range IPs
   filtered out** (`_ip_in_cidr_file "$ip" "${CLOUDFLARE_IPS_FILE}"` → skip when
   true), then `sort -u` the combined set into `SWATTER_DIRECT_SET`.

   **Ranges-missing gate:** the web-peer fold runs only when the CF range list
   is present and trustworthy (`swatter_allowlist_healthy`). Without trustworthy
   ranges we cannot distinguish a CF edge from a direct peer, and folding a CF
   edge into the direct set could CSF-deny the proxy (outage). This is consistent
   with `swatter_failclosed_active`, which already suppresses CSF denies on a
   CF-fronted box with a missing/stale range list.

3. **`DIRECT_WEB_PORTS`** — new setting, documented in
   `config/swatter.example.conf` as `DIRECT_WEB_PORTS="80 443"`. The default
   (applied in `lib/common.sh` via `: "${DIRECT_WEB_PORTS:=80 443}"`) is
   `80 443` **when the key is absent**, so existing prod boxes whose preserved
   `swatter.conf` predates this key get the fix on upgrade without a conf edit.
   Setting it to the **empty string** explicitly disables the new signal (kill
   switch); unset ≠ empty.

4. **`_swatter_has_direct_evidence` / `swatter_classify`** — unchanged. They
   already test `SWATTER_DIRECT_SET` membership, so the new peers route through
   automatically. No change to `lib/score.sh`.

### Data flow

```
ss -Htn (local port in DIRECT_WEB_PORTS)
  → remote IPv4
  → drop IPs in CLOUDFLARE_IPS_FILE        (only when ranges healthy)
  → union into SWATTER_DIRECT_SET (sort -u)
  → _swatter_has_direct_evidence() hit
  → swatter_classify() = DIRECT
  → CSF deny (gated by allowlist health, as today)
```

### Safety analysis

- **No change to who is blocked.** `swatter_build_direct_set` runs at scan start;
  classification happens only after scoring AND after the allowlist never-block
  check (`score.sh:122`, before `swatter_classify` at `:135`). This change only
  selects the *plane* for an already-decided offender. Client safety remains
  owned by the allowlist, unchanged.
- **CF edges never CSF-denied.** Edge IPs are filtered against the CF ranges
  before folding, preserving the anti-outage invariant in `classify.sh`.
- **Fail-closed preserved.** Web peers are folded only when ranges are healthy;
  when they are not, CSF denies are already suppressed for the run.
- **Additive only.** An offender with no live direct socket falls back to the
  current `VIA_CF` path. Detection is never weakened.
- **Graceful degradation.** `ss` missing / non-Linux / empty `DIRECT_WEB_PORTS`
  → helper yields nothing → behavior identical to today.

### Scope / non-goals

- **IPv4 only** in this version, matching the existing `SWATTER_DIRECT_SET`
  (which extracts IPv4 only). IPv6 direct-socket detection is a noted follow-up.
- Point-in-time coverage is accepted; `conntrack`-based widening (approach C) is
  out of scope.
- No Apache logging changes (approach B) and no change to `score.sh`.

## Testing

Extend `test/detect_test.sh` (or add `test/classify_test.sh`) with the same
fixture/dependency-injection style: override `_swatter_websocket_peers` to return
canned remote IPs, point `CLOUDFLARE_IPS_FILE` at a fixture range list, and
assert via `swatter_classify` / direct-set membership. No network, no root, no
firewall.

| Case | Setup | Expectation |
|------|-------|-------------|
| Non-CF peer on web port | injected peer outside CF ranges, healthy ranges | lands in direct set → `swatter_classify` = `DIRECT` |
| CF-edge peer | injected peer inside CF ranges | filtered out → `VIA_CF` |
| **Regression** | offender `novhost=0`, no cPanel-port hit, live non-CF web socket | `DIRECT` (the incident case) |
| Ranges missing/stale | unhealthy range list | web peers NOT folded → no `DIRECT` from this signal |
| `ss` absent / empty `DIRECT_WEB_PORTS` | helper returns nothing | no-op; classification unchanged |

## Rollout

- Patch bump `1.2.1 → 1.2.2`; note in README / changelog area used by prior
  bumps.
- Ships as ordinary code; deployed to prod the usual way
  (`bash install/install.sh remote peaceharbor`), which preserves the server
  `swatter.conf`. Existing boxes need no conf edit: an absent `DIRECT_WEB_PORTS`
  defaults to `80 443`, so the fix is live on upgrade.
