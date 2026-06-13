# Either/or: make Swatter work whether or not the box is behind Cloudflare

**Date:** 2026-06-13
**Status:** Approved (design)

## Problem

Swatter is built around the Cloudflare-fronted cPanel/CSF case, but should be
equally useful on a server with **no Cloudflare domains at all**. Two things
block that today:

1. **Correctness — the fail-closed gate neuters off-mode.**
   `swatter_scan` (`lib/score.sh`) calls `swatter_allowlist_healthy` every run.
   That helper only checks whether `CLOUDFLARE_IPS_FILE` (`cloudflare.cidr`)
   exists and is fresh; if not, **all CSF denies are skipped** for the run
   (`skipped-failclosed`). The gate exists to prevent CSF-denying a Cloudflare
   *edge* socket (which would firewall the proxy and take every site down). On a
   server that is genuinely **not** behind Cloudflare there is no CF range list,
   so the gate trips on every run and Swatter blocks **nothing** even in
   `enforce` mode. The gate is only meaningful when a Cloudflare plane actually
   exists.

2. **UX — the operator has to know to flip `CF_MODE`.**
   The default is `CF_MODE="direct"`. A non-CF operator must understand the
   plane model well enough to choose `off`. We want Swatter to figure out the
   posture itself.

## Safety invariant (unchanged)

Misrouting a Cloudflare edge socket to CSF takes the whole box down. Therefore:

> Any change here may only **relax** CSF blocking when we are **confident** the
> box is not behind Cloudflare. When posture is uncertain, behave as if behind
> Cloudflare — classification stays on and CSF is reserved for proven-direct
> sockets. Ambiguity always fails toward the safe (Cloudflare/challenge) plane.

## Design

### 1. Fail-closed only when Cloudflare is in use

In `swatter_scan`, gate the fail-closed behavior on `swatter_cf_in_use`:

```
healthy=1
if swatter_cf_in_use; then
    swatter_allowlist_healthy || healthy=0
fi
```

When Cloudflare is not in use, every offender classifies `DIRECT` (already true
via `swatter_classify`), there is no edge socket to protect, and CSF denies
proceed normally. The fail-closed warning/audit path is unchanged for the CF
case.

### 2. `CF_MODE="auto"` — the new default

Add `auto` as a recognized `CF_MODE` and make it the default in both
`lib/common.sh` and `config/swatter.example.conf`. Explicit `direct` / `skip` /
`off` continue to mean exactly what they mean today and **skip detection
entirely** — an operator who has set a mode is never second-guessed.

`auto` resolves to a posture via a cached detection verdict:

- verdict `not-behind` → behaves like `off` (classification disabled,
  everything CSF-direct, fail-closed gate inert).
- verdict `behind` or `uncertain`, or **no verdict yet** → behaves like the
  classification-on posture (the safe default). Note: `auto` resolving to
  "behind" implies Swatter manages the CF plane like `direct` **only if** CF
  creds/maps are present; with no creds it behaves like `skip` for the VIA_CF
  plane (logs, does not act) — i.e. it never errors for lack of credentials,
  and it never CSF-denies a proxied socket.

This "does Swatter actively run the CF plane?" decision is its own predicate,
`swatter_cf_manages_plane` (true for explicit `direct`, or `auto` + fronted +
creds&map present). The VIA_CF routing in `lib/score.sh` and the rule
create/sweep/unblock gates in `lib/block_cf.sh` — all previously hardcoded to
`CF_MODE == "direct"` — switch to this predicate so `auto` participates without
regressing `skip`/`off`.

### 3. Detection — `swatter_detect_cf` (new, in `lib/classify.sh`)

Writes a verdict file `${STATE_DIR}/cf-detect` containing
`<verdict>\t<epoch>\t<reason>` where verdict ∈ `behind|not-behind|uncertain`.
Run at install, on `refresh-feeds`, and on `test-config`. Never run implicitly
by `scan` (scan only *reads* the cache) so the cron path stays cheap and
network-free.

Signals, evaluated in order; the first decisive signal wins. All "behind"
signals are checked before concluding "not-behind", and "not-behind" requires a
real sample to have been inspected (never concluded from absence of data):

1. **Operator config present** — non-empty `CF_DOMAINS_MAP` or `CF_CREDS_FILE`
   ⇒ `behind`. (The operator already wired Cloudflare.)
2. **mod_remoteip / CF header in web-server config** — Apache config references
   `CF-Connecting-IP` or a Cloudflare trusted-proxy/remoteip block ⇒ `behind`.
3. **lfd sockets in CF ranges** — any raw peer IP in `LFD_LOG` (within the
   window) falls inside `cloudflare.cidr` ⇒ `behind`.
4. **DNS of the box's own vhosts vs CF ranges** (primary positive *and*
   negative signal, independent of mod_remoteip): resolve a bounded sample of
   vhost names (domlog basenames) via `getent hosts` / `host` / `dig`
   (whichever is available; skip if none). If any resolve into `cloudflare.cidr`
   ⇒ `behind`. If the sample resolved successfully and **none** point at
   Cloudflare ⇒ `not-behind`.
5. Otherwise ⇒ `uncertain` (treated as behind/safe at runtime).

`cloudflare.cidr` is required for signals 3–4, so `refresh-feeds` continues to
download it on **every** box, CF or not (it is the public CF range list, not
account-specific). This is unchanged behavior.

Detection must be cheap and bounded: cap the vhost DNS sample (e.g. first ~20
distinct vhosts), short per-lookup timeouts, no retries. It must never abort a
run or the installer — on any error it yields `uncertain`.

### 4. `swatter_cf_in_use` understands `auto`

```
swatter_cf_in_use:
  case CF_MODE in
    off)  return 1
    auto) read cached verdict; "not-behind" -> return 1; else fall through
    *)    [[ -s CLOUDFLARE_IPS_FILE ]] && return 0 || return 1
```

For `auto` with verdict `behind`/`uncertain`/absent, fall through to the
existing `[[ -s CLOUDFLARE_IPS_FILE ]]` check — so a not-yet-refreshed `auto`
box behaves exactly like today's safe path.

### 5. Surface / reporting

- `test-config`: print the detection verdict, its reason, and age, plus the
  resolved posture (e.g. `CF mode: auto -> not-behind (no vhosts resolve to
  Cloudflare); offenders go to CSF`). For `auto` resolved to behind, show the
  same CF creds/map lines `direct` shows.
- `status`: `CF in use:` line already exists; extend with the resolved verdict
  when `CF_MODE=auto`.
- `refresh-feeds`: after refreshing ranges, recompute and cache the verdict.
- `install.sh`: no flow change required (it already runs `refresh-feeds` then
  `test-config`); the new verdict is computed there and surfaced by
  `test-config`. The post-install hint text gains a one-liner naming the
  detected posture.

### 6. Docs

- `README.md`: add an `auto` row to the `CF_MODE` table; state plainly that a
  non-Cloudflare box is fully supported and now blocks correctly (the prior
  fail-closed footgun is fixed). Keep the existing warning that `off` must not
  be used to mean "leave my Cloudflare alone" on a proxied box.
- `config/swatter.example.conf`: document `auto` as the default and what it
  detects.

## Components & boundaries

- `swatter_detect_cf` (new) — pure detector: gathers signals, returns a verdict;
  side effect limited to writing the cache file. Testable by pointing it at
  fixture `cloudflare.cidr` / `LFD_LOG` / vhost list and stubbing the resolver.
- `swatter_cf_fronted` (new) — posture predicate, range-independent; the base
  the other predicates build on.
- `swatter_cf_in_use` (changed) — fronted AND ranges present (classifier
  shortcut). `swatter_failclosed_active` (new) — fronted AND ranges unhealthy.
  `swatter_cf_manages_plane` (new) — fronted AND creds/map present (or explicit
  `direct`). All thin consumers of `swatter_cf_fronted` + the verdict cache.
- `swatter_scan` / `block_cf` (changed) — swap hardcoded `CF_MODE == "direct"`
  gates for the predicates above; no detection logic of their own.
- Verdict cache file (`$STATE_DIR/cf-detect`) — the only shared state between
  detection (write) and scan/status (read).

## Testing

Extend `test/` (no network, no root):

1. **Fail-closed fix:** with `CF_MODE=off` (and again with `auto`→`not-behind`)
   and a missing `cloudflare.cidr`, a scoring offender is routed to CSF
   (channel `csf`, not `skipped-failclosed`). With `CF_MODE=direct` + missing
   ranges, it still fail-closes (regression guard for the safety property).
2. **Detector verdicts:** fixtures for each branch — populated CF map ⇒
   `behind`; lfd socket in CF range ⇒ `behind`; stubbed resolver where vhosts
   resolve to a CF IP ⇒ `behind`; resolver where none do ⇒ `not-behind`; no
   resolver / no data ⇒ `uncertain`.
3. **`swatter_cf_in_use`:** verdict `not-behind` ⇒ not in use; `uncertain` /
   absent ⇒ falls through to the range-file check.

## Out of scope (YAGNI)

- Per-domain mode within one box beyond what `CF_DOMAINS_MAP` already provides.
- Active HTTP probing of the box's own URLs to read response headers.
- Auto-editing `swatter.conf` to replace `auto` with a concrete mode.
