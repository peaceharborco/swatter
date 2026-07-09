# Proposal: per-plane enforcement + CSF channel-upgrade

Status: **sketch v2 — revised after Grok review** (see
`csf-channel-enforcement-review-grok.md`) · Author: Josh (via Claude) ·
Anchors: `lib/score.sh`, `lib/classify.sh`, `lib/store_sqlite.sh`, `lib/block*.sh`, `bin/swatter`

## Incident that motivates this

2026-07-08, cds1: a webmail flood on **:2095** (cpsrvd) drove ~15.5k Apache
`connect to 127.0.0.1:2095 failed` errors and a brief CPU warning as cpsrvd's
45-slot listen backlog overflowed. Two IPs did most of it (`45.148.10.67`,
`195.178.110.199`). Both were **already perm-blocked by Swatter** — score 91,
`spamhaus:drop(100)` — but **only on the Cloudflare plane**. A CF IP Access Rule
blocks at the edge; a direct-to-server-IP connection to :2095 never transits CF,
so the block did nothing, and there was **no active CSF deny**. cPHulk (enabled)
kept logins safe; the damage was connection volume against an open service port.

## Root cause

1. **Perm-ness is global, not per-plane.** `offenders.perm` is one boolean and
   `offenders.channel` is last-write-wins (`lib/store_sqlite.sh:106,132`). So
   `swatter_store_is_perm` is true the moment an IP is perm-blocked on *any* plane.
2. **`noop-perm` short-circuits channel re-routing.** `lib/score.sh:254` (and the
   honeypot path `:246`, and `lib/swarm.sh:182`) dismiss any perm IP without
   re-classifying — a CF-perm IP that later hits the origin directly can never
   acquire the CSF deny that would stop it.
3. **The DIRECT set can miss a service-port flood.** `swatter_build_direct_set`
   Source 1 reads `lfd.log` cPanel-port lines; a backlog-exhaustion flood that
   never trips lfd leaves the flood IP out of the set → classify `VIA_CF`.

## What the Grok review changed (v1 → v2)

The v1 sketch tried to derive plane state from the append-only `actions` log.
That is unsafe: the query would count live **temps** as perm (breaks the
temp→perm ladder), survive **unblock** (can't re-block), and count **dry-run**
report-mode rows (never blocks after the enforce flip), and it dropped the
`ipset` backend. v1 also tried to do dual-plane by calling
`_swatter_execute_block` twice — but that function re-classifies and would just
repeat the same plane, and a forced backend call would bypass the `never_block` /
unsafe-target / fail-closed / cap gates. **v2 replaces both mechanisms:**

- a **dedicated per-plane state table** that is written on real block and cleared
  on unblock (no log-replay hazards); and
- a **forced-plane helper** that all three paths (normal, upgrade, dual-plane)
  funnel through, so every block — including the second plane — passes the same
  gates and counters.

## Design

### 0. Per-plane state table (replaces the `active_planes` SQL)

```sql
CREATE TABLE IF NOT EXISTS plane_blocks (
  ip     TEXT NOT NULL,
  plane  TEXT NOT NULL,            -- 'csf' | 'ipset' | 'cloudflare'
  kind   TEXT NOT NULL,           -- 'perm' | 'temp'
  expires_at INTEGER NOT NULL,    -- 0 = perm (never), else epoch
  PRIMARY KEY (ip, plane)
);
```
- **Written only on an ENFORCED block** (never in dry-run / report mode) —
  upsert `(ip, plane, kind, expires_at)` right where `swatter_store_record` runs
  for a real action (`lib/score.sh:122`, `dry_run==0` branch only).
- **Cleared on unblock:** `swatter_store_unblock` (`lib/store_sqlite.sh:174`) —
  and `cmd_unblock` already drops both firewall planes (`bin/swatter:157-158`) —
  also `DELETE FROM plane_blocks WHERE ip=?`. This is the fix for the
  can't-re-block-after-unblock hazard.

```sh
# perm-blocked on THIS plane right now? (perm only — temps still escalate)
swatter_store_is_perm_on() {                       # ip, plane
    [[ "$(_sqlq "SELECT 1 FROM plane_blocks
                 WHERE ip='$(_sql_escape "$1")' AND plane='$2'
                   AND kind='perm' LIMIT 1;")" == 1 ]]
}
# any active (perm OR unexpired temp) block on this plane — for noop of repeats
swatter_store_active_on() {                        # ip, plane
    [[ "$(_sqlq "SELECT 1 FROM plane_blocks
                 WHERE ip='$(_sql_escape "$1")' AND plane='$2'
                   AND (kind='perm' OR expires_at > $(swatter_now)) LIMIT 1;")" == 1 ]]
}
```
Plane values come straight from `${DIRECT_BACKEND:-csf}` / `cloudflare`, so
`ipset` is handled with no special-casing. `perm_blocks` on the flatfile store is
a no-op (flatfile already can't do low-and-slow persistence,
`lib/store_sqlite.sh:182`) — flatfile keeps today's global-perm behavior, and
per-plane upgrade is a **sqlite-only** feature. No wrong flatfile semantics.

### 1. Forced-plane helper (replaces the twice-called execute_block)

Factor the plane-execution tail of `_swatter_execute_block` into one helper that
takes an explicit plane and runs **all** the gates. Both the normal path and the
upgrade/dual-plane paths call it — nothing calls a backend directly.

```sh
# _swatter_apply_plane <ip> <plane:DIRECT|VIA_CF> <action> <ttl> <reason>
#                       <top_vhost> <healthy> <folded> <ev> <rep>
# Returns 0 and audits on success; audits skipped-* / failed otherwise.
_swatter_apply_plane() {
    local ip=$1 plane=$2 action=$3 ttl=$4 reason=$5 top_vhost=$6 healthy=$7 \
          folded=$8 ev=$9 rep=${10} channel rc=0

    _swatter_block_ip_ok "$ip" || return 1                 # invalid/unsafe target
    swatter_is_never_block "$ip" && { _swatter_audit ... exempt ...; return 1; }  # CF ranges, operator, monitoring
    (( _SW_TOTAL_BLOCKS >= MAX_BLOCKS_PER_RUN )) && { SWATTER_RUN_BREAKER=1; _swatter_audit ... skipped-cap ...; return 1; }

    if [[ "$plane" == DIRECT ]]; then
        channel="${DIRECT_BACKEND:-csf}"
        (( healthy )) || { _swatter_audit ... skipped-failclosed ...; return 1; }   # fail-closed
        [[ "$action" == perm ]] && swatter_block_direct_perm "$ip" "$reason" || swatter_block_direct_temp "$ip" "$ttl" "$reason"; rc=$?
    else
        channel="cloudflare"
        swatter_cf_manages_plane || { _swatter_audit ... skipped-cf-plane ...; return 1; }
        [[ "$action" == perm ]] && ttl="$(_swatter_pick_ttl 99)"
        swatter_cf_block "$ip" "$ttl" "$reason" "$top_vhost"; rc=$?
    fi
    (( rc == 0 )) || { <existing rc==CAP/CONFIG/NOVHOST/failed audit logic>; return 0; }

    (( _SW_TOTAL_BLOCKS++ )); SWATTER_RUN_ACTED=$((SWATTER_RUN_ACTED+1))    # breaker counts EVERY plane
    swatter_store_record "$ip" "$action" "$channel" "$ttl" "$folded" "$reason" \
        "$([[ ${SWATTER_MODE} == enforce ]] && echo 0 || echo 1)"
    [[ ${SWATTER_MODE} == enforce ]] && swatter_store_plane_set "$ip" "$channel" "$action" "$ttl"  # per-plane table
    _swatter_audit "$ip" "$folded" "$action" "$channel" "$ttl" "$reason" "$ev" "$rep"
}
```
`_swatter_execute_block` becomes: classify once → `_swatter_apply_plane … "$plane"
…`. The CSF cap (`SWATTER_CSF_DENIES_THIS_RUN`) stays inside `block_csf.sh` as
today. Because the breaker (`_SW_TOTAL_BLOCKS`) lives in the shared helper, a
second plane correctly costs 2 toward the breaker and is itself breaker-gated —
no bypass, no under-count. `swatter_abuseipdb_report` moves to fire **once per
IP per run** (guard on a per-run seen-set), not per plane.

### 2. Channel-upgrade in the scan loop

Replace the blanket `swatter_store_is_perm → noop-perm` at `lib/score.sh:254`
**and the honeypot path at `:246`** with:

```sh
plane="$(swatter_classify "$ip" "$novhost")"
want_ch=$([[ "$plane" == DIRECT ]] && echo "${DIRECT_BACKEND:-csf}" || echo cloudflare)

if swatter_store_active_on "$ip" "$want_ch"; then
    _swatter_audit ... noop-perm ...; continue          # already covered on the plane the evidence points to
fi
if swatter_store_is_perm "$ip"; then                    # perm on the OTHER plane → upgrade, not noop
    _swatter_apply_plane "$ip" "$plane" perm 0 "plane-upgrade ${reason}" \
        "$top_vhost" "$healthy" "$folded" "$ev" "$rep"
    continue
fi
... existing temp/perm ladder, but calling _swatter_apply_plane ...
```
Audit label: `_swatter_apply_plane` audits `action=perm`; to surface upgrades
distinctly, pass an `audit_action` override (`plane-upgrade`) — one extra param —
so `report.sh`/digest and the tests agree. Note `is_perm_on` is **not** used in
the hot path; `active_on` (perm-or-unexpired-temp) drives the noop so a live temp
still escalates through the ladder (it is not perm, so the `is_perm` branch is
skipped and the ladder runs).

Incident replay: once `45.148.10.67` shows DIRECT evidence, it classifies
`DIRECT`, `active_on(csf)` is false, it is perm on CF → **upgrade adds a CSF
deny.** With Source 3 (below) the DIRECT evidence appears the very next scan.

### 2b. Swarm consumer — same per-plane skip (in scope)

The fleet consumer has the identical global short-circuit
(`lib/swarm.sh:182`): `swatter_store_is_perm "$ip" && continue`. A swarm
candidate has no local traffic, so its comment already states it "protects the
DIRECT plane" (a CF target audits `skipped-novhost`). So a fleet-corroborated IP
that is only CF-perm today never acquires the CSF deny the swarm evidence
justifies. v2 change:

```sh
# was: swatter_store_is_perm "$ip" && continue
swatter_store_active_on "$ip" "${DIRECT_BACKEND:-csf}" && continue   # skip only if already on the direct plane
```
and route the swarm block through the forced-plane helper on the **DIRECT** plane
(swarm's posture — it can't name a vhost) instead of `_swatter_execute_block`'s
re-classification:

```sh
# was: _swatter_execute_block "$ip" temp "$ttl" "$score" ...
_swatter_apply_plane "$ip" DIRECT temp "$ttl" "swarm-corroborated hosts=${hc}" \
    "" "$healthy" "$score" "{\"swarm\":true,\"hosts\":${hc}}" "$score" && n=$(( n + 1 ))
```
This keeps swarm's existing DIRECT-only posture explicit (no more incidental
`skipped-novhost` on the CF plane) and lets a CF-perm IP pick up its CSF deny
from fleet corroboration. The health gate inside the helper preserves fail-closed
exactly as the loop's `healthy` flag intends (`lib/swarm.sh:170-171`).

### 3. Dual-plane for hard-intel IPs

For `rep >= INTEL_HARDBLOCK_MIN` (default 100) **and `action == perm`**, after the
primary plane succeeds, apply the *other* plane through the same helper:

```sh
if [[ "${DUAL_PLANE_HARD_INTEL}" == true ]] && (( rep >= INTEL_HARDBLOCK_MIN )) \
   && [[ "$action" == perm ]] && (( did )); then
    other=$([[ "$plane" == DIRECT ]] && echo VIA_CF || echo DIRECT)
    _swatter_apply_plane "$ip" "$other" perm 0 "dual-plane ${reason}" \
        "$top_vhost" "$healthy" "$folded" "$ev" "$rep"
fi
```
**Fail-closed interaction (the M9 fix):** the DIRECT leg is health-gated *inside*
`_swatter_apply_plane`, so it self-suppresses to `skipped-failclosed` when ranges
are stale — the CF leg is unaffected. And because the primary path no longer
`return`s the whole function on an unhealthy DIRECT (that early-return moves into
the per-plane helper), a hard-intel IP whose primary plane is DIRECT-but-fail-
closed still reaches the CF leg. So dual-plane degrades to CF-only under stale
ranges instead of doing nothing.

**Why CSF-ing a hard-intel IP does not risk a proxy outage:** Swatter denies the
**logged client IP**, never the TCP edge socket, and `_swatter_apply_plane` runs
`swatter_is_never_block` first — which already covers the Cloudflare ranges
(`lib/allowlist.sh:218-221`). So the invariant ("never CSF a CF edge") is held by
never_block, not by the reputation score. The real residual risk is a
**false-positive intel-100** getting CSF-locked off origin service ports (user
lockout, not site outage) — bounded by intel being high-confidence,
operator/monitoring allowlists, and one-command reversibility (`swatter unblock`,
which now also clears `plane_blocks`).

### 4. DIRECT-set Source 3 — service-port socket peers

Add to `swatter_build_direct_set`, **mirroring Source 2 exactly** (the health
gate and CF-range exclusion are not optional):

```sh
if [[ -n "${SERVICE_PORTS:-}" ]] && swatter_allowlist_healthy; then   # SAME gate as Source 2
    while IFS= read -r peer; do
        [[ -n "$peer" ]] || continue
        _ip_in_cidr_file "$peer" "${CLOUDFLARE_IPS_FILE}" && continue  # SAME CF exclusion
        printf '%s\n' "$peer"
    done < <(_swatter_service_port_peers) >> "$out"
fi
```
`_swatter_service_port_peers` = `_swatter_websocket_peers` generalized to
`SERVICE_PORTS="2082 2083 2086 2087 2095 2096 2077 2078"`. Caveats made explicit:
IPv4-only (inherits `_swatter_websocket_peers`, `lib/classify.sh:195`; IPv6 is a
follow-up), point-in-time `ss` sample (short floods may miss a window — detection
lag, not an invariant break), and **legit direct clients** (operator WHM, backup,
monitoring, direct-webmail customers) fold in the same way — they are protected
**only** by never_block / operator / monitoring allowlists
(`lib/allowlist.sh:223-239`), so document that Source 3 assumes those are
populated before it can safely feed CSF.

## Safety rails (preserved — verified against code)

- **Every block, all three paths, goes through `_swatter_apply_plane`** → one
  place enforces: valid/safe target, `never_block` (incl. CF ranges), fail-closed
  health gate on the CSF/direct plane, and the `MAX_BLOCKS_PER_RUN` breaker.
- **Fail-closed** is unchanged in force: a DIRECT plane with unhealthy ranges
  audits `skipped-failclosed` and writes nothing (`lib/score.sh:105` logic, now
  in the helper). Dual-plane degrades to CF-only, never CSF-without-ranges.
- **`plane_blocks` is written only when `SWATTER_MODE==enforce`** → report/dry-run
  never poisons plane state.
- **Unblock stays symmetric** — `bin/swatter:157-158` already removes both
  firewall planes; v2 only adds the `plane_blocks` row deletion so the ledger
  matches.
- **`CF_MODE=off` (bare box):** everything is DIRECT/CSF, one plane exists →
  dual-plane and upgrade are inert. Flatfile store → per-plane feature off,
  today's global behavior.

## Decision table

| IP state | new evidence | today | v2 |
|---|---|---|---|
| perm on CF, no direct evidence | via-CF again | `noop-perm` | `noop-perm` (active_on cf) |
| perm on CF, **new direct evidence** | hit :2095 direct | `noop-perm` ❌ | **upgrade → CSF deny** |
| live **temp** on plane, re-offends | same plane | ladder escalates | ladder escalates (active_on, not perm → falls through) |
| **unblocked**, re-offends | any | re-blocks | re-blocks (plane_blocks cleared) |
| first perm, **intel ≥ 100**, healthy | any | single plane | **both planes** |
| first perm, intel ≥ 100, ranges stale | direct | fail-closed (no block) | **CF-only** (CSF leg skipped-failclosed) |
| first block, behavioral only | via-CF | CF only | CF only (unchanged) |
| any, CF-range / operator IP | any | never-block | never-block (helper runs it first) |

## Tests (`test/dual_plane_test.sh` + extend classify/block_csf/unblock/score)

1. CF-perm IP + DIRECT_SET membership → CSF deny, audit `plane-upgrade`.
2. CF-perm IP, only via-CF evidence → `noop-perm` (no regression).
3. **Live CSF temp, re-offends** → ladder escalates to perm (NOT noop) — the B1 regression guard.
4. **Unblocked IP re-offends** → re-blocks; `plane_blocks` empty after unblock — the B2 guard.
5. **Report-mode dry-run perm, then enforce** → real block placed; no `plane_blocks` row written while dry — the B4 guard.
6. `DIRECT_BACKEND=ipset` → plane recorded/queried as `ipset`; upgrade/noop correct — the B5 guard.
7. intel-100 first perm, healthy → both `swatter_cf_block` and `swatter_csf_perm` called; breaker += 2.
8. intel-100 first perm, **unhealthy** ranges, primary VIA_CF → CF placed, CSF `skipped-failclosed`.
9. intel-100 first perm, **unhealthy** ranges, primary DIRECT → CF-only placed (M9 path), CSF `skipped-failclosed`.
10. behavioral-only via-CF → CF only (unchanged).
11. Source 3: non-CF peer on :2095 → in DIRECT set; CF-edge peer excluded; **stale ranges → Source 3 contributes nothing** (health gate).
12. Honeypot CF-perm + DIRECT evidence → CSF upgrade (M4).
13. `swatter unblock` removes both firewall planes AND clears `plane_blocks`.
14. `CF_MODE=off` → dual-plane inert; single-plane identical to today.
15. abuseipdb reported once per IP per run despite dual-plane (Minor).
16. Swarm: CF-perm IP with fleet corroboration → CSF deny on the DIRECT plane; already-direct IP → skipped; no incidental CF `skipped-novhost` (§2b).

## Rollout

Ship behind `DUAL_PLANE_HARD_INTEL` (default on). The upgrade path only ever
*adds* a block the evidence already justifies, through the same gates — safe to
leave always-on. Watch the digest for any `plane-upgrade`/`dual-plane` on an
unexpected IP for a week, same gate as the original enforce cutover. The swarm
consumer fix (§2b) is **in scope** — the scan loop and the fleet consumer land
together so no path stays single-plane.
```
