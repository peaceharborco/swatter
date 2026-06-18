# Swatter v1.4 — feeds + maintenance design

**Date:** 2026-06-17
**Status:** approved design, pre-implementation
**Scope:** one combined spec — 6 keyless list feeds (generic registry), AbuseIPDB
daily blocklist (opt-in), IPv6 ASN lookups, Spamhaus EDROP fix.

All additions are list/feed work that follows the existing `ipsum.sh`/`spamhaus.sh`
patterns. The guiding invariants are unchanged: a failed/absent lookup never
blocks; intel is only consulted for IPs **already past WATCH** and is cached, so
the cron path stays cheap; list feeds are downloaded by `refresh-feeds`, not per
scan; the never-block allowlist (CF ranges, operator IPs, monitoring) is checked
last and wins over any feed hit.

---

## 0. Why a registry (not 7 more files)

Six new keyless list feeds join the existing `ipsum`/`spamhaus`. They differ only
by URL, wire format, parse rule, and confidence score. Rather than 7 near-duplicate
provider files (the per-task reviews in v1.3 flagged verbatim duplication as a
defect), a single **data-driven registry** holds one row per feed and two generic
handlers do all the work. Adding a future feed becomes one table row.

---

## 1. Generic list-feed registry — `lib/providers/listfeeds.sh`

**Registry table** (one row per feed): `name · url · format(ip|cidr) · score · parse`.

| name | url | format | score | parse (awk over the raw download) |
|---|---|---|---|---|
| `firehol_level1` | `https://iplists.firehol.org/files/firehol_level1.netset` | cidr | 95 | `/^[0-9]/{print $1}` |
| `cins` | `https://cinsscore.com/list/ci-badguys.txt` | ip | 95 | `/^[0-9]/{print $1}` |
| `dshield` | `https://feeds.dshield.org/block.txt` | cidr | 95 | `/^[0-9]/ && $3>=0 && $3<=32 {print $1"/"$3}` |
| `blocklist_de` | `https://lists.blocklist.de/lists/all.txt` | ip | 80 | `/^[0-9A-Fa-f]/{print $1}` |
| `et_compromised` | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | ip | 80 | `/^[0-9]/{print $1}` |
| `greensnow` | `https://blocklist.greensnow.co/greensnow.txt` | ip | 70 | `/^[0-9]/{print $1}` |

Scores are **confidence tiers**: A≈95 (near-zero-FP: FireHOL level1, CINS,
DShield) · B≈80 (blocklist.de, ET compromised) · C≈70 (GreenSnow). Spamhaus stays
100; ipsum stays level-scaled. Because intel is a MAX-fold that only *raises* an
already-past-WATCH IP, the score controls how hard a feed can push a borderline IP
over TEMP — a noisier feed corroborates less.

**Two generic handlers:**
- `_listfeed_refresh <name>` — look up the row, `curl --max-time 30 -fsS <url>` to a
  `.tmp`, pipe through the row's `awk` parse, and **`mv` to the final file only on
  success** (a transient feed outage keeps the prior file; mirrors `ipsum`/`spamhaus`).
  Output path: `$STATE_DIR/feeds/<name>.txt` (ip) or `.cidr` (cidr). Requires
  `SWATTER_HAVE_CURL` (warn + return 1 otherwise).
- `_listfeed_lookup <name> <ip>` — ip format: `awk -v ip=... '$1==ip{found=1;exit}
  END{exit !found}'`; cidr format: reuse `_ip_in_cidr_file` (from `allowlist.sh`).
  On hit, the calling provider emits `score \t INTEL_CACHE_TTL \t <name>` (3-field
  contract, **no suppress verdict** — feeds never suppress). On miss / missing feed
  file, return 1 (no data).

**Provider generation.** At source time, `listfeeds.sh` iterates the registry and
defines, for each `name`, two thin functions via `eval`:
```sh
eval "provider_${name}()        { _listfeed_lookup ${name} \"\$1\"; }"
eval "provider_${name}_refresh() { _listfeed_refresh ${name}; }"
```
so the intel layer dispatches each by exact name (`provider_${prov}`) and
`refresh-feeds` finds each `provider_${prov}_refresh`. The registry is the single
source of truth for url/score/format, read by both handlers via the `name` key.

**Bogon note.** FireHOL level1 includes reserved/bogon ranges (`0.0.0.0/8`,
`10.0.0.0/8`, …). That is intentional and safe here: intel is only consulted for
IPs that already crossed WATCH from real traffic, and the never-block allowlist is
checked last, so a flagged bogon cannot cause a wrong block of a legitimate peer.

---

## 2. `swatter_intel_init` + `refresh-feeds` wiring

`swatter_intel_init` (in `lib/intel.sh`) currently sources `providers/<name>.sh`
per provider name — which does not exist for registry feed names. Two changes:

1. **Source aggregates first.** Before the per-name loop, source any aggregate
   provider file that exists (currently just `listfeeds.sh`):
   `[[ -f "${SWATTER_LIB_DIR}/providers/listfeeds.sh" ]] && source ...`.
2. **Suppress the spurious "not found" warn.** In the per-name loop, if
   `providers/<name>.sh` is absent but `provider_<name>` is already defined (by an
   aggregate), skip silently; only warn when the provider is genuinely undefined.

`cmd_refresh_feeds` (in `bin/swatter`) already calls `swatter_intel_init` (line
~213) before refreshing. Replace the two hardcoded
`provider_ipsum_refresh`/`provider_spamhaus_refresh` lines with a self-extending
loop:
```sh
local p
for p in ${INTEL_PROVIDERS}; do
    declare -F "provider_${p}_refresh" >/dev/null && { provider_"${p}"_refresh || true; }
done
```
Per-IP providers (greynoise/abuseipdb/projecthoneypot) define no `_refresh` and are
skipped; every list feed refreshes automatically.

---

## 3. AbuseIPDB daily blocklist — `lib/providers/abuseipdb_blocklist.sh` (opt-in)

A separate provider name (`abuseipdb_blocklist`) reusing `ABUSEIPDB_KEY`, distinct
from the per-IP `abuseipdb` provider:

- `provider_abuseipdb_blocklist_refresh` — `GET https://api.abuseipdb.com/api/v2/blacklist`
  with `Key:` + `Accept: text/plain` and `--data-urlencode confidenceMinimum=${ABUSEIPDB_BLOCKLIST_CONFIDENCE:-90}`,
  written (atomically, `.tmp`+`mv` on success) to `$STATE_DIR/feeds/abuseipdb_blocklist.txt`
  (one IP per line). No-op + warn without `ABUSEIPDB_KEY` or `curl`. Any HTTP/transport
  failure leaves the prior file intact.
- `provider_abuseipdb_blocklist` — flat-IP grep (same idiom as the registry ip
  handler), emits `90 \t INTEL_CACHE_TTL \t abuseipdb_blocklist` on hit; inert
  (return 1) when the feed file is absent.
- **Opt-in:** NOT in the default `INTEL_PROVIDERS` (needs the key and spends a daily
  blacklist call). Documented as a config addition. Its `_refresh` runs only if the
  operator adds `abuseipdb_blocklist` to `INTEL_PROVIDERS`.
- Config: `ABUSEIPDB_BLOCKLIST_CONFIDENCE=90`.

> Not folded into `abuseipdb.sh`: keeping it a separate file/name keeps each
> provider single-responsibility and lets an operator run the cheap daily blocklist
> *instead of* per-IP checks (to save quota) or alongside it (MAX-fold takes the
> higher).

---

## 4. IPv6 ASN lookups (origin6) — `lib/asn.sh`

Implement the deferred `TODO(v1.3.1)`. In `swatter_asn_resolve`, replace the v6
early-return with an origin6 query:

- Expand the v6 address to 32 hex nibbles via the existing `_ipv6_expand` (from
  `allowlist.sh`; already sourced) — returns the 128-bit value as 32 lowercase hex
  nibbles, handling `::` compression and v4-mapped forms.
- Reverse the nibble string and dot-separate it, append `.origin6.asn.cymru.com`,
  and query TXT via `_swatter_dns_txt` — the **same parse, cache, and hosting-match**
  as the v4 path (origin TXT is `"ASN | prefix | CC | registry | date"`; take the
  first ASN token). Reversal: `printf '%s' "$nibbles" | rev | sed 's/./&./g; s/\.$//'`
  (or an awk equivalent) yields `1.0.0.….1.0.0.2`.
- Cache key is the IP string (works unchanged for v6); the hosting-set match is
  already ASN-number based, so a v6 attacker from a hosting ASN now gets the
  conditional boost. Malformed/unresolvable v6 still returns no-data (no boost).

---

## 5. Spamhaus EDROP fix — `lib/providers/spamhaus.sh`

`edrop.txt` is deprecated — it now returns 6 empty lines; its content was merged
into `drop.txt` (1,714 CIDRs). Remove `SPAMHAUS_EDROP_URL` and drop it from the
refresh loop; fetch only `drop.txt`. The parse (`awk '/^[0-9]/{print $1}'`,
stripping the `; SBLnnn` comment) and the `provider_spamhaus` lookup are unchanged.
Net: one fetch, identical coverage, no more silent failure on the dead endpoint.

---

## Configuration summary

```sh
# New default — adds the 6 keyless feeds (existing 5 + these):
INTEL_PROVIDERS="ipsum spamhaus abuseipdb greynoise projecthoneypot \
                 firehol_level1 blocklist_de cins greensnow dshield et_compromised"

# AbuseIPDB daily blocklist (opt-in: add 'abuseipdb_blocklist' to INTEL_PROVIDERS;
# reuses ABUSEIPDB_KEY).
ABUSEIPDB_BLOCKLIST_CONFIDENCE=90
```

All feed providers degrade to no-data when their feed file is absent (e.g. before
the first `refresh-feeds`), so an upgraded install is never broken — coverage
begins after the next refresh.

---

## Files

**New:**
- `lib/providers/listfeeds.sh` — registry + 2 generic handlers + generated providers.
- `lib/providers/abuseipdb_blocklist.sh` — opt-in daily blocklist provider.

**Modified:**
- `lib/intel.sh` — `swatter_intel_init` sources aggregates + suppresses spurious warn.
- `bin/swatter` — `cmd_refresh_feeds` self-extending refresh loop; `SWATTER_VERSION=1.4.0`.
- `lib/asn.sh` — origin6 v6 ASN path.
- `lib/providers/spamhaus.sh` — drop the dead EDROP fetch.
- `lib/common.sh` — new `INTEL_PROVIDERS` default + `ABUSEIPDB_BLOCKLIST_CONFIDENCE`.
- `config/swatter.example.conf` — document the new feeds + opt-in blocklist.
- `README.md` — extend the threat-intel feed list; note "run `refresh-feeds` after
  upgrade" so the new feeds download.

No new `/etc/swatter/` files — all feeds download to `STATE_DIR/feeds/`.

---

## Testing

Plain bash suites under `test/`, mocking `curl`/`dig`:
- **listfeeds:** registry generates `provider_<name>` + `provider_<name>_refresh` for
  every row; `_listfeed_refresh` with a mocked `curl` produces the right parsed file
  for each format (flat-IP, plain-CIDR, DShield `col1/col3` with the 0–32 guard);
  `_listfeed_lookup` hit returns the row's tier score, miss/missing-file returns
  no-data; ip vs cidr dispatch correct.
- **abuseipdb_blocklist:** mocked-curl refresh writes the flat file; lookup hit→90,
  miss→no-data; empty key→no-data + no fetch.
- **asn origin6:** extend `asn_test.sh` — a v6 IP, with a mocked `_swatter_dns_txt`,
  resolves its ASN and matches the hosting set; the nibble-reverse query name is
  correct.
- **spamhaus:** refresh now fetches a single URL; `provider_spamhaus` lookup
  unchanged (CIDR hit→100).
- **refresh loop:** providers without a `_refresh` (greynoise/abuseipdb) are skipped
  without error; a registry feed's `_refresh` is invoked.
- **intel_init:** a registry feed name in `INTEL_PROVIDERS` resolves to a defined
  `provider_<name>` (no spurious "not found" warn); a genuinely-missing provider
  still warns.

---

## Build order

1. `listfeeds.sh` registry + handlers + generation (the core).
2. `intel_init` aggregate-sourcing + warn suppression.
3. `refresh-feeds` self-extending loop.
4. `abuseipdb_blocklist.sh` (opt-in).
5. `asn.sh` origin6 v6 path.
6. `spamhaus.sh` EDROP removal.
7. `common.sh` default + config; `swatter.example.conf`; README; `SWATTER_VERSION=1.4.0`.

Steps 1–3 are the registry spine and must land together-ish (the registry is inert
until intel_init sources it and refresh feeds it). 4–6 are independent. Per the
release rule, the version bump + tag + GitHub/GitLab release is a separate deliberate
step after merge (push alone does not publish).
