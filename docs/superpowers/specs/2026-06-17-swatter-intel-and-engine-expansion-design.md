# Swatter — intel + engine expansion (v1.3) design

**Date:** 2026-06-17
**Status:** approved design, pre-implementation
**Scope:** one combined spec, sequenced build (single review/implementation cycle)

Adds six capabilities to Swatter, all default-off / safe, none changing the
existing scan cost on a box that doesn't opt in:

1. **GreyNoise** intel provider (with a benign/RIOT *suppression* verdict).
2. **Project Honey Pot http:BL** intel provider.
3. **Datacenter/hosting-ASN** signal (Team Cymru DNS, conditional additive boost).
4. **Honeypot/tarpit** instant-perm trap path.
5. **Low-and-slow** cross-window persistence escalation.
6. **Prometheus** textfile metrics.

The guiding invariants are unchanged: never take the site down, false-positive
on the via-CF plane = a challenge not a lockout, a failed/absent lookup never
blocks, and the cron path stays cheap (new lookups run **only for IPs already
past WATCH**, cached).

---

## 0. Cross-cutting: intel provider contract gains a `verdict` channel

**Problem.** RIOT-suppress (§1) needs a provider to say "this is known-good,
*cap* the score," but today a provider can only return a 0–100 score and
`swatter_intel_score` only ever returns the MAX (it can raise, never lower).

**Change.** Extend the provider output contract from 3 to an optional 4 fields:

```
score_0_100 \t ttl_seconds \t label \t verdict
```

`verdict` is `""` (normal) or `suppress`. Back-compatible: existing providers
(ipsum, spamhaus, abuseipdb) emit 3 fields and the 4th reads as empty.

`swatter_intel_score <ip>` return value goes from `best_score \t label` to:

```
best_score \t best_label \t suppress_flag
```

`suppress_flag` is `1` if **any** provider returned `verdict=suppress` for the
IP, else `0`. The intel cache file format gains the verdict
(`score \t label \t verdict`); a stale 2-field cache file reads verdict as empty.

**Consumption in `score.sh`.** After `swatter_intel_score`, if `suppress_flag=1`,
the IP is routed through the **existing never-block/exempt path** — the same
branch that already exempts an allowlisted IP — auditing
`action="exempt", channel="none", reason="intel:<label>"`. This means:

- Scoring still "only raises" — suppression is modeled as a *dynamic
  soft-allowlist*, not a negative score.
- Suppression wins over the CRITICAL bad-path floor **and** the honeypot
  perm-floor (§4). Rationale: a known Google/Slack/CDN range appearing to hit
  `/.env` or a secret trap is almost certainly a forged log line or
  misclassification, and the safety-biased choice is never to perm-ban core
  internet infrastructure. (One-line toggle `HONEYPOT_OVERRIDES_SUPPRESS` left
  for operators who want honeypot-wins; default `false`.)

**Files:** `lib/intel.sh` (contract + return value + cache format),
`lib/score.sh` (consume `suppress_flag`).

---

## 1. GreyNoise provider — `lib/providers/greynoise.sh`

**API.** GreyNoise Community API: `GET https://api.greynoise.io/v3/community/{ip}`
with header `key: ${GREYNOISE_KEY}`. Free Community tier. Needs `curl` + `jq`
(already required by abuseipdb). Daily-quota guard + intel cache, modeled
exactly on `abuseipdb.sh` (`$STATE_DIR/feeds/greynoise.quota.<YYYYMMDD>`).

**Response → output mapping** (fields: `noise` bool, `riot` bool,
`classification` ∈ {malicious,benign,unknown}, `name`):

| Condition | score | label | verdict |
|---|---|---|---|
| `classification == malicious` | 100 | `malicious:<name>` | `""` |
| `riot == true` | 0 | `riot:<name>` | `suppress` |
| `classification == benign` | 0 | `benign:<name>` | `""` |
| `unknown` / HTTP 404 / no data | — (exit 1) | — | — |

`benign` only labels/informs — behavior still decides, so an aggressive but
"benign"-classified scanner can still be blocked on its own conduct. `riot`
suppresses (§0).

**Config:** `GREYNOISE_KEY` (stub already exists in `common.sh`),
`GREYNOISE_DAILY_QUOTA` (default e.g. 100; tune to your plan). Provider returns
no-data when the key is empty, curl/jq missing, or quota exhausted.

---

## 2. Project Honey Pot http:BL provider — `lib/providers/projecthoneypot.sh`

**API.** DNS-based http:BL. Query
`<HTTPBL_KEY>.<reversed-octets>.dnsbl.httpbl.org` (A record). IPv4 only — return
no-data for any IPv6 IP. A valid hit's A record is `127.<days>.<threat>.<type>`:

- octet1 must be `127` (else NXDOMAIN/garbage → no data).
- octet2 = days since last activity (freshness).
- octet3 = threat score 0–255.
- octet4 = visitor-type bitmask: `0`=search engine, `1`=suspicious,
  `2`=harvester, `4`=comment spammer (bits combine).

**Mapping.** If type == 0 (pure search engine) → no-data (good crawlers are
already handled by `VERIFY_GOOD_CRAWLERS`). Otherwise score = `min(100, round(threat *
100 / 255))`, label `httpbl:t<type>:s<threat>:d<days>`. No `suppress` verdict.

**DNS client.** Prefer `dig +short`, fall back to `host` then `nslookup`;
degrade to no-data if none present (a new *optional* dependency — does not break
anything when absent). A small `SWATTER_HAVE_DIG`-style probe is added in
`common.sh`'s dependency block. Cached via the intel cache; no daily quota
(DNS, generous), `INTEL_CACHE_TTL` applies.

**Config:** `HTTPBL_KEY` (12-char access key; empty disables).

---

## 3. Datacenter/hosting-ASN signal — `lib/asn.sh`

**Source.** Team Cymru IP→ASN DNS:

- IPv4: reverse octets + `.origin.asn.cymru.com` TXT.
- IPv6: nibble-reverse + `.origin6.asn.cymru.com` TXT.
- TXT payload `"ASN | BGP-prefix | CC | registry | date"`; take the first ASN.

Runs **only for IPs past WATCH**, cached under `$STATE_DIR/asn/<ip>` with
`INTEL_CACHE_TTL`. Same DNS-client probe/fallback as §2; no-data if no client.

**Matching.** Resolved ASN is tested against `HOSTING_ASNS_FILE`
(`/etc/swatter/hosting-asns.txt`), one AS number per line (`#` comments ok).
Shipped default (operator-tunable):

```
16276   # OVH
14061   # DigitalOcean
24940   # Hetzner
20473   # Vultr / Choopa
63949   # Akamai / Linode
51167   # Contabo
14618   # AWS EC2 (us-east-1 legacy)   -- optional, high traffic; commented by default
9009    # M247
49981   # WorldStream
+ a short curated set of recurrent abuse-heavy hosting/bulletproof ASNs
```

**Scoring — conditional additive boost (NOT a max-fold).** This is the key
distinction from the intel layer. In `score.sh`, after the behavioral score and
the reputation fold, if `ASN_SIGNAL_ENABLE` and the IP's ASN ∈ hosting set
**and the evidence is attack-shaped**, add `W_ASN` (default 12) to the composite,
clamped to 100. "Attack-shaped" = any of: a decisive-floor rule fired
(`evidence.decisive_rule != ""`), `hibad_fail > 0`, or a meaningful error-burst
(`status 403/404/444` burst). A clean visitor from a hosting ASN gets **zero**
boost; a credential-brute from OVH at composite 64 is nudged to ~76 → TEMP.

The boost is applied before the TEMP/PERM threshold decision and recorded in the
audit reason (`asn=AS16276(OVH)+12`). It can only raise.

**Config:** `ASN_SIGNAL_ENABLE` (default `false`), `HOSTING_ASNS_FILE`,
`W_ASN` (default 12).

---

## 4. Honeypot / tarpit instant-perm — `score.awk` + `score.sh` + helper

**Trap definition.** `HONEYPOT_PATHS_FILE` (`/etc/swatter/honeypot.paths`), one
path-regex per line. **No default shipped** — a published trap path is a useless
trap; the operator picks a secret path (e.g. `/__trap_a7f3/`). Empty/absent file
disables the feature.

**Detection (`score.awk`).** Load the trap patterns in `BEGIN` (same mechanism
as `BADPATHS`, via a new `-v HONEYPOTS=` path). For each request, test the path
against the trap patterns; a match:

- sets `honeypot[ip]=1`,
- floors the score at 100, sets `decisive_rule="honeypot"`,
- **bypasses `MIN_REQS`** — extend the floor-guard
  `if (n < MIN_REQS && bm < 100) continue` to also pass when `honeypot[ip]`.
- emits `"honeypot":1` in the evidence JSON.

**Action (`score.sh`).** When `evidence.honeypot == 1` (or
`decisive_rule == "honeypot"`), force `action="perm"` immediately — skip the
temp ladder and the `REPEAT_N` repeat-offender accounting. Still:
plane-classified, allowlist/never-block checked, suppression-respected (§0),
circuit-breaker counted, audited (`reason="honeypot"`).

**Deploy helper — `swatter honeypot`.** New subcommand prints a ready-to-paste
snippet for the configured trap path (or a suggested random one if unset):

- a `robots.txt` line: `Disallow: /<trap>` (so well-behaved crawlers avoid it and
  only path-scanning bots find it),
- an invisible, `nofollow`, `aria-hidden` anchor to drop into a template so
  link-following bots trip it but humans never see it,
- a reminder to add the path to `HONEYPOT_PATHS_FILE`.

Swatter remains log-based — the helper only helps *advertise* the trap; detection
is in the scorer.

---

## 5. Low-and-slow persistence — `store_sqlite.sh` + `score.sh`

**Gap.** The 600 s window + `MIN_REQS` is blind to an attacker spreading sub-floor
activity over hours/days. Today only IPs that cross TEMP get persisted to the
store; WATCH-band IPs only hit `decisions.jsonl`.

**New table (SQLite).**

```sql
CREATE TABLE IF NOT EXISTS sightings(
  ip TEXT, bucket INTEGER, hits INTEGER DEFAULT 0,
  worst_score INTEGER DEFAULT 0, last_ts INTEGER,
  PRIMARY KEY (ip, bucket));
CREATE INDEX IF NOT EXISTS ix_sightings_ip ON sightings(ip);
```

`bucket = floor(now / PERSIST_BUCKET_SECONDS)` (default hourly). Bucketing makes
the overlapping 5-minute crons within one hour count **once**, so the threshold
measures distinct windows of badness, not scan frequency.

**Flow (`score.sh`).** For each IP in the WATCH band (folded ≥ `SCORE_WATCH`,
< `SCORE_TEMP`, not otherwise acted):

1. Upsert a sighting: `hits+1`, `worst_score = MAX(...)`, `last_ts = now`.
2. Count distinct buckets for the IP within `PERSIST_WINDOW_DAYS`.
3. If count ≥ `PERSIST_N` → **escalate**: treat as a TEMP block now, decisive
   rule `low_and_slow_persist`, through the normal plane/allowlist/breaker path.

On any block of an IP (here or elsewhere), delete its sightings rows so it
doesn't re-escalate every scan. Each scan also sweeps rows older than the window
(cheap `DELETE WHERE bucket < cutoff`).

**Defaults:** `PERSIST_ENABLE` = `true` (SQLite only), `PERSIST_N` = 6,
`PERSIST_WINDOW_DAYS` = 3, `PERSIST_BUCKET_SECONDS` = 3600. On the flatfile
store the feature no-ops with a `log_debug` (documented).

---

## 6. Prometheus textfile metrics — `lib/metrics.sh` + `swatter metrics`

**Output.** node_exporter textfile-collector format, **atomic** write
(`mktemp` in the same dir + `mv`) to `METRICS_FILE`
(default `/var/lib/node_exporter/textfile_collector/swatter.prom`; empty
disables). Emitted at the **end of `swatter_scan`** *and* on-demand via
`swatter metrics` (which can also `--print` to stdout).

**Metric set** (all `swatter_` prefixed, `# HELP`/`# TYPE` headers included):

| Metric | Type | Source |
|---|---|---|
| `swatter_scan_timestamp_seconds` | gauge | scan end time |
| `swatter_scan_watched` / `swatter_scan_acted` | gauge | last run counters |
| `swatter_blocks_total{action,channel}` | counter | `actions` table, cumulative |
| `swatter_offenders{state="temp\|perm"}` | gauge | `offenders` table |
| `swatter_feed_age_seconds{feed}` | gauge | mtime of cloudflare/ipsum/spamhaus feed files |
| `swatter_failclosed` | gauge 0/1 | `swatter_failclosed_active` |
| `swatter_circuit_breaker_tripped` | gauge 0/1 | last run |
| `swatter_intel_quota_used{provider}` | gauge | quota files |
| `swatter_mode{mode}` | gauge 1 | `SWATTER_MODE` |
| `swatter_build_info{version}` | gauge 1 | `SWATTER_VERSION` |

`feed_age_seconds` is the staleness signal an operator alerts on (e.g. feed not
refreshed in > 48 h ⇒ page). Reading the store is a handful of `COUNT`s; the
whole emit is sub-millisecond and never fails the scan (best-effort, like
`_swatter_audit`).

**Config:** `METRICS_FILE` (empty disables).

---

## Configuration summary (all new keys, all safe defaults)

```sh
# intel
INTEL_PROVIDERS="ipsum spamhaus abuseipdb greynoise projecthoneypot"  # new default
GREYNOISE_KEY=""              # already a stub
GREYNOISE_DAILY_QUOTA=100
HTTPBL_KEY=""                 # Project Honey Pot http:BL 12-char key

# asn signal
ASN_SIGNAL_ENABLE="false"
HOSTING_ASNS_FILE="/etc/swatter/hosting-asns.txt"
W_ASN=12

# honeypot
HONEYPOT_PATHS_FILE="/etc/swatter/honeypot.paths"
HONEYPOT_OVERRIDES_SUPPRESS="false"

# low-and-slow persistence
PERSIST_ENABLE="true"
PERSIST_N=6
PERSIST_WINDOW_DAYS=3
PERSIST_BUCKET_SECONDS=3600

# metrics
METRICS_FILE="/var/lib/node_exporter/textfile_collector/swatter.prom"
```

---

## Files

**New:**
- `lib/providers/greynoise.sh`
- `lib/providers/projecthoneypot.sh`
- `lib/asn.sh`
- `lib/metrics.sh`
- `config/hosting-asns.txt`
- `config/honeypot.paths.example` (commented example; the live file is operator-authored)

**Modified:**
- `lib/intel.sh` — 4-field contract, suppress flag, cache format
- `lib/score.awk` — honeypot detection/floor/MIN_REQS bypass + evidence flag
- `lib/score.sh` — suppress handling, ASN boost, honeypot perm, persistence escalation, metrics hook
- `lib/store_sqlite.sh` — `sightings` table + upsert/count/prune + offender-state counts
- `lib/common.sh` — DNS-client probe, new config defaults
- `bin/swatter` — `honeypot` + `metrics` subcommands; `SWATTER_VERSION` → `1.3.0`
- `config/swatter.example.conf` — document all new keys
- `README.md` — providers, ASN signal, honeypot, persistence, metrics sections
- installer — install `hosting-asns.txt` + `honeypot.paths.example`, note the
  metrics dir

`refresh-feeds` is **unchanged** — every new lookup is per-IP HTTP/DNS, no new
feed file to download.

---

## Dependencies

- GreyNoise: `curl` + `jq` (already required by abuseipdb).
- Project Honey Pot + Team Cymru ASN: a DNS client (`dig` preferred,
  `host`/`nslookup` fallback) — a **new optional** dependency. All three degrade
  cleanly to no-data when no client is present; nothing breaks.

---

## Testing

Matches the existing `test/` harness; no live keys needed (mock `curl`/`dig`):

- **greynoise:** mocked curl JSON for malicious / riot(suppress) / benign /
  unknown / quota-exhausted / no-key.
- **projecthoneypot:** mocked dig A-records for each visitor-type bitmask,
  search-engine→no-data, IPv6→no-data, no-DNS-client→no-data.
- **asn:** mocked Cymru TXT parse; ASN in/out of the hosting set; boost applied
  only when attack-shaped; no boost on clean behavior.
- **score.awk:** honeypot hit floors at 100 and bypasses `MIN_REQS`;
  `"honeypot":1` in evidence.
- **persistence:** against a temp SQLite db — N distinct buckets escalate,
  sub-N does not, overlapping same-bucket crons count once, sightings cleared on
  block.
- **metrics:** emitted file is valid `.prom` (HELP/TYPE present, label syntax),
  written atomically, empty `METRICS_FILE` disables.
- **intel contract:** 3-field legacy providers still parse; suppress flag
  propagates; suppress routes to exempt.

---

## Build order (dependency-aware)

1. Intel contract + suppress plumbing (`lib/intel.sh`, `lib/score.sh`)
2. GreyNoise provider
3. Project Honey Pot provider
4. ASN signal (`lib/asn.sh` + score.sh boost)
5. Honeypot (score.awk + score.sh + `swatter honeypot`)
6. Persistence (store schema + score.sh escalation)
7. Metrics (`lib/metrics.sh` + `swatter metrics` + scan hook)
8. Docs + installer + `SWATTER_VERSION` bump to `1.3.0`

Steps 1–3 share the intel layer; 4–6 are independent of each other; 7 reads what
the others write. Per Swatter's release rule, the version bump + tag +
GitHub/GitLab release is part of step 8 (push alone does not publish).

---

## Deployment (keys)

Keys live in the Proton Pass `AI` vault, deployed root-only to `/etc/swatter/`
like the existing CF creds — never committed:

- AbuseIPDB — `AI > AbuseIPDB > API Key`
- GreyNoise — `AI > GreyNoise > API Key`
- Project Honey Pot http:BL — `AI > Project HoneyPot > Access Key`

All three keys are provisioned and in the vault.

A deploy helper in `install/` (mirroring `swatter-deploy-cf-creds.sh`) writes the
keys into `/etc/swatter/swatter.conf` or a root-only key file with `0600`
`root:root`, matching the cross-tree SSH/ownership rules.
```
