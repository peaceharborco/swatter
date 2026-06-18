# 🪰 Swatter

[![CI](https://github.com/peaceharborco/swatter/actions/workflows/ci.yml/badge.svg)](https://github.com/peaceharborco/swatter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A Cloudflare-aware abuse swatter for cPanel + CSF servers.**

Swatter reads your web-server logs, scores every IP on weighted behavioral
signals plus optional threat-intel, and blocks the malicious ones — automatically,
on the right firewall plane. Distributed scanners, credential brute-force,
`/.env` and `/.git` probes, exploit fuzzers, and request floods get swatted before
they spike your load. Repeat offenders earn permanent bans.

It runs as a small set of Bash + awk scripts on a cron. No agent, no daemon, no
compiled dependencies, no phone-home.

```
$ swatter top
IP                 SCORE  OFFN  TEMP PERM CHANNEL     LAST
45.146.165.10         92     4     3    1 csf         high_badpath_repeat
104.152.52.20         78     1     1    0 csf         scanner_profile
193.32.162.40         85     2     2    0 cloudflare  request_flood
```

---

## Why it's different: it won't take your site down

Most "fail2ban for Apache" tools have one fatal blind spot on a Cloudflare-fronted
server. Your logs show the **real visitor IP** (via `mod_remoteip` /
`CF-Connecting-IP`), but the actual TCP socket is a **Cloudflare edge IP**. Block
that socket at your server firewall and you've just firewalled Cloudflare —
**every site on the box goes dark.**

Swatter is built around this. For every offender it decides:

- **Direct-to-origin** (hit your raw IP or cPanel service ports, *or* held a
  live TCP socket to your web ports from a non-Cloudflare peer — even behind a
  valid `Host` header, since a proxied request always arrives from a CF edge)
  → block at **CSF**. Safe: the socket really is the attacker.
- **Via Cloudflare** (came through the proxy) → a zone-scoped **Cloudflare IP
  Access Rule** via API, a **managed challenge** by default — so a false
  positive means a human solves a challenge, not a lockout. The CSF plane is
  never touched.
- **Ambiguous** → defaults to the Cloudflare plane (the safe one).

Cloudflare's own ranges are a hardcoded **never-block** set, re-checked
immediately before every single block. If the range list ever goes missing or
stale, Swatter **fails closed** — it stops issuing CSF denies entirely rather than
risk an outage.

Four Cloudflare postures (`CF_MODE`):

| Mode | Your setup | Via-CF offenders | Direct offenders |
|---|---|---|---|
| `auto` | **Default** — detect and adapt | safe plane unless proven bare | CSF |
| `direct` | Behind CF, Swatter is the defense | challenged/blocked via API | CSF |
| `skip` | Behind CF, **you** run your own WAF rules stack | logged, left to your edge rules | CSF |
| `off` | Not behind Cloudflare at all | n/a — everything is direct | CSF |

**Either/or, out of the box.** `auto` (the default) detects whether the server
sits behind Cloudflare — it resolves your own vhosts and checks them, your
inbound sockets, and your web-server config against the Cloudflare ranges — and
picks the posture for you. Detection runs at install, on `refresh-feeds`, and on
`test-config`, never per-scan, so the cron path stays cheap. It is **safety-
biased**: only a confident "this box is not behind Cloudflare" reading turns the
CF plane off; anything uncertain keeps classification on (the safe plane), so
`auto` can never misroute a proxied socket to CSF. A box with **no Cloudflare
domains at all** therefore works as a plain CSF auto-blocker with zero Cloudflare
config — and it actually issues blocks: the fail-closed rail (which disables CSF
denies when the CF range list is missing) only engages on a CF-fronted box,
where the list is needed to tell an edge socket from a direct one.

Detection re-runs daily (the `refresh-feeds` cron), so `auto` adapts if a box
moves on or off Cloudflare. It identifies the box's domains from the
domlog filenames, so on a **plain (non-cPanel) Apache/nginx** server with only a
single shared access log it can't prove the box is bare and stays on the safe,
classification-on posture. On such a server that isn't behind Cloudflare, set
`CF_MODE="off"` explicitly (`test-config` will tell you when it couldn't decide).

If you maintain your own Cloudflare WAF rules, rate limits, and login-page
protections, set `skip` explicitly: Swatter stays out of the realm you already
manage but still swats raw-IP scanners at CSF and logs what it would have
challenged. Do **not** use `off` on a proxied server to mean "hands off
Cloudflare" — `off` disables the plane classification itself, so proxied
visitors (your own customers included) can be misrouted to a CSF deny that also
takes out their mail and cPanel access. (Setting any explicit mode skips
detection.)

The closest tool in spirit is [CrowdSec](https://crowdsec.net) with its
Cloudflare bouncer, and it's good — if you want a daemon, a central reputation
network, and a component per concern. Swatter is the other end of the spectrum:
bash + gawk + cron, no resident process, cPanel/CSF-native, and the
direct-vs-proxied classification built into every decision rather than bolted on
as a bouncer.

---

## How it scores

Each IP is scored 0–100 over a sliding window from a **weighted blend** of signals:

| Signal | What it catches |
|---|---|
| Request rate | hammering / floods |
| Error ratio (4xx/5xx) | scanners generate errors |
| Error burst (403/404/444) | brute-force & path fuzzing |
| URL fanout | path enumeration / scanning |
| **Bad-path hits** | `/.env`, `/.git`, `wp-login.php`, `xmlrpc.php`, `/cgi-bin/`, shell drops, … |
| User-agent | `sqlmap`, `nikto`, `zgrab`, empty UAs |
| POST flood | login / xmlrpc / comment spam |
| No-vhost / raw-IP | only attackers hit you by IP |
| **Reputation** | AbuseIPDB, Spamhaus, IPsum (optional) |

A pure average dilutes a *focused* attack (a credential brute trips only a few
signals), so Swatter pairs the blended score with **decisive floors**: a
`/.env` probe, a sustained flood, a broad scanner profile, or repeated hits on a
sensitive endpoint are each independently sufficient to act — and every decision
records *why*, with the evidence, to `/var/log/swatter/decisions.jsonl`.

Tune everything (weights, thresholds, bad-path table) in
`/etc/swatter/swatter.conf` and `/etc/swatter/badpaths.conf`.

---

## Threat-intel enrichment (optional, free)

For IPs that already look suspicious, Swatter can corroborate against external
reputation feeds before acting:

- **IPsum** — aggregated blocklist, no key needed.
- **Spamhaus DROP/EDROP** — hijacked/criminal netblocks, no key needed.
- **AbuseIPDB** — confidence score, free tier (1,000 checks/day), cached + quota-limited.
- **GreyNoise** — Community API classification. `malicious` raises; **RIOT**
  (known business services — Google/Slack/CDNs) is a soft never-block guard;
  `benign` scanners are logged but still judged on behavior.
- **Project Honey Pot http:BL** — DNS reputation (harvesters, comment spammers,
  suspicious hosts). Needs a free member access key and a DNS client.
- **Keyless list feeds** — **FireHOL level1** (near-zero-FP aggregate), **CINS Army**,
  **DShield** top attacker netblocks, **blocklist.de** (brute-force reporters),
  **Emerging Threats** compromised hosts, and **GreenSnow** (scanners) — all no-key,
  refreshed by `swatter refresh-feeds`, confidence-tiered so noisier feeds corroborate
  less. On by default.
- **AbuseIPDB daily blocklist** *(opt-in)* — a once-a-day download of the top abusive
  IPs (reuses your `ABUSEIPDB_KEY`); add `abuseipdb_blocklist` to `INTEL_PROVIDERS`.

Reputation only ever *raises* a borderline score — it never blocks on its own, and
a failed or offline lookup is simply ignored. Works fully with **zero** API keys.

### Getting your own provider API keys

**Swatter runs fully with zero API keys** — IPsum and Spamhaus need none, and
every keyed provider degrades silently to "no data" when its key is unset. Add
a key only for the providers you want; each is free:

| Provider | Cost | Get a key |
|---|---|---|
| AbuseIPDB | Free (1,000 checks/day) | Create an account at abuseipdb.com → **Account → API** → generate a key. Set `ABUSEIPDB_KEY`. |
| GreyNoise | Free (Community) | Sign up at greynoise.io → **Account / Profile** → copy the API key. Set `GREYNOISE_KEY`. |
| Project Honey Pot | Free (membership) | Join projecthoneypot.org → request an **http:BL access key** (12 chars) from your member dashboard. Set `HTTPBL_KEY`. Needs `dig`/`host` installed. |

Put keys in your **own** `/etc/swatter/swatter.conf` (root-only, `0600`) — never
in the repo, never shared. The shipped `swatter.example.conf` has every key set
to empty by default.

## Beyond reputation: ASN, traps, persistence, metrics

- **Hosting-ASN signal** *(`ASN_SIGNAL_ENABLE`)* — when an offender is already
  behaving like an attack, originating from a datacenter/bulletproof ASN
  (Team Cymru lookup) adds a small bounded boost. Legit visitors from those
  networks are never penalized on origin alone.
- **Honeypot traps** *(`HONEYPOT_PATHS_FILE`)* — define a secret path no human
  hits; one request = score 100 = instant permanent ban. `swatter honeypot`
  prints a robots.txt + invisible-anchor snippet to advertise it to bots only.
- **Low-and-slow persistence** — an IP that lingers just under the block
  threshold across many hours is escalated once it recurs in
  `PERSIST_N` distinct buckets within `PERSIST_WINDOW_DAYS`.
- **Prometheus metrics** *(`METRICS_FILE`)* — a node_exporter textfile with
  block counts, current offender counts, feed-staleness ages, quota use, and
  fail-closed state, written atomically each scan and via `swatter metrics`.

---

## Nightly digest — swat errors *and* bad actors

`swatter report` emails one nightly digest covering both planes of server health:

- **Bad actors** — blocks taken (perm/temp), grouped by offense type, bad-path
  category, and channel (CSF vs Cloudflare), plus allowlist exemptions to review.
- **Server errors** *(optional, `ERROR_DIGEST_ENABLE`)* — FATAL/ERROR from Apache,
  PHP-FPM, per-site PHP, and MySQL over the same window, with known high-volume
  noise filtered and the rest grouped by signature. Point it at logs directly, or
  reuse an existing consolidated error log.

It stays silent on a genuinely quiet window. Delivery is pluggable —
`sendmail` (default), **SendGrid**, or **Brevo** — so hosts whose IP isn't an
authorized sender for the From domain can still deliver. The installer schedules
it nightly; set the cron hour to your timezone.

```bash
swatter report --test          # force-send now, to verify delivery
swatter report 7d              # ad-hoc 7-day digest
swatter report --print         # print the digest to stdout, send nothing
```

### Email delivery setup

All the knobs live in `/etc/swatter/swatter.conf`:

1. Set `REPORT_EMAIL` (empty disables the digest) and `REPORT_FROM`.
2. Pick `REPORT_METHOD`. `sendmail` needs nothing else. `sendgrid` and `brevo`
   need `curl` + `jq` plus an API key — keep it in a root-only file and point
   the config at it:

   ```bash
   install -m 600 /dev/null /etc/swatter/sendgrid.key
   vi /etc/swatter/sendgrid.key        # paste the API key, nothing else
   ```

   Then in `swatter.conf`: `REPORT_METHOD="sendgrid"` +
   `SENDGRID_KEY_FILE="/etc/swatter/sendgrid.key"`, or
   `REPORT_METHOD="brevo"` + `BREVO_KEY_FILE="/etc/swatter/brevo.key"`.
3. Verify delivery with `swatter report --test`.

## Safety first

- **Report-only by default.** Out of the box Swatter scores and logs decisions but
  touches nothing. Watch it for a week, then flip `SWATTER_MODE="enforce"`.
- **Temp before perm.** First offense is a temporary block (TTL ladder
  1h → 6h → 24h → 72h). Permanent bans are *earned* by repeat offenses, never from
  a single window — so one anomalous burst can't blackhole a shared/CGNAT IP.
- **Circuit breakers.** Hard caps on blocks per run, with a separate, lower cap on
  the catastrophic CSF channel. A log-parsing bug can't nuke thousands of IPs.
- **Never-block allowlist**, checked last: Cloudflare ranges, your `csf.allow`,
  the server's own IPs, RFC1918, your operator IPs (`swatter allow <ip>`),
  monitoring services, and **forward-confirmed** good crawlers (Googlebot/Bingbot
  verified by reverse + forward DNS, because PTR alone is forgeable).
- **Sensitive paths need failure evidence.** Hitting `wp-login.php` is not a
  crime — your clients do it every day. The brute-force floor only trips on
  repeated *failed* attempts (errors or POST floods), so a site owner logging in
  and working in wp-admin can never be blocked for it.
- **Full audit + appeal.** `swatter why <ip>` shows exactly what triggered a block;
  `swatter unblock <ip> [--perm-allow]` reverses it on both planes.

---

## Install

Requirements: a cPanel/Apache + **CSF** server (AlmaLinux/CentOS/RHEL), `gawk`,
`flock`. Optional: `jq` + `curl` (threat-intel & Cloudflare API), `sqlite3`
(falls back to a flat file otherwise).

```bash
git clone https://github.com/peaceharborco/swatter.git
cd swatter

# On the server itself (as root):
sudo ./install/install.sh local

# …or push from your workstation over SSH:
./install/install.sh remote root@your-server
```

Then:

```bash
swatter refresh-feeds      # pull Cloudflare ranges + intel feeds
swatter test-config        # sanity-check deps, paths, CF token
swatter scan --dry-run     # see what it WOULD do
swatter top                # review the worst offenders
```

**Before you enforce: teach it who you are.** Run in report mode for a week and
review what it *would* have blocked (`swatter top`, `swatter why <ip>`, the
nightly digest). Any IP on that list that's actually you, your staff, or a
client belongs in the never-block set **before** the first enforce run:

```bash
swatter allow 203.0.113.7 "office"
swatter allow 198.51.100.0/24 "client X static range"
```

The most embarrassing failure mode of any auto-blocker is banning the customer —
a site owner fumbling a password and then working in wp-admin can look a lot
like an attack. Swatter's scoring is built to tell those apart, but your
operator IPs deserve a guarantee, not a probability.

When you trust it, set `SWATTER_MODE="enforce"` in `/etc/swatter/swatter.conf`.
The installer adds a cron entry that scans every 5 minutes and refreshes feeds
daily. After upgrading, run `swatter refresh-feeds` so the new feeds download.

### Enabling the Cloudflare plane

To block proxied attackers at Cloudflare (not just CSF-direct ones), Swatter
needs a token per CF account scoped to **only** `Firewall Services: Edit` (zone
IP Access Rules — a different product from the WAF Rulesets, so it never collides
with your existing WAF automation). It blocks each attacker in the specific zone
they hit, using your domain→account map.

1. In the Cloudflare dashboard, create an API token per account with the single
   permission *Zone → Firewall Services → Edit* over that account's zones.
2. Build a root-only creds file (`account<TAB>token`, one line per account) and a
   `cf-domains.conf`-style domain list, then deploy both from your workstation —
   no secret is committed and only the minimal token lands on the server:

   ```bash
   ./install/swatter-deploy-cf-creds.sh \
     --creds   /path/to/cloudflare.creds \
     --domains /path/to/cf-domains.conf \
     --host    root@your-server
   ```

   This writes `/etc/swatter/cloudflare.creds` (0600) and
   `/etc/swatter/cf-domains.map` (0644), then runs `test-config`. A dry-run will
   then show `cloudflare block <ip> in <domain>` for proxied offenders. (Hosts
   not behind Cloudflare can skip all of this entirely — the default
   `CF_MODE="auto"` detects a bare box and runs as a plain CSF auto-blocker; set
   `CF_MODE="off"` to make that explicit and skip detection.)

### Recommended: make Cloudflare classification exact

By default Swatter infers direct-vs-proxied from your logs *and* from live origin
sockets — a TCP peer on your web ports (`DIRECT_WEB_PORTS`, default `80 443`)
that isn't a Cloudflare edge is provably direct, which catches an in-progress
flood that bypasses Cloudflare with a valid `Host` header. For log-based ground
truth too, add Cloudflare's ray ID to your Apache log format — present means the
request came through Cloudflare, absent means direct:

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" cfray=%{CF-Ray}i" swatter
```

(Optional — heuristics work without it.)

### Division of labor with your edge WAF

If you already run serious protection at the Cloudflare edge — say, a
geo-restricted managed challenge on `wp-login.php` and `wp-admin` — think about
what that does to the traffic Swatter sees at the origin: **the hostile noise on
those paths never arrives.** What's left hitting your login pages is
overwhelmingly legitimate (site owners and whoever passes your challenge), so
path-based suspicion at the origin inverts — it starts selecting *for* your
customers instead of against attackers.

Two ways to run in that setup:

- **`CF_MODE="skip"`** — the cleanest split. Your edge rules own the proxied
  realm; Swatter owns what the edge can never see: direct-to-origin traffic from
  scanners that found your server's real IP. On that plane the bad-path table is
  at full strength, because no legitimate user logs into WordPress via your raw
  server IP. (Use `skip`, **not** `off`, here: the box *is* behind Cloudflare, so
  classification must stay on or a proxied socket could be CSF-denied. `skip`
  keeps classification and simply leaves the via-CF plane to your edge rules.)
- **Keep the CF plane but demote the auth paths** in `config/badpaths.conf`
  (e.g. `wp-login.php` HIGH → MEDIUM) if your edge protection is partial — for
  instance a geo challenge that still admits same-country bots.

Either way, the brute-force floor requires failure evidence (failed POSTs /
error responses), so even the default tuning won't ban an owner for logging in.

---

## Commands

| Command | Purpose |
|---|---|
| `swatter scan [--dry-run\|--enforce]` | ingest → score → decide → act |
| `swatter status` | state, mode, allowlist health, counts |
| `swatter top [-n N]` | worst tracked offenders |
| `swatter why <ip>` | the evidence and history behind a block |
| `swatter allow <ip\|cidr> [note]` | add to the never-block set (both planes) |
| `swatter unblock <ip> [--perm-allow]` | reverse a block on both planes |
| `swatter list [temp\|perm\|cf\|allow]` | current blocks / allowlist |
| `swatter report [WINDOW] [--test\|--print]` | email a digest grouped by offense + action (`--print`: stdout only) |
| `swatter refresh-feeds` | update Cloudflare ranges + intel feeds |
| `swatter test-config` | validate config and dependencies |
| `swatter honeypot` | print robots.txt + invisible-anchor snippet for the trap path |
| `swatter metrics [--print]` | write (or print) the Prometheus textfile |

---

## How it fits together

```
 logs ─▶ ingest ─▶ score.awk ─▶ [past WATCH?] ─▶ threat-intel ─▶ classify ─┬▶ CSF (direct)
 (domlogs,         (weighted        (per-IP        (AbuseIPDB/     (direct   └▶ Cloudflare WAF (proxied)
  access_log)       signals +        evidence)      Spamhaus/       vs CF)
                    decisive                        IPsum)              │
                    floors)                                             ▼
                                                            never-block check (last)
                                                            + circuit breakers
                                                                        │
                                                                        ▼
                                                       SQLite ledger + decisions.jsonl
```

Incremental log reads use a per-file byte cursor (exact across the busiest logs,
survives rotation). Everything is `set -uo pipefail`, single-instance via `flock`,
and parses with awk in one pass — it scales to high-volume hours without forking
per line.

---

## License

MIT © [Peace Harbor Studios](https://studios.peaceharbor.com). See [LICENSE](LICENSE).

Contributions welcome — new firewall backends (ipset/nftables), an nginx log
parser, and additional intel providers all slot into the existing adapter
interfaces.
