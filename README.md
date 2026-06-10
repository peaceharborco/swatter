# 🪰 Swatter

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

- **Direct-to-origin** (hit your raw IP or cPanel service ports, bypassing
  Cloudflare) → block at **CSF**. Safe: the socket really is the attacker.
- **Via Cloudflare** (came through the proxy) → block at the **Cloudflare WAF**
  via API. The CSF plane is never touched.
- **Ambiguous** → defaults to the Cloudflare plane (the safe one).

Cloudflare's own ranges are a hardcoded **never-block** set, re-checked
immediately before every single block. If the range list ever goes missing or
stale, Swatter **fails closed** — it stops issuing CSF denies entirely rather than
risk an outage.

Not behind Cloudflare? Set `CF_MODE="off"` and Swatter is a straightforward CSF
auto-blocker. Zero Cloudflare config required.

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
- **AbuseIPDB** — confidence score, free tier (1,000 checks/day), cached and
  quota-limited.

Reputation only ever *raises* a borderline score — it never blocks on its own, and
a failed or offline lookup is simply ignored. Works fully with **zero** API keys.

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
```

## Safety first

- **Report-only by default.** Out of the box Swatter scores and logs decisions but
  touches nothing. Watch it for a week, then flip `SWATTER_MODE="enforce"`.
- **Temp before perm.** First offense is a temporary block (TTL ladder
  1h → 6h → 24h → 72h). Permanent bans are *earned* by repeat offenses, never from
  a single window — so one anomalous burst can't blackhole a shared/CGNAT IP.
- **Circuit breakers.** Hard caps on blocks per run, with a separate, lower cap on
  the catastrophic CSF channel. A log-parsing bug can't nuke thousands of IPs.
- **Never-block allowlist**, checked last: Cloudflare ranges, your `csf.allow`,
  the server's own IPs, RFC1918, your operator IPs, monitoring services, and
  **forward-confirmed** good crawlers (Googlebot/Bingbot verified by reverse +
  forward DNS, because PTR alone is forgeable).
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

When you trust it, set `SWATTER_MODE="enforce"` in `/etc/swatter/swatter.conf`.
The installer adds a cron entry that scans every 5 minutes and refreshes feeds
daily.

### Recommended: make Cloudflare classification exact

By default Swatter infers direct-vs-proxied from your logs. For ground truth, add
Cloudflare's ray ID to your Apache log format — present means the request came
through Cloudflare, absent means direct:

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" cfray=%{CF-Ray}i" swatter
```

(Optional — heuristics work without it.)

---

## Commands

| Command | Purpose |
|---|---|
| `swatter scan [--dry-run\|--enforce]` | ingest → score → decide → act |
| `swatter status` | state, mode, allowlist health, counts |
| `swatter top [-n N]` | worst tracked offenders |
| `swatter why <ip>` | the evidence and history behind a block |
| `swatter unblock <ip> [--perm-allow]` | reverse a block on both planes |
| `swatter list [temp\|perm\|cf\|allow]` | current blocks / allowlist |
| `swatter report [WINDOW] [--test]` | email a digest grouped by offense + action |
| `swatter refresh-feeds` | update Cloudflare ranges + intel feeds |
| `swatter test-config` | validate config and dependencies |

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
