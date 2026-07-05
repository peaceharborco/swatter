# 🪰 Swatter

[![CI](https://github.com/peaceharborco/swatter/actions/workflows/ci.yml/badge.svg)](https://github.com/peaceharborco/swatter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A Cloudflare-aware abuse swatter for cPanel + CSF servers** — and any Linux host
with `ipset`/`iptables`, since CSF is optional (see [Firewall backend](#firewall-backend)).

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
- **Via Cloudflare** (came through the proxy) → a **Cloudflare IP Access Rule**
  via API, a **managed challenge** by default — so a false positive means a
  human solves a challenge, not a lockout. The CSF plane is never touched. The
  rule lands per `CF_SCOPE`: `zone` (the single zone hit) or `account` (every
  account at once, so a vhost-rotating scanner can't roam — see below).
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
to empty by default. At runtime, keys never appear on a curl command line
(where any local user could read them out of `ps`): every credentialed request
passes its secret through a per-call `0600` config file (`curl -K`). The one
exception is Project Honey Pot's http:BL, whose protocol embeds the key in the
DNS query itself — that key is lookup-only by design.

---

## Alerting

**Swatter needs no alerting config to run.** All channels are opt-in; omit any
you don't need. Credentials go in root-only files on the server — never in the
repo.

| Channel | What to set | Where to sign up |
|---|---|---|
| Email (SendGrid / Brevo) | `ALERT_EMAIL` (recipient) — sent via the nightly report mailer, so it follows `REPORT_METHOD` + that method's key file | sendgrid.com (free 100/day) or brevo.com (free 300/day). Create an API key with **Mail Send** permission only. |
| Twilio SMS | `ALERT_SMS_TO`, `TWILIO_SID`, `TWILIO_FROM`, `TWILIO_TOKEN_FILE` | console.twilio.com — free trial credits. Copy Account SID and Auth Token from the dashboard; write the Auth Token to a `0600` file and set `TWILIO_TOKEN_FILE`. |
| Webhook (Slack, Discord, PagerDuty, …) | `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_FORMAT` | Slack: **App directory → Incoming Webhooks**. Discord: channel **Settings → Integrations → Webhooks**. Set `ALERT_WEBHOOK_FORMAT` to `slack`, `discord`, or `raw-json`; `auto` sniffs the URL. |

`ALERT_REPEAT_TTL` (default 6 h) suppresses repeat alerts for the same IP so a
sustained attack doesn't flood your inbox or phone.

`swatter test-config` reports which channels are active.

---

## Firewall backend

By default Swatter issues direct blocks through **CSF** (`DIRECT_BACKEND=csf`).
On servers where CSF is not installed, or for lower-latency bulk drops, set
`DIRECT_BACKEND=ipset` to use kernel **ipset + iptables DROP** rules instead.

```bash
# In /etc/swatter/swatter.conf:
DIRECT_BACKEND="ipset"
IPSET_SAVE_FILE="/etc/swatter/ipset.save"   # written by setup-ipset; restore at boot
```

After changing to `ipset`, run the one-time setup:

```bash
swatter setup-ipset      # creates swatter4/swatter6 ipsets + iptables DROP rules
```

`setup-ipset` is idempotent — safe to re-run after a reboot or kernel upgrade.
The two backends can coexist: CSF continues to manage its own deny list; the
ipset sets are separate. After a reboot, restore the ipset with the save file
(`ipset restore < "${IPSET_SAVE_FILE}"`); the installer notes this if
`DIRECT_BACKEND=ipset` is set.

### IPv6

IPv6 is supported across scoring, exact-prefix allowlisting, ASN/hosting boost
(`origin6` lookups), and blocking (the `swatter6` set + `ip6tables` DROP rule).
Install `ip6tables` so v6 blocks actually enforce — `swatter test-config` warns
if it's missing. Two signals remain **IPv4-only** by nature of their data
sources: the Project Honeypot provider and the live-socket direct-evidence check.

---

## Origin lock

The direct-vs-proxied classifier (above) is **reactive**: it scores a
direct-to-origin Cloudflare-bypass offender *after* it shows up in the logs,
which a fast valid-`Host` flood can outrun. **Origin lock is the structural
complement** — an inline L3 firewall rule that only lets Cloudflare edge ranges
reach the locked web ports (`ORIGIN_LOCK_PORTS`, default `443`), so bypass
traffic is dropped at the socket before it ever becomes a log line. The classifier still scores offenders from
logs; the lock closes the door instead of scoring who walked through it. The two
are independent and conflict-free (different chains, different purpose).

It is **off by default** and config-driven — it carries no IPs, hostnames, or
allow assumptions of its own. The Cloudflare ranges come from the same
`CLOUDFLARE_IPS_FILE` (`/etc/swatter/cloudflare.cidr`) that `refresh-feeds`
already maintains; everything policy-specific (whether to enforce, which extra
sources to admit) lives in your own `/etc/swatter/` config.

### Off → log → drop (validate before you enforce)

`ORIGIN_LOCK` is a three-state ladder, and you climb it deliberately:

| `ORIGIN_LOCK` | What `apply` installs |
|---|---|
| `off` *(default)* | nothing — a fresh install enforces no restriction |
| `log` | `ACCEPT` Cloudflare edges → web ports, then a rate-limited `LOG` (prefix `ORIGIN-LOCK: `) of everything else. **No drop.** |
| `drop` | the same `ACCEPT` + `LOG`, then a `DROP` of the remainder |

> ⚠️ **Run `log` mode first. Read the would-be-drops with `preflight`. Allowlist
> every legitimate source. THEN enforce.** A direct-to-origin lock that drops
> blind can blackhole real visitors to a non-proxied (grey-cloud) vhost, your
> monitoring, or your own health checks. `drop` is guarded for exactly this
> reason: `apply` refuses to install a `DROP` without first running `preflight`
> and getting an interactive confirmation (or `--yes` / `--force`). The most
> embarrassing failure of any inline lock is firewalling your own customers — so
> the tool makes enforcing blind hard to do by accident.

Rules are built **accept-first, drop-last**, so a mid-build failure can never
leave a `DROP` standing without its preceding `ACCEPT`s (fail-open). If
`cloudflare.cidr` is missing, empty, or yields fewer than a sane minimum of
ranges, `apply` installs **no** restriction at all and logs why — an empty
allowlist plus `DROP` would firewall the entire internet.

**Locking `:80` breaks HTTP certificate validation — leave it out of
`ORIGIN_LOCK_PORTS` if you rely on ACME HTTP-01 / cPanel AutoSSL DCV.**
Earlier versions shipped an `ORIGIN_LOCK_ALLOW_ACME` carve-out that accepted
packets containing `/.well-known/` on `:80`; it is retired because it **cannot
work**: an `xt_string` payload match can never admit a *new* connection — the
TCP handshake carries no payload, so a validator's SYN hits the `DROP` before
any matchable packet exists (observed in production: the rule's counter stayed
at zero while Let's Encrypt validators were SYN-dropped and renewals failed).
Validator source IPs are deliberately unpublishable, so allowlisting is not an
option either. The supported postures are `ORIGIN_LOCK_PORTS="443"`
(recommended — `:80` serves only redirects and challenges; content stays
locked on `:443`) or DNS-01 validation if you must lock both ports. `apply`
warns on every run whose port list includes `80`. The old toggle is ignored,
and teardown still removes the legacy rule from boxes an older version
configured.

### IPv4 and IPv6

`cloudflare.cidr` carries both v4 and v6 ranges (`refresh-feeds` fetches both
families). `apply` builds the v4 path with `iptables` and the v6 path with
`ip6tables`, **gated on `ip6tables` being present**. If it is absent the v6 path
logs a loud warning and leaves v6 web ports uncovered rather than failing —
install `ip6tables` so a dual-stack host doesn't keep a silent direct-to-origin
hole on v6.

### Persistence: CSF (csfpre) vs standalone

A single idempotent code path (`apply`) serves both worlds; the execution
context is explicit, never guessed:

- **CSF present.** Install writes one guarded line — `swatter origin-lock apply
  --hook=csf --yes` — into `/etc/csf/csfpre.sh` (created if absent). `csfpre.sh`
  runs before CSF builds its chains on every `csf -r`, so the lock re-applies and
  is ordered ahead of CSF's blanket TCP_IN accept (measured durable across
  `csf -r`/`csf -ra`/lfd restart under `FASTSTART=1`/`LF_IPSET=1` — csfpre is the
  sole carrier, no systemd needed). The `--yes` is required: at `csf -r` the hook
  runs non-interactively, and DROP mode would otherwise abort at the confirm
  guard and install nothing (setting `ORIGIN_LOCK=drop` is the operator's
  consent). CSF already supplies loopback,
  established/related, and `csf.allow` accepts above csfpre, so in this context
  `apply` adds **only** the Cloudflare/ACME accept + LOG/DROP (a redundant
  established accept is deliberately avoided — it can leak handshakes under
  `nf_conntrack_tcp_loose=1`).
- **No CSF (standalone).** Install writes a small `oneshot` systemd unit
  (`WantedBy=multi-user.target`) that runs `apply` at boot; an `rc.local`
  equivalent works too. Here `apply` lays a safe preamble before the `DROP` —
  `ACCEPT -i lo` to the web ports (local self-calls / health checks) plus
  `ACCEPT` of `allow.cidr` + `monitoring.cidr` (the portable `csf.allow`
  equivalent). It still adds no standing established accept; outbound-initiated
  return traffic lands on ephemeral ports, never `dport 80/443`, so the `DROP`
  never matches it.

`swatter origin-lock status` reports which persistence mode is active.

### Subcommands

| Command | Behavior |
|---|---|
| `swatter origin-lock apply` | Converge the firewall to the configured `ORIGIN_LOCK` mode (including removing rules when `off`). The drop guard applies. |
| `swatter origin-lock status` | Mode, ipset health (v4/v6 entry counts), live ACCEPT/DROP counters, persistence mode (csfpre vs systemd), and whether the hook is installed. |
| `swatter origin-lock preflight` | Read-only. Classifies the would-be-drops from the `log`-mode sample against Swatter's intel feeds + allowlist: **confirmed attacker** (in a feed, safe to drop), **legit** (in `monitoring.cidr` / `allow.cidr` — allowlist before you drop), or **unknown** (review — could be a real visitor to a non-CF vhost). It reads the kernel-LOG source (`journalctl -k`, else `/var/log/{messages,syslog,kern.log}`) and notes it is a rate-limited sample, not every packet. |
| `swatter origin-lock disable` | Full teardown: removes the iptables/ip6tables rules, the `cf_origin4`/`cf_origin6` sets, **and** the persistence hooks (the csfpre line + the systemd unit), so nothing re-applies on reboot or `csf -r`. |

`swatter test-config` and `swatter status` surface origin-lock state (mode,
ipset health, hook installed) alongside the existing readiness checks. The lock
coexists with `DIRECT_BACKEND=ipset`: the offender `swatter4`/`swatter6` sets
and the `cf_origin4`/`cf_origin6` sets are independent and both live in `INPUT`
without conflict.

### cPanel control-panel subdomains

If your origin is a cPanel server, the lock will block its **service subdomains**
on `:443`. cPanel auto-creates `cpanel.`, `whm.`, `webmail.`, `webdisk.`,
`autodiscover.`, `autoconfig.`, `cpcontacts.`, and `cpcalendars.` as DNS-only
(grey-cloud) records pointing straight at the origin — so they arrive **not** from
a Cloudflare edge, and the lock drops them. (`mail.` and the MX/IMAP/SMTP records
use other ports, so the lock never touches them — and they must stay DNS-only,
since Cloudflare can't proxy mail protocols.)

Two ways to restore the HTTP ones:

- **Use their service ports** — `https://<domain>:2083` (cPanel), `:2087` (WHM),
  `:2096` (webmail). The lock only covers `ORIGIN_LOCK_PORTS` (default `443`),
  so the high ports are unaffected. Best for the admin panels (cPanel/WHM), which
  you generally don't want publicly reachable anyway — restrict them to your own
  IPs in `csf.allow`.
- **Proxy them through Cloudflare** (orange-cloud the record) so they arrive via a
  CF edge the lock accepts. Good for a customer-facing `webmail.`.

**The 526 gotcha when proxying.** cPanel AutoSSL secures a *primary* domain's
service subdomains, but **not an addon domain's** — for an addon's `webmail.`, the
origin presents the server-hostname certificate, which Cloudflare **Full (strict)**
rejects with **HTTP 526**. Fix it without weakening the zone: add a per-hostname
**Configuration Rule** that sets SSL to **Full** (not strict) for the service-sub
hostnames, leaving the apex on strict. Cloudflare then accepts the origin's
hostname cert while still serving a valid edge certificate to visitors.
Certificate renewal keeps working behind the lock because the default
`ORIGIN_LOCK_PORTS="443"` leaves `:80` — where HTTP DCV lands — unlocked (see
"Locking `:80` breaks HTTP certificate validation" above), and a proxied
record's validation traffic arrives via Cloudflare edges the lock already
accepts.

---

## Outbound reporting

Set `ABUSEIPDB_REPORT=true` in `/etc/swatter/swatter.conf` to report each
permanent ban back to AbuseIPDB (reuses your existing `ABUSEIPDB_KEY`). Off by
default — opt in deliberately.

```bash
ABUSEIPDB_REPORT="true"
ABUSEIPDB_REPORT_TTL=900   # don't re-report the same IP within N seconds
```

`swatter test-config` shows whether reporting is on and warns if `ABUSEIPDB_KEY`
is unset (reporting would be inert).

---

## Fleet ban-sync

On a multi-server fleet, share the permanent-ban list across hosts:

```bash
swatter export-bans /tmp/bans.txt       # write perm-ban list to file (or stdout)
swatter import-bans /tmp/bans.txt       # block each listed IP as perm on another host
```

`import-bans` skips IPs on the never-block list, any malformed entries, and
catastrophic targets (a `/0` or an unspecified address like `0.0.0.0`) — safe
to pipe from an untrusted source. Use `export-bans` in a cron and `import-bans`
on the receiving hosts to keep ban lists in sync across a fleet.

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

## Nightly digest — swat errors, bad actors *and* bypass attempts

`swatter report` emails one nightly digest, delivered as a structured HTML
report (verdict line → stat tiles → per-plane tables), covering up to four
planes of server health:

- **Bad actors** — blocks taken (perm/temp), grouped by offense type, bad-path
  category, and channel (CSF vs Cloudflare), plus allowlist exemptions to review.
  Backend failures get their own line (`backend-failed: N (top: <cause>)`) so a
  silently erroring firewall or API never hides inside the block counts.
- **Server errors** *(optional, `ERROR_DIGEST_ENABLE`)* — FATAL/ERROR from Apache,
  PHP-FPM, per-site PHP, and MySQL over the same window, with known high-volume
  noise filtered and the rest grouped by signature. Point it at logs directly, or
  reuse an existing consolidated error log.
- **Origin-lock** *(opt-in, `ORIGIN_LOCK_DIGEST`, default `auto`)* — when the
  window contains `ORIGIN-LOCK:` syslog hits, a dedicated plane shows the
  direct-to-origin drop count, unique source IPs, the `:80`/`:443` split, and
  top sources tagged attacker/legit. `auto` shows it only when there are hits, so
  it stays invisible for operators who don't run the lock; `ORIGIN_LOCK_LOG`
  selects the syslog source.
- **Swarm** *(shown when `SWARM_ENABLE=true`)* — an informational plane summarizing
  what the fleet gave and got: fleet IPs consumed from the shared feed (with a
  stale-feed note when the feed is older than `SWARM_MAX_AGE_DAYS`), corroborated
  pre-blocks taken this window, confirmed bans contributed back this window, and
  the date of the last contribution. It reads only local swarm state at report
  time (no hub call) and is purely informational — it never changes the report
  grade or breaks the silent-when-quiet behavior, and it degrades to a note (not
  silent zeros) on a box without `jq`.

It stays silent on a genuinely quiet window. Delivery is pluggable —
`sendmail` (default), **SendGrid** (free tier 100/day), or **Brevo** (free tier
300/day) — so hosts whose IP isn't an authorized sender for the From domain can
still deliver via a free transactional-email account. The installer schedules
it via `REPORT_CRON` (default `0 4` — 4 AM) and `REPORT_CRON_TZ` (an IANA zone
like `America/Los_Angeles`; empty = server/UTC), baked into `/etc/cron.d/swatter`
with a `CRON_TZ` header so the send time doesn't drift across DST.

```bash
swatter report --test          # force-send now, to verify delivery
swatter report 7d              # ad-hoc 7-day digest
swatter report --print         # print the digest to stdout, send nothing
```

### Email delivery setup

All the knobs live in `/etc/swatter/swatter.conf`:

1. Set `REPORT_EMAIL` (recipient; empty disables the digest) and `REPORT_FROM`
   (sender address). These two are all you normally set — `REPORT_FROM_NAME`
   defaults to `Swatter (<this host's FQDN>)` and the subject is generated per
   report, so you rarely touch either.
2. Pick `REPORT_METHOD`. `sendmail` needs nothing else. `sendgrid` and `brevo`
   need `curl` + `jq` plus an API key — keep it in a root-only file and point
   the config at it:

   ```bash
   install -m 600 /dev/null /etc/swatter/sendgrid.key   # or .../brevo.key
   vi /etc/swatter/sendgrid.key        # paste the API key, nothing else
   ```

   Then in `swatter.conf`, either:
   - **SendGrid** (free 100/day): `REPORT_METHOD="sendgrid"` +
     `SENDGRID_KEY_FILE="/etc/swatter/sendgrid.key"`, or
   - **Brevo** (free 300/day): `REPORT_METHOD="brevo"` +
     `BREVO_KEY_FILE="/etc/swatter/brevo.key"`.
3. Verify delivery with `swatter report --test`.
4. Optional white-label: the HTML report's header shows the Peace Harbor
   Studios lockup by default. Put your own company logo there with
   `REPORT_LOGO_URL` (https URL, shown 360px wide) and `REPORT_LOGO_ALT`.
   The footer branding is part of the project and is not configurable.

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
- **Only real, sane addresses ever reach the firewall.** Every block target is
  strictly validated at the sink — not just the scan path but the direct router,
  the Cloudflare plane, and `import-bans` — so a malformed token parsed from a
  hostile log line can't reach `csf`/`ipset`/the CF API. Catastrophic-but-valid
  targets are refused too: a `/0` (whole-internet deny) or an unspecified address
  (`0.0.0.0`, `::`) is never blocked, even from an untrusted `import-bans` file.
- **Full audit + appeal.** `swatter why <ip>` shows exactly what triggered a block;
  `swatter unblock <ip> [--perm-allow]` reverses it on both planes.
- **Failures are loud, never silent.** A block or unblock that a backend
  rejects is recorded as such — failed blocks carry the backend's actual error
  in the decision record (`evidence.backend_err`), and `unblock` exits nonzero
  with an `INCOMPLETE` message if any plane's removal failed, instead of
  printing a false "unblocked" while a rule is still live.

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
needs a token per CF account (IP Access Rules — a different product from the WAF
Rulesets, so it never collides with your existing WAF automation). Where the
rule lands is set by **`CF_SCOPE`**:

- **`zone`** (default) — blocks each attacker in the specific zone they hit,
  using your domain→account map. Token needs only `Firewall Services: Edit`.
  Smallest blast radius, but a scanner that rotates target vhosts is only
  challenged on the first zone it touches: once Swatter's per-IP ledger marks the
  IP handled, it stops creating rules, so the IP roams free across every other
  zone on the account.
- **`account`** — blocks the attacker on **every account at once**, so the block
  scope matches the per-IP ledger and a vhost-rotating scanner is shut out
  everywhere. No target vhost is required, so it also covers raw-IP / no-`Host`
  offenders. Token additionally needs `Account Firewall Access Rules: Edit`. This
  is the recommended scope when Swatter is your main line of defense; a token
  lacking account scope makes account blocks fail and retry each run (logged with
  a scope hint) so the misconfig surfaces, rather than silently skipping.

1. In the Cloudflare dashboard, create an API token per account: *Zone →
   Firewall Services → Edit* over that account's zones (and, for
   `CF_SCOPE=account`, also *Account → Account Firewall Access Rules → Edit*).
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
| `swatter refresh-feeds` | update Cloudflare ranges + intel feeds (validates the range body; exits nonzero on failure so cron can alert) |
| `swatter test-config` | validate config and dependencies |
| `swatter honeypot` | print robots.txt + invisible-anchor snippet for the trap path |
| `swatter setup-ipset` | create ipset sets + iptables DROP rules (idempotent; use with `DIRECT_BACKEND=ipset`) |
| `swatter metrics [--print]` | write (or print) the Prometheus textfile |
| `swatter export-bans [file]` | write the perm-ban list to a file (or stdout) |
| `swatter import-bans <file>` | block each listed IP as perm (skips allowlisted / invalid) |

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
