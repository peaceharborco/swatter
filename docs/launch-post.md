# Behind Cloudflare, blocking attackers the normal way takes your own site down

You run fail2ban or CSF. Some IP is hammering `wp-login.php`. You ban it. iptables
drops the address. Done, right?

Not behind Cloudflare. Behind Cloudflare you just shot yourself in the foot — you
only don't know it yet.

Here's the trap. When your site is proxied through Cloudflare, every request hits
your server *from a Cloudflare edge IP*, not from the visitor. `mod_remoteip`
quietly rewrites the logged address back to the real visitor (from
`CF-Connecting-IP`), so your access logs look perfectly normal. But the actual TCP
socket — the thing iptables can see and drop — is Cloudflare. So when fail2ban
reads the real attacker IP out of the log and tells iptables to ban it, the ban
does nothing. The attacker isn't connecting to you. Cloudflare is.

And it gets worse than "does nothing." Misread a log line, or ban an IP that turns
out to be a Cloudflare range, and iptables will cheerfully firewall Cloudflare
itself. Now every site on the box is dark — for everyone. You banned one scanner
and took down all your clients.

## The usual fixes don't fix it

**"Just whitelist all Cloudflare IPs in your firewall."** Sure. Now you *literally
cannot* block HTTP abuse at the firewall, because all of it arrives from
whitelisted Cloudflare IPs. The bots walking `/xmlrpc.php`, `/.env`, and
`/wp-content/.../shell.php` are now unblockable at the exact layer fail2ban works
on. CSF even says so in its own docs.

**"Use Cloudflare's WAF, then."** Cloudflare only sees *proxied* traffic — it never
sees the attacker who found your origin IP and connects straight to port 443.
Free-tier WAF is shallow, and Bot Fight Mode is a blunt on/off switch most of us
turn off because it eats legitimate SEO crawlers. Meanwhile CSF's `lfd` is great at
login-failure brute force and port scans, but distributed HTTP scanners and
slow-and-low probers stroll right past it.

So you're caught between two firewalls that each see half the picture, and the
obvious move takes you offline.

## The actual insight

Every attacker reaches you one of two ways:

- **Direct to origin** — they found your server's IP and connect straight to it,
  bypassing Cloudflare. The socket *is* the attacker. Safe to block at CSF.
- **Through Cloudflare** — the socket is a Cloudflare edge. Blocking it at CSF is
  the outage. This one has to be blocked at Cloudflare's WAF instead.

The fix was never a better log regex. It's deciding, *per attacker*, which side of
the proxy they're on — and sending the block to the right plane.

I went looking for a tool that does that. fail2ban's Cloudflare action sends
*everything* to Cloudflare. CrowdSec's bouncer sends *everything* to Cloudflare.
CSF's `--cloudflare` mirrors only a couple of trigger types. Not one of them
decides per-IP which plane the block belongs on. So I built one.

## Swatter

Swatter reads your Apache logs, scores every IP, and routes each block to the
correct plane:

- **Direct-to-origin** offenders → **CSF**.
- **Cloudflare-proxied** offenders → the **Cloudflare WAF** (zone IP Access Rules),
  in the exact zone they attacked.
- Cloudflare's own ranges are a hardcoded **never-block** set, re-checked before
  every single block. It **fails closed**: if it can't be certain, it doesn't touch
  CSF.

It isn't match-a-regex-and-count. It scores on request rate, error-ratio bursts,
URL fanout, known-bad paths (`/.env`, `/.git`, `wp-login`, `xmlrpc`, cgi-bin
shells), bot user-agents, and POST floods — and it'll cross-check an IP against
AbuseIPDB, Spamhaus, and IPsum before it acts. Decisive signals (a `/.env` probe, a
sustained flood) block on their own; the weighted score catches the quieter stuff.

```
$ swatter top
IP                 SCORE  OFFN  TEMP PERM CHANNEL     LAST
45.146.165.10         92     4     3    1 csf         high_badpath_repeat
104.152.52.20         78     1     1    0 csf         scanner_profile
193.32.162.40         85     2     2    0 cloudflare  request_flood
```

Safety is the default, not a footnote:

- **Report-only out of the box.** It scores, logs, and touches *nothing* until you
  tell it to enforce. Run it for a week, read the decisions, then flip the switch.
- **Temp before permanent.** Repeat offenders escalate; one bad window can't
  blackhole a shared CGNAT address forever.
- **Circuit breakers** cap blocks per run — with a lower, separate cap on the CSF
  plane specifically, because that's the one that can hurt.
- **Forward-confirmed crawler verification**, so a spoofed Googlebot PTR doesn't buy
  a free pass.
- Every decision is logged with the evidence that triggered it. `swatter why <ip>`
  tells you exactly why an address got hit.

It's Bash and awk. No daemon, no agent, no database server, no phone-home. It drops
onto a cPanel/CSF box and runs on cron.

## What it's not

It's not here to replace fail2ban for SSH, or to match CrowdSec's crowd-sourced
blocklist. If you're *not* behind Cloudflare, you don't have the problem it solves —
set `CF_MODE=off` and it's a fine CSF auto-blocker, but that's not the point. The
point is the dual-plane decision. If you run cPanel + CSF behind Cloudflare, you've
hit this wall, and nothing else gets you over it without either taking your site
down or leaving the abuse unblockable.

## Try it

MIT-licensed, free, on GitHub: **github.com/peaceharborco/swatter**

Report-only by default — so you can point it at production today and just watch what
it *would* do. Read a week of decisions before you let it swing.

---

*Built and maintained by [Peace Harbor Studios](https://studios.peaceharbor.com).*

---
---

## Shorter variants

### Hacker News / title options
- *Show HN: Swatter – a Cloudflare-aware abuse blocker that won't firewall your own proxy*
- *Behind Cloudflare, fail2ban can take your own site down. So I built Swatter.*
- *Why banning an IP behind Cloudflare is a trap (and the tool I wrote for it)*

### r/sysadmin / Reddit tl;dr
> If you run fail2ban or CSF on a cPanel box behind Cloudflare, banning an attacker
> at iptables does nothing — the socket is a Cloudflare edge, not the attacker. Ban
> the wrong range and you firewall Cloudflare and take every site down. The usual
> "whitelist all CF IPs" fix means you then *can't* block HTTP abuse at all.
>
> Swatter scores web-log IPs and routes the block to the right plane: direct-to-
> origin → CSF, proxied → Cloudflare WAF, never the CF edge. Bash + awk, report-only
> by default, MIT. Nothing else I found decides per-IP which side of the proxy an
> attacker is on. Links + how it scores in the post.

### One-liner (X / LinkedIn)
> Banning an attacker behind Cloudflare with fail2ban is a trap: the socket is a CF
> edge, so the ban either does nothing or takes your whole server down. Swatter
> decides per-IP which side of the proxy each attacker is on and blocks on the right
> plane. Bash, MIT, report-only by default.
