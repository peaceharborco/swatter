# Handoff — Swatter is challenging our own CI on the billing host

Written 2026-08-28, from the `phhosting` side. Nothing in Swatter has been
changed. This is evidence plus options; the decision is yours.

Unrelated to `docs/handoff-2026-08-28-gate-d-review-complete.md` — different
problem, same day.

---

## Start here

A brand/accessibility conformance check runs in GitHub Actions against the
billing portal. Since it was wired up it fails roughly **two runs in three**,
and the failures are Swatter's doing: the runner's IP gets a
`managed_challenge` IP Access Rule part-way through the run, and every request
after that returns 403.

This is not a false positive in the usual sense. **The traffic really is a
burst from one datacenter IP, and Swatter is correctly describing it.** The
problem is that the burst is ours.

Confirmed from `firewallEventsAdaptive`, not inferred: the blocks report
`action=managed_challenge, source=ip`. Not `securityLevel`, not `bic`, not
`l7ddos`. `source=ip` is IP Access Rules, and every one of the 202 on that zone
carries Swatter's note format.

The three GitHub Actions IPs that failed CI, with their rules at the time:

| IP (ASN 8075, Azure / GitHub Actions) | rule | AbuseIPDB confidence |
| --- | --- | --- |
| `20.63.219.114` | `scanner_profile` | 100 |
| `4.246.63.145` | `request_flood` | 3 |
| `172.203.196.180` | `request_flood` | 26 |

The workstation running the same checks by hand was swatted identically
(`request_flood`, score 75). That is worth noting on its own: it went from 200
to 403 mid-session and took an unrelated sibling site with it, because the
rules are account-wide. From the operator's chair it looked like a Cloudflare
problem for several hours.

## Why it fires, in Swatter's own terms

`lib/score.awk`:

```awk
if (ndist >= 25 && n >= MIN_REQS && (nerr / n) >= 0.6 && floor < 78) { floor = 78; frule = "scanner_profile" }
if (rps >= RATE_SAT && n >= 60 && floor < 75)                        { floor = 75; frule = "request_flood" }
```

Defaults are `RATE_SAT=8`, `MIN_REQS=15`. A single conformance run is three
config files, each loading a page about seven times (two OS-theme passes, a
reduced-motion pass, two forced-theme passes, plus a reload for the keyboard
focus check), and each page load pulls its own CSS/JS/font/image subresources.
Order of 300 requests from one IP, at well over 8 rps. `request_flood` is not
being fooled — it is measuring exactly what happened.

**`scanner_profile` on the third IP is the part worth pausing on, because it
looks like a feedback loop.** That rule needs `nerr/n >= 0.6`. Once the first
swat lands, every subsequent request from that IP returns 403 — which drives
the error ratio up, across the many distinct subresource paths the run touches
(`ndist >= 25` is easy for a page with fonts and images). So being challenged
makes the client look more like a scanner, which can promote it to a higher
floor than the behaviour on its own earned. Worth confirming against the
archive before treating it as fact, but the ordering fits.

Two things this is **not**:

- **Not the ASN signal.** AS8075 is absent from `config/hosting-asns.txt` and
  `config/shared-egress-asns.txt`. Nothing here is origin-penalising Azure.
- **Not the AbuseIPDB intel doing the work.** Two of the three fired on a
  behavioural rule with confidence 3 and 26 — effectively noise. Azure address
  space recycles constantly and carries strangers' history. The intel is
  along for the ride, not driving.

## What will NOT fix it

Recorded because the `phhosting` side spent real time on both before checking
the events, and someone will otherwise repeat it.

- **A Cloudflare Configuration Rule** lowering Security Level / Browser
  Integrity Check for the checker. Wrong layer twice over: neither is the
  source, and the zone's existing skip rule already lists `bic` and
  `securityLevel` in its `products`.
- **Anything in the zone's WAF custom rules**, including the existing
  shared-secret header the checker sends (documented in the private
  `terminal-scripts` repo). **IP Access Rules are evaluated ahead of custom
  rules and cannot be skipped by one.** That is the whole reason the header,
  which does work against the datacenter-ASN custom rule, is powerless here.
- **A bigger Cloudflare plan.** More custom-rule headroom does not reach an IP
  Access Rule either.

## Options

None started. Roughly cheapest-and-safest first.

**1 — Make the checker quieter (no Swatter change at all).** **DONE
2026-08-31.** Visual contract 1.10.0. Live-origin navigations are spaced
5 seconds apart (`PH_CHECK_PACE_MS` overrides, including `0` to disable).
Local `--root` and loopback `--origin` stay unpaced. The phhosting contrast
checker got the same spacing. Costs a slower origin-mode CI job, gives up
no protection, needs no allowlist. It is still calibration against
thresholds that can move.

The rest of this document is not moot: the 403→`scanner_profile` loop is
real and still open. Option 1 only stops the checker from being the
traffic that trips `request_flood`.

**2 — A narrow exemption requiring TWO independent signals.**
A distinctive User-Agent on the checker **and** membership of GitHub's
published Actions ranges (`api.github.com/meta`, key `actions`, refreshable the
same way the Cloudflare ranges already are). Either alone is unsafe:

- UA alone is spoofable by anyone, and this is the billing host. Note
  `_swatter_is_good_crawler` in `lib/allowlist.sh` deliberately uses
  forward-confirmed rDNS for exactly this reason — GitHub runners have no
  equivalent, which is why a second signal has to substitute for it.
- Range alone allowlists a platform anyone can rent by the minute.

**This should NOT go in the existing never-block allowlist.** That set is
all-or-nothing, and it would exempt this traffic from `honeypot` and
`critical_badpath` too — which is precisely what you would want to still fire
if a runner were ever used against you. What is wanted is narrower than
Swatter currently expresses: suppression of the **volume/behaviour** floors
(`request_flood`, `scanner_profile`, `error_burst`) only. That is a new
concept, and the design question is whether it earns its complexity.

**3 — Let Swatter recognise the header.**
Cleanest discriminator in principle, and currently **impossible**: Swatter
reads cPanel domlogs (`DOMLOGS_GLOB`, `lib/common.sh:44`), which are Apache
combined format and carry no arbitrary request headers. It would need a
LogFormat change on the origin first — and note that logging the header's
*value* would put a live credential at rest in domlogs, readable by anyone with
log access, which is worse than the problem. Logging only a presence marker
would be needed, and Apache does not express that cleanly. Probably a dead end;
written down so it is not rediscovered as a bright idea.

**4 — Accept it.**
Re-run CI until it passes. Rejected on the `phhosting` side and worth saying
why here: a gate that is red two runs in three gets ignored, and the check
exists because that exact surface had been silently unverified for four days.
A flaky gate and a disabled gate end up in the same place.

## Open questions for whoever picks this up

1. Does the `scanner_profile` feedback loop above actually hold? Check a
   swatted CI IP against the archive: were the 403s that inflated `nerr/n`
   Swatter's own challenge responses?
2. Is there prior art for a partial exemption — suppressing some floors but not
   others? If not, is option 2 worth introducing one, or does option 1 make the
   question go away?
3. Should very low AbuseIPDB confidence (3, 26) contribute at all? It is not
   what fired here, but it is riding along on shared cloud space and the same
   pattern will recur.

## Not a Swatter problem, noted for completeness

The same investigation found and fixed an unrelated leak on the `phhosting`
side: the checker's shared-secret header was being attached at the browser
*context* level, so it rode every request the page made, including to a
third-party analytics script. Scoped to the origin, and the secret was rotated.
Nothing in Swatter was involved and nothing here needs to change for it.
