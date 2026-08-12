# Outage corroboration: tell a customer-visible outage from a quiet one

**Status:** design, **rev 2** — rev 1 reviewed and largely refuted, see
`2026-08-12-outage-corroboration-design-review-grok.md` (grok-4.6
EXECUTE-WITH-FIXES, grok-4.5 RETHINK)
**Repos:** `swatter` (primary), `foghorn` (secondary, separate deploy)
**Follows:** `2026-08-11-fatal-scanner-correlation-design.md` (rev 4), shipped as v2.14.0

## §0. The problem

v2.14.0 grades a fatal signature spanning ≥4 accounts RED, and deliberately accepts
that a bot sweep and a broken deploy are indistinguishable in an error log. Three
situations now produce the same RED and need different responses at 4am:

1. Real visitors got broken pages. **An outage.**
2. A scanner poked files that crashed. **Noise.**
3. A background job — wp-cron, a loopback REST call, WP-CLI — crashed.
   **Broken, but no human was waiting on it.**

The digest cannot currently tell them apart, so every RED reads as the worst case,
and an operator who dismisses a few learns to dismiss the next one.

### §0.1 What rev 1 got wrong, and what the evidence actually says

Rev 1 proposed netdata's `web_log_apache` 5xx series as the corroborator and
concluded, from zero 5xx during the 4-account Jetpack cluster of 2026-08-11, that
those fatals were invisible background PHP. **That conclusion was an artifact of the
wrong meter.** Verified on cds1:

- netdata's `go.d.plugin` has exactly one web log open — `/var/log/apache2/access_log`
  (`/proc/<pid>/fd`). Customer HTTPS traffic is in the per-vhost `*-ssl_log`
  domlogs, which it never reads.
- The chart carries **`500` and `502` dimensions only. There is no `503`** — the
  main log almost never sees one.
- All four accounts **did** serve failures in that window. From their own archives
  (`/home/<acct>/logs/*-ssl_log-Aug-2026.gz`, 11 Aug 05:00–06:59): `kpsd` 1×503,
  `condodelsol` 1×503, `cbcsherman` 2×500 + 1×503, `idahomining` 1×500 + 1×503.
  The chain is `wp-cron.php` → WordPress loopback → Jetpack `spawn-sync` → 503 →
  the fatal at `class-client.php:57`.

So those fatals were **served failures on a background request path** — case 3
above, but reached by evidence, not by an absence the meter could not have seen.

The lesson generalizes: a host-wide RRD of the wrong file cannot answer a
per-account question. **The corroborating plane is the per-account domlogs**, which
swatter already ingests for its abuse plane (`DOMLOGS_GLOB`).

## §1. What changes

1. **A per-account lookup** in the errors plane: for the signature that crossed the
   fan-out threshold, ask each affected account's own access log what it served in
   that window, and what *kind* of request it was.
2. **A 🔥 escalation** on the digest and SMS when the failures were visitor-shaped.
3. **Foghorn hardening**, scoped to what actually strengthens a dead-man alarm.

## §2. The safety rule

> **Corroboration may escalate or annotate. It may never suppress.**

No absence of evidence downgrades a RED. A failed or missing lookup never moves a
grade in either direction. The only movement permitted is RED → RED-escalated, plus
wording. A signal allowed to turn RED into GREEN rebuilds the defect v2.14.0 closed.

Rev 1 obeyed this in the grade and still broke it in the prose: labelling a RED
*"consistent with background/cron crashes"* is a causal claim the evidence cannot
carry, and it suppresses attention even while the SMS fires. **Rev 2 reports what
was observed and lets the operator conclude.**

## §3. The 🔥 escalation — a RED variant, and a three-way split

`RPT_GRADE` stays `RED`. This is forced by the shipped code, confirmed
independently by both reviewers:

- `ALERT_SMS_GRADES` is a literal padded-string match against `RPT_GRADE`
  (`lib/alerts.sh:75`), default `"RED"`. A grade named `FIRE` matches nothing, so
  **the most severe status the tool can produce would send no SMS**, and the
  stale-knob warn at `:70-72` would not fire because `RED` is still in the string.
- Dedup compares `"<grade> <ts>"` in `$STATE_DIR/last-sms-alert` and suppresses the
  same grade within `ALERT_SMS_DEDUP_HOURS` (`:79-86`), so a RED that escalates 40
  minutes later would be silently eaten.

`grade` (`lib/alerts.sh:65`) currently serves four roles at once. They must split:

| Role | Value when escalated |
|---|---|
| `ALERT_SMS_GRADES` membership | `RPT_GRADE` → `RED` (unchanged) |
| Dedup read + marker write | `RED!` |
| SMS body `Status …` token | `RED` |
| Icon / word / recommendation | 🔥 / `Outage` / corroboration detail |

- `_report_grade` always assigns `RPT_GRADE_ESCALATED` (`0` or `1`) — never leaves
  it stale, since tests call it repeatedly in one shell.
- `REPORT_GRADE_FORCE=fire` maps to level `red` **plus** `ESCALATED=1` *before* the
  `case` at `lib/report.sh:483`, whose `*)` arm is GREEN. An unmapped `fire` would
  preview as GREEN — the opposite of intent.
- **Sticky fail-open:** once escalated within the dedup window, a lookup that
  returns no answer must not overwrite `RED!` with `RED`. Otherwise a blink in the
  evidence path texts a de-escalation that means nothing changed.
- Tests must pin: plain→escalated sends; escalated→escalated dedups; a no-answer
  after an escalation does not text; `RPT_GRADE` is never anything but RED/YELLOW/GREEN.
  Note `test/alerts_test.sh:41` matches `Status RED` as a substring, so it would
  pass even on a wrong body — it needs a stricter assertion.

## §4. The corroboration lookup

### §4.1 Window: per signature, not per digest

The window is the min/max timestamp of **one normalized signature** — the `nsig`
that crossed `ERROR_FATAL_FANOUT_ACCOUNTS` — padded by `ERROR_OUTAGE_PAD_SECS`
(default 120), computed **inside the existing classifier awk** and exported as
`ERR_CORR_AFTER` / `ERR_CORR_BEFORE` / `ERR_CORR_ACCTS`.

It cannot be derived after the fact: `swatter_errors_section` exports no timestamps
today (`lib/errors.sh:296-303`), `fatal_genuine` is a `local`, and the rendered body
is `head -25` of an unsorted concatenation. Taking min/max over *all* genuine fatals
would routinely span the whole day — measured spans of real clusters in the retained
feed are **16–19 hours** (07-22 `get_locale` 01:27→20:58; 08-10 02:36→18:57). Only
the Jetpack cluster is tight at 50 minutes. A day-wide window corroborates from
baseline noise and means nothing.

### §4.2 Source: the affected accounts' own logs

For each account in `ERR_CORR_ACCTS`, read that account's access logs — the live
`/etc/apache2/logs/domlogs/<domain>` and `<domain>-ssl_log`, falling back to
`/home/<acct>/logs/<domain>-ssl_log-<Mon>-<Year>.gz` when the window predates
rotation — and count responses with status 500, 502 or 503 inside the window.

502 is **included** here, unlike rev 1. It was excluded because it is an order of
magnitude noisier host-wide, but that objection dissolves once the count is scoped
to the four accounts and the minutes that fataled — and on cPanel + php-fpm +
`mod_proxy_fcgi`, pool exhaustion surfaces precisely as 502/503.

Account → domain mapping already exists for the CF plane
(`/etc/swatter/cf-domains.map`); confirm whether it is reusable or whether the
`/home/<acct>/` layout is the more reliable index.

### §4.3 The discriminator: request shape, not just count

This is what rev 1 missed and what actually answers the question. For each 5xx in
the window, classify the requester:

- **Self / background** — client is the server's own IP, or the UA is `WordPress/…`,
  or the path is `wp-cron.php`, `wp-json/jetpack/…`, `admin-ajax.php` from
  loopback. The Jetpack cluster is entirely this shape.
- **Scanner** — the client IP appears in swatter's own ban ledger, or the path is a
  known bad-path probe. Swatter already owns this judgement; no new dependency.
- **Visitor** — anything else: a remote client, browser-shaped UA, ordinary page URL.

**🔥 escalates only on visitor-shaped failures**, across at least two accounts.
Background-only or scanner-only clusters stay RED, annotated with what they were.

### §4.4 What the operator sees

- **Visitor-shaped:** 🔥 — *"N accounts served M failed responses to outside
  clients during this window."*
- **Background/scanner-shaped:** RED — *"M failed responses in the same window, all
  to wp-cron/loopback (or to IPs already blocked). No outside client saw a failure."*
- **None found:** RED — *"No 5xx found in these accounts' logs for this window."*
- **Lookup failed** (logs unreadable, rotated away, mapping missing): RED, no
  claim, one `log_warn`.

Every line states an observation. None asserts a cause.

### §4.5 Cost and failure modes

Reading four accounts' logs over a bounded window at digest time is cheap; the
abuse plane already scans 219 domlogs every five minutes. Bound it: only for the
fan-out signature, only when `ERR_FATAL_GENUINE > 0`, hard cap on accounts examined,
`gzip` reads only when the window predates rotation.

netdata is **demoted to optional context** — a coarse "main-log 5xx in window: N"
line, never a 🔥 trigger and never a causal claim. If it is used at all, the query
needs `options=unaligned,null2zero`, an explicit `dimensions=` filter, and awareness
that values are responses/second, not counts (this is why rev 1's historical figures
came back fractional).

## §5. Foghorn — scoped down

Its purpose stands: **text the operator when the server is down.** Two of rev 1's
four proposals are cut.

**Cut — watching customer vhosts on the SMS path.** It scales the false-page rate
with the flakiest tenant, and it reopens a closed production constraint neither rev 1
nor I had checked: `TODO.md` and the 08-04 handoff closed `monitoring.cidr` empty
*on the condition that foghorn is never pointed at a customer vhost*, because its
1,440/day cache-busted empty-UA GETs would then land in `DOMLOGS_GLOB` as a
`request_flood` shape. If customer-site checks are ever wanted, they belong on a
separate quieter channel, not the dead-man SMS.

**Cut — content assertion as the anti-cache fix.** `isReachable` already treats 5xx
as down (`src/index.ts:125-134`) and already cache-busts, and WordPress's fatal page
is already HTTP 500. `EXPECT_TEXT` earns a place only for the narrow
200-with-error-body case; it does not detect Always-Online serving a healthy cached
copy, which is the failure it was proposed for.

**Keep — the direct-origin probe.** This is the real hardening: probe the origin
itself, so "the edge is serving" and "the origin is alive" are separable. A
dead-man alarm that only ever asks the CDN cannot see the corpse. Mechanism is
Cloudflare's `cf.resolveOverride` — **not** a `Host` header, which fails TLS — and
it must be allowlisted against origin-lock, which exists precisely to count raw-IP
hits.

**Keep — a token-gated read-only state endpoint**, so swatter can cite foghorn in
the digest. Note the KV schema is `{status, fails}` (`src/index.ts:33-36`), not
`{state, since, last_transition}`; `since` cannot be reconstructed from what is
stored, so this is a schema change, not just a handler. It is a new HTTP surface on
a Worker that currently has none.

## §6. Sequencing

1. Export `ERR_CORR_AFTER` / `ERR_CORR_BEFORE` / `ERR_CORR_ACCTS` from the
   classifier awk. Pure addition, testable alone, no behavior change.
2. `lib/corroborate.sh`: the per-account log lookup and the request-shape
   classifier, with fixtures. No digest change yet.
3. **Measurement gate.** Run it over the retained history and hand-classify what it
   finds. The fan-out default was set from one event and now sits on its threshold
   in production; do not repeat that. If visitor-shaped and background-shaped
   clusters do not separate cleanly, ship §4.4's annotation and **not** the 🔥.
4. The 🔥 escalation, the alerts split (§3), and `test-config` reporting whether the
   lookup can read what it needs.
5. Foghorn: direct-origin probe, then the state endpoint. Separate repo, separate
   `wrangler deploy`, operator-run. Not coupled to 1–4.

## §7. Known limitations

- **Rotation.** The nightly digest covers the last 24h, so the live domlog normally
  holds the window. A late run, a long window, or an archived month means gz reads
  or no answer. No answer is safe (§2) but silently degrades to today's behavior.
- **"Visitor-shaped" is a heuristic**, not proof. A scanner with a browser UA reads
  as a visitor (false 🔥, recoverable). A real user behind an IP that swatter banned
  reads as a scanner (missed 🔥 — annotated RED, still texted).
- **Some real outages produce no 5xx anywhere**: headers already sent → blank 200; a
  plugin catching the fatal and rendering 200; Cloudflare serving cache while the
  origin fails; or an outage that is wrong content rather than an error status.
  Nothing here detects those.
- **This does not reduce the RED rate.** It labels REDs. Reducing them would require
  suppression, which §2 forbids.
