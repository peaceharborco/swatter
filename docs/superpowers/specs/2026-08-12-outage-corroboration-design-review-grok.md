# Adversarial review — outage corroboration design, rev 1

Two independent models (the roster gained `grok-4.6` today, so this ran as
**grok-4.6 = plan fidelity** and **grok-4.5 = monitoring soundness**, rather than
one model under two lenses), plus inline `[code-review]` / `[gap]` passes.

**Verdicts: grok-4.6 EXECUTE-WITH-FIXES · grok-4.5 RETHINK.**

Rev 1 is superseded by rev 2. The meter it was built on cannot see the events it
was built to measure.

## Blocker 1 — the meter is blind to the traffic that matters `[grok-4.5, verified]`

Rev 1 §0.1 claimed netdata's `web_log_apache` series covers customer vhost traffic,
and drew from it the conclusion that the 4-account Jetpack cluster of 2026-08-11
served zero failures and was therefore invisible background PHP.

**Both halves are wrong, and I confirmed it directly on cds1:**

- netdata's `go.d.plugin` has exactly one web log open: `/var/log/apache2/access_log`
  (read from `/proc/<pid>/fd`). Customer HTTPS traffic goes to the per-vhost
  `*-ssl_log` domlogs, which it never reads.
- The chart's dimensions are **`500` and `502` only — there is no `503` dimension**,
  because the main log almost never sees one. Rev 1 §4.1's "count 500 and 503, not
  502" policy is not expressible against this chart.
- All four accounts in that cluster **did** serve 5xx in the window. From their own
  monthly archives (`/home/<acct>/logs/*-ssl_log-Aug-2026.gz`), 11 Aug 05:00–06:59:
  `kpsd` 1×503, `condodelsol` 1×503, `cbcsherman` 2×500 + 1×503, `idahomining`
  1×500 + 1×503. The chain is `wp-cron.php` → WordPress loopback → Jetpack
  `spawn-sync` → 503 → the fatal in `class-client.php:57`.

So the design's motivating measurement — "zero 5xx, therefore nobody saw it" — was
the wrong meter reporting an absence it could not have detected. Worse, the failure
mode is systematic and silent: any multi-account break that only fataled on HTTPS
vhosts reads as "uncorroborated", gets labelled *"consistent with background/cron"*,
and trains the operator to discount the very RED that matters.

**Consequence for rev 2:** the corroborating plane is the **per-account domlogs**,
which swatter already ingests for the abuse plane. netdata is demoted to, at most,
a coarse secondary note.

## Blocker 2 — there is no cluster span to query `[grok-4.6, verified]`

Rev 1 §4.2 said "take the earliest and latest timestamps in the genuine fatal set."
`swatter_errors_section` exports counts and `ERR_FATAL_FANOUT_MAX` and nothing else
(`lib/errors.sh:296-303`); `fatal_genuine` is a `local`, the rendered body is
`head -25` of an unsorted concatenation, and the collectors never sort
(`lib/errors.sh:40-43`). Min/max over *all* genuine fatals in a 24h digest would
routinely produce a ~20-hour window — exactly the "whole window vs minutes-long
cluster" failure rev 1 called its single most important parameter.

Confirmed empirically: real clusters in the retained feed span **16–19 hours**
(07-22 `get_locale`, 4 accounts, 01:27→20:58; 08-10, 3 accounts, 02:36→18:57). Only
the Jetpack one is tight (50 minutes).

**Consequence for rev 2:** the window is per *normalized signature* — the `nsig`
that crossed the fan-out threshold — computed inside the classifier awk and
exported, never derived from rendered output.

## Blocker 3 — the SMS split must be three values, not two `[both]`

Both models confirmed rev 1 §3's central premise at the line level: `ALERT_SMS_GRADES`
is a literal padded-string match against `RPT_GRADE` (`lib/alerts.sh:75`) with default
`"RED"`, so a new grade name would silence the most severe alert the tool can send,
and the stale-config warn at `:70-72` would not fire because `RED` is still present.
Keeping `RPT_GRADE=RED` is correct.

But `grade` is one local serving **four** roles — membership test, dedup compare,
marker value, and the SMS body token (`lib/alerts.sh:65, 75, 84, 97, 100`). The
natural implementation (`grade="RED!"` when escalated) makes the membership test
look for `" RED! "` inside `" RED "`, matches nothing, and **sends no SMS for a
corroborated outage** — while every existing test stays green, because none of them
set the escalation flag.

**Required split:** membership uses `RPT_GRADE` (`RED`); dedup read/write uses
`RED!`; the SMS body says `RED` and carries the distinction in 🔥 + wording.

## Majors folded into rev 2

- **`REPORT_GRADE_FORCE=fire` must map before the case statement** `[grok-4.6]`.
  `RPT_GRADE_LEVEL="$force"` (`lib/report.sh:475`) feeds a `case` whose `*)` arm is
  GREEN (`:483-486`), so an unmapped `fire` previews as GREEN — the opposite of
  intent. Map `fire` → level `red` + `ESCALATED=1`.
- **Fail-open must be sticky** `[grok-4.6 M1]`. With a dual dedup key, a netdata (now
  domlog) read failure flips `RED!` → `RED` and texts a de-escalation that means
  "the collector blinked." Once escalated inside the dedup window, a no-answer must
  not overwrite the marker.
- **Excluding 502 is wrong on this stack** `[grok-4.5 B2]`. On cPanel + php-fpm +
  `mod_proxy_fcgi`, pool exhaustion surfaces as 502/503. Rev 2 counts 500, 502 and
  503 **from the vhost logs**, where the baseline problem that motivated excluding
  502 does not apply — the count is scoped to the affected accounts, not the host.
- **No causal wording** `[grok-4.5 B3]`. "Consistent with background/cron crashes"
  is a claim the evidence cannot support and is the seed of attention-suppression.
  Report what was observed, per account, and let the operator conclude.
- **Foghorn multi-tenant SMS is a downgrade, not hardening** `[both]`. Watching 3–4
  customer sites scales the false-page rate with the flakiest tenant, and — never
  mentioned in rev 1 — it reopens a closed production constraint: `TODO.md` and the
  08-04 handoff closed `monitoring.cidr` empty on the condition that foghorn is
  never pointed at a customer vhost, because its 1,440/day cache-busted empty-UA
  GETs would land in `DOMLOGS_GLOB` as a `request_flood` shape. Customer-site checks
  must not page over SMS, and rev 2 scopes them out of the alarm entirely.
- **The content assertion is not the anti-cache fix** `[both]`. `isReachable`
  already treats 5xx as down (`foghorn/src/index.ts:125-134`) and already
  cache-busts, and WordPress's fatal page is already HTTP 500. `EXPECT_TEXT` earns
  its place only for 200-with-error-body; the change that actually separates "edge
  is serving" from "origin is alive" is the direct-origin probe, which needs
  `cf.resolveOverride` (not a `Host` header, which fails TLS) and must be
  allowlisted against origin-lock.
- **netdata query semantics** `[grok-4.6 B3]`, retained for the demoted secondary
  use: `after`/`before` are aligned unless `options=unaligned`; values are
  responses/s, so `points=1&group=sum` on a coarse tier returns a rate, not a count
  (this is why rev 1's historical "counts" came back fractional — 161.8, 23.4);
  gaps are `null` unless `null2zero`; and with no `dimensions=` filter the query
  sums every dimension, i.e. the opposite of the stated policy.

## Minors recorded

- Foghorn writes KV on partial fail streaks, not only transitions
  (`src/index.ts:66-68`) — rev 1 §0.2 overstated "no writes when healthy".
- Its KV schema is `{status, fails}`, not `{state, since, last_transition}`; a state
  endpoint cannot reconstruct `since` from what is stored today.
- `first_entry` on a netdata chart is chart-creation time, not proof of per-second
  retention at that age.
- New knobs need the house three-copy invariant (`lib/common.sh`,
  `config/swatter.example.conf`, `docs/RUNBOOK.md`) — the previous spec was dinged
  for the same omission.
- The HTML legend (`lib/report.sh:345`) hardcodes 🟢/🟡/🔴 and would leave 🔥
  undocumented; `test/report_test.sh:88`'s emoji ban does not cover it.
- My rev 1 claim that customer domains appear in netdata's log was weak evidence —
  the main log has no `%{Host}i` field, so those matches were referer/URI strings,
  not vhost attribution `[grok-4.5 m1]`.

## What survived review

- Keep `RPT_GRADE=RED` with a separate escalation flag. Both models, independently.
- Corroboration may escalate or annotate, never suppress; a failed lookup must not
  move a grade in either direction.
- Gate the escalation behind a real measurement before shipping it.
- The direct-origin probe is a genuine strengthening of foghorn's dead-man alarm.
- Neither model found a path where a *correctly implemented* escalation makes a real
  outage less likely to reach the operator than v2.14.0 does today. The danger is
  implementation drift and soft wording, not the structure.
