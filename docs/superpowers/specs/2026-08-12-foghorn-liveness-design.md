# Foghorn liveness cross-check: does the monitor still probe us?

**Status:** design, **rev 3** — rev 1 and rev 2 both reviewed; **both returned
RETHINK**, from two models independently. The feature survives; three of rev 1's
four structural choices did not. Corrections are marked inline so they stay
legible against what they replace.
**Repo:** `swatter` · **Origin:** step 8 of `foghorn`'s
`docs/specs/2026-08-12-hardening-design.md` (rev 3), the only item in that spec
that is work in *this* repo.

## §1. What this is, and why it is not redundant

Foghorn is a cron Cloudflare Worker that texts the operator when
`cds1.peaceharborhosting.com` stops answering. Its own death is silent: a
removed cron trigger, a suspended account, a deploy that throws, and the result
is indistinguishable from a healthy week — a quiet phone.

Foghorn now closes most of that itself with an outbound heartbeat to
healthchecks.io. **This is the second, independent detector**, and it earns its
place only because it fails in a *different direction*:

| Detector | Sees foghorn die when… | Blind to |
|---|---|---|
| healthchecks.io heartbeat | any run stops pinging; within ~5 min | a Cloudflare-wide failure that also takes healthchecks' view of it, and anything requiring trust in a third party |
| **this** | foghorn stops arriving in cds1's own logs | **cds1 itself being down** — no box, no log — and it looks only once a night |

The second row is the honest limitation and it is severe: the case we most want
covered (foghorn dead *during* an outage) is exactly the one this cannot see.
It is still worth having because it depends on nothing outside this host.

## §2. What makes this possible now

Until 2026-08-12 foghorn sent **no** `User-Agent` — Workers `fetch` omits it —
so its probes were indistinguishable from any other empty-UA client in
`access_log`. Foghorn now identifies itself:

```
141.101.97.94 - - [12/Aug/2026:23:44:25 +0000] "GET /?_cb=1786578264794 HTTP/2.0" 200 163 "-" "Foghorn/1.0 (+https://github.com/peaceharborco/foghorn)"
```

One request a minute, to `ACCESS_LOG` (`lib/common.sh:45`), **not** a per-vhost
domlog. That log is already ingested (`lib/ingest.sh:191`).

## §3. Verdicts — and the one that must not be guessed

Mirrors `_errors_corroborate`'s shape, for the same reason: absence is a claim,
and claims need evidence.

| Verdict | Meaning |
|---|---|
| `present` | the log covered the window and held ≥ `WATCHDOG_FOGHORN_MIN` probes |
| `thin` | the log covered the window, some probes, fewer than the minimum |
| `absent` | the log covered the window and held **zero** probes — the finding |
| `""` | could not look: log missing, unreadable, disabled, or holding no requests at all in the window |

**How `absent` is distinguished from `""`** is the whole design. Count *every*
request in the window first:

- zero total requests → the log does not cover the window (idle host, rotation,
  wrong path). Verdict `""`.
- some requests, none from foghorn → `absent`.

**REV 2 — B1: this rule is only as good as the non-foghorn traffic, and rev 1
never checked.** The review's objection: foghorn is a *primary* writer of
`ACCESS_LOG`, because customer HTTPS lands in per-vhost `*-ssl_log` files
(`lib/corroborate.sh:14-19`), not here. If so, foghorn dying collapses the
window toward zero lines, the rule returns `""`, and **the finding that is the
entire product is suppressed** — the lookup manufacturing "no evidence" out of
the subject's own absence, which is precisely backwards.

**Measured on cds1, 2026-08-13, before writing any code:**

| Hour (UTC) | non-foghorn lines in ACCESS_LOG |
|---|---|
| 12/Aug 21 | 911 |
| 12/Aug 22 | 527 |
| 12/Aug 23 | 387 |
| 13/Aug 00 | 456 |
| 13/Aug 01 | 606 |
| 13/Aug 02 | 292 |

Foghorn is ~60/hour — **6-17%** of the channel, not the bulk of it. The rule
survives on this host: hundreds of independent lines per hour would still prove
coverage with foghorn gone. The mechanism the review described is real; its
magnitude here is not fatal.

**REV 3 — the second review showed the same-window rule cannot be rescued at
all, only replaced.** Its decisive sentence: *you cannot have "no false alarm on
idle" and "catch foghorn dying as the only writer" from one same-window total.*
The four cases that break it:

| Situation | Live file holds | Rev 1/2 verdict | Truth |
|---|---|---|---|
| Foghorn dead, log otherwise idle | 0 requests | `""` | **miss** |
| Rotation mid-window, foghorn's lines in `access_log.1` | some non-foghorn | `absent` | **false alarm** |
| Rotation to an empty file, Apache still writing the old inode | 0 | `""` | **miss** |
| Busy host | lots of non-foghorn | `absent` | correct, by luck |

Measurement (below) says today's host is the lucky row. Designing for luck is
what rev 1 did.

**Rev 3 separates the two questions rev 1 conflated, because they need
different windows:**

- **Coverage — "is this log alive and readable?"** Looked for over a **24-hour**
  window, and satisfied by *any* timestamped line **including foghorn's own
  earlier probes**. A log that carried foghorn yesterday and is still being
  written is demonstrably the right file, whatever the last hour holds.
- **The finding — "did foghorn probe in the last hour?"** The 1-hour window,
  and only meaningful once coverage is established.

This is what makes "foghorn was the only writer and then died" detectable: its
own yesterday proves the channel. **Rotated siblings are read** the way
`lib/corroborate.sh:141-153` already reads archives, or the mid-window rotation
row above becomes a nightly false alarm.

`""` is still surfaced as loudly as `absent` — inability to look is a finding —
but it is now a genuinely rare state rather than the common one.

## §3.5 REV 2 — B2: the digest goes quiet on exactly the night this matters

Rev 1 said "surface in the nightly digest" and stopped there. `lib/report.sh`
has a **silence gate**: when abuse, origin-lock and errors are all quiet, the
mail is not sent at all.

```
    if (( ! test_mode )) && (( RPT_ACTED == 0 && RPT_EXEMPT == 0 && rpt_failed == 0
        && ol_hits == 0 && err_genuine == 0 && err_fatal == 0 )); then
        log_info "report: quiet window (${window}); not sending"
```

So on the cleanest possible "the monitor died" night — foghorn dead, box
otherwise quiet — rev 1 would have produced **no email**, and the prominent note
would never have left the host. The detector became a no-op exactly when it was
the only on-host signal. "Surface loudly" without this is fiction.

**Rev 2: `absent`, `thin` and `""` all BREAK SILENCE**, in the same class as
`err_fatal` and `ol_hits`. This is separate from the escalation decision in §7
and does not conflict with it: breaking silence sends the mail; escalating would
change the grade. The operator chose to send, not to grade.

## §4. The timezone trap, stated before it is walked into

`CLAUDE.md` records that v2.15.0's lookup "matched nothing at all on any host
not already on UTC".

**REV 2 — B3: rev 1 named the trap and then proposed walking into it.** "Compare
epochs" is a wish, not an algorithm, and re-implementing a third parser is
exactly how v2.15.0 regressed. Two correct patterns already exist in-tree and
this must adopt one, not invent:

| Existing | Approach | Cost |
|---|---|---|
| `lib/ingest.sh:41-55` | `gawk` + `mktime` under process `TZ=UTC`, then subtract the `+zzzz` offset | **hard-depends on gawk**; stock macOS awk has no `mktime`, and the suite runs under both dialects |
| `lib/corroborate.sh:64-107` | deliberately avoids `mktime`; precomputes minute/day keys with `( unset TZ; date -d … \|\| date -r … )` and matches Apache's stamp as a fixed string | portable across awk dialects and BSD/GNU `date` |

**Rev 2 takes the `corroborate.sh` approach**: precomputed minute keys matched
as fixed strings, no `mktime`, no new dependency on the report path. A one-hour
window is 60 keys, which is cheap.

`make test` must pass under a non-UTC `TZ` and under **both** awk dialects, and
the tests must actually exercise both rather than assert the intent.

## §4.5 REV 2 — cost, which rev 1 never mentioned

`ACCESS_LOG` on cds1 is **554,485 lines**. A nightly full scan is wasteful and
grows without bound. The lookup reads the tail only — bounded by the window,
not by the file — and follows `corroborate.sh`'s pattern for reaching a rotated
sibling when the window straddles one.

## §5. Config

| Knob | Default | Notes |
|---|---|---|
| `WATCHDOG_FOGHORN_ENABLE` | `false` | **REV 3 — OPEN QUESTION, see below.** Matches `ERROR_DIGEST_ENABLE`'s posture, but both reviews flagged that shipping default-off makes the release a **no-op on cds1** until someone edits the live conf |
| `WATCHDOG_FOGHORN_UA` | `Foghorn/` | substring, not a regex, so a version bump does not break it |
| `WATCHDOG_FOGHORN_MIN` | `30` | expected probes in the last hour. Foghorn sends 60; half of that absorbs a rotation boundary and a few skipped crons |
| `WATCHDOG_FOGHORN_WINDOW` | `3600` | seconds to look back |

Both numeric knobs go through the same validation as
`_errors_validate_fatal_scanner`'s siblings (`*[!0-9]*|''|??????*` → warn +
default). Per `CLAUDE.md`: a non-numeric conf value re-resolves as a variable
name in an arithmetic context and aborts the run under `set -u`; test with
`SWATTER_CONF=<copy>`, not `VAR=x swatter …`.

## §6. Where it lives — REV 3, rewritten; rev 1 misread the digest

Rev 1 said "a new `lib/watchdog.sh`, surfaced by `report.sh`" as though that
were a one-line wiring job. It is not, and a file that is never sourced is the
quietest possible failure. The real surface, verified against the code:

| Touchpoint | What it needs |
|---|---|
| `bin/swatter:67` | an **explicit** source list — a new lib is NOT loaded unless named. `install/install.sh:228` copies `lib/*.sh`, so the file can sit on disk, installed and never sourced |
| `swatter_report_build` (`lib/report.sh:62-85`) | four planes gathered **before** `_report_grade`; a fifth needs a tempfile + `declare -F` guard, exactly as errors does |
| `_report_render_html` (`:277-386`) | independent of the text body — no new globals means **no HTML output at all** |
| silence gate (`:720-731`) | must include the new plane (§3.5), and its comment still says "ALL THREE planes" |
| status subline + subject (`:429-578`, `:687-690`) | where "loudly" actually lives; rev 1 touched neither |
| `cmd_test_config` (`bin/swatter:363-383`) | prints error-log and corroboration readiness so a mute lookup cannot pass for a quiet night. Needs the same for this |
| `test/report_test.sh:6-40` | hermetic — sources only `common.sh` + `report.sh` and stubs each section. A real section function will be missing unless stubbed |

Whether that lives in a new `lib/watchdog.sh` or inside `lib/errors.sh` is now
the smaller question. Rev 3 keeps a separate file for the reason rev 1 gave —
"is my monitor alive?" is not the server-error plane — but **the wiring above is
the actual work**, and none of it is optional.

## §7. Fail direction, and the open question

Per `CLAUDE.md`: everything in this plane fails toward the LOUDER reading, and
**no signal may turn a RED green**. This one never downgrades anything.

**DECIDED by the operator, 2026-08-12: surface loudly, do NOT escalate.**

`absent` gets a prominent, plainly worded line in the digest and changes no
grade. Rationale: a monitoring gap is not a server fault, and `RPT_GRADE_LEVEL`
is the server's grade — borrowing it to mean "and also the watchman is missing"
overloads a signal the operator already reads a particular way. It can be
promoted later, once it has been seen to fire on real data and its false-alarm
rate is known. Until then it is loud enough to notice and cheap enough to
ignore, which is the correct order to learn a new signal in.

It never downgrades anything and never turns a RED green, per `CLAUDE.md`.

**REV 3 refines what "loudly" means**, per the second review: *do not create a
RED; do force the mail and put it on the status line.* So — break silence
(§3.5), a line in the status subline and the subject, and no change to
`RPT_GRADE_LEVEL`. Rev 1's "prominent note" in the body alone would have been
buried under the planes an operator actually scans.

## §8. What this deliberately does not do

- **No alerting of its own.** It reports into the nightly digest. If it needs to
  page, that is a different change with a different blast radius.
- **No check that foghorn's alerts work** — only that it probes. Whether Twilio
  would deliver is foghorn's own synthetic delivery test.
- **No per-vhost inspection.** Foghorn hits the server hostname, which lands in
  `ACCESS_LOG` and nowhere else.

## §8.5 REV 3 — OPEN, for the operator: does this ship on by default?

`WATCHDOG_FOGHORN_ENABLE=false` follows house style and means **nothing happens
on cds1 until the live conf is edited** — a release that changes no behavior,
which is exactly the shape of a feature everyone forgets is off. Both reviews
called it out.

Three options:

1. **Default `false`, and flip cds1's conf as part of the same deploy.** Safest
   blast radius, one more manual step that has to actually happen.
2. **Default `true`.** The feature works on install. Risks a false `absent` on
   any host where foghorn is not the monitor — but swatter runs on one host.
3. **Default `false`, ship, decide later.** Honest but likely permanent.

Recommendation: **(1)** — default `false` in the example conf, and the cds1 conf
edit is part of the deploy checklist for this change, not a follow-up.

## §9 REV 2 — deliberate foghorn downtime

A redeploy, or foghorn being turned off on purpose, would otherwise produce
`absent` every night until someone remembered. Rev 2 adds
`WATCHDOG_FOGHORN_ENABLE=false` as the documented off switch and says plainly in
the digest line that the check can be disabled — rather than adding a
maintenance-window knob, which is a second piece of state to get wrong. If this
proves annoying in practice, a snooze belongs in a later change with its own
review.
