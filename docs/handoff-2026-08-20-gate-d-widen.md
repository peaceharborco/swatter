# Handoff — gate D widen, for pickup 2026-08-26

Written 2026-08-20. Everything in the run-up is done; the floor is the only thing
left to wait on. This is the one document to open on the 26th.

**STATUS 2026-08-29 04:49 UTC — freeze + knob applied.**
`REPEAT_WINDOW_DAYS=30`, `ABUSEIPDB_REPORT=false`, swarm left on. Backup
`/etc/swatter/swatter.conf.bak-20260829-gate-d-widen`. Back-out:
`swatter rollback-ladder --since 1787978948`. Remaining: 48h baseline (not
before 2026-08-31 04:49 UTC), `shared-egress-audit`, restore reporting. The
sequence below is still the source of truth for those leftover steps.

---

## Start here

**The floor is Wed 2026-08-26 22:40 UTC = 15:40 PDT.** Nothing below runs before it.

```bash
ssh peaceharbor
swatter test-config          # confirm the knobs still read as below
swatter report 24h --print   # confirm nothing odd happened while you were away
```

Expected, unchanged since 2026-08-20: `swatter 2.16.1`, mode `enforce`, ladder
ARMED, `REPEAT_N=3 window=7d crit-single=4`, perm tripwire `5/run 70/day`,
`publication: swarm=true abuseipdb=true`, shared-egress ENABLED with **11**
ranges and **1** ASN, origin-lock `mode=drop`.

If any of that differs, stop and find out why before widening — gate D's whole
method is judging a new rate baseline against a stable one.

---

## Sequence

### 1 — after 15:40 PDT on the 26th, three fresh runs

```bash
# a. unstamped-temp readiness. See the TRAP below before reading the number.
sqlite3 -cmd '.timeout 5000' /var/lib/swatter/swatter.db \
  "SELECT date(ts,'unixepoch') d, COUNT(*) FROM actions
    WHERE action='temp' AND dry_run=0
      AND ts >= strftime('%s','now','-30 days')
      AND reason NOT LIKE '%rule=%'
    GROUP BY d ORDER BY d;"

# b. scanner_profile audit, fresh, FROM RAW DOMLOGS (not swatter's evidence JSON,
#    which folds UA to the first and paths to the first five).

# c. the candidate list. Never review a saved one.
swatter escalate-preview --window 30 > /root/gate-d-review/preview-$(date -u +%Y%m%dT%H%M%SZ).tsv
```

### 2 — enrich and sort

```bash
mkdir -p /root/gate-d-review && chmod 700 /root/gate-d-review
tools/gate-d/gate-d-enrich.sh --preview /root/gate-d-review/preview-<utc>.tsv \
                              --out /root/gate-d-review/round-<utc>
```

Read `buckets.txt`. Three piles:

- **bucket 1 — inert.** Already allowlisted, private, or shared-egress capped.
  Cannot perm. Count them, do not read them.
- **bucket 2 — hostile.** Hard external intel, nothing served, no User-Agent on
  any request. **Audit the 25–30 row sample it prints.** One false positive in
  the sample collapses the whole bucket into 3.
- **bucket 3 — human review.** Everything else, plus everything the tool could
  not fully evidence. This is the work.

### 3 — the review

Disposition by class. **This is the rule that was wrong until 08-20 — do not use
an older note:**

| What the address is | What to do |
|---|---|
| A single identified endpoint (customer office, site owner, your own box) | `swatter allow <ip> "<who> - <why> - verified <date>"` |
| A **shared** exit (consumer VPN, CGNAT, mobile carrier NAT, WARP) | **shared-egress, never allowlist.** Add the range to `/etc/swatter/shared-egress.cidr` or the ASN to `shared-egress-asns.txt` |
| Verified crawler | neither — forward-confirmed rDNS already exempts it |

`swatter allow` writes a **never-block**. On a shared exit that is a free pass for
everyone else riding it — which is exactly the mistake the 2026-08-11 sweep
reversed (7 `--perm-allow` never-blocks removed and replaced with shared-egress).

**Ordering trap:** for a candidate that currently holds a temp it is
**`swatter unblock` THEN `swatter allow`**. The unblock is what resets the ladder
count. `allow` alone leaves the count intact and the IP simply re-escalates,
looking like the allowlist did not take.

Verify every unblock on **both planes** — `swatter list perm`, `swatter list cf`,
`csf -g <ip>`. The exit code is not enough: `swatter_store_unblock` clears
`offenders.perm` before the failure check, so a partial backend failure still
*looks* remediated.

### 4 — the widen, in this order

```bash
# STEP 1 — freeze AbuseIPDB FIRST, before the knob change.
cp /etc/swatter/swatter.conf /etc/swatter/swatter.conf.bak-$(date -u +%Y%m%d)
# set ABUSEIPDB_REPORT="false"
swatter test-config          # must read: abuseipdb reporting: off
# Leave SWARM_PUBLISH alone — toggling swarm flushes its whole deferred backlog.

# STEP 2 — only after the review AND step 1
# set REPEAT_WINDOW_DAYS=30
swatter test-config
```

Config is read per-process, so both take effect on the next `*/5` scan. No cron
hold needed.

Then watch 48h and establish gate D's **own** rate baseline. Judge against that,
never against gate C's band. `PERM_RATE_ALERT_*` only notifies — **a silent
tripwire is not a green light**, and ladder perms keep landing every `*/5` while
you wait.

### 5 — before restoring reporting

```bash
swatter shared-egress-audit     # read what the widen actually permed
```

This is the last point at which a wrong perm is still free to fix. While
`ABUSEIPDB_REPORT` is false a misclassification costs a reversible ban; once
reporting is back on, the same mistake is a permanent public accusation with no
delete API. Minutes of work, and it is why bucket 2 is acceptable at all.

Only after the 48h baseline **and** a clean audit: restore
`ABUSEIPDB_REPORT="true"`. Nothing replays — the arm has no cursor, so perms
placed during the freeze are simply never reported. That is the accepted cost.

**Back-out** at any point is `swatter rollback-ladder --since <ts>` — **never** a
config revert, which does not undo bans already placed.

---

## Traps that will bite

**The unstamped-temp query reads ~646, and that is fine.** Two post-v2.11.0 temps
(2026-08-12, hard-intel blocks with an empty `decisive_rule`) are unstamped and
always will be. They are honest negatives — no decisive rule means genuinely not
`critical_badpath` — not the unevaluable pre-stamp rows the floor exists to
clear. Read the per-day breakdown: the `07-21..27` block is the real backlog and
should have aged out. **Do not slip the floor to 09-11 over the 08-12 rows.**

**The review is probably bigger than 615.** That figure is from 2026-08-01. On
08-20 the window=7 population had gone 125 → 201, 1.6× in 19 days. If window=30
moved similarly it is nearer **1,000 rows**. Plan capacity against the larger
number; the fresh preview gives the real one.

**Do not triage from `swatter top`.** On 08-20 all 20 rows carried `PERM=1` and 19
showed `plane-upgrade` as `LAST`. It answers "who has been worst", never "who is
about to escalate". `escalate-preview` is the instrument.

**`escalate-preview` does not model `REPEAT_N_CRITICAL_SINGLE` at all** — its own
preamble says so. The review instrument cannot show you that bar either way.

**Do not pre-run `escalate-preview --window 30` to "get ahead".** A preview
generated before the floor is exactly the saved list the gate forbids reviewing,
and running it twice means reviewing it twice.

**Do not hand-edit `/etc/swatter/shared-egress-asns.txt` without a trailing
newline.** It is a single line (`206092`). Losing that newline silently turns off
the shared-VPN ASN protection while `test-config` still reports it healthy. Fixed
in the repo (`d396ad6`) but **not yet deployed** — see below.

---

## State of the tooling

`tools/gate-d/gate-d-enrich.sh` — committed, `test/gate_d_enrich_test.sh` green
(16 cases, mutation-verified, both awk dialects). Needs **bash 4+**; it refuses
to run under macOS `/bin/bash` 3.2.

**It has not been re-reviewed since the round-4 fixes.** Four review rounds each
found a distinct way for a shared-egress address to reach bucket 2 — the pile no
human reads — and each round found something the previous one missed. It is in
much better shape and it now has tests, but it is not proven. A fifth pass is
cheap if you want one: `/grok tools/gate-d/gate-d-enrich.sh`.

Full history and reasoning:
`docs/superpowers/specs/2026-08-20-gate-d-enrich-review-grok.md`.

If you would rather not rely on it at all, the fallback is to review the raw
`escalate-preview` output by hand. Slower, no bucket 2, no risk from the tool.

---

## Deliberately not done

- **The library fix (`d396ad6`) is committed but NOT deployed.** All six live
  policy files on cds1 end with a newline as of 2026-08-20, so the bug is latent.
  Deploying four days before the widen would make any rate anomaly ambiguous —
  the widen, or the deploy? Ship it in a normal release *after* gate D settles:
  tests both dialects, `/grok` over the range, dry-run against real prod data,
  release, deploy, sha-verify.
- **`notify.sh` dedup key — parked** (owner call 2026-08-20). A failed send still
  spends the alert's key for 6h. Revisit only if a delivery failure is actually
  observed: a non-2xx Twilio line, or a missing `alerts: SMS sent` on a night
  that graded RED. Spec is on disk.
- **cds1 is on v2.16.1 and sha-matches the tag** (verified 2026-08-20). 12
  commits sit on `main` since that tag; ten are docs.

---

## If something looks wrong

The nightly digest lands 11:00 UTC / 04:00 PDT. A 🔥 RED there before the widen is
almost certainly unrelated to gate D — check whether the perm rate moved before
treating it as related. And **check file mtimes against the fatal's timestamp
before treating a missing-core-file PHP fatal as an outage or a compromise**: on
2026-08-20 a WordPress 7.1 auto-update produced exactly that shape on
`sandpointlife`, and it was neither.
