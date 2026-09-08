# SMTP AUTH campaign digest — visibility, no blocks

**Status:** design, rev 1. Not stamped. Requires its own review before any code.
**Repo:** `swatter` only.
**Constraints:** Peace Harbor v3 plans
`2026-09-07-webmail-credential-spray-swatter.md` (not a mechanism) and
`2026-09-07-webmail-credential-spray-review-claude.md` (four RETHINK verdicts).
**Spike:** Task 1 surface split, cds1, 2026-09-08, read-only.

This spec is the mechanism v3 refused to prescribe. It is deliberately smaller
than anything that died in review.

## §0. The problem

A distributed credential spray, one attempt per source IP, against real client
mailboxes. Every per-IP counter is defeated by construction (`cPHulk
max_failures_byip=5` never fires). Swatter is structurally blind: `swatter_ingest`
reads Apache only. There is no victim/target dimension anywhere.

A failed password is not evidence of malice. A failed password from a known-bad
source is. The v2 attempt to express that in `score.awk` is impossible
(`score.awk:16-19`: reputation is not computed there) and the only arithmetic
that would both block a feed-listed IP and spare a clean residential IP is a
four-point emit band `[66, 69]` whose bounds move if anyone retunes
`W_REPUTATION` or `SCORE_TEMP`. That band is **rejected**. This spec does not
block.

### §0.1 Task 1 — the three disagreeing numbers were three different events

Read-only on cds1, 2026-09-08. Origin-lock `MODE=DROP`. No state changed.

| Source | Number (incident window) | What it actually was |
|---|---|---|
| cPHulk `login_track` SERVICE=`mail` TYPE=`-1` | ~470 / 6h then; **349 fails, 318 IPs, 289 ones, 69 users** in the 6h before the spike | **The spray.** `AUTHSERVICE=dovecot`. |
| `exim_mainlog` `dovecot_login authenticator failed` | **349 / 318 / 68** in the same 6h | **The same events.** Connecting IPs are real; **zero** in `cloudflare.cidr`. Gray MX — Cloudflare cannot see this. |
| `maillog` `imap-login` auth failed | 24 / 24h on Sep 7 | **Not the spray.** 23 from one already-noted benign client. Intersection with live cPHulk IPs: **0**. 754 `Logged in` from `127.0.0.1` = webmail → local dovecot. |
| `login_log` `[webmaild]` FAILED | 148 lines, 6 distinct IPs on Sep 7 | **Not the spray.** 148 GET, all `login attempt without username`, 3 scanner IPs + 3 `whostmgrd`. **0 POST. 0 CF colos. 0 SUCCESS lines for any service in 2026** (fail-only file). |

v2's colo hypothesis is false: those six IPs are not Cloudflare colos and are
not the campaign. `login_log` would not show colo IPs anyway if `mod_remoteip`
restores `CF-Connecting-IP`. Origin-lock covers `:80`/`:443` only.

**Authoritative log for this campaign: `/var/log/exim_mainlog`.** cPHulk is a 6h
rolling window over the same dovecot AUTH (`TYPE=-1` expires with
`lookback_time=21600`) and cannot fill a 24h digest.

### §0.2 What this does not claim

- A webmail geo-gate would not have stopped this spray.
- LIVE-1 (spoofable UA skip on 49 zones) and LIVE-2 (unscoped datacenter
  challenge on webmail XHR) remain live, independent, and out of this spec.
- Password rotation remains the cure.
- `username_based_protection=1` remains a DoS lever. This spec does not block
  by mailbox.

## §1. Locked decisions

1. Reject the `[66, 69]` band. Nothing in this work uses the shared reputation fold.
2. Visibility only. No CSF, no Cloudflare WAF change, no AbuseIPDB report.
3. Report-time only. A 5-minute scan cannot see a campaign (~5 SMTP AUTH fails
   per scan, spread across ~68 mailboxes).
4. Source: `exim_mainlog` over the digest window. Not `login_log`, not `maillog`,
   not cPHulk as the source of truth.
5. Grade unchanged. Campaigns are read, not paged. SMS stays on RED fatals.
6. Fail-loud: an unreadable log is never “0 campaigns.”

## §2. The safety property

> A failed password is not evidence of malice.

This plane never produces a block, a watch row in `decisions.jsonl`, a persist
bucket, or an AbuseIPDB report. Mailbox names are attacker-chosen; they are
displayed as rotation targets and are never fed to `bad_rx[]` / `hp_rx[]`.
Connecting IPs are counted, never classified, never denied.

T6 (whole-box CSF deny) and T7 (AbuseIPDB has no delete API) are closed by
not entering those paths. T8 (shadow run cannot gate the irreversible action)
does not apply. T9 (one stream / two scorers) does not apply. T10
(`MAX_BLOCKS_PER_RUN`) does not apply.

## §3. Architecture

A **fourth digest plane**, sibling to Bad Actors, Origin-Lock, Server Errors,
and Swarm. Report-time only.

| Piece | Role |
|---|---|
| `lib/mail_campaigns.sh` | Parser + campaign rule + section emitter |
| `swatter_mail_campaigns_section <window>` | Public contract, same as `swatter_errors_section`: stdout = text section; globals set in the **current** shell |
| `bin/swatter` | Source `mail_campaigns` in the module list **before** `report` |
| `lib/report.sh` | Gather via redirection into a temp file **before** `_report_grade`. Never `$(...)`. |
| `lib/common.sh` | Defaults + `_swatter_validate_int` for numeric knobs |
| `config/swatter.example.conf` | Commented knobs |

**Source of truth:** `${EXIM_MAINLOG:-/var/log/exim_mainlog}` plus rotated
`exim_mainlog-*` (including `.gz`) in the same directory whose content can
overlap the digest window. Time-filter, no `SEED_BYTES`, no ingest cursor, no
fd 3.

**Enable:** `MAIL_CAMPAIGN_DIGEST=auto` (default).

| Value | Plane runs | Missing / unreadable log |
|---|---|---|
| `off` | never | n/a |
| `on` | always | `MAILCAMP_OK=0`, UNREADABLE section, must send |
| `auto` | default path exists, **or** `EXIM_MAINLOG` is explicitly set | file we intended to read is unreadable → same as `on`. Default path absent and `EXIM_MAINLOG` unset → plane **skipped** (not a mail host, not an error). An explicitly set `EXIM_MAINLOG` that is missing is UNREADABLE, not a skip. |

**Globals** (unset until the plane runs):

- `MAILCAMP_OK` — `1` on a successful read (including zero campaigns); `0` on
  unreadable / incomplete
- `MAILCAMP_N` — mailboxes that meet the campaign rule
- `MAILCAMP_FAILS` — successfully parsed `dovecot_login authenticator failed`
  lines in the window
- `MAILCAMP_IPS` — distinct connecting IPs among those lines

`_report_grade` and `swatter_alert_on_grade` do **not** read these.

**Quiet-window skip** (`swatter_report` around the `RPT_ACTED == 0 && … &&
err_fatal == 0` test) gains:

- Plane skipped (`off` / `auto`+absent) → no change
- `MAILCAMP_OK=1` and `MAILCAMP_N=0` → plane is quiet
- `MAILCAMP_N>0` → send
- `MAILCAMP_OK=0` → send, even if every other plane is empty

`--print` always prints. `--test` still forces send.

**Render when the plane ran**, including successful zero and UNREADABLE — same
as Server Errors, not Origin-Lock `auto` hiding on zero hits. HTML gets a
matching `Mail Campaigns` block. UNREADABLE uses the ember color already used
for fatals. Subject line stays the existing grade summary. Help line stays
`swatter why` / `swatter unblock` — this plane creates nothing to unblock.

## §4. Parser

Match **only** this line class (the one that equalled cPHulk 349/349):

```
YYYY-MM-DD HH:MM:SS dovecot_login authenticator failed for H=… [addr]:port: 535 … (set_id=IDENTITY)
```

Anything else in `exim_mainlog` is ignored.

**Anchored parse, not field-split.** T5: `set_id` is attacker-chosen and shares
the line with the source IP. A tab or a `[1.2.3.4]:25` inside `set_id` must not
become the connecting IP.

- **Timestamp:** start of line, `YYYY-MM-DD HH:MM:SS`. Interpret in the host’s
  local zone (`unset TZ` for `mktime`, same trick as the Apache error collector
  in `errors.sh`). `common.sh` exports `TZ=UTC` process-wide; a bare gawk would
  otherwise shift a non-UTC host the way v2.15.0 did.
- **Connecting IP:** the last `[IPv4]:digits` or `[IPv6]:digits` **before**
  `535`. Never take an address from `H=`, from a parenthetical HELO
  (`([49.124.131.248])`), or from `set_id`.
- **Identity:** `set_id=` through `)` or end of line. Grouping key = that
  string, **verbatim**. Do not reconstruct `@domain`, do not lowercase, do not
  put it in a path-shaped field.
- Drop the line if timestamp, connecting IP, or `set_id` is missing. A line we
  cannot fully parse does not become a row.

**Locale:** `LC_ALL=C` on the gawk invocation (T13). Fixtures include a
non-UTF-8 byte and a tab inside `set_id`.

**Rotation:** glob `exim_mainlog` and `exim_mainlog-*` in the log’s directory
(and `.gz`). **Select** a file only if it is the live log or its mtime is
`>= cutoff` (it could still contain lines in the window). Do not open ancient
rotations. If **any selected** file is unreadable, `MAILCAMP_OK=0` and the
section is an error — do not publish a campaign list from a partial read. An
unreadable file we would not have selected does not fail the night.

## §5. Campaign rule

Group by verbatim `set_id`.

A **campaign** is a mailbox with **≥ `MAIL_CAMPAIGN_MIN_IPS` distinct connecting
IPs** in the window. Default **5**, validated `2–100` via `_swatter_validate_int`
during `swatter_load_config`. Tested with `SWATTER_CONF=<copy>`, not
`VAR=x swatter …`. (`MIN_IPS=1` would make every mailbox a campaign; the floor
is 2 so that is a typo, not a config.)

One IP with 23 failures against one mailbox is a client typo, not a campaign —
omit it.

**Section contents:**

- Header: campaigns, parsed fails, distinct IPs in the window.
- Table, cap `MAIL_CAMPAIGN_LIST_CAP` (default 20, validated `1–200`): mailbox,
  distinct IPs, attempts, percent of attempts that were one-per-IP.
- Sorted by distinct IPs descending, then attempts.
- One remainder line if more campaigns exist than the cap.
- Zero campaigns + successful read: `No SMTP AUTH campaigns this window.`
- Unreadable: `UNREADABLE: …` and **not** that sentence.

No connecting-IP list in the email.

## §6. Knobs

| Knob | Default | Validation |
|---|---|---|
| `MAIL_CAMPAIGN_DIGEST` | `auto` | `auto` / `on` / `off`; anything else → warn + `auto` |
| `EXIM_MAINLOG` | `/var/log/exim_mainlog` | path. Unset + `auto` + default missing → skip plane. Set to a missing path → UNREADABLE even under `auto`. |
| `MAIL_CAMPAIGN_MIN_IPS` | `5` | `_swatter_validate_int` 2–100 |
| `MAIL_CAMPAIGN_LIST_CAP` | `20` | `_swatter_validate_int` 1–200 |

Environment variables do not reach that validation (`lib/common.sh` assigns
defaults unconditionally). The real vector is the conf file. Repo rule in
`CLAUDE.md` applies.

## §7. Tests

New `test/mail_campaigns_test.sh`, same harness as `errors_test.sh`: source
`common.sh` + the new lib, fixed `swatter_now`, fixture dir, redirection not
`$()` so globals survive. `make test` already globs `test/*_test.sh`. Both awk
dialects and a non-UTC `TZ` — existing `make test` contract.

Fixture stamp `2026-06-25 10:00:00` with `swatter_now=1782396000` (inside 24h).
Identities are synthetic (`box1`), not production mailboxes.

### Parser / campaign

| Case | Fixture | Assert |
|---|---|---|
| Happy spray | 5 IPs × `set_id=box1`, one attempt each | `MAILCAMP_OK=1` `MAILCAMP_N=1` `MAILCAMP_FAILS=5`; section lists `box1` |
| Below threshold | 4 IPs × `box1` | `MAILCAMP_N=0`; body is `No SMTP AUTH campaigns this window.` |
| Typo, not campaign | 23 fails, one IP, `box1` | `MAILCAMP_N=0`; `box1` absent |
| Threshold knob | 4 IPs, `MAIL_CAMPAIGN_MIN_IPS=4` | `MAILCAMP_N=1` |
| Cap | 25 campaigns of 5 IPs | 20 rows + remainder line |
| Verbatim key | `shipping` and `shipping@x.com` | two groups, not merged |
| HELO decoy | `H=([203.0.113.9]) [198.51.100.10]:25:` | connecting IP is `198.51.100.10` |
| T5 tab + fake IP in `set_id` | `set_id=x\t[203.0.113.9]:25` | IP remains the real `[addr]:port`; not `203.0.113.9` |
| Drop incomplete | no `set_id` / no `[addr]:port` / no timestamp | no row, does not crash |
| T13 binary byte | one garbage line + one valid | valid still counted |
| IPv6 | `[2001:db8::1]:465` | counted |
| TZ | `TZ=America/New_York`, stamp near cutoff | same `mktime`/unset-TZ rule as Apache errors; must not vanish |

### Fail-loud / wiring

| Case | Assert |
|---|---|
| File unreadable (`chmod 000`) | `MAILCAMP_OK=0`; section contains `UNREADABLE`; does **not** contain `No SMTP AUTH campaigns` |
| One rotated file unreadable | same — no partial list |
| `auto` + missing default path | `MAILCAMP_OK` unset; no section |
| `on` + missing path | `MAILCAMP_OK=0`; UNREADABLE |
| Rotation | live + `exim_mainlog-20260625` both in window | sums both |
| `.gz` rotation | gzip fixture readable | counted |

### Report builder (`test/report_test.sh`)

Stub `swatter_mail_campaigns_section` like errors / origin-lock.

- Campaign-only night (`MAILCAMP_N=1`, everything else zero) still **sends**.
- `MAILCAMP_OK=0` still sends.
- `MAILCAMP_OK=1` `MAILCAMP_N=0` does **not** by itself send.
- `_report_grade` with `MAILCAMP_N=99` and no fatals/blocks stays GREEN.
- HTML contains `Mail Campaigns` when the plane ran.

### Knobs

`SWATTER_CONF=` copy with `MAIL_CAMPAIGN_MIN_IPS=abc` and `=1` → warn + default
5. `config/swatter.example.conf` and `test/shipped_config_valid_test.sh` grow
the new keys.

**Out of scope for tests (and for the feature):** CSF, AbuseIPDB, `score.awk`,
`login_log`, `maillog`.

## §8. Out of scope

- Blocking, watch-band emit, persist, dual-plane, AbuseIPDB.
- Ingest of `login_log`, `maillog`, or cPHulk sqlite.
- Victim-keyed **blocking** (cPHulk `username_based_protection`).
- Cloudflare WAF / geo-gate / LIVE-1 / LIVE-2 (companion repo
  `terminal-scripts`; companion plan is still a constraints document).
- Password rotation (operator).
- Changing the nightly grade or SMS.
- A scan-time victim-key store.

## §9. Files

| Path | Change |
|---|---|
| `lib/mail_campaigns.sh` | create |
| `lib/report.sh` | gather, skip predicate, text banner, HTML block, summary one-liner |
| `lib/common.sh` | defaults + validation |
| `bin/swatter` | source list |
| `config/swatter.example.conf` | knobs |
| `test/mail_campaigns_test.sh` | create |
| `test/report_test.sh` | stub + skip/grade/HTML cases |
| `test/shipped_config_valid_test.sh` | new keys |
| `docs/RUNBOOK.md` | short operator note: section meaning, not a block |

No change to `lib/score.awk`, `lib/score.sh`, `lib/ingest.sh`, `lib/block_*.sh`,
`lib/report_abuseipdb.sh`.
