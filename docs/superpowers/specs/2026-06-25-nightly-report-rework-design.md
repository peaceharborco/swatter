# Swatter Nightly Report — email rework + scheduling

**Date:** 2026-06-25
**Status:** Draft (design approved via brainstorming; pending spec review)
**Scope:** Report/email layer + cron scheduling only. No scoring, classification, or blocking changes.
**Target version:** 2.2.0 (minor — new opt-in plane + new config keys, backward compatible)

## Summary

Rework the nightly `swatter report` email:

1. **Structured HTML layout** (replacing today's summary-pills-over-a-monospace-`<pre>`-dump).
2. **Title Case** across the title, section headers, stat-tile labels, and table column headers.
3. **A new opt-in "Origin-Lock" plane** — direct-to-origin Cloudflare-bypass hits, which today live only in the interactive `/server-logs` command, never in the inbox.
4. **"Report" wording everywhere** (title + subject; the command is `swatter report`).
5. **Dated subject with a verdict-led short summary**: `Report {YYYY-MM-DD} - {short summary}`.
6. **Config-driven scheduling**: an operator-declared delivery time + timezone so the report fires at a true wall-clock hour, DST-aware, instead of the current DST-drifting `0 11 UTC` hack.

## Motivation

- The current HTML email is colored summary pills above one dark monospace block (the plain-text body rendered verbatim in `<pre>`). Functional and copy-paste-faithful, but a wall of monospace that's hard to skim on a phone.
- The interactive `/server-logs` reports **three** planes (bad actors, origin-lock, server errors); the email carries only two. Origin-lock activity never reaches the inbox.
- The subject (`[Swatter] X perm + Y temp … in 24h — host`) and schedule drift: `0 11 UTC` ≈ 4am PDT in summer but 3am PST in winter, and the title says "digest" while the command and mental model say "report".

## Goals

- Skimmable, structured HTML email ("Direction B" from the mockups), with graceful degradation across 1, 2, or 3 enabled planes.
- Origin-lock surfaced in the nightly email, **opt-in and auto-gated** (invisible to operators who don't run the lock).
- Consistent "Report" wording; a clean dated subject whose short summary still flags a bad night in the inbox list.
- Schedule + delivery timezone driven by config, durable across reinstalls, with a **neutral public default** (no Pacific assumption baked into the public repo).

## Non-goals (YAGNI)

- **No numeric report serial.** The run date (`YYYY-MM-DD`, one report/night) is the identifier; a monotonic counter needs persistent state and would gap on quiet nights (which send nothing).
- No change to scan/scoring/blocking, the silence-on-quiet-window behavior, or the delivery transport (`sendmail`/`sendgrid`/`brevo`).
- No new persisted report artifacts (the durable record stays `decisions.jsonl` + `swatter why <ip>`).
- No icon change — staying with 🪰 (native emoji; zero email-client rendering risk).
- No spike/anomaly detection in the verdict for v1 (severity is error-driven; see §6).

## Design

### 1. Layout — Direction B (structured HTML)

The email body becomes real HTML sections instead of a wrapped `<pre>`:

- **Header bar** (dark): `🪰 Swatter Nightly Report` + `host · last 24h · mode: <enforce|report>`.
- **Verdict line** (one line, color-coded by worst plane — see §6): e.g. *"Healthy. 198 bad actors swatted at the edge · 0 FATAL · the 4 server errors are transient backend blips."*
- **Stat tiles** (flex row): Permanent / Temporary / Via Cloudflare / (Origin-Lock) / Server Errors — only tiles for enabled planes render.
- **Plane sections** (see §3), each: a Title-Case header, a compact summary, and a real HTML table with action badges where applicable.
- **Footer**: `swatter why <ip>` / `swatter unblock <ip>`.

**Refactor implied:** `lib/report.sh` currently intermixes data-gathering with a plain-text emit, and the HTML renderer (`_report_render_html`) just HTML-escapes that text into a `<pre>`. Direction B needs HTML built from the underlying data, not from the text. Split `report.sh` into three clear responsibilities:

- **gather** — compute per-plane counters + record lists (sets the `RPT_*` / `ERR_*` / new `OL_*` globals).
- **render-text** — the plain-text body (for `--print` and non-HTML clients), restructured to match (Title Case, origin-lock section).
- **render-html** — Direction B structured HTML from the gathered data.

Both renderers consume the same gathered data, so text and HTML stay in parity.

### 2. Title Case

Applied to the chrome only: the title, section headers (`Bad Actors`, `Origin-Lock`, `Server Errors`), stat-tile labels (`Permanent`, `Via Cloudflare`, …), and table column headers (`IP`, `Score`, `Action`, `Why`, `TTL`). Data values — IPs, reasons (`secret files`), offense chips — are left as-is.

### 3. Planes — order, gating, graceful degradation

Rendered top-to-bottom when enabled:

| # | Section | Gate | Default |
|---|---------|------|---------|
| 1 | 🛡️ **Bad Actors** | always | core |
| 2 | 🔒 **Origin-Lock** | `ORIGIN_LOCK_DIGEST` ∈ {auto,on,off}; **auto** = render when the window has `ORIGIN-LOCK:` hits (any lock mechanism) | `auto` |
| 3 | 🩺 **Server Errors** | `ERROR_DIGEST_ENABLE` (existing) | `false` |

Degradation rule: the verdict line, the stat-tile row, and the section list are all assembled from the set of *enabled* planes. A public operator with only Bad Actors gets a clean single-plane email; the 2-plane (Josh today) and 3-plane (Josh after this) forms add sections without restructuring.

### 4. Origin-Lock section (new)

New function `swatter_originlock_section <window>` in **`lib/origin_lock.sh`** (domain-cohesive with the lock itself), mirroring the read-only logic `/server-logs` already uses:

- Source: `ORIGIN-LOCK:`-prefixed hits within the window from `ORIGIN_LOCK_LOG` (default `/var/log/messages*`; Debian-family hosts set `/var/log/syslog`). Both the standalone `csfpre.sh` lock and the inline `swatter origin-lock` emit the same `ORIGIN-LOCK:` prefix, so one reader covers both.
- Reports: total dropped hits, distinct source IPs, the `:80`/`:443` split, the lock **mode** (`LOG` dry-run vs `DROP` enforcing), and the **top 10 source IPs** by hit count — each tagged: in a swatter threat feed → *attacker*; in `monitoring.cidr`/`allow.cidr` → **legit — flag for allowlisting before DROP**; else *uncategorized*.
- **Auto-gating is data-driven** (`ORIGIN_LOCK_DIGEST=auto`): render the section when the window contains any `ORIGIN-LOCK:` hits — which works regardless of *which* lock mechanism is in use (this prod runs the standalone `csfpre.sh` DROP with the inline lock `off`, so a config/marker-based gate would wrongly suppress it). `on` always renders (even at zero hits, as a reassuring "0 dropped"); `off` never renders.
- Read-only: no state change; never runs `swatter scan`/`origin-lock apply`.

### 5. Subject + wording

- **Title string** → `Swatter Nightly Report` (text body line, HTML `<h2>`).
- **Subject** → `Report {YYYY-MM-DD} - {short summary}`:
  - `{YYYY-MM-DD}` = run date in **UTC** (`date -u +%F`), matching the tool's `TZ=UTC`. Window stays "last 24h".
  - `{short summary}` leads with the verdict so a bad night is visible in the inbox list without opening:
    - Healthy: `Report 2026-06-25 - healthy · 198 blocked, 0 FATAL`
    - With origin-lock: `Report 2026-06-25 - healthy · 198 blocked · 253 origin-lock · 0 FATAL`
    - Bad night: `Report 2026-06-25 - ⚠ 2 FATAL · 198 blocked`
  - Composition: lead with the verdict word/marker, then the present planes' headline counts (blocks, origin-lock hits when the section renders, FATAL/errors), comma/`·`-joined; omit a plane's count when that plane is absent.
  - The "Swatter" brand lives in the **sender name** (`REPORT_FROM_NAME="Swatter"`), so the inbox reads *"Swatter — Report 2026-06-25 - …"*.

### 6. Verdict severity (worst-plane-wins)

A single rule drives both the verdict-line color and the subject short-summary lead:

- **RED** — any FATAL server error in the window.
- **AMBER** — genuine non-FATAL server errors present (`ERR_GENUINE > 0`, `ERR_FATAL == 0`).
- **GREEN** — otherwise (blocks landing is healthy enforcement; no genuine errors).

Origin-lock activity does not by itself raise severity (drops are the lock working as intended); a *legit source caught in the lock* is surfaced as a flagged row inside the section, not a global red. (Spike-based escalation is intentionally out of scope for v1.)

### 7. Scheduling — config-driven, DST-aware

New config keys:

- **`REPORT_CRON="0 4"`** — `minute hour` for the nightly report.
- **`REPORT_CRON_TZ=""`** — the **report delivery timezone** (IANA name). Empty = use the server's clock (UTC for a normal server). Set = exact wall-clock delivery in that zone, DST-aware via cronie's `CRON_TZ`.

`install.sh` generates `/etc/cron.d/swatter`'s report line from these, emitting a `CRON_TZ=<zone>` line immediately **before** the report entry only when `REPORT_CRON_TZ` is set (so the `*/5` scan and `refresh-feeds` lines stay in the default TZ). Because the cron is generated from config, this survives the reinstall-clobber problem (a hand-edited `CRON_TZ` previously got overwritten on every `install.sh`).

- **Public default:** `REPORT_CRON="0 4"`, `REPORT_CRON_TZ=""` → 04:00 in the server's TZ. Honest and neutral — no Pacific assumption. (Replaces the current Pacific-targeting `0 11 UTC` template line.)
- **This prod (`peaceharbor`):** `REPORT_CRON_TZ="America/Los_Angeles"`, `REPORT_CRON="0 4"` → 04:00 Pacific year-round, DST-correct.

`swatter.example.conf` documents the reasoning inline: *"Your server clock is almost certainly UTC. To get the report at 4am in YOUR timezone, set REPORT_CRON_TZ to your IANA zone, e.g. America/Los_Angeles."*

### 8. Config additions (summary)

| Key | Default | Meaning |
|-----|---------|---------|
| `ORIGIN_LOCK_DIGEST` | `"auto"` | `auto` = origin-lock section when the window has `ORIGIN-LOCK:` hits; `on`/`off` force |
| `ORIGIN_LOCK_LOG` | `""` | syslog source for origin-lock hits; empty = `/var/log/messages*` (Debian: `/var/log/syslog`) |
| `REPORT_CRON` | `"0 4"` | nightly report schedule (`minute hour`) |
| `REPORT_CRON_TZ` | `""` | report delivery timezone (IANA); empty = server/UTC |

Title/"Report" wording is in code, not config.

## Files touched

- `lib/report.sh` — split into gather / render-text / render-html; Direction B HTML; Title Case; new subject + verdict; plane assembly + degradation.
- `lib/origin_lock.sh` — new `swatter_originlock_section` + arming-detection gate helper.
- `lib/common.sh` — new config defaults (`ORIGIN_LOCK_DIGEST`, `ORIGIN_LOCK_LOG`, `REPORT_CRON`, `REPORT_CRON_TZ`).
- `install/swatter.cron` + `install.sh` — config-driven report line + conditional `CRON_TZ`.
- `config/swatter.example.conf` — document the three new keys (and the "delivery timezone" reasoning).
- `bin/swatter` — version bump (2.2.0) at release time.
- Tests — see below.

## Testing

The report layer is currently **untested** (no `report_test.sh`). Add one, plus origin-lock section coverage:

- **`test/report_test.sh`** (new): from a synthetic `decisions.jsonl` + stubbed section functions —
  - subject equals `Report <YYYY-MM-DD> - <summary>` with the correct verdict lead (green/amber/red selection);
  - each plane is present/absent per its gate (1-, 2-, 3-plane degradation);
  - "Report" wording and Title-Case headers are present; the monospace `<pre>` dump is gone;
  - silence-on-quiet-window is preserved (no email when all planes quiet and not `--test`).
- **`test/origin_lock_test.sh`** (extend): given synthetic `ORIGIN-LOCK:` syslog lines, assert hit/IP counts, `:80`/`:443` split, source tagging (attacker/legit/uncategorized), and `ORIGIN_LOCK_DIGEST` auto-gating on/off.
- Keep `shellcheck --severity=error` clean; full `make test` green.

## Rollout

- TDD → deploy (surgical scp of changed libs; update `/etc/cron.d/swatter` via `install.sh` regeneration or a careful manual edit that preserves the `*/5` scan + `refresh-feeds` lines) → release `v2.2.0`.
- **Backward compatible by default:** origin-lock section auto-hides when the lock isn't armed; empty `REPORT_CRON_TZ` keeps server-TZ behavior. The only default change for *fresh* installs is the template report time (`0 11 UTC` → `0 4` in server/declared TZ); existing installs are unaffected until their config/cron is regenerated. For this prod, set `REPORT_CRON_TZ="America/Los_Angeles"` + `REPORT_CRON="0 4"` explicitly.

## Decisions captured

- Date is the report identifier; no serial counter (state + quiet-night gaps for no gain).
- "Report" wording in both subject and title; brand carried by the sender name.
- Verdict v1 is error-severity-driven (RED FATAL / AMBER genuine errors / GREEN otherwise); no spike detection.
- Origin-lock home is `lib/origin_lock.sh`; section is read-only and auto-gated.
- Scheduling is operator-declared TZ (not a mythical "local server time"); neutral public default = UTC.
