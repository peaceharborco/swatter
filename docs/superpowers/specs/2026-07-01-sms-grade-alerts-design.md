# SMS alert on severe report grades — design

**Date:** 2026-07-01
**Status:** approved (brainstorm) → implement
**Depends on:** the report-card grade (`_report_grade` / `RPT_GRADE*`) added in the report-email redesign.

## Goal

When the nightly report grades **D or F**, send an SMS alert (in addition to the email) so a severe day reaches the operator immediately. Fully configurable and OFF by default so the public build ships nothing bespoke.

## Delivery

**Twilio REST API.** `POST https://api.twilio.com/2010-04-01/Accounts/<SID>/Messages.json` with basic auth `SID:token` and form fields `From`, `To`, `Body`. Auth token read from a mode-0400 file (mirrors `SENDGRID_KEY_FILE`), never stored in the conf.

## Config (all in `swatter.conf`; public defaults keep it OFF)

| Key | Default | Meaning |
|---|---|---|
| `ALERT_SMS_METHOD` | `""` | `"twilio"` enables; `""` = off |
| `ALERT_SMS_GRADES` | `"D F"` | space-separated grades that trigger |
| `ALERT_SMS_TO` | `""` | destination number, E.164 (`+1555…`) |
| `ALERT_SMS_DEDUP_HOURS` | `6` | suppress a duplicate same-grade text within this window |
| `TWILIO_SID` | `""` | Account SID |
| `TWILIO_TOKEN_FILE` | `""` | path to a file holding the auth token (mode 0400) |
| `TWILIO_FROM` | `""` | Twilio sender number, E.164 |

## Components (`lib/alerts.sh` — new, single responsibility)

- **`swatter_send_sms <to> <body>`** — dispatch on `ALERT_SMS_METHOD`. Twilio path curls the API; returns nonzero + logs on failure. **Fail-soft**: a send error never propagates to break the report/email. Requires curl; guards missing token file / config.
- **`swatter_alert_on_grade [--test]`** — the trigger. Reads the `RPT_GRADE*` globals + config:
  - off unless `ALERT_SMS_METHOD` is set and `ALERT_SMS_TO`/creds present.
  - fire when `RPT_GRADE` is in `ALERT_SMS_GRADES` (normal), or always with a `[TEST]` prefix under `--test`.
  - **dedup**: read/write `$STATE_DIR/last-sms-alert` (`<grade> <epoch>`); skip if same grade alerted within `ALERT_SMS_DEDUP_HOURS`. `--test` bypasses dedup.
  - compose the message from the grade globals.

## Message

Short, ~1 SMS segment, e.g.:
> `Swatter cds1: Grade F — Fatal. 2 fatal errors — a service may be down. Run /server-logs now.`

Built from `${host}`, `RPT_GRADE`/`RPT_GRADE_WORD`, `RPT_GRADE_SUB`, and `RPT_RECO`. `--test` prepends `[TEST] `.

## Trigger point

In `swatter_report`, after the build/grade and the email send, on a **real** run (not `--print`): call `swatter_alert_on_grade`. Under `--test`, call `swatter_alert_on_grade --test`. SMS is an **additional** channel — the email always sends regardless.

## Safety & non-goals

- Fail-soft everywhere: a Twilio outage or misconfig logs a warning and is ignored; the email is never blocked.
- Token only from a 0400 file; never echoed.
- `--print` sends nothing (email or SMS).
- Not in scope: multi-recipient fan-out, non-Twilio backends (email-gateway/others can be added behind `ALERT_SMS_METHOD` later), MMS.

## Tests (`test/alerts_test.sh`, curl stubbed)

- fires on D and F; not on A/B/C.
- respects a custom `ALERT_SMS_GRADES` (e.g. adding C).
- off when `ALERT_SMS_METHOD=""` or `ALERT_SMS_TO=""`.
- dedup suppresses a 2nd same-grade send within the window; allows after it, and always on a different grade.
- `--test` sends regardless of grade with a `[TEST]` prefix and bypasses dedup.
- message contains host, grade letter, and the triage hint.
- send failure (stubbed non-zero curl) is swallowed (function still returns 0 to the caller).
