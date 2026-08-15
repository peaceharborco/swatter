# Design — a failed send must not spend the alert's dedup key (2026-08-15)

**Rev 1.**

**Repo:** `swatter` · **Branch:** `fix/perm-rate-tripwire-counting-and-key` · **Base:** `bdb07b3`
**cds1 runs v2.16.0.**
**Origin:** deferred Blocker from the perm-rate tripwire review — flagged by `grok-4.6` and
`grok-4.5` in both rounds, declined there on scope and carried here.
**Predecessor:** `captains-log/2026-08-15-0734-perm-rate-tripwire-alert-spam-root-cause.md`
(in `peaceharborstudios`) · CHANGELOG "Known and deliberately out of scope".

Nothing is committed as code yet.

---

## 0. The defect

`lib/notify.sh` writes an alert's rate-limit marker **before** it tries to send, and no channel
reports whether it succeeded. A total delivery failure therefore spends the key for the full
`ALERT_REPEAT_TTL` (6h default) and the operator is told nothing, for a situation that is still
happening.

The mechanism, in three lines:

```14:25:lib/notify.sh
_notify_ratelimited() {
    ...
    : > "$m" 2>/dev/null      # marker written HERE
    return 1                  # ...then the caller proceeds to send
}
```

```90:99:lib/notify.sh
swatter_notify() {
    ...
    _notify_ratelimited "$key" && { log_debug "alert '${key}' rate-limited"; return 0; }
    ( _notify_mail    "$subject" "$body"
      _notify_email   "$subject" "$body"
      _notify_sms     "$subject" "$body"
      _notify_webhook "$subject" "$body" ) &      # backgrounded; nobody reads the result
    return 0
}
```

Every channel swallows its own failure and returns 0 (`lib/notify.sh:27-88`) — `_notify_sms`
logs `notify: twilio sms failed` and returns success. An **unconfigured** channel also returns 0.
So even if `swatter_notify` waited for the subshell, there is currently no signal to wait for:
"sent", "failed" and "not configured" are the same value.

### 0.1 Severity — it is not only the tripwire

Three alerts route through `swatter_notify`, and all three are the ops-critical kind that exist
precisely because the nightly digest is too slow or too quiet:

| Call site | Key | Consequence of a swallowed failure |
|---|---|---|
| `lib/score.sh:641` | fail-closed | Swatter is not CSF-denying because the Cloudflare range list went stale, and the operator is not told for 6h. |
| `lib/score.sh:786` | `circuit_breaker` (**static**) | `MAX_BLOCKS_PER_RUN` reached — blocks are being *dropped*. A static key means one attempt, ever, per 6h. |
| `lib/score.sh:814` | perm-rate band | The subject of the review that surfaced this. |

The circuit breaker is the sharpest case and it **predates** any recent change: its key is the
literal string `circuit_breaker`, so a Twilio outage at the moment the breaker trips buys 6h of
silence while the scan is discarding blocks.

### 0.2 Why it surfaced now

Until v2.16.1 the perm-rate key was bucketed by the hour, so a failed send was accidentally
retried on the next hour's new key. That accident was a *side effect of a different bug* (the
hourly key defeated its own dedup and produced the alert spam this all started from). Fixing the
key to a stable severity band removed the accident and left the underlying defect exposed.

**This is worth stating plainly: the spam fix did not create this, it stopped hiding it.** Both
reviewers judged the deferral indefensible on those grounds. The counter-argument accepted at the
time was scope — the fix changes the return contract of four functions used by every alert — not
that they were wrong.

---

## 1. The pattern already exists in this repo

`lib/alerts.sh` — the nightly status SMS — solves exactly this problem, correctly, and writes down
the rule:

```87:89:lib/alerts.sh
        # Dedup: same status already alerted within the window? The marker is NOT
        # written here — a failed send must not suppress the retry. It is recorded
        # only after swatter_send_sms succeeds, below.
```

```118:123:lib/alerts.sh
    if swatter_send_sms "${ALERT_SMS_TO}" "$body"; then
        # Record the dedup marker only on a successful send (never in --test mode).
        (( test_mode )) || printf '%s %s\n' "$dedup_key" "$now" > "$statef" 2>/dev/null || true
    else
        log_warn "alerts: SMS send failed (report unaffected)"
    fi
```

It can do that because `swatter_send_sms` returns a real status — `_alert_sms_twilio` inspects the
HTTP code and returns 1 on anything non-2xx (`lib/alerts.sh:45-52`), while an intentionally
disabled method returns 0 as a no-op success (`lib/alerts.sh:20`).

**So this design is not novel work; it is making `notify.sh` obey a convention its sibling already
follows.** That materially lowers the risk: the shape is proven in this codebase, and the
"disabled is a no-op success" distinction — the subtle part — is already solved there.

---

## 2. The fix

Three changes, in dependency order.

### 2.1 Channels report an outcome

Each `_notify_*` gains a three-state return, matching `swatter_send_sms`:

| Return | Meaning |
|---|---|
| `0` | Delivered. |
| `1` | Configured, tried, **failed**. |
| `2` | **Not configured** — nothing was attempted. |

The `|| log_warn "…"` tails become `|| { log_warn "…"; return 1; }`. The existing
`[[ -n "${ALERT_EMAIL:-}" ]] || return 0` guards become `return 2`.

`_notify_sms` needs one extra fix: it currently early-returns `0` when curl is missing, the token
file is unreadable, or the token is empty (`lib/notify.sh:39-41`). Missing config is `2`; a
**present but unusable** token is a configuration fault and must be `1`, not silently "fine".

### 2.2 Attempt markers, promoted on success

Waiting on the fan-out is not acceptable — it is backgrounded so a slow SMS endpoint never delays
the `*/5` scan, and that is worth keeping. Instead the marker carries its own state:

- `_notify_ratelimited` writes an **attempt** marker: the literal `attempt <epoch>`.
- An attempt marker suppresses for `ALERT_ATTEMPT_TTL` (new knob, default **300s** — one scan
  interval), not `ALERT_REPEAT_TTL`.
- The background subshell collects the channel returns and, if **at least one channel returned 0**
  — or if **every channel returned 2** (nothing configured, so nothing to retry) — rewrites the
  marker as `sent <epoch>`.
- A `sent` marker suppresses for the full `ALERT_REPEAT_TTL`, exactly as today.

Net effect: a delivery failure costs one scan interval of suppression instead of six hours, the
scan is still never delayed, and a duplicate alert cannot be emitted *within* a run.

### 2.3 Legacy markers read as `sent`

Existing markers in `$STATE_DIR/alerted/` are **empty files** (`: > "$m"`). Under §2.2 an
unrecognised marker must therefore be treated as **`sent`**, not as an attempt.

This matters more than it looks. If empty read as "attempt", then on the upgrade every live
suppression across every key lapses within 5 minutes and the host emits a burst of re-alerts for
incidents the operator has already seen — the tool's first act after a fix for alert spam would be
alert spam. Legacy-empty ⇒ `sent` makes the upgrade silent, and the new state only ever applies to
markers written by the new code.

---

## 3. The safety invariant — state it in the code

> **A marker may only reach the long TTL by evidence of delivery.** Absence of evidence — an
> unreadable marker, a failed rewrite, a channel that cannot be classified — resolves to the SHORT
> TTL, i.e. to retrying.

Every failure path in §2 must fall that way, and the invariant belongs in a comment above
`_notify_ratelimited` where the next editor will see it. This is the same direction as the
errors/alerting plane's existing rule (`CLAUDE.md`, "Fail direction"): a lookup that cannot read
its evidence must never report absence.

Note the deliberate asymmetry with the marker itself: if the promotion write **fails**, the marker
stays an attempt and the alert retries next scan. A duplicate page is an acceptable cost; a missed
one is not.

---

## 4. Error handling

- **Promotion write fails** (read-only fs, full disk, perms) — leave the attempt marker, log
  `log_warn`. Retries next scan. Do not abort the subshell.
- **`STATE_DIR` unwritable at `_notify_ratelimited`** — today `: > "$m" 2>/dev/null` fails silently
  and the function returns 1, so the alert sends every run with no dedup at all. Preserve that
  behaviour (fail loud), but log it once — a silently un-deduped alert channel is worth knowing
  about.
- **Marker with a corrupt/partial body** — treat as `sent` per §2.3 (unrecognised ⇒ legacy). The
  `ALERT_REPEAT_TTL` mtime check still bounds it, so a corrupt marker cannot suppress forever.
- **`ALERT_ATTEMPT_TTL` non-numeric** — must go through the same validation as its siblings in
  `lib/common.sh` (`*[!0-9]*|''|??????*` → warn + default). Repo rule: bash re-resolves a
  non-numeric string in an arithmetic context as a variable name and aborts under `set -u`. Test it
  with `SWATTER_CONF=<copy>`, not `VAR=x swatter …` — an environment variable does not reach that
  validation.
- **`ALERT_ATTEMPT_TTL >= ALERT_REPEAT_TTL`** — a misconfiguration that makes the attempt window
  swallow the real one. Clamp to `ALERT_REPEAT_TTL` and warn.

---

## 5. Testing

`test/notify_test.sh` exists and is the right home. The suite must fail if any of these regress:

1. **All channels fail ⇒ marker stays `attempt`** ⇒ a second `swatter_notify` after
   `ALERT_ATTEMPT_TTL` sends again.
2. **One channel succeeds, others fail ⇒ marker promoted to `sent`** ⇒ suppressed for
   `ALERT_REPEAT_TTL`.
3. **No channel configured ⇒ promoted to `sent`** ⇒ no retry storm on a host that alerts nowhere.
4. **Legacy empty marker ⇒ treated as `sent`** ⇒ no upgrade burst. This is the migration test; it
   is the one most likely to be omitted.
5. **Promotion write fails ⇒ marker stays `attempt`** ⇒ retries (chmod the file read-only).
6. **Within one scan, a repeat call is still suppressed** ⇒ the attempt marker does its job.
7. **Unusable-but-present Twilio token ⇒ return 1, not 2** (§2.1) ⇒ marker not promoted.
8. **`ALERT_ATTEMPT_TTL` non-numeric / >= `ALERT_REPEAT_TTL`** ⇒ validated, warned, defaulted.

**Mutation-verify, do not trust green.** The perm-rate work shipped a suite where every call-site
contract could be reverted with the suite still passing; it was caught by review, not by the tests.
Revert each of §2.1/§2.2/§2.3 in turn and confirm a named test fails.

**Drive `swatter_notify` end to end**, not just the helpers — that was the specific gap last time.
Because the fan-out is backgrounded, tests must `wait` for the subshell before asserting on the
marker; a test that reads it immediately will race and pass for the wrong reason.

---

## 6. Sequencing

Independent of the perm-rate branch — it touches `lib/notify.sh` and `lib/common.sh`, which that
branch does not. It can ship before or after. Two notes:

- If the perm-rate fix ships first, the exposure described in §0.2 is live in the meantime: stable
  keys with no delivery retry. That is an argument for shipping this promptly, not for holding the
  perm-rate fix, which is fixing a louder problem.
- The CHANGELOG's "Known and deliberately out of scope" paragraph is retired by this change and
  must be removed in the same commit that lands it, or the docs will claim a live defect that no
  longer exists.

---

## 7. Out of scope

- **Delivery confirmation beyond the API's 2xx.** Twilio accepting a message is not the handset
  receiving it. Unfixable here and not attempted.
- **Retry/backoff inside a single run.** The `*/5` scan is the retry loop; adding another inside
  the subshell risks stacking curl timeouts against the scan lock.
- **The three call sites' keys.** `circuit_breaker` being static is noted in §0.1 as the worst
  victim, but a static key is *correct* for a condition that is either true or false. This change
  fixes the retry, which is the actual complaint; whether the breaker should also ratchet is a
  separate question.
- **`lib/alerts.sh`.** It already does the right thing. Do not "unify" the two paths as part of
  this — the status SMS has different semantics (sticky fail-open on de-escalation) that are
  deliberate and easy to break.

---

## 8. Review

Ships through the standard gate: `/grok` over the diff before release and before any surgical-scp
to prod, per `CLAUDE.md`. Give the red-team lens two things specifically — the **upgrade path**
(§2.3, the one with a blast radius across every existing marker on every installed host) and the
**backgrounded promotion write**, which is new concurrent state in the alert path and the kind of
thing this repo has been bitten by before.
