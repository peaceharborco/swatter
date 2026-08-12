# Consolidated adversarial review — rev 3 (2026-08-11)

**Target:** `docs/superpowers/specs/2026-08-11-fatal-scanner-correlation-design.md` (rev 3)
**Prior rounds:** `…-design-review-grok.md` (rev 1), `…-design-review-grok-rev2.md` (rev 2)
**Reviewers:** `grok-4.5` ×2 (lens mode), plus Claude-side `[code-review]` / `[security-review]` /
`[gap]` passes with an executable prototype.
**Read-only guard:** `git status --short` identical before and after both passes.

| Pass | Lens | Verdict |
|---|---|---|
| `[pass-a]` | correctness skeptic | **EXECUTE-WITH-FIXES** |
| `[pass-b]` | safety / edge-case red-teamer | **EXECUTE-WITH-FIXES** |

**First round where both verdicts agree**, and both endorse the direction. Rev 3's central safety
claim survived attack: `[pass-a]` states *"No input was found where a correct `max(depth,breadth)`
implementation files S for a line today's rule would file G."* What did not survive is rev 3's
claim that the mechanism is complete — three Blockers, all of which let the original false GREEN
survive.

All three were reproduced in an executable prototype on **both** BSD awk (macOS) and gawk before
being accepted, and all three were independently found by the Claude `[gap]` pass.

---

## Blockers

### BL-1 — The `unknown` sentinel collapses fan-out `[both]` `[gap]`

`_errors_collect_php` falls back to the **literal shared string** `unknown` when the home-path
strip fails (`lib/errors.sh:85`):

```bash
acct="${f#"${ERROR_PHP_HOME_GLOB}"/}"; acct="${acct%%/*}"; [[ -n "$acct" ]] || acct="unknown"
```

That is not a missing tag — it is a determinate-*looking* identity shared by every failed
derivation. Rev 3 §2.2 only handles "account cannot be determined," so keying on the tag treats all
such lines as **one** account.

Prototype, 17 accounts with distinct `/home/acctNN/` paths all tagged `[php/unknown]`:
`S=17 G=0` — **veto never fires, defect survives intact.** Rev 3's §2.2 fail-direction prose and
its extraction rule contradict each other.

### BL-2 — `/home`-only normalization misses multi-home hosts `[both]` `[gap]`

Rev 3 §2.2 normalizes `/home/<anything>/` only. cPanel routinely uses `/home2`, `/home3` as
additional mount roots, and `ERROR_DIGEST_LOG` is an external feed that can carry any path
regardless of `ERROR_PHP_HOME_GLOB="/home"` (`lib/common.sh:310`).

Prototype, 17 accounts under `/home2/acctNN/` with correct per-account tags: `S=17 G=0`. The
normalized signature still embeds the account, so accounts never share an `nsig` and breadth is
inert. Same defect class as §0, different mount root.

### BL-3 — §4's `fanout-no-account` expectation contradicts the gate math `[both]`

Rev 3 §4 asserts a fatal with neither tag nor `/home/` path "counts as distinct → genuine." But a
**singleton** such fatal has depth 1 and breadth 1, so `max(1,1) < 3` → **scanner**, exactly as
today. Prototype confirms `S=1`.

Either the test row is wrong, or rev 3 silently wants a different policy for undetermined identity
that `max(depth, breadth)` does not express. As written §4 would ship a failing regression test or
fork the policy.

---

## Majors

- **MA-1 — Whitespace must CO-SHIP, not ship first** `[both, with a disagreement worth recording]`.
  `[pass-b]` says sequence whitespace "first"; `[pass-a]` shows why that is dangerous, and
  `[pass-a]` is right. On a two-space feed the scanner pattern never matches, so the class is inert
  and the false GREEN is **unreachable**. Fixing whitespace *alone* makes the pattern match and
  **manufactures** the defect. Fixing fan-out alone leaves it dead on that feed. They must land in
  one commit. Rev 3 §5 has the ordering backwards and calls it "fix first."

- **MA-2 — Only the PHP collector emits a per-account tag** `[pass-a]`. Verified:
  `_errors_collect_php` (`lib/errors.sh:80-101`) emits `php/<acct>`; `_errors_collect_apache`
  (`:43-77`) emits `apache` or `apache/<host>` (a vhost, not an account);
  `_errors_collect_fpm` emits `fpm/<ver>[:pool]` (pool often *is* the account, unused by rev 3);
  `_errors_collect_mysql` emits `mysql`. So apache-sourced fleet-shaped fatals collapse their
  `nsig` correctly but share one account key → breadth 1 → still scanner. Another surviving
  false-GREEN path. Fix: fall back to the account parsed from the `/home*/<acct>/` path whenever
  the tag is not a usable `php/<acct>`.

- **MA-3 — Reusing `ERROR_FATAL_SCANNER_REPEATS` for breadth is not principled, and chronic RED is
  the steady state** `[both]`. Rev 3 §2 claimed fan-out across N accounts is "exactly as much
  evidence as N repeats on one account." Both passes refute it: depth ≥3 on one account means app
  breakage, while breadth ≥3 with depth 1 is the *default bot sweep* — the reason the classifier
  exists. `[pass-b]` quantifies the consequence: with `ALERT_SMS_GRADES="RED"`
  (`lib/common.sh:284`) and a nightly report (`REPORT_CRON="0 4"`, `:305`), the result is ~1 RED
  SMS per night for as long as any sweep continues — not a Twilio flood but a **denial of
  attention**, since `ALERT_SMS_DEDUP_HOURS` (`:286`) only suppresses duplicates inside 6h and the
  SMS body carries the status word only (`lib/alerts.sh:97`). An operator trained on "RED means
  bots again" will miss the real outage. Fix: a **separate breadth knob** with a higher default.

- **MA-4 — No escape hatch** `[pass-b]`. Rev 3 took pride in "no new configuration," but that
  leaves no lever if cds1 goes chronically RED: `REPEATS=0/1` disables the whole classifier
  (*more* RED), raising `REPEATS` reopens the multi-account false GREEN *and* weakens single-account
  depth sensitivity, `ERROR_DIGEST_ENABLE=false` silences the plane entirely, and
  `REPORT_GRADE_FORCE=green` is dangerous if left set (`lib/report.sh:453-459`). **Note the fix for
  MA-3 also fixes this**: a separate breadth knob is itself the escape hatch, adjustable without
  touching depth.

- **MA-5 — The operator still cannot separate a sweep from an outage** `[both]`. The recap says
  "N fatal errors — a service or app may be down" (`lib/report.sh:526-554`) with no breadth/depth
  split; the only evidence channel is up to 25 verbatim fatals in the body
  (`lib/errors.sh:350-353`). Rev 3 moved the ambiguity from the classifier into the operator's lap
  without giving them the evidence to resolve it. Fix: label the cluster in the digest body —
  "17 fatals across 17 accounts (fan-out)" vs "17 on one account."

- **MA-6 — The safety proof is conditional and the invariant is unstated** `[pass-a]`. `max(depth,
  breadth) ≥ depth` holds **only if** depth stays keyed on the *raw* signature and `re`/`ex` keep
  matching the *raw* signature. Nothing in rev 3 forbids a future implementer rekeying `cnt` onto
  the normalized signature. State the invariant beside the pseudocode and pin it with a test that
  locks single-account depth counts as unchanged.

- **MA-7 — Breadth promotes an untrusted field to a grading input** `[pass-b]`. The
  `ERROR_DIGEST_LOG` filter anchors only on the timestamp (`lib/errors.sh:25`); the rest of the
  line, including the account tag, is taken as truth. So a buggy or hostile aggregator can inflate
  fan-out (three forged tags → RED) or deflate it (one forged tag with real per-account paths →
  GREEN, i.e. BL-1 by another route). Rev 3 §3's "no new external dependency" is false *in the
  trust sense*: the field existed, but it was cosmetic and is now security-grade. The path fallback
  from MA-2 mitigates the deflation case. Document the feed contract.

- **MA-8 — §4's table misses every finding above** `[both]` `[gap]`, and `make test` passing is not
  evidence the defect is closed: the existing suite is entirely single-account, so it *cannot*
  catch BL-1, BL-2 or MA-2.

---

## Minors

- `SUBSEP` collision: a composite `nsig SUBSEP acct` key can in principle merge accounts if a log
  line carries `\034` (fail direction is *lower* fan-out — unsafe). Strip it before keying. Low
  practicality, cheap fix.
- Rev 3 §5 mislabels severity: the digest-copy rewrite is copy accuracy, not a correctness blocker.
  Only whitespace is load-bearing.
- Natural per-account path variance (custom plugin directories, per-site cache paths, DB names like
  `acct01_wp` appearing outside `/home/<acct>/`) diversifies `nsig` and defeats breadth. This is the
  realistic residual GREEN — more so than an attacker rewriting other tenants' fatal messages,
  which `[pass-b]` rates low. Worth documenting; note it also defeats today's depth grouping, so it
  is a limit rather than a regression.
- Normalizing the leading `[LEVEL] [src]` cannot merge FATAL with ERROR because the classifier
  input is FATAL-only (`lib/errors.sh:288`). Harmless today; note it so a future
  "classify all severities" change does not inherit a cross-level collapse.
- Include chains containing two `/home/<acct>/` paths collapse both to the placeholder — harmless,
  account key still comes from tag or first path segment.
- Rev 3's citation of `lib/errors.sh:209-214` for its fail direction is right in spirit, wrong in
  mechanism (that passage is about the veto's empty-pattern fallback). Not harmful.
- Rollback is clean — no schema, no state file. The hazard is forward (chronic RED), not stranded
  state.
- Line references in rev 3 verified accurate against the tree by `[pass-a]`.

---

## Claude's adjudication

Accepted in full. Nothing declined — both passes were accurate at every file:line, and the three
Blockers were independently reproduced in a prototype on two awk dialects before acceptance.

All fixes validated in the prototype (11/11 on BSD awk and gawk):

| Fix | Result |
|---|---|
| BL-1 — treat `unknown`/empty as non-identity, fall back to path | `/home` + `unknown` → `G=17` |
| BL-2 — normalize `/home[0-9]*/<acct>/` | `/home2` and `/home3` → `G=17` |
| BL-3 — corrected expectation | single untagged fatal → `S=1` |
| MA-2 — path fallback for non-`php` tags | apache-tagged, 17 accounts → `G=17` |
| MA-3/MA-4 — separate breadth knob | 4 accounts at `FANOUT=5` → scanner; 5 → genuine |
| Single-account parity | ×1 → scanner, ×3 → genuine, both unchanged |

Two rev-3 positions are withdrawn as a result:

1. **"No new configuration" was wrong.** Depth and breadth are different phenomena with different
   operating points; one integer cannot express "catch single-site breakage at 3, but only
   fleet-scale fan-out at 15." The separate knob is also the escape hatch MA-4 requires.
2. **"Fix whitespace first" was backwards and dangerous.** It must co-ship.

The one number that cannot be settled from the repo is the breadth default. It depends on how often
cds1 actually sees identical probe-shaped fatals across ≥N accounts — which is exactly what §0.1's
cds1 feed inspection would reveal. Proposed default 5, flagged as provisional pending that data.
