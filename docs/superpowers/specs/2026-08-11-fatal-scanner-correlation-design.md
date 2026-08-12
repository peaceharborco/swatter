# Design — close the fatal classifier's false GREEN with a fan-out-aware gate (2026-08-11)

**Rev 4** — supersedes revs 1–3. Revs 1 and 2 proposed correlating fatals with scored IPs (handoff
§4) and were killed in review; §1 records why, so it is not re-attempted. Rev 3 introduced the
fan-out gate and was reviewed with three Blockers; rev 4 fixes them, all verified in an executable
prototype on both awk dialects.

**Repo:** `swatter` · **Branch:** `main` · **Base:** `955476f` · **cds1 runs v2.13.0.**
**Predecessor:** `docs/handoff-2026-08-11-fatal-classifier-false-green.md`
**Reviews:** `…-review-grok.md` (rev 1) · `…-review-grok-rev2.md` (rev 2) · `…-review-grok-rev3.md` (rev 3)

Nothing is committed as code yet.

---

## 0. The defect

`swatter_errors_section` files a fatal as scanner-induced — which does not trip RED — when its
signature repeats fewer than `ERROR_FATAL_SCANNER_REPEATS` (default 3) times in the window. The
signature is the whole log line minus its timestamp (`lib/errors.sh:310-311`), so it retains the
absolute `/home/<acct>/…` path and the `[php/<acct>]` tag. One shared bug on N accounts therefore
produces N distinct signatures of count 1 — every one under the gate.

Re-confirmed against `955476f`, with a control isolating the mechanism:

| Fixture | Result | Grade |
|---|---|---|
| 17 accounts × 1 identical fatal | `FATAL=17 GENUINE=0 SCANNER=17` | **GREEN** |
| Same 17 fatals, all on `acct01` | `FATAL=17 GENUINE=17 SCANNER=0` | RED |

**The gate counts depth (recurrence of one signature) and is blind to breadth (one signature across
many accounts).** That sentence is the whole defect.

Severity: `ERR_FATAL_GENUINE=0` drives the GREEN path (`lib/report.sh:422`, `:474`), and
`ALERT_SMS_GRADES="RED"` (`lib/common.sh:284`) means a false GREEN also **suppresses the operator's
SMS** and prints "All Clear" (`lib/report.sh:484`).

### 0.1 Resolved on cds1 — measured 2026-08-12

Raw PHP writes `PHP Fatal error:` with **two** spaces and the shipping pattern expects one, so the
feed's whitespace handling decides whether the defect is reachable at all:

| Fixture | Result |
|---|---|
| one space | `GENUINE=0 SCANNER=17` → GREEN |
| two spaces | `GENUINE=17 SCANNER=0` → RED |

**cds1's feed (`/var/log/ph-errors/ph-errors.log`) carries the one-space form, 10/10 FATAL lines.**
The aggregator normalizes. So:

- **The defect is live on cds1.** The handoff's §1 was right; its §5 whitespace note does not
  neutralize it on this host.
- **The whitespace fix does not gate this change on cds1** (§5). It remains a real inconsistency for
  any host whose aggregator does not normalize.
- cds1 does not override `ERROR_FATAL_SCANNER_REPEATS` or `ERROR_PHP_HOME_GLOB`, so defaults 3 and
  `/home` apply.

Measured fan-out per **24h window** (the window the gate sees) over 2026-08-09 → 08-12, 10 FATAL
lines total, 9 matching the default scanner pattern:

| Day | Normalized signature | Accounts | What it actually was |
|---|---|---|---|
| 08-09 | `Call to undefined function get_locale()` in `wp-admin/…` | 2 | bot noise |
| 08-10 | same | 3 | bot noise |
| 08-11 | docket-cache `substr(): … array given` | 1 | probe; does not match pattern |
| 08-11 | `Undefined constant …Jetpack\Connection\Error_Handler::ERROR_TYPE_REST` | **4** | **genuine fleet bug** |

The last row was investigated rather than assumed (§0.2). It is the discriminating fact for §2.4:

- **Maximum fan-out from bot noise: 3.**
- **The one confirmed real fleet event had fan-out 4.**

### 0.2 The 08-11 Jetpack event — investigated, and it was real

Accounts `kpsd`, `condodelsol`, `cbcsherman`, `idahomining`, one fatal each between 05:44 and 06:34,
identical signature and identical file:line —
`jetpack/jetpack_vendor/automattic/jetpack-connection/src/class-client.php:57`.

Evidence it was a genuine bug, not a bot executing a file directly:

1. The class **resolved** and only the *constant* was undefined. A bot running a vendored library file
   outside the bootstrap would fail earlier, on the class.
2. `class-client.php` today carries a comment at line 54 stating the constants "must not be referenced
   from this class: during a plugin update, a stale `Error_Handler` that predates them can already be
   loaded, and resolving them against it would fatal the request." That is a description of this exact
   failure, written as its fix — the code now uses literal strings.
3. Timing is a ~50-minute spread with irregular gaps, not a sweep.
4. `idahomining` carries **four** copies of `jetpack-connection` (Jetpack plus WooCommerce, WC
   Payments, WC Services), and only Jetpack's own defines `ERROR_TYPE_REST` — the autoloader skew that
   lets a stale `Error_Handler` win.

**Resolution:** cds1 picked up the upstream fix in the Jetpack update at 2026-08-12 00:44–01:19, and
there are zero Jetpack fatals after that window (log runs to 08-12 03:00). No action needed on the
four accounts. The mechanism — one plugin's newer vendored code referencing a constant a
sibling-plugin's older copy lacks — remains a live class of risk on multi-copy installs like
`idahomining`, and will recur whenever a new constant is introduced.

**This is the defect doing real harm, in production, today:** four accounts, real requests fataling,
graded GREEN and SMS suppressed.

## 1. Why the correlation direction was abandoned

Recorded so it is not re-attempted. Handoff §4 chose "correlate fatals with IPs Swatter itself
scored." Two rounds of review killed it.

**Rev 1** matched each fatal to the temporally nearest 5xx on its account. Review found that the
`ERROR_FATAL_SCANNER` regex was not a weak proxy but the **mouth-limiter** restricting which fatal
shapes could ever be hidden; removing it opened every shape while substituting an evidence gate that
continuous background bot traffic already satisfies. Rev 1's stated defense (the repeat gate) was
circular, since that gate is inert in exactly the sparse multi-account case that is the defect.

**Rev 2** replaced it with a per-account causation rule — SCANNER only if the account's 5xx count
pairs 1:1 with its fatal count and all resolve to one scored IP. Review found its success case and
its failure case are **the same evidence**:

| Scenario | `\|F\|` | `\|X\|` | distinct IPs | scored | Verdict |
|---|---|---|---|---|---|
| cds1 probe sweep — bot hits `?page[limit]=1`, unguarded `substr` 500s | 1 | 1 | 1 | yes | SCANNER *(wanted)* |
| Fleet bug — bot crawls a normal route, bad deploy 500s | 1 | 1 | 1 | yes | SCANNER *(real outage)* |

**The generalization that ends the direction.** Handoff §3 concluded no regex over the fatal
*message* can separate a sweep from a fleet bug. The true statement is stronger:

> No combination of (fatal, 5xx, client IP, IP reputation) can separate them. Reputation identifies
> *who* issued the request. The distinguishing fact is whether the application would have served a
> healthy response to that request, and nothing in this data answers that.

So handoff §4's goal — keep a sweep GREEN *and* reveal a fleet outage — is self-contradictory.

**This reframes handoff §3's rejection of path-normalized counting.** §3 rejected it for producing
"a guaranteed false RED on every scanner sweep," treating that as too high a price. It is in fact
**the only currency available**. Rev 4 pays it deliberately.

**Decided 2026-08-11 (Josh):** give up hiding the sweep; close the false GREEN.

## 2. The fix

Make the gate count **breadth as well as depth**.

For each fatal, alongside the existing raw signature, compute an **account-normalized** signature
and count how many **distinct accounts** share it. A fatal is scanner-induced only if it is under
the depth threshold *and* under the breadth threshold:

```awk
scanner = (sigof[i] ~ re                     \   # unchanged: raw signature
           && cnt[sigof[i]] < reps           \   # unchanged: DEPTH, raw signature
           && sigof[i] !~ ex                 \   # unchanged: CLI veto, raw signature
           && fan[nsigof[i]] < fanmin)           # NEW: BREADTH, normalized signature
```

`ERROR_FATAL_SCANNER` is neither widened (handoff §3's prohibition) nor removed (rev 1's error). It
is unchanged, and remains the mouth-limiter.

### 2.1 The safety invariant — state it in the code

The change can only move fatals *toward* genuine, because adding a conjunct can only shrink the
scanner class. Round 3 confirmed no input exists where this files scanner for a line today's rule
calls genuine. **But the proof is conditional**, and rev 3 failed to say so:

> **Invariant:** depth (`cnt`) is keyed on the **raw** signature, and both `re` and `ex` are matched
> against the **raw** signature. Only breadth uses the normalized signature. Rekeying `cnt` onto the
> normalized signature would change single-account semantics and void this proof.

This belongs as a comment beside the awk, in the house style of the surrounding warnings, plus a
test locking single-account depth counts as unchanged.

### 2.2 Account identity — three tiers, and why

Fan-out is only as good as the account key. Round 3 found two shipping cases where a naive key
collapses many accounts into one and the defect survives untouched.

1. **`php/<acct>` tag** — but only when the tag's prefix is literally `php` and the account is
   neither empty nor the sentinel `unknown`. `_errors_collect_php` falls back to the **literal
   shared string** `unknown` (`lib/errors.sh:85`), which is determinate-looking and shared across
   every failed derivation. Treating it as an identity merges every such account into one.
2. **The `/home[0-9]*/<acct>/` path** — used whenever tier 1 yields nothing. This covers the
   collectors that do not emit per-account tags: `_errors_collect_apache` (`:43-77`) emits `apache`
   or `apache/<host>`, which is a *vhost*, not an account; `_errors_collect_fpm` emits
   `fpm/<ver>[:pool]`; `_errors_collect_mysql` emits `mysql`. Without this tier, apache-sourced
   fleet-shaped fatals collapse to one account key and stay scanner.
3. **Per-line unique key** — when neither tier yields an account. Unknown identity then contributes
   fully to fan-out and can never suppress the veto, biasing toward GENUINE/RED.

### 2.3 Normalization

- `/home[0-9]*/<anything>/` → placeholder. **Not `/home/` alone** — cPanel routinely uses `/home2`,
  `/home3` as additional mount roots, and `ERROR_DIGEST_LOG` is an external feed that can carry any
  path regardless of `ERROR_PHP_HOME_GLOB="/home"` (`lib/common.sh:310`). With `/home` only, the
  normalized signature still embeds the account and breadth is inert.
- Leading `[LEVEL] [src/id]` → placeholders. Cannot merge FATAL with ERROR because the classifier
  input is FATAL-only (`lib/errors.sh:288`); note that so a future "classify all severities" change
  does not inherit a cross-level collapse.
- Normalization is account-agnostic — no account name is ever interpolated into a regex — and the
  patterns stay hardcoded, never passed via `-v`, per the trap documented at `lib/errors.sh:300-302`.
- Strip `\034` before building the composite `nsig SUBSEP acct` key. A log line carrying `SUBSEP`
  could otherwise merge two accounts, and the fail direction of a collision is *lower* fan-out.

### 2.4 A separate breadth threshold

Rev 3 reused `ERROR_FATAL_SCANNER_REPEATS` for both and called it principled. **That was wrong, and
it is withdrawn.** Depth and breadth mean different things on a shared host:

| Signal | What it usually means |
|---|---|
| Depth ≥ 3 on one account | the same crash on repeated requests — app breakage |
| Breadth ≥ 3, depth 1 each | the **default bot sweep** — the reason the classifier exists |

At a shared default of 3, any probe-shaped fatal touching three accounts in a window grades RED and
can SMS. With a nightly report (`REPORT_CRON="0 4"`, `lib/common.sh:305`) and
`ALERT_SMS_DEDUP_HOURS` (`:286`) suppressing only duplicates within 6h, that is roughly one RED SMS
per night for as long as any sweep continues — not a Twilio flood but a **denial of attention**,
since the SMS body carries only the status word (`lib/alerts.sh:97`). An operator trained on "RED
means bots again" misses the real outage.

So breadth gets its own knob, `ERROR_FATAL_FANOUT_ACCOUNTS`, which also supplies the **escape hatch**
rev 3 lacked: it can be raised without weakening single-account depth sensitivity. Validation follows
the house pattern (`lib/errors.sh:256-260`): non-integer → built-in default with a `log_warn`, and
never clamp upward — the RED-safe direction is low.

**Disable semantics need an explicit special case.** Fan-out is always ≥ 1, so `fan < fanmin` is false
for any `fanmin ≤ 1`, which would void the **entire** scanner class rather than just the breadth gate.
So the condition is written `(fanmin <= 0 || fan[nsig] < fanmin)`, giving:

| Value | Meaning |
|---|---|
| `0` | breadth gate **off** — special-cased; depth behaviour exactly as today |
| `1` | every pattern-matching fatal counts genuine (maximum sensitivity, RED-heavy) |
| `≥ 2` | threshold as described |

`0` is the operator's escape hatch; `1` is legal and RED-safe but blunt.

**Default: 4, chosen from measurement (§0.1, §0.2).** On cds1's measured window, bot noise reaches
**3** accounts and the one confirmed genuine fleet event reached **4**. The default sits exactly on
that boundary:

| Default | Effect on the measured window |
|---|---|
| 3 | RED on 08-10's 3-account bot sweep — chronic RED from noise |
| **4** | Bot sweeps (2, 3) stay scanner; the **real Jetpack event surfaces** ✓ |
| 5 | Everything stays scanner — the real event stays hidden |
| 8 | Same, with more margin for hiding real events |

**A correction worth recording.** An earlier pass set this to 8 by treating the 4-account Jetpack
signature as routine sweeping when computing "maximum fan-out from bot noise." Investigating it
(§0.2) showed it was the genuine article, which moves the bot-noise maximum to 3 and the real-event
observation to 4. **Defaults of 5 and 8 would both have hidden the one real fleet bug in the sample —
the very event cited as justification for the design.** The lesson generalizes: the breadth default
cannot be set from fan-out counts alone. Each cluster has to be classified before it can calibrate
the threshold.

**Margin is thin, deliberately.** Bot noise at 3 and a real event at 4 are adjacent, so a bot sweep
touching 4+ accounts will grade RED. That is §2.6's accepted cost, and it is the correct direction:
the failure mode is a false RED, which is visible and recoverable, not a hidden outage.

**Caveat on the sample:** four days, 10 fatal lines, and exactly **one** confirmed real event is a
thin basis for a boundary this tight. Re-measure over a longer window — classifying each cluster, not
just counting it — before treating 4 as settled, and re-check after any change to the aggregator or
the host's account count. The knob exists partly so this is tunable per host without touching depth
(its escape-hatch role above).

### 2.5 Prototype results

Validated in scratch against the real default pattern and veto, on **both** BSD awk (macOS) and
gawk — 11/11 identical on each:

| Fixture | Result |
|---|---|
| 17 accounts × 1, `/home` | genuine — **the defect, fixed** |
| 17 accounts × 1, `/home2` and `/home3` | genuine — multi-home covered |
| 17 accounts × 1, all tagged `[php/unknown]` | genuine — sentinel handled |
| 17 accounts × 1, `/home2` + `unknown` | genuine — both at once |
| 17 accounts × 1, `[apache/<host>]` tags | genuine — path fallback works |
| single untagged, no path | **scanner** — depth 1, breadth 1, same as today |
| 4 accounts at `FANOUT=5` | scanner — below breadth threshold |
| 5 accounts at `FANOUT=5` | genuine — threshold reached |
| 1 account × 1 / × 3 | scanner / genuine — **single-account parity** |

### 2.6 What this costs

A sweep spanning ≥ `ERROR_FATAL_FANOUT_ACCOUNTS` accounts with an identical probe-shaped fatal grades
**RED**, including the cds1 docket-cache window that started this work. This is the accepted price
from §1 and it is permanent.

**This is the primary blast radius and must be stated as such**, not buried: RED after this change
means "a cluster we cannot attribute," not "likely outage." Handoff §2 called the defect latent and
narrow; rev 4 pays a permanent semantic cost on every qualifying sweep to close it.

### 2.7 Residual — natural signature variance

Any per-account variance *inside* the message diversifies the normalized signature and defeats
breadth grouping: custom plugin directories, per-site cache paths, DB names like `acct01_wp`
appearing outside `/home/<acct>/`. Those fatals stay scanner-classified. Note this also defeats
today's depth grouping, so it is a pre-existing limit rather than a regression — but it means fan-out
closes the common case, not every case. An attacker deliberately rewriting other tenants' fatal
messages to defeat breadth was rated low-reachability in review.

## 3. Operator evidence

Rev 3 moved the sweep-versus-outage ambiguity from the classifier into the operator's lap without
giving them the means to resolve it. The recap says only "N fatal errors — a service or app may be
down" (`lib/report.sh:526-554`), and the sole evidence channel is up to 25 verbatim fatals in the
body (`lib/errors.sh:350-353`).

So the digest body must **label the cluster**: "17 fatals across 17 accounts (fan-out)" versus "17 on
one account." Cheap, and it is what makes the accepted RED actionable rather than merely loud.

## 4. Error handling

The change adds no I/O, no new state, and no external dependency. The existing fail-closed structure
governs and is untouched:

- Classification producing nothing despite fatals present → all fatals genuine
  (`lib/errors.sh:315-317`). An awk abort on a bad `gsub` lands here — RED-safe.
- `report.sh` unsets `ERR_FATAL_GENUINE` / `ERR_FATAL_SCANNER` before the section runs
  (`lib/report.sh:54-58`) so a dying errors plane falls back to the raw `ERR_FATAL` total via
  `_report_fatal_effective` (`:422`). Preserved.
- Both patterns remain validated against grep **and** awk at config time (`lib/errors.sh:233-262`),
  and `ex` still rides in via `ENVIRON`, not `-v` (pinned by `environ-not-dashv`).

**One trust dependency is new, and rev 3 wrongly denied it.** Breadth promotes the account field of
the `ERROR_DIGEST_LOG` feed from a cosmetic source tag to a **grading input**, while the feed filter
anchors only on the timestamp (`lib/errors.sh:25`). A buggy or hostile aggregator can inflate fan-out
(forged distinct tags → RED) or deflate it (one forged tag with real per-account paths → GREEN). The
§2.2 path fallback mitigates deflation, since the real paths still carry account identity. Document
the feed contract in `RUNBOOK.md`.

## 5. Sequencing — whitespace co-ships, but does not gate cds1

**Not "whitespace first."** Rev 3 said that and it is dangerous *in general*. On a two-space feed the
scanner pattern never matches, so the class is inert and the false GREEN is unreachable:

- Whitespace fix **alone** makes the pattern match and **manufactures** the defect.
- Fan-out **alone** leaves breadth dead on that feed, because eligibility fails earlier at
  `sig ~ re`.

So they land in **one commit** as a general rule. **cds1 specifically is unaffected by this hazard** —
§0.1 measured its feed as one-space, so the mouth is already open there and the fan-out gate delivers
on its own. The whitespace work is therefore correctness-consistency for other hosts and for the live
path, not a gate on shipping the fix to cds1.

The live emit collapses whitespace runs (`lib/errors.sh:39`); the pre-consolidated path (`:22-26`)
does not. Fix the normalization there and add two-space fixtures pinning *both* pattern eligibility
and normalized-signature collapse.

Remaining items, correctly labelled — rev 3 called the first a blocker; it is copy accuracy:

- **Digest copy** (`lib/errors.sh:356`, `lib/report.sh:499`): "bots executing PHP files directly" is
  inaccurate (the cds1 case was bootstrapped) and should also convey that cross-account clusters are
  never filed as scanner noise.
- **Disable docs** (`lib/errors.sh:186-187`, `config/swatter.example.conf`): `0` disables as well as
  `1`, deliberately RED-safe (`:254-260`).
- **Three-copy default invariant**: `ERROR_FATAL_SCANNER` is byte-identical across
  `lib/common.sh:320`, `lib/errors.sh:188`, `config/swatter.example.conf:411`, untested. Prose also
  names it at `lib/common.sh:274`, `config/swatter.example.conf:344`, `:430`.

## 6. Testing

**The existing suite passes unchanged** — every fixture in `test/errors_test.sh` is single-account
(`[php/acct]`, `/home/acct/`), so breadth is 1 and the new conjunct never fires. But note: **a green
`make test` is not evidence the defect is closed**, because no existing test pins multi-account
behavior. The new cases are the only proof.

| Test | Setup | Expect |
|---|---|---|
| `fanout-defect` | 17 accounts × 1 probe-shaped fatal | `GENUINE=17 SCANNER=0` |
| `fanout-multihome` | Same under `/home2` and `/home3` | genuine |
| `fanout-unknown-sentinel` | 17 accounts, all tagged `[php/unknown]`, distinct paths | genuine |
| `fanout-apache-tag` | 17 accounts, `[apache/<host>]` tags, distinct `/home` paths | genuine |
| `fanout-fpm-tag` | `fpm/<ver>:<pool>` tags | genuine via path fallback |
| `fanout-threshold` | Accounts at `FANOUT` exactly | genuine |
| `fanout-below` | `FANOUT - 1` accounts | scanner |
| `fanout-single-untagged` | **One** fatal, no tag, no path | **scanner** (depth 1, breadth 1) |
| `fanout-many-untagged` | Many such fatals | genuine (unique keys → fan-out) |
| `fanout-knob-invalid` | `FANOUT` non-integer, empty | default + warn |
| `fanout-knob-disable` | `FANOUT=0` and `1` | breadth gate off, depth intact |
| `fanout-depth-parity` | Single-account ×1, ×2, ×3 | identical to pre-change |
| `fanout-distinct-sigs` | 17 accounts, different messages | unaffected (residual §2.7) |
| `fanout-veto-interaction` | Cross-account fatals matching the CLI veto | genuine |
| `fanout-subsep` | Log line containing `\034` | accounts not merged |
| `fanout-feed-forged` | Feed with forged distinct tags | genuine (inflation is RED-safe) |
| `two-space-feed` | Two-space fixture | pattern eligibility **and** nsig collapse |
| `body-labels-fanout` | Cross-account cluster | body names the account spread (§3) |

Portability: the normalization must be pinned on both dialects. The prototype ran identically on BSD
awk and gawk; the suite should not assert dialect-specific behavior, per the reasoning at
`lib/errors.sh:217-232`.

## 7. Documentation

`RUNBOOK.md`: a cross-account cluster always reports and why (bot sweep and bad deploy are
indistinguishable from the log); what RED means now (§2.6); the `ERROR_FATAL_FANOUT_ACCOUNTS` escape
hatch; and the `ERROR_DIGEST_LOG` account-field contract (§4).

`config/swatter.example.conf` + `lib/common.sh`: `ERROR_FATAL_FANOUT_ACCOUNTS` with its fail
direction; `ERROR_FATAL_SCANNER_REPEATS` still governs depth only.

`CHANGELOG.md` + version bump. Release notes must say the digest may grade RED on windows that
previously graded GREEN — that is the fix working — and name the new knob as the lever if the rate is
too high for a given host.

## 8. Out of scope

- **Correlating with scored IPs** — abandoned, §1. Do not re-propose; the goal is contradictory.
- **Widening `ERROR_FATAL_SCANNER`** — prohibited by handoff §3, unnecessary here.
- **Hiding cds1's sweep** — deliberately given up, §1 and §2.6.
- **The Docket Cache bug** (handoff §6) — unguarded `substr($_GET['page'], …)` at
  `includes/src/Plugin.php:1462`. Report upstream; do not patch locally.
- **Dropping `page[]` at the WAF** — per the developer-wide rules, Cloudflare zone changes go through
  `~/Developer/terminal-scripts` via the `cf` dispatcher, not this repo.
