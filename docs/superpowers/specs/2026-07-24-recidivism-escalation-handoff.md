# Handoff — recidivism escalation, before the cds1 widening

**Written:** 2026-07-24, at the point where the code is merged to `main` and the
production change has deliberately **not** been made.

Read this before running Phase 4. It exists because the sharpest thing learned in
this work is easy to lose: the tool that gates the production decision was itself
wrong until the final review, and its old output looks perfectly plausible.

---

## 1. Status in one line

All nine plan tasks are merged to `main`. **`REPEAT_WINDOW_DAYS` is still 7
everywhere.** cds1's runtime behavior is unchanged — no config was touched, no
bans were placed or removed, nothing was deployed.

> **Read "nothing was deployed" as "none of *this* work is on the box yet" —
> not as "the ladder is not running."** The temp→perm recidivism ladder itself
> shipped in v1.0.0 and has been running on cds1, in enforce mode, since
> 2026-06-12, placing permanent bans daily on the least safe version of the
> ladder that exists. "Nothing was deployed" refers only to the *unreleased
> improvements* this handoff describes. A later design
> (`2026-07-27-v2.11.0-release-and-cds1-deploy-design.md`, superseded — see
> `-design-v2.md`) read these exact words the other way and inverted its
> entire risk model as a result: it treated *shipping* as the risky act,
> when every day cds1 stays on the pre-fix ladder is a day it bans without the
> fixes below.

## 2. The warning that matters most

> **Any `swatter escalate-preview` output captured before 2026-07-24 is wrong.
> Regenerate it. Do not review a saved list.**

The command used `HAVING c >= REPEAT_N`, but the decider perms at
`prior + 1 >= threshold` — it counts the *pending* offense. The preview was
therefore missing every IP sitting at `REPEAT_N - 1`: precisely the cohort whose
**next** request burst becomes a never-expiring DIRECT ban plus a 7-day,
non-retractable fleet-hub publication.

Verified before the fix: an IP with 2 enforced temps produced an **empty**
preview at `--window 30`, then permed on its next offense. An operator would have
reviewed a clean list and widened.

Fixed in `6ce164a` (`HAVING c >= ${n} - 1`, plus a status column distinguishing
"at/over the bar" from "one offense away"). The `temps` column is the **prior**
count, so a resulting ban's `recidivism=` value reads `temps + 1`.

## 3. Why the widening was not done

The final whole-branch review's closing line was explicit: do not widen
`REPEAT_WINDOW_DAYS` to 30 until the preview off-by-one is fixed **and the
preview is re-run** — the list the decision was going to be made from was missing
exactly the IPs that would be banned first.

The fix has landed. The re-run and the human review have not. That is the gate.

## 4. The two Phase 4 steps that are easy to skip and expensive to skip

Full ordered list is in `TODO.md`; these two carry the risk.

**`monitoring.cidr` is empty on cds1.** `allow.cidr` holds four entries, three of
which are documented customer false positives from a single day (2026-06-10: a
Fatbeam site owner, a Comcast residential owner, a T-Mobile mobile user). That is
direct evidence real customers get caught by scoring. With `monitoring.cidr`
empty, the allowlist is effectively the only thing between a legitimate NAT,
office, VPN, or webhook IP and a permanent ban. Populate it **before** the flip.

**Freeze `SWARM_PUBLISH` for 14 days after the flip.** The hub exposes host-wide
purge only, with a 7-day TTL — there is no per-IP retract. A false ladder-perm
that publishes is out of your hands for a week, and peers may already have acted
on it. Operator decision, 2026-07-24.

## 5. Recovery, and the two things that are not recovery

- **`swatter rollback-ladder --since <ts>`** is the undo. It selects from the
  sqlite ledger (not `decisions.jsonl`, which rotates weekly *with compress*),
  takes the state lock once with a 120s wait so it cannot abort mid-list against
  the `*/5` cron, continues past per-IP backend failures, and exits non-zero if
  any were partial.
- **Reverting the config is not a revert.** Lowering `REPEAT_WINDOW_DAYS` does not
  undo bans already placed, and `offenders.perm` is sticky.
- **A local rollback does not undo off-box propagation.** The command warns about
  the swarm hub, and about AbuseIPDB when `ABUSEIPDB_REPORT=true`. Neither can be
  retracted per-IP.

## 6. What the review rounds found, and why that should raise your confidence

Four adversarial rounds (two Grok passes each on the design, plus per-task
reviews and a final whole-branch pass) found real defects, several in code the
plan itself prescribed. Recorded so a future reader knows where the sharp edges
were:

| Defect | Consequence had it shipped |
|---|---|
| Empty `REPEAT_N` | `(( 1 >= 0 ))` true → **every first offense a permanent ban** |
| `escalate-preview` off-by-one | The widening decision made from a list missing the highest-risk IPs |
| `unblock` left temps counting | An operator's false-positive correction silently undone; next offense jumps to perm |
| `shift 2` on a bare flag | **Infinite hang** in the one command built to be safe on a live host |
| `&&` short-circuit | A failed CSF unblock skipped Cloudflare entirely, leaving the edge rule live |
| Zero-padded values parsed as octal | `REPEAT_N="020"` → escalation at 16, not 20, silently |
| Digest counted non-perm decisions | "2 of those permanent block(s)…" under "permanent blocks: 0" |

Two of these were found only because a reviewer *executed* the code rather than
reading it, and the end-to-end ladder test was added only after two mutations to
its load-bearing lines were shown to pass the entire suite. Treat "the tests are
green" as necessary and not sufficient in this area.

## 7. Open hazards not closed by this work

- Four config knobs still carry the silent-arithmetic hazard — `SCORE_TEMP`,
  `MAX_BLOCKS_PER_RUN`, `WINDOW_SECONDS`, `MIN_REQS`. Under `set -u` a
  non-numeric value can exit the shell mid-scan. Listed in `TODO.md`.
- The CRITICAL-single gate is **inert on flatfile stores** (degrading toward
  *more* banning, not less) and inert for the first `REPEAT_WINDOW_DAYS` after
  deployment on any store, because pre-upgrade temps carry no `rule=` in their
  reason. Production is sqlite; documented in the README.
- `swatter allow` does **not** reset the ladder — only `swatter unblock` does.
  This is the correct operator path for a false positive and is easy to get
  wrong.

## 8. Where everything lives

| Artifact | Path |
|---|---|
| Design + investigation | `docs/superpowers/specs/2026-07-24-recidivism-escalation-design.md` |
| Round-1 review | `…-design-review-grok.md` |
| Round-2 review | `…-design-review-grok-rev2.md` |
| Implementation plan | `docs/superpowers/plans/2026-07-24-recidivism-escalation.md` |
| Remaining work | `TODO.md` |

The plan document contains two snippets that shipped **differently** from what it
prescribes (the validation block predates the `10#` octal fix; the dispatch
registration shape is non-functional). Both are annotated in place. The shipped
code is authoritative — do not re-execute those blocks verbatim.

The per-task SDD workspace (briefs, implementer reports, review packages,
progress ledger) was deleted on completion by design; the commit messages and the
documents above are the record.

## 9. No release was cut

`CHANGELOG.md` has an `[Unreleased]` section. `SWATTER_VERSION` is unchanged and
no tag was pushed — publishing a release is a separate, deliberate step (gap
analysis → version bump → tag → GitHub/GitLab release).
