# Consolidated adversarial review — rev 2 (2026-08-11)

**Target:** `docs/superpowers/specs/2026-08-11-fatal-scanner-correlation-design.md` (rev 2)
**Prior round:** `…-design-review-grok.md` (rev 1: BL1–BL5, MA1–MA7)
**Reviewers:** `grok-4.5` ×2 (lens mode — one model family on the roster), plus Claude-side
`[code-review]` / `[security-review]` / `[gap]` passes.
**Read-only guard:** `git status --short` identical before and after both passes.

| Pass | Lens | Verdict |
|---|---|---|
| `[pass-a]` | correctness skeptic | **RETHINK** |
| `[pass-b]` | safety / edge-case red-teamer | **EXECUTE-WITH-FIXES** |

The verdicts are inverted from rev 1, and again the split is not factual disagreement: both
raised the same central Blocker at Blocker severity. Pass A concludes the layer needs rethinking;
pass B concludes the layer is right but must not ship until the trade-off is written as doctrine.

**Claude's adjudication: pass A is right, and for a reason neither pass states outright — the
goal itself is incoherent, not merely the mechanism.** See BL-1.

---

## Credit where rev 2 earned it (not reopened)

| Rev 1 finding | Rev 2 status |
|---|---|
| BL1 circular repeat-gate defense | Replaced by §2.2; multi-IP and surplus-5xx hides now fail closed |
| BL2 nearest-5xx latch | **FIXED** — account-level counts, §2.3 miss table, 500–599 stated |
| BL3 ledger holes | **PARTIAL** — allowlist, `since`, watermark named; predicates underspecified (MA-1) |
| BL4 unbounded I/O | **PARTIAL → new defect** — budgets added, but tail bias introduces BL-2 |
| BL5 enum validation | **FIXED** — §3.5, case-sensitive, documented fail direction |
| MA1 test-suite churn | **FIXED** — §8 two-change sequencing |
| MA2 shadow counters | **FIXED** — §5 expanded list |
| MA3 userdomains | **PARTIAL** — `*`/`nobody`, truncate-as-failure, tag authoritative; gaps in MA-4 |
| MA4 wiring | **FIXED** — §7 `bin/swatter:67` ordering, doc surface, shadow must not touch `ERR_*` |
| MA5 store disciplines | **FIXED** — §3.3 empty-stdout, `_store_ip_ok`, `_sql_escape` |
| MA6 `on` gate | **PARTIAL** — four criteria written; unsatisfiable + no detection story (MA-3) |
| MA7 hide-vs-recognize asymmetry | **FIXED (documented)** — §6.4; `MIN_REQS` correction verified at `lib/score.awk:196` |

---

## Blockers

### BL-1 — §2.2's success case and its failure case are the same evidence `[both]`

Confirmed by construction; no code required.

| Scenario | `\|F\|` | `\|X\|` | distinct IPs | scored | §2.2 verdict |
|---|---|---|---|---|---|
| cds1 probe sweep (bot hits `?page[limit]=1`; unguarded `substr` 500s) | 1 | 1 | 1 | yes | SCANNER — **wanted** |
| Fleet bug (bot crawls a normal route; bad deploy 500s) | 1 | 1 | 1 | yes | SCANNER — **real outage** |

Numerically identical. §8's test table demands `SCANNER=17` for row 1, which means it demands it
for row 2 as well. On a quiet shared host — overnight, dormant cPanel accounts, bots still
crawling — row 2 is not an edge case; it is the native habitat of the defect this design exists
to fix. Grade keys on `ERR_FATAL_GENUINE` (`lib/report.sh:422`), so the outcome is fleet GREEN,
"All Clear" (`:484`), and **no SMS** (`ALERT_SMS_GRADES="RED"`, `lib/common.sh:284`).

Rev 2's §2.2 residual paragraph admits only the narrower "fatal was not the 5xx" case. Pass A:
*"It understates the larger residual: any sparse fleet bug whose only 5xx sources are a singleton
scored IP."* Pass B: *"Mislabeling that dual as a 'narrow residual' reintroduces the
false-GREEN class… §6.1 still defends with a wrong claim, which is rev 1's core error in a
smaller costume."*

Both are right, and the conclusion generalizes further than either pass states:

> **Handoff §3 said no regex over the fatal message can separate a sweep from a fleet bug. The
> true statement is stronger: no combination of (fatal, 5xx, client IP, IP reputation) can
> separate them.** Reputation identifies *who* issued the request. The distinguishing fact is
> whether the application would have served a healthy response to that same request — and
> nothing in this data answers that.

**Therefore handoff §4's goal was incoherent, not merely hard.** It asked to keep a sweep GREEN
*and* to reveal a fleet outage. Those are the same observation. Any rule that hides row 1
necessarily hides row 2. No amount of tightening the join changes this, because the join is not
where the missing information is.

This also retroactively vindicates the handoff's rejection of path-normalized counting — but
inverts *why*. The handoff rejected it for producing "a guaranteed false RED on every scanner
sweep." That cost is now revealed to be **unavoidable** if the false GREEN is to be closed at
all. The handoff treated the false RED as a price too high; the review establishes it is the
only currency available.

Resolution is a product decision, escalated to the author (see §Open question).

### BL-2 — Rev 2's own budget fix creates a new false GREEN `[both]` `[gap]`

Found independently by both passes and by the Claude gap pass.

§3.2 specifies `ERROR_FATAL_CORRELATE_MAX_BYTES` as "bytes read per domlog (tail-biased, like
`SEED_BYTES`)" while §3.2 and §4 treat budget exhaustion as "abort → GENUINE." Those are
different things: **a partial read that stays inside the cap is a success, not an abort.** That
is exactly ingest's model (`SEED_BYTES` at `lib/common.sh:48`, tail start at
`lib/ingest.sh:120-121`), which silently drops the head of the file.

Flip path:

1. Busy account; early in the window, multi-IP 5xx (would force `distinct_ips != 1`).
2. Those lines fall outside the tail byte window of a large domlog.
3. Tail holds only late quiet traffic — one scored IP, `|X_tail| == |F|`.
4. Rule → **SCANNER**, i.e. false GREEN manufactured by truncation.

`|F|` is taken from the full error feed and is *not* byte-capped, which usually saves you — but
early **5xx without matching fatals** (503s, proxy blips, neighbour noise) never appear in `|F|`
and would have broken the singleton test had they been retained in `X`.

§4's "partial readability across an account's domains → GENUINE" does not cover "file readable,
only last N bytes indexed."

**Required:** any byte-cap truncation on an account marks `X` incomplete → GENUINE with a reason
counter; or prove completeness (byte range reaches back past `cutoff`, or file ≤ cap).

### BL-3 — Per-account memoized verdict paints mixed-cause fatals `[pass-a]` `[gap]`

§3 memoizes the verdict per account, so every under-`reps`, non-vetoed fatal on that account
inherits one `C`/`-`. Rev 2 credits this with dissolving rev 1's `(account, second)` hazard,
which it does — but it creates account-wide taint.

Counterexample: one bot 5xx **without** a fatal, plus one genuine non-5xx fatal → `|X|=|F|=1`,
singleton scored IP → the genuine fatal grades SCANNER. More generally, a single bad singleton
match hides *all* fatals on that account in the window, including CLI-origin fatals co-mingled
with HTTP ones.

The design never states whether mixed causation is possible or how it would split. At minimum
this widens BL-1's residual well beyond "single fatal."

---

## Majors

- **MA-1 — Unblock watermark is half-specified** `[pass-a]` `[gap]`. §3.3 names the pattern but
  not the predicates. Verified: `swatter_store_unblock` (`lib/store_sqlite.sh:471-477`) records
  via `store_record` and clears only `perm`; it does **not** call
  `swatter_store_sighting_clear` (that runs on the successful-block path, `lib/score.sh:219`).
  The watermark pattern lives on `actions` (`lib/store_sqlite.sh:130-136`), while `sightings`
  (`:43-46`) has no action history. So the design must state three predicates explicitly:
  watermark = `MAX(ts) FROM actions WHERE action='unblock'`; `offenders` needs
  `last_seen > unblock_ts` (the unblock itself refreshes `last_seen` and `MAX(worst_score,0)`
  preserves the score, `:378-387`); `sightings` needs `last_ts > unblock_ts`.

- **MA-2 — `ERROR_FATAL_CORRELATE_WINDOW` is vestigial** `[pass-a]` `[gap]`. Rev 1's rule was
  proximity-based (±5s); rev 2's rule is count-based over the digest window, so the knob has no
  defined semantics yet is still validated (§3.5) and documented (§9). Worse, if an implementer
  invents a meaning and applies a *different* window to `X` than to `F`, `|X| == |F|` becomes
  meaningless and can flip either way. Either delete the knob or pin it to
  `swatter_errors_section`'s cutoff.

- **MA-3 — The `on` gate is unsatisfiable, and there is no post-`on` detection story**
  `[pass-a]` `[pass-b]`. §5 criterion 1 requires observing a sparse multi-account **genuine**
  outage during shadow whose counters show GENUINE. Under BL-1 a *quiet* one grades SCANNER, so
  the gate can only ever be satisfied by busy multi-IP outages — which already fail closed and
  validate nothing about the residual. So the gate either never passes or gets waived under ship
  pressure. And if `on` is wrong in production the failure is silent: SMS carries grade only
  (`lib/alerts.sh:98`), deduped 6h (`ALERT_SMS_DEDUP_HOURS`, `lib/common.sh:286`), with none of
  §4.1's counters — detection degrades to customer tickets.

- **MA-4 — Missing-vs-unreadable domlog matrix undefined** `[pass-b]` `[gap]`. cPanel accounts
  routinely list addon/parked domains with no domlog at all. "Missing = empty contribution"
  undercounts `X` and can manufacture a singleton (unsafe); "missing = hard fail" makes
  multi-domain accounts almost always GENUINE (safe but kills recognition). §3.1/§3.2 never
  choose. Related: a *well-formed but wrong* userdomains map (same domain mapped to two users,
  stale full map, CRLF/whitespace on the username, punycode vs unicode basenames) is not caught
  by the truncated-file rule and is a false-SCANNER oracle.

- **MA-5 — TSV field integrity is not inherited** `[pass-b]` `[security-review]`. §3.3's
  `_store_ip_ok` + `_sql_escape` requirement does cover SQL injection via the joined IP —
  verified. But `_swatter_parse` does not strip tabs/newlines from `path` or `ua`
  (`lib/ingest.sh:70-95`) before emitting tab-separated output (`:97`), and it does not inherit
  the CNTRL stripping used at `lib/score.sh:61-65` or `lib/intel.sh:82-92`. A tab in
  path/UA shifts fields for any consumer reading status by field number. Realistic vector is a
  corrupt or partial line rather than live Apache. Fix at the correlate boundary: reject rows
  whose field count ≠ 8 or whose status is not `^[1-5][0-9][0-9]$`.

- **MA-6 — Unparseable status undercounts `X` in the dangerous direction** `[gap]`. Verified:
  `_swatter_parse` defaults a line with no 3-digit token to `status = "0"`
  (`lib/ingest.sh:75-80`). `0` is not in 500–599, so a malformed line that was really a 500
  silently shrinks `|X|` — the same direction as BL-2. Safe handling is to count
  unknown-status lines as *competing* (inflating `|X|`, biasing to GENUINE), which rev 2 never
  specifies.

- **MA-7 — Operator trust: the worst nights and the broken nights look identical** `[pass-b]`.
  §3.2 intentionally degrades fleet-wide events to RED via budget abort, and chronic
  userdomains/sqlite failures produce the same generic RED on the same SMS channel. §4.1's
  counters live in the email body only. Needs a subject/headline distinction between
  "attribution-failure RED" and "genuine-fatal RED," or infrastructure counters routed off the
  SMS channel.

- **MA-8 — §8 still misses the high-leverage cases** `[pass-a]` `[pass-b]` `[gap]`. Absent:
  quiet multi-account genuine deploy with one scored 5xx per account (the BL-1 shape — and note
  §8's existing "Non-5xx cause → SCANNER" row *pins the residual as desired behavior*, which is
  honest for that case but must not be the only acknowledgement of the dual); tail-truncated
  competing multi-IP 5xx; one domain log unreadable while another would singleton-match; parked
  domain with no log; tab/CNTRL shifting TSV status; mixed-cause fatals on one account;
  `ERROR_DIGEST_LOG` set-but-unreadable (today falls through to live aggregation,
  `lib/errors.sh:22`); window-boundary half-open mismatch; sightings swept mid-digest;
  `SCORE_WATCH` changed between scan and digest.

---

## Minors

- Cross-ref error: §2.2's "subject to §3.5's surviving conditions" should read §3.4 — the
  surviving conditions are `reps` and the exclude veto, not config validation.
- `F` is written as "all fatals on `A`" without saying pre- or post-veto. Pre-veto inflates `|F|`,
  biasing to GENUINE (safe), but it should be stated.
- Two fatals from one request give `|F| > |X|` → GENUINE (safe), worth a line.
- Window inclusivity: the digest feed uses a lexical `substr($0,2,19) >= c` compare
  (`lib/errors.sh:25`), inclusive at the second. The domlog side must use the identical bound or
  boundary fatals lose their 5xx.
- `perm = 1` in §3.3 condition 1 bypasses the `since` filter, so an ancient perm satisfies
  "scored" indefinitely until the unblock watermark applies. Pair with MA-1.
- `SCORE_WATCH` raised between scan and digest → GENUINE (safe); lowered → more hide power. One
  validation warning if they disagree.
- Concurrent scan + digest: 3s busy timeout (`lib/store_sqlite.sh:82`) yields empty → not scored
  → GENUINE. Safe, worth pinning as a race test.
- §0.1's whitespace precondition and §7 remain correct and unaffected by all of the above.

---

## Open question for the author

BL-1 is not a fixable defect in the mechanism; it is a contradiction in the goal. Rev 2 cannot
be repaired into a design that both hides cds1's sweep and reveals a quiet fleet outage, because
those are one observation. The author must choose which of the two to give up — and that choice
determines whether most of rev 2 survives at all. Three coherent positions exist; none revives a
rejected idea:

1. **Give up hiding the sweep.** Close the false GREEN completely and accept that multi-account
   sweeps grade RED, permanently. This is the cheapest and safest, and it makes most of rev 2
   unnecessary.
2. **Give up closing the false GREEN.** Ship rev 2 with BL-2/BL-3/MA-1…MA-8 fixed and write the
   dual as operator-visible doctrine with a non-waivable gate and a real detection story.
3. **Find a third signal** — necessarily a property of the *request* (malformedness), not of the
   client's reputation. A separate design with its own fragility, and the same class of problem
   handoff §3 rejected, relocated.
