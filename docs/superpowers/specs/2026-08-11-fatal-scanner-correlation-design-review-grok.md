# Consolidated adversarial review — fatal-scanner-correlation design (2026-08-11)

**Target:** `docs/superpowers/specs/2026-08-11-fatal-scanner-correlation-design.md`
**Reviewers:** `grok-4.5` ×2 (lens mode — only one model family on the roster), plus
Claude-side `[code-review]` / `[security-review]` / `[gap]` passes.
**Read-only guard:** `git status --short` identical before and after both passes.

| Pass | Lens | Verdict |
|---|---|---|
| `[pass-a]` | correctness skeptic | **EXECUTE-WITH-FIXES** |
| `[pass-b]` | safety / edge-case red-teamer | **RETHINK** |

The verdict split is itself signal, and it is not a disagreement about facts — both passes
raised the same central Blocker and rated it Blocker. They differ only on whether the rest of
the design survives it. Claude's adjudication: **pass B is right that the design as written
must not be executed**, because the Blocker invalidates the design's stated primary defense
rather than merely adding work.

Every code claim in both passes was verified at file:line. No hallucinated references found in
either pass.

---

## Blockers

### BL1 — Replacing the regex reopens the false-GREEN class handoff §3 closed `[both]` `[gap]`

Confirmed and **accepted**. This is the finding that sends the design back.

The design's §2.1 removes `sigof[i] ~ re` from the decision at `lib/errors.sh:314`. That regex
was not merely a weak proxy — it was the **mouth-limiter**. Handoff §2 says so explicitly:
the defect is "a latent hole with a narrow mouth" and "it silently widens the moment anyone
broadens the pattern." The design widens it maximally (every fatal shape becomes eligible) and
substitutes an evidence gate that ordinary, continuous background scanner traffic can satisfy.

Pass B's framing is exact: *"This design does the same widening by a different gate."*

Newly reachable false-GREEN shapes, none exotic:

| Scenario | Why it grades GREEN |
|---|---|
| Fleet botched deploy, 1 fatal/account, bot-heavy traffic | per-account `cnt=1`; nearest 5xx is often a scored bot |
| First 1–2 OOM / "too many connections" fatals | shape never matched the old pattern; now hideable |
| Scored CGNAT/VPN IP, real customer hits a real bug once | design §6.2 admits it; repeat gate inert at `cnt<3` |

**The design's §6.1 defense is circular, and this is the core error.** §6.1 item 2 calls the
repeat gate "the primary defense" because a real bug "fires on every page view, crosses
`reps`, and grades genuine." But the defect being fixed *is* the sparse case — signatures are
per-account (`lib/errors.sh:310-311`), so cross-account fan-out never accumulates. The gate is
inert exactly where the residual risk lives. Both passes constructed real outages that never
cross `reps`: sparse fleet deploy, intermittent race/flaky OOM, low-traffic endpoint, and one
logical bug spread across several file:line signatures.

Severity is set by `ALERT_SMS_GRADES="RED"` (`lib/common.sh:284`) and
`_report_fatal_effective` (`lib/report.sh:422`): a false GREEN suppresses the operator's SMS
and prints "All Clear" (`lib/report.sh:484`).

**Resolution required before any code.** Options are laid out for the author's decision; this
review does not pick one. Neither rejected idea (regex widening, path-normalized counting) is
revived by any of them.

### BL2 — "Nearest 5xx" is not a same-request join; the non-5xx miss class is unnamed `[both]`

Confirmed. The design §1.2 calls the join "near-exact." It is not, and the gap is not merely
cosmetic: when the fatal's own request is **not** a 5xx, "temporally nearest 5xx within ±5s"
latches onto a stranger's 5xx — often a scored bot's.

Cases where a PHP fatal does not produce a matching 5xx line in the searched log:

| Case | Domlog line | Outcome | Safe? |
|---|---|---|---|
| Fatal after headers/output flushed | often **200** | nearest *other* 5xx may win | **NO** |
| `ignore_user_abort` / client gone | depends what was sent | same | **NO if non-5xx** |
| Output buffering off / early echo | often 200 | same | **NO** |
| CLI / system cron | no HTTP line | no 5xx → GENUINE | yes |
| WP-Cron loopback | 5xx from `127.0.0.1` | unscored → GENUINE | yes |
| Internal redirect / subrequest | final status ≠ worker's | miss or wrong | mixed |
| Vhost only in `ACCESS_LOG` (`lib/common.sh:45`) | design searches per-domain only (§3.2) | GENUINE | yes |

The design's §4 says "no 5xx in window → GENUINE," which is correct but insufficient: it never
says *do not treat an unrelated 5xx as the causing request when the causing request cannot be
identified.* That is the actual rule needed.

Also unspecified: whether the join accepts all `5xx` or only `500`. A 502/503 from a health
check or another client can steal "nearest."

### BL3 — Ledger reputation is wrong in three specific ways `[both]` `[security-review]`

All three verified in code.

1. **Unblock residue.** `swatter_store_unblock` (`lib/store_sqlite.sh:471-477`) calls
   `swatter_store_record … 0 …`, which upserts `offenders` with
   `worst_score=MAX(worst_score,0)` — unchanged — and refreshes `last_seen`; only `perm` is
   cleared. So an IP an operator **deliberately forgave** still reads scanner-shaped under
   design §3.4. A false-SCANNER path created by operator mercy.
2. **`since` is never defined.** The design says `since` must not reach past
   `PERSIST_WINDOW_DAYS` but never says what it is — report window, persist window, or fatal
   epoch − ε. Implementer roulette on a security-relevant bound.
3. **Allowlisted / exempt IPs are not consulted.** The exempt path audits and returns without
   blocking (`lib/score.sh:142-144`), but historical `offenders` / `sightings` rows persist.
   Design §3.4 never consults the allowlist, so an exempted IP can still be "scored."

Coverage holes the design also does not name: `PERSIST_ENABLE=false` (watch band writes
nothing), and `skipped-cap` / backend-fail / `skipped-config` / `skipped-novhost` paths (no
`store_record`, no sighting).

**Plus a factual error in the design.** §1.1 claims *"One request per account is exactly the
shape that is filtered out"* by `MIN_REQS`. **False** — `MIN_REQS` at `lib/score.awk:196` is a
per-IP request total, not per account. cds1's shape (one IP × N accounts × 1 request) is
`n=N`; for N≥15 it *clears* `MIN_REQS=15`. The `top_vhost` singularity argument
(`lib/score.awk:284`) still kills ledger-as-account-index, but the blanket "light probes never
reach the ledger" is overstated and must be corrected.

### BL4 — Digest-time cost is unbounded `[pass-a]` `[pass-b]`

Verified. Design §3.2 claims cost "scales with fatal-bearing accounts, not fleet size." On a
**fleet-wide** fatal — the very case being fixed — fatal-bearing accounts ≈ fleet size. Each
account fans out to many domains via `/etc/userdomains`, each with `_log` and `-ssl_log`.

The design correctly forbids `_swatter_read_file`, but that is exactly where ingest's caps
live: `SEED_BYTES` and `MAX_BYTES_PER_FILE` (`lib/ingest.sh:120-135`). So the design inherits
`_swatter_parse`'s safety on cursors while losing all byte bounds, and §3.5's cap-on-fatals
does not bound **index-build I/O**. A huge or symlinked domlog is a cost-DoS on the nightly
path.

Needs a hard budget: max files, max bytes per file, max accounts, early abort → remaining
fatals GENUINE with a reason counter.

### BL5 — `ERROR_FATAL_CORRELATE` has no validation or fail direction `[pass-b]`

Verified against the house pattern. Every neighbouring knob is validated with an explicit
fail direction and pinned by tests: empty/invalid regex → built-in default with a warn
(`lib/errors.sh:239-252`), non-numeric `REPEATS` → 3 (`:256-260`), `0`/`1` deliberately kept
as RED-safe (`:254-255`), tests at `test/errors_test.sh:79-98,170-177`.

The design introduces a three-valued enum with none of that. `ERROR_FATAL_CORRELATE=onn`,
`ON`, or `""` is unspecified — and empty silently meaning `on` would be the worst outcome.

---

## Majors

- **MA1 — The existing test suite encodes the model being replaced** `[gap]` `[pass-a]`
  `[pass-b]`. Independently found by the Claude gap pass and both Grok passes. Every
  scanner-class assertion in `test/errors_test.sh` uses an `ERROR_DIGEST_LOG` fixture with **no
  domlogs and no ledger**, so under `on` mode correlation fails closed and each inverts:
  `oneoff-genuine 0 → 2` (`:36-38`), `tune-scanner 2 → 0` (`:58`), `mixed-scanner 1 → 0`
  (`:68`), and the veto cases at `:139+`. The design's §8 adds a 14-row table and never
  mentions rewriting ~half a 236-line suite. This is a scope-honesty failure, and it suggests
  the correct sequencing: ship `shadow` with the suite intact plus new shadow-counter tests,
  and make the `on` flip a separate change that rewrites the suite.

- **MA2 — Shadow counters cannot answer the question §5 says they answer** `[pass-a]`
  `[pass-b]`. The counters conflate below-watch with never-seen, and omit unblock residue,
  budget skips, userdomains-failure vs empty mapping, and the non-5xx miss class. §5's stated
  purpose — deciding whether ledger-only reputation suffices — is unreachable with them.

- **MA3 — `/etc/userdomains` parsing rules unstated** `[pass-b]` `[pass-a]`. Real format is
  `domain.tld: username` plus a `*: nobody` line. Must-specify: ignore `*`/`nobody`; treat a
  truncated-but-readable file as failure rather than a partial map (a stale map pointing at
  another account's domains is a false-SCANNER oracle); and treat the fatal's own
  `[php/<acct>]` tag as authoritative for identity, with userdomains supplying only that
  account's domain list. Customer-controlled addon/subdomains affect only their own account's
  correlation — limited blast radius. File is typically `0644` root-owned, so no new privilege
  boundary given Swatter already reads logs as root.

- **MA4 — Consumers and wiring the design omits** `[pass-a]` `[gap]`. `lib/correlate.sh` must
  be added to the fixed source list at `bin/swatter:67`, and ordering matters because
  `_errors_validate_fatal_scanner` executes at source time (`lib/errors.sh:262`). Copy/doc
  surface is larger than §7's "three copies": value at `lib/common.sh:320`,
  `lib/errors.sh:188`, `config/swatter.example.conf:411`, plus prose at `lib/common.sh:274`,
  `config/swatter.example.conf:344`, `:430`, `lib/report.sh:499`, `lib/errors.sh:356`. The
  recap arithmetic at `lib/report.sh:490` (`enf = e - fsc - f`) keys on `ERR_FATAL_SCANNER`, so
  shadow mode must not touch those globals.

- **MA5 — The store accessor must copy two existing house disciplines** `[security-review]`
  `[pass-b]`. Empty stdout from `_sqlq` on a lock timeout must not read as a value — the
  pattern to copy is `swatter_store_has_enforced_perm` (`lib/store_sqlite.sh:334-347`), which
  requires `[[ "$n" =~ ^[0-9]+$ ]]` for exactly this reason (3s busy timeout at `:82`). And the
  joined IP is log-derived, so it must pass `_store_ip_ok` (`:124-128`) and `_sql_escape`
  before reaching any query.

- **MA6 — The `on` flip is the real one-way door** `[pass-a]` `[pass-b]`. No schema migration,
  so rollback strands no data — good. But once operators trust GREEN again, the semantic change
  is operationally irreversible. The flip must be gated on shadow evidence as a hard ship
  criterion, including having actually observed a sparse multi-account genuine outage during
  the shadow window. A quiet shadow week proves nothing.

- **MA7 — Asymmetry between hiding and recognizing** `[pass-b]`. Because §10 defers lowering
  the floors, a light cds1-style probe may *still* grade GENUINE under `on` (original pain
  unfixed) while heavier already-scored IPs gain power to hide *any* sparse fatal. The design
  is stronger at hiding than at recognizing — the opposite of the intent.

---

## Minors

- §1.2's "near-exact join" should read "heuristic nearest-5xx join," or implementers will
  under-defend it.
- `perm=1` as scanner-shaped is coarse (an old perm for an unrelated offense class); pair with
  the BL3 unblock fix.
- `ERROR_FATAL_SCANNER` becomes dead for grading under `on` while still validated — document
  it as shadow/off-only so nobody "tunes" a no-op. Note this makes §7's proposed three-copy
  invariant test partly moot, an internal inconsistency in the design.
- Domlog `-f`/`-r` guards: a FIFO or symlink is an availability risk (digest hang), not a
  false GREEN, but must be named.
- Memoizing by `(account, second)` (§3.5) can copy one fatal's verdict onto a different
  concurrent fatal in the same second.
- `SWATTER_MODE=report` (dry-run) still writes `offenders` (`lib/score.sh:220-221`), so
  reputation works in report mode; worth one line so nobody special-cases it.
- Both passes independently confirm the design's line references are accurate and that the
  handoff's `:363` was stale (correct is `lib/errors.sh:356`).
- Whitespace asymmetry (§7) confirmed as a genuine blocker by both passes, and verified
  empirically: identical 17-account fixture grades `SCANNER=17` with one space and
  `GENUINE=17` with two. Note detection of `[FATAL]` does **not** depend on spacing
  (`lib/errors.sh:288`) — the dependency is signature collapse and `cnt`, which survives regex
  removal, so the fix is still required under every option.

---

## Claude's adjudication

Accepted in full: BL1–BL5, MA1–MA7, and all Minors. Nothing declined — both passes were
accurate on every verified claim, and BL1 identifies a genuine error in the design's reasoning
(a circular defense) rather than merely an omission.

**BL1 is escalated to the author as an open question** rather than resolved here, because it
invalidates a design decision that was explicitly chosen ("replace the regex, stage the
rollout") and any replacement changes the product rule about what may be hidden. Per the
authority model, that ratification is not Claude's to make.

The direction endorsed by handoff §4 — correlate with scored IPs, fail closed to GENUINE, no
regex widening, no path-normalized counting, shadow first — is still the right layer. What
must change is the *mouth-limiter*: correlation cannot be allowed to hide arbitrary sparse
fatal shapes on the strength of proximity to a scored IP.
