# Grok adversarial review — scanner-fatal veto

**Target:** `2499882` (`fix(errors): local CLI fatals can never be scanner-induced`)
and `f2838c5` (changelog). **Date:** 2026-07-30. **Model:** `grok-4.5`.
**Invocation:** `grok -p <brief> --always-approve --sandbox read-only --max-turns 40`
(working tree verified clean before and after).

**VERDICT: SHIP** — no Blockers. Four Majors, all documentation/comment
correctness; the mechanism itself (CLI veto, `ENVIRON` plumbing, dual-dialect
validation) was probed and held.

This review replaces the unpersisted pass noted in
`docs/handoff-2026-07-30-scanner-veto.md` §2. An earlier review did run and
returned SHIP with two Majors folded in before commit (awk-side validation,
narrowing the over-broad `phar://`), but its transcript was not captured. This
one is the record.

## Disposition

### Folded in before the v2.12.0 cut

| # | Finding | Action |
|---|---------|--------|
| **M1** | Docs claimed a bot-induced bare `phar://` fatal "belongs in the genuine count on its own merits". It does not — under default knobs a one-off counts **scanner**. `test/errors_test.sh` already said this correctly; the prose in four other places did not. | Corrected in `lib/errors.sh`, `config/swatter.example.conf`, `CHANGELOG.md`, and this handoff. |
| **M4** | `lib/errors.sh` apply-path comment still described the pre-fix world ("validated with grep -E but applied by awk"), i.e. claimed a gap the commit closed. | Rewritten to describe the guard as defense-in-depth, with a pointer to the new `environ-not-dashv` test. |
| **m6** | Same block said a local CLI entrypoint means "wp-cli.phar, **a phar:// path**", implying any phar path proves local — contradicting the deliberately non-bare default 10 lines below. | Narrowed to "wp-cli.phar under /usr/local/bin". |
| **M3** (partial) | The invalid/empty fallback trade-off was undocumented. | Trade-off now stated explicitly in both `lib/errors.sh` and the example conf: fallback is the shipping default, which is the *middle* of three behaviours. |
| **m5** (partial) | No test failed if someone switched the apply path from `ENVIRON` to `-v` — the detail the handoff calls load-bearing. | Added `environ-not-dashv` / `environ-not-genuine`: a `wp-cliXphar` signature stays scanner under `ENVIRON` and would be wrongly forced genuine under `-v`. `errors_test.sh` 38 → 40. |
| **m5** (partial) | `config_defaults_test.sh` never asserted the new key's default. | Added `fatal-veto-set` and `fatal-veto-default`. |

### Declined, with reasons

| # | Finding | Why declined |
|---|---------|--------------|
| **M3** (prescription) | Recommends invalid/empty veto fall back to `'^$'` "under the stated RED-safe bias". | **Self-contradictory.** The same finding correctly establishes that empty is the RED-*heaviest* outcome and the default is the middle — which makes `'^$'` (veto nothing) the *least* RED-safe of the three, not the safest. Falling back to `'^$'` would push CLI-tooling fatals back into the scanner class, which is the exact bug this change exists to fix. Keeping the shipping default; the trade-off is now documented instead. |
| **M2** | Unanchored `wp-cli\.phar` lets an attacker who can drop a file by that name under a docroot force a false RED. | Real, and Grok confirms the direction is safe — the veto can only move fatals *toward* genuine, never hide one. Tightening the pattern would cost the coverage in m7 and is a default-behaviour change that deserves its own measured decision, not one made mid-soak. Recorded as a known false-RED surface in the example conf. |
| **m7** | Default misses `/usr/bin/wp`, `/usr/local/bin/wp`, and composer-layout wp-cli. | Same reasoning. The motivating incident's path (`phar:///usr/local/bin/wp-cli.phar/…`) is covered; broadening to bare `/usr/local/bin/wp` widens the false-RED surface M2 already flags. Left as documented residual. |
| **m1** | `_errors_regex_ok` "oversells" completeness — not re-proven against mawk/busybox awk. | Accepted as accurate but not actionable here: cPanel/AlmaLinux ship gawk, and the probe demonstrably catches the real footguns (`$^`, `(?i)x`, unclosed `[`). Not claiming more than that. |

`m2`, `m3`, `m4`, `m8` were confirmations, not defects — the `ENVIRON` claim holds
and is load-bearing, operator precedence is correct, whitespace handling is fine,
and the version bump is MINOR (2.12.0), which matches the cut.

---

## Full review transcript

# Adversarial review: scanner-fatal veto (`2499882`, `f2838c5`)

Tests: `test/errors_test.sh` → **38/38 pass**. Claims checked against code and local `awk`/`grep` probes.

---

## Blockers

**None.** The motivating case (CLI `wp-cli.phar` fatals under the repeat gate) is classified genuine; the apply path uses `ENVIRON`; dual-dialect validation rejects `$^` / `(?i)x`. Nothing here *hides* an outage relative to pre-change behavior for non-CLI fatals.

---

## Majors

### M1 — Product docs claim bot `phar://` fatals land in the **genuine** count; code + test put the fixture in **scanner**

Evidence:

| Source | Claim / behavior |
|--------|------------------|
| `CHANGELOG.md:16-18` | “belongs in the **genuine** count on its own merits” |
| `config/swatter.example.conf:404-407` | same |
| `lib/errors.sh:200-203` | same |
| `docs/handoff-2026-07-30-scanner-veto.md:33-36` | same, cites `veto-bare-phar` |
| `test/errors_test.sh:148-154` | PHARBOT → `check veto-bare-phar "$ERR_FATAL_SCANNER" "1"` |

**Failure scenario (operator model, not runtime bug):**  
Input: one-off  
`Call to undefined function x() in phar:///home/…/evil.phar/payload.php:3`  
Outcome under default knobs: **scanner-induced**, `ERR_FATAL_GENUINE=0` → **no RED**, no SMS (`lib/report.sh:422`, `:479-482`).  
Docs say “security event … genuine count.” An operator who deploys on that reading will expect a page and will not get one for this shape. Real `PharException` / non-scanner-pattern fatals still go genuine; the written claim is still false for the documented fixture.

The *code* intent (“do not force these genuine via an over-broad veto”) is fine. The *wording* is not.

---

### M2 — Default veto is an unanchored substring; attacker-influenced signature content can force **false RED**, not suppress an event

Default (`lib/errors.sh:204`, `lib/common.sh:313`):

```text
phar:///usr/local/bin/|/usr/local/bin/wp-cli|wp-cli\.phar
```

Signature = full post-timestamp line (`lib/errors.sh:290-294`), so path, constant name, and message text all count.

Verified classifications:

| Signature fragment | Class |
|--------------------|-------|
| `… in /home/x/public_html/wp-cli.phar:1` | **G** |
| `Undefined constant "wp-cli.phar" in …/shell.php:3` | **G** |
| `… in /home/x/public_html/evil.phar:1` | **S** (bare `phar://` not vetoed — correct) |

**Failure scenario:** Bot or dropper executes `/home/acct/public_html/wp-cli.phar` once with `Call to undefined function …`. Matches `ERROR_FATAL_SCANNER`, count &lt; 3, matches `wp-cli\.phar` → **genuine** → RED + SMS if enabled.

Direction relative to RED-safety: **elevates** noise; it does **not** hide a security event. The review prompt’s “veto suppresses a genuine security event” is **false for this code** — `!~ ex` only removes **S**, never **G** (`lib/errors.sh:294`). Taxonomy is wrong (outage vs bot), paging can cry wolf.

Hardness: path is free if the attacker can write a file name; constant/function names are harder (identifier rules) but dynamic `constant("…")` / odd eval shapes can put the substring in the message. No test covers the `public_html/wp-cli.phar` false-RED case.

---

### M3 — Invalid/empty **exclude** fallback to the **matching default** conflicts with the project’s “never hide breakage” bias

`lib/errors.sh:229-234`: empty or invalid `ERROR_FATAL_SCANNER_EXCLUDE` → `_ERR_FATAL_SCANNER_EXCLUDE_DEFAULT` (active veto).

Facts:

- Empty exclude at apply time: `sig !~ ""` is false for all lines → **everything G** (probed). That is *more* RED-safe than the default.
- Empty is rejected and replaced by the default, which **re-enables** scanner classification for non-CLI shapes.
- Invalid custom broader veto (typo) → default → host-specific CLI paths may fall back into **S** (hides *that* box’s tooling breakage).
- Invalid disable attempt `$^` → default veto (not `^$`) — dialect tests pin this; RED-heavier for CLI, surprising for “I tried to disable.”

For `ERROR_FATAL_SCANNER`, fallback-to-default is RED-safe (empty classifier would mark almost everything **S**). For the **veto**, empty is the RED-heavy extreme; falling back to a positive-match default is the **ops** choice (preserve scanner class), not the pure RED-safe choice. Comment at `195-198` treats “veto every classification” as a failure mode — that is cry-wolf avoidance, not “never hide an attack.”

Safer invalid path under stated bias: invalid/empty exclude → `'^$'` (veto nothing) + warn; keep the built-in default only as the *shipping* default when unset at install. At minimum, empty and invalid should not share one fallback story without saying the RED trade-off out loud in `config/swatter.example.conf`.

---

### M4 — Stale apply-path comment still describes pre-fix validation

`lib/errors.sh:279-281` still says the pattern is “validated with **grep -E** but applied by awk.” Dual validation is in `_errors_regex_ok` (`215-219`, `225-234`). The empty-`marked` guard remains useful as defense-in-depth (runtime override without re-validate), but the comment claims a gap the commit message says is closed. Next maintainer may “re-fix” the dialect problem or remove ENVIRON carelessly.

---

## Minors

### m1 — `_errors_regex_ok` is good enough for syntax aborts, not a full soundness proof

`lib/errors.sh:215-219`:

```bash
printf '' | grep -Eq "$1" 2>/dev/null || rc=$?
(( rc == 2 )) && return 1
SWATTER_RE_CHK="$1" awk 'BEGIN { r = ("x" ~ ENVIRON["SWATTER_RE_CHK"]) }' </dev/null 2>/dev/null
```

| Claim | Verdict |
|-------|---------|
| Catches `$^`, `(?i)x`, unclosed `[`, `**` on this host’s awk | **Yes** (exit 2) |
| Subject `"x"` vs real signatures for *syntax* errors | **OK** (compile-time) |
| `grep` rc 2 = invalid ERE | **Reliable** on GNU and BSD for syntax errors; 0=match, 1=no match; other rcs rare on `printf ''` |
| Non-zero after awk regex error | **Yes** here (nawk/gawk exit 2). Not re-proven for mawk/busybox; cPanel/Alma usually gawk |
| Pattern that passes probe and still aborts apply | No solid syntax example; semantic dialect drift without abort is still possible and undetected |
| Return code | awk failure returns **2**, not 1; works with `!` but is inconsistent |
| Trailing `\` | Can exit 0 on this awk — not a realistic operator pattern |

Net: closes the real `$^` footgun; oversells “validated against awk” as complete.

---

### m2 — `ENVIRON` vs `-v` claim is **true** and load-bearing

Probed with the real default:

- `-v re='…wp-cli\.phar'`: backslash eaten → `.` is “any char” → `wp-cliXphar` matches.
- `ENVIRON`: literal `\.` → `wp-cliXphar` does not match.

Apply path uses `ENVIRON` for both RE and EX (`287-292`). Probe matches apply (`219`). Claim **holds**. No test fails if someone “simplifies” the probe to `-v`.

---

### m3 — Operator precedence of the combined condition is fine

`(sig ~ re && cnt < reps && sig !~ ex)` — all `&&`, left-assoc. Veto cannot be short-circuited incorrectly. Precedence test: re=ex=match → all **G**.

---

### m4 — Whitespace handling is OK; not a footgun for space-containing patterns

`${VAR//[[:space:]]/}` is only the emptiness check (`222`, `229`). Patterns with internal spaces are kept. Whitespace-only → treated empty → default. Fine.

---

### m5 — Test quality: pins the real behavior; overclaims in comments/docs

| Assertion | Pins? |
|-----------|--------|
| `cli-veto-*` | Yes — CLI shape → genuine, listed under FATAL verbatim |
| `cli-veto-off` with `^$` | Yes — disable recipe |
| `xdialect-$^` / `(?i)x` | Yes — dual validation |
| `veto-not-greedy` | Yes — normal bots stay **S** |
| `veto-bare-phar` | Pins **not vetoed → S**, **not** “genuine on merits.” Name is OK; surrounding prose is wrong (M1) |
| Attacker `…/wp-cli.phar` | **Missing** |
| ENVIRON vs `-v` regression | **Missing** |
| `config_defaults_test.sh` | Still no assert for `ERROR_FATAL_SCANNER_EXCLUDE` default (`32-33` only scanner + reps) |

---

### m6 — Config/docs agreement on keys and `^$` vs `$^`

- Defaults match across `lib/common.sh:313`, `lib/errors.sh:204`, `config/swatter.example.conf:412`.
- Disable value is **`^$`** in common, example conf, comments, tests, handoff — **no** place recommends `$^` as disable; `$^` is correctly called out as illegal for awk.
- Drift is the **genuine vs scanner** story for bare `phar://` (M1), not the disable recipe.

`lib/errors.sh:192` still says “wp-cli.phar, **a phar:// path**” as if any phar path proved local CLI; the default deliberately does not treat bare `phar://` that way.

---

### m7 — Default coverage gaps for real WP-CLI layouts

Still classified **S** (scanner) under default exclude:

- `/usr/bin/wp`, `/usr/local/bin/wp` (no `wp-cli` substring)
- `vendor/wp-cli/wp-cli/php/wp-cli.php` (composer)

Motivating `phar:///usr/local/bin/wp-cli.phar/…` is covered. Other installs can still hide tooling fatals as bot noise.

---

### m8 — Version: this is **MINOR**, not PATCH; not bumped yet

- New user-facing key + behavior change (CLI fatals → genuine/RED).
- Semver: **2.12.0** (handoff already says this).
- `bin/swatter` still `SWATTER_VERSION="2.11.0"`; notes under `[Unreleased]` — correct until release, but do not ship as 2.11.x PATCH.

---

## Claim-by-claim

| Claim | Result |
|-------|--------|
| Veto: match → never scanner | **True** (`294`) |
| Not bare `phar://` | **True** for pattern; **false** for “then genuine” (M1) |
| Dual grep+awk validation | **True**; soundness limited (m1) |
| ENVIRON not `-v` | **True**, load-bearing (m2) |
| Disable is `^$` not `$^` | **True**, consistent |
| Attacker can “suppress” via veto | **False** — veto only forces **G** |
| Attacker can force false RED via `wp-cli.phar` in signature | **True** (M2) |

---

## Operational risk (live host, RED → SMS)

- Veto **increases** `ERR_FATAL_GENUINE` for matching CLI lines → more RED, more SMS if `ALERT_SMS_*` on.
- Intentional for broken `wp eval`; handoff says that bug is already fixed, so first night may be quiet.
- Residual: any remaining cron/maintenance fatals under the default path strings will page; unanchored `wp-cli\.phar` can false-page (M2).
- Invalid operator exclude does not void classification anymore (improvement); mis-set `$^` re-enables default veto instead of disabling (surprising, RED-heavier for CLI).

---

## Inconsistencies in touched `lib/errors.sh`

1. Dual-validation block (`206-214`) vs stale apply comment (`279-281`).
2. “a phar:// path” (`192`) vs deliberately non-bare default (`200-204`).
3. “genuine count on its own merits” (`200-203`) vs `veto-bare-phar` expecting **S**.

---

## VERDICT: **SHIP**

Ship the mechanism (CLI veto + ENVIRON + dual-dialect gate). Before release notes / operator-facing deploy: fix M1 wording, decide M3 fallback story in the conf comment, and treat unanchored `wp-cli\.phar` (M2) as a known false-RED surface or tighten it (e.g. require path-like context). Cut **2.12.0**, not a patch on 2.11.
