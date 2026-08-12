# Fan-Out-Aware Fatal Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a fleet-wide PHP fatal from grading GREEN by making the fatal classifier's gate count breadth (one signature across many accounts) as well as depth (repeats of one signature).

**Architecture:** One conjunct is added to the existing single-pass awk in `swatter_errors_section`. Alongside today's raw signature it computes an account-normalized signature and a per-account key, counts distinct accounts per normalized signature, and requires that count to be under a new threshold for a fatal to be filed scanner-induced. Adding a conjunct can only shrink the scanner class, so the change can only move fatals toward genuine/RED.

**Tech Stack:** bash 4+, POSIX awk (must work identically on BSD awk/macOS and gawk/CI), sqlite3 not involved, existing `test/errors_test.sh` harness.

**Spec:** `docs/superpowers/specs/2026-08-11-fatal-scanner-correlation-design.md` (rev 4)
**Reviews:** `…-review-grok.md`, `…-review-grok-rev2.md`, `…-review-grok-rev3.md`
**Branch:** `docs/fatal-classifier-fanout-design` (already holds the spec commits)

## Global Constraints

- **Depth stays keyed on the RAW signature, and `re`/`ex` keep matching the RAW signature.** Only breadth uses the normalized signature. Rekeying `cnt` onto the normalized signature voids the safety proof (spec §2.1).
- **Regex patterns stay hardcoded in the awk program or arrive via `ENVIRON`, never via `-v`.** `-v` escape-processes backslashes; pinned by `environ-not-dashv` in `test/errors_test.sh`. Numeric knobs via `-v` are fine.
- **Must behave identically under BSD awk (macOS) and gawk.** No gawk-only features: no three-argument `match()`, no `gensub()`, no character classes inside bracket expressions that BSD awk rejects.
- **Never clamp a threshold upward.** The RED-safe direction is low (`lib/errors.sh:254-260`).
- **`ERROR_FATAL_SCANNER` is not modified.** Not widened, not removed. Its value must stay byte-identical across `lib/common.sh:320`, `lib/errors.sh:188`, `config/swatter.example.conf:411`.
- **Task order is load-bearing.** The fan-out gate (Task 2) must land *before* the whitespace fix (Task 4). On a two-space feed the scanner pattern never matches, so fixing whitespace first would open the mouth with no breadth gate in place and manufacture the defect (spec §5).
- **New knob default:** `ERROR_FATAL_FANOUT_ACCOUNTS=4`, measured from cds1 (spec §0.1/§0.2/§2.4).
- **Public repo:** commits must use the noreply git identity (already configured; `peaceharbor.identityGuard=strict`).
- Run `make test` before every commit. Every existing test must keep passing unchanged.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `lib/common.sh` | Ship the `ERROR_FATAL_FANOUT_ACCOUNTS` default; fix prose naming `ERROR_FATAL_SCANNER` as sole classifier | 1, 5 |
| `lib/errors.sh` | Validate the knob; the gate change; the digest-body fan-out label; digest-feed whitespace normalization; copy + disable-docs fixes | 1, 2, 3, 4, 5 |
| `config/swatter.example.conf` | Document the new knob and its fail direction; prose fixes | 1, 5 |
| `lib/report.sh` | Fix the "bots executing PHP files directly" copy at `:499` | 5 |
| `test/errors_test.sh` | All new tests, appended in the file's existing style | 1, 2, 3, 4 |
| `docs/RUNBOOK.md` | What RED means now; the escape hatch; the feed contract | 5 |
| `CHANGELOG.md` | Release entry + version bump | 5 |

No new files. The spec's earlier revisions proposed `lib/correlate.sh`; rev 4 abandoned that direction (spec §1).

---

### Task 1: The `ERROR_FATAL_FANOUT_ACCOUNTS` knob and its validation

Ships the config surface with its fail direction, before anything consumes it. Reviewable alone: a new default, a validation branch, and tests pinning invalid input.

**Files:**
- Modify: `lib/common.sh` (near `ERROR_FATAL_SCANNER_REPEATS=3` at `:321`)
- Modify: `lib/errors.sh` (`_errors_validate_fatal_scanner`, `:239-261`)
- Modify: `config/swatter.example.conf` (near `ERROR_FATAL_SCANNER_REPEATS=3` at `:412`)
- Test: `test/errors_test.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: shell variable `ERROR_FATAL_FANOUT_ACCOUNTS`, guaranteed to be a non-negative integer string after `lib/errors.sh` is sourced. Task 2 reads it.

- [ ] **Step 1: Write the failing tests**

Append to `test/errors_test.sh`:

```bash
# --- fan-out threshold knob: validation + fail direction ----------------------
# Non-numeric, negative and empty all fall back to the built-in default (4).
# Never clamp upward: 0 and 1 are legal and are the RED-safe end of the range.
_fanout_default=4
ERROR_FATAL_FANOUT_ACCOUNTS="abc"; _errors_validate_fatal_scanner
check fanout-knob-nonnum   "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS=""; _errors_validate_fatal_scanner
check fanout-knob-empty    "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS="-2"; _errors_validate_fatal_scanner
check fanout-knob-negative "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS="4.5"; _errors_validate_fatal_scanner
check fanout-knob-float    "$ERROR_FATAL_FANOUT_ACCOUNTS" "$_fanout_default"
ERROR_FATAL_FANOUT_ACCOUNTS=0; _errors_validate_fatal_scanner
check fanout-knob-zero-ok  "$ERROR_FATAL_FANOUT_ACCOUNTS" "0"
ERROR_FATAL_FANOUT_ACCOUNTS=1; _errors_validate_fatal_scanner
check fanout-knob-one-ok   "$ERROR_FATAL_FANOUT_ACCOUNTS" "1"
ERROR_FATAL_FANOUT_ACCOUNTS=12; _errors_validate_fatal_scanner
check fanout-knob-passthru "$ERROR_FATAL_FANOUT_ACCOUNTS" "12"
ERROR_FATAL_FANOUT_ACCOUNTS=4
# the shipped default must match the validation fallback and the example conf
check fanout-default-common "$(grep -c '^ERROR_FATAL_FANOUT_ACCOUNTS=4$' "${ROOT}/lib/common.sh")" "1"
check fanout-default-conf   "$(grep -c '^ERROR_FATAL_FANOUT_ACCOUNTS=4$' "${ROOT}/config/swatter.example.conf")" "1"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash test/errors_test.sh 2>&1 | tail -20`
Expected: FAIL lines for `fanout-knob-nonnum` (got `abc`, want `4`) and `fanout-default-common` (got `0`, want `1`) — the variable is not yet defaulted or validated.

- [ ] **Step 3: Add the shipped default**

In `lib/common.sh`, immediately after `ERROR_FATAL_SCANNER_REPEATS=3` (`:321`):

```bash
# Breadth companion to ERROR_FATAL_SCANNER_REPEATS. That knob counts DEPTH —
# repeats of one exact signature — and is blind to BREADTH, because the signature
# retains the /home/<acct> path and [php/<acct>] tag, so one shared bug on N
# accounts is N signatures of count 1 and every one slips under the depth gate.
# This is the account count at which a shared signature stops being filed as bot
# noise. Measured on cds1: bot sweeps reach 3 accounts, the one confirmed genuine
# fleet event reached 4, so 4 is the boundary. Raise it per host if ordinary
# sweeping is wider there; 0 disables the breadth gate entirely.
ERROR_FATAL_FANOUT_ACCOUNTS=4
```

- [ ] **Step 4: Add the validation branch**

In `lib/errors.sh`, inside `_errors_validate_fatal_scanner`, directly after the existing `ERROR_FATAL_SCANNER_REPEATS` `case` block (`:256-260`):

```bash
    # Same discipline as REPEATS: a non-negative integer or the built-in default,
    # never clamped upward. Fan-out is always >= 1, so a threshold of 0 would make
    # `fan < fanmin` false for every line and void the WHOLE scanner class rather
    # than just this gate — the apply site special-cases 0 as "breadth gate off"
    # instead. 1 is legal and means every matching fatal counts genuine.
    case "${ERROR_FATAL_FANOUT_ACCOUNTS:-}" in
        *[!0-9]*|'')
            log_warn "errors: ERROR_FATAL_FANOUT_ACCOUNTS='${ERROR_FATAL_FANOUT_ACCOUNTS:-}' is not a non-negative integer; using 4"
            ERROR_FATAL_FANOUT_ACCOUNTS=4 ;;
    esac
```

Note `*[!0-9]*` catches `-2` and `4.5` as well as `abc`, because `-` and `.` are not in `0-9`.

- [ ] **Step 5: Document the knob in the example conf**

In `config/swatter.example.conf`, immediately after `ERROR_FATAL_SCANNER_REPEATS=3` (`:412`):

```bash
# How many DISTINCT ACCOUNTS must share one fatal signature before it stops being
# filed as scanner-induced. ERROR_FATAL_SCANNER_REPEATS above counts repeats of a
# single signature (depth); this counts how far one signature has spread (breadth).
# Breadth matters because the signature keeps each account's own /home/<acct> path,
# so a single shared bug across N accounts looks like N unrelated one-offs and every
# one of them slips under the depth gate — a fleet-wide outage graded green.
#
# A cross-account cluster is reported whether a bot swept your sites or a deploy
# broke them: those are indistinguishable in the error log, so the digest surfaces
# it and lets you judge. Expect some REDs that used to be GREEN; that is this
# working.
#
# Tune per host. Measured on the reference host, bot sweeps reached 3 accounts and
# a genuine fleet bug reached 4, hence 4. If routine sweeping on your box is wider,
# raise this — it does not weaken single-account detection, which REPEATS still
# governs. Invalid values fall back to 4 with a warning; 0 turns the breadth gate
# off; 1 makes every matching fatal count genuine.
ERROR_FATAL_FANOUT_ACCOUNTS=4
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `bash test/errors_test.sh 2>&1 | tail -5`
Expected: no `FAIL` lines; the summary shows the new checks passing.

- [ ] **Step 7: Run the full suite**

Run: `make test`
Expected: exit 0, all planes pass. No pre-existing test changes behaviour — nothing consumes the knob yet.

- [ ] **Step 8: Commit**

```bash
git add lib/common.sh lib/errors.sh config/swatter.example.conf test/errors_test.sh
git commit -m "feat(errors): add ERROR_FATAL_FANOUT_ACCOUNTS knob and validation

Breadth companion to ERROR_FATAL_SCANNER_REPEATS, defaulting to 4 (measured on
cds1: bot sweeps reach 3 accounts, one confirmed genuine fleet event reached 4).
Validated like REPEATS — non-negative integer or the built-in default, never
clamped upward. Nothing consumes it yet.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: The fan-out gate

The core change. Delivers the complete correct gate in one commit — normalization, the three-tier account key, and the new conjunct — because a gate with a naive account key is knowingly broken (spec §2.2: the `unknown` sentinel and `/home2` both collapse fan-out and let the defect survive).

**Files:**
- Modify: `lib/errors.sh:303-324` (the `marked` awk block and the two `cut -f2-` calls that parse its output)
- Test: `test/errors_test.sh`

**Interfaces:**
- Consumes: `ERROR_FATAL_FANOUT_ACCOUNTS` from Task 1.
- Produces: the `marked` stream format changes from `FLAG \t LINE` to `FLAG \t FAN \t LINE`, where `FAN` is the distinct-account count for that line's normalized signature. Task 3 reads the `FAN` column to build the digest-body label. `ERR_FATAL_GENUINE` / `ERR_FATAL_SCANNER` keep their existing meaning and remain the only globals `lib/report.sh` reads.

- [ ] **Step 1: Write the failing tests**

Append to `test/errors_test.sh`. `_mkfan` builds N accounts × one identical fatal; the account appears in both the source tag and the path, as the live PHP collector emits it (`lib/errors.sh:85-86`).

```bash
# --- fan-out gate: breadth joins depth ---------------------------------------
# One shared bug across N accounts is N raw signatures of count 1, so the depth
# gate never fires on it. Breadth is what catches it.
_mkfan() { # _mkfan <n_accounts> <root> <tag_override|-> <msg>
  local n="$1" root="$2" tag="$3" msg="$4" i a
  for i in $(seq -w 1 "$n"); do a="acct$i"
    printf '[%s] [FATAL] [php/%s] %s in %s/%s/public_html/wp-content/plugins/v/r.php:88\n' \
      "$TS" "$([[ "$tag" == "-" ]] && echo "$a" || echo "$tag")" "$msg" "$root" "$a"
  done
}
FANMSG='PHP Fatal error: Uncaught Error: Call to undefined function shared_helper()'

ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4

# the defect itself: 17 accounts x 1 fatal must be genuine, not scanner
_mkfan 17 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-defect-total   "$ERR_FATAL" "17"
check fanout-defect-genuine "$ERR_FATAL_GENUINE" "17"
check fanout-defect-scanner "$ERR_FATAL_SCANNER" "0"

# multi-home cPanel roots must normalize too, or the account stays in the
# signature and breadth never groups
_mkfan 17 /home2 - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-home2 "$ERR_FATAL_GENUINE" "17"
_mkfan 17 /home3 - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-home3 "$ERR_FATAL_GENUINE" "17"

# the live collector's fallback tag is the literal shared string "unknown"
# (lib/errors.sh:85) — it must NOT be treated as one account
_mkfan 17 /home unknown "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-unknown-sentinel "$ERR_FATAL_GENUINE" "17"
_mkfan 17 /home2 unknown "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-unknown-home2 "$ERR_FATAL_GENUINE" "17"

# only the php collector emits a per-account tag; apache emits a vhost, fpm a
# pool. Those must fall back to the account in the path.
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [apache/site${i}.com] ${FANMSG} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-apache-tag "$ERR_FATAL_GENUINE" "17"
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [fpm/8.2:acct${i}] ${FANMSG} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-fpm-tag "$ERR_FATAL_GENUINE" "17"

# threshold behaviour
_mkfan 3 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-below-threshold "$ERR_FATAL_SCANNER" "3"
_mkfan 4 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-at-threshold "$ERR_FATAL_GENUINE" "4"
ERROR_FATAL_FANOUT_ACCOUNTS=8
_mkfan 4 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-tunable-8 "$ERR_FATAL_SCANNER" "4"
ERROR_FATAL_FANOUT_ACCOUNTS=0
_mkfan 17 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-disabled-zero "$ERR_FATAL_SCANNER" "17"
ERROR_FATAL_FANOUT_ACCOUNTS=1
_mkfan 1 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-one-all-genuine "$ERR_FATAL_GENUINE" "1"
ERROR_FATAL_FANOUT_ACCOUNTS=4

# single-account behaviour must be bit-identical to before this change
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-parity-1x1 "$ERR_FATAL_SCANNER" "1"
{ for _ in 1 2; do echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-parity-1x2 "$ERR_FATAL_SCANNER" "2"
{ for _ in 1 2 3; do echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-parity-1x3 "$ERR_FATAL_GENUINE" "3"

# a feed that forges distinct account tags INFLATES fan-out, which grades genuine
# -> RED. That is the safe direction and must stay that way: an untrusted feed
# must never be able to talk the classifier into hiding something.
{ for i in $(seq -w 1 5); do
    echo "[${TS}] [FATAL] [php/forged${i}] ${FANMSG} in /var/www/nohome/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-feed-forged "$ERR_FATAL_GENUINE" "5"

# a single fatal with neither tag nor path is depth 1 / breadth 1 -> scanner,
# exactly as today. Many of them get unique keys and fan out.
{ echo "[${TS}] [FATAL] ${FANMSG}"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-single-untagged "$ERR_FATAL_SCANNER" "1"
{ for i in $(seq 1 17); do echo "[${TS}] [FATAL] ${FANMSG} at offset ${i}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-many-untagged "$ERR_FATAL_GENUINE" "17"

# distinct messages across accounts are unrelated: breadth must not group them
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [php/acct${i}] PHP Fatal error: Uncaught Error: Call to undefined function fn${i}() in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-distinct-sigs "$ERR_FATAL_SCANNER" "17"

# the CLI veto still forces genuine, and wins over a scanner verdict
{ for i in $(seq -w 1 2); do
    echo "[${TS}] [FATAL] [php/acct${i}] PHP Fatal error: Uncaught Error: Undefined constant \"X\" in phar:///usr/local/bin/wp-cli.phar/x.php:9"
  done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-veto-still-genuine "$ERR_FATAL_GENUINE" "2"

# a SUBSEP byte in the line must not merge two accounts' keys
{ printf '[%s] [FATAL] [php/acctA] %s in /home/acctA/public_html/x.php:88\n' "$TS" "$FANMSG"
  printf '[%s] [FATAL] [php/acctB] %s\034 in /home/acctB/public_html/x.php:88\n' "$TS" "$FANMSG"
  printf '[%s] [FATAL] [php/acctC] %s in /home/acctC/public_html/x.php:88\n' "$TS" "$FANMSG"
  printf '[%s] [FATAL] [php/acctD] %s in /home/acctD/public_html/x.php:88\n' "$TS" "$FANMSG"
} > "$ERROR_DIGEST_LOG"; _run
check fanout-subsep-no-merge "$ERR_FATAL_GENUINE" "4"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash test/errors_test.sh 2>&1 | grep -c '^FAIL'`
Expected: a non-zero count, including `FAIL fanout-defect-genuine: want='17' got='0'` — today's gate files all 17 as scanner. Confirm that specific line appears:
`bash test/errors_test.sh 2>&1 | grep fanout-defect`

- [ ] **Step 3: Replace the awk block**

In `lib/errors.sh`, replace lines `303-321` (from `local fatal_genuine="" fatal_scanner=""` through the `fatal_scanner="$(...)"` assignment) with:

```bash
    local fatal_genuine="" fatal_scanner=""
    if (( ERR_FATAL > 0 )); then
        local marked
        marked="$(printf '%s\n' "$fatal" \
            | SWATTER_FS_RE="${ERROR_FATAL_SCANNER}" \
              SWATTER_FS_EX="${ERROR_FATAL_SCANNER_EXCLUDE}" \
            awk -v reps="${ERROR_FATAL_SCANNER_REPEATS}" \
                -v fanmin="${ERROR_FATAL_FANOUT_ACCOUNTS}" '
                { sig=$0; sub(/^\[[0-9-]+ [0-9:]+\] /,"",sig)
                  # SUBSEP hygiene: the composite fan-out key below is
                  # "nsig SUBSEP acct", so a \034 in the line could merge two
                  # accounts into one key. A collision LOWERS fan-out, which is
                  # the unsafe direction, so strip it before anything keys on it.
                  gsub(/\034/,"",sig)
                  line[NR]=$0; sigof[NR]=sig; cnt[sig]++

                  # --- account identity, three tiers ---
                  # 1. a php/<acct> source tag, which only _errors_collect_php
                  #    emits. Reject the literal "unknown": that is the collector
                  #    fallback (see _errors_collect_php) and is SHARED by every
                  #    account whose path strip failed, so trusting it would
                  #    collapse them all into one and hide the very fan-out we
                  #    are counting.
                  acct=""
                  if (substr(sig,1,1)=="[") {
                      p=index(sig,"] [")
                      if (p>0) { rest=substr(sig,p+3); q=index(rest,"]")
                                 if (q>0) { src=substr(rest,1,q-1); sl=index(src,"/")
                                            if (sl>0 && substr(src,1,sl-1)=="php") acct=substr(src,sl+1) } }
                  }
                  # 2. the /home<N>/<acct>/ path. apache tags carry a vhost and
                  #    fpm tags a pool, so those feeds land here.
                  if (acct=="" || acct=="unknown") {
                      acct=""
                      if (match(sig, /\/home[0-9]*\/[^\/]+\//)) {
                          seg=substr(sig,RSTART,RLENGTH)
                          sub(/^\/home[0-9]*\//,"",seg); sub(/\/$/,"",seg)
                          if (seg!="") acct=seg
                      }
                  }
                  # 3. no identity at all -> a key unique to this line, so an
                  #    unattributable fatal contributes to fan-out and can never
                  #    suppress the gate. Unknown identity biases toward RED.
                  key = (acct=="") ? ("\001" NR) : ("\002" acct)

                  # --- account-normalized signature, for BREADTH only ---
                  # /home[0-9]* not /home: cPanel uses /home2, /home3 as extra
                  # mount roots, and ERROR_DIGEST_LOG is an external feed that can
                  # carry any path. With /home alone the account stays embedded in
                  # nsig, no two accounts ever share one, and breadth is inert.
                  nsig=sig
                  gsub(/\/home[0-9]*\/[^\/]+\//, "/home<N>/<A>/", nsig)
                  sub(/^\[[A-Z]+\] \[[^]]+\]/, "[L] [<SRC>]", nsig)
                  nsigof[NR]=nsig
                  if (!((nsig SUBSEP key) in seen)) { seen[nsig SUBSEP key]=1; fan[nsig]++ }
                }
                END { re=ENVIRON["SWATTER_FS_RE"]; ex=ENVIRON["SWATTER_FS_EX"]
                      for (i=1;i<=NR;i++) {
                          # DEPTH is cnt on the RAW signature and re/ex match the
                          # RAW signature; only BREADTH uses nsig. That split is
                          # what makes this gate a strict narrowing of the old one
                          # — every conjunct can only move a fatal toward genuine,
                          # so this can never introduce a new false green. Do NOT
                          # rekey cnt onto nsig.
                          # fanmin <= 0 disables the breadth gate: fan is always
                          # >= 1, so a bare `fan < fanmin` would be false for
                          # every line and void the whole scanner class instead.
                          s = (sigof[i] ~ re && cnt[sigof[i]] < reps && sigof[i] !~ ex \
                               && (fanmin <= 0 || fan[nsigof[i]] < fanmin))
                          print (s ? "S" : "G") "\t" fan[nsigof[i]] "\t" line[i]
                      } }')"
        if [[ -z "$marked" ]]; then
            log_warn "errors: fatal classification failed; counting all fatals as genuine"
            fatal_genuine="$fatal"
        else
            fatal_genuine="$(printf '%s\n' "$marked" | grep '^G' | cut -f3- || true)"
            fatal_scanner="$(printf '%s\n' "$marked" | grep '^S' | cut -f3- || true)"
        fi
    fi
```

The `cut -f2-` calls become `cut -f3-` because the stream now carries the fan-out count as field 2.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `bash test/errors_test.sh 2>&1 | tail -5`
Expected: no `FAIL` lines.

- [ ] **Step 5: Verify identical behaviour on the other awk dialect**

The classifier must not depend on which awk is installed (`lib/errors.sh:217-232`).

Run:
```bash
bash test/errors_test.sh 2>&1 | tail -3
PATH="$(dirname "$(command -v gawk)"):$PATH" awk() { gawk "$@"; }; bash test/errors_test.sh 2>&1 | tail -3
```
If the shell function does not propagate, instead run the suite on a box with each awk, or temporarily symlink `gawk` ahead of `awk` on `PATH` in a subshell:
```bash
( d="$(mktemp -d)"; ln -s "$(command -v gawk)" "$d/awk"; PATH="$d:$PATH" bash test/errors_test.sh 2>&1 | tail -3 )
```
Expected: identical pass counts and zero `FAIL` under both.

- [ ] **Step 6: Run the full suite**

Run: `make test`
Expected: exit 0. Every pre-existing test in `test/errors_test.sh` still passes — all of its fixtures are single-account (`[php/acct]`, `/home/acct/`), so breadth is 1 and the new conjunct never fires.

- [ ] **Step 7: Commit**

```bash
git add lib/errors.sh test/errors_test.sh
git commit -m "fix(errors): count fan-out, not just repeats, in the fatal gate

The gate counted depth — repeats of one exact signature — and was blind to
breadth. Because the signature keeps each account's /home/<acct> path and
[php/<acct>] tag, one shared bug across N accounts is N signatures of count 1,
every one under the depth threshold, so a fleet-wide outage graded GREEN with the
RED SMS suppressed.

Adds a breadth conjunct: distinct accounts sharing an account-normalized
signature must be under ERROR_FATAL_FANOUT_ACCOUNTS. Adding a conjunct can only
shrink the scanner class, so this can never introduce a new false green.

Account identity is three-tiered, because two shipping cases otherwise collapse
fan-out and leave the defect intact: the php collector's fallback tag is the
literal shared string 'unknown', and normalizing only /home misses the /home2 and
/home3 mount roots cPanel uses. Tier 2 (the path) also covers apache and fpm
feeds, which tag a vhost and a pool rather than an account.

Depth stays keyed on the raw signature and re/ex still match the raw signature;
only breadth uses the normalized one. Verified identical under BSD awk and gawk.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Label the cross-account cluster in the digest body

Without this the operator sees "17 fatal errors" and cannot tell a bot sweep from a fleet outage — the ambiguity moves from the classifier into their lap with no evidence to resolve it (spec §3).

**Files:**
- Modify: `lib/errors.sh` (the `ERR_FATAL_GENUINE > 0` body block, `:350-354`, and the globals line at `:269`)
- Test: `test/errors_test.sh`

**Interfaces:**
- Consumes: the `FAN` column from Task 2's `marked` stream. The tests below also reuse the `_mkfan` shell helper and the `FANMSG` fixture string defined in Task 2 Step 1 — they are appended to the same file, so define Task 2's tests first or copy those two definitions.
- Produces: global `ERR_FATAL_FANOUT_MAX` — the largest distinct-account count among genuine fatals, `0` when there are none. Nothing outside `lib/errors.sh` reads it; it exists so the body text and the tests can agree on one number.

- [ ] **Step 1: Write the failing tests**

Append to `test/errors_test.sh`:

```bash
# --- digest body must distinguish breadth from depth -------------------------
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
_mkfan 17 /home - "$FANMSG" > "$ERROR_DIGEST_LOG"; _run
check fanout-body-max   "$ERR_FATAL_FANOUT_MAX" "17"
check fanout-body-label "$(printf '%s' "$SECTION_OUT" | grep -c 'across 17 accounts')" "1"
# a depth-only cluster (one account, repeats) must NOT claim a cross-account spread
{ for _ in 1 2 3; do echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; done; } > "$ERROR_DIGEST_LOG"; _run
check fanout-body-depth-max   "$ERR_FATAL_FANOUT_MAX" "1"
check fanout-body-depth-label "$(printf '%s' "$SECTION_OUT" | grep -c 'across .* accounts')" "0"
# no genuine fatals at all -> zero, no label
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"; _run
check fanout-body-none-max "$ERR_FATAL_FANOUT_MAX" "0"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash test/errors_test.sh 2>&1 | grep fanout-body`
Expected: FAILs — `ERR_FATAL_FANOUT_MAX` is unbound (got `''`) and the label is absent.

- [ ] **Step 3: Declare and compute the new global**

In `lib/errors.sh`, extend the globals reset at `:269` to include the new name:

```bash
    ERR_TOTAL=0 ERR_FATAL=0 ERR_FATAL_GENUINE=0 ERR_FATAL_SCANNER=0 ERR_GENUINE=0 ERR_NOISE=0
    ERR_FATAL_FANOUT_MAX=0
```

Also add `ERR_FATAL_FANOUT_MAX` to the comment listing the globals above `swatter_errors_section` (`:265`).

Then, immediately after the `fatal_scanner="$(...)"` assignment inside the `else` branch added in Task 2:

```bash
            # Widest cross-account spread among the GENUINE fatals. Drives the
            # body label below so an operator can tell "one signature across many
            # accounts" (breadth) from "one account failing repeatedly" (depth) —
            # the two now grade the same and need different responses.
            local _fmax
            _fmax="$(printf '%s\n' "$marked" | grep '^G' | cut -f2 | sort -rn | head -1)"
            [[ "$_fmax" =~ ^[0-9]+$ ]] && ERR_FATAL_FANOUT_MAX="$_fmax"
```

- [ ] **Step 4: Add the body label**

In `lib/errors.sh`, replace the `ERR_FATAL_GENUINE > 0` block (`:350-354`) with:

```bash
        if (( ERR_FATAL_GENUINE > 0 )); then
            echo "FATAL entries (verbatim):"
            if (( ERR_FATAL_FANOUT_MAX >= 2 )); then
                echo "  (one signature spans across ${ERR_FATAL_FANOUT_MAX} accounts — reported whether a bot swept the"
                echo "   sites or a deploy broke them; those are indistinguishable in this log.)"
            fi
            printf '%s\n' "$fatal_genuine" | head -25 | sed 's/^/  /'
            echo
        fi
```

The `>= 2` guard keeps the line off single-account windows, where it would be noise.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `bash test/errors_test.sh 2>&1 | grep -E 'fanout-body|^FAIL'`
Expected: no output for `^FAIL`; the `fanout-body-*` checks pass.

- [ ] **Step 6: Run the full suite**

Run: `make test`
Expected: exit 0. Existing body-grep assertions are unaffected — they match `FATAL entries (verbatim)` and the verbatim lines, both still present and in order.

- [ ] **Step 7: Commit**

```bash
git add lib/errors.sh test/errors_test.sh
git commit -m "feat(errors): label cross-account fatal clusters in the digest body

A breadth cluster and a depth cluster now grade the same but need different
responses, so the body says which it is. Without it the operator sees 'N fatal
errors' and has no way to tell a bot sweep from a fleet outage.

Adds ERR_FATAL_FANOUT_MAX, the widest account spread among genuine fatals, and
prints it only at >= 2 so single-account windows stay quiet.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Normalize whitespace on the pre-consolidated feed

**Must land after Task 2, never before.** Raw PHP writes `PHP Fatal error:` with two spaces and the shipping pattern expects one, so on a two-space feed the scanner class is inert and the defect is unreachable. Fixing whitespace with no breadth gate in place would open the mouth and manufacture the defect (spec §5).

**Files:**
- Modify: `lib/errors.sh:22-27` (the `ERROR_DIGEST_LOG` branch of `_errors_consolidated`)
- Test: `test/errors_test.sh`

**Interfaces:**
- Consumes: Task 2's gate (the tests below assert breadth behaviour on two-space input), plus the `FANMSG` fixture string from Task 2 Step 1.
- Produces: nothing new. `_errors_consolidated` keeps emitting `[ts] [LEVEL] [src] msg` lines; runs of whitespace inside the message are now collapsed to one space, matching the live emit at `lib/errors.sh:39`.

- [ ] **Step 1: Write the failing tests**

Append to `test/errors_test.sh`:

```bash
# --- the two feeds must normalize whitespace identically ---------------------
# Raw PHP logs "PHP Fatal error:" with TWO spaces. The live emit collapses runs
# (see _ERR_AWKLIB emit); this pre-consolidated path did not, so the same error
# produced different signatures on the two feeds and matched no pattern here.
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
TWOSP='PHP Fatal error:  Uncaught Error: Call to undefined function shared_helper()'
{ echo "[${TS}] [FATAL] [php/acct] ${TWOSP} in /home/acct/public_html/x.php:88"; } > "$ERROR_DIGEST_LOG"; _run
check twospace-eligible "$ERR_FATAL_SCANNER" "1"
# and breadth still applies once the pattern matches
{ for i in $(seq -w 1 17); do
    echo "[${TS}] [FATAL] [php/acct${i}] ${TWOSP} in /home/acct${i}/public_html/x.php:88"
  done; } > "$ERROR_DIGEST_LOG"; _run
check twospace-fanout "$ERR_FATAL_GENUINE" "17"
# one- and two-space forms of the same error must collapse to ONE signature, so
# three of them cross the depth gate together
{ echo "[${TS}] [FATAL] [php/acct] ${TWOSP} in /home/acct/public_html/x.php:88"
  echo "[${TS}] [FATAL] [php/acct] ${FANMSG} in /home/acct/public_html/x.php:88"
  echo "[${TS}] [FATAL] [php/acct] ${TWOSP} in /home/acct/public_html/x.php:88"
} > "$ERROR_DIGEST_LOG"; _run
check twospace-collapse "$ERR_FATAL_GENUINE" "3"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash test/errors_test.sh 2>&1 | grep twospace`
Expected: `FAIL twospace-eligible: want='1' got='0'` — the two-space line matches neither arm today, so it counts genuine, not scanner.

- [ ] **Step 3: Collapse whitespace on the digest-feed path**

In `lib/errors.sh`, replace the `ERROR_DIGEST_LOG` branch (`:22-27`) with:

```bash
    if [[ -n "${ERROR_DIGEST_LOG}" && -r "${ERROR_DIGEST_LOG}" ]]; then
        # Pre-consolidated UTC log: fixed-width ISO timestamp -> lexical compare.
        # Collapse runs of whitespace in the MESSAGE exactly as the live emit does
        # (see emit() in _ERR_AWKLIB). Raw PHP writes "PHP Fatal error:" with two
        # spaces, so without this the same error yields a different signature on
        # each feed: it matches no pattern here, and depth/breadth counting cannot
        # collapse the two forms together.
        local cut_human; cut_human="$(date -u -d "@${cutoff}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -r "${cutoff}" '+%Y-%m-%d %H:%M:%S')"
        awk -v c="$cut_human" '/^\[[0-9-]{10} [0-9:]{8}\]/ {
                if (substr($0,2,19) < c) next
                head=substr($0,1,21); msg=substr($0,22)
                gsub(/[ \t\r]+/," ",msg); sub(/^ /,"",msg); sub(/ $/,"",msg)
                print head msg
            }' "${ERROR_DIGEST_LOG}"
        return 0
    fi
```

`head` is the fixed-width `[YYYY-MM-DD HH:MM:SS] ` prefix — 21 characters including the trailing space — so the timestamp is preserved byte-for-byte and only the remainder is normalized.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `bash test/errors_test.sh 2>&1 | grep -E 'twospace|^FAIL'`
Expected: no `^FAIL` output; the three `twospace-*` checks pass.

- [ ] **Step 5: Run the full suite**

Run: `make test`
Expected: exit 0. Existing fixtures are single-space, so collapsing is a no-op on them.

- [ ] **Step 6: Commit**

```bash
git add lib/errors.sh test/errors_test.sh
git commit -m "fix(errors): collapse whitespace on the pre-consolidated feed

The live emit collapses runs of whitespace; this path did not. Raw PHP writes
'PHP Fatal error:' with two spaces, so the same error arriving on the two feeds
produced two different signatures — it matched no pattern on this one, and
depth/breadth counting could not collapse the forms together.

Lands after the fan-out gate deliberately. On a two-space feed the scanner class
is inert, so this fix alone would open the mouth with no breadth gate behind it
and manufacture the fleet-wide false green.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Copy, docs, and release

The digest still tells operators these fatals are "bots executing PHP files directly," which was already inaccurate and is now actively wrong. Also lands the invariant test for the three-copy default and the RUNBOOK note that this change alters what RED means.

**Files:**
- Modify: `lib/errors.sh:356` (scanner-section heading), `:186-187` (disable docs)
- Modify: `lib/report.sh:499` (the `nofatal` string)
- Modify: `lib/common.sh:274` (prose naming `ERROR_FATAL_SCANNER` as sole classifier)
- Modify: `config/swatter.example.conf:344`, `:430` (same prose)
- Modify: `docs/RUNBOOK.md`
- Modify: `CHANGELOG.md`
- Test: `test/errors_test.sh`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing consumed by later tasks. This is the final task.

- [ ] **Step 1: Write the failing tests**

Append to `test/errors_test.sh`:

```bash
# --- the scanner default must stay byte-identical in all three copies --------
# A silent split between the shipping default, the validation fallback and the
# documented value is possible today because nothing compares them.
_scan_common="$(sed -n "s/^ERROR_FATAL_SCANNER='\(.*\)'$/\1/p" "${ROOT}/lib/common.sh")"
_scan_errors="$(sed -n "s/^_ERR_FATAL_SCANNER_DEFAULT='\(.*\)'$/\1/p" "${ROOT}/lib/errors.sh")"
_scan_conf="$(sed -n "s/^ERROR_FATAL_SCANNER='\(.*\)'$/\1/p" "${ROOT}/config/swatter.example.conf")"
check threecopy-nonempty "$([[ -n "$_scan_common" ]] && echo ok)" "ok"
check threecopy-errors   "$_scan_errors" "$_scan_common"
check threecopy-conf     "$_scan_conf"   "$_scan_common"

# --- the digest must not claim these came from direct file execution ---------
ERROR_FATAL_SCANNER_REPEATS=3; ERROR_FATAL_FANOUT_ACCOUNTS=4
{ echo "[${TS}] [FATAL] [php/acct] ${SCAN1}"; } > "$ERROR_DIGEST_LOG"; _run
check copy-no-direct-exec "$(printf '%s' "$SECTION_OUT" | grep -c 'executing PHP files directly')" "0"
check copy-has-heading    "$(printf '%s' "$SECTION_OUT" | grep -c 'Scanner-induced FATALs')" "1"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash test/errors_test.sh 2>&1 | grep -E 'threecopy|copy-no-direct'`
Expected: `FAIL copy-no-direct-exec: want='0' got='1'`. The `threecopy-*` checks should already pass — they are a regression guard, not a bug fix; if any fails, the defaults have already drifted and that must be fixed before continuing.

- [ ] **Step 3: Fix the digest copy**

In `lib/errors.sh:356`, replace the scanner-section heading:

```bash
            echo "Scanner-induced FATALs (isolated one-off crashes, no outage signal):"
```

In `lib/report.sh:499`, replace the `nofatal` assignment:

```bash
    (( fsc > 0 )) && nofatal="No genuine fatals — ${fsc} isolated one-off crash(es), not an outage"
```

Both drop the "bots executing PHP files directly" claim, which was already wrong for the cds1 case (a bootstrapped plugin file) and does not describe what the gate now measures.

- [ ] **Step 4: Fix the disable docs and the sole-classifier prose**

In `lib/errors.sh:186-187`, replace the disable sentence:

```bash
# to the built-in default; to disable the classifier entirely, set
# ERROR_FATAL_SCANNER_REPEATS to 0 or 1 — no signature count is below either, so
# every matching fatal then counts as genuine. Both are kept as the RED-safe
# direction and are never clamped upward. Note REPEATS governs DEPTH only;
# ERROR_FATAL_FANOUT_ACCOUNTS governs breadth across accounts.
```

In `lib/common.sh:274`, replace the prose so it no longer names the pattern as the whole classifier:

```bash
# GENUINE fatal error — fatals filed scanner-induced by the errors plane (pattern
# ERROR_FATAL_SCANNER, depth ERROR_FATAL_SCANNER_REPEATS, breadth
# ERROR_FATAL_FANOUT_ACCOUNTS) do not trip RED
```

Then apply the same correction to the two equivalent sentences in the example conf. Display them first so the edit is exact rather than guessed:

```bash
sed -n '340,348p;426,434p' config/swatter.example.conf
```

Both passages describe `ERROR_FATAL_SCANNER` as though the pattern alone decides the scanner class. Reword each so it names all three inputs — the pattern, `ERROR_FATAL_SCANNER_REPEATS` for depth, and `ERROR_FATAL_FANOUT_ACCOUNTS` for breadth — keeping that file's comment width and voice. Do not change the `ERROR_FATAL_SCANNER` value on `:411`; the `threecopy-*` tests will fail if it drifts.

- [ ] **Step 5: Add the RUNBOOK note**

Append to `docs/RUNBOOK.md`, in the section covering the nightly digest's grades:

```markdown
### What a RED from cross-account fatals means

A fatal signature appearing on `ERROR_FATAL_FANOUT_ACCOUNTS` or more accounts in
one window is always reported, and the digest body says so ("one signature spans
across N accounts"). It is reported whether a bot swept your sites or a deploy
broke them, because **those two are indistinguishable in the error log** — the log
records that a request fataled, never whether a healthy application would have
served it. The digest surfaces the cluster and leaves the judgement to you.

Expect some windows that used to grade GREEN to grade RED. That is the fix
working: before it, one shared bug across N accounts produced N signatures of
count 1, slipped under the repeat threshold, and graded GREEN with the RED SMS
suppressed.

**Triage:** open the body and read the verbatim fatals. Identical `file:line`
across accounts with a plugin or theme path points at a deploy or an auto-update;
paths under `wp-admin/` or a vendored library executed head-on point at a bot.

**If the rate is too high on this host,** raise `ERROR_FATAL_FANOUT_ACCOUNTS`. It
does not weaken single-account detection, which `ERROR_FATAL_SCANNER_REPEATS`
still governs on its own. `0` turns the breadth gate off entirely.

**Feed contract.** When `ERROR_DIGEST_LOG` is set, the account in each line's
`[php/<acct>]` tag is now a grading input, not just a label. The window filter
only checks the timestamp, so a malformed or wrong account field skews the
account count — inflating it grades RED (safe), collapsing it grades GREEN. The
classifier falls back to the `/home<N>/<acct>/` path when the tag is unusable,
which covers the common cases.
```

- [ ] **Step 6: Add the CHANGELOG entry and bump the version**

Read the top of `CHANGELOG.md` and the current version to match the file's format exactly:

```bash
head -30 CHANGELOG.md; grep -rn "2\.13\.0" lib/common.sh bin/swatter | head
```

Add a new entry above the previous release, in that file's established style, covering:
- the fatal gate now counts breadth as well as depth, closing a false GREEN on fleet-wide fatals;
- the new `ERROR_FATAL_FANOUT_ACCOUNTS` knob, default 4, and that raising it is the lever if a host sees wider routine sweeping;
- **operator-visible:** windows that previously graded GREEN may now grade RED, and the RED SMS fires accordingly;
- the pre-consolidated feed now collapses whitespace like the live path;
- corrected digest copy.

Bump the version to `2.14.0` wherever `2.13.0` appears in `lib/common.sh` / `bin/swatter` (a behaviour change with a new config key, not a patch).

- [ ] **Step 7: Run the full suite**

Run: `make test`
Expected: exit 0, no `FAIL` lines.

- [ ] **Step 8: Verify the version bump is consistent**

Run: `grep -rn "2\.14\.0" lib/common.sh bin/swatter CHANGELOG.md | head`
Expected: the new version appears in every place the old one did, and `grep -rn "2\.13\.0" lib/ bin/` returns only historical CHANGELOG references.

- [ ] **Step 9: Commit**

```bash
git add lib/errors.sh lib/report.sh lib/common.sh config/swatter.example.conf docs/RUNBOOK.md CHANGELOG.md test/errors_test.sh
git commit -m "docs(errors): correct digest copy, document breadth, release 2.14.0

The digest told operators these fatals were 'bots executing PHP files directly'.
That was already wrong for the cds1 case, which came from a bootstrapped plugin
file, and it does not describe what the gate measures now — so it is replaced
with 'isolated one-off crashes', which is what a low depth and low breadth
actually mean.

Also: REPEATS is documented as governing depth only, 0 and 1 are both documented
as disabling it, the RUNBOOK explains what a cross-account RED means and how to
triage it, and a test pins the three copies of the scanner default byte-identical.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Verification Before Merge

Not a task — the gate before this branch merges.

- [ ] `make test` exits 0.
- [ ] The suite passes under both BSD awk and gawk (Task 2 Step 5).
- [ ] `git log --oneline` shows the fan-out gate (Task 2) landing **before** the whitespace fix (Task 4).
- [ ] The §0 repro from the spec now grades RED: build the 17-account fixture, confirm `GENUINE=17 SCANNER=0`.
- [ ] `git diff main --stat` touches only the files in the File Structure table.
- [ ] `git log --all --format='%ae%n%ce' | sort -u` shows only `*.noreply` addresses.
- [ ] A dry-run digest on cds1 renders the new body label correctly against real data, before the cron picks it up.

## Known Limitations To Carry Forward

Recorded so nobody rediscovers them as bugs:

- **The breadth default rests on one confirmed real event.** cds1 showed bot noise at 3 accounts and a single genuine fleet bug at 4, so 4 is the boundary — with no margin. Re-measure over a longer window, **classifying each cluster rather than counting it**, before treating 4 as settled. Setting it from counts alone hides exactly what the gate exists to reveal (spec §2.4).
- **Per-account variance inside the message defeats breadth.** Custom plugin directories, per-site cache paths, or an account name appearing outside `/home<N>/<acct>/` (a DB name like `acct01_wp`) all diversify the normalized signature. Those fatals stay scanner-filed. This also defeats today's depth grouping, so it is a pre-existing limit, not a regression (spec §2.7).
- **A bot sweep across ≥4 accounts will grade RED.** Accepted and permanent: a sweep and a fleet bug are indistinguishable in the log, and the false RED is the visible, recoverable direction (spec §2.6).
- **Multi-copy vendored packages remain a live risk class.** `idahomining` carries four copies of `jetpack-connection`; only Jetpack's own defines the constant that fataled. Not this repo's problem to fix, but it is why that cluster happened (spec §0.2).
