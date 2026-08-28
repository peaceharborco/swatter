# gate-d-enrich.sh — round 5 review (2026-08-28)

Fifth adversarial pass, run because the tool had to be copied to cds1 to bucket
1,118 live gate D candidates and the round-4 fixes had never been reviewed.
Round 4's own lesson — *probe the matcher, do not trust the validator* — turned
out to have been applied to only half the problem.

**Reviewers:** `grok-4.6` lens A (correctness skeptic) and `grok-4.5` lens B
(safety / edge-case red-teamer), 2 passes, run concurrently and read-only
(`--sandbox read-only`); plus the Claude-side `[code-review]`, `[security-review]`
and `[gap]` sweeps over the same target. Both Grok verdicts: **HOLD**, on the
same B1.

Prior rounds: `2026-08-20-gate-d-enrich-review-grok.md`.

---

## Blockers

### B1 — the CIDR probe certified the arm on ONE address family `[4.6-a] [4.5-b]` — both models, independently

`_probe_cidr_arm` took `tail -1` of `shared-egress.cidr` and required the real
matcher to find it. But `_cidr_overlaps_file` is **two** matchers: IPv4 is a
separate `awk` process (`lib/allowlist.sh:176-196`), IPv6 is a bash `while read`
(`:151-170`). Probing whichever family happens to sit on the last line proves
nothing about the other — and which family that is depends only on the order
someone appended ranges.

Both spellings of the failure were live at once:

- repo `config/shared-egress.cidr` ends with `2a09:bac7::/32` (v6) → the awk arm
  that is **WARP v4's only protection** (AS13335 is deliberately off the ASN
  list) went unprobed;
- cds1's live file ends with `194.5.82.0/24` (v4) → the **v6** arm went unprobed
  instead, while a real WARP v6 candidate sat in the list.

**Reproduced end-to-end against HEAD**: dual-stack file + a working `gawk` for
the traffic pass + an `awk` that fails on `-v ipint=…` put `104.28.196.52`
(WARP v4) in **bucket 2** — the pile no human reads, whose downstream
consequence is a permanent ban plus a public AbuseIPDB report with no delete API.

Fixed: probe **every family present** in the file; each must match, and at
least one must be present. Regression test
`R5-dual-stack-v4-matcher-broken-cannot-reach-bucket-2` fails against HEAD.

### B2 — IPv4-mapped candidates are evaluated inconsistently `[4.6-a]`

`_inert_reason` unwraps `::ffff:a.b.c.d` and `0:0:0:0:0:ffff:a.b.c.d`
internally, but the shared-egress CIDR leg and `_asn_of` use the **original**
string. A mapped WARP address therefore skips the v4 CIDR arm entirely (the
prefix is v4, the address parses as v6) while `origin6` of the mapped nibbles
can still return a numeric ASN. Reviewer put
`0:0:0:0:0:ffff:104.28.1.1` in bucket 2.

> **SUPERSEDED — see the RE-REVIEW below.** The fix described here matched two
> literal spellings and was WRONG; four more spellings still reached bucket 2.
> The shipped fix decides this semantically via `_ipv6_expand`.

Fixed conservatively: mapped forms are routed to **bucket 3**, not
canonicalized. Canonicalizing would desync three separately-keyed lookups
(`want[]` in the domlog pass, `TRAF_OF`, and the preview itself) immediately
before a live run; the invariant already has the right answer for an address we
cannot evaluate consistently. Zero candidates in this preview are mapped form.

---

## Majors

### M1 — RFC6598 CGNAT (`100.64.0.0/10`) was not inert `[4.6-a]`

Shared **by construction** — the space ISPs put many subscribers behind, which
is precisely the "shared exit, never allowlist" class the handoff's disposition
table names. It was absent from `_inert_reason`'s private-range case, and it
cannot simply be added to `shared-egress.cidr`: a `/10` is rejected by
`SHARED_EGRESS_MIN_PREFIX4=16`, and one rejected line disables the **whole**
CIDR arm (`lib/asn.sh:106-112`), taking WARP v4 down with it.

**Reproduced against HEAD: `100.64.1.8`, scanner-shaped, landed in bucket 2.**
This is a third independent path into the unread pile, so in practice it is
Blocker-grade. Fixed as a special case in `_inert_reason`.

### M2 — rows that failed to parse vanished from every bucket `[4.6-a] [4.5-b]`

Phase 1 kept only `NF==4 && $1!="ip" && $1!=""`; the completeness gate compared
enriched rows to `$CAND`, never to the input. A preview with a fifth column, a
lost field or a trailing tab dropped those IPs from all three buckets while the
report still ended `COMPLETE n/n`. A vanished row is worse than a misfiled one
because nothing reports it.

> **SUPERSEDED — see the RE-REVIEW below.** Refusing was itself a denial of
> review. The shipped fix emits unparsed lines as visible bucket-3 rows instead.

Fixed: every non-empty, non-header input line must be accounted for or the run
refuses, printing the offending lines. Verified against the real preview —
1,119 lines, 1,118 parsed, 0 unaccounted.

### M3 — `CLOUDFLARE_IPS_FILE` had no poison guard `[4.6-a] [4.5-b]`

The existing guard covered operator-allow and monitoring, but `_inert_reason`
consults `CLOUDFLARE_IPS_FILE` **first** for every candidate. A poisoned file
marks every row `inert:cloudflare-range` and the report reads "N inert, 0 to
review" — a clean-looking run that examined nothing.

**One reviewer's proposed fix was wrong and is recorded here so it is not
retried:** reusing `swatter_intel_cidr_feed_ok` (the width test) would abort
every run on a perfectly healthy file. Cloudflare's real published list is
legitimately wider than the shared-egress thresholds allow — cds1 carries
`104.16.0.0/13`, `104.24.0.0/14`, `162.158.0.0/15`, `172.64.0.0/13` and
`2a06:98c0::/29`. Fixed instead with the script's own probe philosophy: a real
Cloudflare list must not match reserved documentation space
(`192.0.2.1`, `198.51.100.1`, `203.0.113.1`, `2001:db8::1`).

> **INCOMPLETE — see the RE-REVIEW below.** The canary alone misses a
> *wrong-width* file: `0.0.0.0/1` evades all four canaries. The shipped fix adds
> a second leg, a width floor tuned to Cloudflare's real shape.

### M4 — serial DNS is unbounded `[4.5-b]` — ACCEPTED, NOT FIXED

~1,118 candidates each doing an ASN dig, plus a PTR pair per bucket-3 row, all
serial at `+time=2`, as root beside the `*/5` scan. This is an availability
concern during the gate, not a mis-sort, and every failure direction is already
safe (`asn_ok=0` → bucket 3). Left as-is deliberately: adding concurrency to a
tool being run once, imminently, on production is a worse trade than a slow run.
**Watch the wall-clock; if it stalls, that is this.**

---

## Minors fixed

- **m1** `[4.6-a]` — 301/302/303/307/308 were not counted as `served`. A
  redirect is the origin answering a real client; a row whose only traffic was a
  301 reached bucket 2 against HEAD. Counting them can only make the bucket-2
  predicate harder to satisfy.
- **m3/m4** `[4.6-a] [4.5-b]` — the probe-failure notes said "first entry" while
  the code probed the last. Both models called this out as the wording that hid
  B1 for four rounds.
- **`awk` selected by presence, not function** `[code-review]` — found by the
  Claude-side sweep. `command -v gawk` proves the binary exists, not that it
  runs; a stale Homebrew symlink is selected and then fails every awk stage
  (observed live: 16 green tests became 14 failures). Now probed with a fallback
   — the same round-4 lesson applied to a third resource.
- **`awk` dash-leading filenames** `[4.5-b]` — normalised to `./`-prefixed
  paths. Note `--` does **not** work here: for an inline program awk stops
  option parsing at the program text, so a trailing `--` is taken as a filename
  and its "can't open file" trips the degraded-read guard, collapsing the entire
  sort to bucket 3. Adding `--` was tried and did exactly that.

## Declined

- **`--out` symlink hardening / refusing `/tmp`** `[4.5-b]` — real, but the
  attack requires an existing local foothold on cds1 able to pre-plant symlinks
  under a root-chosen output dir, and the run uses `/root/gate-d-review` (mode
  0700). Logged, not fixed under time pressure before a live run.
- **False inert via a poisoned Cymru answer** `[4.5-b]` — inherent to the ASN
  arm and equally true of the enforcer; out of scope for this tool.

---

## Live-exposure check on the actual candidate list

Verified on cds1 against the real `preview-20260828T123856Z.tsv` before any fix,
because a defect that cannot fire on this list is not a reason to delay:

| | |
|---|---|
| candidates | 1,118 (243 at-bar, 875 one-away) |
| WARP v4 in `104.28.0.0/16` | **13** |
| WARP v6 in `2a09:bac0-bac7::/32` | **1** |
| all 14 matched by the live CIDR arm | **yes** — would have been bucket 1 |
| IPv4-mapped candidates (B2) | 0 |
| CGNAT candidates (M1) | 0 |
| rows failing `NF==4` (M2) | 0 |
| `cloudflare.cidr` matching documentation space (M3) | no |

So none of the Blockers was live for this specific run — but B1's protection was
incidental to file line-ordering, and **14 real WARP addresses in this list rode
on it**. One appended range would have flipped which family was probed.

## Verification

- 23/23 tests green under **both** awk dialects (gawk and BSD awk).
- 7 new round-5 tests; **6 fail against HEAD** (mutation-verified). The seventh
  is the healthy-path control and correctly passes both ways.
- Both Grok passes ran under `--sandbox read-only` and wrote nothing; the only
  working-tree changes are the two files fixed here.

---

# Round 5 — RE-REVIEW of the fixes (same day)

The fixes above are themselves unshipped code, and running this tool means
copying it to cds1. So the gate was re-run over the fix diff before anything
went to the host. **Both models returned HOLD again, on the same Blocker — and
they were right: the first B2 fix was wrong.**

**Reviewers:** `grok-4.6` lens A (correctness) + `grok-4.5` lens B (safety /
regression), 2 passes, read-only; plus the Claude-side sweeps.

## Blocker — the B2 fix matched SPELLINGS, not addresses `[4.6-a] [4.5-b]`

Both models, independently. The first fix was:

```bash
case "${ip,,}" in ::ffff:*|0:0:0:0:0:ffff:*) ... bucket 3 ...
```

`swatter_is_valid_ip_or_cidr` accepts many more encodings of the same address.
Reproduced against the *fixed* tree, with full bucket-2 setup:

| input | first fix |
|---|---|
| `0:0:0:0:0:ffff:104.28.1.1` | 3 (caught) |
| `::ffff:104.28.1.1` | 3 (caught) |
| `0000:0000:0000:0000:0000:ffff:104.28.1.1` | **2** |
| `0::ffff:104.28.1.1` | **2** |
| `0:00:0:0:0:ffff:104.28.1.1` | **2** |
| `0000::ffff:104.28.1.1` | **2** |

And these are exactly the spellings that *survive*: `lib/ingest.sh:33-34`
unwraps only the compact form, so the ledger preserves the rest verbatim.

Refixed **semantically** — expand once with `_ipv6_expand` and inspect the
canonical 32 nibbles (`00000000000000000000ffff…`), plus the deprecated
IPv4-compatible form when a dotted quad was actually written (so `::` and `::1`
are not swallowed). All six spellings now bucket 3; mutation-verified — the four
extra spellings fail against the first fix.

## Major — the cloudflare canary missed the wider half of its own class `[4.6-a]`

The documentation-address canary catches a *wrong-content* file but not a
*wrong-width* one. Verified: a body of `0.0.0.0/1` evades all four canaries
while still marking WARP v4 — and half the IPv4 internet — `inert:cloudflare-range`.

Fixed with a second leg: a width floor tuned to Cloudflare's **real** shape
(widest `/13` v4, `/29` v6 on cds1), set at `/10` and `/24` so it catches `/0`,
`/1` and `/8` with margin and never fires on a healthy list. Both legs kept —
they catch different failures. Tests assert both that the poison refuses and
that real Cloudflare widths still run.

## Major — the accounting `die` was itself a denial of review `[4.5-b]`

The first fix traded a vanishing row for an abort: one stray annotation, a
trailing tab, or an Excel-touched copy of a valid 1,118-row preview would kill
the whole gate before a single row was bucketed — the same class as the
width-check mistake this round had just avoided.

Refixed: an unparseable line is emitted as a visible **bucket-3 row**
(`unparsed-preview-line:<n>`), counted in `COMPLETE n/n`. It neither vanishes
nor blocks. Blank and `#`-comment lines are correctly not "lost rows". Header
detection is now line 1 only, so a data row whose first field is literally `ip`
no longer disappears from both counters `[4.6-a m1]`.

## Test assertions tightened `[4.6-a m3]`

- the dual-stack test now pins `why=shared-egress-not-evaluable`, not just
  bucket 3 (which `scan_errs` or `have_traffic==0` would also satisfy);
- the refusal tests now match the specific `die` message rather than accepting
  any non-zero exit (which any unrelated failure would have satisfied).

---

## The one that only real data could find

Dry-running the guard chain against cds1's actual files — step 3 of the release
sequence in `CLAUDE.md` — turned up a **live blocker in the round-4 guard that
neither model saw and no fixture could produce**:

`monitoring.cidr` ships as an all-comments header block with every vendor range
commented out. `[[ -s ]]` is true (it has bytes), comment-stripping leaves
nothing, and `swatter_intel_cidr_feed_ok` **fails on empty input** — so the
round-4 never-block guard would have aborted the entire gate D review on a
stock, healthy file. The tool has never been on cds1, so this was never
exercised.

A file with no entries cannot mark anything inert, which is the exact harm the
guard exists to prevent, so it is safe and must not die. Fixed by requiring at
least one real entry before validating. Mutation-verified: the test fails
against HEAD with `refused`.

*"Fixtures do not contain the shapes that break things; production does."*

## Final verification

- **35/35 tests green under both awk dialects**; shellcheck clean at
  `-S warning` (stricter than CI's `--severity=error` — note CI lints
  `test/*.sh` but **not** `tools/gate-d/*.sh`).
- Every new guard exercised against cds1's real files: parser 1118 candidates /
  0 unparsed; cloudflare width floor **pass**; cloudflare canary **pass**;
  never-block guards **pass** (was DIE); shared-egress v4 probe **MATCH**
  (`194.5.82.0/24`) and v6 probe **MATCH** (`2a09:bac7::/32`).
- Mutation-verified throughout: the round-5 tests fail against HEAD, and the
  mapped-spelling tests fail against the first fix.
