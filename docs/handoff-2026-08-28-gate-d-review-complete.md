# Handoff — gate D review COMPLETE, widen BLOCKED

Written 2026-08-28. Supersedes `docs/handoff-2026-08-20-gate-d-widen.md` for
everything through step 3. **Do not run step 4 (the widen) until the srcset
item below is resolved.**

---

## Start here

The gate D review is done. All 1,118 candidates are dispositioned. **The widen
did not happen and should not happen yet**, because the review found an active,
fleet-wide source of false positives that the widen would multiply.

**The ladder itself is untouched:** `REPEAT_WINDOW_DAYS` is still 7,
`ABUSEIPDB_REPORT` is still `true`, and no ban was placed or lifted.

Two changes WERE made to cds1 on 2026-08-28, both detailed below: `lib/score.awk`
was deployed (the false-positive fix), and `AS137409` was added to
`shared-egress-asns.txt`. Neither touches the widen.

Work products are on cds1 under `/root/gate-d-review/round-20260828T123856Z/`
(mode 0700): `enriched.tsv`, `buckets.txt`, `decisions.tsv` (1,077 rows),
plus the raw archive extracts the audit was built from.

---

## What the review found

Preview: 1,118 candidates (243 at-bar, 875 one-away) from
`escalate-preview --window 30`, generated after the floor at 2026-08-26 22:40 UTC.

```
bucket 1 (inert)        41    27x shared-egress:AS206092 + 14x WARP via CIDR
bucket 2 (hostile)       7    collapsed into review, see below
bucket 3 (human review) 1070  all dispositioned
```

`decisions.tsv`: 1,062 `ban-ok`, 7 `collapsed-to-review`, 4
`ban-ok-low-confidence`, 2 `insufficient-evidence`, **2 `DO-NOT-BAN`**.

**Bucket 2 was collapsed into review, per the handoff's own rule.** Auditing all
7 against the rotated archive (not just live logs) showed the bucket's predicate
— "no UA on ANY request" — was false for 4 of them: `157.230.19.140` had 7,595
requests with a UA, `93.123.109.101` 4,639, `143.244.168.161` 4,559. All 7 are
genuinely hostile (forged AI-crawler UAs from GCP with command injection,
webshell enumeration, Spamhaus DROP with UA rotation), but the bucket exists so
nobody reads them, and its stated evidence did not hold. Two are `leakix.net`, a
public research scanner.

---

## The two false positives — both real people

**FP-1** (a US commercial IPv4; the address is in `decisions.tsv` on cds1) —
161x304 + 3x200, one stable Chrome/114 on macOS, fetching jQuery and magazine
images from a customer magazine site. A browser revalidating cache. This is the
`request_flood` asset-burst mode already documented on 2026-07-27, recurring.

**FP-2** (a residential Comcast IPv6) — all 224 of its 404s are one
malformed-`srcset` path shape produced by the site's own markup. Scored
`rule=error_burst`, twice.

*Both addresses are deliberately not written here. This repo is public and these
are innocent third parties; the concrete values live in `decisions.tsv` on cds1
(mode 0700), the same way client specifics were redacted on 2026-08-04.*

### The second one is a class, and it is still running

Broken `srcset` markup makes a browser request the whole srcset value as one URL,
which always 404s. Fleet-wide:

```
17,829 requests   8,767 DISTINCT client IPs   128 browser UAs
3,198 residential IPv6 clients                35 sites
```

**35 hosted sites**, spanning customer sites and several of Peace Harbor's own
internal hosts. The single worst accounts for 10,889 of the hits; the next four
carry 400–1,700 each. Referer is each site's homepage. The site list is
deliberately not written here — this repo is public. Regenerate it on cds1 with
the `zgrep` above piped through `zgrep -l`.

Monthly volume shows it is **current, not historical**:

```
2026-Jan 3109   Feb 1747   Mar 839   Apr 2596   May 2510   Jun 953   Jul 538   Aug 2148
```

**Nineteen real visitors have already been temp-blocked by it** (six by
`error_burst`), overwhelmingly residential Comcast IPv6 with ordinary consumer
browser UAs. None permed yet. Exactly one was a gate D candidate.

Find them again with:

```bash
zgrep -h -E 'uploads/[0-9]{4}/[0-9]{2}/[^ ]*%20[0-9]+w,%20https:' /home/*/logs/*.gz
```

---

## Why the widen is blocked

The widen takes `REPEAT_WINDOW_DAYS` from 7 to 30. An IP perms at 3 temps
**inside the window**. Today these visitors mostly collect one temp and age out
within 7 days; at 30 days they have four times as long to reach three. One
candidate already had two.

A perm here is not just a block. With `ABUSEIPDB_REPORT="true"` it is a permanent
public abuse accusation, with no delete API, against a residential broadband
customer of a Peace Harbor client. That is the exact harm the step-4 freeze
bounds, and the exact thing gate D exists to catch.

**Two things gate the widen. The first is done; the second is not.**

---

## 1. DONE — swatter no longer scores this class (deployed 2026-08-28)

Branch `fix/gate-d-round5-and-srcset-false-positives`, commit `a729dd8`.

`lib/score.awk` gains `is_mangled_srcset()`. A 404 whose request path is a
browser faithfully fetching a broken srcset/sizes attribute is **dropped before
scoring** — not merely kept out of `cerr[]`/`cburst[]`, because counting it in
`reqs[]` while excluding it from `cerr[]` would be an `err_ratio` dilution lever
(50 probes at 100% become 500 requests at 10%) and would also inflate `rps` and
feed `request_flood`, the rule behind the *other* false positive.

Both review models broke the first version and were right about it: three
independent unanchored substring tests meant appending
`/uploads/2025/10/x.jpg%20300w,` to any path won the exemption, and the early
skip hid the request from badpath **and** honeypot scoring — a path that scored
90 before scored nothing after. It is now one **anchored positional** regex
(descriptor must immediately follow the image extension; dot-bearing prefix
segments refused, which is what stops `/.env/uploads/...`,
`/index.php/uploads/...` via PATH_INFO, and `/scan/path-1.html/uploads/...`),
gated at the call site on `path_scores_on_its_own()` so a bad-path or honeypot
hit is never exempted however it is dressed.

Verified on real production data per `CLAUDE.md`:

| | old scorer | new scorer |
|---|---|---|
| the false positive, 238 archived lines | **75 (banned)** | **not flagged** |
| control attacker `20.65.98.162` | 78 | **78** |
| all 27,574 live domlog lines | 4 IPs scored | **identical** |

27 score assertions green under both awk dialects; the nine reviewer bypass
strings are each pinned by name and fail against the broken version. `make test`
green, CI lint clean.

**DEPLOYED to cds1 2026-08-28 17:10 UTC.** Surgical-scp of `lib/score.awk` only,
per `CLAUDE.md`: staged from the live install, `/etc/cron.d/swatter` held OUTSIDE
`/etc/cron.d` at `/root/cron-hold-20260828/` during the swap, waited for any
in-flight scan, atomic `mv` into place, cron restored (both cron files verified
back with original timestamps, hold dir removed). Live file backed up to
`/root/score.awk.bak-20260828T171018Z`.

Post-deploy verification: `test-config` healthy and posture unchanged (enforce,
ladder ARMED, 2 ASNs, origin-lock drop, AbuseIPDB still on); `scan --dry-run`
clean; and the 17:15 scheduled `enforce` scan ran with no errors and correctly
blocked a real attacker (`34.123.132.35`, `critical_badpath`).

`sha256` of the installed file matches commit `a729dd8` exactly.

**RELEASED as v2.17.0 and fully deployed, 2026-08-28.** The earlier state — prod
running v2.16.1 plus one hand-copied file — is closed. `install/release.sh 2.17.0`
tagged and published to GitHub and GitLab after all three CI checks went green.

The release also carried `d396ad6`, the policy-file trailing-newline fix, which
had been committed but deliberately left undeployed on 08-20 so that a rate
anomaly could not be ambiguous. That reasoning no longer applies — the widen has
not happened, so there is nothing to confound.

Second deploy (`bin/swatter`, `lib/allowlist.sh`, `lib/asn.sh`,
`lib/origin_lock.sh`) used the same surgical procedure: every staged file
`bash -n` checked BEFORE anything was touched, cron held outside `/etc/cron.d`,
backups in `/root/deploy-bak-20260828T173728Z/`, cron restored and verified.

**All 32 installed files now sha-match the `v2.17.0` tag — zero drift.**
`origin-lock` still reports `ranges ok` and **`/etc/csf/csfpre.sh` is byte-identical
to before the deploy** (sha `5445ca24…`, 66 lines, 2 DROP/LOG rules), which was
the thing to watch: `lib/origin_lock.sh` gained per-line range validation, and a
too-aggressive prefix floor there could have dropped a real Cloudflare edge range
from the lock. It did not. Shared-egress still resolves for WARP v4, WARP v6,
`AS206092` and the new `AS137409`. The 17:40 scheduled enforce scan ran clean.

## 2. NOT DONE — the WordPress markup bug itself

Swatter now refuses to punish the symptom; the sites still emit it. The bad
markup is on the homepage of each affected site and the fleet shares the
component. Candidates worth checking first, by how many affected sites carry
them: `imagify` (23), `docket-cache` (16), `wp-rocket` (12),
`divi-contact-form-helper` (19). The paths mix root-relative and absolute URLs
in one srcset, which suggests a CDN/URL-rewrite pass rather than core WordPress.

This is web work in the hosting fleet, not a swatter change, and it was left
alone deliberately rather than diagnosed blind across 35 customer sites.

---

## Also outstanding

**`AS137409` needs adding to `shared-egress-asns.txt`.** `85.203.23.0/24` (4
candidates, `inert="-"`) belongs to GSL Networks, an operator already recognised
as a consumer-VPN exit via `194.5.82.0/24` — but it is listed as a **CIDR**, so
its other ranges are uncovered. The ASN arm is the durable fix. Owner approved on
2026-08-28; the agent was blocked from writing prod config, so this is still
pending:

```bash
ssh peaceharbor 'F=/etc/swatter/shared-egress-asns.txt
cp -p "$F" "$F.bak-$(date -u +%Y%m%d)"
printf "%s\n" "137409 # GSL Networks Pty LTD (AU) - VPN Consumer operator; already listed via 194.5.82.0/24 CIDR. ASN arm so all ranges are covered (85.203.23.0/24 escalating) - verified 2026-08-28 gate D review" >> "$F"
tail -c1 "$F" | od -c | head -1   # expect \n
swatter test-config | grep -i asns'   # expect 2 ASN(s)
```

`printf '%s\n'` guarantees the trailing newline. Config is read per-process, so
it takes effect on the next `*/5` scan.

**Three AbuseIPDB reports were lost** to `curl (28)` timeouts on 2026-08-25/26
(`4.232.148.111`, `20.220.227.7`, `45.138.16.62`). The marker is cleared on
failure and only retried if that IP perms again; none has. The TODO's pair-check
should stop being described as "empty = healthy" — it is not empty.

**`d396ad6` (policy-file final line) is still undeployed**, as noted on 08-20.

---

## Recommended order from here

1. ~~Deploy the scorer fix to cds1.~~ **DONE 2026-08-28 17:10 UTC.**
2. ~~Add `AS137409`.~~ **DONE 2026-08-28** — all four `85.203.23.x` addresses now
   resolve as `AS137409(GSL Networks…)` shared egress, verified end-to-end with
   DNS armed; `206092` control still resolves and an ordinary attacker still does
   not. Backup at `/etc/swatter/shared-egress-asns.txt.bak-20260828`.
3. **Cut a release** to close the v2.16.1 + one-file drift described above.
4. Fix the srcset markup on the fleet.
5. Only then: step 4 of the 08-20 handoff (freeze AbuseIPDB, `REPEAT_WINDOW_DAYS=30`,
   48h baseline, `shared-egress-audit`, restore reporting).

Re-run `escalate-preview` fresh at that point. This preview is now days old, and
reviewing a saved list is what the gate forbids.
