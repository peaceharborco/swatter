# Origin-lock persistence & repo⇄live reconciliation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This plan is written for Grok adversarial review BEFORE any production firewall change** (standing decision #2 from the 2026-06-30 incident handoff). Save Grok's review as `2026-07-01-origin-lock-persistence-reconciliation-review-grok.md`, fold blockers, THEN execute. Repo-only tasks (1, 4, 5, 6) may proceed without waiting on Grok; every task that mutates the prod firewall (2, 3) is gated on it.

**Goal:** Make origin-lock persistence deterministic under CSF `FASTSTART=1`/`LF_IPSET=1`, and collapse the repo⇄live drift to a single owner (the repo-managed hook), retiring the untracked hand static csfpre block.

**Architecture:** Origin-lock is an L3 iptables/CSF firewall wholly owned by Swatter (NOT a Cloudflare zone rule — the "CF changes go through terminal-scripts" rule does not apply). Today the live enforcer is a 56-line *hand-written* static block in `/etc/csf/csfpre.sh` that inlines its own `ipset`/`iptables` and never calls the Swatter lib. We replace it with the repo's **managed csfpre hook** (`swatter origin-lock apply --hook=csf`) for correct ordering during `csf -r`, and add a **systemd oneshot + timer** safety-net that re-arms via the standalone path after lfd restarts / FASTSTART races that bypass csfpre. Single owner = the repo.

**Tech Stack:** bash (POSIX-ish, must run on macOS bash 3.2 for tests and on RHEL/cPanel bash for prod), CSF v16.20 (cPanel), iptables-legacy + ipset, systemd.

## Global Constraints

- **Prod host:** `cds1.peaceharborhosting.com`, origin IP `67.225.133.76`, SSH alias `peaceharbor` (login user `root`). CSF `v16.20 (cPanel)`, `FASTSTART="1"`, `LF_IPSET="1"`.
- **Deploy convention:** surgical `scp` of individual libs to `/usr/local/lib/swatter/` and hooks — **never** run `install.sh` remotely on prod. Match existing deploy-script patterns.
- **Fail-open guard is sacred:** an empty / under-min CF range list must install NOTHING (never a bare DROP that blackholes the origin). Preserve `_ol_ranges_healthy`.
- **Ordering invariant (top→bottom INPUT):** `lo/allow accepts → CF-ACCEPT → ACME-ACCEPT → LOG → DROP`, and the whole block must sit **above** CSF's blanket `ctstate NEW --dport 80/443 ACCEPT` (live rules #31/#34) so the DROP fires first.
- **ACME carve-out:** `/.well-known/` accept on :80 must remain (cPanel AutoSSL / Let's Encrypt HTTP-01), and the carve-out is the whole `/.well-known/` path, not just `acme-challenge` (per memory `swatter-origin-lock-cpanel-cf`).
- **No client-safety regressions:** managed_challenge / block posture for real traffic is unaffected; this is origin-lock only.
- **Tests must stay green on macOS bash 3.2** (no array-of-arrays, guard empty-array `set -u` expansions, no `mapfile`).
- **Public repo:** `apps/swatter` is public — commit identity `Peace Harbor Studios <142285318+peaceharborco@users.noreply.github.com>`, no secrets/hostnames beyond what's already public in docs.

---

## Ground truth (verified live 2026-07-01, read-only)

- **Live INPUT (enforcing, correct order):** `#16 ACME(:80 /.well-known/) → #17 CF-ACCEPT(cf_origin4, 15 ranges) → #18 LOG(ORIGIN-LOCK:, 10/min) → #19 DROP(80,443)`; CSF blanket accepts at `#31/#34` sit **below** the DROP. Direct-to-origin from an off-CF IP times out (blocked); `kootenaichurch.org` via CF = 200. **Origin is protected right now.**
- **Enforcer = hand static block** `/etc/csf/csfpre.sh` (56 lines, `MODE="DROP"`, `LOGPREFIX="ORIGIN-LOCK: "`, LOG `--limit 10/min`, self-contained inline `ipset`/`iptables` — does **not** call the lib). The repo-managed csfpre block was previously stripped by `swatter origin-lock disable`.
- **`/etc/swatter/swatter.conf` has no `ORIGIN_LOCK` line** → resolves `off` → the managed hook, if present, would no-op.
- **No systemd unit** (`swatter-origin-lock.service` "could not be found").
- **Deployed lib** `/usr/local/lib/swatter/origin_lock.sh` = 587 lines (matches HEAD), but `swatter --version` prints stale **2.2.0**.
- **§4 correction:** the static csfpre block is currently **surviving** reloads — so "FASTSTART always wipes csfpre" is **not** reliably true. Persistence is **intermittent/nondeterministic** (the handoff observed a wipe; today it is intact). The plan must (a) empirically characterize what survives which reload, and (b) add a deterministic safety-net so the answer stops mattering.

---

## Task 0 (DONE — commit pending): standalone apply ordering + LOG-teardown fix

Already implemented this session via TDD; needs commit. Reproduces & fixes the §5 outage bug and root-causes the §4 "lingering LOG" anomaly.

**Files:**
- Modify: `lib/origin_lock.sh` (standalone teardown-first in `swatter_origin_lock_apply`; quoted `--log-prefix` delete loop in `_ol_teardown_family`)
- Create: `test/origin_lock_transition_test.sh` (chain-model regression: `log→drop` keeps CF-ACCEPT and LOG above DROP)

**Interfaces:**
- Produces: `swatter_origin_lock_apply <hook>` now tears down its own rules first when `hook != csf` (csf hook path unchanged — flushed by `csf -r`). `_ol_teardown_family` now reliably removes the LOG rule.

- [ ] **Step 1: Verify green** — Run: `for t in test/*_test.sh; do bash "$t" >/dev/null || echo "FAIL $t"; done; echo done`  Expected: `done` with no FAIL lines (30 suites).
- [ ] **Step 2: Commit on a branch** (do not commit to `main`; branch off `docs/cf-block-failure-spec` which carries the handoff)

```bash
git checkout docs/cf-block-failure-spec 2>/dev/null || git checkout -b origin-lock-persistence-reconcile
git checkout -b fix/origin-lock-standalone-ordering
git add lib/origin_lock.sh test/origin_lock_transition_test.sh docs/superpowers/plans/2026-07-01-origin-lock-persistence-reconciliation.md
git commit -m "fix(origin-lock): teardown-first standalone apply + reliable LOG-rule teardown

Standalone apply mis-ordered on a log->drop transition: the new DROP -I-prepended
to INPUT pos 1, above the CF-ACCEPT -> total origin outage (2026-06-30 incident §5).
Tear the module's own rules down first so the rebuild lands on a clean, correctly
ordered chain (csf hook path unchanged — csf -r flushes it).

Also: _ol_teardown_family consumed its delete patterns unquoted, word-splitting the
trailing space off the LOG --log-prefix so -D never matched — the 'only the appended
LOG survived' anomaly (§4). Delete the LOG rule with a quoted prefix.

Regression: test/origin_lock_transition_test.sh models the INPUT chain and asserts
CF-ACCEPT and LOG stay above DROP after a log->drop transition."
```

---

## Task 1 (repo-only): install.sh retires a legacy hand static origin-lock block

So a fresh/again install never ends up doubled (managed hook + hand static block), and so `install.sh` can adopt an existing hand-block host cleanly.

**Files:**
- Modify: `install/install.sh` (origin-lock persistence install section, ~`:30-95`)
- Test: `test/install_origin_lock_test.sh` (new) or extend `test/persist_test.sh`

**Interfaces:**
- Consumes: existing marker constants `# >>> swatter origin-lock (managed) >>>` / `<<<`.
- Produces: `_ol_retire_legacy_static <csfpre_path>` — detects a hand static block (heuristic: a `cf_origin4` / `ORIGIN-LOCK:` body **outside** the managed markers) and comments it out or removes it, idempotently, preserving file perms.

- [ ] **Step 1: Write the failing test** — a csfpre fixture containing BOTH a hand static block (no markers) and nothing else; assert `_ol_retire_legacy_static` removes/neutralizes the static `iptables ... cf_origin4 ... -j DROP` lines and leaves a single managed marker block after install.

```bash
# test/install_origin_lock_test.sh (sketch — fill with real fixture)
tmp=$(mktemp -d); pre="$tmp/csfpre.sh"
cat > "$pre" <<'EOF'
#!/bin/sh
SET4="cf_origin4"
ipset create "$SET4" hash:net family inet -exist
iptables -I INPUT -p tcp -m multiport --dports 80,443 -m set --match-set "$SET4" src -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j DROP
EOF
_ol_retire_legacy_static "$pre"
grep -q 'swatter origin-lock (managed)' "$pre" && ! grep -qE '^iptables .*cf_origin4.* -j ACCEPT' "$pre"
```

- [ ] **Step 2: Run test to verify it fails** — Run: `bash test/install_origin_lock_test.sh`  Expected: FAIL (`_ol_retire_legacy_static: command not found`).
- [ ] **Step 3: Implement `_ol_retire_legacy_static`** in `install/install.sh` (awk-based, mark the retired block with `# retired-by-swatter (legacy static origin-lock)` rather than silent deletion; no-op when only the managed block exists).
- [ ] **Step 4: Run test to verify it passes.**
- [ ] **Step 5: Run full suite** — Run: `for t in test/*_test.sh; do bash "$t" >/dev/null || echo FAIL $t; done`  Expected: no FAIL.
- [ ] **Step 6: Commit** — `git commit -am "feat(install): retire legacy hand static origin-lock block on (re)install"`

---

## Task 2 (PROD, GATED on Grok + Task 0/1 deployed): deterministic persistence

**Decision to ratify with Grok — persistence design.** Recommendation: **Option C (managed csfpre hook + systemd timer safety-net).** Alternatives documented so Grok can push back.

| Option | Mechanism | Pro | Con |
|---|---|---|---|
| **A. systemd only** | oneshot `swatter-origin-lock.service` + timer every 5 min, `After=csf.service lfd.service` | reload-agnostic; deterministic | brief teardown-first window each fire; rules land via `-I` (top of INPUT) — ordering vs csf rules needs care |
| **B. csf-native ipset** | register `cf_origin4` with csf so FASTSTART preserves it | uses csf's own machinery | csf has no "drop-all-except-set on ports" primitive; awkward/unsupported |
| **C. hook + systemd (recommended)** | managed csfpre hook = primary (correct order during `csf -r`); systemd oneshot+timer = re-arm after lfd/FASTSTART races | belt-and-suspenders; single repo owner; survives every reload path | two carriers to keep consistent; must prove they don't duplicate/mis-order |

**Files (repo side, prerequisite of the prod step):**
- Verify/adjust: `install/swatter-origin-lock.service` and `install/install.sh:_install_origin_lock_systemd` (add `After=csf.service lfd.service`, `Wants=network-online.target`; oneshot `ExecStart=/usr/local/bin/swatter origin-lock apply --yes`).
- Create: `install/swatter-origin-lock.timer` (`OnBootSec=2min`, `OnUnitActiveSec=5min`, `Persistent=true`).
- Test: extend `test/persist_test.sh` — unit/timer content assertions (After= ordering, oneshot, apply invocation).

- [ ] **Step 1 (repo, TDD): timer/unit content test** — assert the generated `.service` has `After=csf.service lfd.service` and `Type=oneshot`, and the `.timer` has `OnUnitActiveSec=5min`. Run → FAIL → implement generator → PASS → commit.
- [ ] **Step 2 (PROD diagnostic — read-only, run FIRST): characterize reload survival.** On prod, with the CURRENT static block in place, record `iptables -L INPUT --line-numbers -n | grep -nE 'cf_origin4|ORIGIN-LOCK|DROP'` and `ipset list cf_origin4 | grep entries` before/after each of: `csf -r`, `csf -ra`, `systemctl restart lfd`, and (scheduled) a reboot. **This is the empirical answer to §4.** Capture to the handoff evidence log. Do NOT proceed to Step 3 until survival matrix is known.
- [ ] **Step 3 (PROD, GATED): deploy fixed lib + managed hook in LOG mode.** `scp lib/origin_lock.sh` (Task 0) to `/usr/local/lib/swatter/`. Install the managed csfpre hook (idempotent markers) and set `ORIGIN_LOCK=log` in `/etc/swatter/swatter.conf`. `csf -r`. Verify the managed hook's LOG rules appear and the hand static block is still present (do NOT remove it yet — belt-and-suspenders during validation). Sanity: CF sites 200, direct-origin still blocked (by the static DROP).
- [ ] **Step 4 (PROD, GATED): install systemd oneshot + timer.** `scp` unit+timer, `systemctl daemon-reload`, `systemctl enable --now swatter-origin-lock.timer`. Confirm `systemctl list-timers | grep swatter` and that a manual `systemctl start swatter-origin-lock.service` re-arms without outage (watch `iptables -L INPUT -n --line-numbers` before/after: CF-ACCEPT line# < DROP line#).
- [ ] **Step 5 (PROD, GATED): flip managed hook to DROP, retire static block.** Set `ORIGIN_LOCK=drop`; `csf -r`; verify the managed DROP is present and correctly ordered. THEN run `_ol_retire_legacy_static` (Task 1) against `/etc/csf/csfpre.sh` to neutralize the hand block; `csf -r`; verify single-owner enforcement: exactly one CF-ACCEPT/LOG/DROP set, CF-ACCEPT above DROP, DROP above CSF's blanket accept. Re-run the Step-2 survival matrix to confirm the systemd safety-net re-arms after lfd restart.
- [ ] **Step 6 (PROD verify):** `curl` CF site → 200; `curl --resolve peaceharborhosting.com:443:67.225.133.76` → timeout; confirm `ORIGIN-LOCK:` LOG still records direct hits. Roll-back note: `swatter origin-lock disable` + re-add the static block from git history if anything regresses.

---

## Task 3 (PROD, GATED): fix stale `--version` stamp

**Files:** Modify: whatever `version-stamp` / `SWATTER_VERSION` mechanism drives `swatter --version` (verify `bin/swatter` reads `SWATTER_VERSION`); redeploy the version file/lib surgically.

- [ ] **Step 1:** Identify why prod prints `2.2.0` while libs are HEAD (stale `VERSION` file or unstamped deploy). Run: `ssh peaceharbor 'cat /usr/local/lib/swatter/VERSION 2>/dev/null; swatter --version'`.
- [ ] **Step 2:** Re-stamp to the current release (per memory `swatter-version-bump`: this is a real release action — bump `SWATTER_VERSION`, tag, GitHub+GitLab release if the version changes; if only the prod stamp is stale, redeploy the correct VERSION artifact).
- [ ] **Step 3:** Verify `ssh peaceharbor 'swatter --version'` matches HEAD.

---

## Task 4 (repo-only): docs + CHANGELOG + README

- [ ] **Step 1:** Update `CHANGELOG.md` (Unreleased): the standalone-apply ordering fix, the LOG-teardown fix, install.sh legacy-retire, and the systemd persistence safety-net.
- [ ] **Step 2:** Update README/origin-lock docs to describe the real deployment model on CSF hosts: **managed csfpre hook (primary) + systemd timer (re-arm)**, and that the hand static block is retired.
- [ ] **Step 3:** Commit.

---

## Task 5 (repo-only): update memory

- [ ] Update `swatter-direct-origin-gap.md` and `swatter-origin-lock-cpanel-cf.md`: (a) §4 anomaly root-caused (trailing-space teardown mismatch → LOG lingered); (b) FASTSTART wipe is intermittent, not absolute; (c) new persistence model (hook + systemd timer); (d) live enforcer was the untracked hand static block until reconciliation.

---

## Task 6 (final): Grok adversarial review of THIS plan

- [ ] Submit this document to Grok; save as `docs/superpowers/specs/2026-07-01-origin-lock-persistence-reconciliation-review-grok.md`. Fold blockers (esp. Task 2 ordering-interaction between the csf-hook append and the systemd standalone `-I` re-arm, and the teardown-first window on a live enforcing chain). Only then execute Tasks 2/3.

---

## Self-review notes

- **Spec coverage vs handoff §7:** (1) §5 fix → Task 0 ✓; (2) persistence → Task 2 ✓; (3) arm hook + retire static → Task 2 Step 5 ✓; (4) install.sh legacy detect → Task 1 ✓; (5) version stamp → Task 3 ✓; (6) docs/memory → Tasks 4/5 ✓; (7) Grok review → Task 6 ✓.
- **Key open risk for Grok:** do the managed csf-hook (`-A` on flushed chain) and the systemd standalone re-arm (`-I`, teardown-first) ever coexist in a way that duplicates rules or lands the DROP above CF-ACCEPT / below CSF's accept? The teardown-first fix (Task 0) makes repeated standalone applies safe, but the interaction with csf's own restart timing is the thing to prove on the LOG-mode gate (Task 2 Step 3) before DROP.
