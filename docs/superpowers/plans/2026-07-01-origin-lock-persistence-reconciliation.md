# Origin-lock repo⇄live reconciliation (single-carrier csfpre) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **REVISION 2 (2026-07-01).** Rev 1's dual-carrier "Option C" (managed csfpre hook + systemd oneshot/timer safety-net) was **rejected** by Grok adversarial review (`…-review-grok.md`) AND invalidated by measurement: a prod survival matrix proved the csfpre lock **survives `csf -r`, `csf -ra`, and `systemctl restart lfd`** with zero drops. So **csfpre is a reliable single carrier on this host** — there is no persistence problem to engineer around. This revision drops systemd entirely and reduces the work to **drift + hygiene**. Re-review with Grok before the prod tasks (standing decision #2).

**Goal:** Make the repo own the live origin-lock: retire the untracked hand static csfpre block and enforce via the repo-managed csfpre hook (single owner = repo), on the Task-0-fixed lib, with the version stamp corrected.

**Architecture:** Origin-lock is an L3 iptables/CSF firewall wholly owned by Swatter (NOT a Cloudflare zone rule). The **single persistence carrier is `/etc/csf/csfpre.sh`**, which CSF re-sources on every `csf -r`/`csf -ra`/lfd-restart (measured durable). The managed block calls `swatter origin-lock apply --hook=csf`, which appends (`-A`) CF-ACCEPT → ACME → LOG → DROP onto the chain CSF has just flushed — correct order, no teardown-first path, reads `ORIGIN_LOCK` from `/etc/swatter/swatter.conf`. **No systemd unit, no timer, no dual carrier.**

**Tech Stack:** bash (macOS bash 3.2 for tests; RHEL/cPanel bash on prod), CSF v16.20 (cPanel), iptables-legacy + ipset.

## Global Constraints

- **Prod host:** `cds1.peaceharborhosting.com`, origin `67.225.133.76`, SSH alias `peaceharbor` (root). CSF `v16.20`, `FASTSTART="1"`, `LF_IPSET="1"` — **csfpre lock measured to survive all reload paths** (see Ground truth).
- **Deploy convention:** surgical `scp` of individual libs/hooks; **never** run `install.sh` remotely. Edit `/etc/csf/csfpre.sh` in place (preserve mode `0700`, owner `root:root`).
- **Whole-box blast radius:** any `csf -r`/`csf -ra`/lfd restart rebuilds the firewall for **every** customer site + WHMCS. Run attended, low-traffic window. Auto-mode blocks these unprompted — expect to run them via `!` or explicit approval.
- **Fail-open is sacred:** empty/under-min CF ranges install NOTHING; the csfpre managed block is guarded (`[ -x swatter ] && … || true`) so a broken binary fails OPEN, never a DROP without its preceding CF-ACCEPT.
- **Ordering invariant (top→bottom):** `CF-ACCEPT → ACME → LOG → DROP`, all above CSF's blanket `ctstate NEW --dport 80/443 ACCEPT`.
- **ACME carve-out:** whole `/.well-known/` on :80 stays (cPanel AutoSSL).
- **Rollback = restore the live csfpre backup**, NOT git (the hand static block was never in the repo). Back up `/etc/csf/csfpre.sh` to `csfpre.sh.bak-<UTC>` before every edit (match the existing `.bak-20260619-184214` pattern).
- **Public repo** `apps/swatter`: commit identity `Peace Harbor Studios <142285318+peaceharborco@users.noreply.github.com>`.

## Ground truth (verified live 2026-07-01)

- **Survival matrix (measured):** snapshot `ipset cf_origin4` entries + INPUT CF-ACCEPT/LOG/DROP counts before/after `csf -r`, `csf -ra`, `systemctl restart lfd`, then restore `csf -r`. Result: **15 / 1 / 1 / 1 throughout — zero drops.** csfpre is durable here; the handoff §4 "always wiped" premise is refuted.
- **Live enforcer = hand static csfpre block** (56 lines, `MODE="DROP"`, LOG `10/min`, inline `ipset`/`iptables`, does NOT call the lib). Repo-managed hook is absent; `/etc/swatter/swatter.conf` has no `ORIGIN_LOCK` line (→ off). No systemd unit.
- Live INPUT: `#16 ACME → #17 CF-ACCEPT(cf_origin4,15) → #18 LOG(10/min) → #19 DROP`, above CSF blanket `#31/#34`. CF site 200, direct-origin blocked.
- Deployed lib = 587 lines (pre Task-0); `swatter --version` prints stale `2.2.0`.

---

## Task 0 — DONE (committed + pushed): standalone apply ordering + teardown fixes

Committed on branch `fix/origin-lock-standalone-ordering` (GitHub+GitLab): teardown-first standalone apply, quoted LOG-rule `-D`, looped preamble `-D`, + `test/origin_lock_transition_test.sh`. All 30 suites green. **Not yet deployed to prod** (Task 2 Step 1). Note: the live static block never calls the lib, so this fix only affects the *managed* hook / standalone / disable paths — i.e. everything we switch TO in this plan.

---

## Task 1 — DONE (commit `1b9de30`): install.sh retires a legacy hand static origin-lock block

So a (re)install never doubles up, and so the retire logic used on prod (Task 2) is tested code, not an ad-hoc `sed`.

**Files:** Modify `install/install.sh` (add `_ol_retire_legacy_static`); Test `test/install_origin_lock_test.sh` (new).

**Interfaces:** Produces `_ol_retire_legacy_static <csfpre_path>` — backs up the file to `<path>.bak-<UTC>` (caller passes stamp via `SWATTER_NOW_STAMP` to stay deterministic for tests), then **comments out** (prefix `#RETIRED# `) any line matching an origin-lock signature (`cf_origin4`, `ORIGIN-LOCK`, `--match-set cf_origin`, or a `-j DROP` on `--dports 80,443`) that sits **outside** the managed `>>> … <<<` markers. Idempotent; never touches the managed block; never deletes (reversible).

- [ ] **Step 1: Write the failing test** — fixture csfpre with a hand static block (no markers) + a managed block; assert after retire: managed block intact, static `iptables … cf_origin4 … ACCEPT`/`… -j DROP` lines are `#RETIRED# `-prefixed, a `.bak-<stamp>` exists, and a second call is a no-op.
- [ ] **Step 2: Run → FAIL** (`_ol_retire_legacy_static: not found`).
- [ ] **Step 3: Implement** `_ol_retire_legacy_static` (awk; signature match outside markers; backup first; comment not delete).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Full suite** — `for t in test/*_test.sh; do bash "$t" >/dev/null || echo FAIL $t; done` → no FAIL.
- [ ] **Step 6: Commit** — `feat(install): retire (comment-out, backed-up) legacy hand static origin-lock block`.

## Task 2 — DONE (commit `1b9de30`): digest no longer depends on the static `MODE=` line

Grok Major: `swatter_origin_lock_status`/digest greps `^MODE=` from the hand static block (`lib/origin_lock.sh:580`) — goes stale/empty once the static block is retired.

**Files:** Modify `lib/origin_lock.sh` (`OL_MODE` resolution ~`:580`); Test: extend `test/origin_lock_test.sh` or `report` test.

- [ ] **Step 1: Failing test** — with no static `MODE=` line present and `ORIGIN_LOCK=drop` in conf, assert digest `OL_MODE == drop` (currently would fall to `?`/empty on the grep path).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — resolve mode from `_ol_mode` (conf) first; use the csfpre `^MODE=` grep only as a legacy fallback.
- [ ] **Step 4: Run → PASS; full suite green.**
- [ ] **Step 5: Commit.**

## Task 3 (PROD, GATED on Grok re-review): deploy fixed lib + switch static → managed hook

Single carrier throughout. The static block keeps enforcing until the managed hook is proven, so the origin is never unprotected.

- [ ] **Step 1 (PROD): deploy the Task-0 lib.** `scp lib/origin_lock.sh peaceharbor:/usr/local/lib/swatter/origin_lock.sh`; set `root:root 0644`. No firewall change yet (nothing calls it until the managed hook exists / conf armed).
- [ ] **Step 2 (PROD): real-iptables LOG-space validation** (Grok Major — the trailing-space `-D` fix is only proven in a model fake). On prod: `iptables -A INPUT -p tcp -m multiport --dports 80,443 -m limit --limit 5/min -j LOG --log-prefix "ORIGIN-LOCK: TEST "` then confirm `iptables -D INPUT … --log-prefix "ORIGIN-LOCK: TEST "` (quoted, trailing space) **removes it** on this iptables-legacy. If `-D` fails to match, STOP — the LOG-teardown fix does not hold on real iptables-legacy and must be reworked before relying on `disable`/off-teardown. (Use a throwaway `TEST ` prefix so it never collides with the live rule.)
- [ ] **Step 3 (PROD): arm the managed hook in the conf, DROP mode.** The origin-lock DROP posture is already battle-tested on this box (memory: enforce since 2026-06-19); the managed hook builds the *same* rules from the *same* `cloudflare.cidr`, so no separate LOG soak is needed — but keep the static block in place as the live enforcer during this step. Back up csfpre. Add the managed block to `/etc/csf/csfpre.sh` (exact content below), set `ORIGIN_LOCK=drop` in `/etc/swatter/swatter.conf`, `csf -r`.

  Managed block (verbatim, matches `install.sh:_install_origin_lock_csfpre`):
  ```sh
  # >>> swatter origin-lock (managed) >>>
  # Re-apply the Cloudflare-only web-port lock ahead of CSF's chains.
  # GUARDED: a missing/broken swatter binary fails OPEN (no rule added),
  # never leaving a DROP without its preceding Cloudflare ACCEPT.
  if [ -x /usr/local/bin/swatter ]; then
      /usr/local/bin/swatter origin-lock apply --hook=csf --yes || true
  fi
  # <<< swatter origin-lock (managed) <<<
  ```
  **`--yes` is mandatory** (else DROP silently no-ops at `csf -r` — return 3 swallowed by `|| true`; fixed in commit `1b9de30`). **Also verify `SWATTER_MODE="enforce"` is set** in `/etc/swatter/swatter.conf` first — otherwise `apply` dry-runs and installs nothing (`lib/origin_lock.sh:296`). Prod already runs enforce (memory `swatter-prod-posture`), but confirm before relying on the managed hook.
- [ ] **Step 4 (PROD): verify managed rules are correct + ordered** (with static still present — expect duplicate-but-harmless CF-ACCEPT/LOG/DROP from both owners). `iptables -L INPUT --line-numbers -n`: confirm a managed CF-ACCEPT sits above a managed DROP, LOG above DROP, and the whole set above CSF's blanket accept. `ipset list cf_origin4` = 15. Direct-origin still blocked; CF site 200.
- [ ] **Step 5 (PROD): retire the static block** using the tested function (not ad-hoc sed). `install.sh` isn't deployed to prod, so scp it to a temp path and source it source-only:
  ```sh
  scp install/install.sh peaceharbor:/tmp/swatter-install.sh
  ssh peaceharbor 'set -e
    . /tmp/swatter-install.sh --source-only
    SWATTER_OL_CSFPRE=/etc/csf/csfpre.sh _ol_retire_legacy_static /etc/csf/csfpre.sh
    sh -n /etc/csf/csfpre.sh && echo "csfpre parses OK" || { echo "BROKEN — restoring"; cp /etc/csf/csfpre.sh.bak-* /etc/csf/csfpre.sh; exit 1; }
    rm -f /tmp/swatter-install.sh'
  ```
  `_ol_retire_legacy_static` (commit `1b9de30`) backs csfpre up itself and wraps the hand block in an inert `: <<'MARKER'` here-doc, leaving the managed block active. **Only `csf -r` after `sh -n` passes** — never reload a broken csfpre.
- [ ] **Step 6 (PROD): verify single-owner enforcement.** Exactly ONE CF-ACCEPT/ACME/LOG/DROP set, correct order, above CSF blanket. `curl` CF site → 200; `curl --resolve peaceharborhosting.com:443:67.225.133.76 …` → timeout; `ORIGIN-LOCK:` LOG still records direct hits. Re-run the survival matrix once (managed-only) to confirm durability. **Rollback if anything regresses:** `cp /etc/csf/csfpre.sh.bak-<UTC> /etc/csf/csfpre.sh && csf -r` (restores the static block).

## Task 4 (PROD, GATED): fix stale `--version` stamp

- [ ] **Step 1:** Diagnose (`cat /usr/local/lib/swatter/VERSION 2>/dev/null; swatter --version` → `2.2.0`; compare to `bin/swatter`/HEAD). Per memory `swatter-version-bump`, a version *change* is a real release (bump `SWATTER_VERSION` + tag + GitHub/GitLab release); if only the deployed stamp is stale, redeploy the correct VERSION artifact surgically.
- [ ] **Step 2:** `ssh peaceharbor 'swatter --version'` matches HEAD.

## Task 5 (repo-only): docs + CHANGELOG

- [ ] Update `CHANGELOG.md` (Unreleased): standalone-apply ordering fix, LOG/preamble teardown fixes, install.sh legacy-retire, digest mode source, and — importantly — the **corrected persistence model** (csfpre is durable here; single carrier; NO systemd). Update README origin-lock section to the single-carrier model and remove any "FASTSTART wipes it / needs systemd" language. Commit.

## Task 6 (repo-only): update memory + retire the handoff's wrong premise

- [ ] Update `swatter-origin-lock-persistence-incident` (already reflects the survival-matrix refutation) and cross-link from `swatter-direct-origin-gap`. Note in the branch handoff (or a short addendum) that §4's root cause was refuted by measurement so a future reader doesn't re-engineer systemd.

## Task 7 (final): Grok re-review of THIS revision, then execute Tasks 3/4

- [ ] Run `/grok docs/superpowers/plans/2026-07-01-origin-lock-persistence-reconciliation.md`; save/refresh `…-review-grok.md`. Confirm the single-carrier design clears the Rev-1 blockers (no systemd/standalone-teardown-on-timer, rollback-from-backup, retire tested, LOG-space validated on prod, digest fixed). Fold any new blockers. Only then execute the prod tasks, attended.

---

## Self-review notes

- **Rev-1 Grok blockers, dispositioned:** dual-carrier coexistence → **removed** (no systemd); teardown-first on 5-min timer → **removed** (no timer; the managed hook uses `-A` append, not teardown-first); systemd `--yes`/`After=` → **removed** (no unit); rollback "from git" → **fixed** (csfpre backup, Global Constraints + Task 3 Step 6); retire heuristic fragile/untested → **Task 1** (tested, backup-first, comment-not-delete); LOG-space fake-only → **Task 3 Step 2** (real-iptables prod validation, gated STOP); digest `^MODE=` stale → **Task 2**; preamble single-shot `-D` → **already fixed in Task 0**.
- **Open question for Grok:** Task 3 Step 3 arms managed straight to DROP (no LOG soak) on the argument that the managed hook reproduces the already-proven lock from the same `cloudflare.cidr`, with the static block still enforcing as the safety net. Is the brief duplicate-owner window (both static + managed DROP present between Step 3 and Step 5) acceptable, or should the static block be retired in the SAME `csf -r` that arms the managed hook (one owner at all times, but no belt-and-suspenders)? Grok to weigh.
