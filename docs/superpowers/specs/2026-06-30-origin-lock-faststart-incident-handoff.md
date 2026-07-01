# Origin-lock ⇄ live ⇄ repo drift — incident + reconciliation handoff

> **RESOLVED — v2.3.1 (2026-07-01).** This handoff is a historical record; the
> reconciliation it describes is done and shipped. **Its §4 root-cause theory
> ("FASTSTART=1/LF_IPSET=1 wipes the csfpre origin-lock on every reload") was
> REFUTED by measurement** — a prod survival matrix showed the csfpre lock
> survives `csf -r`/`csf -ra`/lfd restart. The §5 apply-ordering bug and the §4
> "lingering LOG" anomaly were real and are fixed. The live lock is now the
> single repo-managed csfpre hook (the hand static block was retired). See
> `2026-07-01-origin-lock-persistence-reconciliation.md` (+ its `-review-grok*`
> passes) for the corrected design and the executed rollout.

**Date:** 2026-06-30 (Pacific) / 2026-07-01 UTC
**Host:** `cds1.peaceharborhosting.com` (prod), origin IP `67.225.133.76`
**Branch:** `docs/cf-block-failure-spec`
**Status at stop:** Origin-lock **DROP enforcing again and verified**, BUT **non-persistent** —
it is live-only and **will be wiped on the next `csf -r` / lfd restart** (see §4). This is the
#1 thing to fix next session.

---

## 0. TL;DR / where we are

- We set out to reconcile the "repo ⇄ live ⇄ Swatter origin-lock" drift.
- While inspecting, we discovered origin-lock was **completely down on prod** (origin exposed to
  direct-to-origin Cloudflare-bypass) — the live incident, not just doc drift.
- Root cause of the outage: **CSF `FASTSTART=1` + `LF_IPSET=1` wipes the csfpre-installed
  origin-lock** (ipset `cf_origin4` + the CF-ACCEPT/DROP) on every reload. csfpre is **not a
  reliable carrier** for origin-lock on this host.
- Restoring via `csf -r` **did not work** (reproduced — FASTSTART re-wipes it).
- Restoring via the Swatter standalone apply hit a **code bug**: a `log→drop` mode transition
  inserts the DROP **above** the CF-ACCEPT → **total outage** (I caused a brief one, then fixed it).
- Final restore used a **teardown + single fresh drop apply**, which orders correctly. Verified:
  CF sites up, direct-to-origin blocked.
- **Persistence is currently OFF** (the `disable` step stripped the csfpre hook). The live DROP
  will vanish on the next csf reload. **Re-arm command in §6.**

Two decisions the user already made this session:
1. Reconcile direction = **arm the Swatter managed hook, retire the static block** (single owner = repo).
2. Step-2 firewall design change must go through a **written plan + Grok review** before executing.

---

## 1. Architecture ground truth (verified)

- **Origin-lock is an L3 iptables/CSF firewall, wholly Swatter-owned.** It is NOT a Cloudflare
  zone rule → the "Cloudflare changes go through terminal-scripts" rule does **not** apply.
  `terminal-scripts` contains **zero** origin-lock logic; `cf-proxy-webmail.sh` and `lib/cf-lib.sh`
  only *reference* "the Swatter origin-lock" as an external neighbor.
- Swatter ships origin-lock as a **default-OFF managed csfpre hook** (`install/install.sh:30-95`),
  markers `# >>> swatter origin-lock (managed) >>>` … `<<<`, body `swatter origin-lock apply --hook=csf`.
- Real implementation: `lib/origin_lock.sh` (587 lines) — fail-open guard (empty/under-min CF
  ranges install nothing), ACME `/.well-known/` carve-out, v6 gating, live `cloudflare.cidr` refresh.
- Config default `ORIGIN_LOCK="off"` (`config/swatter.example.conf:314`; `off|log|drop`).

## 2. What was actually on prod (as found)

`/etc/csf/csfpre.sh` had **two** origin-lock mechanisms side by side:
1. **Static block (lines 1-56)** — hand-written `MODE="DROP"` origin lock (builds `cf_origin4`,
   CF-ACCEPT + ACME + LOG + DROP). References the 2026-06-14 bypass incident. *This was the
   intended enforcer.*
2. **Swatter managed hook (lines 57-64)** — appended after, `apply --hook=csf`.

- `/etc/swatter/swatter.conf` has **no `ORIGIN_LOCK` line** → resolves to `off` → managed hook is a
  **no-op** ("toggled off next to the static one").
- Prod `swatter --version` prints **2.2.0**, but the installed libs are **current**:
  `/usr/local/lib/swatter/origin_lock.sh` = 587 lines (matches HEAD), deployed Jun 29 22:55.
  → the **version string is stale**, the code is not. (Fix the stamp; surgical-scp deploy history.)
- Persistence path chosen at install = **csfpre only**; `swatter-origin-lock.service` systemd unit
  is **not installed** (`systemctl status` → "could not be found"). So csfpre was the sole carrier.

## 3. The live incident (found, verified)

At inspection, the live nft INPUT chain had **no DROP and no `cf_origin4` ipset** — only the
`ORIGIN-LOCK:` LOG rule lingered, and CSF's own blanket `--ctstate NEW --dport 443 ACCEPT` was
letting direct-to-origin traffic straight in. `ipset list cf_origin4` → "set does not exist".
Legacy iptables table = 0 rules (so nothing hidden there). Real non-CF hits were being logged live
(04:17-04:18 UTC, e.g. `SRC=87.252.100.19 DPT=443 SYN`). **Origin was exposed.**

Timeline (UTC): Jun 30 07:01 last good "ENFORCING (DROP) — 15 CF ranges" → **Jul 1 01:50 lfd
restarted** → Jul 1 03:20 `swatter refresh-feeds` (updated cidr, did NOT re-arm the lock) → found
down ~04:1x.

## 4. ROOT CAUSE — why csfpre origin-lock does not survive here

`/etc/csf/csf.conf`: **`FASTSTART = "1"`**, **`LF_IPSET = "1"`** (csf v16.20 cPanel), csf.conf
mtime 2026-06-18 (not a fresh flip). With FASTSTART, csf rebuilds INPUT via atomic
`iptables-restore` and (LF_IPSET) tears down/rebuilds the ipset space — **wiping `cf_origin4` and
the csfpre-added ACCEPT/DROP moments after csfpre runs.** Reproduced on both `csf -r` and `csf -ra`:
the ipset + DROP never persist; only the appended LOG survived (still-unexplained anomaly, low
priority). An **lfd restart** also drops them and does NOT re-source csfpre until the next full
`csf -r`.

**Implication for the plan:** "just arm the managed csfpre hook" is **NOT sufficient** — the managed
hook builds its lock from csfpre too and would be wiped identically. The durable fix must apply the
lock **after** CSF settles.

## 5. THE CODE BUG (must fix in repo, test-first)

`lib/origin_lock.sh` standalone path mis-orders on a **mode transition** (`log` already applied,
then `drop`):

- `_ol_ensure` (`:118-121`) = insert-if-absent via `-C … || -I INPUT …` (prepend to pos 1).
- The reverse-emit trick (`_ol_rules_family` `:159-161`, emit DROP,LOG,ACME,CF) yields correct
  order **only on a fresh apply from a clean chain**.
- On `log→drop`: CF/ACME/LOG already exist → their `-C` matches → no-op; only the **new DROP** gets
  `-I`-prepended to **position 1, above the CF-ACCEPT** → drops ALL 80/443 incl. Cloudflare = outage.
- `apply` does **not** teardown-first, so the transition path is broken.

**Reproduced live:** `ORIGIN_LOCK=log apply` then `ORIGIN_LOCK=drop apply --yes` put DROP at INPUT
rule #1 (confirmed via `iptables -L --line-numbers`) → sites down until I deleted that DROP.

**Fix direction (for TDD):** make standalone `apply` **teardown-first then rebuild in one pass**
(idempotent), OR have `_ol_emit_drop` insert at the correct position relative to the accepts rather
than pos 1. Add a regression test in `test/origin_lock_test.sh` that applies `log` then `drop` and
asserts DROP is drop-last (after CF-ACCEPT). Minor secondary: fresh drop apply currently lands DROP
just **above** the 5/min LOG (dropped packets not logged) — invariant wants LOG before DROP; fix
while here.

## 6. CURRENT PROD STATE (exactly as left) + re-arm

- Live INPUT (verified order): `[monitoring-accepts, lo, cf_origin4 ACCEPT (rule 4), ACME (5),
  DROP (6), LOG 5/min (7)]` → **enforcing correctly**. `cf_origin4` = 15 v4 entries.
- Verified: CF sites 200/301; direct-to-origin `67.225.133.76:443` **times out** (blocked).
- **Persistence = NONE** (`swatter origin-lock disable` stripped the csfpre managed block; systemd
  unit was never installed; the hand static block may still be in csfpre but is FASTSTART-wiped).
  **⇒ This DROP is live-only and will disappear on the next `csf -r` / lfd restart, reverting to
  EXPOSED.**

**Quick safe re-arm if it wipes before next session** (teardown-first avoids the §5 bug):
```sh
ssh peaceharbor 'swatter origin-lock disable; \
  ORIGIN_LOCK=drop /usr/local/bin/swatter origin-lock apply --yes; \
  iptables -L INPUT --line-numbers -n | grep -E "80,443|cf_origin4"'
# sanity: the cf_origin4 ACCEPT line number MUST be < the DROP line number.
```
Verify after: `curl -m10 -o/dev/null -w"%{http_code}\n" https://kootenaichurch.org/` (expect 200)
and `curl -m8 --resolve peaceharborhosting.com:443:67.225.133.76 https://peaceharborhosting.com/`
(expect timeout).

## 7. NEXT SESSION — reconciliation plan (needs written plan + Grok review before prod firewall changes)

1. **Fix the §5 ordering bug** in `lib/origin_lock.sh` (TDD, regression test). Deploy surgically
   (scp lib, per prod convention — never `install.sh` remote).
2. **Solve persistence under FASTSTART/LF_IPSET** — the core durable fix. Options to weigh:
   - Install + enable the **systemd unit** `install/swatter-origin-lock.service` (applies AFTER
     csf/lfd settle; add `After=csf.service lfd.service` and a restart hook / path unit or timer so
     an lfd restart re-arms). install.sh has `_install_origin_lock_systemd` but the CSF branch chose
     csfpre — decide whether CSF hosts should get **both** (csfpre for ordering + systemd for
     post-reload re-arm) or move off csfpre entirely.
   - OR integrate `cf_origin4` into CSF's own ipset/allow mechanism so FASTSTART preserves it.
3. **Arm the managed hook properly** (`ORIGIN_LOCK=drop` in `/etc/swatter/swatter.conf`) and
   **retire the hand static block** (csfpre lines 1-56) so there is a single owner = the repo.
   Gate: `log → verify → drop → verify → remove static → verify (CF up + direct blocked)`.
4. **Fix `install.sh`** so it detects & retires a legacy hand static origin-lock block (so fresh
   installs don't end up doubled), and so CSF hosts get resilient (post-reload) persistence.
5. **Fix the stale `--version`** (prints 2.2.0; libs are HEAD) via `version-stamp`.
6. **Update repo docs + CHANGELOG + memory** to reflect the real deployment model.
7. **Grok adversarial review** of the plan (save as `*-review-grok.md`), fold blockers, then execute.

## 8. Evidence log (key commands run this session — all read-only except the noted mutations)

- Read-only: dumped `csfpre.sh`, `csf.conf` (FASTSTART/LF_IPSET), `iptables -S/-L INPUT`,
  `ipset list`, origin-lock logger, systemd unit absence, csf version.
- **Mutations made:** `csf -r`/`csf -ra` (no effect); `ORIGIN_LOCK=log apply` (ok);
  `ORIGIN_LOCK=drop apply --yes` (**caused outage — DROP mis-ordered**); `iptables -D INPUT … DROP`
  (fixed outage); `swatter origin-lock disable` + fresh `ORIGIN_LOCK=drop apply --yes` (correct,
  current state). No changes committed to the repo. Working tree clean.
