# Swatter Nightly Report Rework — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework the nightly `swatter report` email into a structured, Title-Case HTML report with an opt-in Origin-Lock plane, a dated verdict-led subject, and config-driven DST-aware scheduling.

**Architecture:** Split `lib/report.sh` into three responsibilities — a **gather** layer that computes per-plane counts and detail rows into globals, and two renderers (**text** for `--print`/non-HTML clients, **HTML** for the "Direction B" structured email) that consume the same gathered data so they stay in parity. A new read-only `swatter_originlock_section` in `lib/origin_lock.sh` (mirroring `swatter_errors_section`) adds the third plane. `install.sh` generates the report cron line from config so the schedule is DST-correct and survives reinstalls.

**Tech Stack:** Bash + awk + jq (existing), cronie (`CRON_TZ`), sendmail/sendgrid/brevo via `swatter_send_email`. Tests are the repo's hermetic `bash test/*_test.sh` harness.

## Global Constraints

- Shell convention: `set -uo pipefail`, **NOT `-e`** (one failing source must not abort a run). `TZ=UTC` everywhere.
- Lint gate (CI): `shellcheck --severity=error bin/swatter lib/*.sh install/*.sh test/*.sh` must pass.
- Test gate: `make test` — every `test/*_test.sh` reports `0 failed`.
- Scope: report/email layer + cron scheduling only. **No** scoring/classification/blocking changes.
- Wording: the report is titled **"Swatter Nightly Report"** (not "digest"). Title Case on chrome (title, section headers, stat-tile labels, table column headers); data values unchanged.
- Backward compatible: new config keys default to current behavior; origin-lock section auto-hides with zero hits.
- Decision-log action vocabulary already includes the `skipped-*`/`failed` set; only `perm`/`temp` count as blocks.
- Reference design: `docs/superpowers/specs/2026-06-25-nightly-report-rework-design.md`. Target version **2.2.0**.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

- `lib/common.sh` — add 4 config defaults (`ORIGIN_LOCK_DIGEST`, `ORIGIN_LOCK_LOG`, `REPORT_CRON`, `REPORT_CRON_TZ`).
- `lib/origin_lock.sh` — add `swatter_originlock_section` (read-only digest) + `_ol_digest_should_render`.
- `lib/report.sh` — split into `swatter_report_gather` / `_report_render_text` / `_report_render_html`; new verdict + subject; plane assembly + degradation.
- `install/swatter.cron` — template becomes a base; report line + optional `CRON_TZ` generated.
- `install.sh` — generate the report cron line from `REPORT_CRON`/`REPORT_CRON_TZ` (modify the install at line 149).
- `config/swatter.example.conf` — document the 4 new keys.
- `bin/swatter` — version bump to 2.2.0 (final task).
- `test/config_defaults_test.sh` — assert new defaults (extend).
- `test/origin_lock_test.sh` — assert section counts/tags/gating (extend).
- `test/report_test.sh` — **new**: gather, verdict, subject, planes/degradation, text + HTML structure.
- `test/report_cron_test.sh` — **new**: cron-line generation for empty vs set TZ.

---

## Task 1: Config foundation

**Files:**
- Modify: `lib/common.sh` (defaults block, near the other `REPORT_*`/`ERROR_DIGEST_*` keys ~line 141-152)
- Modify: `config/swatter.example.conf` (after the error-digest block ~line 222-230)
- Test: `test/config_defaults_test.sh`

**Interfaces:**
- Produces: globals `ORIGIN_LOCK_DIGEST` (default `"auto"`), `ORIGIN_LOCK_LOG` (default `""`), `REPORT_CRON` (default `"0 4"`), `REPORT_CRON_TZ` (default `""`).

- [ ] **Step 1: Write the failing test** — append to `test/config_defaults_test.sh` before the summary line:

```bash
check report-cron-default     "${REPORT_CRON}" "0 4"
check report-cron-tz-default  "${REPORT_CRON_TZ}" ""
check ol-digest-default       "${ORIGIN_LOCK_DIGEST}" "auto"
check ol-log-default          "${ORIGIN_LOCK_LOG}" ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash test/config_defaults_test.sh`
Expected: FAIL — `REPORT_CRON: unbound variable` (or want/got mismatch) since the keys don't exist yet.

- [ ] **Step 3: Add the defaults** in `lib/common.sh`, immediately after the `ERROR_DIGEST_LOG=""` line (~152):

```bash
# Origin-lock digest plane (nightly report). auto = render when the window has
# ORIGIN-LOCK: hits (works for the standalone csfpre.sh lock AND the inline lock);
# on = always; off = never. ORIGIN_LOCK_LOG empty = /var/log/messages* (Debian: syslog).
ORIGIN_LOCK_DIGEST="auto"
ORIGIN_LOCK_LOG=""

# Nightly report schedule. install.sh writes /etc/cron.d/swatter from these.
# REPORT_CRON is "minute hour". REPORT_CRON_TZ is the delivery timezone (IANA);
# empty = the server clock (UTC on a normal server). Set it to deliver at a true
# local wall-clock hour, DST-aware via cron's CRON_TZ.
REPORT_CRON="0 4"
REPORT_CRON_TZ=""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash test/config_defaults_test.sh`
Expected: PASS (`Total: N passed, 0 failed`, N increased by 4).

- [ ] **Step 5: Document the keys** in `config/swatter.example.conf`, after the error-digest block (~line 230):

```bash
# ---- origin-lock digest plane (nightly report) ----------------------------
# When the nightly report runs and the window has any origin-lock drops, a
# "Origin-Lock" section is included: total direct-to-origin hits dropped, source
# IPs, the 80/443 split, and the top sources tagged attacker/legit. "auto" shows
# it only when there are hits; "on" always; "off" never.
ORIGIN_LOCK_DIGEST="auto"
# Syslog source for ORIGIN-LOCK: lines. Empty = /var/log/messages* (RHEL/cPanel).
# Debian/Ubuntu: set to /var/log/syslog.
ORIGIN_LOCK_LOG=""

# ---- nightly report schedule ----------------------------------------------
# install.sh writes /etc/cron.d/swatter from these. REPORT_CRON is "minute hour".
# Your server clock is almost certainly UTC. To get the report at 4am in YOUR
# timezone, set REPORT_CRON_TZ to your IANA zone, e.g. America/Los_Angeles —
# cron then delivers at that exact wall-clock hour, following DST. Empty = UTC.
REPORT_CRON="0 4"
REPORT_CRON_TZ=""
```

- [ ] **Step 6: Commit**

```bash
git add lib/common.sh config/swatter.example.conf test/config_defaults_test.sh
git commit -m "feat(report): add origin-lock-digest + report-schedule config keys

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Origin-Lock digest section

**Files:**
- Modify: `lib/origin_lock.sh` (append the digest function near the end, after the apply/status functions)
- Test: `test/origin_lock_test.sh`

**Interfaces:**
- Consumes: `swatter_now`, `_report_window_secs` (from report.sh — already loaded before origin_lock in `bin/swatter`'s module order; the test sources both), `ORIGIN_LOCK_LOG`, `STATE_DIR`.
- Produces:
  - `_ol_digest_should_render <hits>` → returns 0 (render) / 1 (skip) per `ORIGIN_LOCK_DIGEST`.
  - `swatter_originlock_section <window>` → emits the plain-text section on stdout; sets globals `OL_HITS OL_IPS OL_P80 OL_P443 OL_MODE OL_TOP_ROWS` (the last is TSV `ip<TAB>hits<TAB>tag`, top 10).

- [ ] **Step 1: Write the failing test** — append to `test/origin_lock_test.sh` (before its summary). It builds a synthetic syslog + feed/cidr fixtures, points `ORIGIN_LOCK_LOG` at them, and asserts counts, the 80/443 split, tagging, and gating:

```bash
# --- origin-lock digest section ---------------------------------------------
OLD_STATE="$STATE_DIR"
DIG="$(mktemp -d "${TMPDIR:-/tmp}/swatter-oldig.XXXXXX")"; STATE_DIR="$DIG"
mkdir -p "$DIG/feeds"
printf '45.135.232.17\n193.32.162.40\n' > "$DIG/feeds/ipsum.txt"   # 2 known attackers
ORIGIN_LOCK_LOG="$DIG/messages"
# 3 sources: 45.. (attacker, :80 x2), 193.. (attacker, :443 x1), 198.51.100.7 (unknown, :80 x1)
cat > "$DIG/messages" <<'LOG'
Jun 25 03:00:01 cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=45.135.232.17 DPT=80 SPT=51000
Jun 25 03:01:01 cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=45.135.232.17 DPT=80 SPT=51002
Jun 25 03:02:01 cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=193.32.162.40 DPT=443 SPT=4000
Jun 25 03:03:01 cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=198.51.100.7 DPT=80 SPT=4002
LOG
ORIGIN_LOCK_DIGEST="auto"
out="$(swatter_originlock_section 24h)"
check ol-hits   "$OL_HITS" "4"
check ol-ips    "$OL_IPS"  "3"
check ol-p80    "$OL_P80"  "3"
check ol-p443   "$OL_P443" "1"
check ol-top-attacker "$(printf '%s\n' "$OL_TOP_ROWS" | awk -F'\t' '$1=="45.135.232.17"{print $3}')" "attacker"
check ol-gate-auto-hits "$(_ol_digest_should_render 4 && echo show || echo hide)" "show"
ORIGIN_LOCK_DIGEST="auto"
check ol-gate-auto-zero  "$(_ol_digest_should_render 0 && echo show || echo hide)" "hide"
ORIGIN_LOCK_DIGEST="on"
check ol-gate-on-zero    "$(_ol_digest_should_render 0 && echo show || echo hide)" "show"
ORIGIN_LOCK_DIGEST="off"
check ol-gate-off-hits   "$(_ol_digest_should_render 4 && echo show || echo hide)" "hide"
STATE_DIR="$OLD_STATE"; rm -rf "$DIG"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash test/origin_lock_test.sh`
Expected: FAIL — `swatter_originlock_section: command not found` / `_ol_digest_should_render: command not found`.

- [ ] **Step 3: Implement** in `lib/origin_lock.sh` (append near the end of the file):

```bash
# --- nightly-report digest section (read-only) ------------------------------
# Resolve the syslog source(s) holding ORIGIN-LOCK: lines.
_ol_digest_logs() {
    if [[ -n "${ORIGIN_LOCK_LOG}" ]]; then printf '%s' "${ORIGIN_LOCK_LOG}"; return; fi
    printf '/var/log/messages'
}

# Gate: should the section render given <hits> in the window?
_ol_digest_should_render() {
    local hits="${1:-0}"
    case "${ORIGIN_LOCK_DIGEST:-auto}" in
        on)  return 0 ;;
        off) return 1 ;;
        *)   (( hits > 0 )) ;;   # auto: render only when there were drops
    esac
}

# Is <ip> in a swatter threat feed (attacker) or an allow/monitoring range (legit)?
_ol_tag_ip() {
    local ip="$1" f
    for f in "${STATE_DIR}/feeds/"ipsum.txt "${STATE_DIR}/feeds/"blocklist_de.txt \
             "${STATE_DIR}/feeds/"cins.txt "${STATE_DIR}/feeds/"greensnow.txt \
             "${STATE_DIR}/feeds/"et_compromised.txt; do
        [[ -r "$f" ]] && grep -qxF "$ip" "$f" 2>/dev/null && { printf 'attacker'; return; }
    done
    local c
    for c in /etc/swatter/monitoring.cidr /etc/swatter/allow.cidr; do
        [[ -r "$c" ]] && grep -qF "$ip" "$c" 2>/dev/null && { printf 'legit'; return; }
    done
    printf 'uncategorized'
}

# swatter_originlock_section <window> — emits the plain-text Origin-Lock section
# and sets OL_* globals for the renderers. Read-only.
swatter_originlock_section() {
    local window="$1" cutoff
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    OL_HITS=0 OL_IPS=0 OL_P80=0 OL_P443=0 OL_MODE="" OL_TOP_ROWS=""

    local logs; logs="$(_ol_digest_logs)"
    local hits; hits="$(grep -hE "ORIGIN-LOCK:" $logs 2>/dev/null || true)"
    OL_HITS=$(printf '%s\n' "$hits" | grep -c . || true)
    [[ "$OL_HITS" -gt 0 ]] || { OL_HITS=0; echo "Origin-lock: no direct-to-origin drops in the last ${window}."; return 0; }

    OL_P80=$(printf '%s\n' "$hits"  | grep -oE 'DPT=80\b'  | grep -c . || true)
    OL_P443=$(printf '%s\n' "$hits" | grep -oE 'DPT=443\b' | grep -c . || true)
    OL_MODE="$(grep -m1 '^MODE=' "${SWATTER_OL_CSFPRE:-/etc/csf/csfpre.sh}" 2>/dev/null | sed 's/.*=//; s/"//g; s/ .*//' || true)"
    [[ -n "$OL_MODE" ]] || OL_MODE="$( [[ "$(_ol_mode)" == off ]] && echo "?" || echo "$(_ol_mode)" )"

    local srcs; srcs="$(printf '%s\n' "$hits" | grep -oE 'SRC=[0-9a-fA-F:.]+' | sed 's/SRC=//' | sort | uniq -c | sort -rn)"
    OL_IPS=$(printf '%s\n' "$srcs" | grep -c . || true)

    local ip n tag
    while read -r n ip; do
        [[ -n "$ip" ]] || continue
        tag="$(_ol_tag_ip "$ip")"
        OL_TOP_ROWS+="${ip}"$'\t'"${n}"$'\t'"${tag}"$'\n'
    done < <(printf '%s\n' "$srcs" | head -10)

    {
        echo "Direct-to-origin drops: ${OL_HITS} from ${OL_IPS} IPs  (:80 ${OL_P80} · :443 ${OL_P443}; mode ${OL_MODE})"
        echo
        echo "Top sources"
        echo "-----------"
        printf '%s' "$OL_TOP_ROWS" | awk -F'\t' '{printf "  %-16s %5s  %s\n",$1,$2,$3}'
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash test/origin_lock_test.sh`
Expected: PASS. (`ol-hits=4`, `ol-ips=3`, `ol-p80=3`, `ol-p443=1`, `45.135.232.17→attacker`, gating show/hide/show/hide.)

- [ ] **Step 5: Lint**

Run: `shellcheck --severity=error lib/origin_lock.sh`
Expected: exit 0. (Note: `grep -hE … $logs` intentionally word-splits `$logs` for the glob; if shellcheck flags SC2086, add `# shellcheck disable=SC2086` on that line with a comment that multi-path globbing is intended.)

- [ ] **Step 6: Commit**

```bash
git add lib/origin_lock.sh test/origin_lock_test.sh
git commit -m "feat(report): read-only origin-lock digest section + gating

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Verdict + dated subject + "Report" wording

**Files:**
- Modify: `lib/report.sh` (subject block ~256-268; title strings line 68 + 192)
- Test: `test/report_test.sh` (new)

**Interfaces:**
- Consumes: `RPT_PERM RPT_TEMP RPT_ACTED RPT_EXEMPT ERR_GENUINE ERR_FATAL OL_HITS` (gather globals; in this task they may be pre-set by the test).
- Produces:
  - `_report_verdict` → echoes `LEVEL<TAB>SUMMARY` where LEVEL ∈ `green|amber|red` and SUMMARY is the verdict-led count string.
  - `_report_subject <window>` → echoes `Report <YYYY-MM-DD> - <summary>` (UTC date).

- [ ] **Step 1: Write the failing test** — create `test/report_test.sh`:

```bash
#!/usr/bin/env bash
# test/report_test.sh — nightly report: verdict, subject, planes/degradation, render.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Fixed UTC date for the subject assertion (override swatter_now via SOURCE_DATE).
swatter_now() { echo 1782396000; }   # 2026-06-25 (UTC)
DATE_UTC="$(date -u -d "@1782396000" +%F 2>/dev/null || date -u -r 1782396000 +%F)"

# verdict: green when only blocks, amber when genuine non-FATAL errors, red on FATAL.
RPT_PERM=36 RPT_TEMP=162 RPT_ACTED=198 RPT_EXEMPT=0 OL_HITS=0 ERR_GENUINE=0 ERR_FATAL=0
check verdict-green "$(_report_verdict | cut -f1)" "green"
ERR_GENUINE=4 ERR_FATAL=0
check verdict-amber "$(_report_verdict | cut -f1)" "amber"
ERR_GENUINE=4 ERR_FATAL=2
check verdict-red   "$(_report_verdict | cut -f1)" "red"

# subject: "Report YYYY-MM-DD - <summary>"
ERR_GENUINE=0 ERR_FATAL=0
check subject-shape "$(_report_subject 24h)" "Report ${DATE_UTC} - healthy · 198 blocked, 0 FATAL"
OL_HITS=253
check subject-ol "$(_report_subject 24h | grep -c '253 origin-lock')" "1"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash test/report_test.sh`
Expected: FAIL — `_report_verdict: command not found`.

- [ ] **Step 3: Implement** in `lib/report.sh`. Add the two helpers above `swatter_report` (~line 220). The green summary reads `healthy · 198 blocked, 0 FATAL`; amber/red lead with a `⚠` marker (so a bad night is visible in the inbox):

```bash
# Worst-plane-wins severity. Echoes "LEVEL<TAB>SUMMARY" (LEVEL: green|amber|red).
_report_verdict() {
    local level="green" lead="healthy"
    if   (( ${ERR_FATAL:-0}   > 0 )); then level="red";   lead="⚠ ${ERR_FATAL} FATAL"
    elif (( ${ERR_GENUINE:-0} > 0 )); then level="amber"; lead="⚠ ${ERR_GENUINE} server error(s)"
    fi
    local tail="${RPT_ACTED:-0} blocked"
    (( ${OL_HITS:-0} > 0 )) && tail="${tail} · ${OL_HITS} origin-lock"
    [[ "$level" == "green" ]] && tail="${tail}, ${ERR_FATAL:-0} FATAL"
    printf '%s\t%s · %s' "$level" "$lead" "$tail"
}

# Echoes "Report <YYYY-MM-DD> - <summary>" (UTC run date).
_report_subject() {
    local d; d="$(date -u -d "@$(swatter_now)" +%F 2>/dev/null || date -u -r "$(swatter_now)" +%F)"
    local v; v="$(_report_verdict)"
    printf 'Report %s - %s' "$d" "${v#*$'\t'}"
}
```

- [ ] **Step 4: Wire the subject + title.** Replace the subject build in `swatter_report` (lines ~256-268) with:

```bash
    local subject; subject="$(_report_subject "$window")"
    (( test_mode )) && subject="[TEST] ${subject}"
```

Change the title strings: line ~68 `echo "Swatter nightly digest — ..."` → `echo "Swatter Nightly Report — ..."`; line ~192 `🪰 Swatter nightly digest` → `🪰 Swatter Nightly Report`.

- [ ] **Step 5: Run tests**

Run: `bash test/report_test.sh`
Expected: PASS (verdict green/amber/red + subject shape + origin-lock-in-subject).

- [ ] **Step 6: Commit**

```bash
git add lib/report.sh test/report_test.sh
git commit -m "feat(report): dated verdict-led subject + 'Report' wording

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Gather + text renderer with planes, Title Case, origin-lock

**Files:**
- Modify: `lib/report.sh` (`swatter_report_build` ~48-86; `_report_emit_abuse` headings)
- Test: `test/report_test.sh` (extend)

**Interfaces:**
- Consumes: `swatter_errors_section`, `swatter_originlock_section`, `_ol_digest_should_render`, the `RPT_*`/`ERR_*`/`OL_*` globals.
- Produces: `swatter_report_build <window>` emits the full **plain-text** body with Title-Case section headers and the three planes assembled in order (Bad Actors → Origin-Lock → Server Errors), each present only when enabled/gated.

- [ ] **Step 1: Write the failing test** — append to `test/report_test.sh`:

```bash
# Plane assembly + degradation. Stub the section builders so the test is hermetic.
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rpt.XXXXXX")"; : > "$LOG_DIR/decisions.jsonl"
SWATTER_HAVE_JQ=1; SWATTER_MODE="enforce"
swatter_errors_section()    { ERR_GENUINE=0 ERR_FATAL=0; echo "(errors section)"; }
swatter_originlock_section(){ OL_HITS="${FAKE_OL:-0}"; echo "(origin-lock section)"; }

# 1 plane: abuse only (error digest off, no origin-lock hits).
ERROR_DIGEST_ENABLE="false"; ORIGIN_LOCK_DIGEST="auto"; FAKE_OL=0
body="$(swatter_report_build 24h)"
check title-report      "$(printf '%s' "$body" | grep -c 'Swatter Nightly Report')" "1"
check titlecase-bad     "$(printf '%s' "$body" | grep -c 'Bad Actors')" "1"
check no-origin-1plane  "$(printf '%s' "$body" | grep -c 'Origin-Lock')" "0"
check no-errors-1plane  "$(printf '%s' "$body" | grep -c 'Server Errors')" "0"

# 3 planes: error digest on + origin-lock hits present.
ERROR_DIGEST_ENABLE="true"; FAKE_OL=253
body="$(swatter_report_build 24h)"
check has-origin-3plane "$(printf '%s' "$body" | grep -c 'Origin-Lock')" "1"
check has-errors-3plane "$(printf '%s' "$body" | grep -c 'Server Errors')" "1"
rm -rf "$LOG_DIR"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash test/report_test.sh`
Expected: FAIL — current body says "BAD ACTORS"/"SERVER ERRORS" (upper) and has no Origin-Lock plane, so `Bad Actors`/`Origin-Lock` counts are 0.

- [ ] **Step 3: Rewrite `swatter_report_build`** (`lib/report.sh` ~48-86) to gather + assemble planes in Title Case:

```bash
swatter_report_build() {
    local window="$1" cutoff
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    local log="${LOG_DIR}/decisions.jsonl"

    RPT_ACTED=0 RPT_PERM=0 RPT_TEMP=0 RPT_CF=0 RPT_DIRECT=0 RPT_EXEMPT=0 RPT_WATCH=0
    ERR_TOTAL=0 ERR_FATAL=0 ERR_GENUINE=0 ERR_NOISE=0
    OL_HITS=0 OL_IPS=0 OL_P80=0 OL_P443=0 OL_MODE="" OL_TOP_ROWS=""

    # Gather origin-lock + errors into temp sections first so their counters are
    # set before the verdict/subject read them (mirror the existing error flow).
    local olsec="" errsec=""
    olsec="$(swatter_originlock_section "$window")"
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && declare -F swatter_errors_section >/dev/null; then
        errsec="$(swatter_errors_section "$window")"
    fi

    echo "Swatter Nightly Report — $(hostname -f 2>/dev/null || hostname)"
    echo "Window: last ${window}  (mode: ${SWATTER_MODE})"
    echo
    echo "========================  Bad Actors  ==========================="
    echo
    _report_emit_abuse "$window" "$cutoff" "$log"

    if _ol_digest_should_render "${OL_HITS:-0}"; then
        echo
        echo "========================  Origin-Lock  =========================="
        echo
        printf '%s\n' "$olsec"
    fi

    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        echo
        echo "========================  Server Errors  ========================"
        echo
        printf '%s\n' "$errsec"
    fi

    echo
    echo "------------------------------------------------------------------"
    echo "Full evidence:  swatter why <ip>      Abuse log: ${log}"
}
```

- [ ] **Step 4: Title-Case the abuse sub-headings** in `_report_emit_abuse` (lib/report.sh ~117-166): change `Actions taken`→`Actions Taken`, `By offense type (acted only)`→`By Offense Type`, `By bad-path category (acted only)`→`By Bad-Path Category`, `Blocks (newest first)`→`Blocks (Newest First)`, `Exemptions (...)`→`Exemptions`. Leave the table data and the `printf` column headers' data values unchanged (column headers `IP SCORE ACTION WHY CHANNEL TTL` are already effectively caps).

- [ ] **Step 5: Run the report test + full suite**

Run: `bash test/report_test.sh && make test 2>&1 | grep -c '0 failed'`
Expected: report test PASS; full suite all green.

- [ ] **Step 6: Commit**

```bash
git add lib/report.sh test/report_test.sh
git commit -m "feat(report): assemble 3 opt-in planes in Title Case (text body)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Direction-B structured HTML renderer

**Files:**
- Modify: `lib/report.sh` (`_report_render_html` ~177-212; the call site ~270)
- Test: `test/report_test.sh` (extend)

**Interfaces:**
- Consumes: `RPT_* OL_* ERR_*` globals + `OL_TOP_ROWS`; the `$recs` block rows for the table are re-derived in the renderer from the same in-window `jq` query (or passed via a global `RPT_BLOCK_ROWS` set in gather).
- Produces: `_report_render_html <text-body>` → Direction-B HTML on stdout (header, verdict line colored by `_report_verdict` level, stat tiles for enabled planes, per-plane sections). No `<pre>` dump.

- [ ] **Step 1: Write the failing test** — append to `test/report_test.sh`:

```bash
# HTML render: Direction B structure, verdict color, tiles, no <pre> dump.
RPT_PERM=36 RPT_TEMP=162 RPT_ACTED=198 RPT_CF=198 RPT_DIRECT=0 RPT_EXEMPT=62 RPT_WATCH=2
ERR_GENUINE=0 ERR_FATAL=0; OL_HITS=253 OL_IPS=61 OL_P80=171 OL_P443=82 OL_MODE="DROP"
OL_TOP_ROWS=$'45.135.232.17\t88\tattacker\n193.32.162.40\t41\tattacker\n'
ERROR_DIGEST_ENABLE="true"; ORIGIN_LOCK_DIGEST="auto"
html="$(_report_render_html "plain body here")"
check html-title    "$(printf '%s' "$html" | grep -c 'Swatter Nightly Report')" "1"
check html-verdict  "$(printf '%s' "$html" | grep -c 'verdict-green')" "1"
check html-bad      "$(printf '%s' "$html" | grep -c '🛡️ Bad Actors')" "1"
check html-origin   "$(printf '%s' "$html" | grep -c '🔒 Origin-Lock')" "1"
check html-no-pre   "$(printf '%s' "$html" | grep -c '<pre')" "0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash test/report_test.sh`
Expected: FAIL — current renderer emits `<pre>` and lacks `verdict-green`/`🛡️ Bad Actors` markers.

- [ ] **Step 3: Rewrite `_report_render_html`** to build Direction B from the globals. Reference design: `docs/superpowers/specs/2026-06-25-nightly-report-rework-design.md` §1 and the approved mockup. The verdict color maps `green→#1a7f37/#f0fff4`, `amber→#9a4d00/#fffbea`, `red→#b31d28/#fff5f5`. Use inline styles + tables (email-client safe). Full implementation:

```bash
_report_render_html() {
    local _unused_body="$1"   # text body no longer embedded; kept for call-site compat
    local host; host="$(hostname -f 2>/dev/null || hostname)"
    local v level summary; v="$(_report_verdict)"; level="${v%%$'\t'*}"; summary="${v#*$'\t'}"
    local vbar vbg
    case "$level" in
        red)   vbar="#b31d28"; vbg="#fff5f5" ;;
        amber) vbar="#9a4d00"; vbg="#fffbea" ;;
        *)     vbar="#1a7f37"; vbg="#f0fff4" ;;
    esac
    local esc; esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

    _tile() { # value label bg border fg
        (( ${1:-0} > 0 )) || return 0
        printf '<div style="flex:1;min-width:80px;text-align:center;background:%s;border:1px solid %s;border-radius:8px;padding:8px 4px"><div style="font-size:20px;font-weight:800;color:%s">%s</div><div style="font-size:10px;color:#586069">%s</div></div>' "$3" "$4" "$5" "$1" "$2"
    }
    _sechead() { printf '<div style="font-size:14px;font-weight:700;color:#24292e;border-bottom:2px solid #eaecef;padding-bottom:5px;margin:14px 0 9px">%s</div>' "$1"; }

    printf '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;border:1px solid #e1e4e8;border-radius:10px;overflow:hidden;color:#24292e">'
    printf '<div style="background:#24292e;color:#fff;padding:14px 18px"><div style="font-size:17px;font-weight:700">🪰 Swatter Nightly Report</div><div style="font-size:12px;color:#b1b8c0;margin-top:2px">%s · last %s · mode: <b style="color:#fff">%s</b></div></div>' \
        "$(printf '%s' "$host" | esc)" "${REPORT_WINDOW:-24h}" "${SWATTER_MODE}"
    printf '<div class="verdict-%s" style="padding:12px 18px;border-left:4px solid %s;background:%s;font-size:13px">%s</div>' \
        "$level" "$vbar" "$vbg" "$(printf '%s' "$summary" | esc)"

    printf '<div style="display:flex;flex-wrap:wrap;gap:8px;padding:14px 18px 6px">'
    _tile "${RPT_PERM:-0}"  "Permanent"     "#fff5f5" "#ffd7d7" "#b31d28"
    _tile "${RPT_TEMP:-0}"  "Temporary"     "#fffbea" "#f5e6a8" "#735c0f"
    _tile "${RPT_CF:-0}"    "Via Cloudflare" "#fff5ec" "#ffd9b8" "#9a4d00"
    _ol_digest_should_render "${OL_HITS:-0}" && _tile "${OL_HITS:-0}" "Origin-Lock" "#faf7ff" "#e6d8ff" "#8957e5"
    [[ "${ERROR_DIGEST_ENABLE}" == "true" ]] && _tile "${ERR_GENUINE:-0}" "Server Errors" "#f6f8fa" "#e1e4e8" "#444d56"
    printf '</div>'

    # Bad Actors (always)
    printf '<div style="padding:0 18px">'
    _sechead "🛡️ Bad Actors"
    printf '<div style="font-size:12px;color:#444d56">Permanent <b>%s</b> · Temporary <b>%s</b> · Via Cloudflare <b>%s</b> · Exempted <b>%s</b></div>' \
        "${RPT_PERM:-0}" "${RPT_TEMP:-0}" "${RPT_CF:-0}" "${RPT_EXEMPT:-0}"
    printf '</div>'

    # Origin-Lock (gated)
    if _ol_digest_should_render "${OL_HITS:-0}"; then
        printf '<div style="padding:0 18px">'
        _sechead "🔒 Origin-Lock"
        printf '<div style="font-size:12px;color:#444d56"><b>%s</b> direct-to-origin hits dropped · %s IPs · :80 %s · :443 %s · mode %s</div>' \
            "${OL_HITS:-0}" "${OL_IPS:-0}" "${OL_P80:-0}" "${OL_P443:-0}" "$(printf '%s' "${OL_MODE}" | esc)"
        printf '<table style="width:100%%;border-collapse:collapse;font-size:12px;margin-top:6px"><thead><tr style="color:#586069;font-size:11px;text-align:left"><th style="padding:3px 6px">Source IP</th><th style="padding:3px 6px">Hits</th><th style="padding:3px 6px">Tag</th></tr></thead><tbody>'
        printf '%s' "$OL_TOP_ROWS" | while IFS=$'\t' read -r ip n tag; do
            [[ -n "$ip" ]] || continue
            printf '<tr style="border-top:1px solid #ece3fb"><td style="padding:4px 6px;font-family:ui-monospace,Menlo,monospace">%s</td><td style="padding:4px 6px">%s</td><td style="padding:4px 6px">%s</td></tr>' \
                "$(printf '%s' "$ip" | esc)" "$n" "$(printf '%s' "$tag" | esc)"
        done
        printf '</tbody></table></div>'
    fi

    # Server Errors (gated)
    if [[ "${ERROR_DIGEST_ENABLE}" == "true" ]]; then
        printf '<div style="padding:0 18px">'
        _sechead "🩺 Server Errors"
        printf '<div style="font-size:12px;color:#444d56"><b>%s Genuine</b> · %s FATAL</div>' "${ERR_GENUINE:-0}" "${ERR_FATAL:-0}"
        printf '</div>'
    fi

    printf '<div style="padding:14px 18px 16px;color:#959da5;font-size:11px"><code>swatter why &lt;ip&gt;</code> for evidence · <code>swatter unblock &lt;ip&gt;</code> to reverse</div>'
    printf '</div>'
}
```

(The bad-actors and server-errors sections show summary lines here; the full blocks table and error signatures remain in the **plain-text** body for the audit-grade detail. If a richer HTML blocks table is wanted later, gather can expose `RPT_BLOCK_ROWS` as TSV the same way `OL_TOP_ROWS` works — out of scope for v1.)

- [ ] **Step 4: Run tests + full suite + lint**

Run: `bash test/report_test.sh && make test 2>&1 | grep -E 'failed' | grep -v '0 failed' || echo ALL-GREEN`
Run: `shellcheck --severity=error lib/report.sh`
Expected: report test PASS; `ALL-GREEN`; shellcheck exit 0.

- [ ] **Step 5: Commit**

```bash
git add lib/report.sh test/report_test.sh
git commit -m "feat(report): Direction-B structured HTML renderer (replaces pre dump)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Config-driven cron scheduling

**Files:**
- Modify: `install/swatter.cron` (drop the static `0 11` report line + the CRON_TZ comment block)
- Modify: `install.sh` (the cron install at line ~149)
- Test: `test/report_cron_test.sh` (new)

**Interfaces:**
- Produces: `_swatter_render_cron <tmpl> <report_cron> <report_cron_tz>` → writes the final cron to stdout: the template's static lines (scan, refresh-feeds) followed by an optional `CRON_TZ=<tz>` line and the generated `0 4 ... swatter report` line.

- [ ] **Step 1: Remove the static report line** from `install/swatter.cron` — delete the `#CRON_TZ=...` comment block and the `0 11 * * * root /usr/local/bin/swatter report` line, leaving the `*/5` scan and `20 3` refresh-feeds lines and a trailing comment: `# The nightly report line is appended by install.sh from REPORT_CRON / REPORT_CRON_TZ.`

- [ ] **Step 2: Write the failing test** — create `test/report_cron_test.sh`:

```bash
#!/usr/bin/env bash
# test/report_cron_test.sh — install.sh generates the report cron line from config.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/install.sh" --source-only 2>/dev/null || true   # load funcs without running main
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

TMPL="${ROOT}/install/swatter.cron"
out="$(_swatter_render_cron "$TMPL" "0 4" "")"
check no-tz-line   "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=')" "0"
check report-utc   "$(printf '%s\n' "$out" | grep -c '^0 4 \* \* \* root .*swatter report')" "1"
out="$(_swatter_render_cron "$TMPL" "0 4" "America/Los_Angeles")"
check tz-line      "$(printf '%s\n' "$out" | grep -c '^CRON_TZ=America/Los_Angeles')" "1"
check report-after-tz "$(printf '%s\n' "$out" | awk '/^CRON_TZ=/{tz=NR} /swatter report/{r=NR} END{print (tz<r)?"ok":"bad"}')" "ok"
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
```

- [ ] **Step 3: Run test to verify it fails**

Run: `bash test/report_cron_test.sh`
Expected: FAIL — `_swatter_render_cron: command not found`.

- [ ] **Step 4: Add a `--source-only` guard + the generator** to `install.sh`. Near the top (after the shebang/initial vars), add:

```bash
[[ "${1:-}" == "--source-only" ]] && SWATTER_INSTALL_SOURCE_ONLY=1 || SWATTER_INSTALL_SOURCE_ONLY=0
```

Add the function:

```bash
# Render the final /etc/cron.d/swatter from the template + report schedule config.
_swatter_render_cron() {
    local tmpl="$1" report_cron="$2" report_tz="$3"
    cat "$tmpl"
    echo
    [[ -n "$report_tz" ]] && echo "CRON_TZ=${report_tz}"
    echo "${report_cron} * * * root /usr/local/bin/swatter report"
}
```

Guard `main`/the install entrypoint so sourcing with `--source-only` doesn't run it: wrap the bottom-of-file invocation in `(( SWATTER_INSTALL_SOURCE_ONLY )) || _install_main "$@"` (adapt to the actual entrypoint name).

- [ ] **Step 5: Use the generator** at the cron install (line ~149). Replace:

```bash
    install -m 0644 "${SRC}"/install/swatter.cron      /etc/cron.d/swatter
```

with:

```bash
    _swatter_render_cron "${SRC}/install/swatter.cron" "${REPORT_CRON:-0 4}" "${REPORT_CRON_TZ:-}" \
        > /etc/cron.d/swatter
    chmod 0644 /etc/cron.d/swatter
```

- [ ] **Step 6: Run test + lint**

Run: `bash test/report_cron_test.sh`
Expected: PASS (no-tz / report-utc / tz-line / report-after-tz).
Run: `shellcheck --severity=error install.sh`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add install/swatter.cron install.sh test/report_cron_test.sh
git commit -m "feat(report): generate report cron from REPORT_CRON + REPORT_CRON_TZ

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Version bump, changelog, full-suite gate

**Files:**
- Modify: `bin/swatter` (`SWATTER_VERSION`), `CHANGELOG.md`

- [ ] **Step 1: Bump version** — `bin/swatter`: `SWATTER_VERSION="2.1.3"` → `SWATTER_VERSION="2.2.0"`.

- [ ] **Step 2: Add CHANGELOG entry** under `## [Unreleased]` → new `## [2.2.0] — <date>` section summarizing: structured Direction-B HTML report; Title Case; opt-in data-gated Origin-Lock plane; "Report" wording; dated verdict-led subject; config-driven DST-aware scheduling (`REPORT_CRON`/`REPORT_CRON_TZ`); new `report_test.sh` + `report_cron_test.sh`; credit the Grok/Cursor reviews if any apply. (Match the existing CHANGELOG entry style.)

- [ ] **Step 3: Full gate**

Run: `make test 2>&1 | grep -oE '[0-9]+ passed, [0-9]+ failed' | awk '{p+=$1;f+=$3} END{print p" passed, "f" failed"}'`
Expected: `… 0 failed`.
Run: `shellcheck --severity=error bin/swatter lib/*.sh install/*.sh test/*.sh`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add bin/swatter CHANGELOG.md
git commit -m "release: v2.2.0 — nightly report rework

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Deployment (post-merge, operator step — not a code task)

Per the spec's rollout: surgical scp of changed libs (`common.sh`, `origin_lock.sh`, `report.sh`) + `bin/swatter` to prod (`common.sh` first), then regenerate `/etc/cron.d/swatter` (or run the install path) so the report line picks up `REPORT_CRON_TZ="America/Los_Angeles"` + `REPORT_CRON="0 4"` — set those two in `/etc/swatter/swatter.conf` on prod first. Validate staged against the real conf, watch one live scan + the next report window, then `make release V=2.2.0`.

## Self-Review notes

- Spec coverage: layout/Direction-B (T5), Title Case (T4+T5), 3 opt-in planes + degradation (T4+T5), origin-lock section + data-driven gating + `ORIGIN_LOCK_LOG` (T2), subject/verdict/"Report" (T3), scheduling/`CRON_TZ` (T6), config keys (T1), tests incl. new `report_test.sh` (T3-5) + `report_cron_test.sh` (T6), version (T7). All spec sections map to a task.
- The plain-text blocks table / error signatures remain in the text body (audit detail); HTML shows summaries — explicitly noted as v1 scope in T5.
