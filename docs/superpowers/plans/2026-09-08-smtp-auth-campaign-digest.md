# SMTP AUTH Campaign Digest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth nightly-digest plane that lists SMTP AUTH credential-spray campaigns (same mailbox, ≥N distinct connecting IPs) from `exim_mainlog`, with no blocks.

**Architecture:** Report-time sibling of the errors/origin-lock planes. `lib/mail_campaigns.sh` parses Exim, groups by verbatim `set_id`, and emits a section plus `MAILCAMP_*` globals. `report.sh` gathers it by redirection before `_report_grade`, which does not read those globals. Unreadable evidence is UNREADABLE, never “0 campaigns.”

**Tech Stack:** bash 4+, `gawk` (same as `errors.sh` Apache collector / `ingest.sh`; `mktime` + `unset TZ`), `gzip -dc` for rotated `.gz`. No sqlite, no `score.awk`.

**Spec:** `docs/superpowers/specs/2026-09-08-smtp-auth-campaign-digest-design.md` (rev 1)

## Global Constraints

- **Visibility only.** No CSF, Cloudflare, AbuseIPDB, `decisions.jsonl` watch rows, persist, or `score.awk` / `ingest.sh` changes.
- **Failed password ≠ malice.** Mailbox names are attacker-chosen; display them; never feed them to `bad_rx[]` / `hp_rx[]`. Connecting IPs are counted, never denied.
- **Grade and SMS do not read `MAILCAMP_*`.** An UNREADABLE section on an otherwise GREEN night is a GREEN email with a loud section.
- **Fail-loud:** a selected file we cannot read → `MAILCAMP_OK=0` and no campaign table. A partial read is not an all-clear.
- **Numeric knobs** go through `_swatter_validate_int` in `swatter_load_config`. Test with `SWATTER_CONF=<copy>`, never `VAR=x swatter …`.
- **`EXIM_MAINLOG=""` means default path** `/var/log/exim_mainlog`. Non-empty is explicit: missing file is UNREADABLE even under `auto`.
- **Parser is gawk + `LC_ALL=C`**, wrapped in `( unset TZ; … )` like `lib/errors.sh` Apache collector. Connecting IP is `[addr]:port:` immediately before `535`, never from `H=` / HELO / `set_id`.
- **Public repo:** noreply git identity (`peaceharbor.identityGuard=strict`).
- **`make test` before every commit.** Both awk dialects are the existing suite contract; this plane pins `gawk` the way errors/ingest already do.
- **Do not change** `lib/score.awk`, `lib/score.sh`, `lib/ingest.sh`, `lib/block_*.sh`, `lib/report_abuseipdb.sh`.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `lib/common.sh` | Defaults + `_swatter_validate_int` + DIGEST enum | 1 |
| `config/swatter.example.conf` | Documented knobs | 1 |
| `test/config_defaults_test.sh` | Defaults + `SWATTER_CONF=` validation | 1 |
| `lib/mail_campaigns.sh` | Parser, campaign rule, section emitter | 2, 3 |
| `test/mail_campaigns_test.sh` | Parser, campaign, fail-loud, rotation | 2, 3 |
| `bin/swatter` | Source `mail_campaigns` before `report` | 4 |
| `lib/report.sh` | Gather, quiet-skip, text+HTML render | 4 |
| `test/report_test.sh` | Stubs, skip predicate, grade, HTML | 4 |
| `docs/RUNBOOK.md` | Operator note: section ≠ block | 4 |
| `CHANGELOG.md` | Unreleased entry | 4 |

`install/install.sh` already copies `lib/*.sh`; no install change.

---

### Task 1: Knobs and validation

Ships the config surface before anything consumes it. Reviewable alone: defaults, validation, example.conf, tests.

**Files:**
- Modify: `lib/common.sh` (after `ORIGIN_LOCK_LOG=""` ~:300)
- Modify: `lib/common.sh` (`swatter_load_config` validation block ~:491)
- Modify: `config/swatter.example.conf` (after origin-lock block ~:397)
- Test: `test/config_defaults_test.sh`

**Interfaces:**
- Consumes: `_swatter_validate_int`
- Produces: `MAIL_CAMPAIGN_DIGEST` (`auto`/`on`/`off`), `EXIM_MAINLOG` (empty = default path), `MAIL_CAMPAIGN_MIN_IPS` (int 2–100, default 5), `MAIL_CAMPAIGN_LIST_CAP` (int 1–200, default 20)

- [ ] **Step 1: Write the failing tests**

Append to `test/config_defaults_test.sh` after the `ol-log-default` checks (~:57):

```bash
check mailcamp-digest-default "${MAIL_CAMPAIGN_DIGEST}" "auto"
check mailcamp-exim-default   "${EXIM_MAINLOG}" ""
check mailcamp-min-ips        "${MAIL_CAMPAIGN_MIN_IPS}" "5"
check mailcamp-list-cap       "${MAIL_CAMPAIGN_LIST_CAP}" "20"
```

Append vchecks after the `min-reqs-*` block (~:193):

```bash
vcheck mailcamp-min-empty   'MAIL_CAMPAIGN_MIN_IPS=""'     MAIL_CAMPAIGN_MIN_IPS "5"
vcheck mailcamp-min-alpha   'MAIL_CAMPAIGN_MIN_IPS="abc"'  MAIL_CAMPAIGN_MIN_IPS "5"
vcheck mailcamp-min-one     'MAIL_CAMPAIGN_MIN_IPS=1'      MAIL_CAMPAIGN_MIN_IPS "5"
vcheck mailcamp-min-huge    'MAIL_CAMPAIGN_MIN_IPS=999'    MAIL_CAMPAIGN_MIN_IPS "5"
vcheck mailcamp-min-padded  'MAIL_CAMPAIGN_MIN_IPS="020"'  MAIL_CAMPAIGN_MIN_IPS "20"
vcheck mailcamp-min-valid   'MAIL_CAMPAIGN_MIN_IPS=4'      MAIL_CAMPAIGN_MIN_IPS "4"

vcheck mailcamp-cap-empty   'MAIL_CAMPAIGN_LIST_CAP=""'    MAIL_CAMPAIGN_LIST_CAP "20"
vcheck mailcamp-cap-alpha   'MAIL_CAMPAIGN_LIST_CAP="abc"' MAIL_CAMPAIGN_LIST_CAP "20"
vcheck mailcamp-cap-zero    'MAIL_CAMPAIGN_LIST_CAP=0'     MAIL_CAMPAIGN_LIST_CAP "20"
vcheck mailcamp-cap-valid   'MAIL_CAMPAIGN_LIST_CAP=10'    MAIL_CAMPAIGN_LIST_CAP "10"

vcheck mailcamp-digest-bogus 'MAIL_CAMPAIGN_DIGEST="yes"' MAIL_CAMPAIGN_DIGEST "auto"
vcheck mailcamp-digest-on    'MAIL_CAMPAIGN_DIGEST="on"'  MAIL_CAMPAIGN_DIGEST "on"
vcheck mailcamp-digest-off   'MAIL_CAMPAIGN_DIGEST="off"' MAIL_CAMPAIGN_DIGEST "off"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bash test/config_defaults_test.sh`

Expected: FAIL `mailcamp-digest-default` (unset variable under `set -u`, or empty ≠ `auto`).

- [ ] **Step 3: Write minimal implementation**

In `lib/common.sh` after `ORIGIN_LOCK_LOG=""`:

```bash
# SMTP AUTH campaign digest (nightly report). auto = run when the Exim mainlog
# exists (or EXIM_MAINLOG is set); on = always; off = never. Empty EXIM_MAINLOG
# means /var/log/exim_mainlog. A set path that is missing is UNREADABLE, not a skip.
MAIL_CAMPAIGN_DIGEST="auto"
EXIM_MAINLOG=""
MAIL_CAMPAIGN_MIN_IPS=5
MAIL_CAMPAIGN_LIST_CAP=20
```

In `swatter_load_config`, after the existing `_swatter_validate_int MIN_REQS` line:

```bash
    _swatter_validate_int MAIL_CAMPAIGN_MIN_IPS  5   2 100
    _swatter_validate_int MAIL_CAMPAIGN_LIST_CAP 20  1 200
    case "${MAIL_CAMPAIGN_DIGEST:-}" in
        auto|on|off) ;;
        *) log_warn "MAIL_CAMPAIGN_DIGEST='${MAIL_CAMPAIGN_DIGEST:-}' invalid (want auto|on|off); using auto"
           MAIL_CAMPAIGN_DIGEST="auto" ;;
    esac
```

In `config/swatter.example.conf` after the origin-lock block:

```bash
# ---- SMTP AUTH campaign digest (nightly report) -----------------------------
# Visibility only — never a block. Groups Exim `dovecot_login authenticator
# failed` lines by mailbox; a campaign is ≥ MAIL_CAMPAIGN_MIN_IPS distinct
# connecting IPs against the same mailbox in the digest window. "auto" runs
# when /var/log/exim_mainlog exists (or EXIM_MAINLOG is set); "on" always;
# "off" never. An unreadable log is reported as UNREADABLE, never as zero
# campaigns, and does not change the GREEN/YELLOW/RED grade.
MAIL_CAMPAIGN_DIGEST="auto"
EXIM_MAINLOG=""
MAIL_CAMPAIGN_MIN_IPS=5
MAIL_CAMPAIGN_LIST_CAP=20
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bash test/config_defaults_test.sh`

Expected: all `mailcamp-*` PASS, existing checks still PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/common.sh config/swatter.example.conf test/config_defaults_test.sh
git commit -m "$(cat <<'EOF'
feat(report): SMTP AUTH campaign digest knobs

Visibility-only plane. MIN_IPS floor is 2 so a typo of 1 cannot make
every mailbox a campaign. DIGEST enum falls back to auto.
EOF
)"
```

---

### Task 2: Parser and campaign rule

Core of the plane. Tests source `common.sh` + `report.sh` (for `_report_window_secs`) + `mail_campaigns.sh`. Does not yet wire `report.sh` gather/HTML.

**Files:**
- Create: `lib/mail_campaigns.sh`
- Create: `test/mail_campaigns_test.sh`

**Interfaces:**
- Consumes: `MAIL_CAMPAIGN_MIN_IPS`, `MAIL_CAMPAIGN_LIST_CAP`, `EXIM_MAINLOG`, `MAIL_CAMPAIGN_DIGEST`, `_report_window_secs`, `swatter_now`, `stat_mtime`
- Produces: `swatter_mail_campaigns_section <window>` (stdout = section; sets `MAILCAMP_OK`, `MAILCAMP_N`, `MAILCAMP_FAILS`, `MAILCAMP_IPS` in the current shell). Also `_mailcamp_should_run`, `_mailcamp_path` for Task 4.

- [ ] **Step 1: Write the failing test harness and parser cases**

Create `test/mail_campaigns_test.sh`:

```bash
#!/usr/bin/env bash
# test/mail_campaigns_test.sh — SMTP AUTH campaign digest plane.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
source "${ROOT}/lib/mail_campaigns.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

swatter_now() { echo 1782396000; }   # 2026-06-25 12:00:00 UTC
WORK="$(mktemp -d "${TMPDIR:-/tmp}/swatter-mct.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

EXIM_MAINLOG="${WORK}/exim_mainlog"
MAIL_CAMPAIGN_DIGEST="on"
MAIL_CAMPAIGN_MIN_IPS=5
MAIL_CAMPAIGN_LIST_CAP=20

_line() { # _line <ip> <id>
  printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo.example [%s]:41666: 535 Incorrect authentication data (set_id=%s)\n' "$1" "$2"
}
_run() { swatter_mail_campaigns_section 24h > "${WORK}/sec.out"; SECTION_OUT="$(cat "${WORK}/sec.out")"; }

# --- happy spray: 5 IPs, one attempt each, same mailbox ----------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14; do
  _line "$ip" "box1" >> "$EXIM_MAINLOG"
done
_run
check happy-ok     "$MAILCAMP_OK" "1"
check happy-n      "$MAILCAMP_N" "1"
check happy-fails  "$MAILCAMP_FAILS" "5"
check happy-ips    "$MAILCAMP_IPS" "5"
check happy-lists  "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "1"
check happy-no-unr "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "0"

# --- below threshold: 4 IPs --------------------------------------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13; do
  _line "$ip" "box1" >> "$EXIM_MAINLOG"
done
_run
check below-n      "$MAILCAMP_N" "0"
check below-zero   "$(printf '%s' "$SECTION_OUT" | grep -c 'No SMTP AUTH campaigns this window.')" "1"
check below-absent "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "0"

# --- typo: 23 fails, one IP --------------------------------------------------
: > "$EXIM_MAINLOG"
for _i in $(seq 1 23); do _line "198.51.100.10" "box1" >> "$EXIM_MAINLOG"; done
_run
check typo-n       "$MAILCAMP_N" "0"
check typo-absent  "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "0"

# --- threshold knob ----------------------------------------------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13; do
  _line "$ip" "box1" >> "$EXIM_MAINLOG"
done
MAIL_CAMPAIGN_MIN_IPS=4; _run
check knob-n       "$MAILCAMP_N" "1"
MAIL_CAMPAIGN_MIN_IPS=5

# --- verbatim set_id: shipping vs shipping@x.com -----------------------------
: > "$EXIM_MAINLOG"
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14; do
  _line "$ip" "shipping" >> "$EXIM_MAINLOG"
  _line "203.0.113.${ip##*.}" "shipping@x.com" >> "$EXIM_MAINLOG"
done
_run
check verbatim-n   "$MAILCAMP_N" "2"

# --- HELO decoy: parenthetical IP is not the connecting IP -------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do
  printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=([203.0.113.9]) [198.51.100.%s]:56131: 535 Incorrect authentication data (set_id=box1)\n' "$n" >> "$EXIM_MAINLOG"
done
_run
check helo-n       "$MAILCAMP_N" "1"
check helo-ips     "$MAILCAMP_IPS" "5"

# --- T5: tab + fake [ip]:port inside set_id (after 535) ----------------------
: > "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data (set_id=x\t[203.0.113.9]:25)\n' >> "$EXIM_MAINLOG"
for n in 11 12 13 14; do _line "198.51.100.$n" "x	[203.0.113.9]:25" >> "$EXIM_MAINLOG"; done
_run
check t5-n         "$MAILCAMP_N" "1"
check t5-not-decoy "$(printf '%s' "$SECTION_OUT" | grep -c '203.0.113.9')" "0"
check t5-ips       "$MAILCAMP_IPS" "5"

# --- drop incomplete lines ---------------------------------------------------
: > "$EXIM_MAINLOG"
printf 'not a stamp dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data (set_id=box1)\n' >> "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo no-addr 535 Incorrect authentication data (set_id=box1)\n' >> "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data\n' >> "$EXIM_MAINLOG"
_run
check drop-fails   "$MAILCAMP_FAILS" "0"
check drop-ok      "$MAILCAMP_OK" "1"

# --- T13: binary byte on one line does not drop the valid neighbor ----------
: > "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [198.51.100.10]:41666: 535 Incorrect authentication data (set_id=box1)\n' >> "$EXIM_MAINLOG"
printf '2026-06-25 10:00:00 \x80dovecot_login authenticator failed for H=foo [198.51.100.99]:41666: 535 Incorrect authentication data (set_id=junk)\n' >> "$EXIM_MAINLOG"
for n in 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
_run
check t13-fails    "$MAILCAMP_FAILS" "5"
check t13-n        "$MAILCAMP_N" "1"

# --- IPv6 connecting IP ------------------------------------------------------
: > "$EXIM_MAINLOG"
for h in 1 2 3 4 5; do
  printf '2026-06-25 10:00:00 dovecot_login authenticator failed for H=foo [2001:db8::%s]:465: 535 Incorrect authentication data (set_id=box1)\n' "$h" >> "$EXIM_MAINLOG"
done
_run
check v6-n         "$MAILCAMP_N" "1"
check v6-ips       "$MAILCAMP_IPS" "5"

# --- cap: 25 campaigns, list 20 + remainder ---------------------------------
: > "$EXIM_MAINLOG"
for c in $(seq 1 25); do
  for n in 10 11 12 13 14; do _line "198.51.100.$n" "box$c" >> "$EXIM_MAINLOG"; done
done
_run
check cap-n        "$MAILCAMP_N" "25"
check cap-remain   "$(printf '%s' "$SECTION_OUT" | grep -c '+ 5 more')" "1"
check cap-rows     "$(printf '%s' "$SECTION_OUT" | grep -c 'box')" "20"

# --- TZ wrapper: process-wide TZ=UTC must not drop an in-window local stamp --
# The parser unsets TZ for mktime (errors.sh Apache collector). A 10:00 stamp
# on 2026-06-25 is inside a 24h window from 12:00 UTC on any host TZ that is
# not more than 10 hours ahead of UTC — and on UTC it is trivially inside.
TZ=UTC
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
_run
check tz-n         "$MAILCAMP_N" "1"
check tz-unset     "$(grep -c 'unset TZ' "${ROOT}/lib/mail_campaigns.sh")" "1"
unset TZ
export TZ=UTC

echo "PASS=$PASS FAIL=$FAIL"
(( FAIL == 0 ))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash test/mail_campaigns_test.sh`

Expected: FAIL immediately on `source …/lib/mail_campaigns.sh` (no such file).

- [ ] **Step 3: Write `lib/mail_campaigns.sh`**

```bash
#!/usr/bin/env bash
# lib/mail_campaigns.sh — SMTP AUTH campaign digest (report-time, visibility only).
#
# Parses Exim `dovecot_login authenticator failed` over the digest window,
# groups by verbatim set_id, and emits a "Mail Campaigns" section. Never
# blocks, never writes decisions.jsonl, never talks to CSF/CF/AbuseIPDB.

_MAILCAMP_DEFAULT_PATH="/var/log/exim_mainlog"

_mailcamp_path() {
    if [[ -n "${EXIM_MAINLOG}" ]]; then printf '%s' "${EXIM_MAINLOG}"
    else printf '%s' "$_MAILCAMP_DEFAULT_PATH"; fi
}

_mailcamp_explicit() { [[ -n "${EXIM_MAINLOG}" ]]; }

_mailcamp_should_run() {
    case "${MAIL_CAMPAIGN_DIGEST:-auto}" in
        off) return 1 ;;
        on)  return 0 ;;
        *)
            _mailcamp_explicit && return 0
            [[ -e "$(_mailcamp_path)" ]] && return 0
            return 1
            ;;
    esac
}

_mailcamp_emit_unreadable() {
    local why="$1"
    MAILCAMP_OK=0
    MAILCAMP_N=0
    MAILCAMP_FAILS=0
    MAILCAMP_IPS=0
    printf 'UNREADABLE: cannot read %s (%s)\n' "$(_mailcamp_path)" "$why"
}

# Select the live log (always, if we are running) plus rotations whose mtime
# is >= cutoff. Uses stat_mtime from common.sh (GNU/BSD).
_mailcamp_select_files() {
    local path="$1" cutoff="$2"
    local dir base f mt
    dir="$(dirname -- "$path")"
    base="$(basename -- "$path")"
    printf '%s\n' "$path"
    for f in "$dir"/"$base"-* "$dir"/"$base".*; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$path" ]] && continue
        mt="$(stat_mtime "$f")" || continue
        [[ "$mt" =~ ^[0-9]+$ ]] || continue
        (( mt >= cutoff )) || continue
        printf '%s\n' "$f"
    done
}

_mailcamp_parse() {
    local cutoff="$1"
    # Connecting IP = [addr]:port: immediately before 535. set_id is after 535,
    # so a forged [ip]:port inside set_id cannot win. HELO parentheticals have
    # no :port: 535. LC_ALL=C; unset TZ so common.sh's TZ=UTC does not shift
    # host-local Exim stamps (v2.15.0 class).
    ( unset TZ; LC_ALL=C gawk -v cutoff="$cutoff" '
        {
            if (substr($0,5,1) != "-" || substr($0,8,1) != "-" || substr($0,11,1) != " ") next
            ts = substr($0, 1, 19)
            Y = substr(ts,1,4)+0; Mo = substr(ts,6,2)+0; D = substr(ts,9,2)+0
            h = substr(ts,12,2)+0; mi = substr(ts,15,2)+0; s = substr(ts,18,2)+0
            ep = mktime(sprintf("%04d %02d %02d %02d %02d %02d", Y, Mo, D, h, mi, s))
            if (ep < cutoff) next
            if (index($0, "dovecot_login authenticator failed") == 0) next
            p535 = index($0, ": 535")
            if (p535 == 0) p535 = index($0, ":535")
            if (p535 == 0) next
            head = substr($0, 1, p535)
            ip = ""
            rest = head
            while (match(rest, /\[[0-9A-Fa-f:.]+\]:[0-9]+:/)) {
                ip = substr(rest, RSTART, RLENGTH)
                rest = substr(rest, RSTART + RLENGTH)
            }
            if (ip == "") next
            sub(/^\[/, "", ip)
            sub(/\]:[0-9]+:$/, "", ip)
            tail = substr($0, p535)
            if (match(tail, /\(set_id=/) == 0) next
            id = substr(tail, RSTART + 8)
            sub(/\).*$/, "", id)
            if (id == "") next
            print ip "\t" id
        }
    ' )
}

swatter_mail_campaigns_section() {
    local window="$1" cutoff path
    cutoff=$(( $(swatter_now) - $(_report_window_secs "$window") ))
    path="$(_mailcamp_path)"
    MAILCAMP_OK=1 MAILCAMP_N=0 MAILCAMP_FAILS=0 MAILCAMP_IPS=0

    local files f
    files="$(_mailcamp_select_files "$path" "$cutoff")"
    local parsed; parsed="$(mktemp "${TMPDIR:-/tmp}/swatter-mc.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -f '$parsed'" RETURN

    local any=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if [[ "$f" == "$path" && ! -e "$f" ]]; then
            _mailcamp_emit_unreadable "missing"
            return 0
        fi
        if [[ ! -r "$f" ]]; then
            _mailcamp_emit_unreadable "unreadable: ${f}"
            return 0
        fi
        any=1
        if [[ "$f" == *.gz ]]; then
            gzip -dc -- "$f" 2>/dev/null | _mailcamp_parse "$cutoff" >> "$parsed" || {
                _mailcamp_emit_unreadable "gzip failed: ${f}"; return 0; }
        else
            _mailcamp_parse "$cutoff" < "$f" >> "$parsed"
        fi
    done <<< "$files"

    if (( ! any )) && [[ ! -e "$path" ]]; then
        _mailcamp_emit_unreadable "missing"
        return 0
    fi

    local min="${MAIL_CAMPAIGN_MIN_IPS:-5}" cap="${MAIL_CAMPAIGN_LIST_CAP:-20}"
    local summary
    summary="$(LC_ALL=C gawk -F '\t' -v min="$min" -v cap="$cap" '
        NF >= 2 {
            ip=$1; id=$2
            fails[id]++; ipn[id SUBSEP ip]++; seenip[ip]=1; n++
        }
        END {
            print n+0, length(seenip)+0
            for (id in fails) {
                d = 0; ones = 0
                for (k in ipn) {
                    split(k, a, SUBSEP)
                    if (a[1] != id) continue
                    d++
                    if (ipn[k] == 1) ones++
                }
                if (d >= min) printf "%d\t%d\t%d\t%s\n", d, fails[id], ones, id
            }
        }
    ' "$parsed")"

    local totals campaigns
    totals="$(printf '%s\n' "$summary" | sed -n '1p')"
    MAILCAMP_FAILS="${totals%% *}"
    MAILCAMP_IPS="${totals#* }"
    [[ "$MAILCAMP_FAILS" =~ ^[0-9]+$ ]] || MAILCAMP_FAILS=0
    [[ "$MAILCAMP_IPS" =~ ^[0-9]+$ ]] || MAILCAMP_IPS=0

    campaigns="$(printf '%s\n' "$summary" | sed '1d' | sort -t$'\t' -k1,1nr -k2,2nr)"
    MAILCAMP_N=0
    [[ -n "$campaigns" ]] && MAILCAMP_N="$(printf '%s\n' "$campaigns" | grep -c . || true)"

    if (( MAILCAMP_N == 0 )); then
        printf 'No SMTP AUTH campaigns this window.\n'
        return 0
    fi

    printf 'Mail Campaigns\n'
    printf '--------------\n'
    printf '  %s campaigns  ·  %s fails  ·  %s distinct IPs\n\n' "$MAILCAMP_N" "$MAILCAMP_FAILS" "$MAILCAMP_IPS"
    printf '  %-40s %5s %6s %8s\n' "mailbox" "ips" "fails" "1-per-IP"
    local shown=0 d fails ones id pct
    while IFS=$'\t' read -r d fails ones id; do
        [[ -n "$id" ]] || continue
        if (( shown >= cap )); then
            printf '  + %s more campaigns\n' "$(( MAILCAMP_N - shown ))"
            break
        fi
        pct=0
        (( fails > 0 )) && pct=$(( (ones * 100 + fails/2) / fails ))
        printf '  %-40s %5s %6s %7s%%\n' "$id" "$d" "$fails" "$pct"
        shown=$(( shown + 1 ))
    done <<< "$campaigns"
}
```

Make the file executable bit unnecessary (sourced). Mode 0644 is fine.

- [ ] **Step 4: Run tests to verify they pass**

Run: `bash test/mail_campaigns_test.sh`

Expected: `PASS=<n> FAIL=0`. If `cap-rows` fails because `box` matches the remainder line, tighten the grep to `'^  box'` (two spaces, table indent). If `t5-not-decoy` fails because the mailbox column prints the tab-forged id, that is OK for grouping but the connecting-IP must still be the real five addresses (`t5-ips=5`). Do not list connecting IPs.

- [ ] **Step 5: Commit**

```bash
git add lib/mail_campaigns.sh test/mail_campaigns_test.sh
git commit -m "$(cat <<'EOF'
feat(report): parse Exim SMTP AUTH failures into campaigns

Report-time only. Group by verbatim set_id; campaign is >=MIN_IPS
distinct connecting IPs. Connecting IP is [addr]:port: before 535.
EOF
)"
```

---

### Task 3: Fail-loud file selection (rotation, gzip, auto/on)

Extends Task 2’s module with the I/O contract. Parser tests must keep passing.

**Files:**
- Modify: `lib/mail_campaigns.sh` (only if Task 2’s I/O is incomplete)
- Modify: `test/mail_campaigns_test.sh` (append)

**Interfaces:**
- Consumes: `_mailcamp_select_files`, `_mailcamp_should_run`, `_mailcamp_emit_unreadable` from Task 2
- Produces: same public function; `MAILCAMP_OK=0` on missing/unreadable selected files; plane skip when `auto` and default path absent

- [ ] **Step 1: Write the failing I/O tests**

Append to `test/mail_campaigns_test.sh` before the `PASS=` summary:

```bash
# --- unreadable live file ----------------------------------------------------
: > "$EXIM_MAINLOG"
chmod 000 "$EXIM_MAINLOG"
_run
check unr-ok       "$MAILCAMP_OK" "0"
check unr-word     "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "1"
check unr-not-zero "$(printf '%s' "$SECTION_OUT" | grep -c 'No SMTP AUTH campaigns')" "0"
chmod 600 "$EXIM_MAINLOG"

# --- selected rotation unreadable: no partial list ---------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
touch -t 202606251000 "$EXIM_MAINLOG-20260625"
chmod 000 "$EXIM_MAINLOG-20260625"
_run
check rot-unr-ok   "$MAILCAMP_OK" "0"
check rot-unr-word "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "1"
check rot-unr-no   "$(printf '%s' "$SECTION_OUT" | grep -c 'box1')" "0"
chmod 600 "$EXIM_MAINLOG-20260625"
rm -f "$EXIM_MAINLOG-20260625"

# --- ancient unreadable rotation is NOT selected -----------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
touch -t 202001010000 "$EXIM_MAINLOG-20200101"
chmod 000 "$EXIM_MAINLOG-20200101"
_run
check ancient-ok   "$MAILCAMP_OK" "1"
check ancient-n    "$MAILCAMP_N" "1"
chmod 600 "$EXIM_MAINLOG-20200101"
rm -f "$EXIM_MAINLOG-20200101"

# --- rotation sums live + dated file ----------------------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
: > "$EXIM_MAINLOG-20260625"
for n in 13 14; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG-20260625"; done
touch -t 202606251000 "$EXIM_MAINLOG-20260625"
_run
check rot-n        "$MAILCAMP_N" "1"
check rot-fails    "$MAILCAMP_FAILS" "5"
rm -f "$EXIM_MAINLOG-20260625"

# --- gzip rotation -----------------------------------------------------------
: > "$EXIM_MAINLOG"
for n in 10 11 12; do _line "198.51.100.$n" "box1" >> "$EXIM_MAINLOG"; done
: > "${WORK}/rot.txt"
for n in 13 14; do _line "198.51.100.$n" "box1" >> "${WORK}/rot.txt"; done
gzip -c "${WORK}/rot.txt" > "$EXIM_MAINLOG-20260625.gz"
touch -t 202606251000 "$EXIM_MAINLOG-20260625.gz"
_run
check gz-n         "$MAILCAMP_N" "1"
check gz-fails     "$MAILCAMP_FAILS" "5"
rm -f "$EXIM_MAINLOG-20260625.gz"

# --- auto + missing default path: should_run is false (skip, not UNREADABLE) -
EXIM_MAINLOG=""
MAIL_CAMPAIGN_DIGEST="auto"
check auto-skip    "$(_mailcamp_should_run; echo $?)" "1"
# --- on + missing path: section UNREADABLE ----------------------------------
MAIL_CAMPAIGN_DIGEST="on"
EXIM_MAINLOG="${WORK}/no-such-exim"
_run
check on-miss-ok   "$MAILCAMP_OK" "0"
check on-miss-word "$(printf '%s' "$SECTION_OUT" | grep -c 'UNREADABLE')" "1"
# --- auto + explicit missing path: UNREADABLE --------------------------------
MAIL_CAMPAIGN_DIGEST="auto"
EXIM_MAINLOG="${WORK}/no-such-exim"
check auto-expl    "$(_mailcamp_should_run; echo $?)" "0"
_run
check auto-expl-ok "$MAILCAMP_OK" "0"
MAIL_CAMPAIGN_DIGEST="on"
EXIM_MAINLOG="${WORK}/exim_mainlog"
```

- [ ] **Step 2: Run tests to verify new cases fail (or already pass)**

Run: `bash test/mail_campaigns_test.sh`

Expected: if Task 2 already implemented `_mailcamp_select_files` and missing-path as specified, these PASS. If `ancient-ok` fails because the glob selected the 2020 file, tighten selection to `mtime >= cutoff` (cutoff is `swatter_now - 86400` = 1782309600; `touch -t 202001010000` is far below). If `rot-unr-ok` fails because a chmod 000 dated file with current mtime is still opened, that is the bug to fix.

- [ ] **Step 3: Fix `lib/mail_campaigns.sh` I/O until the new cases pass**

Keep the Task 2 parser. Required behaviors:

1. `_mailcamp_select_files` prints the live path first, then only siblings with `stat_mtime >= cutoff`.
2. Live path missing under `on` / explicit `auto` → `_mailcamp_emit_unreadable missing` **before** parsing anything.
3. Any selected path `! -r` → UNREADABLE, **do not** parse the readable siblings (no partial list).
4. `*.gz` via `gzip -dc --`.
5. `_mailcamp_should_run`: `off` → 1; `on` → 0; `auto` + explicit → 0; `auto` + default exists → 0; `auto` + default missing + not explicit → 1.

- [ ] **Step 4: Run the full mail_campaigns suite**

Run: `bash test/mail_campaigns_test.sh`

Expected: `FAIL=0`. Re-run `bash test/config_defaults_test.sh` as well.

- [ ] **Step 5: Commit**

```bash
git add lib/mail_campaigns.sh test/mail_campaigns_test.sh
git commit -m "$(cat <<'EOF'
feat(report): fail-loud Exim rotation and auto-skip

Unreadable selected files emit UNREADABLE, never a partial campaign
list. auto skips when the default path is absent; an explicit
EXIM_MAINLOG that is missing is still UNREADABLE.
EOF
)"
```

---

### Task 4: Digest wiring, quiet-skip, HTML, docs

Hooks the plane into the nightly report without changing the grade.

**Files:**
- Modify: `bin/swatter` (source list ~:67)
- Modify: `lib/report.sh` (gather ~:61–86, render ~:113–128, HTML ~:381–397, `swatter_report` skip ~:722–734)
- Modify: `test/report_test.sh`
- Modify: `docs/RUNBOOK.md` (new short section at end)
- Modify: `CHANGELOG.md` (`## [Unreleased]`)

**Interfaces:**
- Consumes: `_mailcamp_should_run`, `swatter_mail_campaigns_section`, `MAILCAMP_OK`, `MAILCAMP_N`, `MAILCAMP_FAILS`, `MAILCAMP_IPS`
- Produces: `_report_should_send` (0 = send); text banner `Mail Campaigns`; HTML block; quiet-skip honors campaigns and UNREADABLE

- [ ] **Step 1: Write the failing report-builder tests**

In `test/report_test.sh`, next to the existing plane stubs (~:34–40), add:

```bash
_mailcamp_should_run() { [[ "${FAKE_MAILCAMP:-}" == "run" ]]; }
swatter_mail_campaigns_section() {
    MAILCAMP_OK="${FAKE_MAILCAMP_OK:-1}"
    MAILCAMP_N="${FAKE_MAILCAMP_N:-0}"
    MAILCAMP_FAILS="${FAKE_MAILCAMP_FAILS:-0}"
    MAILCAMP_IPS="${FAKE_MAILCAMP_IPS:-0}"
    echo "(mail campaigns section)"
}
FAKE_MAILCAMP=""
```

Existing 1-plane / 3-plane checks must keep `Mail Campaigns` absent (`FAKE_MAILCAMP` empty). Add:

```bash
# 4th plane: campaign section when the stub says run.
FAKE_MAILCAMP=run FAKE_MAILCAMP_N=1 FAKE_MAILCAMP_OK=1
ERROR_DIGEST_ENABLE="false"; ORIGIN_LOCK_DIGEST="auto"; FAKE_OL=0
body="$(swatter_report_build 24h)"
check has-mailcamp "$(printf '%s' "$body" | grep -c 'Mail Campaigns')" "1"
FAKE_MAILCAMP=""
```

Add skip-predicate tests (after `_report_should_send` exists they will fail until Step 3). Put them with the grade checks:

```bash
# Quiet-window: campaigns or UNREADABLE must send; successful zero must not.
RPT_ACTED=0 RPT_EXEMPT=0 RPT_FAILED=0 OL_HITS=0 ERR_GENUINE=0 ERR_FATAL=0
unset MAILCAMP_OK MAILCAMP_N
check skip-unset   "$(_report_should_send; echo $?)" "1"
MAILCAMP_OK=1 MAILCAMP_N=0
check skip-zero    "$(_report_should_send; echo $?)" "1"
MAILCAMP_OK=1 MAILCAMP_N=1
check send-camp    "$(_report_should_send; echo $?)" "0"
MAILCAMP_OK=0 MAILCAMP_N=0
check send-unr     "$(_report_should_send; echo $?)" "0"
unset MAILCAMP_OK MAILCAMP_N

# Grade ignores MAILCAMP_N.
MAILCAMP_N=99 ERR_FATAL=0 ERR_GENUINE=0 OL_HITS=0 RPT_ACTED=0
REPORT_GRADE_FORCE=""
_report_grade
check grade-ignores-mailcamp "$RPT_GRADE" "GREEN"
unset MAILCAMP_N
```

HTML: after the existing `html-origin` check (~:75), with `FAKE_MAILCAMP=run` and `MAILCAMP_OK=1 MAILCAMP_N=1` in the environment of `_report_render_html`:

```bash
MAILCAMP_OK=1 MAILCAMP_N=1 MAILCAMP_FAILS=5 MAILCAMP_IPS=5
html_mc="$(_report_render_html "plain")"
check html-mailcamp "$(printf '%s' "$html_mc" | grep -c 'Mail Campaigns')" "1"
unset MAILCAMP_OK MAILCAMP_N MAILCAMP_FAILS MAILCAMP_IPS
```

- [ ] **Step 2: Run `bash test/report_test.sh` to verify new cases fail**

Expected: FAIL `has-mailcamp` (builder never calls the stub) and FAIL `_report_should_send: command not found`.

- [ ] **Step 3: Wire `lib/report.sh` and `bin/swatter`**

`bin/swatter` source list, insert `mail_campaigns` immediately before `report`:

```bash
for m in allowlist classify ingest store_sqlite block_csf block_ipset block block_cf origin_lock intel asn metrics corroborate errors mailer notify report_abuseipdb score swarm alerts mail_campaigns report; do
```

`lib/report.sh` — at the start of `swatter_report_build`, with the other unsets:

```bash
    unset MAILCAMP_OK MAILCAMP_N MAILCAMP_FAILS MAILCAMP_IPS
```

After the swarm gather block, before `_report_grade`:

```bash
    local mcfile=""
    if declare -F _mailcamp_should_run >/dev/null && _mailcamp_should_run; then
        mcfile="$(mktemp "${TMPDIR:-/tmp}/swatter-mcsec.XXXXXX")"
        swatter_mail_campaigns_section "$window" > "$mcfile"
    fi
```

After the swarm text section, before the help line:

```bash
    if [[ -n "${MAILCAMP_OK+x}" ]]; then
        echo
        echo "========================  Mail Campaigns  ======================="
        echo
        _report_summary_mailcamp
        echo
        [[ -n "$mcfile" && -s "$mcfile" ]] && cat "$mcfile"
    fi
    rm -f "$mcfile"
```

Add:

```bash
_report_summary_mailcamp() {
    if [[ "${MAILCAMP_OK:-1}" != "1" ]]; then
        echo "SMTP AUTH log unreadable — not an all-clear."
        return 0
    fi
    if (( ${MAILCAMP_N:-0} == 0 )); then
        echo "No SMTP AUTH campaigns this window."
        return 0
    fi
    echo "${MAILCAMP_N} mailbox(es) under a distributed SMTP AUTH spray (${MAILCAMP_FAILS} fails, ${MAILCAMP_IPS} IPs). Not blocked — rotate those passwords."
}

_report_should_send() {
    (( ${RPT_ACTED:-0} > 0 )) && return 0
    (( ${RPT_EXEMPT:-0} > 0 )) && return 0
    (( ${RPT_FAILED:-0} > 0 )) && return 0
    (( ${OL_HITS:-0} > 0 )) && return 0
    (( ${ERR_GENUINE:-0} > 0 )) && return 0
    (( ${ERR_FATAL:-0} > 0 )) && return 0
    if [[ "${MAILCAMP_OK+x}" == "x" ]]; then
        [[ "${MAILCAMP_OK}" != "1" ]] && return 0
        (( ${MAILCAMP_N:-0} > 0 )) && return 0
    fi
    return 1
}
```

Replace the quiet-window `if` in `swatter_report` (~:731) with:

```bash
    if (( ! test_mode )) && ! _report_should_send; then
        log_info "report: quiet window (${window}); not sending"
        return 0
    fi
```

HTML, after the Swarm block (~:397), before the Help line:

```bash
    if [[ "${MAILCAMP_OK+x}" == "x" ]]; then
        local mcc="$pine"
        [[ "${MAILCAMP_OK}" != "1" ]] && mcc="$ember"
        printf '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;border-top:1px solid %s;"><tr><td style="padding-top:14px;%s">Mail Campaigns</td><td style="padding-top:14px;%s;font-weight:700;font-size:20px;color:%s;text-align:right;">%s</td></tr></table>' \
            "$bdr" "$h3" "$f_h" "$mcc" "${MAILCAMP_N:-0}"
        printf '<div style="font-size:13px;color:%s;margin-top:5px;line-height:1.55;">%s</div>' \
            "$ink" "$(_report_summary_mailcamp | esc)"
    fi
```

`_report_grade` / `_report_verdict` / SMS: **no** `MAILCAMP_*` reads.

- [ ] **Step 4: RUNBOOK + CHANGELOG**

Append to `docs/RUNBOOK.md`:

```markdown
---

## Mail Campaigns (nightly digest)

The "Mail Campaigns" section is **visibility, not a block**. It lists mailboxes
that saw SMTP AUTH failures from many distinct IPs in the digest window
(default ≥5). Swatter did not CSF-deny those IPs and did not report them to
AbuseIPDB.

- **Rotate the listed mailboxes.** That is the actual cure.
- `UNREADABLE` means Exim's mainlog could not be read. That is not "no
  spray." Fix permissions/path (`EXIM_MAINLOG`) before treating the night as
  quiet.
- `MAIL_CAMPAIGN_DIGEST=off` disables the plane. It does not stop the spray.
- Do not enable cPHulk `username_based_protection` — anyone can lock a real
  mailbox by spraying its name.
```

Under `CHANGELOG.md` `## [Unreleased]`:

```markdown
### Added
- **Nightly digest: SMTP AUTH campaign visibility.** A fourth report plane
  reads `exim_mainlog` (plus in-window rotations) for `dovecot_login
  authenticator failed`, groups by mailbox, and lists campaigns (≥5 distinct
  connecting IPs by default). Visibility only — no CSF, no AbuseIPDB, no
  grade change. An unreadable log is UNREADABLE, never "0 campaigns."
```

- [ ] **Step 5: Run tests**

```bash
bash test/report_test.sh
bash test/mail_campaigns_test.sh
bash test/config_defaults_test.sh
make test
```

Expected: all green. Existing report 1-plane tests still have no Mail Campaigns banner (`FAKE_MAILCAMP` empty → `_mailcamp_should_run` false → `MAILCAMP_OK` stays unset).

- [ ] **Step 6: Commit**

```bash
git add bin/swatter lib/report.sh test/report_test.sh docs/RUNBOOK.md CHANGELOG.md
git commit -m "$(cat <<'EOF'
feat(report): wire SMTP AUTH campaigns into the nightly digest

Fourth plane, gathered before grade. Quiet-window skip sends on
campaigns or UNREADABLE. Grade and SMS still ignore MAILCAMP_*.
EOF
)"
```

---

## Spec coverage (self-review)

| Spec | Task |
|---|---|
| §1 locked decisions (no fold, visibility, report-time, exim, grade unchanged, fail-loud) | 1–4; no score/ingest/block files in the file list |
| §2 safety property | Task 2 parser never calls block/intel; Task 4 grade ignores MAILCAMP |
| §3 architecture, enable table, globals, quiet-skip, render-when-ran | Tasks 3–4 |
| §4 parser (anchor, TZ, IP-before-535, verbatim set_id, LC_ALL=C, drop incomplete) | Task 2 |
| §5 campaign rule, cap, remainder, zero/UNREADABLE copy | Tasks 2–3 |
| §6 knobs + `SWATTER_CONF=` tests | Task 1 |
| §7 test matrix | Tasks 1–4 |
| §8 out of scope | Global constraints |
| §9 files | File structure. Knob tests live in `config_defaults_test.sh` (that is where `SWATTER_CONF=` copies already run), not `shipped_config_valid_test.sh` (CIDR guard only). |

**Placeholder scan:** none. **Type consistency:** `swatter_mail_campaigns_section <window>`, `_mailcamp_should_run`, `_report_should_send`, `MAILCAMP_OK`/`N`/`FAILS`/`IPS` used under those names in every task.
