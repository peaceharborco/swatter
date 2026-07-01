#!/usr/bin/env bash
# test/origin_lock_test.sh — origin-lock rule composition, fail-open, idempotency,
# ACME toggle, drop guard, preflight classification, and disable teardown. Injects
# iptables/ip6tables/ipset via shell functions (the block_ipset_test.sh pattern);
# no live firewall is ever touched.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/report.sh"
source "${ROOT}/lib/allowlist.sh"
source "${ROOT}/lib/origin_lock.sh"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-ol.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
CALLS="$TMP/calls"; : > "$CALLS"

# --- environment / config under test ---------------------------------------
SWATTER_MODE="enforce"
ORIGIN_LOCK="log"
ORIGIN_LOCK_PORTS="80,443"
ORIGIN_LOCK_ALLOW_ACME="true"
ORIGIN_LOCK_SET="cf_origin"
STATE_DIR="$TMP/state"; LOG_DIR="$TMP/log"; mkdir -p "$STATE_DIR" "$LOG_DIR"
ALLOWLIST_MAX_AGE_DAYS=7
SWATTER_NOW_EPOCH="$(date -u +%s)"
SWATTER_HAVE_IP6TABLES=1
SWATTER_OL_HAVE_XT_STRING=1   # pretend xt_string is available unless a test clears it
SWATTER_OL_CSFPRE="$TMP/csfpre.none"   # absent by default -> persistence-removal no-ops
SWATTER_OL_UNIT="$TMP/unit.none"

# A healthy cloudflare.cidr with both families (>= min ranges).
CLOUDFLARE_IPS_FILE="$TMP/cloudflare.cidr"
cat > "$CLOUDFLARE_IPS_FILE" <<'EOF'
203.0.113.0/24
198.51.100.0/24
192.0.2.0/24
2001:db8:1::/48
2001:db8:2::/48
EOF

OPERATOR_ALLOW_FILE="$TMP/allow.cidr"
MONITORING_RANGES_FILE="$TMP/monitoring.cidr"
: > "$OPERATOR_ALLOW_FILE"; : > "$MONITORING_RANGES_FILE"

check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
# -e protects patterns that start with '-' (e.g. '-j DROP', '-i lo') from being
# parsed as grep options — without it those negative checks vacuously "pass".
has()   { local n="$1" pat="$2"; if grep -qF -e "$pat" "$CALLS"; then PASS=$((PASS+1)); else echo "FAIL ${n}: '${pat}' not in calls"; FAIL=$((FAIL+1)); fi; }
hasnt() { local n="$1" pat="$2"; if grep -qF -e "$pat" "$CALLS"; then echo "FAIL ${n}: '${pat}' unexpectedly in calls"; FAIL=$((FAIL+1)); else PASS=$((PASS+1)); fi; }
count() { local n="$1" pat="$2" want="$3" g; g="$(grep -cF -e "$pat" "$CALLS")"; check "$n" "$g" "$want"; }

# --- firewall stubs (record every call; -C returns 1 so guarded inserts fire) --
ipset()    { echo "ipset $*" >> "$CALLS"; if [[ "$1" == "list" ]]; then return "${IPSET_LIST_RC:-1}"; fi; return 0; }
iptables() { echo "iptables $*" >> "$CALLS"; [[ "$1" == "-C" ]] && return "${IPT_CHECK_RC:-1}"; return 0; }
ip6tables(){ echo "ip6tables $*" >> "$CALLS"; [[ "$1" == "-C" ]] && return "${IPT_CHECK_RC:-1}"; return 0; }

# ===========================================================================
# 1. apply (log mode, --hook=csf) — CF/ACME accept + LOG, NO established, NO preamble
# ===========================================================================
: > "$CALLS"
cmd_origin_lock apply --hook=csf
has  csf-set4   "ipset create cf_origin4 hash:net family inet"
has  csf-set6   "ipset create cf_origin6 hash:net family inet6"
has  csf-add4   "ipset add cf_origin4 203.0.113.0/24"
has  csf-add6   "ipset add cf_origin6 2001:db8:1::/48"
has  csf-acc4   "iptables -A INPUT -p tcp -m multiport --dports 80,443 -m set --match-set cf_origin4 src -j ACCEPT"
has  csf-acc6   "ip6tables -A INPUT -p tcp -m multiport --dports 80,443 -m set --match-set cf_origin6 src -j ACCEPT"
has  csf-acme4  "iptables -A INPUT -p tcp --dport 80 -m string --string /.well-known/ --algo bm -j ACCEPT"
has  csf-log4   "iptables -A INPUT -p tcp -m multiport --dports 80,443 -m limit --limit 5/min -j LOG --log-prefix ORIGIN-LOCK: "
has  csf-log6   "ip6tables -A INPUT -p tcp -m multiport --dports 80,443 -m limit --limit 5/min -j LOG --log-prefix ORIGIN-LOCK: "
hasnt csf-no-drop4 "-j DROP"
hasnt csf-no-lo    "-i lo"
hasnt csf-no-estab "ESTABLISHED"

# ===========================================================================
# 2. accept-before-log ordering (ACCEPT must precede LOG in the call stream)
# ===========================================================================
acc_line="$(grep -nF -e 'cf_origin4 src -j ACCEPT' "$CALLS" | head -1 | cut -d: -f1)"
log_line="$(grep -nF -e '-j LOG' "$CALLS" | head -1 | cut -d: -f1)"
if [[ -n "$acc_line" && -n "$log_line" && "$acc_line" -lt "$log_line" ]]; then PASS=$((PASS+1)); else echo "FAIL order-accept-before-log"; FAIL=$((FAIL+1)); fi

# ===========================================================================
# 3. standalone apply (plain) — adds lo + allow/monitoring preamble, NO established
# ===========================================================================
: > "$CALLS"
cmd_origin_lock apply
has  std-lo    "iptables -C INPUT -i lo -p tcp -m multiport --dports 80,443 -j ACCEPT"
has  std-allow "INPUT"
hasnt std-no-estab "ESTABLISHED"
# guarded inserts: standalone uses -C then -I (idempotent), not bare -A
has  std-guard "iptables -C INPUT"

# ===========================================================================
# 3b. STANDALONE ordering invariant (drop mode, plain hook) — the effective
#     top-to-bottom INPUT chain must be accept-first / drop-last EVEN THOUGH
#     standalone builds with `-I` (prepend). Because every -I lands at position 1,
#     the effective chain order is the REVERSE of the -I call stream: the rule
#     inserted LAST sits at the TOP. So in the recorded call stream we require the
#     emission order DROP -> LOG -> CF-ACCEPT -> preamble(lo), which yields the
#     intended effective order lo,CF-ACCEPT,...,LOG,DROP top->bottom. This guards
#     the standalone reversal that the csf-only tests (2,4) never exercised.
: > "$CALLS"
ORIGIN_LOCK="drop"
cmd_origin_lock apply --yes >/dev/null 2>&1
# Pull line numbers of the v4 INSERT (`-I`) emissions in the call stream.
ins_drop="$(grep -nF -e 'iptables -I INPUT' "$CALLS" | grep -F -e '-j DROP'                       | head -1 | cut -d: -f1)"
ins_cf="$(  grep -nF -e 'iptables -I INPUT' "$CALLS" | grep -F -e 'cf_origin4 src -j ACCEPT'       | head -1 | cut -d: -f1)"
ins_lo="$(  grep -nF -e 'iptables -I INPUT' "$CALLS" | grep -F -e '-i lo'                          | head -1 | cut -d: -f1)"
# Effective order = reverse of insert order. DROP must be inserted BEFORE (lower
# call-stream line than) CF-ACCEPT, and CF-ACCEPT before the lo preamble accept,
# so that effective top->bottom is lo, CF-ACCEPT, ..., DROP.
if [[ -n "$ins_drop" && -n "$ins_cf" && -n "$ins_lo" \
      && "$ins_drop" -lt "$ins_cf" && "$ins_cf" -lt "$ins_lo" ]]; then
    PASS=$((PASS+1))
else
    echo "FAIL std-order-drop-last (insert stream: drop=${ins_drop} cf=${ins_cf} lo=${ins_lo}; need drop<cf<lo)"
    FAIL=$((FAIL+1))
fi
ORIGIN_LOCK="log"

# ===========================================================================
# 4. drop mode + --yes installs DROP (last); log mode never does
# ===========================================================================
: > "$CALLS"
ORIGIN_LOCK="drop"
cmd_origin_lock apply --hook=csf --yes
has  drop-rule4 "iptables -A INPUT -p tcp -m multiport --dports 80,443 -j DROP"
has  drop-rule6 "ip6tables -A INPUT -p tcp -m multiport --dports 80,443 -j DROP"
# DROP must be the LAST rule line: appears after the ACCEPT
acc_l="$(grep -nF -e 'cf_origin4 src -j ACCEPT' "$CALLS" | head -1 | cut -d: -f1)"
drp_l="$(grep -nF -e '-j DROP' "$CALLS" | head -1 | cut -d: -f1)"
if [[ -n "$acc_l" && -n "$drp_l" && "$acc_l" -lt "$drp_l" ]]; then PASS=$((PASS+1)); else echo "FAIL order-accept-before-drop"; FAIL=$((FAIL+1)); fi

# ===========================================================================
# 5. drop guard: drop mode WITHOUT --yes/--force must NOT install DROP
# ===========================================================================
: > "$CALLS"
ORIGIN_LOCK="drop"
cmd_origin_lock apply --hook=csf </dev/null >/dev/null 2>&1
rc=$?
hasnt guard-no-drop "-j DROP"
check guard-rc-nonzero "$([[ "$rc" -ne 0 ]] && echo nz || echo z)" "nz"
ORIGIN_LOCK="log"

# ===========================================================================
# 6. fail-open: missing cloudflare.cidr => install NOTHING
# ===========================================================================
: > "$CALLS"
CLOUDFLARE_IPS_FILE="$TMP/does-not-exist.cidr"
cmd_origin_lock apply --hook=csf >/dev/null 2>&1
hasnt failopen-missing-no-rules "-j LOG"
hasnt failopen-missing-no-accept "-j ACCEPT"

# fail-open: empty file => nothing
: > "$CALLS"
CLOUDFLARE_IPS_FILE="$TMP/empty.cidr"; : > "$CLOUDFLARE_IPS_FILE"
cmd_origin_lock apply --hook=csf >/dev/null 2>&1
hasnt failopen-empty "-j LOG"

# fail-open: too few ranges (< min) => nothing
: > "$CALLS"
CLOUDFLARE_IPS_FILE="$TMP/tiny.cidr"; printf '203.0.113.0/24\n' > "$CLOUDFLARE_IPS_FILE"
cmd_origin_lock apply --hook=csf >/dev/null 2>&1
hasnt failopen-tiny "-j LOG"
# restore healthy file
CLOUDFLARE_IPS_FILE="$TMP/cloudflare.cidr"

# ===========================================================================
# 7. v6 gating: ip6tables absent => warn-and-skip v6, still build v4
# ===========================================================================
: > "$CALLS"
SWATTER_HAVE_IP6TABLES=0
cmd_origin_lock apply --hook=csf >/dev/null 2>&1
has   v6gate-v4-present "iptables -A INPUT -p tcp -m multiport --dports 80,443 -m set --match-set cf_origin4 src -j ACCEPT"
hasnt v6gate-v6-absent  "ip6tables -A INPUT"
SWATTER_HAVE_IP6TABLES=1

# ===========================================================================
# 8. ACME toggle off => no ACME accept rule
# ===========================================================================
: > "$CALLS"
ORIGIN_LOCK_ALLOW_ACME="false"
cmd_origin_lock apply --hook=csf >/dev/null 2>&1
hasnt acme-off "well-known"
ORIGIN_LOCK_ALLOW_ACME="true"

# ACME soft-fail when xt_string missing => warn, no ACME rule, rest still applied
: > "$CALLS"
SWATTER_OL_HAVE_XT_STRING=0
cmd_origin_lock apply --hook=csf >/dev/null 2>&1
hasnt acme-xtstring-missing "well-known"
has   acme-rest-still "iptables -A INPUT -p tcp -m multiport --dports 80,443 -m set --match-set cf_origin4 src -j ACCEPT"
SWATTER_OL_HAVE_XT_STRING=1

# ===========================================================================
# 9. idempotent standalone re-apply: -C guard present so -I is conditional
# ===========================================================================
: > "$CALLS"
IPT_CHECK_RC=0   # pretend rule already exists -> -C succeeds -> -I must NOT run
cmd_origin_lock apply >/dev/null 2>&1
hasnt idem-no-insert "iptables -I INPUT -i lo"
IPT_CHECK_RC=1

# ===========================================================================
# 10. apply with ORIGIN_LOCK=off => teardown (remove rules + sets)
# ===========================================================================
: > "$CALLS"
ORIGIN_LOCK="off"
cmd_origin_lock apply >/dev/null 2>&1
has off-teardown "iptables -D INPUT"
hasnt off-no-append "-A INPUT"
hasnt off-no-insert "-I INPUT"
ORIGIN_LOCK="log"

# ===========================================================================
# 11. disable => removes rules AND sets
# ===========================================================================
: > "$CALLS"
cmd_origin_lock disable >/dev/null 2>&1
has dis-destroy4 "ipset destroy cf_origin4"
has dis-destroy6 "ipset destroy cf_origin6"
has dis-del-accept "iptables -D INPUT"

# ===========================================================================
# 12. preflight classification — intel hit vs allowlist vs unknown
# ===========================================================================
# Fixture LOG sample read from a file (portable source override).
SAMPLE="$TMP/kernlog.sample"
cat > "$SAMPLE" <<'EOF'
kernel: ORIGIN-LOCK: IN=eth0 SRC=198.18.0.1 DST=203.0.113.5 PROTO=TCP
kernel: ORIGIN-LOCK: IN=eth0 SRC=198.18.0.2 DST=203.0.113.5 PROTO=TCP
kernel: ORIGIN-LOCK: IN=eth0 SRC=198.18.0.3 DST=203.0.113.5 PROTO=TCP
EOF
SWATTER_OL_LOG_SAMPLE="$SAMPLE"   # impl honors this override instead of journalctl/syslog
# .1 is an attacker (intel feed), .2 is allowlisted, .3 is unknown.
INTEL_PROVIDERS="fixturefeed"
# Minimal intel-score stub (intel.sh is not sourced in this unit test): emit
# "score\tlabel\tsuppress" the way lib/intel.sh's swatter_intel_score does.
swatter_intel_score() { case "$1" in 198.18.0.1) printf '95\tfixture:deny\t0\n';; *) printf '0\t\t0\n';; esac; }
printf '198.18.0.2/32\n' > "$OPERATOR_ALLOW_FILE"
out="$(cmd_origin_lock preflight 2>/dev/null)"
echo "$out" | grep -q '198.18.0.1' && echo "$out" | grep -qiE '198.18.0.1.*(attack|confirmed|intel|deny)' && PASS=$((PASS+1)) || { echo "FAIL preflight-attacker"; FAIL=$((FAIL+1)); }
echo "$out" | grep -qiE '198.18.0.2.*(allow|legit|monitor)' && PASS=$((PASS+1)) || { echo "FAIL preflight-allowlist"; FAIL=$((FAIL+1)); }
echo "$out" | grep -qiE '198.18.0.3.*(unknown|review)' && PASS=$((PASS+1)) || { echo "FAIL preflight-unknown"; FAIL=$((FAIL+1)); }

# ===========================================================================
# 13. report (dry-run) mode performs NO firewall mutation — including off-teardown
# ===========================================================================
: > "$CALLS"
SWATTER_MODE="report"
ORIGIN_LOCK="off"
cmd_origin_lock apply >/dev/null 2>&1
hasnt report-off-no-destroy "ipset destroy"
hasnt report-off-no-del     "iptables -D INPUT"
ORIGIN_LOCK="log"
: > "$CALLS"
cmd_origin_lock apply >/dev/null 2>&1
hasnt report-log-no-create "ipset create"
hasnt report-log-no-accept "-j ACCEPT"
SWATTER_MODE="enforce"

# ===========================================================================
# 14. disable strips persistence hooks (csfpre managed block + systemd unit)
# ===========================================================================
systemctl() { echo "systemctl $*" >> "$CALLS"; return 0; }   # stub so disable can "disable" the unit
CSFPRE_FIXTURE="$TMP/csfpre.sh"
cat > "$CSFPRE_FIXTURE" <<'EOF'
#!/bin/sh
# operator-OWN-line-above
# >>> swatter origin-lock (managed) >>>
/usr/local/bin/swatter origin-lock apply --hook=csf || true
# <<< swatter origin-lock (managed) <<<
# operator-OWN-line-below
EOF
UNIT_FIXTURE="$TMP/swatter-origin-lock.service"; : > "$UNIT_FIXTURE"
SWATTER_OL_CSFPRE="$CSFPRE_FIXTURE"
SWATTER_OL_UNIT="$UNIT_FIXTURE"
cmd_origin_lock disable >/dev/null 2>&1
if ! grep -qF 'swatter origin-lock apply --hook=csf' "$CSFPRE_FIXTURE" \
   && grep -qF 'operator-OWN-line-above' "$CSFPRE_FIXTURE" \
   && grep -qF 'operator-OWN-line-below' "$CSFPRE_FIXTURE"; then PASS=$((PASS+1)); else echo "FAIL disable-strips-csfpre-block"; FAIL=$((FAIL+1)); fi
if [[ ! -f "$UNIT_FIXTURE" ]]; then PASS=$((PASS+1)); else echo "FAIL disable-removes-unit"; FAIL=$((FAIL+1)); fi
SWATTER_OL_CSFPRE="$TMP/csfpre.none"; SWATTER_OL_UNIT="$TMP/unit.none"

# --- origin-lock digest section ---------------------------------------------
OLD_STATE="$STATE_DIR"
DIG="$(mktemp -d "${TMPDIR:-/tmp}/swatter-oldig.XXXXXX")"; STATE_DIR="$DIG"
mkdir -p "$DIG/feeds"
printf '45.135.232.17\n193.32.162.40\n' > "$DIG/feeds/ipsum.txt"   # 2 known attackers
ORIGIN_LOCK_LOG="$DIG/messages"
# Build date-relative syslog timestamps so the window filter is always exercised.
# Use SWATTER_NOW_EPOCH (set at top of this file) as the reference "now" so the
# day labels generated here match those computed inside swatter_originlock_section.
_now_ts="${SWATTER_NOW_EPOCH}"
_now_lbl="$(date -d "@${_now_ts}" +'%b %e %T' 2>/dev/null || date -r "${_now_ts}" +'%b %e %T')"
_old_ts=$(( _now_ts - 864000 ))   # 10 days ago — well outside the 24h window
_old_lbl="$(date -d "@${_old_ts}" +'%b %e %T' 2>/dev/null || date -r "${_old_ts}" +'%b %e %T')"
# 3 sources in-window: 45.. (attacker, :80 x2), 193.. (attacker, :443 x1), 198.51.100.7 (unknown, :80 x1)
# Plus one out-of-window line from a NEW IP (10.10.10.10) that must be excluded.
{
    printf '%s cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=45.135.232.17 DPT=80 SPT=51000\n'  "$_now_lbl"
    printf '%s cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=45.135.232.17 DPT=80 SPT=51002\n'  "$_now_lbl"
    printf '%s cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=193.32.162.40 DPT=443 SPT=4000\n'  "$_now_lbl"
    printf '%s cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=198.51.100.7 DPT=80 SPT=4002\n'    "$_now_lbl"
    printf '%s cds1 kernel: ORIGIN-LOCK: IN=eth0 SRC=10.10.10.10 DPT=80 SPT=9999\n'     "$_old_lbl"
} > "$DIG/messages"
# Call directly (not in $()) so OL_* globals persist in this shell; capture text separately.
ORIGIN_LOCK_DIGEST="auto"
_oltmp="$(mktemp "${TMPDIR:-/tmp}/swatter-olsec.XXXXXX")"; swatter_originlock_section 24h > "$_oltmp"; out="$(cat "$_oltmp")"; rm -f "$_oltmp"
check ol-hits   "$OL_HITS" "4"
check ol-ips    "$OL_IPS"  "3"
check ol-p80    "$OL_P80"  "3"
check ol-p443   "$OL_P443" "1"
check ol-top-attacker "$(printf '%s\n' "$OL_TOP_ROWS" | awk -F'\t' '$1=="45.135.232.17"{print $3}')" "attacker"
# Prove window filter: the 10-day-old line from 10.10.10.10 must be excluded.
check ol-window-exclude-oldip "$(printf '%s\n' "$OL_TOP_ROWS" | grep -c '10\.10\.10\.10' || true)" "0"
check ol-gate-auto-hits "$(_ol_digest_should_render 4 && echo show || echo hide)" "show"

# OL_MODE resolution: conf ORIGIN_LOCK (managed hook) is authoritative; a legacy
# static MODE= only surfaces when conf is off — so the digest is correct after the
# static->managed reconciliation, not stuck on a retired static artifact.
ORIGIN_LOCK="drop"; SWATTER_OL_CSFPRE="$TMP/csfpre.none"
swatter_originlock_section 24h >/dev/null 2>&1
check ol-mode-conf-authoritative "$OL_MODE" "drop"
ORIGIN_LOCK=""; printf 'MODE="DROP"\n' > "$TMP/csfpre.legacy"; SWATTER_OL_CSFPRE="$TMP/csfpre.legacy"
swatter_originlock_section 24h >/dev/null 2>&1
check ol-mode-legacy-static "$OL_MODE" "drop (static)"
ORIGIN_LOCK="log"; SWATTER_OL_CSFPRE="$TMP/csfpre.none"
ORIGIN_LOCK_DIGEST="auto"
check ol-gate-auto-zero  "$(_ol_digest_should_render 0 && echo show || echo hide)" "hide"
ORIGIN_LOCK_DIGEST="on"
check ol-gate-on-zero    "$(_ol_digest_should_render 0 && echo show || echo hide)" "show"
ORIGIN_LOCK_DIGEST="off"
check ol-gate-off-hits   "$(_ol_digest_should_render 4 && echo show || echo hide)" "hide"
STATE_DIR="$OLD_STATE"; rm -rf "$DIG"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
