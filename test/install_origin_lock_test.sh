#!/usr/bin/env bash
# test/install_origin_lock_test.sh — install.sh origin-lock wiring:
#   1. the managed csfpre block passes --yes (else DROP silently no-ops at csf -r)
#   2. _ol_retire_legacy_static safely neutralizes a hand static block WITHOUT
#      breaking csfpre.sh shell syntax, backs it up, keeps the managed block, idempotent.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/swatter-inst.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
ok()   { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# Source install.sh for its functions without running main.
# shellcheck disable=SC1091
source "${ROOT}/install/install.sh" --source-only 2>/dev/null || true

# ===========================================================================
# 1. managed csfpre block includes --yes (Blocker 1)
# ===========================================================================
pre="$TMP/csfpre.sh"
SWATTER_OL_CSFPRE="$pre" _install_origin_lock_csfpre >/dev/null 2>&1
if grep -qF -- 'origin-lock apply --hook=csf --yes' "$pre"; then ok; else fail "managed block missing '--yes' (DROP would silently no-op at csf -r)"; fi
grep -qF -- "$ORIGIN_LOCK_BEGIN" "$pre" && ok || fail "managed BEGIN marker absent"
grep -qF -- "$ORIGIN_LOCK_END" "$pre"   && ok || fail "managed END marker absent"
# guarded so a broken binary fails OPEN
grep -qF -- '[ -x /usr/local/bin/swatter ]' "$pre" && ok || fail "managed block not guarded on binary presence"

# ===========================================================================
# 2. _ol_retire_legacy_static: BEHAVIORALLY neutralize a hand static block (the
#    DROP must stop running), keep csfpre valid sh, back up, keep managed block
#    active, idempotent (Blockers 3/4). Uses PATH-stubbed iptables/ipset so we
#    assert what actually EXECUTES, not what the text looks like.
# ===========================================================================
pre2="$TMP/csfpre2.sh"
cat > "$pre2" <<'STATIC'
#!/bin/sh
# hand-written origin lock (legacy)
MODE="DROP"
SET4="cf_origin4"
ipset create "$SET4" hash:net family inet -exist
ipset flush "$SET4"
for cidr in 203.0.113.0/24 198.51.100.0/24; do
    ipset add "$SET4" "$cidr" -exist
done
iptables -I INPUT -p tcp -m multiport --dports 80,443 -m set --match-set "$SET4" src -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m limit --limit 10/min -j LOG --log-prefix "ORIGIN-LOCK: "
if [ "$MODE" = "DROP" ]; then
    iptables -A INPUT -p tcp -m multiport --dports 80,443 -j DROP
fi
STATIC
{ echo "$ORIGIN_LOCK_BEGIN"; echo 'if [ -x /usr/local/bin/swatter ]; then'; echo '    /usr/local/bin/swatter origin-lock apply --hook=csf --yes || true'; echo 'fi'; echo "$ORIGIN_LOCK_END"; } >> "$pre2"

# PATH stubs that record every firewall call to a shared log.
bindir="$TMP/bin"; mkdir -p "$bindir"; fwlog="$TMP/fw.log"
for c in iptables ip6tables ipset; do
    printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$c" "$fwlog" > "$bindir/$c"; chmod +x "$bindir/$c"
done
runcsfpre() { : > "$fwlog"; PATH="$bindir:$PATH" sh "$1" >/dev/null 2>&1 || true; }

sh -n "$pre2" 2>/dev/null && ok || fail "fixture csfpre is not valid sh to begin with"
# sanity: BEFORE retire the static block DOES invoke the DROP
runcsfpre "$pre2"; grep -q -- "iptables -A INPUT.*-j DROP" "$fwlog" && ok || fail "fixture didn't DROP before retire (test is meaningless)"

SWATTER_NOW_STAMP="TESTSTAMP" _ol_retire_legacy_static "$pre2" >/dev/null 2>&1

# a) backup exists
[[ -f "${pre2}.bak-TESTSTAMP" ]] && ok || fail "retire: no backup created"
# b) result is STILL valid shell (the whole point — no dangling then/do)
sh -n "$pre2" 2>/dev/null && ok || fail "retire: csfpre.sh is no longer valid sh (syntax broken)"
# c) BEHAVIOR: after retire the DROP no longer runs, and neither do the legacy ipset ops
runcsfpre "$pre2"
grep -q -- "-j DROP" "$fwlog" && fail "retire: legacy DROP still executes" || ok
grep -q -- "ipset create cf_origin4" "$fwlog" && fail "retire: legacy ipset still executes" || ok
# d) not deleted — the DROP text is preserved (inside the retired here-doc)
grep -qF -- 'iptables -A INPUT -p tcp -m multiport --dports 80,443 -j DROP' "$pre2" && ok || fail "retire: DROP text was deleted, not neutralized"
# e) managed block still ACTIVE: its --yes line sits AFTER the here-doc terminator
mark_ln="$(grep -nxF "$_OL_RETIRE_MARK" "$pre2" | head -1 | cut -d: -f1)"
yes_ln="$(grep -nF -- 'origin-lock apply --hook=csf --yes' "$pre2" | head -1 | cut -d: -f1)"
if [[ -n "$mark_ln" && -n "$yes_ln" && "$yes_ln" -gt "$mark_ln" ]]; then ok; else fail "retire: managed block not active (yes_ln=$yes_ln mark_ln=$mark_ln)"; fi
# f) idempotent: second run makes no new backup and no content change
cp "$pre2" "$TMP/before-2nd"
SWATTER_NOW_STAMP="TESTSTAMP2" _ol_retire_legacy_static "$pre2" >/dev/null 2>&1
[[ ! -f "${pre2}.bak-TESTSTAMP2" ]] && ok || fail "retire: not idempotent (made a 2nd backup)"
diff -q "$TMP/before-2nd" "$pre2" >/dev/null 2>&1 && ok || fail "retire: not idempotent (content changed on 2nd run)"

echo "----------------------------------------"
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
