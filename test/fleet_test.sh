#!/usr/bin/env bash
# test/fleet_test.sh — export-bans (store perm list) + import-bans (allowlist-safe).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP (no sqlite3)"; echo "Total: 0 passed, 0 failed"; exit 0; }
source "${ROOT}/lib/store_sqlite.sh"
PASS=0; FAIL=0
STORE=sqlite; STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-fleet.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
REPEAT_WINDOW_DAYS=7
swatter_store_init
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

# Seed two perm offenders + one temp-only.
swatter_store_record 1.2.3.4 perm csf 0 95 "r" 0
swatter_store_record 5.6.7.8 perm csf 0 95 "r" 0
swatter_store_record 9.9.9.9 temp csf 3600 80 "r" 0
# 7.7.7.7: perm recorded ONLY in dry-run (dry_run=1) — detected, never blocked.
swatter_store_record 7.7.7.7 perm csf 0 95 "r" 1
# 8.8.8.8: really perm-blocked, then unblocked — must not be re-exported.
swatter_store_record 8.8.8.8 perm csf 0 95 "r" 0
swatter_store_unblock 8.8.8.8
mapfile -t perms < <(swatter_store_perm_ips)
check perm-count "${#perms[@]}" "2"
case " ${perms[*]} " in *" 1.2.3.4 "*) PASS=$((PASS+1));; *) echo "FAIL perm-has-ip"; FAIL=$((FAIL+1));; esac
case " ${perms[*]} " in *" 9.9.9.9 "*) echo "FAIL perm-excludes-temp"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac
case " ${perms[*]} " in *" 7.7.7.7 "*) echo "FAIL perm-excludes-dryrun"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac
case " ${perms[*]} " in *" 8.8.8.8 "*) echo "FAIL perm-excludes-unblocked"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac

# Same invariants on the flatfile (JSONL replay) backend.
( STORE=flatfile; STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-fleet-ff.XXXXXX")"; swatter_store_init
  swatter_store_record 1.2.3.4 perm csf 0 95 "r" 0      # enforced perm -> exported
  swatter_store_record 7.7.7.7 perm csf 0 95 "r" 1      # dry-run only  -> excluded
  swatter_store_record 8.8.8.8 perm csf 0 95 "r" 0; swatter_store_unblock 8.8.8.8  # unblocked -> excluded
  swatter_store_record 9.9.9.9 temp csf 3600 80 "r" 0   # temp          -> excluded
  ffp="$(swatter_store_perm_ips | tr '\n' ' ')"
  rm -rf "$STATE_DIR"
  ec=0
  case " $ffp " in *" 1.2.3.4 "*) ;; *) echo "FAIL ff-has-enforced-perm: '$ffp'"; ec=1;; esac
  case " $ffp " in *" 7.7.7.7 "*) echo "FAIL ff-excludes-dryrun"; ec=1;; esac
  case " $ffp " in *" 8.8.8.8 "*) echo "FAIL ff-excludes-unblocked"; ec=1;; esac
  case " $ffp " in *" 9.9.9.9 "*) echo "FAIL ff-excludes-temp"; ec=1;; esac
  exit $ec
) && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "=== import-bans: never-block + invalid skipped, valid applied (dry-run) ==="
IB_PASS=0; IB_FAIL=0
ib_conf="$(mktemp "${TMPDIR:-/tmp}/swatter-ib-conf.XXXXXX")"
ib_state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-ib.XXXXXX")"
ib_allow="$ib_state/allow.cidr"; printf '5.5.5.5\n' > "$ib_allow"
ib_bans="$ib_state/bans.txt"; printf '1.2.3.4\n5.5.5.5\nnot-an-ip\n# a comment\n' > "$ib_bans"
cat > "$ib_conf" <<EOF
STATE_DIR="$ib_state"
LOG_DIR="$ib_state/log"
STORE="flatfile"
SWATTER_MODE="report"
SWATTER_NO_LOCK=1
OPERATOR_ALLOW_FILE="$ib_allow"
DIRECT_BACKEND="csf"
EOF
out="$(SWATTER_CONF="$ib_conf" bash "${ROOT}/bin/swatter" import-bans "$ib_bans" 2>&1)"
# 5.5.5.5 is allowlisted -> must be skipped as never-block.
case "$out" in *"never-block"*5.5.5.5*|*5.5.5.5*"never-block"*) IB_PASS=$((IB_PASS+1));; *) echo "FAIL import-skips-neverblock"; IB_FAIL=$((IB_FAIL+1));; esac
# exactly one ban applied (1.2.3.4); 5.5.5.5 + not-an-ip + comment excluded.
case "$out" in *"1 ban(s) applied"*) IB_PASS=$((IB_PASS+1));; *) echo "FAIL import-applied-count: ${out}"; IB_FAIL=$((IB_FAIL+1));; esac
rm -rf "$ib_state" "$ib_conf"
printf '  import-bans: %d passed, %d failed\n' "$IB_PASS" "$IB_FAIL"
(( IB_FAIL == 0 )) || FAIL=$((FAIL+1))

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
