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
mapfile -t perms < <(swatter_store_perm_ips)
check perm-count "${#perms[@]}" "2"
case " ${perms[*]} " in *" 1.2.3.4 "*) PASS=$((PASS+1));; *) echo "FAIL perm-has-ip"; FAIL=$((FAIL+1));; esac
case " ${perms[*]} " in *" 9.9.9.9 "*) echo "FAIL perm-excludes-temp"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
