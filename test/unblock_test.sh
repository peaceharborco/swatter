#!/usr/bin/env bash
# test/unblock_test.sh — `swatter unblock` CLI contract: a backend failure must
# surface as a nonzero exit + cause on stderr, never a false "unblocked". Drives
# bin/swatter end-to-end with a PATH-stubbed csf (like cli_test.sh's harness).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-unb-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-unb.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
mkdir -p "$state/log" "$state/bin"
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
STORE="flatfile"
SWATTER_NO_LOCK=1
CF_MODE="off"
DIRECT_BACKEND="csf"
EOF

# Failing csf -> unblock must exit nonzero and say why on stderr.
cat > "$state/bin/csf" <<'EOF'
#!/usr/bin/env bash
echo "csf: iptables lock timeout" >&2
exit 1
EOF
chmod +x "$state/bin/csf"
out="$(PATH="$state/bin:$PATH" bash "${ROOT}/bin/swatter" unblock 9.9.9.9 2>"$state/err")"
check fail-exit "$?" "1"
grep -q "INCOMPLETE" "$state/err" && PASS=$((PASS+1)) || { echo "FAIL fail-stderr-incomplete"; FAIL=$((FAIL+1)); }
grep -q "iptables lock timeout" "$state/err" && PASS=$((PASS+1)) || { echo "FAIL fail-stderr-cause"; FAIL=$((FAIL+1)); }
case "$out" in *"unblocked 9.9.9.9"*) echo "FAIL fail-no-false-success"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac

# Working csf -> exit 0, "unblocked".
cat > "$state/bin/csf" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$state/bin/csf"
out="$(PATH="$state/bin:$PATH" bash "${ROOT}/bin/swatter" unblock 9.9.9.9 2>/dev/null)"
check ok-exit "$?" "0"
case "$out" in *"unblocked 9.9.9.9"*) PASS=$((PASS+1));; *) echo "FAIL ok-stdout"; FAIL=$((FAIL+1));; esac

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
