#!/usr/bin/env bash
# test/refresh_feeds_test.sh — `swatter refresh-feeds` contract:
#   * a 200 with a non-CIDR body (captive portal / intercepting proxy) must
#     NEVER replace cloudflare.cidr — that file gates the never-block set, so
#     poisoning it could let a CF edge be CSF-denied (origin outage);
#   * a failed/invalid refresh exits nonzero so cron can alert;
#   * a valid download installs and exits 0.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }

export SWATTER_CONF="$(mktemp "${TMPDIR:-/tmp}/swatter-rf-conf.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/swatter-rf.XXXXXX")"
trap 'rm -rf "$state" "$SWATTER_CONF"' EXIT
mkdir -p "$state/log" "$state/bin" "$state/none"
cat > "$SWATTER_CONF" <<EOF
STATE_DIR="$state"
LOG_DIR="$state/log"
STORE="flatfile"
SWATTER_NO_LOCK=1
CF_MODE="off"
INTEL_PROVIDERS=""
CLOUDFLARE_IPS_FILE="$state/cloudflare.cidr"
SWATTER_HTTPD_CF_GLOB="$state/none/*.conf"
DOMLOGS_GLOB="$state/none/*"
EOF
printf '1.2.3.0/24\n' > "$state/cloudflare.cidr"   # pre-existing (stale but valid)

cat > "$state/bin/curl" <<EOF
#!/usr/bin/env bash
mode="\$(cat "$state/curl_mode" 2>/dev/null)"
case "\$mode" in
    good) case "\$*" in
              *ips-v4*) printf '104.16.0.0/13\n172.64.0.0/13\n131.0.72.0/22\n';;
              *ips-v6*) printf '2400:cb00::/32\n';;
          esac ;;
    html) printf '<html><body>gateway error</body></html>\n' ;;
    fail) exit 22 ;;
esac
exit 0
EOF
chmod +x "$state/bin/curl"
run() { PATH="$state/bin:$PATH" bash "${ROOT}/bin/swatter" refresh-feeds 2>"$state/err"; }

# A) 200-with-garbage -> file untouched, nonzero exit, cause logged.
echo html > "$state/curl_mode"
run; check garbage-rc-nonzero "$([[ $? -ne 0 ]] && echo yes || echo no)" "yes"
check garbage-file-kept "$(cat "$state/cloudflare.cidr")" "1.2.3.0/24"
grep -qi "invalid" "$state/err" && PASS=$((PASS+1)) || { echo "FAIL garbage-cause"; FAIL=$((FAIL+1)); }

# B) valid download -> installed, exit 0.
echo good > "$state/curl_mode"
run; check good-rc "$?" "0"
grep -q "104.16.0.0/13" "$state/cloudflare.cidr" && PASS=$((PASS+1)) || { echo "FAIL good-v4"; FAIL=$((FAIL+1)); }
grep -q "2400:cb00::/32" "$state/cloudflare.cidr" && PASS=$((PASS+1)) || { echo "FAIL good-v6"; FAIL=$((FAIL+1)); }

# C) download failure -> previous good file kept, nonzero exit.
echo fail > "$state/curl_mode"
run; check fail-rc-nonzero "$([[ $? -ne 0 ]] && echo yes || echo no)" "yes"
grep -q "104.16.0.0/13" "$state/cloudflare.cidr" && PASS=$((PASS+1)) || { echo "FAIL fail-file-kept"; FAIL=$((FAIL+1)); }

# D) valid download but UNWRITABLE target -> nonzero exit (a validated body
# that never lands must not read as success to cron).
echo good > "$state/curl_mode"
mkdir -p "$state/ro"; touch "$state/ro/cloudflare.cidr"
chmod 0444 "$state/ro/cloudflare.cidr"; chmod 0555 "$state/ro"
sed -i.bak "s|^CLOUDFLARE_IPS_FILE=.*|CLOUDFLARE_IPS_FILE=\"$state/ro/cloudflare.cidr\"|" "$SWATTER_CONF"
run; check write-fail-rc-nonzero "$([[ $? -ne 0 ]] && echo yes || echo no)" "yes"
chmod 0755 "$state/ro"; mv "$SWATTER_CONF.bak" "$SWATTER_CONF"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
