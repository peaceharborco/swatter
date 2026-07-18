#!/usr/bin/env bash
# test/hardening_test.sh — file-based API keys (#4), curl-cfg under STATE_DIR (#2),
# and stale-state GC (#3).
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
PASS=0; FAIL=0
check() { local n="$1" g="$2" w="$3"; if [[ "$g" == "$w" ]]; then PASS=$((PASS+1)); else echo "FAIL ${n}: want='${w}' got='${g}'"; FAIL=$((FAIL+1)); fi; }
mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

SWATTER_CONF=/dev/null

# --- #4 file-based API keys: file wins over inline; inline kept when no/bad file --
GREYNOISE_KEY=""; GREYNOISE_KEY_FILE=""; HTTPBL_KEY=""; HTTPBL_KEY_FILE=""
TF="$(mktemp "${TMPDIR:-/tmp}/swatter-key.XXXXXX")"; printf 'file-key-value\n' > "$TF"
ABUSEIPDB_KEY=""; ABUSEIPDB_KEY_FILE="$TF"
swatter_load_config
check keyfile-loaded         "$ABUSEIPDB_KEY" "file-key-value"   # trailing newline stripped
ABUSEIPDB_KEY="inline-key"; ABUSEIPDB_KEY_FILE=""
swatter_load_config
check keyfile-inline-kept    "$ABUSEIPDB_KEY" "inline-key"
ABUSEIPDB_KEY="inline-key"; ABUSEIPDB_KEY_FILE="$TF"
swatter_load_config
check keyfile-file-wins      "$ABUSEIPDB_KEY" "file-key-value"
# CRLF / trailing-newline stripped (would 401 the provider otherwise).
printf 'crlf-key\r\n' > "$TF"; ABUSEIPDB_KEY=""; ABUSEIPDB_KEY_FILE="$TF"
swatter_load_config
check keyfile-crlf-stripped  "$ABUSEIPDB_KEY" "crlf-key"
# An EMPTY key file must NOT blank a good inline key.
: > "$TF"; ABUSEIPDB_KEY="inline-key"; ABUSEIPDB_KEY_FILE="$TF"
swatter_load_config
check keyfile-empty-keeps-inline "$ABUSEIPDB_KEY" "inline-key"
# A DIRECTORY path (which is `-r`) must NOT blank a good inline key.
DKF="$(mktemp -d "${TMPDIR:-/tmp}/swatter-kd.XXXXXX")"; ABUSEIPDB_KEY="inline-key"; ABUSEIPDB_KEY_FILE="$DKF"
swatter_load_config
check keyfile-dir-keeps-inline "$ABUSEIPDB_KEY" "inline-key"
rmdir "$DKF"
# The resolved key is a plain shell var, NOT exported (printenv sees only exports).
printf 'shellvar-key\n' > "$TF"; ABUSEIPDB_KEY=""; ABUSEIPDB_KEY_FILE="$TF"; swatter_load_config
check keyfile-not-exported   "$(printenv ABUSEIPDB_KEY >/dev/null 2>&1 && echo exported || echo not)" "not"
rm -f "$TF"

# --- #2 curl cfg lives under STATE_DIR/.curlcfg (0700), NOT world-shared /tmp -----
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-hard.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT
cfg="$(swatter_curl_cfg 'header = "X-Test: 1"')"
check curlcfg-under-statedir "$([[ "$cfg" == "${STATE_DIR}/.curlcfg/"* ]] && echo yes || echo no)" "yes"
check curlcfg-not-in-tmp     "$([[ "$(dirname -- "$cfg")" == "${TMPDIR:-/tmp}" ]] && echo yes || echo no)" "no"
check curlcfg-file-0600      "$(mode "$cfg")" "600"
check curlcfg-dir-0700       "$(mode "${STATE_DIR}/.curlcfg")" "700"
rm -f "$cfg"

# --- #3 swatter_state_gc drops old orphans/cache, keeps fresh --------------------
mkdir -p "${STATE_DIR}/.curlcfg" "${STATE_DIR}/intel/abuseipdb"
touch -t 202001010000 "${STATE_DIR}/.curlcfg/curl.OLD" "${STATE_DIR}/intel/abuseipdb/1.2.3.4"
touch "${STATE_DIR}/.curlcfg/curl.NEW" "${STATE_DIR}/intel/abuseipdb/5.6.7.8"
INTEL_CACHE_TTL=86400 INTEL_FAIL_TTL=3600 swatter_state_gc
check gc-old-curl-removed    "$([[ -e "${STATE_DIR}/.curlcfg/curl.OLD" ]] && echo yes || echo no)" "no"
check gc-new-curl-kept       "$([[ -e "${STATE_DIR}/.curlcfg/curl.NEW" ]] && echo yes || echo no)" "yes"
check gc-old-intel-removed   "$([[ -e "${STATE_DIR}/intel/abuseipdb/1.2.3.4" ]] && echo yes || echo no)" "no"
check gc-fresh-intel-kept    "$([[ -e "${STATE_DIR}/intel/abuseipdb/5.6.7.8" ]] && echo yes || echo no)" "yes"
# no STATE_DIR -> safe no-op
( STATE_DIR=""; swatter_state_gc; check gc-nostate-noop "$?" "0" )

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
