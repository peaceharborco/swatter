#!/usr/bin/env bash
# test/config_defaults_test.sh — new keys have safe built-in defaults.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }
check asn-default       "${ASN_SIGNAL_ENABLE}" "false"
check wasn-default      "${W_ASN}" "12"
check persist-default   "${PERSIST_ENABLE}" "true"
check persist-n         "${PERSIST_N}" "6"
check bucket-default    "${PERSIST_BUCKET_SECONDS}" "3600"
check gn-quota-default  "${GREYNOISE_DAILY_QUOTA}" "100"
check intel-has-gn      "$(case " ${INTEL_PROVIDERS} " in *' greynoise '*) echo yes;; *) echo no;; esac)" "yes"
echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
