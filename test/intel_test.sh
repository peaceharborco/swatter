#!/usr/bin/env bash
# test/intel_test.sh — intel dispatch: max score, suppress verdict, legacy 3-field.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/intel.sh"

PASS=0; FAIL=0
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swatter-intel.XXXXXX")"
trap 'rm -rf "$STATE_DIR"' EXIT
mkdir -p "$STATE_DIR/intel"
INTEL_CACHE_TTL=86400

check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# Fake providers (4-field, 3-field legacy, and a suppress verdict).
provider_high()    { printf '90\t%s\thigh\t\n'      "$INTEL_CACHE_TTL"; }
provider_legacy()  { printf '40\t%s\tlegacy\n'      "$INTEL_CACHE_TTL"; }   # 3-field
provider_riot()    { printf '0\t%s\triot:google\tsuppress\n' "$INTEL_CACHE_TTL"; }
provider_nodata()  { return 1; }

# Max across providers, no suppress.
INTEL_PROVIDERS="legacy high"
out="$(swatter_intel_score 1.2.3.4)"
check max-score   "$(printf '%s' "$out" | cut -f1)" "90"
check max-supp0   "$(printf '%s' "$out" | cut -f3)" "0"

# Suppress flag set when any provider suppresses, even alongside a high score.
INTEL_PROVIDERS="high riot"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 5.6.7.8)"
check supp-flag   "$(printf '%s' "$out" | cut -f3)" "1"

# No-data provider contributes nothing.
INTEL_PROVIDERS="nodata"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 9.9.9.9)"
check nodata      "$(printf '%s' "$out" | cut -f1)" "0"

# Hostile label: a provider whose label carries control chars (tab / newline /
# backslash) — attacker- or MITM-influenced API field (e.g. GreyNoise .name).
# The label reaches the TSV score contract (cut -f2) and downstream reason /
# decisions.jsonl, so intel MUST sanitize it to a single clean line: no embedded
# tab (would mis-split the 3-field output), no newline, no backslash.
provider_evil() { printf '77\t%s\tmal\tishere\nSECOND\\line\t\n' "$INTEL_CACHE_TTL"; }
INTEL_PROVIDERS="evil"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 2.2.2.2)"
check evil-score      "$(printf '%s' "$out" | cut -f1)" "77"

# A provider (or MITM/proxy) that emits a LEADING blank line must not zero the
# reputation signal — we take the first NON-blank line, so the real score/label
# survive while any injected trailing lines are still dropped.
provider_blankfirst() { printf '\n80\t%s\tmalicious:x\t\n99\tINJECTED\t\n' "$INTEL_CACHE_TTL"; }
INTEL_PROVIDERS="blankfirst"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
bout="$(swatter_intel_score 4.4.4.4)"
check blankfirst-score "$(printf '%s' "$bout" | cut -f1)" "80"
check blankfirst-oneline "$(printf '%s' "$bout" | wc -l | tr -d ' ')" "0"
# One clean record: no embedded newline splitting the 3-field score contract.
check evil-one-line   "$(printf '%s' "$out" | wc -l | tr -d ' ')" "0"
lbl="$(printf '%s' "$out" | cut -f2)"
check evil-no-newline "$(printf '%s' "$lbl" | wc -l | tr -d ' ')" "0"
check evil-no-tab     "$(printf '%s' "$lbl" | grep -c $'\t')" "0"
check evil-no-bslash  "$(printf '%s' "$lbl" | grep -c '\\\\')" "0"

# _intel_clean directly: an INLINE backslash + tab on the SAME (first) line must
# be neutralized — tab removed (else it mis-splits the 3-field TSV), backslash
# removed (else it can corrupt the hand-built audit JSON).
_dirty="$(printf 'ab\\cd\tef')"   # ab\cd<TAB>ef
_cleaned="$(_intel_clean "$_dirty")"
check clean-no-tab     "$(printf '%s' "$_cleaned" | grep -c $'\t')" "0"
check clean-no-bslash  "$(printf '%s' "$_cleaned" | grep -c '\\\\')" "0"
check clean-keeps-text "$(printf '%s' "$_cleaned" | grep -c 'ab')" "1"
# A double-quote in a label is neutralized AT THE SOURCE (not only in the audit
# layer) so the intel TSV cache + bestlabel can't carry a raw quote anywhere.
check clean-no-quote   "$(printf '%s' "$(_intel_clean 'ev"il')" | grep -c '"')" "0"

# --- registry wiring: intel_init sources aggregates + refresh loop ---
SWATTER_LIB_DIR="${ROOT}/lib"
# A fake aggregate provider file would normally define provider_<name>; emulate by
# pre-defining one, then assert intel_init does NOT warn for it and DOES warn for a
# genuinely-missing provider.
provider_fakefeed() { printf '50\t%s\tfakefeed\n' "$INTEL_CACHE_TTL"; }
INTEL_PROVIDERS="ipsum fakefeed totallymissing"
warns="$(swatter_intel_init 2>&1 1>/dev/null)"
case "$warns" in *fakefeed*) echo "FAIL init-warns-defined"; FAIL=$((FAIL+1));; *) PASS=$((PASS+1));; esac
case "$warns" in *totallymissing*) PASS=$((PASS+1));; *) echo "FAIL init-missing-no-warn"; FAIL=$((FAIL+1));; esac

# swatter_intel_refresh_all calls _refresh for providers that define one, skips others.
RAN=""
provider_aaa_refresh() { RAN="${RAN}aaa "; }
provider_bbb_refresh() { RAN="${RAN}bbb "; }
provider_ccc()         { :; }   # no _refresh -> must be skipped
INTEL_PROVIDERS="aaa bbb ccc"
swatter_intel_refresh_all
check refresh-all "$RAN" "aaa bbb "

# refresh_all aggregates: partial failure warns but rc 0 (stale lists still
# usable); ALL refresh-capable feeds failing -> rc 1 so cron can alert.
provider_f1_refresh() { return 1; }
provider_f2_refresh() { return 1; }
provider_okk_refresh() { return 0; }
INTEL_PROVIDERS="f1 okk"
swatter_intel_refresh_all 2>/dev/null; check refresh-partial-rc "$?" "0"
INTEL_PROVIDERS="f1 f2"
swatter_intel_refresh_all 2>/dev/null; check refresh-allfail-rc "$?" "1"

# ipsum refresh must never install an EMPTY 200 body over a populated feed.
source "${ROOT}/lib/providers/ipsum.sh"
SWATTER_HAVE_CURL=1
mkdir -p "$STATE_DIR/feeds"; printf '9.9.9.9\n' > "$STATE_DIR/feeds/ipsum.txt"
curl() { local prev="" a out=""; for a in "$@"; do [[ "$prev" == "-o" ]] && out="$a"; prev="$a"; done; : > "$out"; return 0; }
provider_ipsum_refresh 2>/dev/null; check ipsum-empty-rc "$?" "1"
check ipsum-empty-kept "$(cat "$STATE_DIR/feeds/ipsum.txt")" "9.9.9.9"
unset -f curl

# --- [3] transient failure vs authoritative no-record caching ---
# A provider that exits INTEL_RC_TEMPFAIL (quota/transport/timeout) must get a
# SHORT negative-TTL cache entry, not a durable INTEL_CACHE_TTL "nodata" one that
# would blind us to the provider for a whole cache cycle. An authoritative
# no-record (any other non-zero) keeps the durable entry.
provider_temp()  { return "${INTEL_RC_TEMPFAIL:-75}"; }
INTEL_PROVIDERS="temp"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 3.3.3.3)"
check tempfail-score    "$(printf '%s' "$out" | cut -f1)" "0"
check tempfail-ttl      "$(awk -F'\t' 'NR==1{print $4}' "$STATE_DIR/intel/temp/3.3.3.3")" "${INTEL_FAIL_TTL:-300}"
check tempfail-label    "$(awk -F'\t' 'NR==1{print $2}' "$STATE_DIR/intel/temp/3.3.3.3")" "tempfail"

INTEL_PROVIDERS="nodata"
rm -rf "$STATE_DIR/intel"; mkdir -p "$STATE_DIR/intel"
out="$(swatter_intel_score 3.3.3.4)"
check nodata-durable-ttl "$(awk -F'\t' 'NR==1{print $4}' "$STATE_DIR/intel/nodata/3.3.3.4")" "$INTEL_CACHE_TTL"
check nodata-label       "$(awk -F'\t' 'NR==1{print $2}' "$STATE_DIR/intel/nodata/3.3.3.4")" "nodata"

# The short tempfail entry actually goes stale sooner than a durable one: drive
# swatter_now forward past INTEL_FAIL_TTL but well within INTEL_CACHE_TTL — the
# tempfail entry is expired (a re-query would re-hit the provider), the durable
# nodata entry is still fresh.
_base="$(date -u +%s)"
SWATTER_NOW_EPOCH=$(( _base + ${INTEL_FAIL_TTL:-300} + 60 ))
_stale_temp="$(_intel_cache_get temp 3.3.3.3; echo "rc=$?")"
check tempfail-stale   "${_stale_temp##*rc=}" "1"
_fresh_nodata="$(_intel_cache_get nodata 3.3.3.4 >/dev/null; echo "rc=$?")"
check nodata-still-fresh "${_fresh_nodata##*rc=}" "0"
unset SWATTER_NOW_EPOCH

# --- m13: per-entry TTL honored by _intel_cache_get (not just the global) ---
mkdir -p "$STATE_DIR/intel/ttlp"
printf '50\tlab\t\t10\n' > "$STATE_DIR/intel/ttlp/7.7.7.7"       # short ttl=10
SWATTER_NOW_EPOCH=$(( $(date -u +%s) + 100 ))                    # age ~100 > 10
_g="$(_intel_cache_get ttlp 7.7.7.7 >/dev/null; echo $?)"
check ttl-short-expired "$_g" "1"
printf '50\tlab\t\t100000\n' > "$STATE_DIR/intel/ttlp/8.8.8.8"   # long ttl
_g="$(_intel_cache_get ttlp 8.8.8.8 >/dev/null; echo $?)"
check ttl-long-fresh "$_g" "0"
# Legacy 3-field file (no ttl field) falls back to the global INTEL_CACHE_TTL.
printf '50\tlab\t\n' > "$STATE_DIR/intel/ttlp/6.6.6.6"
_g="$(_intel_cache_get ttlp 6.6.6.6 >/dev/null; echo $?)"
check ttl-legacy-fallback "$_g" "0"
unset SWATTER_NOW_EPOCH

# --- m14: a non-numeric score in a cache file is coerced to 0, not fed raw into
# the arithmetic (would error/misbehave in (( score > best ))). ---
mkdir -p "$STATE_DIR/intel/corrupt"
printf 'NOTANUM\tlab\t\t%s\n' "$INTEL_CACHE_TTL" > "$STATE_DIR/intel/corrupt/1.1.1.1"
INTEL_PROVIDERS="corrupt"
provider_corrupt() { return 1; }   # only the cache hit matters
cout="$(swatter_intel_score 1.1.1.1)"
check corrupt-score-zero "$(printf '%s' "$cout" | cut -f1)" "0"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
