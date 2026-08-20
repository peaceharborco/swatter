#!/usr/bin/env bash
# End-to-end tests for tools/gate-d/gate-d-enrich.sh.
#
# Every case below is a bug a review round actually found. Four rounds each found
# a DIFFERENT way for a shared-egress address to reach bucket 2 — the pile no
# human reads, whose downstream consequence is an irreversible public abuse
# report. So the assertions are mostly of the form "this row must NOT be in
# bucket 2", plus a positive control so the suite cannot pass by sending
# everything to human review.
#
# `dig` is stubbed via PATH: these must be deterministic and must not depend on
# (or hit) live DNS.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
REPO="$PWD"
SCRIPT="$REPO/tools/gate-d/gate-d-enrich.sh"
[[ -f "$SCRIPT" ]] || { echo "FAIL missing $SCRIPT"; exit 1; }

BASH_BIN="$(command -v bash)"
if (( BASH_VERSINFO[0] < 4 )); then
    for c in /opt/homebrew/bin/bash /usr/local/bin/bash; do
        [[ -x "$c" ]] && { BASH_BIN="$c"; break; }
    done
fi
if ! "$BASH_BIN" -c '(( BASH_VERSINFO[0] >= 4 ))'; then
    echo "gate_d_enrich_test: SKIP (needs bash 4+; found ${BASH_VERSION})"; exit 0
fi

fails=0; passes=0
check() {
    if [[ "$2" == "$3" ]]; then echo "ok   $1"; passes=$((passes+1))
    else echo "FAIL $1: got '$2' want '$3'"; fails=$((fails+1)); fi
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/domlogs" "$TMP/state" "$TMP/etc" "$TMP/bin"

# --- stub dig -------------------------------------------------------------
# DIG_ANSWER is the TXT body handed back for any origin lookup.
cat > "$TMP/bin/dig" <<'DIG'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in -x) exit 0;; esac; done
[[ "${DIG_FAIL:-0}" == "1" ]] && exit 9
printf '%s\n' "${DIG_ANSWER:-\"64496 | 192.0.2.0/24 | US | arin | 2020-01-01\"}"
DIG
chmod +x "$TMP/bin/dig"

cat > "$TMP/etc/swatter.conf" <<EOF
STATE_DIR="$TMP/state"
LOG_DIR="$TMP/state"
DOMLOGS_GLOB="$TMP/domlogs/*"
ACCESS_LOG="$TMP/nonexistent_access_log"
OPERATOR_ALLOW_FILE="$TMP/etc/allow.cidr"
MONITORING_RANGES_FILE="$TMP/etc/monitoring.cidr"
CLOUDFLARE_IPS_FILE="$TMP/etc/cloudflare.cidr"
SHARED_EGRESS_CIDR_FILE="$TMP/etc/shared-egress.cidr"
SHARED_EGRESS_ASNS_FILE="$TMP/etc/shared-egress-asns.txt"
EOF
: > "$TMP/etc/allow.cidr"; : > "$TMP/etc/monitoring.cidr"; : > "$TMP/etc/cloudflare.cidr"
printf '104.28.0.0/16  # WARP v4\n' > "$TMP/etc/shared-egress.cidr"
printf '206092 # consumer VPN\n'    > "$TMP/etc/shared-egress-asns.txt"

# One scanner-shaped candidate: hard intel, nothing served, no UA on any request.
printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\n198.51.100.7\t3\t2026-08-19 10:00:00\tat-bar\n' \
    > "$TMP/preview.tsv"
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"
sqlite3 "$TMP/state/swatter.db" \
  "CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, ts INTEGER,
     action TEXT, channel TEXT, ttl INTEGER, score INTEGER, reason TEXT, dry_run INTEGER);
   INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
     ('198.51.100.7',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"

OUT="$TMP/out"
run() {  # run [env assignments...] -> echoes the bucket of 198.51.100.7
    rm -rf "$OUT"
    env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" "$@" \
        "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
        --out "$OUT" >/dev/null 2>&1
    awk -F'\t' 'NR>1 && $1=="198.51.100.7"{print $19; exit}' "$OUT/enriched.tsv" 2>/dev/null
}

# --- POSITIVE CONTROL ------------------------------------------------------
# Everything healthy: this row genuinely IS scanner-shaped, so it must reach
# bucket 2. Without this, every other assertion could pass by sorting all rows
# to human review.
b="$(run)"; check "control-scanner-shaped-row-reaches-bucket-2" "$b" "2"

# --- R4-A-B1: digit-leading DOCUMENTATION passes grep, names no ASN --------
printf '1. Add your ASNs below\n' > "$TMP/etc/shared-egress-asns.txt"
b="$(run)"; check "asn-file-of-documentation-must-not-clear-a-row" "$b" "3"
printf '206092 # consumer VPN\n' > "$TMP/etc/shared-egress-asns.txt"

# --- R3a: single entry, no trailing newline --------------------------------
printf '206092 # sole entry, no trailing newline' > "$TMP/etc/shared-egress-asns.txt"
b="$(run DIG_ANSWER='"206092 | 192.0.2.0/24 | US | arin | 2020-01-01"')"
check "unterminated-asn-entry-still-inerts" "$b" "1"
printf '206092 # consumer VPN\n' > "$TMP/etc/shared-egress-asns.txt"

# --- R3b / R2a: multi-origin, shared ASN NOT first -------------------------
b="$(run DIG_ANSWER='"13335 206092 | 104.28.0.0/16 | US | arin | 2020-01-01"')"
check "multi-origin-shared-asn-not-first-still-inerts" "$b" "1"

# --- R2b: ASN list unreadable ---------------------------------------------
: > "$TMP/etc/shared-egress-asns.txt"
b="$(run)"; check "empty-asn-list-cannot-clear-a-row" "$b" "3"
printf '206092 # consumer VPN\n' > "$TMP/etc/shared-egress-asns.txt"

# --- R4-B1: CIDR arm broken (poisoned file) --------------------------------
printf '0.0.0.0/0 # poison\n' > "$TMP/etc/shared-egress.cidr"
b="$(run)"; check "poisoned-cidr-file-cannot-clear-a-row" "$b" "3"
printf '104.28.0.0/16  # WARP v4\n' > "$TMP/etc/shared-egress.cidr"

# --- A-M4: a failed dig is not a successful evaluation ---------------------
b="$(run DIG_FAIL=1)"; check "failed-dig-cannot-clear-a-row" "$b" "3"

# --- R2a: a non-digit token makes the answer ambiguous ---------------------
b="$(run DIG_ANSWER='"NA | 192.0.2.0/24 | US | arin | 2020-01-01"')"
check "ambiguous-asn-answer-cannot-clear-a-row" "$b" "3"

# --- R1-B1: a request path containing a space is still "served" ------------
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /my file.html HTTP/1.1" 200 9 "-" "-"\n' \
    >> "$TMP/domlogs/example.com-ssl_log"
b="$(run)"; check "space-in-request-path-counts-as-served" "$b" "3"
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"

# --- R1-B1: an unparseable line forces review ------------------------------
printf '198.51.100.7 no quotes at all here\n' >> "$TMP/domlogs/example.com-ssl_log"
b="$(run)"; check "unparseable-log-line-forces-review" "$b" "3"
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"

# --- 304 is a successful delivery -----------------------------------------
printf '198.51.100.7 - - [19/Aug/2026:10:00:02 +0000] "GET /i.html HTTP/1.1" 304 0 "-" "-"\n' \
    >> "$TMP/domlogs/example.com-ssl_log"
b="$(run)"; check "304-counts-as-served" "$b" "3"
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"

# --- R1-B4: an invalid candidate never reaches dig -------------------------
printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\nnot-an-ip\t3\t2026-08-19 10:00:00\tat-bar\n' \
    > "$TMP/preview2.tsv"
outx="$TMP/outx"
env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview2.tsv" --libdir "$REPO/lib" --out "$outx" \
    >/dev/null 2>&1
w="$(awk -F'\t' 'NR>1{print $20; exit}' "$outx/enriched.tsv" 2>/dev/null)"
check "invalid-candidate-routed-to-review" "$w" "invalid-candidate"

# --- R4-B-B2: a stale COMPLETE report must not survive a new run ----------
b="$(run)"; grep -q "COMPLETE" "$OUT/buckets.txt" && r=present || r=absent
check "fresh-run-publishes-a-complete-report" "$r" "present"

# --- never-block poison guard ---------------------------------------------
printf '0.0.0.0/0 # oops\n' > "$TMP/etc/allow.cidr"
env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
    --out "$TMP/outnb" >/dev/null 2>&1 && r=ran || r=refused
check "over-broad-never-block-file-refuses-to-run" "$r" "refused"
: > "$TMP/etc/allow.cidr"

# --- A-M2: report-mode activity must not drive a real classification -------
# A dry_run=1 row is a detection that was never enforced. If it becomes MAX(ts)
# it can supply the hard-intel that sends a row into bucket 2 — a pile no human
# reads — on the strength of something the tool only ever pretended to do.
sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
  INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
    ('198.51.100.7',100,'temp','score=50 rule=scanner_profile',0),
    ('198.51.100.7',200,'temp','score=91 intel=abuseipdb:confidence100(100)',1);"
b="$(run)"; check "report-mode-row-cannot-supply-hard-intel" "$b" "3"
sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
  INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
    ('198.51.100.7',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"

# --- read-only: nothing written under STATE_DIR beyond our own fixture ----
extra="$(find "$TMP/state" -type f ! -name 'swatter.db' | wc -l | tr -d ' ')"
check "no-writes-under-state-dir" "$extra" "0"

echo "gate_d_enrich_test: PASS=${passes} FAIL=${fails}"
(( fails == 0 )) || exit 1
