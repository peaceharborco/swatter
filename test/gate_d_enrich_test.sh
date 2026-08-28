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

# --- R5 real-data: a comments-only never-block file must NOT abort the run --
# Found by dry-running against cds1: monitoring.cidr ships as an all-comments
# header block. `-s` is true, comment-stripping leaves nothing, and
# swatter_intel_cidr_feed_ok fails on empty input -- so the round-4 guard
# aborted the entire gate D review on a stock, healthy file.
cp "$TMP/etc/monitoring.cidr" "$TMP/etc/monitoring.cidr.bak" 2>/dev/null || true
printf '# monitoring ranges -- one per line\n# (operator populates; none set)\n#\n' \
    > "$TMP/etc/monitoring.cidr"
env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
    --out "$TMP/outmc" >/dev/null 2>&1 && rmc=ran || rmc=refused
check "R5-comments-only-never-block-file-still-runs" "$rmc" "ran"
# ...but a real over-broad entry in the same file must still refuse.
printf '# header\n0.0.0.0/0\n' > "$TMP/etc/monitoring.cidr"
env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
    --out "$TMP/outmc2" >/dev/null 2>&1 && rmc2=ran || rmc2=refused
check "R5-overbroad-entry-in-commented-file-still-refuses" "$rmc2" "refused"
: > "$TMP/etc/monitoring.cidr"

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

# =========================================================================
# ROUND 5 — findings from the fifth pass (grok-4.6 correctness / grok-4.5
# red-team, both HOLD on the same B1). Both models noted the suite structurally
# could not catch B1: every fixture used a one-line IPv4 CIDR file, so the
# last-entry probe always happened to exercise the IPv4 matcher.
# =========================================================================

# --- R5-B1: dual-stack CIDR file, IPv6 last, IPv4 matcher broken ----------
# The probe must not certify the CIDR arm on the strength of ONE address
# family. Shipped config/shared-egress.cidr ends with a v6 range, so the v4
# awk matcher -- WARP v4's only protection, since AS13335 is deliberately off
# the ASN list -- went unprobed. Break v4 matching only; a WARP v4 row must
# still refuse to reach bucket 2.
printf '104.28.0.0/16  # WARP v4\n2a09:bac7::/32  # WARP v6 (LAST)\n' > "$TMP/etc/shared-egress.cidr"
printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\n104.28.196.52\t3\t2026-08-19 10:00:00\tat-bar\n' \
    > "$TMP/preview5.tsv"
printf '104.28.196.52 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"
sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
  INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
    ('104.28.196.52',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"
# A gawk that works for the traffic pass but an `awk` that fails for the
# library's IPv4 matcher is exactly the divergence the models reproduced.
cat > "$TMP/bin/awk" <<'BADAWK'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in ipint=*) exit 1;; esac; done
exec /usr/bin/awk "$@"
BADAWK
chmod +x "$TMP/bin/awk"
b5="$(env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
      "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview5.tsv" --libdir "$REPO/lib" \
      --out "$TMP/out5" >/dev/null 2>&1; \
      awk -F'\t' 'NR>1 && $1=="104.28.196.52"{print $19"/"$20; exit}' "$TMP/out5/enriched.tsv" 2>/dev/null)"
# Pin the REASON, not just the bucket [4.6-a m3]: scan_errs or have_traffic==0
# would also yield 3, so a bare bucket check could pass for the wrong reason.
check "R5-dual-stack-v4-matcher-broken-cannot-reach-bucket-2" "$b5" "3/shared-egress-not-evaluable"
rm -f "$TMP/bin/awk"

# Same file shape, matchers healthy: WARP v4 must be INERT, not merely reviewed.
b5="$(env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
      "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview5.tsv" --libdir "$REPO/lib" \
      --out "$TMP/out5b" >/dev/null 2>&1; \
      awk -F'\t' 'NR>1 && $1=="104.28.196.52"{print $19; exit}' "$TMP/out5b/enriched.tsv" 2>/dev/null)"
check "R5-dual-stack-healthy-warp-v4-is-inert" "$b5" "1"
printf '104.28.0.0/16  # WARP v4\n' > "$TMP/etc/shared-egress.cidr"

# --- R5-M1 (4.6-a): RFC6598 CGNAT is shared by construction ---------------
printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\n100.64.1.8\t3\t2026-08-19 10:00:00\tat-bar\n' \
    > "$TMP/preview6.tsv"
printf '100.64.1.8 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"
sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
  INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
    ('100.64.1.8',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"
b6="$(env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
      "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview6.tsv" --libdir "$REPO/lib" \
      --out "$TMP/out6" >/dev/null 2>&1; \
      awk -F'\t' 'NR>1 && $1=="100.64.1.8"{print $19; exit}' "$TMP/out6/enriched.tsv" 2>/dev/null)"
check "R5-cgnat-rfc6598-is-inert" "$b6" "1"

# --- R5-B2 (4.6-a), re-review B1 (4.5-b): EVERY mapped spelling -----------
# The first fix matched two literal spellings; 4.5-b reproduced four more that
# still reached bucket 2. lib/ingest.sh:33-34 unwraps only the compact form, so
# these are exactly the spellings the ledger preserves. Give each one the full
# bucket-2 setup (hard intel + matching traffic + no UA) so a miss really would
# land in 2, not merely fail for lack of evidence.
for mapped in '0:0:0:0:0:ffff:104.28.1.1' '::ffff:104.28.1.1' \
              '0000:0000:0000:0000:0000:ffff:104.28.1.1' '0::ffff:104.28.1.1' \
              '0:00:0:0:0:ffff:104.28.1.1' '0000::ffff:104.28.1.1'; do
    printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\n%s\t3\t2026-08-19 10:00:00\tat-bar\n' \
        "$mapped" > "$TMP/preview7.tsv"
    printf '%s - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
        "$mapped" > "$TMP/domlogs/example.com-ssl_log"
    sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
      INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
        ('$mapped',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"
    rm -rf "$TMP/out7"
    env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
        "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview7.tsv" --libdir "$REPO/lib" \
        --out "$TMP/out7" >/dev/null 2>&1
    w7="$(awk -F'\t' 'NR>1{print $19; exit}' "$TMP/out7/enriched.tsv" 2>/dev/null)"
    check "R5-mapped-never-bucket-2 [$mapped]" "$w7" "3"
done
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"
sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
  INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
    ('198.51.100.7',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"

# --- R5-M2 (both models): a row that does not parse must not vanish -------
# A 5-column row is still a CANDIDATE (first 4 fields taken), so it must be
# bucketed normally, not dropped. A 2-column line cannot be, so it must appear
# as a visible bucket-3 row -- never vanish, and never abort the run.
printf 'ip\ttemps_prior\tlast_temp_utc\tstatus\n198.51.100.7\t3\t2026-08-19 10:00:00\tat-bar\ntruncated-line\n\n# an operator annotation\n' \
    > "$TMP/preview8.tsv"
rm -rf "$TMP/out8"
env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview8.tsv" --libdir "$REPO/lib" \
    --out "$TMP/out8" >/dev/null 2>&1 && r8=ran || r8=refused
check "R5-annotated-preview-still-runs" "$r8" "ran"
n8="$(awk -F'\t' 'NR>1' "$TMP/out8/enriched.tsv" 2>/dev/null | wc -l | tr -d ' ')"
check "R5-unparsed-line-emitted-not-dropped" "$n8" "2"
u8="$(awk -F'\t' 'NR>1 && $20 ~ /^unparsed-preview-line/{print $19; exit}' "$TMP/out8/enriched.tsv" 2>/dev/null)"
check "R5-unparsed-line-is-bucket-3" "$u8" "3"
c8="$(grep -o 'COMPLETE [0-9]*/[0-9]*' "$TMP/out8/buckets.txt" 2>/dev/null | head -1)"
check "R5-complete-counts-include-unparsed" "$c8" "COMPLETE 2/2"

# --- R5-m3 (both models): a poisoned cloudflare.cidr must not inert all ---
printf '198.51.100.0/24 # not a Cloudflare range\n' > "$TMP/etc/cloudflare.cidr"
r9="$(env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
    --out "$TMP/out9" 2>&1 >/dev/null | grep -c 'documentation address')"
# Assert the SPECIFIC guard fired [4.6-a m3]: a bare exit-code check would pass
# on any unrelated die (bad conf, missing lib, broken awk).
check "R5-poisoned-cloudflare-file-refuses-to-run" "$r9" "1"

# 4.6-a M1: a narrow-but-implausible range evades the documentation canary.
printf '0.0.0.0/1 # poison that misses every canary\n' > "$TMP/etc/cloudflare.cidr"
r10="$(env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
    --out "$TMP/out10" 2>&1 >/dev/null | grep -c 'implausibly broad')"
check "R5-overbroad-cloudflare-range-refuses-to-run" "$r10" "1"

# ...and a REAL Cloudflare-shaped list (widest /13 and /29) must NOT trip it.
printf '104.16.0.0/13\n172.64.0.0/13\n162.158.0.0/15\n2a06:98c0::/29\n' > "$TMP/etc/cloudflare.cidr"
env PATH="$TMP/bin:$PATH" SWATTER_CONF="$TMP/etc/swatter.conf" \
    "$BASH_BIN" "$SCRIPT" --preview "$TMP/preview.tsv" --libdir "$REPO/lib" \
    --out "$TMP/out11" >/dev/null 2>&1 && r11=ran || r11=refused
check "R5-real-cloudflare-widths-still-run" "$r11" "ran"
: > "$TMP/etc/cloudflare.cidr"

# --- R5-m1 (4.6-a): a redirect is a served response ------------------------
sqlite3 "$TMP/state/swatter.db" "DELETE FROM actions;
  INSERT INTO actions(ip,ts,action,reason,dry_run) VALUES
    ('198.51.100.7',100,'temp','score=91 intel=abuseipdb:confidence100(100) rule=critical_badpath',0);"
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n198.51.100.7 - - [19/Aug/2026:10:00:03 +0000] "GET /x HTTP/1.1" 301 0 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"
b="$(run)"; check "R5-301-counts-as-served" "$b" "3"
printf '198.51.100.7 - - [19/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "-"\n' \
    > "$TMP/domlogs/example.com-ssl_log"

# --- read-only: nothing written under STATE_DIR beyond our own fixture ----
extra="$(find "$TMP/state" -type f ! -name 'swatter.db' | wc -l | tr -d ' ')"
check "no-writes-under-state-dir" "$extra" "0"

echo "gate_d_enrich_test: PASS=${passes} FAIL=${fails}"
(( fails == 0 )) || exit 1
