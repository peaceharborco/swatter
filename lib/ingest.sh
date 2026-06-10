#!/usr/bin/env bash
# lib/ingest.sh — incremental log ingestion + combined-log parsing.
#
# Reads only the bytes appended since the last run, per file, using a
# (path, inode, offset) cursor stored in $STATE_DIR/cursors.tsv. Emits parsed
# TSV on stdout for lib/score.awk:
#   ip \t epoch \t method \t path \t status \t bytes \t ua \t vhost
#
# Why a byte offset and not a timestamp high-water mark: combined-log timestamps
# have one-second resolution, so a timestamp cursor on a busy log either
# re-scans or skips the many requests sharing the boundary second. A byte cursor
# is exact. Rotation is detected by inode change or size shrink.

# Parse combined log format on stdin -> TSV on stdout.
# vhost is supplied via -v vhost=... (basename of the domlog; empty for the
# shared access_log). The IP is field 1 (already CF-Connecting-IP in domlogs).
_swatter_parse() {
    local vhost="$1"
    gawk -v vhost="${vhost}" '
        BEGIN { OFS = "\t"
            split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", _mn, " ")
            for (_i=1;_i<=12;_i++) mon[_mn[_i]] = _i
        }
        {
            ip = $1
            if (ip == "" || ip == "-") next

            # Timestamp: [dd/Mon/yyyy:HH:MM:SS +zzzz]
            lb = index($0, "[")
            rb = index($0, "]")
            if (lb == 0 || rb == 0 || rb < lb) next
            tsraw = substr($0, lb+1, rb-lb-1)        # dd/Mon/yyyy:HH:MM:SS +zzzz
            # Split off the day/mon/year:H:M:S, ignore the tz offset for epoch
            # purposes (Apache logs are emitted in server TZ; we treat the whole
            # pipeline as UTC, consistent with the rest of the toolchain).
            n = split(tsraw, a, /[\/: ]/)
            if (n < 6) next
            m = mon[a[2]]; if (m == "") next
            epoch = mktime(a[3]" "m" "a[1]" "a[4]" "a[5]" "a[6]" 0")
            if (epoch < 0) next

            # Request line: first double-quoted field after the timestamp.
            q1 = index($0, "\"")
            if (q1 == 0) next
            rest = substr($0, q1+1)
            q2 = index(rest, "\"")
            if (q2 == 0) next
            req = substr(rest, 1, q2-1)              # METHOD path proto
            after = substr(rest, q2+1)

            split(req, rp, " ")
            method = rp[1]
            path = rp[2]
            if (path == "") path = "-"
            sub(/\?.*$/, "", path)                   # strip query string
            path = tolower(path)
            if (length(path) > 256) path = substr(path, 1, 256)
            method = toupper(method)

            # Status: first 3-digit token after the request quote.
            ns = split(after, sp, " ")
            status = "0"; bytes = "0"
            for (k = 1; k <= ns; k++) {
                if (sp[k] ~ /^[0-9][0-9][0-9]$/) { status = sp[k]; if (sp[k+1] ~ /^[0-9-]+$/) bytes = sp[k+1]; break }
            }
            if (bytes == "-") bytes = "0"

            # User-agent: substring between the LAST pair of double quotes.
            ualast = ""
            p = $0
            # find last quote
            lastq = 0
            for (i = length(p); i >= 1; i--) { if (substr(p,i,1) == "\"") { lastq = i; break } }
            if (lastq > 1) {
                prevq = 0
                for (i = lastq-1; i >= 1; i--) { if (substr(p,i,1) == "\"") { prevq = i; break } }
                if (prevq > 0) ualast = substr(p, prevq+1, lastq-prevq-1)
            }
            ua = tolower(ualast)
            if (ua == "") ua = "-"

            print ip, epoch, method, path, status, bytes, ua, vhost
        }
    '
}

# Read appended bytes from one file, honoring the cursor. Echoes the new cursor
# line ("path\tinode\toffset\tnow") to fd 3 so the caller can collect updated
# cursors without mixing them into the parsed-output stream on stdout.
_swatter_read_file() {
    local path="$1" vhost="$2" cursors="$3" now="$4"
    [[ -f "$path" ]] || return 0
    [[ -r "$path" ]] || { log_warn "cannot read ${path}"; return 0; }

    local inode size start prev_inode prev_off
    inode="$(stat_inode "$path")" || return 0
    size="$(stat_size "$path")"   || return 0

    local prev=""
    if [[ -f "$cursors" ]]; then
        prev="$(awk -F'\t' -v p="$path" '$1==p{print; exit}' "$cursors")"
    fi

    if [[ -z "$prev" ]]; then
        # First sight: backfill the tail SEED_BYTES only.
        if (( size > SEED_BYTES )); then start=$(( size - SEED_BYTES )); else start=0; fi
    else
        prev_inode="$(printf '%s' "$prev" | cut -f2)"
        prev_off="$(printf '%s' "$prev" | cut -f3)"
        if [[ "$prev_inode" != "$inode" ]] || (( size < prev_off )); then
            start=0   # rotated or truncated
        else
            start="$prev_off"
        fi
    fi

    # Cap the per-file read; on overflow, jump forward and warn (gap).
    if (( size - start > MAX_BYTES_PER_FILE )); then
        log_warn "log_gap ${path}: $(( size - start )) bytes pending > cap ${MAX_BYTES_PER_FILE}; skipping ahead"
        start=$(( size - MAX_BYTES_PER_FILE ))
    fi

    if (( size > start )); then
        tail -c +$(( start + 1 )) "$path" 2>/dev/null | _swatter_parse "$vhost"
    fi

    printf '%s\t%s\t%s\t%s\n' "$path" "$inode" "$size" "$now" >&3
}

# Ingest every configured source; write parsed TSV to stdout, refresh cursors.
swatter_ingest() {
    local now cursors tmp_cursors
    now="$(swatter_now)"
    cursors="${STATE_DIR}/cursors.tsv"
    tmp_cursors="$(mktemp "${TMPDIR:-/tmp}/swatter-cursors.XXXXXX")" || die "mktemp failed"

    {
        # Per-vhost domlogs (primary, real client IP via mod_remoteip).
        local f base vh
        for f in ${DOMLOGS_GLOB}; do
            [[ -f "$f" ]] || continue
            base="$(basename "$f")"
            case "$base" in
                *-bytes_log) continue ;;          # byte-count mirror, not requests
            esac
            vh="${base%-ssl_log}"; vh="${vh%_log}"
            _swatter_read_file "$f" "$vh" "$cursors" "$now"
        done
        # Shared access_log (raw-IP hits / no-vhost).
        [[ -n "${ACCESS_LOG}" ]] && _swatter_read_file "${ACCESS_LOG}" "" "$cursors" "$now"
    } 3>>"$tmp_cursors"

    # Merge: keep refreshed cursors, carry forward any file we did not touch.
    if [[ -f "$cursors" ]]; then
        awk -F'\t' 'NR==FNR{seen[$1]=1; print; next} !($1 in seen)' "$tmp_cursors" "$cursors" > "${tmp_cursors}.merged" 2>/dev/null \
            && mv "${tmp_cursors}.merged" "$tmp_cursors"
    fi
    mv "$tmp_cursors" "$cursors" 2>/dev/null || true
    chmod 0640 "$cursors" 2>/dev/null || true
}
