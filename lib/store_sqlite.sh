#!/usr/bin/env bash
# lib/store_sqlite.sh — offense/decision ledger.
#
# NOTE: This file assumes lib/common.sh has already been sourced (provides
# swatter_is_valid_ip_or_cidr, log_warn, swatter_now, and the globals callers
# expect). Normal entrypoint (bin/swatter) ensures the correct load order.
#
# Tracks per-IP offense history (for repeat-offender escalation) and an append
# log of every action taken. Primary backend is SQLite; a flatfile JSONL
# fallback is used automatically when sqlite3 is absent (see common.sh dep check
# flipping STORE=flatfile). Both expose the same swatter_store_* API.
#
# Schema (sqlite):
#   offenders(ip PK, first_seen, last_seen, worst_score, total_offenses,
#             temp_count, perm INTEGER, last_label, channel)
#   actions(id PK, ip, ts, action, channel, ttl, score, reason, dry_run)

_swatter_db() { printf '%s/swatter.db' "${STATE_DIR}"; }
_swatter_jsonl() { printf '%s/ledger.jsonl' "${STATE_DIR}"; }

swatter_store_init() {
    if [[ "${STORE}" == "sqlite" ]]; then
        # Capture stderr, don't discard it: a corrupt/unwritable DB that fails
        # schema bootstrap would otherwise start the scan on a silently-empty
        # ledger, losing cap + repeat-escalation state with no signal. Warn loud
        # and propagate rc so the caller/cron can tell the ledger is broken.
        local _ierr _irc
        _ierr="$(sqlite3 -cmd '.timeout 3000' "$(_swatter_db)" 2>&1 >/dev/null <<'SQL'
CREATE TABLE IF NOT EXISTS offenders(
  ip TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER,
  worst_score INTEGER DEFAULT 0, total_offenses INTEGER DEFAULT 0,
  temp_count INTEGER DEFAULT 0, perm INTEGER DEFAULT 0,
  last_label TEXT, channel TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, ts INTEGER,
  action TEXT, channel TEXT, ttl INTEGER, score INTEGER, reason TEXT, dry_run INTEGER);
CREATE INDEX IF NOT EXISTS ix_actions_ip_ts ON actions(ip, ts);
CREATE TABLE IF NOT EXISTS sightings(
  ip TEXT, bucket INTEGER, hits INTEGER DEFAULT 0,
  worst_score INTEGER DEFAULT 0, last_ts INTEGER,
  PRIMARY KEY (ip, bucket));
CREATE INDEX IF NOT EXISTS ix_sightings_ip ON sightings(ip);
CREATE TABLE IF NOT EXISTS plane_blocks(
  ip TEXT NOT NULL, plane TEXT NOT NULL,
  kind TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (ip, plane));
CREATE TABLE IF NOT EXISTS pending_blocks(
  ip TEXT NOT NULL, plane TEXT NOT NULL,
  action TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 0,
  reason TEXT, top_vhost TEXT,
  folded INTEGER NOT NULL DEFAULT 0, rep INTEGER NOT NULL DEFAULT 0,
  ev TEXT, audit_action TEXT,
  first_failed INTEGER NOT NULL, last_attempt INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (ip, plane));
SQL
        )"; _irc=$?
        if (( _irc != 0 )); then
            log_error "store init FAILED (${STORE} ${STATE_DIR}): $(printf '%s' "$_ierr" | tr '\n' ' ' | cut -c1-160)"
            return "$_irc"
        fi
        chmod 0640 "$(_swatter_db)" 2>/dev/null || true
    else
        touch "$(_swatter_jsonl)" 2>/dev/null || true
        chmod 0640 "$(_swatter_jsonl)" 2>/dev/null || true
    fi
}

# Run sqlite3 with stderr CAPTURED, not discarded: a locked/corrupt/unwritable
# DB silently diverging the ledger from the firewall is undiagnosable. Errors
# log a bounded warn; stdout passes through untouched for parsers; rc propagates.
# A busy_timeout keeps a concurrent writer from failing instantly with "database
# is locked" and dropping a ledger record while the firewall block succeeded.
_sql() {
    local err rc
    { err="$(sqlite3 -cmd '.timeout 3000' "$(_swatter_db)" "$@" 2>&1 >&3 3>&-)"; rc=$?; } 3>&1
    (( rc != 0 )) && log_warn "sqlite error (rc=${rc}): $(printf '%s' "$err" | tr '\n' ' ' | cut -c1-160)"
    return "$rc"
}
_sqlq() { _sql "$1"; }

# Proper escaping for a value that will be placed inside a single-quoted
# SQLite string literal ( '  -->  '' ). Defense in depth; called with IPs
# that have already been validated by the CLI or scoring path.
_sql_escape() {
    printf '%s' "${1//\'/\'\'}"
}

# Non-fatal ip gate for every store function. The store layer sits below the
# scan loop, so a malformed token (log corruption, odd address form) is logged
# and treated as "no data" — it must never die() and take the sweep down.
_store_ip_ok() {
    swatter_is_valid_ip_or_cidr "${1:-}" && return 0
    log_warn "store: ignoring malformed ip '${1:-}'"
    return 1
}

# Count REAL temp blocks for an IP within the repeat window (used for
# escalation). Only enforced blocks (dry_run=0) count — a report-mode detection
# means "we watched and did nothing," so it must not drive a real permanent ban
# the moment enforce is switched on.
#
# Temps at or before the IP's most recent `unblock` are EXCLUDED. An operator
# who unblocks a false positive is correcting our decision; leaving those temps
# in the count meant the IP's next offense computed prior+1 >= REPEAT_N and went
# straight to perm, silently undoing the correction. Only cmd_unblock writes an
# `unblock` row (CF sweep/CSF expiry write none), so natural expiry never resets
# the ladder.
swatter_store_recent_temp_count() {
    local ip="$1" since
    _store_ip_ok "$ip" || { echo 0; return 0; }
    since=$(( $(swatter_now) - REPEAT_WINDOW_DAYS*86400 ))
    local sip; sip="$(_sql_escape "$ip")"
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT COUNT(*) FROM actions
                WHERE ip='${sip}' AND action='temp' AND dry_run=0 AND ts>${since}
                  AND ts > (SELECT COALESCE(MAX(ts),0) FROM actions
                             WHERE ip='${sip}' AND action='unblock');"
    else
        awk -v ip="$ip" -v since="$since" '
            # Exact IP match. index() not regex — an IP contains dots, which a
            # regex would treat as wildcards and over-match neighbouring IPs.
            index($0, "\"ip\":\"" ip "\"") == 0 { next }
            {
                ts = 0
                if (match($0, /"ts":[0-9]+/)) ts = substr($0, RSTART+5, RLENGTH-5) + 0
            }
            /"action":"unblock"/ { if (ts > ub) ub = ts; next }
            /"action":"temp"/ && /"dry_run":0/ { if (ts > since) { n++; t[n] = ts } }
            END { c = 0; for (i = 1; i <= n; i++) if (t[i] > ub) c++; print c + 0 }
        ' "$(_swatter_jsonl)"
    fi
}

# Offline escalation preview: which IPs would reach REPEAT_N temps inside a
# candidate window, computed from the LEDGER ONLY. No ingest, no cursor
# advance, no mode change — safe to run against a live production host, which
# is the whole point (a report-mode "canary" cannot see history, because ingest
# is byte-cursor based and only ever reads new log bytes).
# Echoes: ip \t temps_in_window \t last_temp_iso
#   swatter_escalate_preview [window_days]
swatter_escalate_preview() {
    local win="${1:-${REPEAT_WINDOW_DAYS}}"
    [[ "$win" =~ ^[0-9]+$ ]] && (( win >= 1 )) || win="${REPEAT_WINDOW_DAYS}"
    local n="${REPEAT_N}"
    [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 )) || n=3
    [[ "${STORE}" == "sqlite" ]] || { log_warn "escalate-preview requires STORE=sqlite"; return 1; }
    local since; since=$(( $(swatter_now) - win*86400 ))
    # Mirrors swatter_store_recent_temp_count exactly: enforced temps only,
    # inside the window, after any operator unblock.
    _sqlq "SELECT a.ip, COUNT(*) AS c, datetime(MAX(a.ts),'unixepoch')
             FROM actions a
            WHERE a.action='temp' AND a.dry_run=0 AND a.ts > ${since}
              AND a.ts > (SELECT COALESCE(MAX(u.ts),0) FROM actions u
                           WHERE u.ip = a.ip AND u.action='unblock')
            GROUP BY a.ip
           HAVING c >= ${n}
            ORDER BY c DESC, a.ip;" | tr '|' '\t'
}

# Is the IP already permanently blocked?
swatter_store_is_perm() {
    local ip="$1"
    _store_ip_ok "$ip" || return 1
    local sip; sip="$(_sql_escape "$ip")"
    if [[ "${STORE}" == "sqlite" ]]; then
        [[ "$(_sqlq "SELECT perm FROM offenders WHERE ip='${sip}';")" == "1" ]]
    else
        # Flatfile JSONL is append-only: a bare grep for a perm row reports an IP
        # as perm even after a LATER unblock cleared it. Replay records in order —
        # banned on an ENFORCED perm (dry_run=0), cleared on a later unblock — and
        # honor only the final state (matches the sqlite offenders.perm semantics,
        # which also bumps perm only on an enforced block).
        local st
        st="$(awk -v ip="$ip" '
            { found=0 }
            match($0, /"ip":"[^"]*"/) { if (substr($0, RSTART+6, RLENGTH-7)==ip) found=1 }
            found {
                a=""; match($0, /"action":"[^"]*"/) && a=substr($0, RSTART+10, RLENGTH-11)
                if (a=="perm") { if ($0 ~ /"dry_run":0/) state=1 }
                else if (a=="unblock") state=0
            }
            END { print state+0 }' "$(_swatter_jsonl)" 2>/dev/null)"
        [[ "$st" == "1" ]]
    fi
}

# Record an action and upsert offender stats.
#   swatter_store_record <ip> <action> <channel> <ttl> <score> <reason> <dry_run>
swatter_store_record() {
    local ip="$1" action="$2" channel="$3" ttl="$4" score="$5" reason="$6" dry="$7"
    _store_ip_ok "$ip" || return 1
    local now; now="$(swatter_now)"
    local sip; sip="$(_sql_escape "$ip")"
    local sreason; sreason="$(_sql_escape "$reason")"
    # Escape action/channel too (defense in depth — internal values, but never
    # trust an interpolated string literal).
    local saction; saction="$(_sql_escape "$action")"
    local schannel; schannel="$(_sql_escape "$channel")"
    # Coerce numerics to integers before interpolating unquoted into SQL — a
    # non-numeric ttl/score/dry would otherwise abort the statement or inject.
    local ittl iscore idry
    [[ "${ttl:-0}"   =~ ^-?[0-9]+$ ]] && ittl="$ttl"     || ittl=0
    [[ "${score:-0}" =~ ^-?[0-9]+$ ]] && iscore="$score" || iscore=0
    [[ "${dry:-0}"   =~ ^[0-9]+$   ]] && idry="$dry"      || idry=0

    if [[ "${STORE}" == "sqlite" ]]; then
        _sql "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
              VALUES('${sip}',${now},'${saction}','${schannel}',${ittl},${iscore},'${sreason}',${idry});"
        # Only a REAL (enforced) block bumps perm/temp_count — a dry-run detection
        # must not make is_perm/counts report report-mode hits as live bans.
        local perm_inc=0 temp_inc=0
        if (( idry == 0 )); then
            [[ "$action" == "perm" ]] && perm_inc=1
            [[ "$action" == "temp" ]] && temp_inc=1
        fi
        _sql "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
              VALUES('${sip}',${now},${now},${iscore},1,${temp_inc},${perm_inc},'${sreason}','${schannel}')
              ON CONFLICT(ip) DO UPDATE SET
                last_seen=${now},
                worst_score=MAX(worst_score,${iscore}),
                total_offenses=total_offenses+1,
                temp_count=temp_count+${temp_inc},
                perm=MAX(perm,${perm_inc}),
                last_label='${sreason}',
                channel='${schannel}';"
    else
        printf '{"ts":%s,"ip":"%s","action":"%s","channel":"%s","ttl":%s,"score":%s,"reason":"%s","dry_run":%s}\n' \
            "$now" "$ip" "$action" "$channel" "${ttl:-0}" "${score:-0}" "${reason//\"/\'}" "${dry:-0}" \
            >> "$(_swatter_jsonl)"
    fi
}

# Listing helpers for the CLI.
swatter_store_top_offenders() {
    local n="${1:-20}"
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT ip,worst_score,total_offenses,temp_count,perm,channel,last_label
               FROM offenders ORDER BY worst_score DESC, total_offenses DESC LIMIT ${n};" \
        | sed 's/|/\t/g'
    else
        tail -n 2000 "$(_swatter_jsonl)" 2>/dev/null | tail -n "$n"
    fi
}

swatter_store_history() {
    local ip="$1"
    _store_ip_ok "$ip" || return 1
    local sip; sip="$(_sql_escape "$ip")"
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT datetime(ts,'unixepoch'),action,channel,ttl,score,reason
               FROM actions WHERE ip='${sip}' ORDER BY ts DESC LIMIT 50;" | sed 's/|/\t/g'
    else
        grep -F "\"ip\":\"${ip}\"" "$(_swatter_jsonl)" 2>/dev/null | tail -n 50
    fi
}

# Mark an IP unblocked / allowlisted in the ledger.
swatter_store_unblock() {
    local ip="$1"
    _store_ip_ok "$ip" || return 1
    swatter_store_record "$ip" "unblock" "none" 0 0 "manual unblock" 0
    local sip; sip="$(_sql_escape "$ip")"
    [[ "${STORE}" == "sqlite" ]] && _sql "UPDATE offenders SET perm=0 WHERE ip='${sip}';"
    swatter_store_plane_clear "$ip"
    # Cancel any durable retry still queued for this IP — the operator has
    # overridden the decision, so a later scan must not re-drive the failed block.
    swatter_store_pending_clear "$ip"
}

# --- low-and-slow persistence (sqlite only; flatfile no-ops) ----------------
swatter_store_sighting_add() {
    local ip="$1" score="$2" bsec="${3:-3600}"
    _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local now bucket sip; now="$(swatter_now)"; bucket=$(( now / bsec ))
    sip="$(_sql_escape "$ip")"
    _sql "INSERT INTO sightings(ip,bucket,hits,worst_score,last_ts)
          VALUES('${sip}',${bucket},1,${score:-0},${now})
          ON CONFLICT(ip,bucket) DO UPDATE SET
            hits=hits+1, worst_score=MAX(worst_score,${score:-0}), last_ts=${now};"
}

swatter_store_sighting_buckets() {
    local ip="$1" wdays="${2:-3}"
    _store_ip_ok "$ip" || { echo 0; return 0; }
    if [[ "${STORE}" != "sqlite" ]]; then echo 0; return 0; fi
    local cutoff sip; cutoff=$(( $(swatter_now) - wdays*86400 )); sip="$(_sql_escape "$ip")"
    local c; c="$(_sqlq "SELECT COUNT(*) FROM sightings WHERE ip='${sip}' AND last_ts>${cutoff};")"
    [[ "$c" =~ ^[0-9]+$ ]] && echo "$c" || echo 0
}

swatter_store_sighting_clear() {
    local ip="$1"; _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local sip; sip="$(_sql_escape "$ip")"
    _sql "DELETE FROM sightings WHERE ip='${sip}';"
}

swatter_store_sighting_sweep() {
    local wdays="${1:-3}"
    [[ "${STORE}" == "sqlite" ]] || return 0
    local cutoff; cutoff=$(( $(swatter_now) - wdays*86400 ))
    _sql "DELETE FROM sightings WHERE last_ts<${cutoff};"
}

# --- per-plane enforcement state (sqlite only; flatfile no-ops) -------------
# Tracks which enforcement planes (DIRECT csf/ipset, VIA_CF cloudflare) currently
# hold a block for an IP, so the enforce path can tell perm vs temp and whether a
# block is still live without re-deriving it from the action ledger.
# kind=perm with ttl=0 is a TRUE perm (expires_at=0, never lapses: DIRECT/CSF,
# import-bans). kind=perm with ttl>0 is an EXPIRING perm — the Cloudflare plane's
# TTL-emulated perm, which really does lapse when swatter_cf_sweep_expired removes
# the edge rule. Recording it as kind='perm' (not the old kind='temp' rewrite)
# lets _swatter_perm_gate noop it while the edge rule is live — the old temp
# rewrite made is_perm_on(cloudflare) permanently false, so every scan re-applied
# a "plane-upgrade" perm and burned MAX_BLOCKS_PER_RUN. Expiry still governs:
# once past, is_perm_on/active_on go false and the gate legitimately re-blocks.
swatter_store_plane_set() {
    local ip="$1" plane="$2" kind="$3" ttl="$4"
    _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local now exp sip splane skind
    now="$(swatter_now)"
    if [[ "$kind" == "perm" && "${ttl:-0}" -eq 0 ]]; then exp=0; else exp=$(( now + ${ttl:-0} )); fi
    sip="$(_sql_escape "$ip")"; splane="$(_sql_escape "$plane")"; skind="$(_sql_escape "$kind")"
    # Merge rules on conflict: perm beats temp; a true perm (exp=0) on either side
    # pins expiry to 0; otherwise expiries only ever extend (MAX), so a later
    # shorter temp can never shorten a live longer block.
    _sql "INSERT INTO plane_blocks(ip,plane,kind,expires_at)
          VALUES('${sip}','${splane}','${skind}',${exp})
          ON CONFLICT(ip,plane) DO UPDATE SET
            kind=CASE WHEN excluded.kind='perm' OR plane_blocks.kind='perm'
                      THEN 'perm' ELSE 'temp' END,
            expires_at=CASE
              WHEN (excluded.kind='perm' AND excluded.expires_at=0)
                OR (plane_blocks.kind='perm' AND plane_blocks.expires_at=0) THEN 0
              ELSE MAX(plane_blocks.expires_at, excluded.expires_at) END;"
}

swatter_store_is_perm_on() {
    local ip="$1" plane="$2"
    _store_ip_ok "$ip" || return 1
    [[ "${STORE}" == "sqlite" ]] || return 1
    local now sip splane n; now="$(swatter_now)"
    sip="$(_sql_escape "$ip")"; splane="$(_sql_escape "$plane")"
    # A perm is "on" while in force: forever for a true perm (expires_at=0), until
    # expiry for a CF TTL-emulated perm. Fail CLOSED: a DB error yields empty
    # stdout — treat non-numeric as 0 (not blocked) so the caller re-attempts the
    # block rather than silently skipping.
    n="$(_sqlq "SELECT COUNT(*) FROM plane_blocks WHERE ip='${sip}' AND plane='${splane}'
                AND kind='perm' AND (expires_at=0 OR expires_at>${now});")"
    [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 ))
}

swatter_store_active_on() {
    local ip="$1" plane="$2"
    _store_ip_ok "$ip" || return 1
    [[ "${STORE}" == "sqlite" ]] || return 1
    local now sip splane n; now="$(swatter_now)"
    sip="$(_sql_escape "$ip")"; splane="$(_sql_escape "$plane")"
    # Fail CLOSED on a DB error (empty stdout) — see swatter_store_is_perm_on.
    # An expiring perm past its expiry is NOT active (the edge rule was swept).
    n="$(_sqlq "SELECT COUNT(*) FROM plane_blocks WHERE ip='${sip}' AND plane='${splane}'
                AND ((kind='perm' AND expires_at=0) OR expires_at>${now});")"
    [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 ))
}

swatter_store_plane_clear() {
    local ip="$1"; _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local sip; sip="$(_sql_escape "$ip")"
    _sql "DELETE FROM plane_blocks WHERE ip='${sip}';"
}

# --- durable failed-block retry queue (sqlite only; flatfile no-ops) ---------
# A block that fails on a genuine backend error (CF API 5xx/timeout, csf/ipset
# command failure) leaves NO firewall rule and NO plane_blocks row. Because
# ingest is cursor-based (lib/ingest.sh reads only bytes appended since the last
# scan and never re-reads a consumed line), the offender is re-scored ONLY if it
# keeps producing fresh evidence — so a single-burst / hit-and-run offender whose
# block failed was silently, permanently dropped. This queue records the INTENT of
# a failed block so _swatter_retry_pending can re-drive it on later scans off the
# stored row, independent of whether the IP reappears in the log.
#
# NOTE the `plane` column here is the ROUTING plane (DIRECT|VIA_CF) that
# _swatter_apply_plane takes as an argument — NOT the firewall channel
# (csf|cloudflare) that plane_blocks is keyed on. One pending intent per (ip,
# plane); a repeat failure bumps attempts via the upsert. Only genuine `failed`
# outcomes are queued: skipped-cap (a deliberate throttle) and skipped-novhost (no
# target to build a rule from) are intentionally NOT queued.
swatter_store_pending_set() {
    local ip="$1" plane="$2" action="$3" ttl="$4" reason="$5" top_vhost="$6" folded="$7" rep="$8" ev="${9:-}" audit_action="${10:-$3}"
    _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local now; now="$(swatter_now)"
    # Strip TAB/newline from the fields the drain splits on IFS=$'\t' so an embedded
    # tab/newline can't shift columns. reason/top_vhost are control-char-clean
    # upstream and ev is jesc'd by score.awk (no tab/newline); this is the backstop.
    reason="${reason//[$'\t\r\n']/ }"; top_vhost="${top_vhost//[$'\t\r\n']/ }"
    ev="${ev//[$'\t\r\n']/ }"; audit_action="${audit_action//[$'\t\r\n']/ }"
    [[ -n "$ev" ]] || ev="{}"
    local sip splane saction sreason svhost sev saudit
    sip="$(_sql_escape "$ip")"; splane="$(_sql_escape "$plane")"
    saction="$(_sql_escape "$action")"; sreason="$(_sql_escape "$reason")"; svhost="$(_sql_escape "$top_vhost")"
    sev="$(_sql_escape "$ev")"; saudit="$(_sql_escape "$audit_action")"
    local ittl ifolded irep
    [[ "${ttl:-0}"    =~ ^-?[0-9]+$ ]] && ittl="$ttl"       || ittl=0
    [[ "${folded:-0}" =~ ^-?[0-9]+$ ]] && ifolded="$folded" || ifolded=0
    [[ "${rep:-0}"    =~ ^-?[0-9]+$ ]] && irep="$rep"       || irep=0
    # first_failed is pinned on the FIRST enqueue (drives the max-age reap); a
    # repeat failure only bumps attempts + last_attempt and refreshes the intent.
    # ev + audit_action are stored so the drain replays the block FAITHFULLY: a
    # primary block (audit_action==action) counts + reports on retry success; a
    # secondary leg (dual-plane/plane-upgrade) records its own label and skips the
    # AbuseIPDB re-report, exactly as the original non-retry path would have.
    _sql "INSERT INTO pending_blocks(ip,plane,action,ttl,reason,top_vhost,folded,rep,ev,audit_action,first_failed,last_attempt,attempts)
          VALUES('${sip}','${splane}','${saction}',${ittl},'${sreason}','${svhost}',${ifolded},${irep},'${sev}','${saudit}',${now},${now},1)
          ON CONFLICT(ip,plane) DO UPDATE SET
            action='${saction}', ttl=${ittl}, reason='${sreason}', top_vhost='${svhost}',
            folded=${ifolded}, rep=${irep}, ev='${sev}', audit_action='${saudit}',
            last_attempt=${now}, attempts=attempts+1;"
}

# Echo every queued intent as a TSV row the drain consumes. ev is LAST (it is the
# widest free-text field); every field is tab/newline-clean by construction above.
#   ip⇥plane⇥action⇥ttl⇥folded⇥rep⇥first_failed⇥attempts⇥audit_action⇥reason⇥top_vhost⇥ev
swatter_store_pending_list() {
    [[ "${STORE}" == "sqlite" ]] || return 0
    _sqlq "SELECT ip||char(9)||plane||char(9)||action||char(9)||ttl||char(9)||folded||char(9)||rep||char(9)||first_failed||char(9)||attempts||char(9)||COALESCE(audit_action,action)||char(9)||COALESCE(reason,'')||char(9)||COALESCE(top_vhost,'')||char(9)||COALESCE(ev,'{}')
           FROM pending_blocks ORDER BY first_failed;"
}

# Drop a queued intent: a specific plane if given, else all planes for the IP
# (used by `swatter unblock` to cancel a retry the operator has overridden).
swatter_store_pending_clear() {
    local ip="$1" plane="${2:-}"; _store_ip_ok "$ip" || return 0
    [[ "${STORE}" == "sqlite" ]] || return 0
    local sip; sip="$(_sql_escape "$ip")"
    if [[ -n "$plane" ]]; then
        local splane; splane="$(_sql_escape "$plane")"
        _sql "DELETE FROM pending_blocks WHERE ip='${sip}' AND plane='${splane}';"
    else
        _sql "DELETE FROM pending_blocks WHERE ip='${sip}';"
    fi
}

# Echo permanently-banned IPs, one per line (source for `swatter export-bans`).
# Only IPs that were ACTUALLY perm-blocked (an enforced, dry_run=0 perm action)
# and are still banned (not later unblocked) — so a report/dry-run box never
# exports IPs it merely detected, and an unblocked IP is never re-exported.
swatter_store_perm_ips() {
    if [[ "${STORE}" == "sqlite" ]]; then
        # offenders.perm reflects current state (unblock sets it 0); the subquery
        # requires at least one real enforced perm block (excludes dry-run perms).
        _sqlq "SELECT ip FROM offenders WHERE perm=1
                 AND ip IN (SELECT ip FROM actions WHERE action='perm' AND dry_run=0)
               ORDER BY ip;"
    else
        # Flatfile JSONL is append-only: replay records per IP, banned on an
        # enforced perm, cleared on a later unblock.
        awk '
            { ip=""; act=""; dr=1 }
            match($0, /"ip":"[^"]*"/)     { ip=substr($0, RSTART+6, RLENGTH-7) }
            match($0, /"action":"[^"]*"/) { act=substr($0, RSTART+10, RLENGTH-11) }
            /"dry_run":0/                 { dr=0 }
            ip!="" && act=="perm"    && dr==0 { state[ip]=1 }
            ip!="" && act=="unblock"          { state[ip]=0 }
            END { for (i in state) if (state[i]) print i }
        ' "$(_swatter_jsonl)" 2>/dev/null | sort -u
    fi
}

# Delta variant for the swarm publisher: perm ips (same still-banned, enforced
# semantics as swatter_store_perm_ips) whose LATEST enforced perm action is
# newer than <since>. Prints "ip<TAB>ts" per line; ts drives the publish cursor.
swatter_store_perm_ips_since() {
    local since="${1:-0}"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT a.ip || char(9) || MAX(a.ts) FROM actions a
                 JOIN offenders o ON o.ip = a.ip
                WHERE o.perm=1 AND a.action='perm' AND a.dry_run=0
                GROUP BY a.ip HAVING MAX(a.ts) > ${since}
                ORDER BY a.ip;"
    else
        awk -v since="$since" '
            { ip=""; act=""; dr=1; ts=0 }
            match($0, /"ip":"[^"]*"/)     { ip=substr($0, RSTART+6, RLENGTH-7) }
            match($0, /"action":"[^"]*"/) { act=substr($0, RSTART+10, RLENGTH-11) }
            match($0, /"ts":[0-9]+/)      { ts=substr($0, RSTART+5, RLENGTH-5)+0 }
            /"dry_run":0/                 { dr=0 }
            ip!="" && act=="perm" && dr==0 { banned[ip]=1; if (ts>last[ip]) last[ip]=ts }
            ip!="" && act=="unblock"       { banned[ip]=0 }
            END { for (i in banned) if (banned[i] && last[i]>since) print i "\t" last[i] }
        ' "$(_swatter_jsonl)" 2>/dev/null | sort
    fi
}

# Echo "temp_offenders <TAB> perm_offenders" (for metrics).
swatter_store_counts() {
    if [[ "${STORE}" != "sqlite" ]]; then printf '0\t0\n'; return 0; fi
    local t p
    t="$(_sqlq "SELECT COUNT(*) FROM offenders WHERE temp_count>0 AND perm=0;")"
    p="$(_sqlq "SELECT COUNT(*) FROM offenders WHERE perm=1;")"
    [[ "$t" =~ ^[0-9]+$ ]] || t=0; [[ "$p" =~ ^[0-9]+$ ]] || p=0
    printf '%s\t%s\n' "$t" "$p"
}
