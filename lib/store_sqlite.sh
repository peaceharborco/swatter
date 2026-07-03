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
        _ierr="$(sqlite3 "$(_swatter_db)" 2>&1 >/dev/null <<'SQL'
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
_sql() {
    local err rc
    { err="$(sqlite3 "$(_swatter_db)" "$@" 2>&1 >&3 3>&-)"; rc=$?; } 3>&1
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
swatter_store_recent_temp_count() {
    local ip="$1" since
    _store_ip_ok "$ip" || { echo 0; return 0; }
    since=$(( $(swatter_now) - REPEAT_WINDOW_DAYS*86400 ))
    local sip; sip="$(_sql_escape "$ip")"
    if [[ "${STORE}" == "sqlite" ]]; then
        _sqlq "SELECT COUNT(*) FROM actions WHERE ip='${sip}' AND action='temp' AND dry_run=0 AND ts>${since};"
    else
        awk -F'"' -v ip="$ip" -v since="$since" '
            /"action":"temp"/ && /"dry_run":0/ {
                a=$0; if (a ~ ("\"ip\":\""ip"\"")) {
                    match(a,/"ts":[0-9]+/); ts=substr(a,RSTART+5,RLENGTH-5)+0
                    if (ts>since) c++
                }
            } END{print c+0}' "$(_swatter_jsonl)"
    fi
}

# Is the IP already permanently blocked?
swatter_store_is_perm() {
    local ip="$1"
    _store_ip_ok "$ip" || return 1
    local sip; sip="$(_sql_escape "$ip")"
    if [[ "${STORE}" == "sqlite" ]]; then
        [[ "$(_sqlq "SELECT perm FROM offenders WHERE ip='${sip}';")" == "1" ]]
    else
        grep -qF "\"ip\":\"${ip}\",\"action\":\"perm\"" "$(_swatter_jsonl)" 2>/dev/null
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

    if [[ "${STORE}" == "sqlite" ]]; then
        _sql "INSERT INTO actions(ip,ts,action,channel,ttl,score,reason,dry_run)
              VALUES('${sip}',${now},'${action}','${channel}',${ttl:-0},${score:-0},'${sreason}',${dry:-0});"
        local perm_inc=0 temp_inc=0
        [[ "$action" == "perm" ]] && perm_inc=1
        [[ "$action" == "temp" ]] && temp_inc=1
        _sql "INSERT INTO offenders(ip,first_seen,last_seen,worst_score,total_offenses,temp_count,perm,last_label,channel)
              VALUES('${sip}',${now},${now},${score:-0},1,${temp_inc},${perm_inc},'${sreason}','${channel}')
              ON CONFLICT(ip) DO UPDATE SET
                last_seen=${now},
                worst_score=MAX(worst_score,${score:-0}),
                total_offenses=total_offenses+1,
                temp_count=temp_count+${temp_inc},
                perm=MAX(perm,${perm_inc}),
                last_label='${sreason}',
                channel='${channel}';"
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

# Echo "temp_offenders <TAB> perm_offenders" (for metrics).
swatter_store_counts() {
    if [[ "${STORE}" != "sqlite" ]]; then printf '0\t0\n'; return 0; fi
    local t p
    t="$(_sqlq "SELECT COUNT(*) FROM offenders WHERE temp_count>0 AND perm=0;")"
    p="$(_sqlq "SELECT COUNT(*) FROM offenders WHERE perm=1;")"
    [[ "$t" =~ ^[0-9]+$ ]] || t=0; [[ "$p" =~ ^[0-9]+$ ]] || p=0
    printf '%s\t%s\n' "$t" "$p"
}
