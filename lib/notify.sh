#!/usr/bin/env bash
# lib/notify.sh — multi-channel ops-critical alerts (best-effort fan-out).
#
# swatter_notify <subject> <body> [dedup_key] — fans out to every CONFIGURED
# channel (local mail, SendGrid/sendmail email, Twilio SMS, Slack/Discord/generic
# webhook). Each channel is independent and best-effort: a failure logs and
# returns, never aborting the scan or the other channels. A keyed alert fires at
# most once per ALERT_REPEAT_TTL (marker $STATE_DIR/alerted/<key>); no key = always.

# Minimal JSON string escape (backslash, quote, control chars -> space).
_notify_jesc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; s="${s//$'\t'/ }"; printf '%s' "$s"; }

# Returns 0 (suppress) if this key fired within ALERT_REPEAT_TTL; else marks + returns 1.
_notify_ratelimited() {
    local key="$1" m now mtime age
    [[ -n "$key" ]] || return 1
    m="${STATE_DIR}/alerted/${key}"
    mkdir -p "${STATE_DIR}/alerted" 2>/dev/null
    if [[ -f "$m" ]]; then
        now="$(swatter_now)"; mtime="$(stat_mtime "$m" 2>/dev/null || echo 0)"; age=$(( now - mtime ))
        (( age < ${ALERT_REPEAT_TTL:-21600} )) && return 0
    fi
    : > "$m" 2>/dev/null
    return 1
}

_notify_mail() {
    [[ -n "${NOTIFY_EMAIL:-}" ]] || return 0
    have mail || return 0
    printf '%s\n' "$2" | mail -s "$1" "${NOTIFY_EMAIL}" 2>/dev/null || log_warn "notify: local mail failed"
}

_notify_email() {
    [[ -n "${ALERT_EMAIL:-}" ]] || return 0
    swatter_send_email "${ALERT_EMAIL}" "$1" "$2" 2>/dev/null || log_warn "notify: alert email failed"
}

_notify_sms() {
    [[ -n "${ALERT_SMS_TO:-}" && -n "${TWILIO_SID:-}" && -n "${TWILIO_FROM:-}" && -n "${TWILIO_TOKEN_FILE:-}" ]] || return 0
    [[ "${SWATTER_HAVE_CURL:-0}" -eq 1 && -r "${TWILIO_TOKEN_FILE}" ]] || return 0
    local token; token="$(cat "${TWILIO_TOKEN_FILE}" 2>/dev/null)"; [[ -n "$token" ]] || return 0
    # SID:token via -K config file, never argv (visible in `ps` on a shared box).
    local cfg
    cfg="$(swatter_curl_cfg "user = \"${TWILIO_SID}:${token}\"")" || { log_warn "notify: cannot create curl config"; return 0; }
    # TWILIO_FROM may be a phone number (+1…) or a Messaging Service SID (MG…) —
    # the latter uses a different Twilio param (mirrors lib/alerts.sh).
    local fromkey="From"; [[ "${TWILIO_FROM}" == MG* ]] && fromkey="MessagingServiceSid"
    local err
    err="$(curl --max-time 8 -fsS -X POST \
        -K "$cfg" \
        --data-urlencode "${fromkey}=${TWILIO_FROM}" --data-urlencode "To=${ALERT_SMS_TO}" \
        --data-urlencode "Body=swatter: $1" \
        "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json" 2>&1 >/dev/null)" \
        || log_warn "notify: twilio sms failed${err:+: $(printf '%s' "${err//${token}/***}" | tr '\n' ' ' | cut -c1-160)}"
    rm -f "$cfg"
}

_notify_webhook() {
    [[ -n "${ALERT_WEBHOOK_URL:-}" ]] || return 0
    [[ "${SWATTER_HAVE_CURL:-0}" -eq 1 ]] || return 0
    local fmt="${ALERT_WEBHOOK_FORMAT:-auto}" payload
    if [[ "$fmt" == "auto" ]]; then
        case "${ALERT_WEBHOOK_URL}" in
            *hooks.slack.com*) fmt="slack" ;;
            *discord.com/api/webhooks*|*discordapp.com/api/webhooks*) fmt="discord" ;;
            *) fmt="generic" ;;
        esac
    fi
    local text host; text="swatter: $1 — $2"; host="$(hostname -s 2>/dev/null)"
    if [[ "${SWATTER_HAVE_JQ:-0}" -eq 1 ]]; then
        # jq escapes control chars correctly; the bash _notify_jesc path is the
        # no-jq fallback only (it maps newlines/tabs to space, drops nothing else).
        case "$fmt" in
            slack)   payload="$(jq -nc --arg t "$text" '{text:$t}')" ;;
            discord) payload="$(jq -nc --arg c "$text" '{content:$c}')" ;;
            *)       payload="$(jq -nc --arg h "$host" --arg s "$1" --arg b "$2" '{host:$h,subject:$s,body:$b}')" ;;
        esac
    else
        case "$fmt" in
            slack)   payload="$(printf '{"text":"%s"}' "$(_notify_jesc "$text")")" ;;
            discord) payload="$(printf '{"content":"%s"}' "$(_notify_jesc "$text")")" ;;
            *)       payload="$(printf '{"host":"%s","subject":"%s","body":"%s"}' "$(_notify_jesc "$host")" "$(_notify_jesc "$1")" "$(_notify_jesc "$2")")" ;;
        esac
    fi
    local err
    err="$(curl --max-time 8 -fsS -H "Content-Type: application/json" -d "$payload" "${ALERT_WEBHOOK_URL}" 2>&1 >/dev/null)" \
        || log_warn "notify: webhook post failed${err:+: $(printf '%s' "$err" | tr '\n' ' ' | cut -c1-160)}"
}

swatter_notify() {
    local subject="$1" body="$2" key="${3:-}"
    # Rate-limit marker is written SYNCHRONOUSLY here; the channel sends (each a
    # bounded-timeout curl/MTA) are dispatched in the BACKGROUND so a slow SMS/
    # webhook/mail endpoint never delays the scan — mirrors the AbuseIPDB report.
    _notify_ratelimited "$key" && { log_debug "alert '${key}' rate-limited"; return 0; }
    ( _notify_mail    "$subject" "$body"
      _notify_email   "$subject" "$body"
      _notify_sms     "$subject" "$body"
      _notify_webhook "$subject" "$body" ) &
    return 0
}
