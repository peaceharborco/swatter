#!/usr/bin/env bash
# lib/alerts.sh — out-of-band alerting (SMS) on severe report grades. A SECOND
# channel alongside the email digest; the email always sends regardless. Every
# path is fail-soft: a misconfig or provider outage logs a warning and is ignored
# so it can never block or break the nightly report.
#
# Config (swatter.conf; OFF by default so the public build alerts nobody):
#   ALERT_SMS_METHOD      "twilio" to enable; "" = off
#   ALERT_SMS_GRADES      statuses that trigger (default "RED")
#   ALERT_SMS_TO          destination number, E.164 (+1555...)
#   ALERT_SMS_DEDUP_HOURS suppress a duplicate same-status text within N hours (default 6)
#   TWILIO_SID / TWILIO_TOKEN_FILE / TWILIO_FROM   Twilio credentials (token from a 0400 file)

# swatter_send_sms <to> <body> — dispatch on ALERT_SMS_METHOD. Returns nonzero on
# failure (callers swallow it). Never echoes the token.
swatter_send_sms() {
    local to="$1" body="$2"
    case "${ALERT_SMS_METHOD:-}" in
        twilio) _alert_sms_twilio "$to" "$body" ;;
        "")     return 0 ;;                       # disabled — no-op success
        *)      log_warn "alerts: unknown ALERT_SMS_METHOD='${ALERT_SMS_METHOD}'"; return 1 ;;
    esac
}

_alert_sms_twilio() {
    local to="$1" body="$2"
    [[ "${SWATTER_HAVE_CURL:-0}" -eq 1 ]] || { log_error "alerts: twilio needs curl"; return 1; }
    [[ -n "${TWILIO_SID:-}" && -n "${TWILIO_FROM:-}" && -r "${TWILIO_TOKEN_FILE:-}" ]] || {
        log_error "alerts: twilio not configured (need TWILIO_SID, TWILIO_FROM, readable TWILIO_TOKEN_FILE)"; return 1; }
    local token; token="$(cat "${TWILIO_TOKEN_FILE}")"
    # TWILIO_FROM may be a phone number (+1…) or a Messaging Service SID (MG…).
    local fromkey="From"; [[ "${TWILIO_FROM}" == MG* ]] && fromkey="MessagingServiceSid"
    # SID:token via -K config file, never argv (visible in `ps` on a shared box).
    local cfg resp code
    cfg="$(swatter_curl_cfg "user = \"${TWILIO_SID}:${token}\"")" || { log_error "alerts: cannot create curl config"; return 1; }
    # Keep the response BODY: on failure it carries Twilio's actionable cause
    # (auth error, unverified number, ...) that a bare "HTTP 401" hides.
    resp="$(curl -sS --max-time 15 -w '\n%{http_code}' \
        -K "$cfg" \
        --data-urlencode "${fromkey}=${TWILIO_FROM}" \
        --data-urlencode "To=${to}" \
        --data-urlencode "Body=${body}" \
        "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json" 2>&1)"
    rm -f "$cfg"
    code="${resp##*$'\n'}"; local rbody="${resp%"${code}"}"; rbody="${rbody%$'\n'}"
    if [[ "$code" =~ ^2 ]]; then
        log_info "alerts: SMS sent to ${to} via Twilio (${code})"
        return 0
    fi
    rbody="${rbody//${token}/***}"
    log_error "alerts: Twilio SMS failed (HTTP ${code:-000})${rbody:+: $(printf '%s' "$rbody" | tr '\n' ' ' | cut -c1-200)}"
    return 1
}

# swatter_alert_on_grade [--test] — decide + fire on the current RPT_GRADE. Reads
# the RPT_GRADE* globals set by _report_grade. Fail-soft: ALWAYS returns 0 so a
# broken alert never breaks the report.
#   normal : fires only when RPT_GRADE is in ALERT_SMS_GRADES, with dedup.
#   --test : fires regardless of status, "[TEST] "-prefixed, bypassing status + dedup
#            (so an operator can verify Twilio setup without waiting for a real RED).
swatter_alert_on_grade() {
    local test_mode=0; [[ "${1:-}" == "--test" ]] && test_mode=1
    [[ -n "${ALERT_SMS_METHOD:-}" && -n "${ALERT_SMS_TO:-}" ]] || return 0   # alerting off

    local grade="${RPT_GRADE:-GREEN}"
    # An escalated RED (🔥 — an outside client actually received a failure) is a
    # DIFFERENT thing to be told about than a plain RED, but it must not become a
    # different GRADE. `grade` below is the membership key against
    # ALERT_SMS_GRADES and the token in the message body; only the DEDUP key
    # carries the distinction. Collapsing those roles is how the most severe
    # alert this tool can send ends up matching no knob and going nowhere.
    local dedup_key="$grade"
    (( ${RPT_GRADE_ESCALATED:-0} )) && dedup_key="${grade}!"
    if (( ! test_mode )); then
        # Surface a stale grade config: statuses are traffic-light (RED/YELLOW/GREEN)
        # since v2.8. A pre-2.8 A–F value (e.g. "D F") matches nothing, so SMS would
        # silently never fire — warn rather than fail quiet.
        case " ${ALERT_SMS_GRADES:-RED} " in
            *" RED "*|*" YELLOW "*|*" GREEN "*) ;;
            *) log_warn "alerts: ALERT_SMS_GRADES='${ALERT_SMS_GRADES:-}' matches no status (RED/YELLOW/GREEN) — SMS alerting will never fire (stale A–F config?)" ;;
        esac
        # Only the configured statuses trigger.
        case " ${ALERT_SMS_GRADES:-RED} " in *" ${grade} "*) ;; *) return 0 ;; esac
        # Dedup: same status already alerted within the window? The marker is NOT
        # written here — a failed send must not suppress the retry. It is recorded
        # only after swatter_send_sms succeeds, below.
        local statef="${STATE_DIR:-/var/lib/swatter}/last-sms-alert"
        local now win; now="$(swatter_now)"; win=$(( ${ALERT_SMS_DEDUP_HOURS:-6} * 3600 ))
        if [[ -r "$statef" ]]; then
            local lg lt; read -r lg lt < "$statef" 2>/dev/null || true
            if [[ "${lt:-0}" =~ ^[0-9]+$ ]] && (( now - lt < win )); then
                if [[ "$lg" == "$dedup_key" ]]; then
                    log_info "alerts: status ${grade} SMS deduped (within ${ALERT_SMS_DEDUP_HOURS:-6}h)"
                    return 0
                fi
                # STICKY FAIL-OPEN. Escalating (RED -> RED!) always texts: the
                # situation materially changed. De-escalating inside the dedup
                # window does NOT, because the overwhelmingly likely cause is the
                # corroboration lookup failing to read a log this run — not the
                # outage ending. Texting "it's fine now" because a log rotated is
                # worse than saying nothing.
                if [[ "$lg" == "${grade}!" && "$dedup_key" == "$grade" ]]; then
                    log_info "alerts: status ${grade} SMS deduped (de-escalation within ${ALERT_SMS_DEDUP_HOURS:-6}h)"
                    return 0
                fi
            fi
        fi
    fi

    local host; host="$(hostname -f 2>/dev/null || hostname)"
    local prefix=""; (( test_mode )) && prefix="[TEST] "
    # Traffic-light icon matching the status (falls back to the report global).
    local icon="${RPT_GRADE_ICON:-}"
    if [[ -z "$icon" ]]; then
        case "$grade" in RED) icon="🔴" ;; YELLOW) icon="🟡" ;; GREEN) icon="🟢" ;; esac
    fi
    local body="${prefix}${icon:+$icon }Swatter ${host}: Status ${grade} (${RPT_GRADE_WORD:-}). ${RPT_RECO:-}"
    if swatter_send_sms "${ALERT_SMS_TO}" "$body"; then
        # Record the dedup marker only on a successful send (never in --test mode).
        (( test_mode )) || printf '%s %s\n' "$dedup_key" "$now" > "$statef" 2>/dev/null || true
    else
        log_warn "alerts: SMS send failed (report unaffected)"
    fi
    return 0
}
