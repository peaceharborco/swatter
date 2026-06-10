# score.awk — single-pass weighted abuse scorer.
#
# Input  (TSV, one parsed request per line, from lib/ingest.sh):
#   ip \t epoch \t method \t path \t status \t bytes \t ua \t vhost
#   path and ua are already lowercased; path has the query string stripped.
#
# Output (TSV, one line per IP that reaches WATCH or above):
#   ip \t score \t reqs \t evidence_json
#   evidence_json is a compact JSON object with the sub-scores and the samples
#   that justify the score (top paths, status histogram, bad-path categories,
#   sample UAs). The caller (score.sh) attaches reputation + routing.
#
# Required -v vars: NOW, WINDOW, MIN_REQS, RATE_SAT, SCORE_WATCH,
#   W_RATE W_ERR_RATIO W_ERR_BURST W_FANOUT W_BADPATH W_UA W_POST_FLOOD W_NOVHOST
#   BADPATHS (path to badpaths.conf)
#
# Reputation is intentionally NOT computed here (it needs network I/O); score.sh
# folds it in afterward. W_REPUTATION is therefore excluded from this denominator
# and re-added by score.sh only when intel is present.

function sev_weight(cat) {
    if (cat == "CRITICAL") return 100
    if (cat == "HIGH")     return 70
    if (cat == "MEDIUM")   return 40
    if (cat == "LOW")      return 20
    return 0
}

function clamp100(x) { return (x > 100) ? 100 : ((x < 0) ? 0 : x) }

function jesc(s,   t) {
    t = s
    gsub(/\\/, "\\\\", t)
    gsub(/"/,  "\\\"", t)
    gsub(/\t/, " ", t)
    gsub(/[\r\n]/, " ", t)
    return t
}

BEGIN {
    FS = "\t"
    win_start = NOW - WINDOW

    # Load the bad-path table: nbad regexes with parallel category/weight arrays.
    nbad = 0
    if (BADPATHS != "") {
        while ((getline line < BADPATHS) > 0) {
            if (line ~ /^[ \t]*#/) continue
            if (line ~ /^[ \t]*$/) continue
            # First token = category, remainder (trimmed) = regex.
            cat = line
            sub(/[ \t].*$/, "", cat)
            rx = line
            sub(/^[^ \t]+[ \t]+/, "", rx)
            if (rx == "" || cat == "") continue
            bad_rx[nbad]  = rx
            bad_cat[nbad] = cat
            bad_w[nbad]   = sev_weight(cat)
            nbad++
        }
        close(BADPATHS)
    }

    # Suspicious user-agent substrings (lowercased).
    nua = split("sqlmap nikto nmap masscan zgrab zmeu nuclei wpscan acunetix " \
                "dirbuster gobuster feroxbuster python-requests go-http-client " \
                "libwww java/ curl/ wget/ httpclient scrapy", ua_bad, " ")
}

# --- per-request aggregation ------------------------------------------------
{
    ip = $1; ep = $2 + 0; method = $3; path = $4; status = $5 + 0; ua = $7
    if (ep < win_start) next            # outside the window
    if (ip == "" || ip == "-") next

    reqs[ip]++
    if (first_ep[ip] == 0 || ep < first_ep[ip]) first_ep[ip] = ep
    if (ep > last_ep[ip]) last_ep[ip] = ep

    # Status buckets.
    if (status >= 200 && status < 300) c2xx[ip]++
    else if (status >= 300 && status < 400) c3xx[ip]++
    else if (status == 401) { c401[ip]++; cerr[ip]++ }
    else if (status == 403) { c403[ip]++; cerr[ip]++; cburst[ip]++ }
    else if (status == 404) { c404[ip]++; cerr[ip]++; cburst[ip]++ }
    else if (status == 444) { c444[ip]++; cerr[ip]++; cburst[ip]++ }
    else if (status >= 400 && status < 500) cerr[ip]++
    else if (status >= 500) { c5xx[ip]++; cerr[ip]++ }

    if (method == "POST") post[ip]++

    # Distinct-path fanout, capped so a scanner cannot blow memory.
    if (distinct[ip] < 500) {
        k = ip SUBSEP path
        if (!(k in seenpath)) { seenpath[k] = 1; distinct[ip]++ }
    }
    # Keep the first few sample paths for evidence.
    if (npaths[ip] < 5) {
        pk = ip SUBSEP path
        if (!(pk in seenpath_ev)) { seenpath_ev[pk] = 1; samp_path[ip, npaths[ip]] = path; npaths[ip]++ }
    }

    # Bad-path scan: record the highest-severity category hit.
    for (i = 0; i < nbad; i++) {
        if (path ~ bad_rx[i]) {
            w = bad_w[i]
            if (w > badmax[ip]) { badmax[ip] = w; badcat[ip] = bad_cat[i] }
            badhits[ip]++
            break        # one category per request (table is severity-ordered)
        }
    }

    # User-agent signal.
    if (ua == "" || ua == "-") { ua_empty[ip]++ }
    else {
        for (j = 1; j <= nua; j++) {
            if (index(ua, ua_bad[j]) > 0) { ua_susp[ip]++; break }
        }
        if (sample_ua[ip] == "") sample_ua[ip] = ua
    }

    # No-vhost / raw-IP hit: vhost empty or literal default.
    vh = $8
    if (vh == "" || vh == "-" || vh ~ /^[0-9.]+$/) novhost[ip]++
}

# --- scoring & emit ---------------------------------------------------------
END {
    wsum = W_RATE + W_ERR_RATIO + W_ERR_BURST + W_FANOUT + W_BADPATH + W_UA + W_POST_FLOOD + W_NOVHOST
    if (wsum <= 0) wsum = 1

    for (ip in reqs) {
        n = reqs[ip]
        if (n < MIN_REQS && badmax[ip] < 100) continue   # below floor, unless CRITICAL

        span = last_ep[ip] - first_ep[ip]
        if (span < 1) span = 1
        rps = n / span

        s_rate = clamp100(100 * (rps / RATE_SAT))

        s_err = 0
        if (n >= MIN_REQS) s_err = clamp100(100 * (cerr[ip] / n))

        # Error burst: absolute count of 403/404/444 over a knee of 40.
        s_burst = clamp100(100 * (cburst[ip] / 40.0))

        # Fanout: high distinct-path ratio AND absolute breadth.
        fr = distinct[ip] / n
        s_fanout = 0
        if (distinct[ip] >= 10) s_fanout = clamp100(100 * fr * (distinct[ip] / 50.0))

        s_bad = clamp100(badmax[ip])

        s_ua = 0
        if (ua_empty[ip] > 0) s_ua = clamp100(100 * (ua_empty[ip] / n))
        if (ua_susp[ip] > 0)  { v = clamp100(100 * (ua_susp[ip] / n)); if (v > s_ua) s_ua = v }

        s_post = 0
        if (post[ip] > 0 && n >= MIN_REQS) s_post = clamp100(100 * (post[ip] / n) * (rps / RATE_SAT))

        s_nov = clamp100(100 * (novhost[ip] / n))

        # Behavioral baseline: weighted average of all signals. Conservative by
        # design — it catches IPs that are suspicious across several weak signals
        # and gives a stable 0-100 ordering. But a weighted average dilutes a
        # FOCUSED attack (a credential brute hits only 3-4 of 8 signals), so it
        # is paired with decisive floors below.
        composite = ( W_RATE*s_rate + W_ERR_RATIO*s_err + W_ERR_BURST*s_burst \
                    + W_FANOUT*s_fanout + W_BADPATH*s_bad + W_UA*s_ua \
                    + W_POST_FLOOD*s_post + W_NOVHOST*s_nov ) / wsum

        # Decisive floors: each is independently sufficient to act. They encode
        # "this single behavior is unambiguous" so a focused attacker is not
        # averaged down to safety. The reason is recorded for the audit trail.
        floor = 0; frule = ""
        # CRITICAL secret/RCE path — block on sight, any volume.
        if (badmax[ip] >= 100)                               { floor = 90; frule = "critical_badpath" }
        # Repeated targeting of a sensitive HIGH endpoint (brute force / probe).
        if (badmax[ip] >= 70 && badhits[ip] >= 3 && floor < 80) { floor = 80; frule = "high_badpath_repeat" }
        # Scanner profile: broad path fanout with a high error ratio.
        if (distinct[ip] >= 25 && n >= MIN_REQS && (cerr[ip] / n) >= 0.6 && floor < 78) { floor = 78; frule = "scanner_profile" }
        # Error burst: a large absolute volume of 403/404/444.
        if (cburst[ip] >= 100 && floor < 75)                 { floor = 75; frule = "error_burst" }
        # Sustained request flood.
        if (rps >= RATE_SAT && n >= 60 && floor < 75)        { floor = 75; frule = "request_flood" }

        if (floor > composite) composite = floor

        score = int(composite + 0.5)
        if (score < SCORE_WATCH) continue

        # Build evidence JSON.
        paths_json = ""
        for (p = 0; p < npaths[ip]; p++) {
            if (p > 0) paths_json = paths_json ","
            paths_json = paths_json "\"" jesc(samp_path[ip, p]) "\""
        }

        ev = "{"
        ev = ev "\"sub\":{"
        ev = ev "\"rate\":" int(s_rate+0.5) ",\"err\":" int(s_err+0.5) ",\"burst\":" int(s_burst+0.5)
        ev = ev ",\"fanout\":" int(s_fanout+0.5) ",\"badpath\":" int(s_bad+0.5) ",\"ua\":" int(s_ua+0.5)
        ev = ev ",\"post\":" int(s_post+0.5) ",\"novhost\":" int(s_nov+0.5) "}"
        ev = ev ",\"reqs\":" n ",\"rps\":" sprintf("%.2f", rps)
        ev = ev ",\"distinct_paths\":" distinct[ip]
        ev = ev ",\"status\":{\"2xx\":" (c2xx[ip]+0) ",\"3xx\":" (c3xx[ip]+0) \
                ",\"401\":" (c401[ip]+0) ",\"403\":" (c403[ip]+0) ",\"404\":" (c404[ip]+0) \
                ",\"444\":" (c444[ip]+0) ",\"5xx\":" (c5xx[ip]+0) "}"
        ev = ev ",\"post\":" (post[ip]+0)
        ev = ev ",\"badpath_cat\":\"" (badcat[ip] == "" ? "" : badcat[ip]) "\""
        ev = ev ",\"badpath_hits\":" (badhits[ip]+0)
        ev = ev ",\"decisive_rule\":\"" frule "\""
        ev = ev ",\"sample_ua\":\"" jesc(sample_ua[ip]) "\""
        ev = ev ",\"sample_paths\":[" paths_json "]"
        ev = ev "}"

        printf "%s\t%d\t%d\t%s\n", ip, score, n, ev
    }
}
