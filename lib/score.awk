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

# is_mangled_srcset(p) : 1 if this request path is a browser faithfully fetching
# a BROKEN srcset/sizes attribute emitted by the site itself, rather than a probe.
#
# When markup puts a whole srcset VALUE where a single URL belongs, the browser
# requests the entire string as one URL and always gets a 404. Found 2026-08-28
# during the gate D review: 17,829 such requests from 8,767 DISTINCT client IPs
# across 35 hosted sites, overwhelmingly residential broadband with ordinary
# consumer browser UAs. Nineteen real visitors had already been temp-blocked,
# six by rule=error_burst, and one was a live permanent-ban candidate. These are
# the site's own visitors punished for the site's own markup.
#
# ONE ANCHORED, POSITIONAL regex, deliberately. The first version used three
# INDEPENDENT unanchored substring tests, and both review models independently
# broke it: any path with "/uploads/2025/10/x.jpg%20300w," appended won the
# exemption, because "image extension" and "NNNw," only had to appear SOMEWHERE
# rather than adjacently. So:
#   ^/            - the shape must BE the request, not appear inside it
#   ([a-z0-9_~-]+/)*  - intermediate dirs, and NO DOT: this is what stops
#                   /.env/uploads/... , /index.php/uploads/... (PATH_INFO) and
#                   /scan/path-1.html/uploads/... from being laundered through
#   uploads/YYYY/MM/  - the WordPress uploads tree
#   <file>.<imgext>   - an image, then IMMEDIATELY
#   (%20|+|space)NNN(w|x)  - the srcset/sizes descriptor, adjacent by construction
#   (,|%2c|end)       - width lists carry a comma; a single-candidate srcset or
#                   the LAST candidate does not, so end-of-string counts too.
#                   Density descriptors (2x, 1.5x) are the "sizes" spelling of
#                   the same defect and are covered.
# Suppression is further gated on path_scores_on_its_own() at the call site, so
# a bad-path or honeypot hit is never exempted however it is dressed.
function is_mangled_srcset(p,   lp) {
    lp = tolower(p)
    return (lp ~ /^\/([a-z0-9_~-]+\/)*uploads\/[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[^\/]+\.(jpg|jpeg|png|gif|webp|avif|svg)(%20|\+| )[0-9]+(\.[0-9]+)?[wx](,|%2c|$)/)
}

# path_scores_on_its_own(p) : 1 if p hits a bad-path pattern or a honeypot trap.
# The srcset exemption must never apply to such a path. Both review models
# independently found the bypass this closes: an early skip made
# "/wp-content/uploads/2025/10/.git/config.jpg%20300w," invisible to badpath AND
# honeypot scoring, so a request that scored 90 before the exemption scored
# nothing after it. A real browser fetching a broken srcset never requests a
# bad-path; only an attacker dressing one up does.
function path_scores_on_its_own(p,   i, h) {
    for (i = 0; i < nbad; i++) if (p ~ bad_rx[i]) return 1
    for (h = 0; h < nhp;  h++) if (p ~ hp_rx[h])  return 1
    return 0
}

function jesc(s,   t) {
    t = s
    gsub(/\\/, "\\\\", t)
    gsub(/"/,  "\\\"", t)
    gsub(/\t/, " ", t)
    gsub(/[\r\n]/, " ", t)
    # Any remaining C0 control byte (0x00-0x1F) is invalid inside a JSON string;
    # collapse to a space so the evidence object always parses.
    gsub(/[\000-\037]/, " ", t)
    return t
}

# Is the token a plausible literal IP address? Rejects non-addresses that the raw
# charset gate would pass (bare hex like "deadbeef", a single digit, out-of-range
# octets like 999.999.999.999). v4: four octets each 0-255. v6: hex groups that
# MUST contain at least one colon (bare hex is not an address).
function ip_plausible(a,   o, i, n) {
    if (a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        n = split(a, o, ".")
        for (i = 1; i <= 4; i++)
            if (o[i] + 0 > 255 || length(o[i]) > 3) return 0
        return 1
    }
    if (a ~ /^[0-9A-Fa-f:]+$/ && a ~ /:/) return 1
    return 0
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

    # Load honeypot trap patterns (operator-defined; a hit = instant perm).
    nhp = 0
    if (HONEYPOTS != "") {
        while ((getline hpl < HONEYPOTS) > 0) {
            if (hpl ~ /^[ \t]*#/) continue
            if (hpl ~ /^[ \t]*$/) continue
            hp_rx[nhp] = hpl; nhp++
        }
        close(HONEYPOTS)
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
    # Must be a plausible literal IPv4/IPv6 address — never a hostname, an
    # out-of-range octet string, bare hex, or a token that could be read as a flag
    # by csf/the CF API downstream. (The block path re-validates strictly; this is
    # the first-line filter so garbage never even reaches scoring.)
    if (!ip_plausible(ip)) next

    # A 404 the site's own broken markup asked for is not an event this IP
    # caused, so it is not scored AT ALL -- not merely kept out of the error
    # counters. Counting it in reqs[] while excluding it from cerr[] would hand
    # an attacker a DILUTION lever: err_ratio is nerr/n, so padding a real scan
    # with exempted 404s would drive the ratio down (50 probes at 100% becomes
    # 500 requests at 10%). It would also inflate rps and feed request_flood,
    # which is one of the two rules that produced the false positives. Dropping
    # the request outright removes both. Recorded in csrcset[] so it stays
    # counted in csrcset[] and surfaced as "404_srcset" in the evidence JSON --
    # but note that only shows up for an IP that scores on its OTHER traffic,
    # because END walks reqs[] and a srcset-only client deliberately has no
    # reqs[] entry. That is the intended outcome (such a client is not an
    # offender and should produce no row at all); the counter is for explaining
    # a borderline IP, not for census of the affected population.
    # Gated on path_scores_on_its_own(): a path that hits a bad-path pattern or a
    # honeypot is NEVER exempted, however it is dressed up.
    if (status == 404 && is_mangled_srcset(path) && !path_scores_on_its_own(path)) {
        csrcset[ip]++; next
    }

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
            # Failure evidence on HIGH+ paths only: an error status or a POST
            # (an actual credential/exploit attempt). HIGH paths like
            # wp-login.php are also visited by legitimate site owners, whose
            # sessions produce successful GETs here — never error bursts or
            # POST floods.
            if (w >= 70 && (status >= 400 || method == "POST")) hibad_fail[ip]++
            break        # one category per request (table is severity-ordered)
        }
    }

    # Honeypot trap: any hit flags the IP for an instant-perm decision.
    for (h = 0; h < nhp; h++) {
        if (path ~ hp_rx[h]) { honeypot[ip] = 1; break }
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
    # Track the vhost this IP hit most (the zone to block in on the CF plane).
    if (vh != "" && vh != "-") {
        vhk = ip SUBSEP vh
        vhcount[vhk]++
        if (vhcount[vhk] > topvh_n[ip]) { topvh_n[ip] = vhcount[vhk]; topvh[ip] = vh }
    }
}

# --- scoring & emit ---------------------------------------------------------
END {
    wsum = W_RATE + W_ERR_RATIO + W_ERR_BURST + W_FANOUT + W_BADPATH + W_UA + W_POST_FLOOD + W_NOVHOST
    if (wsum <= 0) wsum = 1

    for (ip in reqs) {
        n = reqs[ip]
        # Coerce every per-IP counter to a numeric scalar ONCE. An IP with no
        # bad-path hits (etc.) leaves these elements uninitialized, and gawk
        # 5.2.1 double-frees when an uninitialized array element is compared
        # more than once (fixed upstream in 5.2.2; Ubuntu 24.04 still ships
        # 5.2.1). The scalars are also what the rest of this block reads.
        bm = badmax[ip] + 0;   hf = hibad_fail[ip] + 0
        nerr = cerr[ip] + 0;   nburst = cburst[ip] + 0
        ndist = distinct[ip] + 0; npost = post[ip] + 0
        nnov = novhost[ip] + 0; nuae = ua_empty[ip] + 0; nuas = ua_susp[ip] + 0

        hp = honeypot[ip] + 0
        if (n < MIN_REQS && bm < 100 && hp == 0) continue   # below floor (CRITICAL/honeypot bypass)

        span = last_ep[ip] - first_ep[ip]
        if (span < 1) span = 1
        rps = n / span

        s_rate = clamp100(100 * (rps / RATE_SAT))

        s_err = 0
        if (n >= MIN_REQS) s_err = clamp100(100 * (nerr / n))

        # Error burst: absolute count of 403/404/444 over a knee of 40.
        s_burst = clamp100(100 * (nburst / 40.0))

        # Fanout: high distinct-path ratio AND absolute breadth.
        fr = ndist / n
        s_fanout = 0
        if (ndist >= 10) s_fanout = clamp100(100 * fr * (ndist / 50.0))

        s_bad = clamp100(bm)

        s_ua = 0
        if (nuae > 0) s_ua = clamp100(100 * (nuae / n))
        if (nuas > 0) { v = clamp100(100 * (nuas / n)); if (v > s_ua) s_ua = v }

        s_post = 0
        if (npost > 0 && n >= MIN_REQS) s_post = clamp100(100 * (npost / n) * (rps / RATE_SAT))

        s_nov = clamp100(100 * (nnov / n))

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
        if (hp)                                              { floor = 100; frule = "honeypot" }
        # CRITICAL secret/RCE path — block on sight, any volume.
        if (bm >= 100)                                       { floor = 90; frule = "critical_badpath" }
        # Repeated FAILED targeting of a sensitive HIGH endpoint (brute force /
        # probe). Gated on failure evidence (hibad_fail: errors or POSTs on
        # HIGH+ paths), NOT mere path presence — a site owner logging in and
        # working in wp-admin hits the same paths with successful GETs and a
        # couple of login POSTs, and must never trip this floor. A credential
        # brute is dozens of failed POSTs; 10 is far above any human session.
        if (bm >= 70 && hf >= 10 && floor < 80)              { floor = 80; frule = "high_badpath_repeat" }
        # Scanner profile: broad path fanout with a high error ratio.
        if (ndist >= 25 && n >= MIN_REQS && (nerr / n) >= 0.6 && floor < 78) { floor = 78; frule = "scanner_profile" }
        # Error burst: a large absolute volume of 403/404/444.
        if (nburst >= 100 && floor < 75)                     { floor = 75; frule = "error_burst" }
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
        ev = ev ",\"distinct_paths\":" ndist
        ev = ev ",\"status\":{\"2xx\":" (c2xx[ip]+0) ",\"3xx\":" (c3xx[ip]+0) \
                ",\"401\":" (c401[ip]+0) ",\"403\":" (c403[ip]+0) ",\"404\":" (c404[ip]+0) \
                ",\"404_srcset\":" (csrcset[ip]+0) \
                ",\"444\":" (c444[ip]+0) ",\"5xx\":" (c5xx[ip]+0) "}"
        ev = ev ",\"post\":" npost
        ev = ev ",\"badpath_cat\":\"" (badcat[ip] == "" ? "" : badcat[ip]) "\""
        ev = ev ",\"badpath_hits\":" (badhits[ip]+0)
        ev = ev ",\"hibad_fail\":" hf
        ev = ev ",\"decisive_rule\":\"" frule "\""
        ev = ev ",\"honeypot\":" hp
        ev = ev ",\"top_vhost\":\"" jesc(topvh[ip]) "\""
        ev = ev ",\"sample_ua\":\"" jesc(sample_ua[ip]) "\""
        ev = ev ",\"sample_paths\":[" paths_json "]"
        ev = ev "}"

        printf "%s\t%d\t%d\t%s\n", ip, score, n, ev
    }
}
