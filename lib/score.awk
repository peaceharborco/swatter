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

# is_mangled_srcset(p) : 1 if this request path is a client fetching a whole
# srcset/sizes ATTRIBUTE VALUE as a single URL, rather than probing us.
#
# Found 2026-08-28 during the gate D review: 17,829 such requests from 8,767
# DISTINCT client IPs across 35 hosted sites, overwhelmingly residential
# broadband. Nineteen real visitors had already been temp-blocked, six by
# rule=error_burst, and one was a live permanent-ban candidate -- which on a
# publishing host is also an AbuseIPDB report with no delete API, filed against a
# residential customer of the site's own owner.
#
# CAUSE, CORRECTED 2026-08-28 -- READ THIS BEFORE REMOVING THE EXEMPTION.
# This was first diagnosed as the sites emitting broken markup. It is NOT. A
# dedicated investigation swept all 34 in-scope sites and found the markup
# CORRECT everywhere; a falsification review by two adversarial models could not
# refute that finding. The requests are manufactured CLIENT-SIDE by third-party
# Chromium-based clients that read a *correct* srcset attribute and request its
# whole value as one URL. The decisive evidence is the browser mix: 14,653 Chrome
# / 2,635 Edge / 3 Safari / 0 Firefox, against a ~24% Safari / ~7% Firefox
# baseline on the same traffic. Broken markup breaks in every browser.
#
# The consequence for this function: there is no upstream fix coming, and there
# is no markup repair that would make it obsolete. It originates on machines we
# do not control, so this is the ONLY layer that can act on it. Do NOT delete it
# on the grounds that "the markup is clean" -- the markup was always clean.
#
# ONE ANCHORED, POSITIONAL shape, deliberately. The first version used three
# INDEPENDENT unanchored substring tests, and both review models broke it: any
# path with "/uploads/2025/10/x.jpg%20300w," appended won the exemption, because
# "image extension" and "NNNw," only had to appear SOMEWHERE rather than
# adjacently. The first candidate must therefore match, end to end:
#   ^/                     - the shape must BE the request, not appear inside it
#   ([a-z0-9_~-]+/)*       - prefix dirs, and NO DOT and NO %: this is what stops
#                            /.env/uploads/... , /index.php/uploads/... (PATH_INFO),
#                            /scan/path-1.html/uploads/... and /%2egit/uploads/...
#   uploads/               - literal
#   (sites/[0-9]+/)?       - WordPress MULTISITE. The blog id is NUMERIC; a
#                            permissive class here would be a new prefix to launder.
#   YYYY/MM/               - the dated uploads tree
#   ([a-z0-9_~-]+/)*       - nested dirs (plugin thumbnail trees), same dot-free
#                            and %-free class, for the same reason
#   [a-z0-9_~@.%-]+        - the STEM. Dots, '@' and '%' ARE allowed (real upload
#                            names carry them, and a non-ASCII name arrives
#                            percent-encoded); a COMPLETE %2e/%2f is refused for
#                            the whole path up front. Vetted by stem_is_safe().
#   .<imgext>              - then IMMEDIATELY
#   (%20|+|space)+NNN(w|x) - the srcset/sizes descriptor, adjacent by construction
#   (%20|+|space)*$        - end of THIS candidate; whitespace before a comma is
#                            legal srcset. Density descriptors (2x, 1.5x) are the
#                            "sizes" spelling of the same defect and are covered.
# Every LATER candidate must match the same shape, optionally preceded by a
# scheme+host. The host group requires `//` (`https://host` or `//host`); a
# single slash is a path, so `/wp-config.php/x.jpg` cannot parse as a host
# (dots are legal in a host and illegal in a directory). A trailing comma
# with nothing after it is the one permitted empty element.
# Suppression is further gated on path_scores_on_its_own() at the call site, so
# a bad-path or honeypot hit is never exempted however it is dressed.
#
# THE EXEMPT STATUS SET IS (status < 400 || status == 404) -- that is
# {0, 1xx, 2xx, 3xx, 404}, AND IT IS EVIDENCE, NOT TASTE.
# The first attempt at this removed the status gate entirely, reasoning that any
# status set is itself a dilution lever. That reasoning is WRONG and the pre-ship
# review measured why: err_ratio is nerr/n, so only a status that stays OUT of
# cerr[] can dilute. 5xx feeds cerr[]; 403 feeds cerr[] AND cburst[]. Padding a
# probe run with either RAISES the score, it cannot lower it. Only 2xx/3xx dilute
# -- and the measured class is 15,299 x 404, 1,936 x 301, 592 x 302, 2 x 200, with
# ZERO 5xx and ZERO 403. So the set is what the class contains plus every other
# status that CANNOT dilute, and every status carrying real signal keeps scoring.
#
# DO NOT "tidy" the predicate to {2xx,3xx,404}. status 0 is what ingest emits for a
# line it could not parse, and neither 0 nor 1xx feeds cerr[] -- so narrowing the
# predicate to the tidier-looking set REOPENS the dilution lever for them. Verified:
# a 60-probe run padded with 500 srcset-shaped 1xx scores 78 as written, and emits
# no row at all under the narrowed predicate. Dropping 5xx would have made an
# origin melt invisible: 400 requests in 20s scored 75 request_flood before that
# attempt and NONE after it.
#
# END-ANCHORED OVER THE WHOLE CANDIDATE LIST. The first version anchored only ^/,
# so once the alternation took the "," branch the entire remainder of the path was
# unvalidated and any target could ride behind a valid srcset head --
# ".../a.jpg%20300w,/../../../../etc/passwd" was dropped at every status.
# badpaths.conf carries no ".." or %2e pattern, so path_scores_on_its_own() cannot
# see traversal and was never a backstop for it. The path is now split on commas
# (%2c normalised first, or the encoded spelling escapes validation) and EVERY
# candidate must match end-to-end.
#
# THE STEM IS [a-z0-9_~-]+, NOT [^/]+. The old stem admitted dots and percent
# encoding, and everything the exemption requires in order to look like an image
# is what made these miss path_scores_on_its_own(): wp-config.php.jpg,
# c99.php.jpg, .htaccess.jpg, %2eenv.jpg, x%2f.env.jpg were all dropped. The
# badpath table keys on literal spellings and tolower() case-folds WITHOUT
# decoding. Real WordPress upload names (photo-768x576) fit the same dot-free
# class the directories already use, so the stem now uses it too.
#
# The dot refusal on BOTH sides of uploads/YYYY/MM/ is structural on purpose and
# is not merely backstopped by the badpath table; mutation testing found that
# every bypass case pinned before 2026-08-28 carried a segment badpaths ALSO
# caught, so loosening the dir class broke nothing. test/score_test.sh now pins
# segments that appear in NO badpath pattern for exactly this reason.
# candidate_complete(c) : 1 if c parses as a WHOLE srcset candidate (url +
# descriptor). Used to tell a truncated tail from a finished one at the 256-byte
# boundary -- see the note at the call site.
function candidate_complete(c) {
    return (c ~ /^(%20|\+| )*(https?:)?(\/\/[a-z0-9_~.-]+(:[0-9]+)?)?\/([a-z0-9_~-]+\/)*[a-z0-9_~@.%-]+\.(jpg|jpeg|png|gif|webp|avif|svg|bmp|heic|heif|jfif)(%20|\+| )+[0-9]+(\.[0-9]+)?[wx](%20|\+| )*$/)
}

# candidate_prefix_ok(c) : 1 if c could be the BEGINNING of a well-formed srcset
# candidate. Used for the final element of a path that hit the 256-byte ingest
# boundary, where the candidate is cut off mid-way.
#
# It is NOT enough to skip that element. ingest truncates only when the path is
# LONGER than 256, so a path arriving at exactly 256 is indistinguishable from a
# truncated one -- and simply ignoring the tail let an attacker pad to exactly 256
# and ride the unvalidated-tail bypass again. Measured: the same traversal payload
# scored 75 at 255 bytes and was dropped at 256.
#
# A genuinely cut-off URL is still a valid prefix: whitespace, an optional
# scheme+host, dot-free segments, then a final partial token that may carry dots
# because it is a filename being sliced. "/../../../../etc/passwd" is not, because
# its segments carry dots and it never reaches the partial-token position.
function candidate_prefix_ok(c) {
    # A cut-off tail can end mid-percent-escape (".jpg%") or mid-SCHEME ("%20htt",
    # "%20https", "%20https://"). The first version only modelled the former, so a
    # realistic 4-candidate srcset -- ~354 bytes, cut by ingest squarely in the
    # scheme window -- scored 75 and temped a real visitor.
    # Defense in depth: is_mangled_srcset already refused %2e|%2f|%25|%00 on
    # the whole path before either call site, so this branch cannot fire today.
    # It is not what stops the encoded cloaks. Left in place so a future
    # narrowing of that guard does not reopen them on a truncated tail.
    if (c ~ /%2e|%2f/) return 0
    # A cut can also land INSIDE the "%20" that separates candidates, leaving a
    # tail of exactly "%" or "%2". That is a truncation artifact and nothing else,
    # so it is accepted ONLY as the entire tail -- never as a prefix that
    # something follows, which would let ",%/etc/passwd" ride.
    if (c ~ /^(%20|\+| )*%[0-9a-f]?$/) return 1
    # Final token admits + and literal space: they are the other two spellings
    # of the srcset separator already accepted as (%20|\+| ) everywhere else.
    # Omitting + scored a truncation landing on …jpg+ / …jpg+9. Space is
    # unreachable via ingest (request-line split) and is included so this
    # predicate does not depend on its caller.
    return (c ~ /^(%20|\+| )*[a-z]*:?\/?\/?[a-z0-9_~.-]*(:[0-9]+)?(\/[a-z0-9_~-]+)*(\/[a-z0-9_~@. %+-]*)?$/)
}

# candidate_stem(c) : the filename stem of one srcset candidate -- everything
# after the last '/' and before the image extension the regex just matched.
function candidate_stem(c,   t, n, seg) {
    n = split(c, seg, "/")
    t = seg[n]
    sub(/\.(jpg|jpeg|png|gif|webp|avif|svg|bmp|heic|heif|jfif)(%20|\+| )+[0-9]+(\.[0-9]+)?[wx](%20|\+| )*$/, "", t)
    return t
}

# stem_is_safe(stem) : 0 if a dot-separated component of the filename stem is an
# executable or config EXTENSION.
#
# The stem has to admit dots. WordPress sanitize_file_name() strips
# ?[]\/=<>:;,'"&$#*()|~`!{}%+ and NUL but leaves '.' and '@' alone, so
# "my.photo-768x576.jpg" and "logo@2x-768x576.jpg" are REAL upload names --
# refusing every dot scored them at 75, which is the exact irreversible harm this
# exemption exists to prevent. '%' is admitted because a non-ASCII name arrives
# percent-encoded; a COMPLETE %2e/%2f/%25/%00 is refused on the whole path
# before the stem is consulted.
#
# Admitting dots reopens the double-extension cloak, so safety moves here: a
# bounded deny list over ONE token. It is a DENY LIST and therefore has a residual
# tail by construction -- round 2 produced phtm, php-cgi, js, inc, cmd, jspx, ashx,
# shtml and zip against the first version of it. Do not describe it as a structural
# guarantee; the structural guarantees are the dot-free, %-free directory segments. That is a different thing from the path
# substring blocklist this design avoids -- the token is a single dot-component of
# a single filename, and the structural rules (dot-free, %-free directory segments
# on BOTH sides of the dated tree) still carry every traversal case on their own.
function _strip_wp_suffixes(c,   prev) {
    prev = ""
    while (c != prev) {
        prev = c
        sub(/-[0-9]+x[0-9]+$/, "", c)                                  # -768x576
        sub(/-scaled$/, "", c)                                         # WP 5.3+
        sub(/-e[0-9][0-9]*$/, "", c)                                   # -e1699999999
        sub(/[~]+$/, "", c)                                            # php~
        sub(/_+$/, "", c)                                              # php_
        sub(/[-_](cgi|fpm|fcgi|backup|bak|old|new|copy|orig|save|tmp)$/, "", c)
    }
    return c
}

function _deny_token(c) {
    return (c ~ /^(php|php[0-9]+|phps|phtml|phtm|pht|phar|aspx|ashx|asmx|ascx|cshtml|jsp|jspx|jhtml|shtml|cgi|fcgi|wsgi|ps1|vbs|exe|dll|wasm|env|htaccess|htpasswd|htgroup|cfg|yml|yaml|toml|sql|sqlite|sqlite3|pem|pfx|p12|jks|keystore|passwd)$/)
}

# stem_is_safe(stem) : 0 if a dot-component of the filename stem is an executable
# or secret-bearing EXTENSION.
#
# The stem admits dots and '@' because WordPress sanitize_file_name() leaves them
# alone, so "my.photo-768x576.jpg" and "logo@2x-768x576.jpg" are REAL names, and
# it admits '%' because a non-ASCII name arrives percent-encoded ("caf%c3%a9").
# It never admits a COMPLETE %2e or %2f -- that is how the encoded cloaks got in.
#
# THE LIST IS DELIBERATELY NARROW, and that is a decision, not an oversight.
# Rounds 3 AND 4 both shipped false positives from it: photo.bak.jpg, old.jpg,
# backup.zip.jpg, the.bat.jpg, foto.do.evento.jpg, my.key.jpg, warsaw.pl.jpg,
# shanghai.sh.jpg, x.html.jpg, data.json.jpg. Every one is an ordinary filename,
# and each scored 75 -- three of which is a permanent, non-deletable AbuseIPDB
# report against a residential visitor.
#
# The asymmetry settles it. A missed token costs an attacker's request its
# intent-evidence, on a request that executes nothing (the URL ends in the srcset
# descriptor, so the server serves no PHP either way). A wrong token bans a real
# person irreversibly. So: only tokens that are unambiguous file extensions AND
# rarely ordinary words. Short words (bat, do, key, pl, sh, so, ts, der, inc,
# py, rb, ini, cnf, cfm, crt) and
# inert data suffixes (html, json, xml, zip, bak, tmp) are OUT by that rule.
#
# Not consulted at all when the stem has no dot: a dot-free stem cannot BE a
# double extension, and checking it banned bare old.jpg / tmp.jpg / env.jpg.
function stem_is_safe(stem,   k, m, comp, c) {
    m = split(stem, comp, ".")
    if (m < 2) return 1
    # Start at 2, not 1. A double extension is a dangerous token sitting where the
    # REAL extension should be -- "wp-config.php.jpg". A token in the FIRST
    # component is a name prefix and the file is still a .jpg, so refusing it is a
    # false positive by this list's own purpose. Sweeping 62,700 generated
    # WordPress-realistic names through this predicate found 8,316 of 18,216
    # refusals (46%) were exactly that: cfg.autumn-768x576.jpg, sql.report.jpg,
    # py.workshop.jpg. ".htaccess.jpg" still scores -- its components are
    # ("", "htaccess"), so the token is in position 2 where it belongs.
    for (k = 2; k <= m; k++) {
        c = comp[k]
        if (_deny_token(c)) return 0
        # Editor backups, pool variants and WordPress's own resize suffix.
        # ITERATIVE and TARGETED, both deliberately. A single strip let
        # "php-cgi-768x576" keep its dimensions and never reach "php"; a BLANKET
        # strip of any trailing -word detonated on "conf-768x576" -> "conf" and
        # banned mens.conf.jpg. So: only forms WordPress or an editor actually
        # produces, applied until stable. An ordinary hyphenated word
        # ("conf-room", "pen-pal") is not one of them and is left alone.
        c = _strip_wp_suffixes(c)
        if (_deny_token(c)) return 0
    }
    return 1
}

function is_mangled_srcset(p,   lp, n, parts, i, trunc, last) {
    # Cheap prefilter. Also restores the short-circuit the old status==404 gate
    # gave us, now that this runs on every line.
    if (index(p, "uploads/") == 0) return 0
    # lib/ingest.sh:72 cuts the path at 256 bytes, so at the boundary the FINAL
    # candidate is incomplete BY CONSTRUCTION. Holding it to the end anchor scored
    # real long srcset values as ordinary 404 storms -- a false positive the
    # end-anchoring itself created (measured: a real 5-candidate value of 461 bytes
    # scored 75). Measured on p BEFORE the %2c rewrite, which changes the length.
    trunc = (length(p) >= 256)
    lp = tolower(p)
    # An encoded comma is a comma. Normalise before splitting so the two
    # spellings cannot be used to hide a candidate from validation.
    gsub(/%2c/, ",", lp)
    # %2e / %2f are never legitimate here (WordPress does not emit them) and are
    # how the encoded cloaks ride. Checked AFTER the %2c rewrite so a legitimate
    # encoded comma is not caught, and once for the whole path so that admitting
    # '%' into the stem -- needed for percent-encoded UTF-8 names -- cannot
    # reopen %2eenv.jpg or x%2f.env.jpg.
    # %25 closes the DOUBLE-encoded family: "%252e" does not contain the substring
    # "%2e" (it is % 2 5 2 e), so a substring guard alone missed it entirely, and a
    # stem with no literal dot never reaches the deny list. %00 is never legitimate.
    # Overlong/fullwidth spellings (%c0%ae, %ef%bc%8e) are NOT closed here -- see
    # the Known note in CHANGELOG.md.
    if (lp ~ /%2e|%2f|%25|%00/) return 0
    n = split(lp, parts, ",")

    # The FIRST candidate is the request path itself: always root-relative, and
    # always inside the uploads tree. END-ANCHORED -- see the comment above.
    if (trunc && n == 1 && !candidate_complete(parts[1])) {
        # No image extension required here: a 256-byte cut can land before
        # one exists. The uploads-tree anchor, prefix check, and stem check
        # still have to pass. Contained by the dot-free directory rule.
        if (parts[1] !~ /^\/([a-z0-9_~-]+\/)*uploads\/(sites\/[0-9]+\/)?[0-9][0-9][0-9][0-9]\/[0-9][0-9]\//)
            return 0
        if (!candidate_prefix_ok(parts[1])) return 0
        if (!stem_is_safe(candidate_stem(parts[1]))) return 0
        return 1
    }
    if (parts[1] !~ /^\/([a-z0-9_~-]+\/)*uploads\/(sites\/[0-9]+\/)?[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/([a-z0-9_~-]+\/)*[a-z0-9_~@.%-]+\.(jpg|jpeg|png|gif|webp|avif|svg|bmp|heic|heif|jfif)(%20|\+| )+[0-9]+(\.[0-9]+)?[wx](%20|\+| )*$/)
        return 0
    if (!stem_is_safe(candidate_stem(parts[1]))) return 0

    # EVERY later candidate must also be a well-formed one. A trailing comma with
    # nothing after it is the one permitted empty element.
    # Every COMPLETE candidate is still validated, and the first one always is, so
    # a truncated value must still prove it began as this shape.
    last = n
    # candidate_prefix_ok() OVERLAPS complete candidates without being a strict
    # superset (a literal-space candidate parses complete but not as a prefix), so
    # skipping the final element whenever it merely LOOKED like a prefix let a
    # finished attack candidate ride: ",/x.php.jpg%20300w" scored 75 at 255 bytes
    # and was exempt at 256. candidate_complete() is therefore checked FIRST: a
    # complete final stays in the full loop below, and only a genuinely incomplete
    # one gets prefix treatment -- which is itself stem-checked, because
    # prefix-shaped is not the same as safe.
    # A SINGLE candidate cut at the boundary had no prefix path at all -- it was
    # held to the full end-anchored match it cannot satisfy, and scored. Real
    # names reach this: percent-encoded CJK or accented stems inflate ~3x, so the
    # threshold is far below "213 ASCII characters". It still has to prove it
    # began as this shape (the uploads-tree anchor) before the tail is forgiven.
    if (trunc && n > 1 && !candidate_complete(parts[n])) {
        # Prefix-shaped is NOT the same as safe: the round-3 fix full-validated a
        # COMPLETE final candidate but let an INCOMPLETE one skip the stem check
        # entirely, so ",/c99.php" and ",/wp-config.php" rode at exactly 256 bytes.
        # badpaths.conf has no generic \.php rule, so nothing backstopped them.
        if (!candidate_prefix_ok(parts[n])) return 0
        if (!stem_is_safe(candidate_stem(parts[n]))) return 0
        last = n - 1
    }
    for (i = 2; i <= last; i++) {
        if (i == n && parts[i] ~ /^(%20|\+| )*$/) continue
        if (parts[i] !~ /^(%20|\+| )*(https?:)?(\/\/[a-z0-9_~.-]+(:[0-9]+)?)?\/([a-z0-9_~-]+\/)*[a-z0-9_~@.%-]+\.(jpg|jpeg|png|gif|webp|avif|svg|bmp|heic|heif|jfif)(%20|\+| )+[0-9]+(\.[0-9]+)?[wx](%20|\+| )*$/)
            return 0
        if (!stem_is_safe(candidate_stem(parts[i]))) return 0
    }
    return 1
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

    # A request the visitor's own client manufactured from a correct srcset is
    # not an event this IP caused, so it is not scored AT ALL -- not merely kept
    # out of the error counters. Statuses below 400, plus 404: see the predicate
    # note on is_mangled_srcset(). 403/5xx/429 deliberately still score. Counting it in reqs[] while excluding it from cerr[] would hand
    # an attacker a DILUTION lever: err_ratio is nerr/n, so padding a real scan
    # with exempted 404s would drive the ratio down (50 probes at 100% becomes
    # 500 requests at 10%). It would also inflate rps and feed request_flood,
    # which is one of the two rules that produced the false positives. Dropping
    # the request outright removes both. Recorded in csrcset[] so it stays
    # counted in csrcset[] and surfaced as "srcset_exempt" in the evidence JSON --
    # but note that only shows up for an IP that scores on its OTHER traffic,
    # because END walks reqs[] and a srcset-only client deliberately has no
    # reqs[] entry. That is the intended outcome (such a client is not an
    # offender and should produce no row at all); the counter is for explaining
    # a borderline IP, not for census of the affected population.
    # Gated on path_scores_on_its_own(): a path that hits a bad-path pattern or a
    # honeypot is NEVER exempted, however it is dressed up.
    if ((status < 400 || status == 404) && is_mangled_srcset(path) \
        && !path_scores_on_its_own(path)) {
        csrcset[ip]++
        if (first_sr[ip] == 0 || ep < first_sr[ip]) first_sr[ip] = ep
        if (ep > last_sr[ip]) last_sr[ip] = ep
        # Deliberately NOT tracking topvh here. An exempted request is not evidence
        # of anything this IP did wrong, and letting it win the vhost vote pointed
        # the CF-plane block at the wrong zone (measured: 30 real requests on one
        # vhost lost to 80 exempted ones on another).
        next
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

    # --- srcset volume tripwire ---------------------------------------------
    # Exempted requests are dropped before reqs[], which is what closes the
    # dilution lever -- but it also means a client flooding purely in this shape
    # produces no row at all, at any volume. The exempted requests are therefore
    # still counted, and an implausible volume of them surfaces.
    #
    # IT CAN NEVER TEMP, AND THAT IS THE POINT. The first version made this a 75
    # floor at >= 60 requests and >= RATE_SAT rps, justified as "~1300x above the
    # heaviest real client (544/day = 0.006 rps)". That compared a DAILY AVERAGE
    # against a BURST rate. The tripwire measures burst span, and the real class IS
    # a burst -- one image-heavy page makes the client fetch every srcset on it at
    # once. Measured: 70 gallery images in 5s scored 75, temp-blocking a visitor for
    # loading ONE page, and three of those is a permanent AbuseIPDB report. A rate
    # tripwire on this shape will always hit gallery bursts, so it tops out at
    # SCORE_WATCH -- which the config defines as "log + count, no action" -- and the
    # threshold sits far above any page load. Visibility without ban risk.
    for (ip in csrcset) {
        sn = csrcset[ip] + 0
        sspan = last_sr[ip] - first_sr[ip]
        if (sspan < 1) sspan = 1
        if (sn >= 500 && (sn / sspan) >= 25) {
            srflood[ip] = 1
            if (!(ip in reqs)) {      # srcset-only client: give it a row to carry
                reqs[ip] = sn
                first_ep[ip] = first_sr[ip]
                last_ep[ip]  = last_sr[ip]
                seeded[ip]   = 1
            }
        }
    }

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
        # srflood bypasses this too: the first version seeded reqs[] only for an IP
        # that had none, and this guard ran BEFORE the tripwire, so ten ordinary
        # requests were enough to switch the whole channel back off.
        if (n < MIN_REQS && bm < 100 && hp == 0 && !srflood[ip]) continue

        span = last_ep[ip] - first_ep[ip]
        if (span < 1) span = 1
        rps = n / span
        # A seeded row has no SCORED requests behind it, so it must not inherit a
        # rate from the exempted ones -- that would let the watch-only tripwire
        # reach the request_flood floor and temp after all.
        if (seeded[ip]) rps = 0

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

        # Lift a quiet row up to the reporting line. Never an override: a
        # genuine floor (request_flood at 75, etc.) stays put even if an
        # operator raises SCORE_WATCH above it. The first version used only
        # `composite < SCORE_WATCH`, which rewrote frule and lifted the score
        # the moment SCORE_WATCH sat above 75.
        if (srflood[ip] && composite < SCORE_WATCH && floor == 0) {
            composite = SCORE_WATCH
            frule = "srcset_flood"
        }

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
                ",\"srcset_exempt\":" (csrcset[ip]+0) \
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
