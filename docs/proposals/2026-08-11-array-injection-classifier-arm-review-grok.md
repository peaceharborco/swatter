<!-- Grok 4.5, read-only sandbox. Adversarial review of the uncommitted array-injection classifier arm. -->

## Blockers

1. **Per-account signatures make fleet-wide TypeError breakage indistinguishable from a scanner sweep — and the new arm is a common *genuine* PHP 8 bug class.**  
   Signature = full line minus timestamp only (`lib/errors.sh:317-318`), so it keeps both `[php/<acct>]` and `/home/<acct>/…`. Confirmed:

   - 17 accounts × 1 identical plugin TypeError → **17 scanner, 0 genuine** → `ERR_FATAL_GENUINE=0` → GREEN (`lib/report.sh:422`, `474`)
   - 5 accounts × 2 hits each (still `< REPEATS=3`) → **10 scanner, 0 genuine**
   - 1 busy account × 10 hits → genuine (repeat gate works *only* within one path)

   For the old ABSPATH / `undefined function` arm this was already a tradeoff, but those messages are almost always probe-shaped. The new arm matches ordinary app fatals, e.g.:

   - `htmlspecialchars(): … string, array given` in a Divi theme  
   - `trim(): … string, array given` in WooCommerce checkout  
   - `explode()` / `preg_match()` / `strpos()` / `substr()` on config/query that became an array after a bad update  

   All of those **match** the new arm (verified with the shipping regex via ENVIRON/`~`). A real post-update or form-array bug that fires once or twice per account overnight grades **All Clear** and skips RED SMS. That is exactly “over-broad = real outage graded green.”  
   **Missing mitigation:** no host-wide collapse (e.g. strip `/home/[^/]+` for TypeError counting, or “≥N accounts same relative path → genuine”).

2. **Comments assert a premise the TypeError arm does not satisfy — and the digest UI will lie about those lines.**  
   - `lib/errors.sh:179-182` still frames the *whole* classifier as “bot executing a PHP file directly, **outside the app bootstrap**.” The cds1 shape is *inside* bootstrap (`…/plugins/docket-cache/…/Plugin.php:1462`).  
   - `lib/errors.sh:188-189`: “only the argument-is-an-array direction is reachable by decorating a query string.” False: HTML `name="x[]"`, plugins rewriting POST, and normal app bugs produce the same TypeError without any scanner.  
   - UI copy is unchanged and will attach that wrong story to TypeError hits: `lib/errors.sh:363` (“bots executing PHP files directly”) and `lib/report.sh:499` (same). Operators will dismiss real plugin/theme TypeErrors as bot noise even when they appear in the scanner bucket.

Ship without fixing (1) and you bake a GREEN hole for shared-host WordPress fleets. (2) makes that hole harder to notice in the mail.

---

## Majors

1. **Pattern is broader than the “array injection probe” story; `.*` and `[?a-z|]+` are the loose joints.**  
   Arm (`lib/errors.sh:195`):

   `TypeError: [A-Za-z_]+[(][)]: Argument #[0-9]+ .* must be of type [?a-z|]+, array given`

   - Any free function + any lowercase/nullable/union type + `array given` matches — not limited to GET decoration or cache plugins.  
   - `.*` is greedy and unanchored in a line `~` match. Synthetic single-line case **matches** even when the *first* TypeError is `null given` if `, array given` appears later on the same line. Live per-line PHP collect usually drops stack frames (`lib/errors.sh:91-93`), so this is lower probability, but pre-consolidated `ERROR_DIGEST_LOG` lines are unconstrained (`lib/errors.sh:22-26`).  
   - No path/plugin scoping despite the motivation being one Docket Cache line.

2. **Too narrow for the attack class it claims (opposite failure).**  
   `[A-Za-z_]+[(][)]` rejects:

   - `WP_Query::get(): … array given`  
   - `DateTime::modify(): …`  
   - `App\Service::process(): …`  
   - namespaced free functions  

   Verified **NO** match. Real PHP 8 method TypeErrors from `[]` injection will stay genuine and can still RED a window. Arm is both over-broad on free functions and incomplete on methods.

3. **Tests do not pin the claimed narrowness.**  
   `test/errors_test.sh:79-110`: positives for `substr`/`strlen`, repeat gate, inverse (`string given`) + return-value.  
   A much broader pattern  
   `TypeError:.*array given`  
   produces the **same** M/M/N/N outcomes on those four fixtures. Nothing asserts:

   - function-call-only (`Class::method` stays out or in — untested either way)  
   - `Argument #` required  
   - multi-account / path-keyed signatures → all scanner  
   - genuine form/checkout TypeError under threshold stays… (policy unset)  
   - host-wide collapse  

   `arrinj-repeat` only re-checks the same single-account gate as `SCAN2`; it does not exercise the per-account signature interaction called out in the design notes.

4. **Classifier narrative drift vs first arm.**  
   First arm ≈ “file hit outside bootstrap.” Second arm ≈ “typed call got an array.” Same knobs, same RED effect, different meaning. No separate repeat threshold, veto, or copy path for TypeError.

---

## Minors

1. **Three-copy duplication is currently OK.**  
   `lib/common.sh:325`, `lib/errors.sh:195`, `config/swatter.example.conf:417` are **byte-identical**. Drift risk remains: shipping default is `common.sh`; invalid operator regex falls back to `_ERR_FATAL_SCANNER_DEFAULT` in `errors.sh`; example is docs only. Silent split would mean live vs fallback vs docs diverge without a test.

2. **Dialect: no compile-time landmine found** on BSD awk (macOS), gawk 5.4, and `grep -E`.  
   `#` literal, `|` inside `[?a-z|]`, `[(][)]` all compile; full pattern validates; `errors_test` PASS=50. Unlikely to hit the known grep/awk gap and silently replace with default.

3. **Double-space PHP wording.**  
   Raw PHP often logs `PHP Fatal error:  Uncaught` (two spaces). Pattern expects one. Live emit collapses whitespace (`lib/errors.sh:39`); **pre-consolidated** digest path does not. Pre-existing for the Error arm; still means fixtures/tests can pass while a double-space digest feed never classifies TypeErrors (or Errors).

4. **Disable docs omit `REPEATS=0`.**  
   `lib/errors.sh:194` / example say `REPEATS=1` disables; code also keeps `0` as RED-safe off (`lib/errors.sh:261-262`). Incomplete, not wrong for `1`.

5. **`[?a-z|]+` drops capitalized / class types** (`Stringable`, `WP_Post`) — accidental RED-safety for some genuine bugs; inconsistent with “array given ⇒ scanner.”

---

## What the change gets right

- Motivation is real: one probe RED’ing the window trains operators to ignore digests.  
- Inverse / return-value exclusions are intentional and tested.  
- Repeat gate, ENVIRON-not-`-v`, and three-site pattern update are wired consistently.  
- Regex is portable enough to compile under the repo’s dual grep+awk validator.

---

## VERDICT

**HOLD**

Do not ship this arm as written on an enforcing multi-account host. The repeat gate is **per absolute path / account**, so a scanner sweep and a sparse fleet-wide plugin/theme TypeError look identical (N× count-1 → all scanner → GREEN). That was a known tradeoff for ABSPATH-style probes; extending it to every free-function `…, array given` TypeError reclassifies a large, ordinary WordPress failure mode as bot noise, while the UI still claims “bots executing PHP files outside bootstrap.” Fix before ship: either (a) host-level / path-normalized counting for this arm, (b) a much tighter match (plugin- or probe-specific), or (c) stop auto-downgrading TypeErrors without a stronger signal — and rewrite comments + digest copy so they do not assert query-only reachability or “outside bootstrap” for this class. Tests must pin multi-account behavior and reject a bare `TypeError:.*array given` stand-in.
