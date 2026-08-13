#!/usr/bin/env bash
# test/markdown_fences_test.sh — every fenced code block in this repo's markdown
# must actually close.
#
# Why this exists: on 2026-08-13 a README edit left `` ``` A surgical deploy… ``
# on one line. A closing fence must be alone on its line, so the block never
# closed and EVERY section after it rendered as code — on the PUBLIC repo, for as
# long as v2.16.0 was the tip.
#
# Why not markdownlint: it does not catch this. Verified against 0.45.0 with all
# default rules enabled — the malformed line parses as an OPENING fence carrying
# an info string, and no rule flags an unclosed block (MD040 is satisfied by the
# info string). It exits 0 on the exact broken text. A linter that misses the one
# bug you added it for is worse than none, because it reads as coverage.
#
# Why a test and not a CI step: CI runs `make test`, so this covers CI too — and
# unlike a CI-only job it also fires locally and inside release.sh's gate. The
# through-line of that whole incident was that local checks were quieter than CI.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${HERE}/.." && pwd)"

PASS=0; FAIL=0
check() { local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then PASS=$((PASS+1));
  else echo "FAIL ${name}: want='${want}' got='${got}'"; FAIL=$((FAIL+1)); fi; }

# CommonMark fence tracking. An opener is >=3 backticks and may carry an info
# string; a closer must be BARE and at least as long as its opener. Anything else
# while a block is open is content — which is precisely why a botched close
# leaves the block open all the way to EOF, and why checking for "unclosed at
# EOF" catches the bug without a special case for trailing text.
#
# Length-aware on purpose: this repo nests ```bash inside ```` blocks, and a
# naive toggle on /^```/ reports those as broken.
# TWO rules, because either alone is insufficient:
#
#  (1) a block still open at EOF, and
#  (2) inside a block, a run of >= the opener's length followed by TRAILING TEXT
#      — a close someone botched.
#
# Rule 2 is the one that catches the real defect. Rule 1 alone does NOT: a file
# with later fences simply re-pairs around the botched line, so it balances at
# EOF while every section in between renders as code. That is exactly what
# happened to the README, and a detector built only on rule 1 passes the very
# regression it was written for. Verified by mutation.
#
# Length-aware on purpose: this repo nests ```bash inside ```` blocks, and both
# rules must ignore a shorter run as ordinary content.
FENCE_AWK='
{
  if (!inb) { if (match($0, /^`{3,}/)) { inb=1; len=RLENGTH; openline=NR } }
  else {
    if (match($0, /^`{3,}/) && RLENGTH >= len) {
      rest = substr($0, RLENGTH + 1)
      if (rest ~ /^[ \t]*$/) { inb = 0 }
      else { printf "%s:%d: closing fence has trailing text\n", FILENAME, NR; inb = 0 }
    }
  }
}
END { if (inb) printf "%s:%d: fence opened here is never closed\n", FILENAME, openline }'

scan() { awk "$FENCE_AWK" "$1" 2>/dev/null; }

# --- the repo's own markdown must be clean (node_modules is vendored) ---
offenders="$(find "$ROOT" -name '*.md' -not -path '*/.git/*' -not -path '*/node_modules/*' -print0 \
             | xargs -0 -n1 awk "$FENCE_AWK" 2>/dev/null)"
if [[ -n "$offenders" ]]; then
    echo "FAIL unclosed fenced code block(s) — the file renders as code from that line on:"
    printf '%s\n' "$offenders" | sed 's/^/       /'
    FAIL=$((FAIL+1))
else
    PASS=$((PASS+1))
fi

# --- the detector itself must work (else the pass above means nothing) ---
T="$(mktemp -d "${TMPDIR:-/tmp}/swatter-md.XXXXXX")"
trap 'rm -rf "$T"' EXIT

# The exact 2026-08-13 defect.
printf '# T\n\n```bash\ndiff a b\n``` A surgical deploy that copies only x\nmore prose\n' > "$T/botched.md"
check "detects a close with trailing text" "$(scan "$T/botched.md" | wc -l | tr -d ' ')" "1"

# A plain unclosed block.
printf '# T\n\n```bash\nnever closed\n' > "$T/unclosed.md"
check "detects an unterminated block" "$(scan "$T/unclosed.md" | wc -l | tr -d ' ')" "1"

# Correct markdown stays silent.
printf '# T\n\n```bash\na\n```\n\nprose\n' > "$T/ok.md"
check "clean file is silent" "$(scan "$T/ok.md" | wc -l | tr -d ' ')" "0"

# Nested fences: ```bash inside a ```` block is legal and must NOT be flagged.
printf '# T\n\n````\nshowing markdown:\n```bash\nls\n```\n````\n\nprose\n' > "$T/nested.md"
check "nested fences are not false-flagged" "$(scan "$T/nested.md" | wc -l | tr -d ' ')" "0"

# A longer closer than opener is a valid close.
printf '# T\n\n```\na\n`````\n' > "$T/longer.md"
check "a longer bare closer closes the block" "$(scan "$T/longer.md" | wc -l | tr -d ' ')" "0"

# A SHORTER run inside a longer block is content, not a close.
printf '# T\n\n````\n```\nstill inside\n' > "$T/shorter.md"
check "a shorter run does not close a longer block" "$(scan "$T/shorter.md" | wc -l | tr -d ' ')" "1"

# THE REGRESSION THAT MATTERS: a botched close followed by MORE fences later in
# the file. The document re-pairs and ends balanced, so an EOF-only check passes
# while the prose in between renders as code. This is the README defect exactly.
printf '# T\n\n```bash\na\n``` trailing prose\nmore\n\n```bash\nb\n```\n\nend\n' > "$T/repairs.md"
check "botched close is caught even when the file re-pairs" \
    "$(scan "$T/repairs.md" | grep -c 'trailing text')" "1"

# A nested SHORTER run inside a longer block must still not be flagged by rule 2.
printf '# T\n\n````\n```bash\nls\n```\n````\n' > "$T/nested2.md"
check "rule 2 ignores shorter nested runs" "$(scan "$T/nested2.md" | wc -l | tr -d ' ')" "0"

# The reported line points at the problem the author must edit.
check "botched close reports its own line" "$(scan "$T/botched.md" | cut -d: -f2)" "5"

echo "----------------------------------------"
printf 'Total: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
