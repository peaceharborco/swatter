# Swarm Hub IMPLEMENTATION review — Grok two-model pass (pre-merge, pre-v2.6.0)

Adversarial review of the `hub/` implementation on `feat/swarm-hub` against the
frozen contract in `2026-07-03-swatter-swarm-hub.md`. Both models ran headless,
read-only, same brief. **Both verdicts: REVISE-BEFORE-SHIP** — revisions applied
on the branch (commit "harden hub per Grok implementation review"), suite green
(69 tests) after.

Provenance: `[both]` = flagged by grok-build AND grok-composer-2.5-fast;
`[build]`/`[composer]` = single-source (verified against code before acting).

## Fixed

- **[both] Contribute wrote 2 awaited D1 statements per entry** — a full
  `MAX_ENTRIES=1000` publish ≈ 2000 sequential subrequests (exceeds Workers Free
  1000-subrequest cap; huge wall-clock on Paid). → `contributeMany()` chunked
  `DB.batch()` (50 entries / 100 statements per round trip); `contributeOne`
  delegates to it. HTTP test proves a full 1000-entry batch succeeds.
- **[both] `/register` accepted host_ids `/contribute` rejects** (no length
  bound at enroll; composer probe enrolled a 50k-char id → every later publish
  400s = bricked enroll→publish lifecycle). → one shared rule both routes:
  `^[\x21-\x7e]{1,128}$` (also kills whitespace-only ids, composer Minor 10).
- **[composer] Non-string `category` → `D1_TYPE_ERROR` → bare 500** (outside
  the frozen 400/401/413/429 error set; probe-confirmed). → category sanitized
  to string ≤64 chars else `null`; test covers object + number categories.
- **[both] Body fully parsed before any size check** → `content-length > 1 MiB`
  now 413s before `request.json()` on both POST routes. (Chunked bodies without
  content-length still parse — bounded post-parse by MAX_ENTRIES; accepted.)
- **[composer] `label` unbounded at enroll** → string ≤256 chars else null.
- **[both] HTTP-level test gaps** → added: `?limit` clamp + `X-Swarm-Truncated`
  via HTTP, exact JSON row shape, malformed JSON 400, register bounds, category
  sanitize, full-MAX_ENTRIES batch, chunked-batch DB tests. 60 → 69 tests.
- **[both] README documents `swatter swarm enroll` which doesn't exist yet** →
  noted as subsystem-2 + curl fallback for early enrollment.

## Declined (with reasons)

- **[build] "ratelimits namespace_ids are placeholders; deploy will reject"** —
  wrong: namespace_id is an operator-chosen integer, and composer's
  `wrangler deploy --dry-run` probe confirmed both limiters bind.
- **[build] 413 fires before the unenrolled gate** — that ordering is the
  plan's own frozen code; contract includes 413 independently.
- **[composer] D1 failures surface as 500** — intentional: host-side contract
  treats any non-200 as transport failure → keep-last-good, which is the right
  behavior when the hub is broken.
- **[composer] feed runs a correlated COUNT subquery per row (50k worst case)**
  — real at theoretical scale; plan self-review already documents pagination as
  a fast-follow; current fleet is 4 hosts. Accepted for v2.6.0.
- **[build] auth regex strictness / [composer] length-first timing leak** —
  exact `Bearer` match is fine for a machine-to-machine contract we control on
  both sides; tokens are long random strings.
- **[composer] `?format=JSON` case-sensitive** — contract specifies lowercase.
- **[build] lowercase `x-swarm-truncated` emit** — HTTP headers are
  case-insensitive; consumers must match insensitively anyway.

Raw outputs: scratchpad `grok-hub-review-build.md` / `grok-hub-review-composer.md`
(session-local; the substance is captured above).
