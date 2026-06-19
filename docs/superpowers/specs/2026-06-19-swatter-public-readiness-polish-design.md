# Swatter public-readiness polish — design

**Date:** 2026-06-19
**Status:** approved
**Scope:** Documentation + onboarding polish to make the public repo first-class. No
behavioral code changes beyond install-time output wording and code-comment
genericization. The inline origin-lock fold-in is explicitly **out of scope** (its
own future design).

## Goal

Close the gap between "an excellent tool built for one fleet that happens to be
public" and "a tool a stranger trusts enough to point at their own firewall."
The engine is already strong (MIT, CI + unit suite, dry-run-default safety,
fail-closed rails, two firewall backends, optional free intel). What's missing is
the trust/onboarding layer a public security tool is expected to carry.

## Hard constraint — secrets & proprietary hygiene

This is a **public** repo. No artifact may introduce: real server IPs, production
hostnames or SSH aliases, customer/tenant domain names, API keys or tokens,
absolute `/home/...` account paths, or the names of any private/internal repos.
All examples use the existing `*.example` config placeholders and generic
hostnames (`example.com`, `203.0.113.0/24`, etc.). gitleaks already runs in CI and
remains the backstop; new content must stay inside it.

## Audience positioning (decided)

Own the **cPanel + CSF** niche proudly — it is real and underserved — but stop
underselling: the block layer already supports a **CSF-optional raw ipset/iptables
backend**, and that must be visible in the README. Ingest remains Apache/cPanel
shaped; nginx ingest is a separate future effort, not promised here.

## Artifacts

### 1. `SECURITY.md`
Vulnerability-disclosure policy. Reporting channel: **GitHub private vulnerability
reporting only** (no published email — nothing to leak). Contents: supported-version
table (2.x supported), how to report, response-time expectations, in/out-of-scope,
brief good-faith safe-harbor language, explicit "no paid bug bounty."

### 2. `CHANGELOG.md`
[Keep a Changelog] format + a SemVer policy statement. Reconstructed from the six
tags (v1.0.0 2026-06-10 → v2.0.0 2026-06-17) and commit history, written as
**generic feature lines** — no infra specifics, no incident IPs/domains. Coverage:
CF-aware block planes + auto-detect + `skip`/`direct` postures; direct-to-origin
CF-bypass detection (live-socket evidence → CSF); keyless list-feed intel registry
+ opt-in keyed providers (GreyNoise / AbuseIPDB / Project Honeypot); ASN/hosting
boost incl. IPv6 origin lookups; honeypot trap paths; ipset backend + `setup-ipset`;
fleet ban export/import; multi-channel rate-limited alerts; opt-in AbuseIPDB
outbound reporting; nightly error+abuse digest; SQLite persistence; Prometheus
metrics.

### 3. `CONTRIBUTING.md`
Mirrors CI exactly so the documented bar == the enforced bar: prereqs (`bash`,
`gawk`, `shellcheck`); run `make test` and `shellcheck --severity=error bin/swatter
lib/*.sh install/*.sh test/*.sh`; PR expectations (tests + lint green, focused
diffs, test-with-change); commit-message conventions. Includes a short
**"never commit secrets"** section enumerating the hygiene categories above
(public-facing guardrail). Deliberately omits any mention of internal mirror/host
infrastructure.

### 4. `README.md` edits (surgical)
- Correct the headline/intro so CSF reads as **optional** — the raw ipset/iptables
  backend stands alone — while keeping the proud cPanel+CSF framing.
- Add a one-line **IPv6 support status** note: IPv4 full; IPv6 partial (note which
  paths are v4-only today) — honest expectation-setting, no overclaim.

### 5. Install first-run framing (`install/install.sh`)
Make "**run in report/dry-run mode first, read the digest, then enforce**" the loud
default in post-install output. Strongest single stranger-safety nudge. Output-only
change; no logic change to the install steps themselves.

### 6. Optional micro-scrub (`lib/*.sh` comments)
Genericize the handful of `/server-logs` references in code comments to "your error
aggregator" so there are zero internal-tooling names in the public tree. Cosmetic;
include only if it reads cleanly.

## Out of scope

- Inline origin-lock fold-in (`swatter origin-lock`) — separate design.
- nginx log ingest / non-Apache support.
- CODE_OF_CONDUCT.md — optional, not required for this pass (can add on request).

## Testing / verification

- `make test` and the CI shellcheck command pass unchanged (docs don't touch code
  paths; the install echo and comment edits are shellcheck-clean).
- Re-run the tracked-file leak scan (IPs / hosts / customer domains / key-shaped
  strings) after edits — must stay empty.
- Render-check each new Markdown file.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
