# Security Policy

Swatter manipulates firewall state and runs as root. We take its security
seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

Fixes land on the latest `2.x` line. Older versions are not patched — please
upgrade.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's built-in vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, affected version, and reproduction steps.

This keeps the report private until a fix is available, and means no contact
address has to be published.

### What to expect

- **Acknowledgement:** within 5 business days.
- **Assessment & triage:** we'll confirm the issue and share our planned course
  of action.
- **Fix & disclosure:** coordinated once a patch is ready; we'll credit you in
  the changelog unless you prefer to remain anonymous.

There is no paid bug-bounty program — this is a community project — but credit is
gladly given.

## Scope

In scope:

- The `swatter` CLI and `lib/` modules (scoring, classification, allowlisting,
  firewall backends, intel providers, reporting/alerting).
- The swarm hub Worker under `hub/` (token/auth model, feed integrity, rate
  limits) — the fleet trust boundary. A flaw that lets one credential
  impersonate another host, forge fleet corroboration, or poison the shared
  feed is in scope.
- The installer and cron/logrotate units under `install/`.
- Anything that could cause Swatter to block traffic it should allow, **fail to
  fail-closed**, leak configured credentials, or escalate beyond its intended
  root operations.

Out of scope:

- Vulnerabilities in third-party threat-intel feeds or APIs themselves.
- CSF, iptables/ipset, the Cloudflare platform itself (Workers/D1/WAF), or the
  host OS — report those upstream. (The hub *code* in `hub/` is in scope, per
  above.)
- Misconfiguration of a user's own `swatter.conf` (e.g. an over-broad allowlist).

## Good-faith safe harbor

We consider security research conducted in good faith — that respects this
policy, avoids privacy violations and service disruption, and gives us
reasonable time to respond — to be authorized. We will not pursue or support
legal action against researchers acting in good faith.
