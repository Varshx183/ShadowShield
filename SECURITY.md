# Security Policy

## Reporting a vulnerability

If you find a security issue in ShadowShield, please report it privately
rather than opening a public GitHub issue — this gives time to fix it
before details are public.

**How to report:** Open a [GitHub Security Advisory](../../security/advisories/new)
on this repository (GitHub → Security tab → "Report a vulnerability").
This creates a private report visible only to the maintainer until
resolved.

If you're unable to use Security Advisories, open a regular issue titled
"Security contact requested" with no details — the maintainer will follow
up for a private channel.

## What to include

- A clear description of the issue and its potential impact
- Steps to reproduce, or a proof-of-concept if applicable
- The affected file(s)/version
- Your suggested severity, if you have one (not required)

## What to expect

- Acknowledgment within a reasonable timeframe — this is a personal
  open-source project maintained outside of full-time work, so response
  times are best-effort rather than SLA-backed.
- Credit in the fix's changelog entry and commit message, if you'd like
  it (or full anonymity, your choice).
- No bug bounty program exists for this project.

## Scope

**In scope:**
- The extension's own code (`heuristics.js`, `background.js`, `content.js`,
  `trackers.js`, and everything under `pages/`)
- The CI/build configuration
- Logic errors that weaken detection or allow bypass of the security
  controls documented in [THREAT_MODEL.md](THREAT_MODEL.md)

**Out of scope:**
- Vulnerabilities in third-party threat feeds (OpenPhish, URLhaus,
  Phishing.Database) — report those to the respective projects
- Vulnerabilities in the user's chosen AI provider (Anthropic, OpenAI,
  Google, or any custom endpoint) — report those to the provider
- Social engineering, physical access, or attacks requiring a compromised
  browser/OS (outside this project's threat model)

## Disclosure philosophy

This project favors transparency: verdicts, detection signals, and the
codebase itself are all designed to be auditable rather than hidden.
Vulnerability reports follow the same spirit — once a fix ships, a summary
of the issue and remediation will typically be documented in
[CHANGELOG.md](CHANGELOG.md), consistent with how other hardening work in
this project has been recorded.
