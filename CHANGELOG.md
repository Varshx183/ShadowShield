# Changelog

All notable changes to ShadowShield are documented here. This project uses [Semantic Versioning](https://semver.org/) and releases are generated automatically via [semantic-release](https://semantic-release.gitbook.io/) based on [Conventional Commits](https://www.conventionalcommits.org/).

## 1.0.0 (2026-07-22)

### Features

* restore any-provider AI support and add CI/release workflows ([dd691d8](https://github.com/Varshx183/ShadowShield/commit/dd691d8fed04a9d975b86a9f551b5afccd6fb9eb))

# Changelog

All notable changes to ShadowShield are documented here. This project uses
[Semantic Versioning](https://semver.org/) and releases are generated
automatically via [semantic-release](https://semantic-release.gitbook.io/)
based on [Conventional Commits](https://www.conventionalcommits.org/) —
entries above the v1.0.0 line (once future releases land) are generated
automatically from commit history; v1.0.0 below is written by hand.

## v1.0.0 — Initial public release

The first public release of ShadowShield: an AI-assisted, real-time
browser extension for phishing, cloned-login-page, lookalike-domain, and
scam-site protection.

### Detection
- Layered heuristic engine — ~30 explainable, weighted URL and DOM
  signals (lookalike-domain and homoglyph detection, punycode, free-host
  and random-subdomain/path detection, credential-form analysis, urgency
  language) across ~85 commonly-impersonated brand patterns.
- Live threat feeds (OpenPhish, URLhaus, Phishing.Database), merged and
  refreshed automatically, enforcing network-layer blocking via
  `declarativeNetRequest` before a flagged page ever loads.
- Credential submit guard — pauses password submissions to cross-domain,
  unencrypted, or newly-registered destinations and asks first.
- Domain-age signal via RDAP lookups (cached).
- Tracker detection — reveals ~45 analytics, advertising, and
  session-recording services on any page.
- Optional AI second opinion — bring your own key for Claude, GPT, or
  Gemini.
- Measured, reproducible benchmark of the URL-heuristics layer against
  real phishing and real top-site data — see `benchmark/RESULTS.md`.

### Security engineering
- `THREAT_MODEL.md` — STRIDE analysis of the extension's own attack
  surface.
- `SECURITY.md` — vulnerability disclosure policy.
- Strict Content Security Policy, DOM-only UI (no `innerHTML`), API keys
  isolated to local (never synced) storage.
- SAST scanning (Semgrep, project-specific ruleset) enforced in CI as a
  merge-blocking gate.
- A reference "report this site" backend (`backend/`) with a full OWASP
  Top 10 self-review and its own dedicated security test suite.
- Automated test suite covering the detection engine, feed handling,
  tracker matching, and hardening guarantees, enforced in CI on every
  push and pull request.

### Project infrastructure
- Automated, semantic-version releases via `semantic-release`, driven by
  Conventional Commits — see [Releases](../../releases) for the full
  history of everything after this initial version.
