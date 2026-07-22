# Contributing to ShadowShield

Thanks for helping make browsing safer. The easiest high-impact contributions:

- **Grow the brand database** — add commonly impersonated brands to `BRANDS`
  in `heuristics.js` (brand keyword + official domains).
- **Grow the tracker database** — add tracker domains to `PG_TRACKERS`
  in `trackers.js` with an accurate category.
- **Report false positives/negatives** — open an issue with the URL pattern
  (never post live credentials or personal data).

## Ground rules

- Detection must be explainable: every signal has a human-readable label.
- Never add a signal an attacker can trivially forge to *lower* a score.
- All scanning stays local; no data leaves the browser except the optional,
  user-keyed AI analysis.
- Run `node tests/run-tests.js` before opening a PR. CI runs it on every push.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/),
enforced indirectly by [semantic-release](https://semantic-release.gitbook.io/)
(see the "Releases & versioning" section in the README) — commit messages on
`main` directly determine the next version number, so they matter beyond
just readability. Common prefixes: `fix:`, `feat:`, `docs:`, `test:`,
`chore:`, `refactor:`, `ci:`. Add `BREAKING CHANGE:` in the commit body (or
`!` after the type) for a breaking change.

## Dev setup

Load the folder unpacked via `chrome://extensions` (Developer mode).
The heuristics engine is plain JavaScript — testable with Node, no build step.
