# Chrome Web Store submission

Working notes for submitting ShadowShield. Not part of the extension — this
file is repo-only and is excluded from the store package.

## Build the package

```bash
node scripts/build-store-package.js
# -> dist/shadowshield-store-<version>.zip
```

This builds from an **allowlist** of the 14 files the extension actually runs.
It deliberately excludes `demo/phishing-demo.html` — that file is a working
imitation of a PayPal login form, and shipping it inside the submitted package
would put a credential-harvesting page in front of a reviewer. It belongs in
the repo, not in the product.

The script also cross-checks the allowlist against `manifest.json`: if the
manifest ever declares a script the allowlist doesn't have, the build fails
rather than silently shipping a broken extension.

## Single purpose

Chrome requires one clear purpose. State it as:

> Warning users about phishing, scam, and credential-harvesting websites.

Tracker detection is presented as supporting evidence for that purpose (a page
impersonating a bank while running unrelated trackers is a signal), not as a
second product.

## Permission justifications

Each field below maps to one box in the Web Store dashboard. Every permission
listed is genuinely used by the code — none are speculative.

**`storage`**
Stores the user's settings, their allowlist of trusted sites, local counters
shown in the popup, and — if they opt in to AI analysis — their own API key.
Device-local only; nothing is synced or transmitted.

**`tabs`**
Associates a risk verdict with the tab it was computed for, so the popup and
toolbar badge show the result for the page the user is actually looking at.

**`webNavigation`**
Detects when a navigation begins, so a known-malicious URL can be blocked
before the page loads rather than after the user has already landed on it.

**`scripting`**
Reads the visible text of a page the user has explicitly asked the AI feature
to analyse. Only invoked when the user has opted in with their own API key.

**`alarms`**
Schedules the periodic refresh of the public threat feeds so the blocklist
stays current.

**`declarativeNetRequest`**
Blocks navigations to URLs that appear on public phishing/malware feeds
(OpenPhish, URLhaus, Phishing.Database). Chosen specifically because rules are
matched by the browser itself — the extension never sees the user's browsing
traffic in order to block it.

**Host permission — `<all_urls>`**
A phishing page can be hosted on any domain, so the extension cannot know in
advance which sites it will need to inspect. Access is used solely to run
local phishing analysis on the page the user is currently viewing. No browsing
data is sent to the developer — there is no server. See PRIVACY.md.

**Remote code**
The extension executes no remote code. The Content Security Policy is
`script-src 'self'` with no `unsafe-eval`; there is no `eval()`, no
`new Function()`, and no remotely-loaded script anywhere in the codebase — all
enforced by tests in CI. Network requests fetch **data** only (threat-feed
text, RDAP JSON, and — if the user opts in — a verdict from the AI provider
they chose).

## Data disclosure (dashboard privacy tab)

- **Does the extension collect user data?** Yes — but only in the sense that a
  page's domain may be sent to a public domain registry (RDAP) when that page
  requests credentials, and, if the user opts in with their own API key, page
  text may be sent to the AI provider they selected. Nothing is sent to the
  developer.
- **Not collected:** browsing history, analytics, passwords, form values,
  keystrokes, PII.
- **Not sold, not shared, not used for advertising, not used for training.**
- Privacy policy URL: link to the hosted copy of `PRIVACY.md`.

## Listing assets still needed

- Screenshots: 1280×800 (up to 5). The popup on a flagged site, the warning
  interstitial, and the tracker panel make the strongest three.
- Small promo tile: 440×280.
- The 128×128 icon is already in `icons/`.

## Pre-submission checklist

- [ ] `node scripts/build-store-package.js` runs clean
- [ ] Confirm `demo/` is absent from the built zip
- [ ] Load the built zip unpacked in Chrome and click through popup, options,
      and a real block — the package is a different file set than the repo, so
      test the thing you're actually shipping
- [ ] PRIVACY.md hosted at a public URL, pasted into the dashboard
- [ ] $5 developer registration fee paid
