# Threat Model

This document analyzes ShadowShield's own attack surface — the extension is a
security tool, so its trust boundaries deserve the same scrutiny it applies to
the web. Uses a simplified STRIDE approach (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege).

## Assets

| Asset | Why it matters |
|---|---|
| User's AI provider API key | Financial/account exposure if leaked |
| Detection verdicts & blocking rules | Integrity failure = user visits real phishing site unwarned |
| Page content read by content script | Privacy-sensitive if exfiltrated |
| Extension's own code execution context | Full compromise if hijacked |

## Trust boundaries

```
Untrusted                    |  Trusted
──────────────────────────────────────────────
Web page content              |  content.js (reads, never trusts)
Threat feed responses          |  background.js (validates before use)
AI provider responses          |  background.js (schema-sanitized)
RDAP responses                 |  background.js (date/shape validated)
Other browser extensions/pages |  background.js (sender.id checked)
```

## STRIDE analysis

### Spoofing
- **Threat:** A malicious web page or extension sends a message to
  `background.js` pretending to be ShadowShield's own content script.
- **Mitigation:** `sender.id !== chrome.runtime.id` check rejects any
  message not originating from this extension (`background.js`).
- **Residual risk:** Low. Chrome enforces extension ID authenticity at the
  platform level; this check adds defense-in-depth.

### Tampering
- **Threat:** A compromised or malicious threat feed injects a rule that
  blocks a legitimate major site (e.g., a poisoned entry for `google.com`).
- **Mitigation:** Per-feed contribution cap (60% of rule budget), explicit
  `PROTECTED_ROOTS` allowlist that refuses whole-domain rules for major
  platforms, hostname/length/scheme validation on every feed entry before
  it becomes a block rule.
- **Threat:** Injected HTML/script via page-derived text (e.g., a phishing
  page's title containing a script tag) rendered in the warning banner.
- **Mitigation:** All UI construction uses `textContent`/DOM APIs, zero
  `innerHTML`, enforced by a CI test (`content banner uses no innerHTML`).
- **Threat:** An external web page constructs a crafted link directly to
  `pages/warning.html` (e.g. `?target=https://attacker-chosen-site.example`)
  and social-engineers a victim into clicking "Proceed anyway", using
  ShadowShield's own warning page as an intermediary redirector to an
  arbitrary destination.
- **Why this page is reachable at all:** `pages/warning.html` is
  necessarily listed as web-accessible from `<all_urls>` in the manifest
  — the live-feed blocking feature redirects any blocked navigation here
  via `declarativeNetRequest`, which only functions if the resource is
  reachable from the full range of origins that might get blocked. This
  can't be narrowed to a fixed origin list without breaking that feature.
- **Mitigation / accepted residual risk:** `target` is strictly validated
  to a well-formed `http`/`https` URL before use (rejects
  `javascript:`/`data:`/`file:`/etc. — see the submit-guard-adjacent fix
  in `pages/warning.js`). Beyond scheme validation, no domain allowlist
  is applied, because the page's entire purpose is to present a
  previously-unknown, just-flagged domain to the user — an allowlist is
  structurally inapplicable to a page whose job is showing *unlisted*
  domains. This mirrors Chrome's own Safe Browsing interstitial, which
  permits navigating to any URL after an explicit warning. Residual risk
  is bounded by requiring active user interaction with a page that
  visually x-rays and highlights the destination domain, not by
  destination filtering. Flagged by Semgrep's pro ruleset
  (`javascript.browser.tainted-redirect.tainted-redirect`); suppressed
  inline with this reasoning after review — see `SECURITY_REVIEW.md`
  cross-reference in `pages/warning.js`.
- **Residual risk:** Low. Exploitation requires (1) a crafted link, (2) a
  victim clicking it, and (3) that same victim disregarding an explicit,
  domain-highlighted warning to click "Proceed anyway" — and even then,
  the outcome (a redirect to attacker-chosen-site.example) is no more
  harmful than the attacker simply linking to that site directly; routing
  through this page adds friction rather than capability for an attacker.
- **Residual risk:** Low for both.

### Repudiation
- **Threat:** N/A in the traditional sense (no multi-user audit trail is a
  design requirement for a local browser extension). Not a primary concern
  for this asset class.

### Information Disclosure
- **Threat:** The AI-analysis feature sends page content to a third-party
  provider without the user's knowledge or consent.
- **Mitigation:** AI analysis only runs if a user-supplied API key exists
  (`runAI` checks for the key before reading any page content); payload is
  limited to URL, title, form destinations, and a 1500-character text
  sample — form values, passwords, and keystrokes are never read.
- **Threat:** API key exposure via Chrome's cross-device sync.
- **Mitigation:** Key is stored in `chrome.storage.local` (device-only),
  not `sync`; a one-time migration evacuates any key from older versions
  and scrubs it from sync storage.
- **Threat:** Key or other secrets leaked via console logging or DOM
  rendering.
- **Mitigation:** Verified no code path logs or renders the API key value
  (manual review; no automated test yet — see Known Gaps).
- **Residual risk:** Low-medium. The AI feature is opt-in and disclosed,
  but relies on the user trusting their chosen third-party provider — this
  is inherent to the feature and disclosed in the README.

### Denial of Service
- **Threat:** A malformed or oversized threat-feed response causes
  excessive memory use or crashes the background worker.
- **Mitigation:** Per-feed and total rule caps (`MAX_FEED_RULES`), URL
  length limits (2000 chars) and hostname length limits (253 chars) in
  `normalizeUrl`, `declarativeNetRequest`'s own rule-count limits.
- **Threat:** A dead/unreachable feed blocks the refresh cycle for the
  other feeds.
- **Mitigation:** Each feed fetch is independently wrapped in try/catch;
  failures are logged as a zero count and never propagate.
- **Residual risk:** Low.

### Elevation of Privilege
- **Threat:** Content-script code (running in the context of every visited
  page) is compromised and used to call privileged extension APIs.
- **Mitigation:** Content scripts only have access to the limited
  `chrome.runtime.sendMessage` API surface; privileged operations
  (`declarativeNetRequest`, `storage`, `scripting`) are confined to the
  background worker, which independently validates every message.
- **Threat:** A malicious/compromised AI provider response is used to
  directly control blocking behavior.
- **Mitigation:** `sanitizeAiVerdict` coerces the AI response into a strict
  `{risk: 0-100, verdict: enum, reason: string}` shape before it can
  influence scoring; malformed responses degrade to `null`/ignored rather
  than executing.
- **Residual risk:** Low.

## Known gaps (honest, not yet addressed)

- No automated test asserting the API key is never written to console or
  DOM (currently verified by manual code review only).
- No Subresource Integrity or pinning on threat-feed connections beyond
  HTTPS transport security — a feed provider with a compromised TLS
  endpoint could theoretically serve malicious rule data within the caps
  above.
- No formal fuzzing of the heuristics engine or RDAP/AI response parsers;
  validation logic is unit-tested against known-bad inputs but not
  property-tested against a wide input space.
- `<all_urls>` host permission is broad by necessity (the extension must
  inspect any page a user visits) — this is an accepted, documented
  trade-off rather than a mitigated risk.

## Reviewing this document

This threat model should be revisited whenever: a new external data source
is added, a new message type crosses the content-script/background
boundary, or a new permission is requested in the manifest.
