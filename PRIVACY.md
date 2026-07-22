# Privacy policy

**ShadowShield browser extension**
Last updated: 11 July 2026

## Summary

ShadowShield has no servers, no accounts, and no analytics. The developer
receives **no data from you at all** — not your browsing history, not usage
statistics, not crash reports, nothing.

Detection runs locally inside your browser. Three features make outbound
network requests, all described in full below; two are on by default and one
is strictly opt-in.

## What ShadowShield stores, and where

All of the following is stored **only on your own device**, using Chrome's
local extension storage. None of it is synced to other devices, and none of
it is transmitted anywhere.

- Your settings (which protections are enabled).
- Your allowlist — sites you explicitly marked as trusted.
- Local counters (e.g. how many sites have been flagged), shown in the popup.
- Your AI provider API key, if you choose to enable AI analysis. It is stored
  in device-local storage specifically so that it is never synced to your
  Google account or any other device, and it is only ever sent to the AI
  provider you selected, as that provider's authentication header.

## Network requests ShadowShield makes

### 1. Threat feed downloads (enabled by default)

ShadowShield periodically downloads public lists of known phishing and
malware URLs from OpenPhish, URLhaus, and Phishing.Database. These are
**downloads only** — the request asks for a list, and sends no information
about you or the sites you visit. Comparison against the list happens locally
on your machine.

As with any web request, the feed providers can see the IP address making the
request, as they would for any download.

### 2. Domain-age lookup (enabled by default, limited)

Newly registered domains are a strong phishing signal, so ShadowShield can
check when a domain was registered using RDAP — the domain registries' own
public lookup protocol, via `rdap.org`.

**This sends the domain name of the page you are on to `rdap.org`.** It is
the only default-on feature that transmits anything about the sites you
visit, so it is deliberately limited: the lookup only runs when the page
contains a password field, or the page already scores as suspicious. It does
not run on ordinary browsing. Results are cached so a domain is looked up at
most once per week.

Only the domain is sent (for example `example.com`) — never the full URL,
never the page path, and never page content.

If you would rather this never happen, the domain-age check can be disabled
in the extension's settings.

### 3. AI analysis (off by default — opt-in, requires your own API key)

This feature does nothing unless you supply your own API key for an AI
provider. It is off until you do.

When enabled, and when a page is scored as suspicious, ShadowShield sends the
following to **the AI provider you chose** — Anthropic, OpenAI, or Google.
These are the only three destinations the extension can send this data to;
each is a fixed, hardcoded endpoint in the source code, and there is no way to
point it at any other server:

- the page's URL and title,
- whether the page contains a password field (true or false),
- the hostnames that the page's forms submit to,
- up to 1,500 characters of the page's visible text.

**ShadowShield never reads, stores, or transmits the values you type** — not
passwords, not form contents, not keystrokes. It reads the page's visible text
in order to detect phishing language, not what you enter into it.

Data sent to an AI provider is handled under **that provider's** privacy
policy, not this one. If you would prefer that no page content ever leaves your
machine, simply leave this feature off — it is disabled by default, and the
extension's other three detection layers work without it.

## What ShadowShield never does

- It does not send any data to the developer. There is no ShadowShield server.
- It does not collect analytics, telemetry, or usage tracking.
- It does not record your browsing history.
- It does not read or transmit passwords, form values, or keystrokes.
- It does not sell, share, or monetise any data. There is nothing to sell.
- It does not use your data for advertising or for training any model.

## Why the extension requests broad site access

ShadowShield requests access to all sites (`<all_urls>`) because a phishing
page can be hosted on any domain. To warn you about a page, the extension has
to be able to inspect that page — which means it cannot know in advance which
sites it needs access to. This access is used solely for local phishing
analysis, and is subject to everything stated above.

## Your control

- The AI feature is off unless you enable it with your own key.
- The domain-age lookup can be disabled in settings.
- Removing the extension deletes all locally stored data, including your API
  key.
- The complete source code is public and auditable at
  https://github.com/Varshx183/ShadowShield — every claim on this page can be
  verified against the code.

## Changes

Any material change to this policy will be published in the repository above,
with the change visible in the commit history.

## Contact

Questions about this policy, or about how the extension handles data, can be
raised as an issue at https://github.com/Varshx183/ShadowShield/issues.
