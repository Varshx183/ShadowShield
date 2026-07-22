# ShadowShield Benchmark

A reproducible measurement of the **URL-analysis layer** of the heuristics engine.

## Run it

```bash
node benchmark/run-benchmark.js benchmark/sample-phishing.txt benchmark/sample-legit.txt
```

Or supply your own lists (one URL per line): a phishing set and a legitimate set.

## What it measures — and what it does NOT

This harness runs **only** `heuristics.js` URL analysis on a bare URL string. It deliberately does **not** exercise:

- page-content signals (credential forms, brand-name-plus-password mismatch, urgency language) — the strongest detectors, requiring a live DOM
- the live threat feeds (which block known phishing outright)
- the AI second opinion
- the submit guard

Because those layers are where most of ShadowShield's protection lives, **real-world detection is substantially higher than this benchmark's number.** This measures the weakest layer in isolation, on purpose, as a lower bound and a tuning tool.

## Honest baseline (300 live phishing URLs + 300 legitimate sites)

| Metric | Result | Notes |
|---|---|---|
| URL-layer detection | low | Most phishing now uses HTTPS and clean/compromised domains invisible to URL-only inspection; page-content signals (untested here) carry detection |
| False-positive rate | ~3% | After adding legitimate infrastructure/CDN domains to the trusted set |

### What the benchmark surfaced

1. **Fixed:** legitimate infrastructure domains containing brand names (`googleapis.com`, `amazonaws.com`, `googletagmanager.com`) were false-flagged; now trusted.
2. **Known limitation:** regional TLDs (`google.co.in`, `google.com.tr`) aren't recognized as their parent brand — the approximate eTLD+1 logic needs the real public suffix list (on the roadmap).
3. **Confirmed by design:** URL-only analysis is the weak layer; the extension's strength is the page-content, feed, and AI layers this harness can't reach.

The value of publishing this is honesty: a real, reproducible lower-bound number and a visible tuning roadmap, rather than a marketing claim.


## Note on the bundled sample files

`sample-phishing.txt` and `sample-legit.txt` are small (300 lines each),
included only so the benchmark runs out-of-the-box. Numbers from such a small
sample are noisy and NOT representative — expect inflated false-positive rates.
For a real measurement, point the script at full datasets (e.g. Phishing.Database
active links, and the CrUX top-1M list); see RESULTS.md for the real figures.
