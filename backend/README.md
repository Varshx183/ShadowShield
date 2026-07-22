# ShadowShield Report API (reference implementation)

A minimal Express backend demonstrating the "report this site" feature
concept, built primarily as a self-contained security exercise — see
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the full OWASP Top 10
walkthrough and [test-server.js](test-server.js) for the security test
suite that exercises it.

**Not deployed.** This is reference/demo code, run locally.

## Run it

```bash
npm install
node server.js          # starts on :3000
node test-server.js     # runs the security test suite
```

## Endpoints

- `POST /api/report` — submit `{ "url": "...", "reason": "..." (optional) }`
- `GET /api/reports/count` — returns `{ "count": N }`
