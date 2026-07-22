# Security review: Report API

A minimal Express backend accepting anonymous phishing-site reports
(`backend/server.js`), reviewed against the OWASP Top 10 (2021). This is a
self-review of a demo/reference implementation — not deployed, not
independently audited — written the same way the rest of this project
documents its security posture: honestly, with a "known gaps" section
rather than a claim of completeness.

## Scope

- **In scope:** `POST /api/report`, `GET /api/reports/count`, and the
  middleware stack (CORS, headers, rate limiting, body parsing).
- **Out of scope:** deployment/infrastructure security (this API is not
  hosted anywhere), authentication (the endpoint is intentionally
  anonymous — see rationale below), and the extension's own client-side
  code (covered separately in [../THREAT_MODEL.md](../THREAT_MODEL.md)).

## OWASP Top 10 (2021) walkthrough

### A01: Broken Access Control
No user accounts or privileged actions exist, so classic access-control
bypass (IDOR, privilege escalation) has no surface here. The one control
that matters — CORS — restricts which origins can call the API at all,
enforced via an explicit allowlist rather than a wildcard. **Test coverage:**
`CORS: no Access-Control-Allow-Origin without a configured allowed origin`.

### A02: Cryptographic Failures
No passwords or long-lived secrets are handled by this service. The one
sensitive-adjacent value — the reporter's IP address, needed only for
rate-limit bucketing — is never stored or logged in raw form; it's hashed
with a random salt (`hashIp`) before use, and the hash isn't reversible to
the original IP.

### A03: Injection
- **SQL/NoSQL injection:** structurally not applicable — this
  implementation uses no database and no string-built queries.
- **Reflected/stored injection:** the API never echoes user input back
  into an HTML context (it only returns JSON), and `reason`/`url` are
  never rendered anywhere in this codebase.
- **Input validation:** every field is allowlist-validated (type, length,
  URL scheme) and unexpected fields are rejected outright rather than
  silently dropped or stored.
**Test coverage:** malformed URL, `javascript:`/`file:` scheme rejection,
non-string types, oversized fields, unexpected-field rejection.

### Cross-Site Request Forgery (CSRF)
Flagged by Semgrep (`express-check-csrf-middleware-usage`): no CSRF
middleware (`csurf`/`csrf`) is present. Reviewed and found not applicable
in the traditional sense — CSRF exists to protect session/cookie-based
authenticated state, and this endpoint has neither (see A07 below). The
adjacent real risk — a malicious site silently POSTing forged reports via
a hidden `<form>` in a victim's browser, riding their session-less but
still-unwanted request — is closed structurally: `express.json({ type:
"application/json", strict: true })` parses *only* bodies declared as
`application/json`, and browsers cannot set that Content-Type from a
plain HTML `<form>` element (forms are limited to
`application/x-www-form-urlencoded`, `multipart/form-data`, or
`text/plain`). A forged form submission therefore arrives with an
unparsed body and is rejected by `validateReport()` before any report is
created. **Verified directly** (not just reasoned about) — see
`test-server.js`, the three `CSRF:` tests, which submit forged
form-encoded and `text/plain` bodies and confirm both are rejected with
400, while a genuine `application/json` POST still succeeds. Suppressed
inline in `server.js` on the `const app = express()` line, with this
reasoning in the comment — an earlier pass only documented this finding
here without an inline suppression, so the scanner correctly kept
flagging it on every re-scan; documentation alone doesn't stop a
scanner from re-reporting a pattern match.

### A04: Insecure Design
- The endpoint is intentionally anonymous (no auth) — this is a design
  trade-off, not an oversight: requiring accounts to report a phishing
  site would suppress reporting. The trade-off is compensated for with
  rate limiting and strict validation rather than ignored.
- Bounded resource use: request bodies capped at 8KB, in-memory store
  capped at `MAX_REPORTS`, so no request or accumulation pattern leads to
  unbounded growth.
**Test coverage:** rate-limit threshold test, oversized-payload rejection.

### A05: Security Misconfiguration
- No verbose error responses — a generic 500 is returned to the client on
  any unhandled error, with detail only in server-side logs.
- No default/wildcard CORS.
- Baseline security headers set explicitly (`X-Content-Type-Options`,
  `X-Frame-Options`, a restrictive `Content-Security-Policy` on API
  responses) rather than relying on framework defaults.
**Test coverage:** header-presence tests, 404-without-stack-trace test.

### A06: Vulnerable and Outdated Components
Dependency surface is deliberately minimal: `express` and
`express-rate-limit` only (plus `supertest` as a dev/test-only
dependency). Fewer dependencies means a smaller, more auditable
supply-chain surface. **Known gap:** no automated dependency-vulnerability
scanning (e.g. `npm audit` in CI) is wired up yet for this subfolder — see
Known Gaps below.

### A07: Identification and Authentication Failures
Not applicable — the endpoint is unauthenticated by design (see A04).

### A08: Software and Data Integrity Failures
Strict schema validation rejects any field not explicitly expected,
preventing mass-assignment-style attacks where extra client-supplied
fields (e.g. an `isAdmin`-style flag) get silently absorbed into a stored
record. **Test coverage:** `rejects unexpected/extra fields`.

### A09: Security Logging and Monitoring Failures
Every accept/reject/rate-limit/error event is logged in structured JSON
with a timestamp. Logging deliberately **excludes** raw report content and
raw IP addresses — logging is for operational visibility, not a secondary
data store, avoiding the common failure mode where a security log becomes
its own privacy liability.

### A10: Server-Side Request Forgery (SSRF)
The API stores a reported URL as data — it never fetches, dereferences, or
makes any outbound request to a user-supplied URL. This structurally
eliminates SSRF as a concern for this implementation (an SSRF risk would
only appear if a future version added, e.g., automated screenshotting or
metadata-fetching of reported URLs — flagged here for future reviewers).

## Known gaps (honest, not yet addressed)

- No automated dependency-vulnerability scanning (`npm audit`/Dependabot)
  configured for the `backend/` subfolder specifically.
- No persistent storage — the in-memory store means all reports are lost
  on restart; acceptable for a demo, not for production use.
- No authentication path exists even for the maintainer to review reports
  (the `/api/reports/count` endpoint returns only a count, by design, but
  there's currently no secure way to retrieve report details at all).
- Not deployed or load-tested; rate-limit thresholds are reasonable
  defaults, not tuned against real traffic patterns.
- No third-party penetration test — this is a self-review using the
  project's own test suite as evidence, not an independent audit.

## External SAST validation (Semgrep official rulesets)

The custom ruleset in `../.semgrep/rules.yml` runs in CI, but was written
without access to Semgrep's hosted registry (sandboxed build environment).
Running the *official* community rulesets locally
(`p/javascript p/security-audit p/owasp-top-ten`, 123 rules) surfaced one
real finding in this backend, which was fixed:

- **`javascript.express.security.audit.xss.reflected-origin-header`**
  (CORS middleware) — the original code echoed the request's `Origin`
  header back into the response after an allowlist check, a pattern
  Semgrep flags on sight since reflecting an *arbitrary* origin is a
  common bypass. Fixed to set the header to the fixed, pre-validated
  `ALLOWED_ORIGIN` constant instead of the request-derived value, so the
  response can never echo attacker-controlled input even in principle.
  Covered by a new test: `CORS: response never echoes an attacker-supplied
  Origin value verbatim`.

A second real finding from the same scan, in the extension's
`pages/warning.js` (open-redirect / `javascript:`-URI risk via an
unvalidated `target` query parameter reaching `location.href`), was found
and fixed: `target` is now validated as a well-formed http(s) URL before
any navigation. The scanner's taint tracker still flags the sanitized
line afterward — it correctly traces the value back to the query
parameter but doesn't model the protocol-allowlist branch that makes it
safe, a common SAST limitation. This was verified as a true false
positive by exhaustively testing every dangerous URI scheme
(`javascript:`, `data:`, `file:`, `vbscript:`) against the validation
logic in isolation — all are rejected before ever reaching
`location.href` — then suppressed with an inline `// nosemgrep` comment
carrying that justification.

*Lesson learned on suppression placement:* Semgrep only honors
`// nosemgrep: rule-id` when it is the **literal line immediately
preceding** the flagged code — not merely somewhere within a preceding
comment block. An initial attempt placed the directive as the *first*
line of a multi-line justification comment, several lines above the
actual code; this was verified (via a local reproduction against this
project's own custom rules) to **not** suppress the finding, since
Semgrep only inspects the one line directly above the match. Corrected
by moving the directive to the last comment line, immediately adjacent
to `location.href = safe;`, with the justification prose above it.

A third finding, in `.github/workflows/ci.yml`
(`github-actions-mutable-action-tag`), flagged that both GitHub Actions
in CI were referenced by mutable version tags (`@v4`) rather than
immutable commit SHAs — tags can be repointed by the action owner or an
attacker who compromises that repo, a real attack class that has hit
production CI pipelines (e.g. the tj-actions incident). Fixed by pinning
both actions to their full 40-character commit SHAs, with a version
comment for readability
(`actions/checkout@692973e... # v4.1.7`). A corresponding custom rule
(`unpinned-github-action`) was added to `.semgrep/rules.yml` so any future
unpinned action reference is caught automatically in CI going forward.

A later scan (signed-in, pro ruleset, 365 rules) additionally flagged
`demo/phishing-demo.html` for missing a CSRF token on its form. That file
is *deliberately* built to imitate insecure phishing-page patterns — it
exists so ShadowShield's own detection engine has something real to
catch. "Fixing" it would defeat its purpose, so it's excluded from
scanning via `.semgrepignore` with an explanatory comment rather than
suppressed silently.


## Running the tests yourself

```bash
cd backend
npm install
node test-server.js
```
