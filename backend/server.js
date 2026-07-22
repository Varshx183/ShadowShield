// ShadowShield Report API — minimal backend accepting user-submitted
// phishing-site reports. Every design decision here is deliberately
// security-first; see SECURITY_REVIEW.md in this folder for the full
// OWASP Top 10 walkthrough of *why* each control exists.
//
// Scope: this is a demo/reference backend, not deployed. It exists to
// demonstrate secure API design and to give the project a real, self-
// contained pentest surface — see SECURITY_REVIEW.md.

const express = require("express");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

// No CSRF middleware (csurf/csrf) is used: this app has no session or
// cookie-based authentication for CSRF to protect (endpoint is
// intentionally anonymous — see SECURITY_REVIEW.md, "Cross-Site Request
// Forgery"). The adjacent real risk — a forged cross-site <form> POST —
// is closed structurally by express.json({ type: "application/json",
// strict: true }) below, which rejects any body a browser <form> could
// actually submit. Verified directly in test-server.js (three CSRF:
// tests: form-urlencoded rejected, text/plain rejected, genuine JSON
// accepted).
// nosemgrep: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage
const app = express();

// ---------------------------------------------------------------------
// A1: Broken Access Control / A5: Security Misconfiguration
// ---------------------------------------------------------------------
// No wildcard CORS. Only one exact, pre-configured origin (the extension's
// own chrome-extension:// origin, set via env var so it isn't hardcoded to
// one install) may call this API.
//
// Semgrep (javascript.express.security.audit.xss.reflected-origin-header)
// flags any `setHeader("Access-Control-Allow-Origin", <variable>)` on
// sight, since reflecting an *arbitrary* request-supplied origin is a
// common bypass. Here the value is never attacker-influenced end-to-end:
// ALLOWED_ORIGIN is fixed at process start from a trusted env var (not
// from the request), validated once at boot to actually look like an
// origin, and the response header is only ever set to that fixed,
// pre-validated string via a strict `===` match — never to whatever the
// client happened to send.
const ALLOWED_ORIGIN = (() => {
  const v = process.env.ALLOWED_ORIGIN;
  if (!v) return null;
  // Must look like a real origin (scheme://host, optionally with port),
  // not an arbitrary string — catches misconfiguration at boot rather
  // than silently accepting a malformed allowlist value.
  if (!/^[a-z][a-z0-9+.\-]*:\/\/[^/\s]+$/i.test(v)) {
    throw new Error("ALLOWED_ORIGIN is set but is not a valid origin: " + v);
  }
  return v;
})();

app.use((req, res, next) => {
  const requestOrigin = req.headers.origin;
  const isAllowed = ALLOWED_ORIGIN !== null && requestOrigin === ALLOWED_ORIGIN;
  if (isAllowed) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN); // fixed, pre-validated value — never the raw request header
    res.setHeader("Access-Control-Allow-Methods", "POST");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Security headers (A5: Security Misconfiguration). No framework like
// helmet is pulled in for a 3-header set — fewer dependencies, smaller
// supply-chain surface, same effect.
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'");
  next();
});

// A3: Injection — cap body size before parsing to blunt payload-based DoS.
//
// A7 (CSRF, cross-cutting): no CSRF middleware (csurf/csrf) is used
// because there is no session/cookie-based auth for this to protect (see
// A02/A07 in SECURITY_REVIEW.md — the endpoint is intentionally
// anonymous). The remaining CSRF-adjacent risk — a malicious site
// silently POSTing fake reports via a hidden <form> in a victim's
// browser — is closed structurally rather than by a CSRF-token library:
// express.json() with `type: "application/json"` (the default, made
// explicit here) parses ONLY bodies declared as application/json, and
// browsers cannot set that Content-Type from a plain HTML <form> element
// (forms are restricted to application/x-www-form-urlencoded,
// multipart/form-data, or text/plain). A forged form submission therefore
// arrives with an unparsed/empty body and is rejected by validateReport()
// before any report is created. Verified directly in
// test-server.js ("CSRF: forged form-style submission is rejected...").
app.use(express.json({ limit: "8kb", type: "application/json", strict: true }));

// A6/A9: Vulnerable & Outdated Components, Insufficient Logging —
// structured, minimal logging. Deliberately logs NO raw user input and NO
// IP-to-report linkage beyond what's needed for rate limiting, to avoid
// turning a phishing-report log into a privacy liability itself.
function log(event, fields = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

// ---------------------------------------------------------------------
// A4: Insecure Design / A6: Vulnerable and Outdated Components (DoS angle)
// ---------------------------------------------------------------------
// Rate limiting: 10 requests per IP per 10 minutes. A reporting endpoint
// with no auth is inherently abusable (spam, false-report flooding); this
// is the primary control against that, not a nice-to-have.
const reportLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  // In production this always buckets by IP (the express-rate-limit
  // default). In tests only (NODE_ENV=test, set by test-server.js), an
  // X-Test-Client header lets different test cases simulate distinct
  // clients instead of sharing one IP-based bucket and tripping each
  // other's rate limit — inert and ignored outside test runs.
  keyGenerator:
    process.env.NODE_ENV === "test"
      ? (req) => req.headers["x-test-client"] || req.ip
      : undefined,
  message: { error: "Too many reports from this address. Try again later." },
  handler: (req, res, next, options) => {
    log("rate_limit_exceeded", { ip: hashIp(req.ip) });
    res.status(429).json(options.message);
  }
});

// A2: Cryptographic Failures — never store or log raw IP addresses.
// A one-way, salted hash is used only for rate-limit bucketing, so no
// reversible PII is retained anywhere, including in logs.
const IP_SALT = process.env.IP_SALT || crypto.randomBytes(16).toString("hex");
function hashIp(ip) {
  return crypto.createHash("sha256").update(IP_SALT + ip).digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------
// In-memory store. A real deployment would use a database with
// parameterized queries; this demo avoids the dependency, and since
// nothing here is ever interpolated into a query string, SQL/NoSQL
// injection (A3) is structurally not applicable to this implementation.
// ---------------------------------------------------------------------
const reports = [];
const MAX_REPORTS = 10000; // A4: bounded resource use, not unbounded growth

// ---------------------------------------------------------------------
// A3: Injection / A8: Software and Data Integrity Failures
// ---------------------------------------------------------------------
// Strict allowlist-style validation. Reject anything that doesn't parse as
// a well-formed http(s) URL; cap every field length; never trust the
// client-supplied Content-Type beyond what express.json already enforces.
function validateReport(body) {
  const errors = [];
  if (typeof body !== "object" || body === null) {
    return { errors: ["Request body must be a JSON object"] };
  }

  const { url, reason } = body;

  if (typeof url !== "string" || url.length === 0 || url.length > 2000) {
    errors.push("url must be a string between 1 and 2000 characters");
  } else {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        errors.push("url must use http or https");
      }
    } catch {
      errors.push("url is not a valid URL");
    }
  }

  if (reason !== undefined) {
    if (typeof reason !== "string" || reason.length > 500) {
      errors.push("reason must be a string of at most 500 characters");
    }
  }

  // Reject any unexpected fields outright (A8: integrity — no silent
  // absorption of unvalidated extra data into the stored record).
  const allowedKeys = new Set(["url", "reason"]);
  for (const key of Object.keys(body)) {
    if (!allowedKeys.has(key)) errors.push(`unexpected field: ${key}`);
  }

  return { errors, url, reason };
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

app.post("/api/report", reportLimiter, (req, res) => {
  const { errors, url, reason } = validateReport(req.body);
  if (errors.length) {
    log("report_rejected", { reasonCount: errors.length });
    return res.status(400).json({ error: "Invalid report", details: errors });
  }

  if (reports.length >= MAX_REPORTS) {
    log("report_capacity_exceeded");
    return res.status(503).json({ error: "Report queue full, try again later" });
  }

  // A2/A9: store only what's needed; no raw client IP, no user agent,
  // no cookies/session data — this endpoint is intentionally anonymous.
  const record = {
    id: crypto.randomUUID(),
    url,
    reason: reason || null,
    reportedAt: new Date().toISOString()
  };
  reports.push(record);
  log("report_accepted", { id: record.id });

  res.status(201).json({ id: record.id, status: "received" });
});

// Read-only, paginated, capped — prevents a single request from dumping
// the entire dataset (A4: Insecure Design) and never echoes back anything
// beyond what was already validated on the way in (A3: no reflected
// injection surface).
app.get("/api/reports/count", (req, res) => {
  res.json({ count: reports.length });
});

// A5: Security Misconfiguration — explicit 404 and error handlers so stack
// traces / internals are never leaked to the client.
app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.use((err, req, res, next) => {
  log("unhandled_error", { message: err.message });
  res.status(500).json({ error: "Internal server error" });
});

module.exports = app; // exported for tests; only listens when run directly

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => log("server_started", { port: PORT }));
}
