// Security-focused tests for the Report API.
// Run: node backend/test-server.js
// These deliberately probe the OWASP-relevant controls, not just the
// happy path — this is closer to a lightweight pentest script than a
// typical unit-test file.

process.env.NODE_ENV = "test"; // enables per-test client simulation in the
                                // rate limiter (see server.js); must be set
                                // before requiring server.js below.

const request = require("supertest");
const app = require("./server.js");

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log("PASS  " + name);
  } catch (e) {
    console.log("FAIL  " + name + "  ->  " + e.message);
    failures++;
  }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || "assertion failed"); }

(async () => {
  // ---- happy path ----
  await check("accepts a valid report", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t1").send({ url: "https://evil-phish.example/login" });
    assert(res.status === 201, "expected 201, got " + res.status);
    assert(res.body.id, "expected an id in the response");
  });

  // ---- A3: Injection / input validation ----
  await check("rejects non-string url", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t2").send({ url: 12345 });
    assert(res.status === 400);
  });

  await check("rejects malformed url", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t3").send({ url: "not a url at all" });
    assert(res.status === 400);
  });

  await check("rejects non-http(s) scheme (javascript:)", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t4").send({ url: "javascript:alert(1)" });
    assert(res.status === 400);
  });

  await check("rejects file:// scheme", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t5").send({ url: "file:///etc/passwd" });
    assert(res.status === 400);
  });

  await check("rejects oversized url (DoS-style payload)", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t6").send({ url: "https://x.com/" + "a".repeat(3000) });
    assert(res.status === 400);
  });

  await check("rejects oversized reason field", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t7").send({ url: "https://x.com", reason: "a".repeat(600) });
    assert(res.status === 400);
  });

  await check("rejects unexpected/extra fields (mass-assignment style)", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t8").send({ url: "https://x.com", isAdmin: true });
    assert(res.status === 400);
  });

  await check("rejects null body", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t9").send(null);
    assert(res.status === 400 || res.status === 500 === false); // must not 500
  });

  await check("rejects array as body instead of object", async () => {
    const res = await request(app).post("/api/report").set("X-Test-Client", "t10").send([1, 2, 3]);
    assert(res.status === 400);
  });

  // ---- A5: Security misconfiguration ----
  await check("sets X-Content-Type-Options: nosniff", async () => {
    const res = await request(app).post("/api/report").send({ url: "https://x.com" });
    assert(res.headers["x-content-type-options"] === "nosniff");
  });

  await check("sets X-Frame-Options: DENY", async () => {
    const res = await request(app).post("/api/report").send({ url: "https://x.com" });
    assert(res.headers["x-frame-options"] === "DENY");
  });

  await check("unknown routes return 404, not a stack trace", async () => {
    const res = await request(app).get("/some/nonexistent/route");
    assert(res.status === 404);
    assert(!JSON.stringify(res.body).toLowerCase().includes("at object"), "leaked a stack trace");
  });

  await check("CORS: no Access-Control-Allow-Origin without a configured allowed origin", async () => {
    const res = await request(app).post("/api/report").set("Origin", "https://attacker.example").send({ url: "https://x.com" });
    assert(!res.headers["access-control-allow-origin"], "CORS header leaked to an unapproved origin");
  });

  await check("CORS: response never echoes an attacker-supplied Origin value verbatim", async () => {
    // Even in the no-ALLOWED_ORIGIN-configured test setup, prove the code
    // path can't be tricked into reflecting whatever Origin the client sent.
    const evil = "https://evil.example.attacker-controlled";
    const res = await request(app).post("/api/report").set("Origin", evil).send({ url: "https://x.com" });
    assert(res.headers["access-control-allow-origin"] !== evil, "response reflected an attacker-controlled origin");
  });

  // ---- A2: Cryptographic failures / data minimization ----
  await check("report count endpoint never echoes raw report contents", async () => {
    const res = await request(app).get("/api/reports/count");
    assert(typeof res.body.count === "number");
    assert(JSON.stringify(res.body).length < 50, "count endpoint is leaking more than a count");
  });

  // ---- A7-adjacent: CSRF (Semgrep: express-check-csrf-middleware-usage) ----
  // No CSRF middleware is used because there's no session/cookie auth to
  // protect (endpoint is intentionally anonymous). These tests prove the
  // structural mitigation instead: browsers cannot submit a plain <form>
  // with Content-Type: application/json, so a forged cross-site form
  // POST never reaches the report-creation logic. Deliberately placed
  // before the rate-limit test below, which exhausts this test IP's quota
  // and would otherwise mask these with 429s instead of the real result.
  await check("CSRF: forged form-urlencoded submission (simulates a malicious <form>) is rejected", async () => {
    const res = await request(app)
      .post("/api/report")
      .set("X-Test-Client", "t11")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("url=https://attacker-forged.example&reason=csrf");
    assert(res.status === 400, "form-encoded body should be rejected, got " + res.status);
  });

  await check("CSRF: forged text/plain submission (another form-allowed content-type) is rejected", async () => {
    const res = await request(app)
      .post("/api/report")
      .set("X-Test-Client", "t12")
      .set("Content-Type", "text/plain")
      .send('{"url":"https://attacker-forged.example"}');
    assert(res.status === 400, "text/plain body should be rejected, got " + res.status);
  });

  await check("CSRF: only a genuine application/json body is ever accepted", async () => {
    const res = await request(app)
      .post("/api/report")
      .set("X-Test-Client", "t13")
      .set("Content-Type", "application/json")
      .send({ url: "https://legit-client.example/report" });
    assert(res.status === 201, "genuine JSON POST should succeed, got " + res.status);
  });

  // ---- A4: Insecure design — rate limiting ----
  // Runs LAST: intentionally exhausts this test client's rate-limit quota,
  // so any test after this one would see 429s regardless of its own logic.
  await check("rate limiter blocks after threshold (11th request in window)", async () => {
    let lastStatus;
    for (let i = 0; i < 11; i++) {
      const res = await request(app).post("/api/report").set("X-Test-Client", "rate-limit-test").send({ url: "https://x.com/" + i });
      lastStatus = res.status;
    }
    assert(lastStatus === 429, "expected 429 after exceeding rate limit, got " + lastStatus);
  });

  console.log(failures ? "\n" + failures + " test(s) FAILED" : "\nAll security tests passed");
  process.exit(failures ? 1 : 0);
})();
