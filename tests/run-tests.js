// ShadowShield test suite — run with: node tests/run-tests.js
const path = require("path");
const fs = require("fs");
const root = path.join(__dirname, "..");

let failures = 0;
function check(name, cond) {
  console.log((cond ? "PASS" : "FAIL") + "  " + name);
  if (!cond) failures++;
}

// ---- heuristics engine ----
const PG = require(path.join(root, "heuristics.js"));

let r = PG.analyzeUrl("https://paypa1-secure-login.top/verify");
check("lookalike domain scores danger", PG.verdict(PG.score(r.signals)) === "danger");

r = PG.analyzeUrl("https://github.com/some/repo");
check("trusted domain skipped", r.trusted === true);

r = PG.analyzeUrl("https://xn--pypal-4ve.com/signin");
check("punycode flagged", r.signals.some(s => s.id === "punycode"));
check("punycode prefix not counted as hyphens", !r.signals.some(s => s.id === "many-hyphens"));

r = PG.analyzeUrl("https://paypal.com.account-check.icu/login");
check("brand-in-subdomain flagged", r.signals.some(s => s.id === "brand-in-subdomain"));

r = PG.analyzeUrl("https://my-cool-blog-site-thing.com");
check("benign hyphenated blog stays safe", PG.verdict(PG.score(r.signals)) === "safe");

// ---- feed parsing (background.js pure functions) ----
const noop = () => {}; const ev = { addListener: noop };
global.chrome = {
  runtime: { onInstalled: ev, onStartup: ev, onMessage: ev, getURL: p => "x" + p },
  alarms: { onAlarm: ev, create: noop },
  webNavigation: { onBeforeNavigate: ev },
  tabs: { onRemoved: ev, update: noop },
  storage: { onChanged: ev, session: {}, local: {}, sync: {} },
  declarativeNetRequest: {}, action: {}, scripting: {}
};
// This eval() loads only this project's own trusted, version-controlled
// source file (background.js — no module.exports, so this is the
// established way to bring its pure functions into test scope) — never
// user input, network responses, or any externally-influenced string.
// Not a code-injection risk; the CSP prohibiting eval() applies to the
// shipped extension runtime, not this Node-only test harness.
// nosemgrep
eval(fs.readFileSync(path.join(root, "background.js"), "utf8"));

let f = parseFeedText({ name: "T", max: 10 }, "https://evil.top/x\n# comment\nnot-a-url\nftp://skip/x\n");
check("feed: parses URLs, skips comments/garbage/ftp", f.length === 1 && f[0].url === "https://evil.top/x");

f = parseFeedText({ name: "T", max: 10 }, "https://google.com/\nhttps://sites.google.com/view/evil\n");
check("feed: protected-root guard", f.length === 1 && f[0].host === "sites.google.com");

f = parseFeedText({ name: "T", max: 10 }, "https://bad.site/steal?victim=a\n");
check("feed: query strings stripped", f[0].url === "https://bad.site/steal");

check("feed: urlFilter metacharacters sanitized", sanitizeForFilter("/p/a*b") === "/p/a");

// ---- tracker detection ----
global.performance = { getEntriesByType: () => [
  { name: "https://www.google-analytics.com/analytics.js" },
  { name: "https://notgoogle-analytics.example/x.js" }
]};
// Same rationale as the background.js eval() above — loads only this
// project's own trusted source file to bring its functions into scope.
// nosemgrep
eval(fs.readFileSync(path.join(root, "trackers.js"), "utf8"));
const fakeDoc = { querySelectorAll: () => [], location: { href: "https://example.com" } };
const tr = pgDetectTrackers(fakeDoc);
check("trackers: exact/subdomain match only", tr.length === 1 && tr[0].name === "Google Analytics");

// ---- RDAP parsing ----
check("rdap: extracts registration date", parseRdapRegistration({
  events: [{ eventAction: "expiration", eventDate: "2027-01-01" },
           { eventAction: "registration", eventDate: "2026-06-30T00:00:00Z" }]
}) === "2026-06-30T00:00:00Z");
check("rdap: null on missing events", parseRdapRegistration({}) === null);

// ---- security hardening ----
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
check("CSP is defined for extension pages",
  !!manifest.content_security_policy?.extension_pages);
check("CSP forbids remote scripts (script-src self only)",
  /script-src 'self'/.test(manifest.content_security_policy.extension_pages) &&
  !/script-src[^;]*https?:/.test(manifest.content_security_policy.extension_pages));
check("CSP blocks object/embed",
  /object-src 'self'/.test(manifest.content_security_policy.extension_pages));
check("no eval anywhere in shipped code", (() => {
  for (const f of ["heuristics.js","trackers.js","content.js","background.js","pages/popup.js","pages/options.js","pages/warning.js"]) {
    if (/\beval\s*\(/.test(fs.readFileSync(path.join(root,f),"utf8"))) return false;
  }
  return true;
})());
check("content banner uses no innerHTML",
  !/innerHTML/.test(fs.readFileSync(path.join(root,"content.js"),"utf8")));
check("API key never written to sync storage", (() => {
  // Reads apiKey must come from local; the only permitted sync references are
  // the one-time migration (get + remove) that evacuates a legacy synced key.
  for (const f of ["background.js","pages/options.js","pages/popup.js"]) {
    const src = fs.readFileSync(path.join(root,f),"utf8");
    if (/sync\.set\([^)]*apiKey/.test(src)) return false;              // never SET to sync
    const badGets = (src.match(/sync\.get\([^)]*apiKey/g) || []);
    // allow exactly the migration read in background.js
    if (f === "background.js" && badGets.length > 1) return false;
    if (f !== "background.js" && badGets.length > 0) return false;
  }
  return true;
})());
check("API key is read from local storage", (() => {
  const bg = fs.readFileSync(path.join(root,"background.js"),"utf8");
  return /local\.get\(["']apiKey|local\.get\(\{ apiKey/.test(bg);
})());

// ---- extended signal coverage (URL layer) ----
function fires(url, id) { return PG.analyzeUrl(url).signals.some(s => s.id === id); }
check("free-host signal fires", fires("https://evil.weebly.com/login", "free-host"));
check("kit-file signal fires", fires("https://hacked-xyz.com/verify/login.php", "kit-file"));
check("wp-kit signal fires", fires("https://hacked-xyz.com/wp-admin/login.php", "wp-kit"));
check("dynamic-dns signal fires", fires("https://evil.duckdns.org/x", "dynamic-dns"));
check("keyword-domain signal fires", fires("https://secure-account-verify.com/x", "keyword-domain"));
check("random-subdomain signal fires", fires("https://a8f3kd9xmz4p2wqe.badsite.com/x", "random-subdomain"));
check("random-path signal fires", fires("https://bad.com/x7k2mq9zp4bw3nvh", "random-path"));
check("digit-in-name signal fires", fires("https://bet988v.com/x", "digit-in-name"));
check("collapsed-homoglyph catches padded brand (paypaal)", fires("https://paypaal.com/x", "brand-in-domain"));
check("mild-tld weaker than risky-tld", (() => {
  const mild = PG.analyzeUrl("https://plainsite.xyz/").signals.find(s => s.id === "mild-tld");
  return mild && mild.weight < 15;
})());
check("boundary matcher: 'purchase' does not match brand 'chase'",
  !PG.analyzeUrl("https://purchase-online.com/deals").signals.some(s => s.brand === "chase"));
check("convergence bonus applied for 4+ signals", (() => {
  const many = [{id:"a",weight:10},{id:"b",weight:10},{id:"c",weight:10},{id:"d",weight:10}];
  const few = [{id:"a",weight:10}];
  return PG.score(many) > PG.score(few) + 30 * 0.75 * 0.75 * 0.75; // more than pure diminishing sum
})());

// ---- v2.6.0 hardening: hostile input ----
check("normalizeUrl rejects oversized input", normalizeUrl("http://a.com/" + "x".repeat(3000)) === null);
check("normalizeUrl rejects dotless host", normalizeUrl("https://localhost/x") === null);
check("normalizeUrl rejects non-http scheme", normalizeUrl("javascript:alert(1)") === null);
check("normalizeUrl accepts + lowercases valid host", normalizeUrl("https://EVIL.top/x")?.host === "evil.top");
check("AI verdict: clamps risk to 0-100", sanitizeAiVerdict({ risk: 999, verdict: "danger" }).risk === 100);
check("AI verdict: coerces garbage to safe", (() => { const r = sanitizeAiVerdict({ risk: "x", verdict: "evil" }); return r.risk === 0 && r.verdict === "safe"; })());
check("AI verdict: null on non-object", sanitizeAiVerdict("not json") === null);
check("AI verdict: caps reason length", sanitizeAiVerdict({ risk: 10, reason: "a".repeat(999) }).reason.length === 300);
check("RDAP: rejects future date", parseRdapRegistration({ events: [{ eventAction: "registration", eventDate: "3000-01-01" }] }) === null);
check("RDAP: rejects garbage date", parseRdapRegistration({ events: [{ eventAction: "registration", eventDate: "notadate" }] }) === null);
check("message listener verifies sender.id", /sender\.id !== chrome\.runtime\.id/.test(fs.readFileSync(path.join(root,"background.js"),"utf8")));
check("per-feed cap present", /PER_FEED_CAP/.test(fs.readFileSync(path.join(root,"background.js"),"utf8")));

// ---- Semgrep-found: warning.js open-redirect / javascript: URI (fixed) ----
check("warning.js validates target protocol before navigating (no raw location.href = target)", (() => {
  const src = fs.readFileSync(path.join(root,"pages/warning.js"),"utf8");
  return !/location\.href\s*=\s*target;/.test(src) && /protocol === "http:" \|\| parsed\.protocol === "https:"/.test(src);
})());

console.log(failures ? "\n" + failures + " test(s) FAILED" : "\nAll tests passed");
process.exit(failures ? 1 : 0);
