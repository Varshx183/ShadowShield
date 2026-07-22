// ShadowShield v2.2 service worker.
// Feed subsystem: three sources, full-URL matching, 45-minute refresh,
// network-layer blocking via declarativeNetRequest. Plus session-persistent
// state, badge, auto-AI analysis, stats.

const tabResults = new Map();        // tabId -> latest result (memory cache)
const sessionBypass = new Set();     // hostnames the user chose to proceed to
const aiCache = new Map();           // hostname -> AI verdict cache
const AI_CACHE_TTL = 6 * 60 * 60 * 1000;

// ------------------------------------------------------------- feed config

const FEED_REFRESH_MINUTES = 45;     // phishing sites live hours, not days
const MAX_FEED_RULES = 4500;         // stay safely under Chrome's dynamic-rule limits

const FEEDS = [
  { name: "OpenPhish", url: "https://openphish.com/feed.txt", max: 1500 },
  { name: "URLhaus",   url: "https://urlhaus.abuse.ch/downloads/text_online/", max: 2000 },
  // Phishing.Database publishes small, ultra-fresh companion files —
  // ideal at a 45-minute refresh cadence (the full list is 65 MB).
  { name: "PhishDB (today)",     url: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt", max: 800 },
  { name: "PhishDB (last hour)", url: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-last-hour.txt", max: 200 }
];

// Even if a feed has a false positive listing a bare major domain,
// never install a whole-domain block for these.
const PROTECTED_ROOTS = new Set([
  "google.com", "youtube.com", "microsoft.com", "live.com", "office.com",
  "apple.com", "icloud.com", "amazon.com", "facebook.com", "instagram.com",
  "github.com", "cloudflare.com", "wikipedia.org", "paypal.com",
  "dropbox.com", "twitter.com", "x.com", "linkedin.com"
]);

let feedIndex = null;                // Map hostname -> [normalized URL prefixes]

function etld1(hostname) {
  const twoPart = /\.(co|com|org|net|ac|gov|edu)\.[a-z]{2}$/i;
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  if (twoPart.test(hostname)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

// --------------------------------------------------------- feed processing

function normalizeUrl(raw) {
  // Reject absurd input before it ever reaches URL parsing or a block rule.
  if (typeof raw !== "string" || raw.length > 2000) return null;
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const host = u.hostname.toLowerCase();
    // A hostname must have a dot and only sane characters — guards against
    // a poisoned feed line producing a rule that matches far too broadly.
    if (!host.includes(".") || host.length > 253 || !/^[a-z0-9.\-]+$/.test(host)) return null;
    // Match on origin + path; ignore query strings so variants still match.
    return { url: u.origin + u.pathname, host, path: u.pathname };
  } catch { return null; }
}

function parseFeedText(feed, text) {
  const out = [];
  const lines = text.split("\n");
  for (let i = feed.csv ? 1 : 0; i < lines.length && out.length < feed.max; i++) {
    let line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    if (feed.csv) {
      const cols = line.split(",");
      line = (cols[1] || "").replace(/^"|"$/g, "");
    }
    const n = normalizeUrl(line);
    if (!n) continue;
    // Refuse whole-domain rules on protected major platforms.
    if (n.path === "/" && PROTECTED_ROOTS.has(etld1(n.host))) continue;
    out.push({ ...n, source: feed.name });
  }
  return out;
}

async function refreshFeeds() {
  const { feedEnabled = true } = await chrome.storage.sync.get("feedEnabled");
  if (!feedEnabled) {
    await clearFeedRules();
    feedIndex = new Map();
    await chrome.storage.local.set({ feedUrls: [], feedMeta: { updated: Date.now(), counts: {}, total: 0 } });
    return;
  }

  const collected = [];
  const counts = {};
  // No single feed may contribute more than 60% of the rule budget — a
  // compromised or malfunctioning feed can't flood the block list on its own.
  const PER_FEED_CAP = Math.floor(MAX_FEED_RULES * 0.6);
  for (const feed of FEEDS) {
    try {
      const res = await fetch(feed.url, { cache: "no-store" });
      if (!res.ok) { counts[feed.name] = 0; continue; }
      let entries = parseFeedText(feed, await res.text());
      if (entries.length > PER_FEED_CAP) entries = entries.slice(0, PER_FEED_CAP);
      counts[feed.name] = entries.length;
      collected.push(...entries);
    } catch { counts[feed.name] = 0; }  // a dead feed never breaks the others
  }

  const seen = new Set();
  const final = [];
  for (const e of collected) {
    if (seen.has(e.url)) continue;
    seen.add(e.url);
    final.push(e);
    if (final.length >= MAX_FEED_RULES) break;
  }

  await installFeedRules(final);
  buildIndex(final);
  await chrome.storage.local.set({
    feedUrls: final,
    feedMeta: { updated: Date.now(), counts, total: final.length }
  });
}

// ----------------------------------------- network-layer blocking (DNR)
// Rules are enforced by the browser's network stack itself: the request to a
// listed URL never leaves the machine, and blocking works even while this
// service worker is asleep. Each rule redirects straight to our warning page
// with the details baked in.

function sanitizeForFilter(path) {
  // *, ^ and | are urlFilter metacharacters — cut the path at the first one.
  const m = path.match(/[*^|]/);
  return m ? path.slice(0, m.index) : path;
}

function warningPath(entry) {
  const signals = JSON.stringify([
    { label: "This exact address is on the " + entry.source + " feed of confirmed active scam sites" }
  ]);
  return "/pages/warning.html?target=" + encodeURIComponent(entry.url)
    + "&score=95&signals=" + encodeURIComponent(signals);
}

async function installFeedRules(entries) {
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const addRules = entries.map((e, i) => ({
      id: i + 1,
      priority: 1,
      action: { type: "redirect", redirect: { extensionPath: warningPath(e) } },
      condition: {
        urlFilter: "||" + e.host + sanitizeForFilter(e.path),
        resourceTypes: ["main_frame"]
      }
    }));
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map(r => r.id),
      addRules
    });
  } catch (e) {
    // If rule installation fails we still have the webNavigation fallback.
    console.warn("ShadowShield: feed rule install failed", e);
  }
}

async function clearFeedRules() {
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map(r => r.id), addRules: []
    });
  } catch {}
}

// ------------------------------------------------ fallback + fast lookup

function buildIndex(entries) {
  feedIndex = new Map();
  for (const e of entries) {
    if (!feedIndex.has(e.host)) feedIndex.set(e.host, []);
    feedIndex.get(e.host).push(e.url);
  }
}

async function getIndex() {
  if (feedIndex) return feedIndex;
  const { feedUrls = [] } = await chrome.storage.local.get("feedUrls");
  buildIndex(feedUrls);
  return feedIndex;
}

// Belt-and-braces: also watch navigations, for stats and in case DNR
// installation ever failed.
chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0) return;
  let u;
  try { u = new URL(details.url); } catch { return; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return;
  if (await isBypassed(u.hostname)) return;

  const idx = await getIndex();
  const prefixes = idx.get(u.hostname.toLowerCase());
  if (!prefixes) return;
  const norm = u.origin + u.pathname;
  const hit = prefixes.find(p => norm.startsWith(p));
  if (!hit) return;

  const signals = [{ id: "live-feed", weight: 95, label: "This exact address is on a live feed of confirmed active scam sites" }];
  redirectToWarning(details.tabId, details.url, 95, signals);
  storeResult(details.tabId, { url: details.url, hostname: u.hostname, score: 95, verdict: "danger", signals });
  bumpStat("blocked", "scanned");
});

// ----------------------------------------------------------- scheduling

chrome.runtime.onInstalled.addListener(setupFeed);
chrome.runtime.onStartup.addListener(setupFeed);
chrome.alarms.onAlarm.addListener(a => { if (a.name === "pg-feed") refreshFeeds(); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "sync" && changes.feedEnabled) refreshFeeds();
});

function setupFeed() {
  chrome.alarms.create("pg-feed", { periodInMinutes: FEED_REFRESH_MINUTES });
  refreshFeeds();
  migrateSecrets();
}

// One-time: relocate any API key previously kept in synced storage into
// local-only storage, then scrub it from sync.
async function migrateSecrets() {
  try {
    const { apiKey } = await chrome.storage.sync.get("apiKey");
    if (apiKey) {
      await chrome.storage.local.set({ apiKey });
      await chrome.storage.sync.remove("apiKey");
    }
  } catch {}
}

// ------------------------------------------- session-persistent state
// MV3 service workers are shut down when idle; mirror state to
// chrome.storage.session so the popup stays accurate across restarts.

async function getResult(tabId) {
  if (tabResults.has(tabId)) return tabResults.get(tabId);
  const key = "result-" + tabId;
  const stored = await chrome.storage.session.get(key);
  if (stored[key]) tabResults.set(tabId, stored[key]);
  return stored[key] || null;
}

function storeResult(tabId, result) {
  tabResults.set(tabId, result);
  chrome.storage.session.set({ ["result-" + tabId]: result }).catch(() => {});
}

async function isBypassed(hostname) {
  if (sessionBypass.has(hostname)) return true;
  const { bypass = [] } = await chrome.storage.session.get("bypass");
  for (const h of bypass) sessionBypass.add(h);
  return sessionBypass.has(hostname);
}

async function addBypass(hostname) {
  sessionBypass.add(hostname);
  chrome.storage.session.set({ bypass: [...sessionBypass] }).catch(() => {});
  // Session-scoped allow rule outranks the feed's redirect rules, so
  // "Proceed anyway" actually works; cleared automatically on restart.
  try {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const id = rules.reduce((m, r) => Math.max(m, r.id), 0) + 1;
    await chrome.declarativeNetRequest.updateSessionRules({
      addRules: [{
        id, priority: 100,
        action: { type: "allow" },
        condition: { urlFilter: "||" + hostname + "/", resourceTypes: ["main_frame"] }
      }]
    });
  } catch {}
}

// ------------------------------------------------------------- messaging

const BADGE = {
  safe:    { text: "OK", color: "#1F9D6B" },
  caution: { text: "?",  color: "#C97F0A" },
  danger:  { text: "!",  color: "#D6303F" }
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only trust messages originating from this extension's own content scripts
  // and pages — never from an arbitrary website or another extension.
  if (sender.id !== chrome.runtime.id) return false;
  if (!msg || typeof msg.type !== "string") return false;

  if (msg.type === "PG_RESULT" && sender.tab?.id != null) {
    handleResult(msg, sender.tab.id);
  }
  if (msg.type === "PG_GET_RESULT") {
    getResult(msg.tabId).then(sendResponse).catch(() => sendResponse(null));
    return true;
  }
  if (msg.type === "PG_PROCEED") {
    addBypass(msg.hostname).finally(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "PG_DOMAIN_AGE") {
    getDomainAge(msg.domain).then(sendResponse).catch(() => sendResponse({ registered: null }));
    return true;
  }
  if (msg.type === "PG_AI_ANALYZE") {
    runAI(msg.tabId, { force: true }).then(sendResponse).catch(e => sendResponse({ error: String(e) }));
    return true;
  }
  return false;
});

async function handleResult(result, tabId) {
  storeResult(tabId, result);
  setBadge(tabId, result.verdict);
  bumpStat("scanned");

  if (result.verdict === "danger" && !(await isBypassed(result.hostname))) {
    redirectToWarning(tabId, result.url, result.score, result.signals.slice(0, 8));
    bumpStat("blocked");
    return;
  }
  if (result.verdict === "caution") bumpStat("flagged");

  const { autoAI = true } = await chrome.storage.sync.get(["autoAI"]);
  const { apiKey = "" } = await chrome.storage.local.get("apiKey");
  if (apiKey && autoAI && result.score >= 20 && result.verdict !== "danger") {
    const ai = await runAI(tabId);
    if (ai && !ai.error) {
      const blended = { ...result, ai, score: Math.max(result.score, ai.risk || 0) };
      blended.verdict = blended.score >= 60 ? "danger" : blended.score >= 30 ? "caution" : "safe";
      storeResult(tabId, blended);
      setBadge(tabId, blended.verdict);
      if (blended.verdict === "danger" && !(await isBypassed(result.hostname))) {
        const signals = [...result.signals, { id: "ai", weight: ai.risk, label: "AI analysis: " + ai.reason }];
        redirectToWarning(tabId, result.url, blended.score, signals.slice(0, 8));
        bumpStat("blocked");
      }
    }
  }
}

function setBadge(tabId, verdict) {
  const b = BADGE[verdict] || BADGE.safe;
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

function redirectToWarning(tabId, url, score, signals) {
  const warningUrl = chrome.runtime.getURL("pages/warning.html")
    + "?target=" + encodeURIComponent(url)
    + "&score=" + score
    + "&signals=" + encodeURIComponent(JSON.stringify(signals));
  chrome.tabs.update(tabId, { url: warningUrl }).catch(() => {});
}

chrome.tabs.onRemoved.addListener(tabId => {
  tabResults.delete(tabId);
  chrome.storage.session.remove("result-" + tabId).catch(() => {});
});

let statsChain = Promise.resolve();
function bumpStat(...keys) {
  // Serialized read-modify-write: concurrent bumps (e.g. "blocked" +
  // "scanned" for the same navigation) can no longer overwrite each other.
  statsChain = statsChain.then(async () => {
    const stats = (await chrome.storage.local.get("stats")).stats || { scanned: 0, flagged: 0, blocked: 0 };
    for (const k of keys) stats[k] = (stats[k] || 0) + 1;
    await chrome.storage.local.set({ stats });
  }).catch(() => {});
  return statsChain;
}

// ---------------------------------------------------------- domain age
// RDAP is the registries' own free lookup protocol; rdap.org routes each
// domain to the right registry. Most phishing domains are days old, so
// registration date is one of the strongest available signals.

function parseRdapRegistration(data) {
  if (!data || !Array.isArray(data.events)) return null;
  const ev = data.events.find(e => e && e.eventAction === "registration");
  const date = ev && typeof ev.eventDate === "string" ? ev.eventDate : null;
  if (!date) return null;
  // Reject unparseable or absurd dates (future, or before the web existed).
  const t = new Date(date).getTime();
  if (!Number.isFinite(t) || t > Date.now() + 864e5 || t < 315532800000) return null;
  return date;
}

const RDAP_CACHE_TTL = 7 * 24 * 60 * 60 * 1000;

// The AI response crosses a trust boundary — never feed it into scoring or
// UI without coercing it into a known-safe shape.
function sanitizeAiVerdict(raw) {
  if (!raw || typeof raw !== "object") return null;
  let risk = Number(raw.risk);
  if (!Number.isFinite(risk)) risk = 0;
  risk = Math.max(0, Math.min(100, Math.round(risk)));
  const verdict = ["safe", "caution", "danger"].includes(raw.verdict) ? raw.verdict
    : risk >= 60 ? "danger" : risk >= 30 ? "caution" : "safe";
  let reason = typeof raw.reason === "string" ? raw.reason.slice(0, 300) : "";
  return { risk, verdict, reason };
}

async function getDomainAge(domain) {
  if (!domain || /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return { registered: null };
  const key = "rdap-" + domain;
  const cached = (await chrome.storage.local.get(key))[key];
  if (cached && Date.now() - cached.ts < RDAP_CACHE_TTL) return cached;

  const info = { registered: null, ts: Date.now() };
  try {
    const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), {
      headers: { "Accept": "application/rdap+json" }
    });
    if (res.ok) info.registered = parseRdapRegistration(await res.json());
  } catch { /* registry unreachable — cache the miss briefly too */ }
  await chrome.storage.local.set({ [key]: info });
  return info;
}

// ------------------------------------------------------------- AI layer
// Sends URL, title, form destinations and a short visible-text sample.
// Never reads form values, passwords, or keystrokes.

async function runAI(tabId, { force = false } = {}) {
  const { aiProvider = "anthropic", aiBaseUrl = "", aiModel = "" } =
    await chrome.storage.sync.get(["aiProvider", "aiBaseUrl", "aiModel"]);
  const { apiKey } = await chrome.storage.local.get("apiKey");
  if (!apiKey) return { error: "No API key set. Add one in ShadowShield settings." };

  const result = tabResults.get(tabId);
  const host = result?.hostname;
  if (host && !force) {
    const cached = aiCache.get(host);
    if (cached && Date.now() - cached.ts < AI_CACHE_TTL) return cached;
  }

  let payload;
  try {
    const [{ result: collected }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => ({
        url: location.href,
        title: document.title,
        hasPassword: !!document.querySelector('input[type="password"]'),
        formHosts: [...document.querySelectorAll("form")]
          .map(f => { try { return new URL(f.action || location.href, location.href).hostname; } catch { return null; } })
          .filter(Boolean),
        textSample: (document.body?.innerText || "").slice(0, 1500)
      })
    });
    payload = collected;
  } catch {
    return { error: "Couldn't read this page." };
  }

  const prompt = `You are a phishing-detection analyst. Assess whether this web page is likely a phishing/scam page.

URL: ${payload.url}
Title: ${payload.title}
Login form present: ${payload.hasPassword}
Form action hosts: ${payload.formHosts.join(", ") || "none"}
Local heuristic signals: ${(result?.signals || []).map(s => s.label).join("; ") || "none"}
Visible text sample (truncated):
${payload.textSample}

Respond ONLY with JSON: {"risk": <0-100>, "verdict": "safe"|"caution"|"danger", "reason": "<one sentence>"}`;

  try {
    const text = await callProvider(aiProvider, apiKey, prompt, { baseUrl: aiBaseUrl, model: aiModel });
    const parsed = sanitizeAiVerdict(JSON.parse(text.replace(/```json|```/g, "").trim()));
    if (!parsed) return { error: "AI returned an unexpected response" };
    parsed.ts = Date.now();
    if (host) aiCache.set(host, parsed);
    return parsed;
  } catch (e) {
    return { error: "AI analysis failed: " + e.message };
  }
}

// One cheap, fast model per provider — the task is simple classification.
//
// Only three named, fixed endpoints are supported. An earlier version also
// accepted a user-supplied base URL (any OpenAI-compatible service, incl. a
// local Ollama). That was removed deliberately: sending page content to an
// arbitrary user-specified endpoint is indistinguishable, from the outside,
// from a data-exfiltration or remote-code vector, and it is the single
// feature most likely to fail Chrome Web Store review. Every destination the
// extension can now reach is a hardcoded constant below.
async function callProvider(provider, apiKey, prompt, extra = {}) {
  // OpenAI and every OpenAI-compatible service share one code path — that's
  // what lets ShadowShield work with essentially any AI provider, including
  // a model running locally via Ollama.
  if (provider === "openai" || provider === "custom") {
    let base = "https://api.openai.com/v1";
    let model = "gpt-4o-mini";
    if (provider === "custom") {
      base = (extra.baseUrl || "").replace(/\/+$/, "");
      model = extra.model || "";
      if (!base) throw new Error("Set the provider's base URL in ShadowShield settings");
      if (!model) throw new Error("Set a model name in ShadowShield settings");
    }
    const res = await fetch(base + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + apiKey },
      body: JSON.stringify({
        model,
        max_tokens: 300,
        messages: [{ role: "user", content: prompt }]
      })
    });
    if (!res.ok) throw new Error("AI request failed (" + res.status + ")");
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  }

  if (provider === "gemini") {
    const res = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + encodeURIComponent(apiKey),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
      }
    );
    if (!res.ok) throw new Error("Gemini request failed (" + res.status + ")");
    const data = await res.json();
    return data.candidates?.[0]?.content?.parts?.map(p => p.text).join("") || "";
  }

  // default: anthropic
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
      "anthropic-dangerous-direct-browser-access": "true"
    },
    body: JSON.stringify({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 300,
      messages: [{ role: "user", content: prompt }]
    })
  });
  if (!res.ok) throw new Error("Anthropic request failed (" + res.status + ")");
  const data = await res.json();
  return (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
}
