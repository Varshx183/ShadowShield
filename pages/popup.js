const COLORS = { safe: "#4FC28A", caution: "#F0A93B", danger: "#F2565F" };
// Verdict is never signalled by colour alone: each state also swaps in a
// distinct glyph shape (circle / triangle / octagon) beside the word, so the
// reading survives colour-vision deficiency and greyscale rendering.
const GLYPHS = { safe: "ico-safe", caution: "ico-caution", danger: "ico-danger" };
const CIRC = 307.9;  // 2 * pi * r, r = 49

function setGlyph(verdict) {
  for (const id of ["ico-safe", "ico-caution", "ico-danger"]) {
    document.getElementById(id).hidden = true;
  }
  const show = GLYPHS[verdict];
  if (show) document.getElementById(show).hidden = false;
}

let currentTab = null;
let lastVerdict = null;

// Attach all handlers immediately — nothing async can prevent this.
document.getElementById("open-options").addEventListener("click", e => {
  e.preventDefault(); chrome.runtime.openOptionsPage();
});
document.getElementById("trust-btn").addEventListener("click", trustSite);
document.getElementById("ai-btn").addEventListener("click", askAI);
document.getElementById("key-note-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());

// Counters update in real time while the popup is open.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.stats?.newValue) {
    document.getElementById("s-scanned").textContent = changes.stats.newValue.scanned || 0;
    document.getElementById("s-blocked").textContent = changes.stats.newValue.blocked || 0;
  }
});

init();

async function safeSend(msg) {
  try { return await chrome.runtime.sendMessage(msg); } catch { return null; }
}

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    // Buttons work on any regular website, scanned or not.
    const scannable = /^https?:/.test(tab?.url || "");
    document.getElementById("ai-btn").disabled = !scannable;
    document.getElementById("trust-btn").disabled = !scannable;
    if (!scannable) {
      const why = "Unavailable on browser pages — open a regular website";
      document.getElementById("ai-btn").title = why;
      document.getElementById("trust-btn").title = why;
    }

    const result = await safeSend({ type: "PG_GET_RESULT", tabId: tab.id });
    render(result, tab, scannable);
  } catch { /* keep buttons alive even if state loading fails */ }

  try {
    const s = await chrome.storage.sync.get({ enabled: true, feedEnabled: true });
    bindToggle("t-enabled", "enabled", s.enabled);
    bindToggle("t-feed", "feedEnabled", s.feedEnabled);
  } catch {}

  try {
    const { stats = {} } = await chrome.storage.local.get("stats");
    document.getElementById("s-scanned").textContent = stats.scanned || 0;
    document.getElementById("s-blocked").textContent = stats.blocked || 0;
  } catch {}
}

function bindToggle(elId, key, value) {
  const el = document.getElementById(elId);
  el.checked = value;
  el.addEventListener("change", () => chrome.storage.sync.set({ [key]: el.checked }));
}

function render(result, tab, scannable) {
  const hostEl = document.getElementById("host");
  try { hostEl.textContent = new URL(tab.url).hostname; } catch { hostEl.textContent = ""; }

  if (!result) {
    document.getElementById("verdict").textContent = scannable ? "Not scanned yet" : "Not scannable";
    document.getElementById("verdict").style.color = "var(--fog)";
    setGlyph(null);
    setDial(0, "#24394D");
    const sigList = document.getElementById("signals");
    sigList.replaceChildren();
    const msg = document.createElement("li");
    msg.textContent = scannable
      ? "Refresh this tab to scan it. You can still use the buttons below."
      : "Browser pages and the Web Store can't be scanned.";
    sigList.appendChild(msg);
    document.getElementById("trk").style.display = "none";
    return;
  }

  lastVerdict = result.verdict;
  const color = COLORS[result.verdict];
  const verdictEl = document.getElementById("verdict");
  verdictEl.textContent =
    result.trusted ? "Trusted site" :
    result.allowlisted ? "On your trusted list" :
    { safe: "You're protected", caution: "Be careful here", danger: "Dangerous page" }[result.verdict];
  verdictEl.style.color = color;
  setGlyph(result.trusted || result.allowlisted ? "safe" : result.verdict);
  document.getElementById("score").textContent = result.score;
  setDial(result.score, color);

  if (result.ai && !result.ai.error) showAI(result.ai);

  const ul = document.getElementById("signals");
  ul.replaceChildren();
  if (!result.signals?.length) {
    const none = document.createElement("li");
    none.textContent = "No suspicious signals on this page.";
    ul.appendChild(none);
  } else {
    for (const s of result.signals.sort((a, b) => b.weight - a.weight).slice(0, 6)) {
      const li = document.createElement("li");
      li.textContent = s.label;
      ul.appendChild(li);
    }
  }

  renderTrackers(result.trackers || []);
}

function renderTrackers(trackers) {
  const count = document.getElementById("trk-count");
  count.textContent = trackers.length;
  count.style.color = trackers.length ? "var(--caution)" : "var(--safe)";

  const list = document.getElementById("trk-list");
  list.replaceChildren();
  if (!trackers.length) {
    const li = document.createElement("li");
    li.textContent = "No known trackers detected.";
    li.style.color = "var(--fog)";
    list.appendChild(li);
    return;
  }
  for (const t of trackers) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = t.name;
    const cat = document.createElement("span");
    cat.className = "cat";
    cat.textContent = t.category;
    li.append(name, cat);
    list.appendChild(li);
  }
}

function showAI(ai) {
  const el = document.getElementById("ai-line");
  el.replaceChildren();
  const b = document.createElement("b");
  b.textContent = "AI verdict: " + ai.verdict + " (" + ai.risk + "/100). ";
  b.style.color = COLORS[ai.verdict] || "inherit";
  el.append(b, document.createTextNode(ai.reason || ""));
}

function showNote(text, isError) {
  const el = document.getElementById("ai-line");
  el.textContent = text;
  el.style.color = isError ? "var(--rocks)" : "var(--fog)";
}

function setDial(score, color) {
  const arc = document.getElementById("arc");
  arc.style.stroke = color;
  arc.style.transition = "stroke-dashoffset .7s cubic-bezier(.2,.8,.3,1)";
  requestAnimationFrame(() =>
    arc.style.strokeDashoffset = String(CIRC - (CIRC * score) / 100));
}

let trustArmed = false;
let trustTimer = null;

async function trustSite() {
  const btn = document.getElementById("trust-btn");

  // First click arms; second click within the window commits.
  if (!trustArmed) {
    let base = "this site";
    try { base = new URL(currentTab.url).hostname.split(".").slice(-2).join("."); } catch {}

    const risky = lastVerdict === "caution" || lastVerdict === "danger";
    showNote(
      (risky
        ? "⚠️ ShadowShield flagged " + base + " as risky. Trusting it disables all future warnings here — only do this if you are certain it is safe. "
        : "Trust " + base + "? This stops future scans and warnings on it. ")
      + "Click again to confirm.",
      risky
    );
    btn.textContent = "Confirm trust";
    btn.style.borderColor = risky ? "var(--rocks)" : "var(--caution)";
    trustArmed = true;
    trustTimer = setTimeout(resetTrust, 5000);
    return;
  }

  clearTimeout(trustTimer);
  trustArmed = false;
  try {
    if (!currentTab) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      currentTab = tab;
    }
    const host = new URL(currentTab.url).hostname;
    const { allowlist = [] } = await chrome.storage.sync.get("allowlist");
    const base = host.split(".").slice(-2).join(".");
    if (!allowlist.includes(base)) allowlist.push(base);
    await chrome.storage.sync.set({ allowlist });
    btn.textContent = "Trusted ✓";
    btn.disabled = true;
    btn.style.borderColor = "";
    showNote(base + " added to your trusted list. Refresh the page to apply.", false);
  } catch {
    showNote("Couldn't trust this page — it may be a browser page.", true);
  }
}

function resetTrust() {
  trustArmed = false;
  const btn = document.getElementById("trust-btn");
  btn.textContent = "Trust this site";
  btn.style.borderColor = "";
  showNote("", false);
}

async function askAI() {
  const btn = document.getElementById("ai-btn");
  // No key yet? Show the explanation panel instead of failing quietly.
  const { apiKey = "" } = await chrome.storage.local.get("apiKey");
  if (!apiKey) {
    document.getElementById("key-note").style.display = "block";
    return;
  }
  btn.disabled = true; btn.textContent = "Analyzing…";
  try {
    if (!currentTab) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      currentTab = tab;
    }
    const res = await safeSend({ type: "PG_AI_ANALYZE", tabId: currentTab.id });
    if (!res) showNote("Couldn't reach the analysis service. Reload the extension and try again.", true);
    else if (res.error) showNote(res.error, true);
    else showAI(res);
  } finally {
    btn.textContent = "Ask AI now";
    btn.disabled = false;
  }
}
