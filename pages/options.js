const DEFAULTS = { enabled: true, feedEnabled: true, autoAI: true,
                   sensitivity: "balanced", allowlist: [], aiProvider: "anthropic" };

init();

async function init() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  // Secret material lives in local storage only — never cloud-synced across devices.
  const local = await chrome.storage.local.get({ apiKey: "" });
  s.apiKey = local.apiKey;
  for (const id of ["enabled", "feedEnabled", "autoAI"])
    document.getElementById(id).checked = s[id];
  document.getElementById("sensitivity").value = s.sensitivity;
  document.getElementById("aiProvider").value = s.aiProvider;
  document.getElementById("apiKey").value = s.apiKey;
  renderAllowlist(s.allowlist);
  renderFeedStatus();
  document.getElementById("save").addEventListener("click", save);
}

async function renderFeedStatus() {
  const el = document.getElementById("feed-status");
  try {
    const { feedMeta } = await chrome.storage.local.get("feedMeta");
    if (!feedMeta || !feedMeta.total) {
      el.textContent = "Feeds not loaded yet — they download shortly after install and refresh every 45 minutes.";
      return;
    }
    const parts = Object.entries(feedMeta.counts || {})
      .map(([name, n]) => name + " " + n).join(" · ");
    const mins = Math.round((Date.now() - feedMeta.updated) / 60000);
    el.textContent = feedMeta.total + " blocked addresses loaded (" + parts + ") — updated " + mins + " min ago.";
  } catch { el.textContent = ""; }
}

function renderAllowlist(list) {
  const el = document.getElementById("allowlist");
  el.replaceChildren();
  if (!list.length) {
    const empty = document.createElement("div");
    empty.style.border = "none";
    empty.textContent = 'No trusted sites yet. Add them from the popup with "Trust this site".';
    el.appendChild(empty);
    return;
  }
  for (const domain of list) {
    const row = document.createElement("div");
    const name = document.createElement("span");
    name.textContent = domain;
    const rm = document.createElement("button");
    rm.textContent = "Remove";
    rm.addEventListener("click", async () => {
      const { allowlist = [] } = await chrome.storage.sync.get("allowlist");
      const next = allowlist.filter(d => d !== domain);
      await chrome.storage.sync.set({ allowlist: next });
      renderAllowlist(next);
    });
    row.append(name, rm);
    el.appendChild(row);
  }
}

async function save() {
  await chrome.storage.sync.set({
    enabled: document.getElementById("enabled").checked,
    feedEnabled: document.getElementById("feedEnabled").checked,
    autoAI: document.getElementById("autoAI").checked,
    sensitivity: document.getElementById("sensitivity").value,
    aiProvider: document.getElementById("aiProvider").value
  });
  // API key stored locally only, kept out of sync storage.
  await chrome.storage.local.set({ apiKey: document.getElementById("apiKey").value.trim() });
  const saved = document.getElementById("saved");
  saved.style.opacity = "1";

  // Return the user to ShadowShield's home: open the popup (where Chrome
  // allows it) and close this settings tab, landing back where they were.
  setTimeout(async () => {
    try { await chrome.action.openPopup(); } catch { /* not supported everywhere */ }
    try {
      const tab = await chrome.tabs.getCurrent();
      if (tab?.id) await chrome.tabs.remove(tab.id);
      else window.close();
    } catch { window.close(); }
  }, 900);
}
