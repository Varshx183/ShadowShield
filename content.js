// ShadowShield content script — phishing analysis, tracker detection,
// domain-age enrichment, and the credential submit guard.

(async function () {
  const settings = await chrome.storage.sync.get({
    enabled: true,
    sensitivity: "balanced",
    allowlist: []
  });
  if (!settings.enabled) return;

  const urlInfo = PG.analyzeUrl(location.href);
  const mult = { lenient: 0.8, balanced: 1.0, strict: 1.2 }[settings.sensitivity] || 1;

  // Shared state — the submit guard reads this at the instant of submission.
  const state = {
    score: 0, verdict: "safe", signals: [],
    trusted: false, allowlisted: false, ageDays: null
  };
  let last = null;

  const baseTrackers = pgDetectTrackers(document);

  if (urlInfo.trusted) {
    state.trusted = true;
    report({ score: 0, verdict: "safe", signals: [], trusted: true, trackers: baseTrackers });
  } else if (settings.allowlist.includes(urlInfo.base || location.hostname)) {
    state.allowlisted = true;
    report({ score: 0, verdict: "safe", signals: [], allowlisted: true, trackers: baseTrackers });
  } else {
    rescan(baseTrackers);
    watchLateLogin();
    checkDomainAge();
  }

  installSubmitGuard();

  // Trackers often load late (tag managers chain-load others) — look again.
  setTimeout(() => {
    const t2 = pgDetectTrackers(document);
    if (last && t2.length > (last.trackers?.length || 0)) {
      report({ ...last, trackers: t2 });
    }
  }, 4500);

  // ------------------------------------------------------------- scanning

  function rescan(trackers) {
    const signals = [...urlInfo.signals, ...PG.analyzeDocument(document, urlInfo), ...ageSignal()];
    state.signals = signals;
    state.score = Math.min(100, Math.round(PG.score(signals) * mult));
    state.verdict = PG.verdict(state.score);
    report({
      score: state.score, verdict: state.verdict, signals,
      trackers: trackers || pgDetectTrackers(document)
    });
    if (state.verdict === "caution") injectBanner(state.score, signals);
  }

  function ageSignal() {
    const d = state.ageDays;
    if (d == null || d >= 90) return [];
    if (d < 7)  return [{ id: "domain-age", weight: 35, label: `Domain was registered only ${d} day(s) ago` }];
    if (d < 30) return [{ id: "domain-age", weight: 25, label: `Domain was registered just ${d} days ago` }];
    return [{ id: "domain-age", weight: 12, label: `Domain is only ${d} days old` }];
  }

  async function checkDomainAge() {
    // A network lookup is only worth it when the page handles credentials
    // or already looks suspicious.
    if (!document.querySelector('input[type="password"]') && state.score < 15) return;
    try {
      const res = await chrome.runtime.sendMessage({
        type: "PG_DOMAIN_AGE",
        domain: urlInfo.base || location.hostname
      });
      if (res?.registered) {
        state.ageDays = Math.max(0, Math.floor((Date.now() - new Date(res.registered).getTime()) / 864e5));
        if (state.ageDays < 90) rescan();  // escalation (incl. blocking) flows automatically
      }
    } catch { /* RDAP unavailable — heuristics stand alone */ }
  }

  // Catch login forms injected late by single-page phishing kits.
  function watchLateLogin() {
    if (document.querySelector('input[type="password"]')) return;
    const obs = new MutationObserver(() => {
      if (document.querySelector('input[type="password"]')) {
        obs.disconnect();
        const before = state.score;
        rescan();
        checkDomainAge();
        if (state.score <= before) report({ ...last });
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });
    setTimeout(() => obs.disconnect(), 15000);
  }

  function report(result) {
    last = result;
    chrome.runtime.sendMessage({
      type: "PG_RESULT",
      url: location.href,
      hostname: location.hostname,
      ...result
    }).catch(() => {});
  }

  // -------------------------------------------------------- submit guard
  // The last line of defense: the instant credentials are submitted to a
  // risky destination, pause and ask. Clean logins on established sites
  // are never interrupted.

  function installSubmitGuard() {
    document.addEventListener("submit", e => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement) || form.dataset.pgApproved) return;
      if (!form.querySelector('input[type="password"]')) return;
      if (state.trusted || state.allowlisted) return;
      const reasons = guardReasons(form);
      if (!reasons.length) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      showGuard(form, reasons);
    }, true);
  }

  function guardReasons(form) {
    const reasons = [];
    try {
      const action = new URL(form.action || location.href, location.href);
      if (action.protocol === "http:") {
        reasons.push("This form sends your password over an unencrypted connection");
      }
      if (action.hostname && PG.etld1(action.hostname) !== PG.etld1(location.hostname)) {
        reasons.push("Your password would be sent to a different site: " + action.hostname);
      }
    } catch {}
    if (state.score >= 30) {
      reasons.push("This page scored " + state.score + "/100 on ShadowShield's risk scan");
    }
    if (state.ageDays != null && state.ageDays < 30) {
      reasons.push("This website's domain is only " + state.ageDays + " day(s) old");
    }
    return reasons;
  }

  function showGuard(form, reasons) {
    document.getElementById("pg-guard")?.remove();
    const wrap = document.createElement("div");
    wrap.id = "pg-guard";
    wrap.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(5,8,14,.72);display:grid;place-items:center;font:14px/1.5 -apple-system,'Segoe UI',Roboto,sans-serif";
    const card = document.createElement("div");
    card.style.cssText = "max-width:420px;width:calc(100% - 40px);background:#171F2E;color:#E8EDF5;border:1px solid #2B3547;border-top:4px solid #F5A623;border-radius:12px;padding:24px";
    const h = document.createElement("div");
    h.style.cssText = "font-size:16px;font-weight:700;margin-bottom:6px";
    h.textContent = "⚠️ Hold on — check before you send";
    const sub = document.createElement("div");
    sub.style.cssText = "color:#9AA7BC;margin-bottom:12px";
    sub.textContent = "ShadowShield paused this password submission:";
    const list = document.createElement("ul");
    list.style.cssText = "margin:0 0 18px;padding-left:18px;color:#FFE9B8";
    for (const r of reasons) {
      const li = document.createElement("li");
      li.style.padding = "3px 0";
      li.textContent = r;
      list.appendChild(li);
    }
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:10px";
    const back = document.createElement("button");
    back.textContent = "Go back";
    back.style.cssText = "flex:1;background:#E8EDF5;color:#0E1420;border:none;border-radius:8px;padding:11px;font:600 14px/1 inherit;cursor:pointer";
    const send = document.createElement("button");
    send.textContent = "Send anyway";
    send.style.cssText = "flex:1;background:none;color:#9AA7BC;border:1px solid #2B3547;border-radius:8px;padding:11px;font:inherit;cursor:pointer";
    back.addEventListener("click", () => wrap.remove());
    send.addEventListener("click", () => {
      form.dataset.pgApproved = "1";
      wrap.remove();
      form.requestSubmit ? form.requestSubmit() : form.submit();
    });
    row.append(back, send);
    card.append(h, sub, list, row);
    wrap.appendChild(card);
    document.documentElement.appendChild(wrap);
    back.focus();
  }

  // ----------------------------------------------------------- banner

  function injectBanner(score, signals) {
    if (document.getElementById("pg-banner")) return;
    const top = signals.slice().sort((a, b) => b.weight - a.weight)[0];
    const banner = document.createElement("div");
    banner.id = "pg-banner";
    // Built entirely with DOM nodes + textContent — no HTML string ever parsed,
    // so page-derived text (signal labels) can never inject markup.
    const inner = document.createElement("div");
    inner.style.cssText = "display:flex;align-items:center;gap:12px;max-width:960px;margin:0 auto";
    const icon = document.createElement("span");
    icon.style.fontSize = "18px";
    icon.textContent = "\u26A0\uFE0F";
    const mid = document.createElement("div");
    mid.style.cssText = "flex:1;min-width:0";
    const strong = document.createElement("strong");
    strong.textContent = "ShadowShield: this page looks suspicious (risk " + Number(score) + "/100).";
    const span = document.createElement("span");
    span.style.opacity = ".85";
    span.textContent = " " + (top ? top.label + ". " : "") +
      "Don't enter passwords or payment details unless you're certain this site is genuine.";
    mid.append(strong, span);
    const dismiss = document.createElement("button");
    dismiss.id = "pg-dismiss";
    dismiss.textContent = "Dismiss";
    dismiss.style.cssText = "background:#2B3140;color:#E8EDF5;border:1px solid #4A5368;border-radius:6px;padding:6px 12px;cursor:pointer;font:inherit";
    inner.append(icon, mid, dismiss);
    banner.appendChild(inner);
    Object.assign(banner.style, {
      position: "fixed", top: "0", left: "0", right: "0", zIndex: "2147483647",
      background: "#3A2E12", color: "#FFE9B8", borderBottom: "2px solid #F5A623",
      padding: "10px 16px", font: "14px/1.45 -apple-system, 'Segoe UI', Roboto, sans-serif"
    });
    document.documentElement.appendChild(banner);
    dismiss.addEventListener("click", () => banner.remove());
  }

})();
