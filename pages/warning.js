const params = new URLSearchParams(location.search);
const target = params.get("target") || "";
const score = params.get("score") || "?";
let signals = [];
try { signals = JSON.parse(params.get("signals") || "[]"); } catch {}

let host = "";
try { host = new URL(target).hostname; } catch {}

// Domain x-ray: render the hostname in monospace and highlight digits,
// hyphens and punycode markers — the characters lookalike domains hide behind.
const domainEl = document.getElementById("domain");
for (const ch of host) {
  if (/[\d-]/.test(ch)) {
    const b = document.createElement("b");
    b.textContent = ch;
    domainEl.appendChild(b);
  } else {
    domainEl.appendChild(document.createTextNode(ch));
  }
}
if (host.includes("xn--")) {
  const note = document.createElement("div");
  note.style.cssText = "font-size:12px;color:var(--rocks);margin-top:6px;font-family:inherit";
  note.textContent = "punycode domain — displayed characters may not be what they seem";
  domainEl.appendChild(note);
}

document.getElementById("score").textContent = "risk " + score + "/100";

const list = document.getElementById("signals");
for (const s of signals) {
  const li = document.createElement("li");
  li.textContent = s.label;
  list.appendChild(li);
}

document.getElementById("back").addEventListener("click", () => {
  // New tabs have no history to go back to; fall back to a blank tab.
  if (history.length > 2) history.go(-2);
  else location.href = "about:blank";
});

document.getElementById("proceed").addEventListener("click", async () => {
  // Semgrep (javascript.browser.security.open-redirect.js-open-redirect):
  // `target` comes from a URL query parameter and must never be trusted
  // enough to hand directly to location.href — a javascript: URI here
  // would execute in this extension page's context. Only ever navigate to
  // a well-formed http(s) URL; anything else is refused.
  let safe;
  try {
    const parsed = new URL(target);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") safe = parsed.href;
  } catch { /* fall through to refusal below */ }

  if (!safe) {
    showNote_unsafeTarget();
    return;
  }

  await chrome.runtime.sendMessage({ type: "PG_PROCEED", hostname: host });
  // False positive after remediation: Semgrep's taint tracker correctly
  // traces `safe` back to the user-controlled `target` param, but doesn't
  // model the sanitizing branch above (protocol allowlist check) that
  // guarantees `safe` is only ever set to a well-formed http(s) URL —
  // location.href is unreachable on any other path. See
  // tests/run-tests.js ("warning.js validates target protocol before
  // navigating") for the enforced guarantee, and SECURITY_REVIEW.md for
  // the exhaustive proof this was tested against (javascript:/data:/
  // file:/vbscript: URIs all fail the protocol check above).
  //
  // A related pro-rule finding (tainted-redirect) additionally suggests
  // validating the destination against an allowlist of approved domains.
  // That control is intentionally not applicable to this page: its entire
  // purpose is to show the user a domain that was NOT on any allowlist
  // (a flagged/blocked site) and let them make an informed choice — the
  // set of possible destinations is unbounded by design, the same way
  // Chrome's own Safe Browsing interstitial lets you proceed to any
  // flagged URL after an explicit warning. Residual risk is bounded by
  // required user interaction (must click "Proceed anyway" on a page that
  // x-rays and highlights the destination domain) rather than by a
  // domain allowlist. See THREAT_MODEL.md ("Tampering") for the full
  // analysis of this page's necessarily-broad web_accessible_resources
  // scope and why it can't be narrowed without breaking live-feed
  // blocking (declarativeNetRequest redirects here from any origin).
  // nosemgrep: javascript.browser.security.open-redirect.js-open-redirect, javascript.browser.tainted-redirect.tainted-redirect
  location.href = safe;
});

function showNote_unsafeTarget() {
  const btn = document.getElementById("proceed");
  btn.textContent = "Can't proceed — invalid address";
  btn.disabled = true;
}
