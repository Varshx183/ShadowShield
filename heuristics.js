// ShadowShield heuristics engine
// Pure functions only — no DOM access here except where a document is passed in.
// Produces a list of weighted signals; the total maps to a 0–100 risk score.

const PG = (() => {
  // Brands most commonly impersonated in phishing campaigns, with their real domains.
  const BRANDS = {
    paypal: ["paypal.com"],
    apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    google: ["google.com", "gmail.com", "youtube.com", "accounts.google.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
    facebook: ["facebook.com", "fb.com", "meta.com"],
    instagram: ["instagram.com"],
    netflix: ["netflix.com"],
    whatsapp: ["whatsapp.com"],
    linkedin: ["linkedin.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com"],
    dropbox: ["dropbox.com"],
    adobe: ["adobe.com"],
    docusign: ["docusign.com", "docusign.net"],
    steam: ["steampowered.com", "steamcommunity.com"],
    usps: ["usps.com"],
    fedex: ["fedex.com"],
    dhl: ["dhl.com"],
    irs: ["irs.gov"],
    hsbc: ["hsbc.com", "hsbc.co.uk"],
    barclays: ["barclays.co.uk", "barclays.com"],
    santander: ["santander.com", "santander.co.uk"],
    citibank: ["citi.com", "citibank.com"],
    capitalone: ["capitalone.com"],
    amex: ["americanexpress.com"],
    usbank: ["usbank.com"],
    truist: ["truist.com"],
    natwest: ["natwest.com"],
    lloyds: ["lloydsbank.com"],
    kraken: ["kraken.com"],
    metamask: ["metamask.io"],
    trezor: ["trezor.io"],
    ledger: ["ledger.com"],
    blockchain: ["blockchain.com"],
    opensea: ["opensea.io"],
    yahoo: ["yahoo.com"],
    aol: ["aol.com"],
    protonmail: ["proton.me", "protonmail.com"],
    zoho: ["zoho.com"],
    royalmail: ["royalmail.com"],
    auspost: ["auspost.com.au"],
    evri: ["evri.com"],
    laposte: ["laposte.net", "laposte.fr"],
    correos: ["correos.es"],
    verizon: ["verizon.com"],
    vodafone: ["vodafone.com", "vodafone.co.uk"],
    tmobile: ["t-mobile.com"],
    telegram: ["telegram.org"],
    discord: ["discord.com", "discord.gg"],
    snapchat: ["snapchat.com"],
    tiktok: ["tiktok.com"],
    epicgames: ["epicgames.com"],
    roblox: ["roblox.com"],
    blizzard: ["blizzard.com", "battle.net"],
    minecraft: ["minecraft.net"],
    playstation: ["playstation.com"],
    nintendo: ["nintendo.com"],
    xbox: ["xbox.com"],
    walmart: ["walmart.com"],
    alibaba: ["alibaba.com"],
    aliexpress: ["aliexpress.com"],
    flipkart: ["flipkart.com"],
    mercadolibre: ["mercadolibre.com", "mercadolivre.com.br"],
    shopee: ["shopee.com", "shopee.sg"],
    lazada: ["lazada.com"],
    rakuten: ["rakuten.com", "rakuten.co.jp"],
    etsy: ["etsy.com"],
    bestbuy: ["bestbuy.com"],
    costco: ["costco.com"],
    homedepot: ["homedepot.com"],
    spotify: ["spotify.com"],
    hulu: ["hulu.com"],
    disney: ["disney.com", "disneyplus.com"],
    hmrc: ["hmrc.gov.uk"],
    airbnb: ["airbnb.com"],
    uber: ["uber.com"],
    lyft: ["lyft.com"],
    doordash: ["doordash.com"],
    skype: ["skype.com"],
    onedrive: ["microsoft.com", "live.com"],
    sharepoint: ["microsoft.com", "sharepoint.com"]
  };

  // Domains we never scan (exact eTLD+1 match) — cuts false positives and work.
  const TRUSTED = new Set(
    Object.values(BRANDS).flat().concat([
      "wikipedia.org", "github.com", "stackoverflow.com", "reddit.com",
      "twitter.com", "x.com", "ebay.com", "shopify.com", "cloudflare.com",
      "mozilla.org", "anthropic.com", "claude.ai", "nytimes.com", "bbc.com",
      // Legitimate infrastructure/CDN/API domains that contain brand names —
      // flagging these as lookalikes is a false positive (caught by benchmark).
      "google-analytics.com", "googleapis.com", "googletagmanager.com",
      "googlesyndication.com", "googleadservices.com", "googletagservices.com",
      "googleusercontent.com", "gstatic.com", "google.com", "facebook.net",
      "amazonaws.com", "cloudfront.net", "akamaihd.net", "fbcdn.net",
      "demdex.net", "adobedtm.com", "windows.net", "azureedge.net"
    ])
  );

  const RISKY_TLDS = new Set([
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "icu", "cyou",
    "rest", "cam", "monster", "quest", "click", "country", "stream",
    "download", "racing", "loan", "work", "men", "date", "bid",
    "sbs", "cfd", "buzz", "mom", "autos", "boats", "hair", "beauty",
    "skin", "makeup", "bond", "lat"
  ]);

  // Heavily marketed cheap TLDs: abused often, but with real legitimate use —
  // a hint, not an accusation.
  const MILD_TLDS = new Set(["xyz", "online", "site", "space", "pw", "vip", "lol"]);

  // Free/cheap hosting platforms constantly abused by phishing kits. Weak
  // alone (many legit sites live here too) — decisive in combination.
  const FREE_HOSTS = [
    "weebly.com", "weeblysite.com", "000webhostapp.com", "firebaseapp.com",
    "web.app", "netlify.app", "vercel.app", "glitch.me", "repl.co",
    "pages.dev", "workers.dev", "blogspot.com", "wixsite.com", "webflow.io",
    "godaddysites.com", "square.site", "mystrikingly.com", "yolasite.com",
    "duckdns.org", "github.io", "gitlab.io", "surge.sh", "onrender.com",
    "herokuapp.com", "azurewebsites.net", "appspot.com", "r2.dev",
    "infinityfreeapp.com", "wuaze.com", "great-site.net", "kesug.com",
    "rf.gd", "webnode.page", "jimdosite.com"
  ];

  const PHISHY_PATH = /\/(log[-_]?in|sign[-_]?in|verif(y|ication)|secure|security|account|update|confirm|webmail|password|banking|invoice|wallet|recover|unlock)([\/.\-_?]|$)/i;

  // Dynamic-DNS / tunnel hosts: free, instant, disposable — kit favorites.
  const DYNAMIC_DNS = [
    "duckdns.org", "hopto.org", "zapto.org", "sytes.net", "ddns.net",
    "myftp.org", "myftp.biz", "serveo.net", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "loca.lt", "portmap.io", "no-ip.org", "no-ip.biz",
    "chickenkiller.com", "co.vu"
  ];

  // Credential-bait words appearing in the DOMAIN itself (not just the path).
  const HOST_KEYWORDS = /(secure|verif|signin|log[-_]?in|account|support|update|billing|invoice|wallet|unlock|recover|refund|suspend|webmail)/i;

  const URGENCY_PATTERNS = [
    /account (has been|will be) (suspended|locked|closed|limited)/i,
    /verify (your )?(identity|account|information) (now|immediately|within)/i,
    /unusual (sign[- ]?in|activity|login attempt)/i,
    /(confirm|update) your (payment|billing) (details|information)/i,
    /your (package|parcel|delivery) (is|has been) (held|suspended|pending)/i,
    /you (have won|are a winner|have been selected)/i,
    /immediate action required/i,
    /failure to (verify|respond|comply) will result/i,
    /session (has )?expired.{0,30}(sign|log) ?in/i
  ];

  // --- small utilities -----------------------------------------------------

  function etld1(hostname) {
    // Approximate eTLD+1: good enough without the public-suffix list for
    // common cases; handles co.uk-style two-part suffixes.
    const twoPart = /\.(co|com|org|net|ac|gov|edu)\.[a-z]{2}$/i;
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    if (twoPart.test(hostname)) return parts.slice(-3).join(".");
    return parts.slice(-2).join(".");
  }

  function levenshtein(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 99;
    const m = a.length, n = b.length;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(
          prev[j] + 1,
          cur[j - 1] + 1,
          prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
      }
      prev = cur;
    }
    return prev[n];
  }

  // Normalize common homoglyph substitutions before comparing to brands.
  // A brand token only counts when it isn't embedded inside a longer word:
  // it must sit at a string edge or beside a non-letter (hyphen/digit/dot).
  // Long brand names (8+ chars) are allowed as plain substrings — accidental
  // containment is implausible for e.g. "microsoft" or "aliexpress".
  function hasBrandToken(str, brand) {
    if (brand.length >= 8) return str.includes(brand);
    let idx = str.indexOf(brand);
    while (idx !== -1) {
      const before = str[idx - 1];
      const after = str[idx + brand.length];
      const edge = c => c === undefined || /[^a-z]/.test(c);
      if (edge(before) && edge(after)) return true;
      idx = str.indexOf(brand, idx + 1);
    }
    return false;
  }

  function deglyph(s) {
    return s
      .replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e")
      .replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t")
      .replace(/vv/g, "w").replace(/rn/g, "m");
  }

  function shannonEntropy(s) {
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    return -Object.values(freq).reduce((sum, f) => {
      const p = f / s.length;
      return sum + p * Math.log2(p);
    }, 0);
  }

  // --- URL / domain signals ------------------------------------------------

  function analyzeUrl(urlString) {
    const signals = [];
    let url;
    try { url = new URL(urlString); } catch { return { signals, trusted: false }; }

    const host = url.hostname.toLowerCase();
    const base = etld1(host);
    const registrable = base.split(".")[0]; // "paypal" from "paypal.com"

    if (TRUSTED.has(base)) return { signals, trusted: true };

    // Raw IP address as host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      signals.push({ id: "ip-host", weight: 30, label: "Page is served from a raw IP address instead of a domain" });
    }

    // Punycode (internationalized lookalikes like xn--pypal-...)
    if (host.includes("xn--")) {
      signals.push({ id: "punycode", weight: 35, label: "Domain uses punycode, often used to disguise lookalike characters" });
    }

    // Risky TLD
    const tld = host.split(".").pop();
    if (RISKY_TLDS.has(tld)) {
      signals.push({ id: "risky-tld", weight: 15, label: `".${tld}" domains are heavily abused in phishing campaigns` });
    } else if (MILD_TLDS.has(tld)) {
      signals.push({ id: "mild-tld", weight: 8, label: `".${tld}" domains see frequent phishing abuse` });
    }

    // Brand impersonation checks
    const deglyphed = deglyph(registrable);
    // Also compare with collapsed repeats: "commuuntiy" -> "comunity"-ish,
    // catching padded-letter lookalikes like "steamncommuuntiy".
    const collapsed = deglyph(registrable).replace(/(.)\1+/g, "$1");
    for (const [brand, realDomains] of Object.entries(BRANDS)) {
      const official = realDomains.some(d => base === d);
      if (official) continue;

      // Brand name inside a different registrable domain: paypal-secure-login.com
      if (hasBrandToken(registrable, brand) || hasBrandToken(deglyphed, brand) || hasBrandToken(collapsed, brand)) {
        signals.push({
          id: "brand-in-domain", weight: 40, brand,
          label: `Domain contains "${brand}" but is not an official ${brand} site`
        });
        break;
      }
      // Close misspelling: paypa1.com, arnazon.com
      const dist = levenshtein(deglyphed, brand);
      if ((dist === 1 && brand.length >= 6) || (dist === 2 && brand.length >= 9)) {
        signals.push({
          id: "lookalike-domain", weight: 45, brand,
          label: `Domain looks like a misspelling of ${brand}`
        });
        break;
      }
      // Brand in subdomain of unrelated site: paypal.com.evil-host.top
      const subs = host.slice(0, host.length - base.length);
      if (hasBrandToken(subs, brand)) {
        signals.push({
          id: "brand-in-subdomain", weight: 45, brand,
          label: `"${brand}" appears in the subdomain of an unrelated site — a classic phishing trick`
        });
        break;
      }
    }

    // Structural oddities
    const hyphens = (registrable.replace(/xn--/g, "").match(/-/g) || []).length;
    if (hyphens >= 3) {
      signals.push({ id: "many-hyphens", weight: 10, label: "Unusually hyphen-heavy domain name" });
    }
    const subCount = host.split(".").length - base.split(".").length;
    if (subCount >= 3) {
      signals.push({ id: "deep-subdomains", weight: 14, label: "Excessive subdomain nesting" });
    } else if (subCount === 2) {
      signals.push({ id: "multi-subdomain", weight: 7, label: "Multiple subdomain levels" });
    }
    if (host.length >= 40) {
      signals.push({ id: "long-host", weight: 10, label: "Unusually long hostname" });
    }
    if (registrable.length >= 16 && shannonEntropy(registrable) > 3.6) {
      signals.push({ id: "random-domain", weight: 15, label: "Domain name looks randomly generated" });
    }
    if (url.protocol === "http:") {
      signals.push({ id: "no-https", weight: 10, label: "Connection is not encrypted (HTTP)" });
    }
    // Free-hosting subdomain (kit-friendly, disposable)
    if (FREE_HOSTS.some(fh => host === fh || host.endsWith("." + fh))) {
      signals.push({ id: "free-host", weight: 18, label: "Hosted on a free platform frequently abused by phishing kits" });
    }
    // Credential-bait keywords in the path
    if (PHISHY_PATH.test(url.pathname)) {
      signals.push({ id: "phishy-path", weight: 10, label: "URL path uses credential-bait wording (login/verify/secure…)" });
    }
    // Random-looking path segment: long, high-entropy, no vowels/dictionary feel
    for (const seg of url.pathname.split("/")) {
      if (seg.length >= 10 && /^[a-z0-9]+$/i.test(seg) && shannonEntropy(seg) > 3.3 &&
          (seg.match(/[aeiou]/gi) || []).length / seg.length < 0.25) {
        signals.push({ id: "random-path", weight: 12, label: "URL contains a random-looking path segment" });
        break;
      }
    }
    // Digits embedded in the registrable name (not a pure country/version suffix)
    if (/[a-z]\d|\d[a-z]/i.test(registrable) && /\d/.test(registrable)) {
      signals.push({ id: "digit-in-name", weight: 8, label: "Digits mixed into the domain name" });
    }
    // Dynamic-DNS / tunnel host
    if (DYNAMIC_DNS.some(d => host === d || host.endsWith("." + d))) {
      signals.push({ id: "dynamic-dns", weight: 22, label: "Uses a disposable dynamic-DNS/tunnel host common in phishing" });
    }
    // Raw .html/.php page file — hallmark of a static phishing kit
    if (/\.(html?|php|htm)$/i.test(url.pathname)) {
      signals.push({ id: "kit-file", weight: 12, label: "Links directly to a raw page file, typical of phishing kits" });
    }
    // WordPress internals in path = compromised legitimate site hosting a kit
    if (/\/wp-(content|includes|admin)\//i.test(url.pathname) && PHISHY_PATH.test(url.pathname)) {
      signals.push({ id: "wp-kit", weight: 20, label: "Credential page buried in WordPress internals — a hijacked site" });
    }
    // Credential keyword in the registrable domain name itself
    if (HOST_KEYWORDS.test(registrable)) {
      signals.push({ id: "keyword-domain", weight: 15, label: "Domain name itself contains credential-bait wording" });
    }
    // Long, digit-bearing random subdomain (pub-476be…, sparkling-sound-d00e…)
    const subForRandom = host.slice(0, Math.max(0, host.length - base.length - 1));
    if (subForRandom.length >= 16 && /\d/.test(subForRandom) && shannonEntropy(subForRandom) > 3.4) {
      signals.push({ id: "random-subdomain", weight: 16, label: "Long random-looking subdomain, typical of auto-generated phishing hosts" });
    }
    // Credentials embedded in URL (user@host trick)
    if (url.username) {
      signals.push({ id: "userinfo-url", weight: 30, label: "URL embeds a fake domain before the @ sign" });
    }

    return { signals, trusted: false, base };
  }

  // --- Page content signals (pass in `document`) ----------------------------

  function analyzeDocument(doc, urlInfo) {
    const signals = [];
    const url = new URL(doc.location.href);
    const pwFields = doc.querySelectorAll('input[type="password"]');
    const hasPassword = pwFields.length > 0;
    const bodyText = (doc.body?.innerText || "").slice(0, 20000);

    // Sensitive inputs over plain HTTP
    if (hasPassword && url.protocol === "http:") {
      signals.push({ id: "pw-over-http", weight: 40, label: "Password field on an unencrypted page" });
    }
    const ccField = doc.querySelector('input[autocomplete*="cc-"], input[name*="card" i][name*="number" i]');
    if (ccField && url.protocol === "http:") {
      signals.push({ id: "cc-over-http", weight: 40, label: "Card details requested on an unencrypted page" });
    }

    // Login form submitting to a different registrable domain
    for (const form of doc.querySelectorAll("form")) {
      if (!form.querySelector('input[type="password"]')) continue;
      try {
        const action = new URL(form.action || doc.location.href, doc.location.href);
        if (action.protocol === "http:") {
          signals.push({ id: "form-http-action", weight: 35, label: "Login form submits over an unencrypted connection" });
        }
        if (etld1(action.hostname) !== etld1(url.hostname) && action.hostname) {
          signals.push({ id: "cross-domain-form", weight: 30, label: `Login form sends credentials to a different site (${action.hostname})` });
        }
      } catch { /* ignore malformed actions */ }
    }

    // Brand words + credential form on a non-official domain
    if (hasPassword && !urlInfo.trusted) {
      const textSample = (doc.title + " " + bodyText.slice(0, 4000)).toLowerCase();
      for (const [brand, realDomains] of Object.entries(BRANDS)) {
        const onOfficial = realDomains.some(d => etld1(url.hostname) === d);
        if (!onOfficial && textSample.includes(brand)) {
          signals.push({
            id: "brand-page-mismatch", weight: 35, brand,
            label: `Page mentions ${brand} and asks for a password, but is not hosted on ${realDomains[0]}`
          });
          break;
        }
      }
    }

    // Urgency / scare language
    let urgencyHits = 0;
    for (const re of URGENCY_PATTERNS) if (re.test(bodyText)) urgencyHits++;
    if (urgencyHits >= 1) {
      signals.push({
        id: "urgency-language",
        weight: Math.min(10 + urgencyHits * 8, 30),
        label: "Uses pressure tactics ('verify immediately', 'account suspended', prize claims)"
      });
    }

    // Anti-inspection tricks alongside a credential form
    if (hasPassword) {
      const html = doc.documentElement.outerHTML.slice(0, 100000);
      if (/oncontextmenu\s*=\s*["']?\s*return false/i.test(html)) {
        signals.push({ id: "blocks-rightclick", weight: 12, label: "Page blocks right-click while asking for credentials" });
      }
    }

    // Data-URI or blob iframes hosting forms (kit obfuscation)
    for (const f of doc.querySelectorAll('iframe[src^="data:"], iframe[src^="blob:"]')) {
      signals.push({ id: "opaque-iframe", weight: 20, label: "Page embeds content from an opaque data/blob frame" });
      break;
    }

    return signals;
  }

  function score(signals) {
    // Diminishing returns so five weak signals don't equal one smoking gun.
    const sorted = [...signals].sort((a, b) => b.weight - a.weight);
    let total = 0, factor = 1;
    for (const s of sorted) {
      total += s.weight * factor;
      factor *= 0.75;
    }
    // Convergence bonus: independent weak signals agreeing is itself a signal.
    if (sorted.length >= 4) total += 14;
    else if (sorted.length >= 3) total += 7;
    return Math.min(100, Math.round(total));
  }

  function verdict(scoreValue) {
    if (scoreValue >= 60) return "danger";
    if (scoreValue >= 30) return "caution";
    return "safe";
  }

  return { analyzeUrl, analyzeDocument, score, verdict, etld1 };
})();

if (typeof module !== "undefined") module.exports = PG; // for tests
