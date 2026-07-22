// ShadowShield tracker detection — identifies analytics, advertising and
// session-recording scripts loaded by the current page. Detection only;
// nothing is blocked or modified.

const PG_TRACKERS = [
  { match: "google-analytics.com",        name: "Google Analytics",   category: "Analytics" },
  { match: "analytics.google.com",        name: "Google Analytics",   category: "Analytics" },
  { match: "googletagmanager.com",        name: "Google Tag Manager", category: "Tag manager" },
  { match: "doubleclick.net",             name: "Google DoubleClick", category: "Advertising" },
  { match: "googlesyndication.com",       name: "Google AdSense",     category: "Advertising" },
  { match: "adservice.google.com",        name: "Google Ads",         category: "Advertising" },
  { match: "connect.facebook.net",        name: "Meta Pixel",         category: "Advertising" },
  { match: "analytics.tiktok.com",        name: "TikTok Pixel",       category: "Advertising" },
  { match: "static.ads-twitter.com",      name: "X (Twitter) Pixel",  category: "Advertising" },
  { match: "snap.licdn.com",              name: "LinkedIn Insight",   category: "Advertising" },
  { match: "sc-static.net",               name: "Snap Pixel",         category: "Advertising" },
  { match: "amazon-adsystem.com",         name: "Amazon Ads",         category: "Advertising" },
  { match: "criteo.com",                  name: "Criteo",             category: "Advertising" },
  { match: "criteo.net",                  name: "Criteo",             category: "Advertising" },
  { match: "taboola.com",                 name: "Taboola",            category: "Advertising" },
  { match: "outbrain.com",                name: "Outbrain",           category: "Advertising" },
  { match: "adnxs.com",                   name: "Xandr / AppNexus",   category: "Advertising" },
  { match: "rubiconproject.com",          name: "Magnite",            category: "Advertising" },
  { match: "pubmatic.com",                name: "PubMatic",           category: "Advertising" },
  { match: "hotjar.com",                  name: "Hotjar",             category: "Session recording" },
  { match: "fullstory.com",               name: "FullStory",          category: "Session recording" },
  { match: "clarity.ms",                  name: "Microsoft Clarity",  category: "Session recording" },
  { match: "mouseflow.com",               name: "Mouseflow",          category: "Session recording" },
  { match: "logrocket.io",                name: "LogRocket",          category: "Session recording" },
  { match: "mixpanel.com",                name: "Mixpanel",           category: "Analytics" },
  { match: "segment.com",                 name: "Segment",            category: "Analytics" },
  { match: "segment.io",                  name: "Segment",            category: "Analytics" },
  { match: "amplitude.com",               name: "Amplitude",          category: "Analytics" },
  { match: "heap.io",                     name: "Heap",               category: "Analytics" },
  { match: "mc.yandex.ru",                name: "Yandex Metrica",     category: "Analytics" },
  { match: "matomo.cloud",                name: "Matomo",             category: "Analytics" },
  { match: "plausible.io",                name: "Plausible",          category: "Analytics" },
  { match: "scorecardresearch.com",       name: "Comscore",           category: "Audience measurement" },
  { match: "quantserve.com",              name: "Quantcast",          category: "Audience measurement" },
  { match: "chartbeat.com",               name: "Chartbeat",          category: "Audience measurement" },
  { match: "hs-scripts.com",              name: "HubSpot",            category: "Marketing" },
  { match: "hs-analytics.net",            name: "HubSpot",            category: "Marketing" },
  { match: "intercom.io",                 name: "Intercom",           category: "Marketing" },
  { match: "klaviyo.com",                 name: "Klaviyo",            category: "Marketing" },
  { match: "branch.io",                   name: "Branch",             category: "Attribution" },
  { match: "appsflyer.com",               name: "AppsFlyer",          category: "Attribution" },
  { match: "onesignal.com",               name: "OneSignal",          category: "Push / engagement" },
  { match: "pushengage.com",              name: "PushEngage",         category: "Push / engagement" },
  { match: "popads.net",                  name: "PopAds",             category: "Aggressive ads" },
  { match: "propellerads.com",            name: "PropellerAds",       category: "Aggressive ads" },
  { match: "adsterra.com",                name: "Adsterra",           category: "Aggressive ads" },
  { match: "exoclick.com",                name: "ExoClick",           category: "Aggressive ads" }
];

function pgDetectTrackers(doc) {
  const urls = new Set();
  try {
    for (const e of performance.getEntriesByType("resource")) urls.add(e.name);
  } catch { /* performance API unavailable */ }
  for (const el of doc.querySelectorAll("script[src], iframe[src], img[src]")) {
    urls.add(el.src);
  }

  const found = new Map();
  for (const u of urls) {
    let host;
    try { host = new URL(u, doc.location.href).hostname; } catch { continue; }
    for (const t of PG_TRACKERS) {
      if (host === t.match || host.endsWith("." + t.match)) {
        if (!found.has(t.name)) found.set(t.name, { name: t.name, category: t.category, host });
      }
    }
  }
  return [...found.values()].sort((a, b) => a.category.localeCompare(b.category));
}
