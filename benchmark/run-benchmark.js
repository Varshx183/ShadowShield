// ShadowShield heuristics benchmark
//
// Measures the URL-level detection engine against real-world data:
//   - Phishing set: live confirmed phishing URLs (Phishing.Database)
//   - Legitimate set: real websites from Google's CrUX top-1M ranking
//
// This benchmarks ONLY URL-level signals. Page-content signals (credential
// forms, urgency text, cross-domain actions), threat feeds, and the AI layer
// are NOT exercised here — so the detection number is a FLOOR, not the
// extension's full real-world catch rate.
//
// Usage: node benchmark/run-benchmark.js <phishing-file> <legit-csv> [sampleSize]
// Deterministic: fixed-seed sampling, so results are reproducible.

const fs = require("fs");
const path = require("path");
const PG = require(path.join(__dirname, "..", "heuristics.js"));

const [, , phishFile, legitFile, sampleArg] = process.argv;
const SAMPLE = Number(sampleArg) || 500;
if (!phishFile || !legitFile) {
  console.error("usage: node benchmark/run-benchmark.js <phishing-file> <legit-csv> [sampleSize]");
  process.exit(1);
}

function rng(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function sample(arr, n, rand) {
  const out = [], taken = new Set();
  while (out.length < n && taken.size < arr.length) {
    const i = Math.floor(rand() * arr.length);
    if (!taken.has(i)) { taken.add(i); out.push(arr[i]); }
  }
  return out;
}
function loadLines(file) {
  return fs.readFileSync(file, "utf8").split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
}
function scoreUrl(url) {
  const info = PG.analyzeUrl(url);
  const score = PG.score(info.signals);
  return { score, verdict: info.trusted ? "trusted" : PG.verdict(score), signals: info.signals };
}
function evaluate(urls, label) {
  const buckets = { trusted: 0, safe: 0, caution: 0, danger: 0 };
  const signalHits = {};
  let total = 0;
  for (const url of urls) {
    let r; try { r = scoreUrl(url); } catch { continue; }
    buckets[r.verdict]++; total++;
    for (const s of r.signals) signalHits[s.id] = (signalHits[s.id] || 0) + 1;
  }
  const flagged = buckets.caution + buckets.danger;
  console.log(`\n=== ${label} (n=${total}) ===`);
  console.log(`  trusted: ${buckets.trusted}  safe: ${buckets.safe}  caution: ${buckets.caution}  danger: ${buckets.danger}`);
  console.log(`  flagged (caution+danger): ${flagged}  ->  ${(100 * flagged / total).toFixed(1)}%`);
  const top = Object.entries(signalHits).sort((a, b) => b[1] - a[1]).slice(0, 10);
  console.log(`  top signals: ${top.map(([id, n]) => id + " x" + n).join(", ") || "none"}`);
  return { total, flagged };
}

const rand = rng(20260707);
const phishAll = loadLines(phishFile).filter(l => /^https?:\/\//.test(l));
const phish = sample(phishAll, SAMPLE, rand);
const legitAll = loadLines(legitFile).filter(l => l.startsWith("http")).map(l => l.split(",")[0]);
const head = sample(legitAll.slice(0, 50000), Math.floor(SAMPLE / 2), rand);
const tail = sample(legitAll.slice(200000), Math.ceil(SAMPLE / 2), rand);
const legit = head.concat(tail);

console.log("ShadowShield URL-heuristics benchmark");
console.log("phishing pool:", phishAll.length, "| legit pool:", legitAll.length, "| sample:", SAMPLE, "each");
const p = evaluate(phish, "PHISHING (want: HIGH flagged %)");
const l = evaluate(legit, "LEGITIMATE (want: LOW flagged %)");

console.log("\n=== SUMMARY ===");
console.log(`Detection rate (URL signals only, floor): ${(100 * p.flagged / p.total).toFixed(1)}%`);
console.log(`False-positive rate:                      ${(100 * l.flagged / l.total).toFixed(1)}%`);
console.log("\nNote: page-content signals, feeds, and AI are not exercised here;");
console.log("real-world detection is higher than this URL-only floor.");
