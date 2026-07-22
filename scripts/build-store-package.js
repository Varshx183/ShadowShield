#!/usr/bin/env node
// Builds the Chrome Web Store submission package.
//
//   node scripts/build-store-package.js
//   -> dist/shadowshield-store-<version>.zip
//
// This is deliberately an ALLOWLIST, not an ignore-list. Only files the
// extension actually executes at runtime are included. Everything else in
// the repo — tests, benchmark, backend, scripts, docs, node_modules, and
// especially demo/phishing-demo.html — is excluded.
//
// The demo page matters most: it is a working imitation of a PayPal login
// form. It exists so the detection engine has something real to catch, and
// it belongs in the repo. Shipping it inside the extension package would
// put a credential-harvesting page in front of a Web Store reviewer, which
// is a plausible rejection for deceptive content. The allowlist below makes
// that mistake structurally impossible rather than relying on remembering.

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const root = path.join(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
const version = manifest.version;

// Every file the extension loads at runtime, and nothing else.
const FILES = [
  "manifest.json",
  "background.js",
  "content.js",
  "heuristics.js",
  "trackers.js",
  "pages/popup.html",
  "pages/popup.js",
  "pages/options.html",
  "pages/options.js",
  "pages/warning.html",
  "pages/warning.js",
  "icons/icon16.png",
  "icons/icon48.png",
  "icons/icon128.png"
];

// Fail loudly rather than shipping a package with a missing file.
const missing = FILES.filter(f => !fs.existsSync(path.join(root, f)));
if (missing.length) {
  console.error("build-store-package: missing required files:\n  " + missing.join("\n  "));
  process.exit(1);
}

// Cross-check the allowlist against what the manifest actually declares, so
// adding a script to the manifest without adding it here fails the build
// instead of silently shipping a broken extension.
const declared = new Set(["manifest.json"]);
for (const cs of manifest.content_scripts || []) (cs.js || []).forEach(f => declared.add(f));
declared.add(manifest.background.service_worker);
declared.add(manifest.action.default_popup);
if (manifest.options_page) declared.add(manifest.options_page);
for (const w of manifest.web_accessible_resources || []) w.resources.forEach(f => declared.add(f));
Object.values(manifest.icons).forEach(f => declared.add(f));

const undeclared = [...declared].filter(f => !FILES.includes(f));
if (undeclared.length) {
  console.error(
    "build-store-package: manifest declares files not in the allowlist:\n  " +
    undeclared.join("\n  ") +
    "\nAdd them to FILES in this script."
  );
  process.exit(1);
}

const dist = path.join(root, "dist");
fs.mkdirSync(dist, { recursive: true });
const out = path.join(dist, `shadowshield-store-${version}.zip`);
if (fs.existsSync(out)) fs.unlinkSync(out);

// -X strips extra file attributes; keeps the archive minimal and reproducible.
execFileSync("zip", ["-q", "-X", out, ...FILES], { cwd: root, stdio: "inherit" });

const kb = (fs.statSync(out).size / 1024).toFixed(1);
console.log(`Store package: dist/shadowshield-store-${version}.zip (${FILES.length} files, ${kb} KB)`);
console.log("Excluded: demo/, backend/, tests/, benchmark/, scripts/, docs/, node_modules/, all markdown");
