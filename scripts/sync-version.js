#!/usr/bin/env node
// Called by semantic-release's `prepare` step (see .releaserc.json) with
// the new version as the first argument, e.g.:
//   node scripts/sync-version.js 1.2.3
//
// semantic-release itself only understands npm's package.json natively.
// This project's real "version of record" is the extension's
// manifest.json, so this script is the bridge: it keeps manifest.json,
// package.json, and the README's version badge all in sync with whatever
// version semantic-release computed from the commit history.

const fs = require("fs");
const path = require("path");

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+/.test(version)) {
  console.error("sync-version.js: expected a semver version as argv[2], got:", version);
  process.exit(1);
}

const root = path.join(__dirname, "..");

// manifest.json — Chrome requires a bare X.Y.Z(.W) version, no prerelease
// suffix, so strip anything semantic-release might add (e.g. "-beta.1").
const manifestVersion = version.replace(/-.*$/, "");
const manifestPath = path.join(root, "manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.version = manifestVersion;
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
console.log("Updated manifest.json ->", manifestVersion);

// package.json — kept in sync for consistency/tooling, never published to npm.
const pkgPath = path.join(root, "package.json");
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
pkg.version = version;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
console.log("Updated package.json ->", version);

// README.md — the version badge.
const readmePath = path.join(root, "README.md");
let readme = fs.readFileSync(readmePath, "utf8");
const before = readme;
readme = readme.replace(/version-[\d.]+(-[a-zA-Z0-9.]+)?-blue\.svg/, `version-${version}-blue.svg`);
if (readme !== before) {
  fs.writeFileSync(readmePath, readme);
  console.log("Updated README.md badge ->", version);
} else {
  console.warn("README.md: version badge pattern not found, nothing updated");
}
