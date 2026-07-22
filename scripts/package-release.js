#!/usr/bin/env node
// Called by semantic-release's `prepare` step to build the zip that
// @semantic-release/github then attaches to the release. Named
// v<version>.zip, e.g. v1.0.0.zip — solving, permanently, the recurring
// problem of download links pointing at a stale or branch-named zip:
// every release from now on gets a correctly-versioned asset
// automatically, with no manual step and nothing to remember.

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const version = process.argv[2];
if (!version) {
  console.error("package-release.js: expected a version as argv[2]");
  process.exit(1);
}

const root = path.join(__dirname, "..");
const outName = `v${version}.zip`;
const outPath = path.join(root, outName);

if (fs.existsSync(outPath)) fs.unlinkSync(outPath);

// Only version-controlled files, excluding dev-only artifacts (node_modules,
// backend's own node_modules, this project's own git metadata).
execSync(
  `git archive --format=zip -o "${outPath}" HEAD`,
  { cwd: root, stdio: "inherit" }
);

console.log("Packaged release asset:", outName);
