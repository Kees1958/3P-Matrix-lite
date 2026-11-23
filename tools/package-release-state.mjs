#!/usr/bin/env node
// ── tools/package-release-state.mjs ───────────────────────────────────────────
// Writes package-release-state.json: one record per release artifact (extension, tools, docs)
// so a later session can confirm which exact trees were packaged together, and that none is a
// partial export (Xplainer audit — "Multi-artifact packaging integrity").
//
// Usage (paths are the unpacked artifact roots, i.e. the folder inside each zip):
//   node package-release-state.mjs --extension ../3P-Matrix --tools . --docs ../3P-Matrix-docs \
//        --tools-version 4.2.1 [--out package-release-state.json]
//
// Per artifact:
//   hash     SHA-256 (hex) over every file, sorted by relative path ("/" separators). For each
//            file: UTF-8 path, NUL, byte length in decimal, NUL, then the raw bytes. Independent
//            of zip compression, timestamps and file order on disk.
//   version  extension: manifest.json "version" · docs: first "## x.y.z" heading of CHANGELOG.md
//            · tools: --tools-version (the tools line is versioned separately)
//   files    number of files hashed
// extension.shippedPermissions copies the four permission lists from manifest.json.
// Refuses to write when tools/package-release.mjs guardRelease() reports a problem (5.0.7).
// Skipped everywhere: SKIP_NAMES (from package-release.mjs), any file named DEFAULT_OUT (the state file never hashes
// itself, wherever --out points), and the output file itself.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, statSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
// 5.0.7: file names, the changelog heading pattern and the never-shipped names come from the release
// declaration, and a tree that breaks it is never recorded (C21: one declaration, not two copies).
import { MANIFEST_FILE, CHANGELOG_FILE, CHANGELOG_VERSION_RE, guardRelease, releaseTrees } from "./package-release.mjs";
// 5.0.9: the file lists come from releaseTrees() — the same three lists in the repo and the release layout, so a
// state recorded from either layout hashes exactly what the zips hold.

// ── Settings (one place) ─────────────────────────────────────────────────────
const DEFAULT_OUT = "package-release-state.json";
const HASH_ALGORITHM = "sha256";
const FIELD_SEPARATOR = "\0";
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const PERMISSION_KEYS = Object.freeze(["permissions", "host_permissions", "optional_permissions", "optional_host_permissions"]);
const JSON_INDENT = 2;
const ARG_KEYS = Object.freeze(["extension", "tools", "docs", "tools-version", "out"]);
const REQUIRED_ARGS = Object.freeze(["extension", "tools", "docs", "tools-version"]);

function fail(msg) {
  console.error(`package-release-state: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = (argv[i] || "").replace(/^--/, "");
    if (!ARG_KEYS.includes(key) || argv[i + 1] === undefined) fail(`bad argument "${argv[i]}"`);
    args[key] = argv[i + 1];
  }
  for (const k of REQUIRED_ARGS) if (!args[k]) fail(`missing --${k}`);
  if (!VERSION_RE.test(args["tools-version"])) fail(`--tools-version must be x.y.z`);
  for (const k of ["extension", "tools", "docs"]) {
    if (!existsSync(args[k]) || !statSync(args[k]).isDirectory()) fail(`--${k} is not a folder: ${args[k]}`);
  }
  return args;
}

// One tree's entries (from releaseTrees: { name, path }), without the state file itself wherever --out points.
function treeFiles(list, excludeAbs) {
  return list.filter((e) => e.name.split("/").pop() !== DEFAULT_OUT && resolve(e.path) !== excludeAbs);
}

function hashTree(list, excludeAbs) {
  const files = treeFiles(list, excludeAbs);
  const h = createHash(HASH_ALGORITHM);
  for (const { name: rel, path } of files) {
    const bytes = readFileSync(path);
    h.update(rel + FIELD_SEPARATOR + bytes.length + FIELD_SEPARATOR, "utf8");
    h.update(bytes);
  }
  return { hash: h.digest("hex"), files: files.length };
}

function readManifest(extRoot) {
  const path = join(extRoot, MANIFEST_FILE);
  if (!existsSync(path)) fail(`no ${MANIFEST_FILE} in ${extRoot}`);
  try { return JSON.parse(readFileSync(path, "utf8")); } catch (e) { return fail(`${MANIFEST_FILE}: ${e.message}`); }
}

function docsVersion(docsRoot) {
  const path = join(docsRoot, CHANGELOG_FILE);
  if (!existsSync(path)) fail(`no ${CHANGELOG_FILE} in ${docsRoot}`);
  const m = CHANGELOG_VERSION_RE.exec(readFileSync(path, "utf8"));
  if (!m) fail(`${CHANGELOG_FILE} has no "## x.y.z" heading`);
  return m[1];
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const problems = guardRelease({ extension: resolve(args.extension), docs: resolve(args.docs), tools: resolve(args.tools) });
  if (problems.length) fail(`release trees not as declared (tools/package-release.mjs):\n  ${problems.join("\n  ")}`);
  const outAbs = resolve(args.out || DEFAULT_OUT);
  const manifest = readManifest(args.extension);
  if (!VERSION_RE.test(manifest.version || "")) fail(`manifest version "${manifest.version}" is not x.y.z`);

  const shippedPermissions = {};
  for (const k of PERMISSION_KEYS) shippedPermissions[k] = Array.isArray(manifest[k]) ? [...manifest[k]].sort() : [];

  const roots = { extension: resolve(args.extension), tools: resolve(args.tools), docs: resolve(args.docs) };
  const trees = releaseTrees(roots);
  const state = {
    extension: { ...hashTree(trees.extension, outAbs), version: manifest.version, shippedPermissions },
    tools:     { ...hashTree(trees.tools, outAbs),         version: args["tools-version"] },
    docs:      { ...hashTree(trees.docs, outAbs),           version: docsVersion(args.docs) }
  };
  // Same key order as earlier state files: hash, version, files[, shippedPermissions].
  const ordered = {};
  for (const [name, a] of Object.entries(state)) {
    ordered[name] = { hash: a.hash, version: a.version, files: a.files, ...(a.shippedPermissions ? { shippedPermissions: a.shippedPermissions } : {}) };
  }
  writeFileSync(outAbs, JSON.stringify(ordered, null, JSON_INDENT) + "\n");
  console.log(`wrote ${outAbs}: extension ${ordered.extension.version} (${ordered.extension.files} files), ` +
    `tools ${ordered.tools.version} (${ordered.tools.files}), docs ${ordered.docs.version} (${ordered.docs.files})`);
}

main();
