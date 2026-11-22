#!/usr/bin/env node
// ── tools/export-whitelist.mjs ───────────────────────────────────────────────────
// Writes the built-in whitelist (data/builtin-domains.js — the single source) as JSON, so DownloadSentinel
// and uBlock Stripped Dynamic can apply the same review (4.5.6). Derived output: never edit the JSON.
//   { extension, version, generated, categories: { label: [ { host, type, reason } ] }, removed: { host: why } }
//   type: "both" = script + frame allowed, "script" = scripts only, "frame" = frames only.
//
// Usage:  node export-whitelist.mjs --extension ../3P-Matrix [--out builtin-whitelist.json]
// Exit:   0 = written · 2 = did not run
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, DID_NOT_RUN: 2 });
const DEFAULT_OUT = "builtin-whitelist.json";
const JSON_INDENT = 2;

function didNotRun(msg) { console.error(`export-whitelist: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

const ext = arg("extension") ? resolve(arg("extension")) : null;
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
let B, manifest;
try {
  B = await import(pathToFileURL(join(ext, "data/builtin-domains.js")).href);
  manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
} catch (e) { didNotRun(e.message); }

const categories = {};
for (const g of Object.values(B.BUILTIN_GROUP)) categories[g.label] = [];
for (const { host, type, category, reason } of B.BUILTIN_ENTRIES) categories[category].push({ host, type, reason });
const doc = { extension: manifest.name, version: manifest.version, generated: new Date().toISOString(),
              entries: B.BUILTIN_ENTRIES.length, categories, removed: { ...B.BUILTIN_REMOVED } };
const out = resolve(arg("out") || DEFAULT_OUT);
writeFileSync(out, JSON.stringify(doc, null, JSON_INDENT) + "\n");
console.log(`export-whitelist: wrote ${out} — ${doc.entries} entries, ${Object.keys(doc.removed).length} removed`);
process.exit(EXIT.OK);
