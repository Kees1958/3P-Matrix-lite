#!/usr/bin/env node
// ── tools/check-protection-refs.mjs ──────────────────────────────────────────────
// C25 standing check (5.0.7): code, tests and the README name a protection by its KEY
// (e.g. blockRiskyDownloads), never by its display number. Display numbers change whenever a protection is
// added, removed or moved (4.2, 4.3.x, 4.4.3, 4.6.0, 4.7.0, 4.7.1, 5.0.2, 5.0.5, 5.0.7) and every renumbering
// left typed numbers behind that silently described the wrong protection — the sweep "by meaning" was
// repeated by hand each time and never complete (5.0.7 still found "15–25", "1–16", "9, 15–17, 19").
// A key never changes (it is the storage contract), so a reference by key cannot drift.
//
// Fails on "protection N" / "protections N…" (any case) in every scanned file unless the file is in
// ALLOWLIST with a stated reason. Numbers shown to the USER are derived at render time (ui/derived-text.js,
// C39a) and are not affected by this rule.
//
// Usage:  node check-protection-refs.mjs --extension ../3P-Matrix --docs ../3P-Matrix-docs
// Exit:   0 = pass · 1 = reference by number found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const HERE = dirname(fileURLToPath(import.meta.url));
const NUMBER_REF_RE = /\bprotections?\s+#?\d+/gi;
const FILE_EXTENSIONS = Object.freeze([".js", ".mjs", ".html", ".css", ".md"]);
const SKIP_DIRS = Object.freeze(["lib", "node_modules", "lists-raw", "lists-src"]);   // vendored / generated data
const DOCS_FILES = Object.freeze(["README.md"]);   // the docs that describe CURRENT behaviour; history docs keep their numbers
const MAX_HITS_SHOWN = 40;
// Files allowed to hold display numbers, each with its reason (C25: a new hit fails by default).
const ALLOWLIST = Object.freeze({
  "extension/data/protections.js": "the registry itself: `num` lives here, and its header is the version-tagged renumbering history",
  "tools/check-derived-literals.mjs": "its header quotes historical UI text (\"protection 10\") as the example of the bug class it checks",
  "tools/check-protection-refs.mjs": "this check describes the pattern it rejects"
});

function didNotRun(msg) { console.error(`check-protection-refs: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function listFiles(path) {
  if (!existsSync(path)) return [];
  if (statSync(path).isFile()) return FILE_EXTENSIONS.some((e) => path.endsWith(e)) ? [path] : [];
  return readdirSync(path).flatMap((n) => (SKIP_DIRS.includes(n) ? [] : listFiles(join(path, n))));
}
function lineOf(text, index) { return text.slice(0, index).split("\n").length; }

const ext = arg("extension");
const docs = arg("docs");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
if (!docs || !existsSync(docs)) didNotRun("missing or invalid --docs <folder>");

// Scanned roots, each with the label used in ALLOWLIST and in the report.
const targets = [
  ...listFiles(ext).map((f) => ({ f, label: `extension/${relative(ext, f).split(sep).join("/")}` })),
  ...listFiles(HERE).map((f) => ({ f, label: `tools/${relative(HERE, f).split(sep).join("/")}` })),
  ...DOCS_FILES.map((n) => join(docs, n)).filter((f) => existsSync(f)).map((f) => ({ f, label: `docs/${relative(docs, f)}` }))
];
if (!targets.length) didNotRun("no files to scan");

const hits = [];
for (const { f, label } of targets) {
  if (ALLOWLIST[label]) continue;
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(NUMBER_REF_RE)) hits.push(`${label}:${lineOf(text, m.index)}: "${m[0]}" — name the protection by its key`);
}

if (hits.length) {
  console.log(`check-protection-refs: FAIL — ${hits.length} reference(s) by display number:`);
  hits.slice(0, MAX_HITS_SHOWN).forEach((h) => console.log(`  ${h}`));
  if (hits.length > MAX_HITS_SHOWN) console.log(`  … and ${hits.length - MAX_HITS_SHOWN} more`);
  process.exit(EXIT.FOUND);
}
console.log(`check-protection-refs: PASS — ${targets.length} files, no protection referenced by display number (${Object.keys(ALLOWLIST).length} allowlisted with a reason)`);
process.exit(EXIT.OK);
