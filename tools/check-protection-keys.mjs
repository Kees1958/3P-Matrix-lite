#!/usr/bin/env node
// ── tools/check-protection-keys.mjs ──────────────────────────────────────────────
// Static check for the protections registry (audit 2026-10-19, finding 8; C25):
//   1. data/protections.js: PROTECTION_KEY lists exactly the registry's keys (no extra, none
//      missing, no duplicates); display numbers `num` are unique, run 1 … N without gaps and (5.0.7) follow
//      display order (PROTECTION_GROUPS order, then row order).
//   2. Code refers to a protection only through the enum: a quoted protection key anywhere outside
//      data/protections.js fails (a typo in a quoted key silently disabled a protection before).
//   3. Every PROTECTION_KEY.<NAME> used in the code exists in the enum.
// All expected values come from the extension's own registry (C39a).
//
// Usage:  node check-protection-keys.mjs --extension ../3P-Matrix
// Exit:   0 = pass · 1 = problem found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const REGISTRY_FILE = "data/protections.js";
const SCAN_DIRS = Object.freeze(["background.js", "core", "data", "ui", "util"]);   // first-party code (lib/ is vendored)
const FIRST_NUM = 1;
const ENUM_REF_RE = /PROTECTION_KEY\.([A-Z0-9_]+)/g;

function didNotRun(msg) { console.error(`check-protection-keys: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function listJs(path) {
  if (!existsSync(path)) return [];
  if (statSync(path).isFile()) return path.endsWith(".js") ? [path] : [];
  return readdirSync(path).flatMap((n) => listJs(join(path, n)));
}
function lineOf(text, index) { return text.slice(0, index).split("\n").length; }

const root = arg("extension");
if (!root || !existsSync(join(root, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
let R;
try { R = await import(pathToFileURL(resolve(root, REGISTRY_FILE)).href); }
catch (e) { didNotRun(`cannot import ${REGISTRY_FILE}: ${e.message}`); }
if (!R.PROTECTION_KEY || !Array.isArray(R.PROTECTIONS)) didNotRun(`${REGISTRY_FILE} lacks PROTECTION_KEY or PROTECTIONS`);

const problems = [];
const enumValues = Object.values(R.PROTECTION_KEY);
const registryKeys = R.PROTECTIONS.map((p) => p.key);
for (const k of registryKeys) if (!enumValues.includes(k)) problems.push(`${REGISTRY_FILE}: registry key "${k}" missing from PROTECTION_KEY`);
for (const k of enumValues) if (!registryKeys.includes(k)) problems.push(`${REGISTRY_FILE}: PROTECTION_KEY value "${k}" has no registry row`);
if (new Set(registryKeys).size !== registryKeys.length) problems.push(`${REGISTRY_FILE}: duplicate registry key`);
// 5.1.0: only numbered rows (switchable, on a numbered tab — R.isNumbered) carry `num`; every other row carries none.
const numbered = R.PROTECTIONS.filter((p) => R.isNumbered(p));
for (const p of R.PROTECTIONS) if (!R.isNumbered(p) && p.num !== undefined) problems.push(`${REGISTRY_FILE}: "${p.key}" is not numbered (no checkbox or an unnumbered tab) but has num ${p.num}`);
const nums = numbered.map((p) => p.num).sort((a, b) => a - b);
nums.forEach((n, i) => { if (n !== FIRST_NUM + i) problems.push(`${REGISTRY_FILE}: display numbers not ${FIRST_NUM}…${numbered.length} without gaps (got ${nums.join(",")})`); });
// 5.1.0: `requires` one level deep, master never from a higher level; `switchable: false` needs a master.
for (const p of R.PROTECTIONS) {
  const m = p.requires ? R.PROTECTION_BY_KEY[p.requires] : null;
  if (p.requires && !m) problems.push(`${REGISTRY_FILE}: "${p.key}" requires unknown "${p.requires}"`);
  if (m && (m.requires || m.fromLevel > p.fromLevel)) problems.push(`${REGISTRY_FILE}: "${p.key}" requires "${m.key}", which has a master itself or starts at a higher level`);
  if (p.switchable === false && !m) problems.push(`${REGISTRY_FILE}: "${p.key}" has no checkbox (switchable: false) but no master (requires)`);
}
const grouped = new Set(R.PROTECTION_GROUPS.flatMap(R.protectionsInGroup).map((p) => p.key));
for (const p of R.PROTECTIONS) if (!grouped.has(p.key)) problems.push(`${REGISTRY_FILE}: "${p.key}" belongs to no PROTECTION_GROUPS entry (never shown)`);
// 5.0.7: the numbers must also run in DISPLAY order — PROTECTION_GROUPS in their own order, each with its rows
// in registry order (data/protections.js protectionsInGroup, which core/view-models.js renders). A row filed at the wrong place in the
// table otherwise ships a level-2 list reading "…, 17, 30" (user report, 5.0.5).
// The order comes from the registry's own PROTECTIONS_IN_DISPLAY_ORDER — the list the UI renders (C21), never
// rebuilt here.
if (Array.isArray(R.PROTECTIONS_IN_DISPLAY_ORDER)) {
  const shown = R.PROTECTIONS_IN_DISPLAY_ORDER;
  shown.forEach((p, i) => { if (p.num !== FIRST_NUM + i) problems.push(`${REGISTRY_FILE}: "${p.key}" is shown at position ${FIRST_NUM + i} but numbered ${p.num} — numbers must follow group order, then row order`); });
  if (shown.length !== numbered.length) problems.push(`${REGISTRY_FILE}: ${numbered.length - shown.length} numbered protection(s) missing from the display order`);
} else didNotRun(`${REGISTRY_FILE} lacks PROTECTIONS_IN_DISPLAY_ORDER`);

const quoted = new RegExp(`(["'\`])(${enumValues.join("|")})\\1`, "g");
for (const path of SCAN_DIRS.flatMap((d) => listJs(join(root, d)))) {
  const rel = relative(root, path).split("\\").join("/");
  const text = readFileSync(path, "utf8");
  if (rel !== REGISTRY_FILE) {
    for (const m of text.matchAll(quoted)) problems.push(`${rel}:${lineOf(text, m.index)}: quoted protection key ${m[0]} — use PROTECTION_KEY.*`);
  }
  for (const m of text.matchAll(ENUM_REF_RE)) {
    if (!(m[1] in R.PROTECTION_KEY)) problems.push(`${rel}:${lineOf(text, m.index)}: PROTECTION_KEY.${m[1]} does not exist`);
  }
}

if (problems.length) {
  console.error(`check-protection-keys: FAIL — ${[...new Set(problems)].length} problem(s):`);
  for (const p of new Set(problems)) console.error("  " + p);
  process.exit(EXIT.FOUND);
}
console.log(`check-protection-keys: PASS — ${registryKeys.length} protections (${numbered.length} numbered ${FIRST_NUM}…${numbered.length}), enum complete, no quoted keys`);
process.exit(EXIT.OK);
