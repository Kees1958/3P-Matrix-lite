#!/usr/bin/env node
// ── tools/check-list-freshness.mjs ───────────────────────────────────────────────
// Release gate for the shipped third-party data lists (data-sources.json):
//   • updateOn "minor": the list must have been rebuilt for the manifest's major.minor version —
//     moving 4.2 → 4.3 fails until the list's tool has run; a patch (4.3.1 → 4.3.2) never does.
//   • the list file exists, and its entry count matches the register (no hand-edited file, no
//     register entry that drifted from what ships).
//   • 4.5.4 completeness: EVERY shipped list module (lib/downloadsentinel/util/*.default.js) is registered
//     — so no list can ship without a tool in this package that rebuilds it; each one is in the
//     precompiled list-module format (list-modules.mjs) and its parsed entry count matches the register.
//   • 4.5.4 sameSnapshotAs: two lists built from one raw snapshot (public-suffix-list ↔ platform-suffixes)
//     record the same sourceRelease — one PSL release for both.
// Offline by design: it never downloads; it says which tool to run.
//
// Usage:  node check-list-freshness.mjs --extension ../3P-Matrix
// Exit:   0 = all fresh · 1 = a list needs its update · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { LIB_UTIL, readListData, countEntries } from "./list-modules.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const REGISTER_FILE = join(HERE, "data-sources.json");
const UPDATE_ON = Object.freeze({ MINOR: "minor" });
const VERSION_MINOR_RE = /^(\d+\.\d+)/;
const LIST_MODULE_RE = /^([A-Za-z]+)\.default\.js$/;     // lib list module file name → module name

function didNotRun(msg) { console.error(`check-list-freshness: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

const ext = arg("extension") ? resolve(arg("extension")) : null;
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
let register, manifest;
try { register = JSON.parse(readFileSync(REGISTER_FILE, "utf8")); } catch (e) { didNotRun(`cannot read data-sources.json: ${e.message}`); }
try { manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8")); } catch (e) { didNotRun(`cannot read manifest.json: ${e.message}`); }
const versionMinor = (VERSION_MINOR_RE.exec(manifest.version || "") || [])[1];
if (!versionMinor) didNotRun(`manifest version "${manifest.version}" is not x.y[.z]`);

const problems = [];
const lists = Object.entries(register.lists || {});
if (!lists.length) didNotRun("data-sources.json lists no data lists");
// Completeness: every shipped list module has a register entry (and therefore a tool).
const registeredFiles = new Set(lists.map(([, l]) => l.file));
for (const name of readdirSync(join(ext, LIB_UTIL)).filter((f) => LIST_MODULE_RE.test(f))) {
  const rel = join(LIB_UTIL, name).split("\\").join("/");
  if (!registeredFiles.has(rel)) problems.push(`${rel}: shipped list with no data-sources.json entry — add it and the tool that rebuilds it`);
}

for (const [id, list] of lists) {
  const file = join(ext, list.file || "");
  if (!list.file || !existsSync(file)) { problems.push(`${id}: file missing (${list.file})`); continue; }
  const mod = LIST_MODULE_RE.exec(basename(file));
  if (mod) {
    let count = null;
    try { count = countEntries(mod[1], await readListData(ext, mod[1])); }
    catch (e) { problems.push(`${id}: ${list.file} unreadable (${e.message}) — rebuild with ${list.tool}`); }
    if (count !== null && count !== list.entries) problems.push(`${id}: ${list.file} has ${count} entries, register says ${list.entries} — rebuild with ${list.tool}`);
  }
  if (!list.updatedAt) problems.push(`${id}: never rebuilt by ${list.tool} — run it`);
  const twin = list.sameSnapshotAs && register.lists[list.sameSnapshotAs];
  if (list.sameSnapshotAs && (!twin || twin.sourceRelease !== list.sourceRelease)) {
    problems.push(`${id}: built from a different snapshot than ${list.sameSnapshotAs} (${list.sourceRelease} ≠ ${twin ? twin.sourceRelease : "missing"}) — rebuild both`);
  }
  if (list.updateOn === UPDATE_ON.MINOR && list.updatedForVersion !== versionMinor) {
    problems.push(`${id}: last rebuilt for ${list.updatedForVersion}, extension is ${manifest.version} — minor release: run ${list.tool}`);
  }
}

if (problems.length) {
  console.error(`check-list-freshness: FAIL — ${problems.length} list(s) need attention:`);
  for (const p of problems) console.error("  " + p);
  process.exit(EXIT.FOUND);
}
console.log(`check-list-freshness: PASS — ${lists.length} list(s) current for ${versionMinor} (${lists.map(([id, l]) => `${id} ${l.sourceRelease}`).join(", ")})`);
process.exit(EXIT.OK);
