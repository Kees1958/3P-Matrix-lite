#!/usr/bin/env node
// ── tools/check-compat-remove.mjs ────────────────────────────────────────────────
// Release gate for backward-compatibility code (4.5.4 — ported idea from DownloadSentinel's
// tools/check-compat-remove.mjs; 3P Matrix's own tag format). Code that only exists to read data written
// by an older version is tagged
//     COMPAT-REMOVE ≥<major>.<minor>          (data/state-storage.js keeps the schedule)
// From that version on the block must be gone. This check FAILS when the extension's manifest version is
// at or past a tag that is still present — so an overdue conversion can never ship unnoticed again
// (4.5.0–4.5.3 shipped three blocks tagged ≥4.5 because nothing checked it).
//
// Scans the first-party extension code and this tools package (a test of removed code goes with it).
// Skips the vendored DownloadSentinel library (lib/downloadsentinel — DS has its own tag format and check).
//
// Usage:  node check-compat-remove.mjs --extension ../3P-Matrix
// Exit:   0 = nothing overdue · 1 = overdue block(s) found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { NON_EXTENSION_DIR_NAMES } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const TAG_RE = /COMPAT-REMOVE\s*≥\s*(\d+)\.(\d+)/g;
const VERSION_RE = /^(\d+)\.(\d+)/;
const SCANNED_EXT = Object.freeze([".js", ".mjs"]);
const SKIP_DIRS = new Set([...NON_EXTENSION_DIR_NAMES, "downloadsentinel"]);   // 5.0.9: in the repo layout the extension folder also holds tools/ and the documents — skipped via repo-layout.mjs.

function didNotRun(msg) { console.error(`check-compat-remove: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

function* files(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (SCANNED_EXT.some((e) => name.endsWith(e))) yield p;
  }
}

const ext = arg("extension") ? resolve(arg("extension")) : null;
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
let version;
try { version = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8")).version || ""; } catch (e) { didNotRun(`cannot read manifest.json: ${e.message}`); }
const v = VERSION_RE.exec(version);
if (!v) didNotRun(`manifest version "${version}" is not x.y[.z]`);
const [major, minor] = [Number(v[1]), Number(v[2])];

const overdue = [];
let pending = 0;
for (const root of [ext, HERE]) {
  for (const file of files(root)) {
    readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      for (const m of line.matchAll(TAG_RE)) {
        const [tagMajor, tagMinor] = [Number(m[1]), Number(m[2])];
        if (major > tagMajor || (major === tagMajor && minor >= tagMinor)) {
          overdue.push(`${relative(dirname(root), file).split(sep).join("/")}:${i + 1}  ${m[0]}`);
        } else pending++;
      }
    });
  }
}

if (overdue.length) {
  console.error(`check-compat-remove: FAIL — ${overdue.length} tagged block(s) overdue for ${version} (delete them, see data/state-storage.js):`);
  for (const o of overdue) console.error("  " + o);
  process.exit(EXIT.FOUND);
}
console.log(`check-compat-remove: PASS — nothing overdue for ${version} (${pending} tag(s) scheduled for later versions)`);
process.exit(EXIT.OK);
