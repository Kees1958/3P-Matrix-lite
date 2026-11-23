#!/usr/bin/env node
// ── tools/build-curated-lists.mjs ────────────────────────────────────────────────
// Rebuilds the hand-curated (no upstream feed) list modules in lib/downloadsentinel/util/ from their
// single source of truth in this tools package, tools/lists-src/<Name>.json:
//   SuspiciousDomains   { host: score }                         — download/site risk scores
//   SuspiciousTlds      { tld: score }                          — abused TLD risk scores
//   RiskyHostingSites   [{ host, score, exact }]                — user-upload / file-sharing platforms
//   UrlShorteners       [host]                                  — informational signal only
//
// 4.5.4: native to this project (DownloadSentinel keeps the same lists in its own data/*.json;
// lists-src/ was seeded from the 4.5.3 shipped data, so the content is unchanged). To change a list: edit
// its JSON in lists-src/, run this tool, then run rebuild-host-list.mjs (HostList skips hosts these two
// score already: SuspiciousDomains, RiskyHostingSites).
//
// Every source is validated against its shape before anything is written — a malformed edit never ships.
//
// Usage:  node build-curated-lists.mjs [--extension ../3P-Matrix]
// Exit:   0 = written · 1 = refused (a source failed validation) · 2 = did not run (folder / register)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeListModule, recordList } from "./list-modules.mjs";
import { defaultRoots } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, REFUSED: 1, DID_NOT_RUN: 2 });
const DEFAULT_EXTENSION = defaultRoots(HERE).extension;   // 5.0.9: repo root, or ../3P-Matrix in the release layout (repo-layout.mjs)
const SOURCE_DIR = join(HERE, "lists-src");
const TOOL = "build-curated-lists.mjs";
const CADENCE = "curated — re-run after editing tools/lists-src";
const SCORE_MIN = -100, SCORE_MAX = 100;                     // risk scores (negative = trust bonus)
const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const TLD_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

const isScore = (v) => Number.isInteger(v) && v >= SCORE_MIN && v <= SCORE_MAX;
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// One entry per curated list: register id, module name, shape check (returns a problem or null), header.
const LISTS = Object.freeze([
  { id: "suspicious-domains", name: "SuspiciousDomains",
    check: (d) => !isPlainObject(d) ? "not an object" : Object.entries(d).find(([h, s]) => !HOST_RE.test(h) || !isScore(s))?.[0] ?? null,
    about: ["Risk scores (host → score) for domains frequently used in malware delivery.",
            "Curated: tools/lists-src/SuspiciousDomains.json."] },
  { id: "suspicious-tlds", name: "SuspiciousTlds",
    check: (d) => !isPlainObject(d) ? "not an object" : Object.entries(d).find(([t, s]) => !TLD_RE.test(t) || !isScore(s))?.[0] ?? null,
    about: ["Risk scores (TLD → score) for TLDs frequently abused in phishing, spam and malware delivery.",
            "Curated: tools/lists-src/SuspiciousTlds.json."] },
  { id: "risky-hosting-sites", name: "RiskyHostingSites",
    check: (d) => !Array.isArray(d) ? "not an array"
      : d.find((e) => !isPlainObject(e) || !HOST_RE.test(e.host) || !isScore(e.score) || typeof e.exact !== "boolean")?.host ?? null,
    about: ["User-upload / file-sharing platforms: [{ host, score, exact }] (exact false = host or any subdomain).",
            "Curated: tools/lists-src/RiskyHostingSites.json."] },
  { id: "url-shorteners", name: "UrlShorteners",
    check: (d) => !Array.isArray(d) ? "not an array" : d.find((h) => !HOST_RE.test(h)) ?? null,
    about: ["Well-known URL-shortener registered domains — informational signal, never a block on its own.",
            "Curated: tools/lists-src/UrlShorteners.json."] }
]);

function didNotRun(msg) { console.error(`build-curated-lists: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function refuse(msg) { console.error(`build-curated-lists: REFUSED — ${msg}`); process.exit(EXIT.REFUSED); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

const ext = resolve(arg("extension") || DEFAULT_EXTENSION);
if (!existsSync(join(ext, "manifest.json"))) didNotRun(`not an extension folder: ${ext}`);

// Guard: read and validate ALL sources first; write only when every one is valid.
const loaded = LISTS.map((list) => {
  const file = join(SOURCE_DIR, `${list.name}.json`);
  let data;
  try { data = JSON.parse(readFileSync(file, "utf8")); } catch (e) { didNotRun(`cannot read ${file}: ${e.message}`); }
  const problem = list.check(data);
  if (problem !== null) refuse(`${list.name}.json: invalid entry "${problem}"`);
  return { list, data };
});

const generatedAt = new Date().toISOString();
for (const { list, data } of loaded) {
  const entries = writeListModule(ext, { name: list.name, tool: TOOL, cadence: CADENCE, about: list.about, data, generatedAt });
  try { recordList(list.id, ext, { sourceRelease: "curated", entries }); } catch (e) { didNotRun(e.message); }
  console.log(`build-curated-lists: ${list.name} — ${entries} entries`);
}
process.exit(EXIT.OK);
