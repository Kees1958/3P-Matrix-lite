#!/usr/bin/env node
// ── tools/rebuild-host-list.mjs ──────────────────────────────────────────────────
// Rebuilds lib/downloadsentinel/util/HostList.default.js — the merged, deduplicated host-risk table
// (HaGeZi DynDNS + HaGeZi Badware Hoster + Kees1958 "Suspicious websites") that feeds both
// core/site-scorer.js's site-visit check and core/download-guard.js's download check.
//
// 4.5.1 audit gap (C39a/C27): this list WAS registered in data-sources.json but had never actually
// been rebuilt by anything in THIS project's tools — the only script that did it,
// DownloadSentinel's own tools/update-lists.mjs, hardcodes an EXT_ROOT = REPO_ROOT/EXTENSION
// sibling-folder layout (its own standalone repo's shape) that matches neither the DS tools artifact
// itself (no EXTENSION/ tree ships in it) nor 3P-Matrix's real layout (lib/downloadsentinel/{util,...}).
// Per the user's explicit "don't touch DS" instruction, that script is left exactly as it is — this is
// a NEW, independent script, native to this project, that ports its merge logic (C21: same method,
// not reinvented) against 3P-Matrix's own files and own import paths.
// (5.0.9: DownloadSentinel 3.6.0 moved to the repo layout — its update-lists.mjs now builds DS's own data/ from the
// repo root; it still does not know lib/downloadsentinel/, so this script stays the one for 3P Matrix's copy.)
//
// Method (ported from DownloadSentinel tools/update-lists.mjs, same scores/sources):
//   1. Read the three raw lists (cached under tools/lists-raw/, or re-fetch with --fetch).
//   2. Drop any domain already covered by this extension's OWN hand-curated modules
//      (lib/downloadsentinel/util/SuspiciousDomains.js, RiskyHostingSites.js) — "existing entries win
//      on overlap, no double counting" (same rule DS's own tool applies).
//   3. Union the rest; on a cross-list collision keep the worst (highest) score, combine source tags.
//   4. Write lib/downloadsentinel/util/HostList.default.js in the shared precompiled list-module
//      format (4.5.4 — list-modules.mjs; the runtime module HostList.js parses it on first lookup).
//   5. Record the rebuild in data-sources.json (same convention as update-top-sites.mjs).
//
// Usage:  node rebuild-host-list.mjs [--extension ../3P-Matrix] [--fetch]
//         Without --fetch, reads the cached raw files in tools/lists-raw/ (list-modules.mjs readRawSource).
// Exit:   0 = written · 1 = refused (sanity guard) · 2 = did not run (download/parse/folder)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { LIB_UTIL, FETCH_FLAG, writeListModule, recordList, readRawSource, today } from "./list-modules.mjs";
import { defaultRoots } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, REFUSED: 1, DID_NOT_RUN: 2 });
const LIST_ID = "host-list";
const DEFAULT_EXTENSION = defaultRoots(HERE).extension;   // 5.0.9: repo root, or ../3P-Matrix in the release layout (repo-layout.mjs)
const MODULE_NAME = "HostList";
const MIN_RAW_BYTES = 500;                           // guard: refuse an empty/error-page raw file
const MIN_PER_LIST = 50;                             // guard: refuse a truncated/format-changed download

// Per-list source + base score — identical to DownloadSentinel tools/update-lists.mjs's SOURCES.
const SOURCES = Object.freeze({
  HAGEZI_DYNDNS:   { url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
                      rawFile: "hagezi-dyndns.txt", tag: "HaGeZi-DynDNS", score: 60, minBytes: MIN_RAW_BYTES },
  HAGEZI_HOSTER:   { url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt",
                      rawFile: "hagezi-hoster.txt", tag: "HaGeZi-Hoster", score: 65, minBytes: MIN_RAW_BYTES },
  KEES_SUSPICIOUS: { url: "https://raw.githubusercontent.com/Kees1958/W3C_annual_most_used_survey_blocklist/refs/heads/master/Suspicious%20websites.txt",
                      rawFile: "kees-suspicious.txt", tag: "Kees-Suspicious", score: 50, minBytes: MIN_RAW_BYTES },
});
const KEES_RULE_RE = /^\|\|([a-z0-9.-]+)\^\$script,subdocument,websocket,third-party$/i;

function didNotRun(msg) { console.error(`rebuild-host-list: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function refuse(msg) { console.error(`rebuild-host-list: REFUSED — ${msg}`); process.exit(EXIT.REFUSED); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
const SHOULD_FETCH = process.argv.includes(FETCH_FLAG);

function parseHageziOnlyDomains(text) {
  const domains = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    domains.push(line.toLowerCase());
  }
  return domains;
}

function parseKeesSuspicious(text) {
  const domains = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[")) continue;
    const m = KEES_RULE_RE.exec(line);
    if (m) domains.push(m[1].toLowerCase());
  }
  return domains;
}

async function readRaw(source) {
  try { return (await readRawSource(source, { fetch: SHOULD_FETCH })).toString("utf8"); }
  catch (e) { didNotRun(e.message); }
  return "";                                         // unreachable (didNotRun exits)
}

function buildMergedList(listResults, isAlreadyCovered) {
  const merged = new Map();
  const stats = {};
  for (const { sourceKey, domains } of listResults) {
    const source = SOURCES[sourceKey];
    let newCount = 0, coveredCount = 0;
    for (const domain of domains) {
      if (isAlreadyCovered(domain)) { coveredCount++; continue; }
      newCount++;
      const existing = merged.get(domain);
      if (!existing) merged.set(domain, { score: source.score, sources: new Set([source.tag]) });
      else { existing.sources.add(source.tag); existing.score = Math.max(existing.score, source.score); }
    }
    stats[sourceKey] = { total: domains.length, new: newCount, alreadyCovered: coveredCount };
  }
  return { merged, stats };
}

function toTable(merged) {
  const obj = {};
  for (const [domain, { score, sources }] of [...merged.entries()].sort(([x], [y]) => x.localeCompare(y))) {
    obj[domain] = { score, source: [...sources].sort().join("+") };
  }
  return obj;
}

const ABOUT = Object.freeze([
  "Merged, deduplicated host-risk table: HaGeZi DynDNS + HaGeZi Badware Hoster + Kees1958",
  "\"Suspicious websites\" (risk score only, never a block). Entries already covered by this",
  "extension's own SuspiciousDomains.js / RiskyHostingSites.js are excluded (those modules already",
  "score them, usually with more nuance — no double counting)."
]);

async function main() {
  const ext = resolve(arg("extension") || DEFAULT_EXTENSION);
  if (!existsSync(join(ext, "manifest.json"))) didNotRun(`not an extension folder: ${ext}`);
  let SuspiciousDomains, RiskyHostingSites;
  try {
    ({ SuspiciousDomains } = await import(pathToFileURL(join(ext, LIB_UTIL, "SuspiciousDomains.js")).href));
    ({ RiskyHostingSites } = await import(pathToFileURL(join(ext, LIB_UTIL, "RiskyHostingSites.js")).href));
  } catch (e) { didNotRun(`cannot import the extension's SuspiciousDomains/RiskyHostingSites: ${e.message}`); }

  const isAlreadyCovered = (domain) => SuspiciousDomains.lookup(domain) !== null || RiskyHostingSites.lookup(domain) !== null;

  const dyndnsText = await readRaw(SOURCES.HAGEZI_DYNDNS);
  const hosterText = await readRaw(SOURCES.HAGEZI_HOSTER);
  const keesText   = await readRaw(SOURCES.KEES_SUSPICIOUS);

  const dyndnsDomains = parseHageziOnlyDomains(dyndnsText);
  const hosterDomains = parseHageziOnlyDomains(hosterText);
  const keesDomains   = parseKeesSuspicious(keesText);

  for (const [name, domains] of [["HaGeZi-DynDNS", dyndnsDomains], ["HaGeZi-Hoster", hosterDomains], ["Kees-Suspicious", keesDomains]]) {
    if (domains.length < MIN_PER_LIST) refuse(`${name}: parsed only ${domains.length} domains — expected hundreds+ (format may have changed upstream)`);
  }

  const { merged, stats } = buildMergedList([
    { sourceKey: "HAGEZI_DYNDNS",   domains: dyndnsDomains },
    { sourceKey: "HAGEZI_HOSTER",   domains: hosterDomains },
    { sourceKey: "KEES_SUSPICIOUS", domains: keesDomains },
  ], isAlreadyCovered);

  for (const [key, s] of Object.entries(stats)) {
    console.log(`  ${SOURCES[key].tag.padEnd(16)} ${s.total} total  →  ${s.alreadyCovered} already covered  →  ${s.new} new`);
  }
  console.log(`  UNION (deduplicated)   ${merged.size}`);

  const entries = writeListModule(ext, { name: MODULE_NAME, tool: "rebuild-host-list.mjs", cadence: "once per minor release",
                                         about: ABOUT, data: toTable(merged), generatedAt: new Date().toISOString() });
  let versionMinor;
  try { versionMinor = recordList(LIST_ID, ext, { sourceRelease: `merge generated ${today()}`, entries, tool: "rebuild-host-list.mjs" }); }
  catch (e) { didNotRun(e.message); }
  console.log(`\nrebuild-host-list: wrote ${MODULE_NAME}.default.js — ${entries} domains, recorded for ${versionMinor}`);
  process.exit(EXIT.OK);
}

await main();
