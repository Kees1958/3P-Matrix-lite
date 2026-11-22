// ── tools/list-modules.mjs ───────────────────────────────────────────────────────
// THE one implementation of the shipped list-module format (4.5.4, perf P4), shared by every tool that
// writes or reads a lib/downloadsentinel/util/<Name>.default.js list:
//   update-psl.mjs · update-domain-age-lists.mjs · gen-brands-data.mjs · build-curated-lists.mjs ·
//   rebuild-host-list.mjs · update-top-sites.mjs   (writers)
//   update-top-sites.mjs · check-list-freshness.mjs (readers)
//
// Precompiled format: each list ships as ONE JSON string constant, `export const <Name>DefaultJson`.
// Why: the service worker evaluates every statically imported module at every start (dynamic import()
// is not supported in extension service workers). A string literal is scanned as a single token, so
// loading the module costs almost nothing; the runtime wrapper (util/<Name>.js) turns it into objects
// with JSON.parse — V8's fastest way to build them — on its FIRST lookup only (util/LazyJson.js).
//
// Public interface:
//   LIB_UTIL                                  — lib folder of the list modules (relative to the extension)
//   listModulePath(ext, name)                 — absolute path of <Name>.default.js
//   exportName(name)                          — "<Name>DefaultJson"
//   renderListModule({ name, tool, cadence, about, data, generatedAt }) — file text
//   writeListModule(ext, spec)                — renders + writes; returns the entry count
//   readListData(ext, name)                   — Promise<parsed data> of a shipped list module
//   countEntries(name, data)                  — the entry count recorded in data-sources.json
//   recordList(id, ext, fields)               — updates data-sources.json for list `id` (version stamp)
//   readRawSource(source, { fetch })          — Promise<Buffer>: the cached upstream file in lists-raw/,
//                                               re-downloaded (and the cache replaced) first with fetch=true;
//                                               an ON-DEMAND source (cache: false) is always downloaded,
//                                               held in memory only, and never written to lists-raw/
//   FETCH_FLAG                                — "--fetch", the one command-line switch for that
//   today()                                   — "YYYY-MM-DD" (register dates)
//   PSL_SOURCE                                — the one Public Suffix List snapshot (lists-raw/)
//   snapshotId(buf)                           — "snapshot sha256:<12 hex>" of a raw file that carries no
//                                               release name (PSL): lists built from the same snapshot
//                                               record the same id (checked by check-list-freshness.mjs)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
export const LIB_UTIL = join("lib", "downloadsentinel", "util");
export const REGISTER_FILE = join(HERE, "data-sources.json");
const MODULE_SUFFIX = ".default.js";
const EXPORT_SUFFIX = "DefaultJson";
const VERSION_MINOR_RE = /^(\d+\.\d+)/;
const DATE_LENGTH = 10;                                    // "YYYY-MM-DD" of an ISO timestamp
const JSON_INDENT = 2;
const SNAPSHOT_HASH = "sha256";
const SNAPSHOT_ID_LENGTH = 12;                              // hex chars of the snapshot fingerprint
export const RAW_DIR = join(HERE, "lists-raw");             // cached upstream files (one per source)
export const FETCH_FLAG = "--fetch";
// The ONE Public Suffix List snapshot: read by update-psl.mjs (owner — refreshes it with --fetch) and by
// update-domain-age-lists.mjs (PRIVATE section) — both shipped PSL-derived lists come from one release.
export const PSL_SOURCE = Object.freeze({ url: "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat",
                                          rawFile: "public_suffix_list.dat", tag: "Public Suffix List", minBytes: 200000 });

// Lists whose entry count is not simply "array length / key count" (one place — DS's CUSTOM_COUNTERS).
const CUSTOM_COUNTERS = Object.freeze({
  PublicSuffixList: (d) => d.rules.length + d.wildcardRules.length + d.exceptions.length,
  TopSitesFilter:   (d) => d.entryCount
});

export function today() { return new Date().toISOString().slice(0, DATE_LENGTH); }   // "YYYY-MM-DD"

export function listModulePath(ext, name) { return join(ext, LIB_UTIL, name + MODULE_SUFFIX); }
export function exportName(name) { return name + EXPORT_SUFFIX; }

export function countEntries(name, data) {
  if (CUSTOM_COUNTERS[name]) return CUSTOM_COUNTERS[name](data);
  return Array.isArray(data) ? data.length : Object.keys(data).length;
}

// about: string[] — description lines for the header (what the list is, where it comes from).
export function renderListModule({ name, tool, cadence, about, data, generatedAt }) {
  const body = about.map((line) => ` * ${line}`.trimEnd()).join("\n");
  return `"use strict";

/**
 * ${name}${MODULE_SUFFIX} — GENERATED FILE. Do not hand-edit; rebuild with
 * 3P-Matrix-tools/${tool} (${cadence} — data-sources.json).
 *
${body}
 * Content: ${countEntries(name, data)} entries.
 * Generated: ${generatedAt}
 *
 * Precompiled format (3P Matrix 4.5.4): the data is ONE JSON string, parsed by util/${name}.js on its
 * first lookup (util/LazyJson.js) — never at service-worker start. Format: tools/list-modules.mjs.
 */
export const ${exportName(name)} = ${JSON.stringify(JSON.stringify(data))};
`;
}

export function writeListModule(ext, spec) {
  writeFileSync(listModulePath(ext, spec.name), renderListModule(spec));
  return countEntries(spec.name, spec.data);
}

export async function readListData(ext, name) {
  const mod = await import(pathToFileURL(listModulePath(ext, name)).href);
  const text = mod[exportName(name)];
  if (typeof text !== "string") throw new Error(`${name}${MODULE_SUFFIX} has no ${exportName(name)} string — not in the list-module format`);
  return JSON.parse(text);
}

// Records a rebuild in data-sources.json: entries, the extension's major.minor, date, tool, plus `fields`.
export function recordList(id, ext, fields) {
  const registerFile = JSON.parse(readFileSync(REGISTER_FILE, "utf8"));
  const register = registerFile.lists && registerFile.lists[id];
  if (!register) throw new Error(`no "${id}" entry in data-sources.json`);
  const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
  const versionMinor = (VERSION_MINOR_RE.exec(manifest.version) || [])[1] || manifest.version;
  Object.assign(register, fields, { updatedForVersion: versionMinor, updatedAt: today() });
  writeFileSync(REGISTER_FILE, JSON.stringify(registerFile, null, JSON_INDENT) + "\n");
  return versionMinor;
}

// source = { url, rawFile, tag, minBytes, cache? } — rawFile is the cache name in lists-raw/; minBytes guards
// against a truncated download or an error page being cached or used. Throws on any problem.
// cache: false (4.6.1) = ON DEMAND: too large to keep in the tools package (CrUX top 1M ≈ 9 MB) — always
// downloaded, held in memory only, and any stale copy in lists-raw/ is removed (storage guard).
export async function readRawSource(source, { fetch: refetch = false } = {}) {
  const dest = join(RAW_DIR, source.rawFile);
  const onDemand = source.cache === false;
  if (onDemand) {
    clearRawCache(dest);                                    // guard: never leave (or re-package) a stale copy
    return downloadRawSource(source);
  }
  if (refetch) {
    const buf = await downloadRawSource(source);
    mkdirSync(RAW_DIR, { recursive: true });
    writeFileSync(dest, buf);
    return buf;
  }
  if (!existsSync(dest)) throw new Error(`${source.tag}: no cached raw file at ${dest} — run with ${FETCH_FLAG}`);
  const buf = readFileSync(dest);
  if (buf.length < source.minBytes) throw new Error(`${source.tag}: cached raw file implausibly small (${buf.length} bytes)`);
  return buf;
}

// Downloads one upstream file into memory; the size guard applies before anything uses it.
async function downloadRawSource(source) {
  let res;
  try { res = await fetch(source.url); }
  catch (e) { throw new Error(`${source.tag}: download failed (${e.message}) from ${source.url} — on-demand sources need network access`); }
  if (!res.ok) throw new Error(`${source.tag}: download failed (HTTP ${res.status}) from ${source.url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length < source.minBytes) throw new Error(`${source.tag}: download implausibly small (${buf.length} bytes)`);
  return buf;
}

// Removes a cached raw file if present (an on-demand source must not be kept in lists-raw/).
function clearRawCache(dest) {
  if (existsSync(dest)) rmSync(dest, { force: true });
}

export function snapshotId(buf) {
  return `snapshot ${SNAPSHOT_HASH}:${createHash(SNAPSHOT_HASH).update(buf).digest("hex").slice(0, SNAPSHOT_ID_LENGTH)}`;
}
