#!/usr/bin/env node
// ── tools/update-top-sites.mjs ───────────────────────────────────────────────────
// Rebuilds lib/downloadsentinel/util/TopSitesFilter.default.js — the Bloom filter of the web's most
// popular registered domains used by the look-alike check (LookalikeDomainCheck test 1 + test 3) —
// from the latest Chrome UX Report (CrUX) top-1M origins list, and records the update in data-sources.json.
//
// When: once per MINOR release (4.2 → 4.3), not for patches (4.3.1 → 4.3.2) — check-list-freshness.mjs
// fails the suite on a minor bump until this has run (data-sources.json "updateOn": "minor").
//
// Method (4.3.0 — DownloadSentinel 3.2.0's build-top-sites-filter.mjs, project doc
// DS_ALIGNMENT_lookalike_and_lists.md §3; reproduces DS 3.2.0's shipped filter bit for bit — verified on
// the 202609 list: 80,140 entries):
//   origins with CrUX rank ≤ RANK_CUTOFF → hostname → registered domain with the EXTENSION'S OWN UrlUtils
//   (same PSL as at runtime) → distinct set ∪ every brand website (the extension's own Brands.default.js,
//   as listed) ∪ the shared government suffixes (the extension's own GovSuffixes.default.js — 4.5.4: the
//   former tools/gov-suffixes.json copy is gone, one source; both lists are built by gen-brands-data.mjs)
//   → BloomFilter.sizeFor(n, FALSE_POSITIVE_RATE) → the extension's own BloomFilter.js.
//   Reusing the runtime modules guarantees the bits are queried with the identical hashes (C21).
//   4.2: the whole top 1M (≈ 760,000 domains, 1.2 MB); 4.3.0: top 100,000 + brands + gov (≈ 125 KB).
//
// 4.5.4: writes the shared precompiled list-module format (list-modules.mjs).
// 4.6.1: the CrUX list is fetched ON DEMAND (CRUX_SOURCE.cache = false) — downloaded into memory on every
//   run, never cached in tools/lists-raw/ (the 1M-origin file was ≈ 97 % of the tools package). Needs network.
//
// Usage:  node update-top-sites.mjs [--extension ../3P-Matrix]
// Exit:   0 = written · 1 = refused (sanity guard) · 2 = did not run (download/parse/folder)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { LIB_UTIL, writeListModule, readListData, recordList, readRawSource } from "./list-modules.mjs";
import { defaultRoots } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, REFUSED: 1, DID_NOT_RUN: 2 });
const LIST_ID = "top-sites";
const DEFAULT_EXTENSION = defaultRoots(HERE).extension;   // 5.0.9: repo root, or ../3P-Matrix in the release layout (repo-layout.mjs)
const MODULE_NAME = "TopSitesFilter";
const CRUX_SOURCE = Object.freeze({ url: "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz",
                                    rawFile: "crux-top-sites.csv.gz", tag: "CrUX top sites", minBytes: 1000000,
                                    cache: false });   // on demand: always downloaded, never kept in lists-raw/
const FALSE_POSITIVE_RATE = 0.01;               // as the shipped filter (and DownloadSentinel) uses
const RANK_CUTOFF = 100000;                     // CrUX rank bucket kept (DS 3.2.0 / DS_ALIGNMENT §3)
const MIN_ENTRIES = 75000;                      // guard: refuse a truncated or wrong download (202609: 80,140)
const MUST_CONTAIN = Object.freeze(["google.com", "wikipedia.org", "github.com", "amazon.com"]);
const CSV_HEADER = "origin,rank";
const GZIP_MAGIC = Object.freeze([0x1f, 0x8b]);
const GZIP_FLAG_OFFSET = 3, GZIP_FNAME_BIT = 0x08, GZIP_FNAME_OFFSET = 10;   // RFC 1952 header
const RELEASE_RE = /(\d{6})\.csv/;              // CrUX monthly release name, e.g. 202609.csv

function didNotRun(msg) { console.error(`update-top-sites: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function refuse(msg) { console.error(`update-top-sites: REFUSED — ${msg}`); process.exit(EXIT.REFUSED); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

function isGzip(buf) { return buf[0] === GZIP_MAGIC[0] && buf[1] === GZIP_MAGIC[1]; }

// The CrUX mirror stores the release month as the gzip's original file name ("202609.csv").
function gzipReleaseName(buf) {
  if (!isGzip(buf) || !(buf[GZIP_FLAG_OFFSET] & GZIP_FNAME_BIT)) return "";
  const end = buf.indexOf(0, GZIP_FNAME_OFFSET);
  const m = RELEASE_RE.exec(buf.subarray(GZIP_FNAME_OFFSET, end).toString("latin1"));
  return m ? m[1] : "";
}

function about(release) {
  return [
    `Source:  Chrome UX Report (CrUX) origins ranked ≤ ${RANK_CUTOFF}, release ${release || "unknown"},`,
    "         + every brand website (Brands.default.js) + the shared government suffixes (GovSuffixes.default.js)",
    `         ${CRUX_SOURCE.url}`,
    "Licence: CrUX datasets by Google are licensed under a Creative Commons Attribution 4.0",
    "         International License (https://developer.chrome.com/docs/crux/methodology).",
    `Bloom filter at a ${FALSE_POSITIVE_RATE} false-positive rate (util/BloomFilter.js).`
  ];
}

async function main() {
  const ext = resolve(arg("extension") || DEFAULT_EXTENSION);
  if (!existsSync(join(ext, "manifest.json"))) didNotRun(`not an extension folder: ${ext}`);
  let BloomFilter, UrlUtils, brands, govSuffixes;
  try {
    ({ BloomFilter } = await import(pathToFileURL(join(ext, LIB_UTIL, "BloomFilter.js")).href));
    ({ UrlUtils } = await import(pathToFileURL(join(ext, LIB_UTIL, "UrlUtils.js")).href));
    brands = await readListData(ext, "Brands");
    govSuffixes = await readListData(ext, "GovSuffixes");
  } catch (e) { didNotRun(`cannot read the extension's BloomFilter/UrlUtils/Brands/GovSuffixes: ${e.message}`); }

  let raw = null;
  try { raw = await readRawSource(CRUX_SOURCE); } catch (e) { didNotRun(e.message); }
  const release = gzipReleaseName(raw);
  let lines = (isGzip(raw) ? gunzipSync(raw) : raw).toString("utf8").split(/\r?\n/);
  raw = null;                                    // release the ≈ 9 MB download as soon as it is decoded
  if (lines[0].trim() !== CSV_HEADER) didNotRun(`unexpected CSV header "${lines[0].trim()}" (expected "${CSV_HEADER}")`);

  const domains = new Set();
  for (const line of lines.slice(1)) {
    const [origin, rank] = line.split(",");
    if (!origin || !(Number(rank) <= RANK_CUTOFF)) continue;
    let host;
    try { host = new URL(origin).hostname.toLowerCase(); } catch { continue; }   // malformed row: skip
    const rd = UrlUtils.getRegisteredDomain(host);
    if (rd) domains.add(rd);
  }
  lines = null;                                  // release the ≈ 34 MB of decoded CSV lines
  for (const brand of brands) for (const website of brand.domains) domains.add(website);   // as listed (DS 3.2.0)
  for (const suffix of govSuffixes) domains.add(suffix);
  if (domains.size < MIN_ENTRIES) refuse(`only ${domains.size} domains (expected ≥ ${MIN_ENTRIES}) — truncated download?`);

  const { size, numHashes } = BloomFilter.sizeFor(domains.size, FALSE_POSITIVE_RATE);
  const filter = BloomFilter.create(size, numHashes);
  for (const d of domains) filter.add(d);
  const missing = MUST_CONTAIN.filter((d) => !filter.has(d));
  if (missing.length) refuse(`sanity check failed — not in the new filter: ${missing.join(", ")}`);

  const data = { size, numHashes, entryCount: domains.size, falsePositiveRate: FALSE_POSITIVE_RATE, bitsBase64: filter.toBase64() };
  writeListModule(ext, { name: MODULE_NAME, tool: "update-top-sites.mjs", cadence: "once per minor release",
                         about: about(release), data, generatedAt: new Date().toISOString() });
  let versionMinor;
  try { versionMinor = recordList(LIST_ID, ext, { sourceRelease: release || "unknown", entries: domains.size }); }
  catch (e) { didNotRun(e.message); }
  console.log(`update-top-sites: wrote ${MODULE_NAME}.default.js — CrUX ${release || "?"}, ${domains.size} domains, recorded for ${versionMinor}`);
  process.exit(EXIT.OK);
}

await main();
