#!/usr/bin/env node
// ── tools/update-domain-age-lists.mjs ────────────────────────────────────────────
// Rebuilds the two lists that tell the domain-age (RDAP) check when a lookup cannot give an answer, so
// it is skipped instead of failing. Since 4.3.4 they are DownloadSentinel 3.3.0's own list modules
// (lib/downloadsentinel/util/DomainAge.js — one rule for site and download checks), so this tool writes
// DS's generated format byte for byte (only the "Generated:" line differs from a DS rebuild):
//   lib/downloadsentinel/util/PlatformSuffixes.default.js — the PRIVATE section of the Public Suffix List:
//        platforms where anyone gets a subdomain (github.io, blogspot.com, pages.dev …). The registry only
//        knows the platform, never the user's site → no age for the site.
//   lib/downloadsentinel/util/RdapCctlds.default.js — the two-letter country-code TLDs that HAVE an RDAP
//        service, from IANA's RDAP bootstrap file (dns.json). A ccTLD not listed (de, it, es, ch, jp …) has
//        no RDAP → no age. Every gTLD has RDAP (ICANN contract) → always asked.
// 4.5.4: written in the shared precompiled list-module format (list-modules.mjs). The Public Suffix List
// is read from the SAME cached snapshot as update-psl.mjs (lists-raw/public_suffix_list.dat, refreshed by
// `update-psl.mjs --fetch`), so PublicSuffixList and PlatformSuffixes always come from one PSL release.
// Same arrangement as update-top-sites.mjs (also writes into lib). DownloadSentinel rebuilds the same lists
// with its own tool; whichever runs, the data is the same.
// Records both in data-sources.json (updateOn "minor", like the top-sites list).
//
// Usage:  node update-domain-age-lists.mjs [--extension ../3P-Matrix] [--fetch]
//         Reads the cached raw files in tools/lists-raw/; --fetch re-downloads the IANA RDAP file first
//         (the PSL snapshot is owned by update-psl.mjs — refresh it there, then run this tool).
// Exit:   0 = written · 1 = refused (sanity guard) · 2 = did not run (download/parse/folder)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FETCH_FLAG, PSL_SOURCE, writeListModule, recordList, readRawSource, snapshotId } from "./list-modules.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, REFUSED: 1, DID_NOT_RUN: 2 });
const DEFAULT_EXTENSION = join(HERE, "..", "3P-Matrix");
const LIST = Object.freeze({ PLATFORMS: "platform-suffixes", RDAP: "rdap-cctlds" });
const PSL_BEGIN_PRIVATE = "===BEGIN PRIVATE DOMAINS===";
const PSL_END_PRIVATE = "===END PRIVATE DOMAINS===";
const PSL_COMMENT = "//";
const PSL_EXCEPTION = "!";                                  // exception rules: none matter for platforms
const PSL_WILDCARD = "*.";
const CCTLD_RE = /^[a-z]{2}$/;
const MIN_PLATFORMS = 2000;                                  // guard (2026-10: 3,4xx rules)
const MIN_RDAP_CCTLDS = 40;                                  // guard (2026-09-30: 72)
const PLATFORMS_MUST = Object.freeze(["github.io", "blogspot.com", "pages.dev"]);
const RDAP_MUST = Object.freeze(["fr", "nl", "uk"]);
const RDAP_MUST_NOT = Object.freeze(["de", "com"]);          // de: no RDAP service; com: a gTLD, never listed here
const MODULE = Object.freeze({ PLATFORMS: "PlatformSuffixes", RDAP: "RdapCctlds" });   // DS module names
const RDAP_SOURCE = Object.freeze({ url: "https://data.iana.org/rdap/dns.json", rawFile: "iana-rdap-dns.json",
                                    tag: "IANA RDAP bootstrap", minBytes: 10000 });
const TOOL = "update-domain-age-lists.mjs";
const CADENCE = "once per minor release";
const ABOUT = Object.freeze({
  [MODULE.PLATFORMS]: ["Public Suffix List PRIVATE section — platforms where anyone gets a subdomain (github.io,",
                       "blogspot.com, pages.dev …): the registry only knows the platform → no domain age for the site.",
                       "Source: tools/lists-raw/public_suffix_list.dat (the same snapshot as PublicSuffixList)."],
  [MODULE.RDAP]:      ["Two-letter country-code TLDs that HAVE an RDAP service (IANA RDAP bootstrap dns.json).",
                       "A ccTLD not listed has no RDAP → no domain age. Every gTLD has RDAP → always asked."]
});

function didNotRun(msg) { console.error(`update-domain-age-lists: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function refuse(msg) { console.error(`update-domain-age-lists: REFUSED — ${msg}`); process.exit(EXIT.REFUSED); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

async function readSource(source, refetch) {
  try { return await readRawSource(source, { fetch: refetch }); }
  catch (e) { didNotRun(e.message); }
  return null;                                               // unreachable (didNotRun exits)
}

// A rule as the URL API reports host names (punycode); a leading "*." wildcard is kept.
function toAscii(rule) {
  const wild = rule.startsWith(PSL_WILDCARD);
  const ascii = new URL(`http://${wild ? rule.slice(PSL_WILDCARD.length) : rule}/`).hostname;
  return wild ? PSL_WILDCARD + ascii : ascii;
}

function parsePrivate(raw) {
  const text = raw.toString("utf8");
  const begin = text.indexOf(PSL_BEGIN_PRIVATE), end = text.indexOf(PSL_END_PRIVATE);
  if (begin === -1 || end === -1) didNotRun("no PRIVATE DOMAINS section in the Public Suffix List");
  const rules = new Set();
  for (const rawLine of text.slice(text.indexOf("\n", begin), end).split(/\r?\n/)) {   // after the marker line
    const line = rawLine.trim().toLowerCase();
    if (!line || line.startsWith(PSL_COMMENT) || line.startsWith(PSL_EXCEPTION)) continue;
    rules.add(toAscii(line));
  }
  return { rules: [...rules].sort(), release: snapshotId(raw) };   // the PSL has no version line: fingerprint
}

function parseRdap(raw) {
  let json;
  try { json = JSON.parse(raw.toString("utf8")); } catch (e) { didNotRun(`dns.json is not JSON: ${e.message}`); }
  const tlds = new Set();
  for (const service of json.services || []) for (const tld of service[0] || []) if (CCTLD_RE.test(tld)) tlds.add(tld);
  return { tlds: [...tlds].sort(), release: json.publication || "unknown" };
}

async function main() {
  const ext = resolve(arg("extension") || DEFAULT_EXTENSION);
  if (!existsSync(join(ext, "manifest.json"))) didNotRun(`not an extension folder: ${ext}`);
  const platforms = parsePrivate(await readSource(PSL_SOURCE, false));            // owned by update-psl.mjs
  const rdap = parseRdap(await readSource(RDAP_SOURCE, process.argv.includes(FETCH_FLAG)));
  if (platforms.rules.length < MIN_PLATFORMS) refuse(`only ${platforms.rules.length} platform rules (expected ≥ ${MIN_PLATFORMS})`);
  if (rdap.tlds.length < MIN_RDAP_CCTLDS) refuse(`only ${rdap.tlds.length} ccTLDs with RDAP (expected ≥ ${MIN_RDAP_CCTLDS})`);
  const missing = PLATFORMS_MUST.filter((p) => !platforms.rules.includes(p)).concat(RDAP_MUST.filter((t) => !rdap.tlds.includes(t)));
  const wrong = RDAP_MUST_NOT.filter((t) => rdap.tlds.includes(t));
  if (missing.length || wrong.length) refuse(`sanity check failed — missing: ${missing.join(", ") || "none"}; unexpected: ${wrong.join(", ") || "none"}`);

  const generatedAt = new Date().toISOString();
  writeListModule(ext, { name: MODULE.PLATFORMS, tool: TOOL, cadence: CADENCE, about: ABOUT[MODULE.PLATFORMS], data: platforms.rules, generatedAt });
  writeListModule(ext, { name: MODULE.RDAP, tool: TOOL, cadence: CADENCE, about: ABOUT[MODULE.RDAP], data: rdap.tlds, generatedAt });
  let versionMinor;
  try {
    versionMinor = recordList(LIST.PLATFORMS, ext, { sourceRelease: platforms.release, entries: platforms.rules.length });
    recordList(LIST.RDAP, ext, { sourceRelease: rdap.release, entries: rdap.tlds.length });
  } catch (e) { didNotRun(e.message); }
  console.log(`update-domain-age-lists: ${platforms.rules.length} platform suffixes (PSL ${platforms.release}), ` +
              `${rdap.tlds.length} ccTLDs with RDAP (IANA ${rdap.release}), recorded for ${versionMinor}`);
  process.exit(EXIT.OK);
}

await main();
