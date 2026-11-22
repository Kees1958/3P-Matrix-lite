#!/usr/bin/env node
// ── tools/update-psl.mjs ─────────────────────────────────────────────────────────
// Rebuilds lib/downloadsentinel/util/PublicSuffixList.default.js — the Public Suffix List every browser
// uses to know where a host's registrable name ends (co.uk, com.br, github.io …). Used by the site check,
// the download check and the look-alike check (UrlUtils.getRegisteredDomain → PublicSuffixList.js).
//
// 4.5.4: native to this project (ported from DownloadSentinel tools/update-psl.mjs — C21: same parser,
// same punycode rule, same output shape). Before 4.5.4 no 3P Matrix tool rebuilt this list, so it was
// never refreshed for 4.5 while PlatformSuffixes (the same PSL's PRIVATE section) was.
//
// Method:
//   1. Read the cached snapshot tools/lists-raw/public_suffix_list.dat (PSL_SOURCE, list-modules.mjs) —
//      the SAME snapshot update-domain-age-lists.mjs reads; --fetch replaces it first.
//   2. Parse: "x" plain rule · "*.x" wildcard (stored as "x") · "!x" exception; every label through
//      domainToASCII (browsers report IDN hosts in punycode — without this ~460 IDN rules never match).
//   3. Guard: refuse an implausibly small parse (format change or bad download).
//   4. Write the precompiled list module (list-modules.mjs) and record it in data-sources.json.
//   After --fetch, run update-domain-age-lists.mjs too (same snapshot → PlatformSuffixes).
//
// Usage:  node update-psl.mjs [--extension ../3P-Matrix] [--fetch]
// Exit:   0 = written · 1 = refused (sanity guard) · 2 = did not run (download/parse/folder)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, domainToASCII } from "node:url";
import { FETCH_FLAG, PSL_SOURCE, writeListModule, recordList, readRawSource, snapshotId } from "./list-modules.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, REFUSED: 1, DID_NOT_RUN: 2 });
const DEFAULT_EXTENSION = join(HERE, "..", "3P-Matrix");
const LIST_ID = "public-suffix-list";
const MODULE_NAME = "PublicSuffixList";
const TOOL = "update-psl.mjs";
const MIN_RULES = 5000;                                      // guard (2026-11: 10,077 plain rules)
const MUST_CONTAIN = Object.freeze(["co.uk", "com.br", "github.io"]);
const PSL_COMMENT = "//";
const PSL_EXCEPTION = "!";
const PSL_WILDCARD = "*.";
const ABOUT = Object.freeze([
  "Public Suffix List (publicsuffix.org, MPL-2.0): { rules, wildcardRules, exceptions } — punycode labels.",
  "Source: tools/lists-raw/public_suffix_list.dat (the same snapshot as PlatformSuffixes)."
]);

function didNotRun(msg) { console.error(`update-psl: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function refuse(msg) { console.error(`update-psl: REFUSED — ${msg}`); process.exit(EXIT.REFUSED); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

function parsePsl(text) {
  const rules = [], wildcardRules = [], exceptions = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith(PSL_COMMENT)) continue;
    let target = rules, suffix = line;
    if (line.startsWith(PSL_EXCEPTION)) { target = exceptions; suffix = line.slice(PSL_EXCEPTION.length); }
    else if (line.startsWith(PSL_WILDCARD)) { target = wildcardRules; suffix = line.slice(PSL_WILDCARD.length); }
    const ascii = domainToASCII(suffix);
    if (ascii) target.push(ascii.toLowerCase());               // a malformed label is skipped, never stored
  }
  const sorted = (a) => [...new Set(a)].sort();
  return { rules: sorted(rules), wildcardRules: sorted(wildcardRules), exceptions: sorted(exceptions) };
}

async function main() {
  const ext = resolve(arg("extension") || DEFAULT_EXTENSION);
  if (!existsSync(join(ext, "manifest.json"))) didNotRun(`not an extension folder: ${ext}`);
  let raw = null;
  try { raw = await readRawSource(PSL_SOURCE, { fetch: process.argv.includes(FETCH_FLAG) }); }
  catch (e) { didNotRun(e.message); }
  const text = raw.toString("utf8");

  const data = parsePsl(text);
  if (data.rules.length < MIN_RULES) refuse(`parsed only ${data.rules.length} rules (expected ≥ ${MIN_RULES})`);
  const missing = MUST_CONTAIN.filter((r) => !data.rules.includes(r));
  if (missing.length) refuse(`sanity check failed — missing: ${missing.join(", ")}`);

  const entries = writeListModule(ext, { name: MODULE_NAME, tool: TOOL, cadence: "once per minor release", about: ABOUT,
                                         data, generatedAt: new Date().toISOString() });
  let versionMinor;
  try { versionMinor = recordList(LIST_ID, ext, { sourceRelease: snapshotId(raw), entries, tool: TOOL }); }
  catch (e) { didNotRun(e.message); }
  console.log(`update-psl: wrote ${MODULE_NAME}.default.js — ${data.rules.length} rules, ${data.wildcardRules.length} wildcard, ` +
              `${data.exceptions.length} exceptions; recorded for ${versionMinor}`);
  process.exit(EXIT.OK);
}

await main();
