#!/usr/bin/env node
// ── tools/check-derived-literals.mjs ─────────────────────────────────────────────
// Static check for principle C39a (Xplainer audit): a value the UI SHOWS that also exists as a
// constant or registry field — a level, a protection number, a protection count, a score
// threshold, the level range — must be derived from that source at render time
// (ui/derived-text.js), never typed into HTML or into a JS string. A typed copy survives the next
// renumbering or re-scoping and then shows the user something false (real cases: 4.2 renumbered
// the protections and added one; popup "(5 outside safer regions)" and options "protection 10"
// were only correct by luck or became wrong).
//
// Usage:  node check-derived-literals.mjs --extension ../3P-Matrix
// Exit:   0 = no unclassified hit · 1 = unclassified hit(s) found · 2 = check could not run (C38)
//
// Scans every .html and .js file under ui/ (the files that produce visible text). Comments are
// stripped first (HTML <!-- --> and JS // and /* */ comments), so documentation may still say
// "protection 11". A hit is reported unless ALLOWLIST classifies it with a stated reason (C25: a
// new, unclassified hit fails by default — triage it: derive it, or allowlist it with a reason).
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

// ── Settings (one place) ─────────────────────────────────────────────────────
const SCAN_DIR = "ui";
const SCAN_EXTENSIONS = Object.freeze([".html", ".js"]);
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });

// The bug class, as text patterns (a digit typed where a derived value belongs).
const PATTERNS = Object.freeze([
  { id: "level-number",      re: /\b[Ll]evels?\s+\d+/g,                              what: "level number typed into text" },
  { id: "protection-number", re: /\b[Pp]rotections?\s+\d+/g,                         what: "protection number typed into text" },
  { id: "protection-count",  re: /\b\d+\s+(?:of\s+\d+\s+)?(?:protections?|outside)\b/g, what: "protection count typed into text" },
  { id: "score-threshold",   re: /\bscore\s+[−-]?\d+/gi,                             what: "score threshold typed into text" },
  { id: "option-number",     re: /<option[^>]*>\s*\d+\s*<\/option>/g,               what: "numbered <option> typed into HTML (level list?)" },
  { id: "fixed-level-loop",  re: /for\s*\(\s*let\s+\w+\s*=\s*\d+\s*;\s*\w+\s*<=?\s*\d+/g, what: "loop over a typed number range (use LEVEL_MIN/LEVEL_MAX)" }
]);

// Classified exceptions — file (relative to the extension root) + pattern id + exact matched text,
// each with the reason it is NOT a derived value. Keep this list short and explained.
const ALLOWLIST = Object.freeze([
  // (none today)
]);

function fail(msg) {
  console.error(`check-derived-literals: DID NOT RUN — ${msg}`);
  process.exit(EXIT.DID_NOT_RUN);
}

function parseArgs(argv) {
  const i = argv.indexOf("--extension");
  if (i === -1 || !argv[i + 1]) fail("missing --extension <folder>");
  const root = argv[i + 1];
  if (!existsSync(join(root, "manifest.json"))) fail(`not an extension folder (no manifest.json): ${root}`);
  if (!existsSync(join(root, SCAN_DIR)) || !statSync(join(root, SCAN_DIR)).isDirectory()) fail(`no ${SCAN_DIR}/ folder in ${root}`);
  return root;
}

function listFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p));
    else if (SCAN_EXTENSIONS.some((ext) => name.endsWith(ext))) out.push(p);
  }
  return out.sort();
}

// Comments replaced by spaces of the same length, so line numbers stay correct.
function blank(match) { return match.replace(/[^\n]/g, " "); }
function stripComments(text, isHtml) {
  if (isHtml) return text.replace(/<!--[\s\S]*?-->/g, blank);
  return text
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (m, pre) => pre + blank(m.slice(pre.length)));   // not "https://"
}

function lineOf(text, index) { return text.slice(0, index).split("\n").length; }

function isAllowed(file, patternId, matched) {
  return ALLOWLIST.some((a) => a.file === file && a.pattern === patternId && a.text === matched);
}

function main() {
  const root = parseArgs(process.argv.slice(2));
  const files = listFiles(join(root, SCAN_DIR));
  if (!files.length) fail(`no ${SCAN_EXTENSIONS.join("/")} files under ${SCAN_DIR}/`);
  const hits = [];
  for (const path of files) {
    const rel = relative(root, path).split("\\").join("/");
    const code = stripComments(readFileSync(path, "utf8"), path.endsWith(".html"));
    for (const p of PATTERNS) {
      for (const m of code.matchAll(p.re)) {
        if (!isAllowed(rel, p.id, m[0])) hits.push(`${rel}:${lineOf(code, m.index)}  [${p.id}] ${p.what}: "${m[0].trim()}"`);
      }
    }
  }
  if (hits.length) {
    console.error(`check-derived-literals: FAIL — ${hits.length} unclassified hit(s). Derive the value ` +
                  `(ui/derived-text.js) or add an ALLOWLIST entry with a reason:`);
    for (const h of hits) console.error("  " + h);
    process.exit(EXIT.FOUND);
  }
  console.log(`check-derived-literals: PASS — ${files.length} files under ${SCAN_DIR}/, ${PATTERNS.length} patterns, ${ALLOWLIST.length} allowlisted`);
  process.exit(EXIT.OK);
}

main();
