#!/usr/bin/env node
// ── tools/check-magic-numbers.mjs ────────────────────────────────────────────────
// Static check for B1 / C39a (audit 2026-10-19, finding 13): no number is typed into first-party
// code outside a declared, named constant. A numeric literal is allowed only
//   • as 0, 1 or -1 (counting, indexing, sign), or
//   • inside the initializer of an UPPER_CASE constant (a module's "Settings (one place)" block
//     or data/constants.js), where it has a name and a comment.
// Pure data tables (DATA_FILES) are skipped: they ARE the single source of truth.
// Everything else fails by default; a genuine exception needs an ALLOWLIST entry with a reason (C25).
//
// Usage:  node check-magic-numbers.mjs --extension ../3P-Matrix
// Needs:  acorn + acorn-walk (tools/package.json devDependencies)
// Exit:   0 = pass · 1 = typed number(s) found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const ECMA_VERSION = 2022;
const ALLOWED_VALUES = Object.freeze([0, 1, -1]);
const CONSTANT_NAME_RE = /^[A-Z][A-Z0-9_]*$/;
const SKIP_DIRS = Object.freeze(["lib", "node_modules"]);           // vendored code
const SCRIPT_DIRS = Object.freeze(["security"]);                    // classic scripts, not modules
const DATA_FILES = Object.freeze([                                  // tables that are the source of truth
  "data/constants.js", "data/country-data.js", "data/spam-tlds.js", "data/suspicious-hosting.js",
  "data/builtin-domains.js", "data/network-data.js", "data/tld-constants.js"
]);
const SNIPPET_MAX = 110;
// Classified exceptions: { file, line text (trimmed, exact), reason } — keep short and explained.
const ALLOWLIST = Object.freeze([
  // (none today)
]);

function didNotRun(msg) { console.error(`check-magic-numbers: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

let acorn, walk;
try { acorn = await import("acorn"); walk = await import("acorn-walk"); }
catch { didNotRun("acorn / acorn-walk not installed (run npm install in the tools folder)"); }

const root = arg("extension");
if (!root || !existsSync(join(root, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");

function listJs(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return SKIP_DIRS.includes(n) ? [] : listJs(p);
    return p.endsWith(".js") ? [p] : [];
  });
}

function isAllowed(rel, lineText) {
  return ALLOWLIST.some((a) => a.file === rel && a.line === lineText);
}

const hits = [];
let scanned = 0;
for (const path of listJs(root)) {
  const rel = relative(root, path).split("\\").join("/");
  if (DATA_FILES.includes(rel)) continue;
  const src = readFileSync(path, "utf8");
  const lines = src.split("\n");
  const sourceType = SCRIPT_DIRS.some((d) => rel.startsWith(d + "/")) ? "script" : "module";
  let ast;
  try { ast = acorn.parse(src, { ecmaVersion: ECMA_VERSION, sourceType, locations: true }); }
  catch (e) { didNotRun(`${rel} does not parse: ${e.message}`); }
  scanned++;
  walk.fullAncestor(ast, (node, ancestors) => {
    if (node.type !== "Literal" || typeof node.value !== "number") return;
    const parent = ancestors[ancestors.length - 2];
    const value = parent && parent.type === "UnaryExpression" && parent.operator === "-" ? -node.value : node.value;
    if (ALLOWED_VALUES.includes(value)) return;
    const decl = ancestors.find((a) => a.type === "VariableDeclarator");
    if (decl && decl.id.type === "Identifier" && CONSTANT_NAME_RE.test(decl.id.name)) return;
    const lineText = lines[node.loc.start.line - 1].trim();
    if (isAllowed(rel, lineText)) return;
    hits.push(`${rel}:${node.loc.start.line}  ${value} in: ${lineText.slice(0, SNIPPET_MAX)}`);
  });
}

if (hits.length) {
  console.error(`check-magic-numbers: FAIL — ${hits.length} typed number(s). Name it in the module's settings ` +
                `block or data/constants.js, or add an ALLOWLIST entry with a reason:`);
  for (const h of hits) console.error("  " + h);
  process.exit(EXIT.FOUND);
}
console.log(`check-magic-numbers: PASS — ${scanned} files, no typed numbers outside named constants (${ALLOWLIST.length} allowlisted)`);
process.exit(EXIT.OK);
