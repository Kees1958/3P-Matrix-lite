#!/usr/bin/env node
// ── tools/check-no-eval.mjs ───────────────────────────────────────────────────────
// C43 (4.5.1 audit): no first-party code ships a dynamic-code-execution call — eval(), the
// Function constructor used as code-gen, or setTimeout()/setInterval() given a STRING handler
// (the same "implicit eval" the other two forms are). Every MV3 extension page already enforces
// this at runtime (script-src 'self', no 'unsafe-eval' — not optional, not something this project
// configures) — this check makes the same rule a build-time gate, so a violation is caught before
// packaging instead of surfacing later as a page-specific CSP error that has to be hand-traced.
//
// Real incident this check exists for: a CSP EvalError surfaced on ui/download-warning.html during
// the 4.5.1 e2e investigation. Diagnosing it required ruling out the extension's own code by hand
// (grepping download-warning.js's full import graph, writing an isolation repro) because nothing
// already PROVED it mechanically — exactly the C25 pattern ("a recurring class of problem gets a
// standing constraint AND an automated check", applied here to the very first instance, per C42).
//
// Deliberately NOT the same thing as blockHighRiskEval/blockObfuscatedEval/Function/SetTimeout/SetInterval (security/sec-*noeval*.js etc.): those
// scriptlets intercept eval/Function/setTimeout/setInterval ON THIRD-PARTY PAGES the user visits —
// a security FEATURE this project ships. This check is about OUR OWN first-party code never doing
// the thing those scriptlets exist to catch elsewhere. The scriptlets reach the real native function
// through Reflect.apply (indirection, not a literal call-site), by design (sec-noeval.js's own
// header explains why) — so they do not, and should not, need an allowlist entry here; if a future
// scriptlet ever did need one, it goes in ALLOWLIST below with a stated reason (C25).
//
// Scope matches syntax/eslint/magic-numbers: first-party code only (lib/ — vendored DownloadSentinel
// — is out of scope here for the same reason magic-numbers excludes it: it is not this project's
// code to rewrite). Verified by hand at authoring time (full grep of lib/downloadsentinel/, ui/,
// util/, data/, core/): zero eval/Function/string-timer call sites outside the security scriptlets'
// own metadata/comments. A future vendor update is NOT re-verified automatically by this check —
// that is a known gap, same shape as magic-numbers' lib/ exclusion.
//
// Usage:  node check-no-eval.mjs --extension ../3P-Matrix
// Needs:  acorn (tools/package.json devDependencies)
// Exit:   0 = pass · 1 = a call site found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";
import { NON_EXTENSION_DIR_NAMES } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const ECMA_VERSION = 2022;
const SKIP_DIRS = Object.freeze(["lib", ...NON_EXTENSION_DIR_NAMES]);   // vendored code + never-extension folders (5.0.9 repo layout)           // vendored code — see header
const SCRIPT_DIRS = Object.freeze(["security"]);                    // classic scripts, not modules
const SNIPPET_MAX = 110;
const TIMER_FNS = Object.freeze(["setTimeout", "setInterval"]);     // string-first-arg = implicit eval
// Classified exceptions: { file, line text (trimmed, exact), reason } — keep short and explained (C25).
const ALLOWLIST = Object.freeze([
  // (none today — see header: the security scriptlets reach native eval/Function/timers through
  // Reflect.apply, never a literal call site, so none are expected to ever need an entry here)
]);

function didNotRun(msg) { console.error(`check-no-eval: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }

let acorn;
try { acorn = await import("acorn"); }
catch { didNotRun("acorn not installed (run npm install in the tools folder)"); }

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

function calleeName(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && !node.computed && node.property.type === "Identifier") return node.property.name;
  return null;
}

function walkCalls(node, visit) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) { for (const n of node) walkCalls(n, visit); return; }
  if (node.type === "CallExpression" || node.type === "NewExpression") visit(node);
  for (const key of Object.keys(node)) {
    if (key === "type" || key === "loc" || key === "start" || key === "end") continue;
    const v = node[key];
    if (v && typeof v === "object") walkCalls(v, visit);
  }
}

const hits = [];
let scanned = 0;
for (const path of listJs(root)) {
  const rel = relative(root, path).split("\\").join("/");
  const src = readFileSync(path, "utf8");
  const lines = src.split("\n");
  const sourceType = SCRIPT_DIRS.some((d) => rel.startsWith(d + "/")) ? "script" : "module";
  let ast;
  try { ast = acorn.parse(src, { ecmaVersion: ECMA_VERSION, sourceType, locations: true }); }
  catch (e) { didNotRun(`${rel} does not parse: ${e.message}`); }
  scanned++;

  walkCalls(ast, (node) => {
    const name = calleeName(node.callee);
    if (!name) return;
    const isEval = name === "eval";
    const isFunctionCtor = name === "Function" && node.callee.type === "Identifier";
    const isStringTimer = TIMER_FNS.includes(name) && node.arguments[0] &&
      (node.arguments[0].type === "Literal" && typeof node.arguments[0].value === "string");
    if (!isEval && !isFunctionCtor && !isStringTimer) return;

    const lineText = lines[node.loc.start.line - 1].trim();
    if (isAllowed(rel, lineText)) return;
    const kind = isEval ? "eval()" : isFunctionCtor ? "Function() constructor" : `${name}() with a string handler`;
    hits.push(`${rel}:${node.loc.start.line}  ${kind} in: ${lineText.slice(0, SNIPPET_MAX)}`);
  });
}

if (hits.length) {
  console.error(`check-no-eval: FAIL — ${hits.length} dynamic-code-execution call site(s). Every MV3 extension ` +
                `page's CSP blocks these outright — rewrite without eval/Function/string-timers, or add a ` +
                `classified ALLOWLIST entry with a stated reason (C25):`);
  for (const h of hits) console.error("  " + h);
  process.exit(EXIT.FOUND);
}
console.log(`check-no-eval: PASS — ${scanned} first-party files, no eval()/Function()/string-timer call sites (${ALLOWLIST.length} allowlisted)`);
process.exit(EXIT.OK);
