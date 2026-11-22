#!/usr/bin/env node
// ── tools/test-obfuscation-shape.mjs ─────────────────────────────────────────────
// Functional test for util/ObfuscationShape.js — the single source behind
// blockObfuscatedEval/Function/SetTimeout/SetInterval (sec-noeval.js, sec-nofunction.js, sec-nosettimeout.js,
// sec-nosetinterval.js). Each scriptlet inlines a byte-for-byte copy of this logic
// (MAIN-world scripts cannot import ES modules); check-shipped-terms.mjs keeps the
// inlined thresholds in sync, so testing this module directly tests all four.
//
// Cases are drawn from the user-supplied design doc (2026-10-25) for the
// Function()/setTimeout()/setInterval() siblings of blockObfuscatedEval, including its
// explicit "don't flag by itself" examples.
//
// Usage:  node test-obfuscation-shape.mjs --extension ../3P-Matrix
// Exit:   0 = pass · 1 = failure · 2 = could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAIL: 1, DID_NOT_RUN: 2 });

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-obfuscation-shape: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const root = arg("extension");
if (!root || !existsSync(join(root, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");

let detectObfuscation, OBFUSCATION_CONFIG;
try {
  ({ detectObfuscation, OBFUSCATION_CONFIG } = await import(pathToFileURL(resolve(root, "util/ObfuscationShape.js")).href));
} catch (e) { didNotRun(`cannot import util/ObfuscationShape.js: ${e.message}`); }

const failures = [];
function check(label, actual, expected) {
  if (actual !== expected) failures.push(`${label}: got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

// ── Flagged: each recognized shape, built from the module's own thresholds ──────
check("packer bootstrap", detectObfuscation("eval(function(p,a,c,k,e,d){}('x',1,1,'x'.split('|'),0,{}))"), "packer");
check("base64 blob at the threshold length",
  detectObfuscation(`atob("${"A".repeat(OBFUSCATION_CONFIG.MIN_B64_LEN)}")`), "base64-blob");
check("char-code array at the threshold count",
  detectObfuscation(`String.fromCharCode(${Array(OBFUSCATION_CONFIG.MIN_CHARCODE_ARGS).fill(97).join(",")})`), "char-code-array");
// Fixed 4-hex-digit idents (the regex requires 4–6): _0xabcd, _0xbeef, _0xcafe, ...
const HEX_IDENT_POOL = ["abcd", "beef", "cafe", "dead", "face", "feed"];
check("hex identifiers at the threshold count",
  detectObfuscation(Array.from({ length: OBFUSCATION_CONFIG.MIN_HEX_IDENTS }, (_, i) => `_0x${HEX_IDENT_POOL[i]}`).join(";")),
  "hex-identifiers");

// ── Not flagged: below each threshold, and the doc's own "don't flag" examples ──
check("base64 one char short of the threshold",
  detectObfuscation(`atob("${"A".repeat(OBFUSCATION_CONFIG.MIN_B64_LEN - 1)}")`), null);
check("char-code array one arg short of the threshold",
  detectObfuscation(`String.fromCharCode(${Array(OBFUSCATION_CONFIG.MIN_CHARCODE_ARGS - 1).fill(97).join(",")})`), null);
check("one coincidental hex-looking identifier",
  detectObfuscation("const _0xabcd = 1;"), null);
check("Function(): don't flag by itself — doc's own example",
  detectObfuscation("return a + b"), null);
check("setTimeout(): don't flag by itself — ordinary short string", detectObfuscation("doSomething()"), null);
check("plain, unrelated code with no encoded payload", detectObfuscation("console.log('hello world')"), null);

if (failures.length) {
  console.error(`test-obfuscation-shape: FAIL — ${failures.length} failure(s):`);
  for (const f of failures) console.error("  " + f);
  process.exit(EXIT.FAIL);
}
console.log(`test-obfuscation-shape: PASS — ${4 + 6} cases (4 flagged shapes, 6 pass-through cases)`);
process.exit(EXIT.OK);
