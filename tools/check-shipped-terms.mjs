#!/usr/bin/env node
// ── tools/check-shipped-terms.mjs ────────────────────────────────────────────────
// Two guards on the shipped extension (audit 2026-10-19, finding 4):
//
// 1. LOG PREFIX IN SYNC — the MAIN-world security scripts (security/*.js) run inside the web page
//    and cannot import data/constants.js, so each one that logs declares its own copy:
//        const LOG_PREFIX = '[3PMCF]';
//    This check imports the real LOG_PREFIX from data/constants.js (single source of truth) and
//    fails when a script that writes to the console has no declaration or a different value.
//
// 2. NO uBD-ONLY TERMS — 3P Matrix took code from uBlock Stripped Dynamic (uBD). Exemption syntax
//    and identity strings that exist only in uBD must never be shown to a 3P Matrix user: they
//    point to features that do nothing here. Provenance comments ("ported from uBlock Stripped
//    Dynamic 10.2.1") are wanted for troubleshooting and are NOT flagged.
//    Deliberately kept (not matched by any pattern): window.eval.__uBolNoEvalInstalled in
//    sec-noeval.js — an internal install guard shared with uBD, so eval is wrapped once when both
//    extensions run; never shown to the user.
//
// 3. OBFUSCATION THRESHOLDS IN SYNC (4.4.3) — security/sec-noeval.js, sec-nofunction.js,
//    sec-nosettimeout.js and sec-nosetinterval.js each carry their own inlined copy of the
//    OBFUSC_MIN_* thresholds (MAIN-world scripts cannot import util/ObfuscationShape.js, the
//    single source). This check imports that module and fails if any copy's value drifts from it.
//
// 4. SHARED-VALUE COPIES IN SYNC (4.6.0) — the page scripts in security/ cannot import either:
//    • every `const MSG_X = '…'` declared in a security/*.js file must equal data/message-types.js MSG_X
//      (the password-form guard messages the service worker);
//    • every name in SHARED_SCRIPT_CONSTS must have the SAME value in every security/*.js file that declares it
//      (e.g. PASSWORD_SUBMIT_EVENT: the MAIN-world hook dispatches it, the ISOLATED guard listens for it).
//
// Usage:  node check-shipped-terms.mjs --extension ../3P-Matrix
// Exit:   0 = pass · 1 = problem found · 2 = check could not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { listExtensionFiles } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const SECURITY_DIR = "security";
const SCAN_EXTENSIONS = Object.freeze([".js", ".html", ".css", ".json", ".md"]);
const PREFIX_DECL_RE = /const\s+LOG_PREFIX\s*=\s*(['"])(.*?)\1\s*;/;
const LOGS_TO_CONSOLE_RE = /\bconsole\.(?:log|info|warn|error|debug)\b/;
const MSG_DECL_RE = /const\s+(MSG_[A-Z0-9_]+)\s*=\s*(['"])(.*?)\2\s*;/g;               // 4.6.0
const SHARED_SCRIPT_CONSTS = Object.freeze(["PASSWORD_SUBMIT_EVENT", "PASSWORD_SELECTOR", "SKIMMER_BLOCKED_EVENT"]); // 4.6.0/5.0.2: copies across security/ files
// Obfuscation-threshold copies (finding 3 above): file name → inline constant name → the
// util/ObfuscationShape.js OBFUSCATION_CONFIG key it must equal.
const OBFUSC_SHAPE_FILES = Object.freeze(
  ["sec-noeval.js", "sec-nofunction.js", "sec-nosettimeout.js", "sec-nosetinterval.js"]
);
const OBFUSC_CONST_RE = Object.freeze([
  ["OBFUSC_MIN_B64_LEN", "MIN_B64_LEN"],
  ["OBFUSC_MIN_CHARCODE_ARGS", "MIN_CHARCODE_ARGS"],
  ["OBFUSC_MIN_HEX_IDENTS", "MIN_HEX_IDENTS"]
]);
// uBD-only terms: [pattern, what it is, what 3P Matrix has instead]
const FORBIDDEN = Object.freeze([
  { re: /\$worryfree\b/g,               what: "uBD $worryfree exemption",         instead: "3P Matrix allow list" },
  { re: /\$saferregions\b/g,            what: "uBD $saferregions exemption",      instead: "safer regions panel (level 3)" },
  { re: /\[uBol\]/g,                    what: "uBol log prefix",                  instead: "LOG_PREFIX" },
  { re: /\[uBlock-Dynamic\]/g,          what: "uBD log prefix",                   instead: "LOG_PREFIX" },
  { re: /per-toggle allowlist/gi,       what: "uBD per-toggle allowlist",         instead: "allow list / untick the protection" },
  { re: /dashboard checkbox/gi,         what: "uBD dashboard wording",            instead: "popup Protections list" }
]);

function didNotRun(msg) {
  console.error(`check-shipped-terms: DID NOT RUN — ${msg}`);
  process.exit(EXIT.DID_NOT_RUN);
}

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? null : process.argv[i + 1];
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

function lineOf(text, index) { return text.slice(0, index).split("\n").length; }

async function main() {
  const root = arg("extension");
  if (!root || !existsSync(join(root, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
  if (!existsSync(join(root, SECURITY_DIR))) didNotRun(`no ${SECURITY_DIR}/ folder`);
  let expected;
  try {
    ({ LOG_PREFIX: expected } = await import(pathToFileURL(resolve(root, "data/constants.js")).href));
  } catch (e) { didNotRun(`cannot import data/constants.js: ${e.message}`); }
  if (typeof expected !== "string" || !expected) didNotRun("data/constants.js exports no LOG_PREFIX");

  let obfuscationConfig;
  try {
    ({ OBFUSCATION_CONFIG: obfuscationConfig } = await import(pathToFileURL(resolve(root, "util/ObfuscationShape.js")).href));
  } catch (e) { didNotRun(`cannot import util/ObfuscationShape.js: ${e.message}`); }
  if (!obfuscationConfig) didNotRun("util/ObfuscationShape.js exports no OBFUSCATION_CONFIG");

  const problems = [];

  // 1. Log prefix copies
  for (const path of listFiles(join(root, SECURITY_DIR)).filter((p) => p.endsWith(".js"))) {
    const rel = relative(root, path);
    const text = readFileSync(path, "utf8");
    const decl = text.match(PREFIX_DECL_RE);
    if (!decl) {
      if (LOGS_TO_CONSOLE_RE.test(text)) problems.push(`${rel}: writes to the console but declares no LOG_PREFIX`);
      continue;
    }
    if (decl[2] !== expected) problems.push(`${rel}:${lineOf(text, decl.index)}: LOG_PREFIX '${decl[2]}' ≠ constants.js '${expected}'`);
  }

  // 2. Obfuscation-threshold copies in sync with util/ObfuscationShape.js
  for (const name of OBFUSC_SHAPE_FILES) {
    const path = join(root, SECURITY_DIR, name);
    if (!existsSync(path)) { problems.push(`${SECURITY_DIR}/${name}: missing`); continue; }
    const text = readFileSync(path, "utf8");
    for (const [constName, configKey] of OBFUSC_CONST_RE) {
      const m = text.match(new RegExp(`const\\s+${constName}\\s*=\\s*(\\d+)\\s*;`));
      if (!m) { problems.push(`${SECURITY_DIR}/${name}: no ${constName} declaration found`); continue; }
      const got = Number(m[1]);
      const want = obfuscationConfig[configKey];
      if (got !== want) problems.push(`${SECURITY_DIR}/${name}:${lineOf(text, m.index)}: ${constName} ${got} ≠ ObfuscationShape.js ${configKey} ${want}`);
    }
  }

  // 4. Shared-value copies (4.6.0)
  let messageTypes;
  try { messageTypes = await import(pathToFileURL(resolve(root, "data/message-types.js")).href); }
  catch (e) { didNotRun(`cannot import data/message-types.js: ${e.message}`); }
  const sharedSeen = new Map();                               // name → { value, where }
  for (const path of listFiles(join(root, SECURITY_DIR)).filter((p) => p.endsWith(".js"))) {
    const rel = relative(root, path);
    const text = readFileSync(path, "utf8");
    for (const m of text.matchAll(MSG_DECL_RE)) {
      const want = messageTypes[m[1]];
      if (want === undefined) problems.push(`${rel}:${lineOf(text, m.index)}: ${m[1]} is not in data/message-types.js`);
      else if (m[3] !== want) problems.push(`${rel}:${lineOf(text, m.index)}: ${m[1]} '${m[3]}' ≠ message-types.js '${want}'`);
    }
    for (const name of SHARED_SCRIPT_CONSTS) {
      const m = text.match(new RegExp(`const\\s+${name}\\s*=\\s*(['"])(.*?)\\1\\s*;`));
      if (!m) continue;
      const seen = sharedSeen.get(name);
      if (!seen) sharedSeen.set(name, { value: m[2], where: rel });
      else if (seen.value !== m[2]) problems.push(`${rel}:${lineOf(text, m.index)}: ${name} '${m[2]}' ≠ ${seen.where} '${seen.value}'`);
    }
  }

  // 3. uBD-only terms anywhere in the shipped extension
  for (const path of listExtensionFiles(root, { exts: SCAN_EXTENSIONS })) {   // 5.0.9: shipped files only (repo layout)
    const rel = relative(root, path);
    const text = readFileSync(path, "utf8");
    for (const f of FORBIDDEN) {
      for (const m of text.matchAll(f.re)) problems.push(`${rel}:${lineOf(text, m.index)}: ${f.what} "${m[0]}" — use ${f.instead}`);
    }
  }

  if (problems.length) {
    console.error(`check-shipped-terms: FAIL — ${problems.length} problem(s):`);
    for (const p of problems) console.error("  " + p);
    process.exit(EXIT.FOUND);
  }
  console.log(`check-shipped-terms: PASS — LOG_PREFIX '${expected}' in sync, obfuscation thresholds in sync, shared script constants in sync, no uBD-only terms`);
  process.exit(EXIT.OK);
}

await main();
