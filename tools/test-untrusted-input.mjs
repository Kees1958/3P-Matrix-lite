#!/usr/bin/env node
// ── tools/test-untrusted-input.mjs ───────────────────────────────────────────────
// 5.0.7 — C50 (input limits) and C51 (seeded fuzz tests). Everything random here comes from ONE fixed seed, so a
// failure is reproducible run after run (a test that fails at random erodes trust in the suite — C38).
//   A. Import limit: both import paths of the options page read a file only through readImportFile(), which
//      checks the size first (static: no other File.text() call, the size test precedes the read).
//   B. Settings import (fromSettingsFile → normalizeState): random and hostile files (wrong types, huge
//      numbers, "__proto__"/"constructor" keys, deep nesting) either throw an Error or yield a state whose
//      level is a real level and whose objects carry no injected prototype.
//   C. Domain helpers (util/domain.js): random host and URL strings never throw where they promise not to,
//      and always return the promised type.
//   D. Message gate: for random senders and message types, a content script is never allowed a message that is
//      not in CONTENT_SCRIPT_MESSAGES, and an unknown sender is never allowed anything.
//   F. Logs (C52): no console call in first-party code prints an address variable (url, href, …Url); the
//      router names a refused sender by origin only (senderLabel strips path, query and fragment).
//   E. ClickFix patterns: every STRONG pattern finishes on worst-case inputs of the scriptlet's own maximum
//      length within SLOW_PATTERN_MS (catastrophic backtracking would take seconds).
//
// Usage:  node test-untrusted-input.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const SEED = 0x3b3a7e57;                 // fixed: every run sees the same inputs
const ITERATIONS = 3000;                 // per fuzz target
const MAX_DEPTH = 4;                     // nesting of generated JSON values
const MAX_ARRAY = 6;                     // elements per generated array / keys per object
const MAX_STRING = 40;                   // characters per generated string
const SLOW_PATTERN_MS = 250;             // one ClickFix pattern on one worst-case input (real cost: well under 1 ms)
const HOSTILE_KEYS = Object.freeze(["__proto__", "constructor", "prototype", "toString", "hasOwnProperty"]);
const URL_PIECES = Object.freeze(["http://", "https://", "ftp://", "javascript:", "data:", "//", "xn--", ".", "..", ":",
  "@", "[", "]", "::1", "127.0.0.1", "0x7f.1", "%2e", "localhost", "a.b.c", "co.uk", "例え.jp", "\u0000", " ", "#", "?"]);
const IMPORT_READER = "readImportFile";
const UI_FILE = "ui/protections.js";
const CLICKFIX_FILE = "security/sec-clickfix-clipboard.js";
const LOG_SCAN_DIRS = Object.freeze(["background.js", "core", "data", "ui", "util", "security"]);   // first-party (lib/ is vendored)
const LOG_CALL_RE = /console\.(?:log|info|warn|error|debug)\(([^;]*)\)/g;
const ADDRESS_ARG_RE = /(?:\.url\b|\.href\b|\b[a-z]*Url\b|\burl\b|location\b)/;

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-untrusted-input: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const EXT = resolve(ext);
const read = (rel) => readFileSync(join(EXT, rel), "utf8");
const load = (rel) => import(pathToFileURL(join(EXT, rel)).href);

let failures = 0;
function ok(label, pass, detail) {
  console.log(`${pass ? "ok  " : "FAIL"} ${label}${pass ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!pass) failures += 1;
}

// mulberry32 — a small, well-known seeded generator (deterministic across runs and machines).
function makeRandom(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = makeRandom(SEED);
function int(n) { return Math.floor(rnd() * n); }
function pick(list) { return list[int(list.length)]; }
function str() {
  let s = "";
  const n = int(MAX_STRING);
  for (let i = 0; i < n; i++) s += rnd() < 0.3 ? pick(URL_PIECES) : String.fromCharCode(32 + int(95));
  return s;
}
function value(depth) {
  const kind = int(depth >= MAX_DEPTH ? 5 : 7);
  switch (kind) {
    case 0: return null;
    case 1: return rnd() < 0.5;
    case 2: return pick([0, -1, 1, 2, 5, 6, 1e308, -1e308, Number.MAX_SAFE_INTEGER, 0.5]);
    case 3: return str();
    case 4: return pick(HOSTILE_KEYS);
    case 5: return Array.from({ length: int(MAX_ARRAY) }, () => value(depth + 1));
    default: {
      const o = {};
      for (let i = int(MAX_ARRAY); i > 0; i--) o[rnd() < 0.3 ? pick(HOSTILE_KEYS) : str()] = value(depth + 1);
      return o;
    }
  }
}
// JSON text round-trip: a real file arrives through JSON.parse, which makes "__proto__" an OWN property.
function asFile(obj) { return JSON.parse(JSON.stringify(obj)); }
function hasInjectedProto(o, seen = new Set()) {
  if (!o || typeof o !== "object" || seen.has(o)) return false;
  seen.add(o);
  const proto = Object.getPrototypeOf(o);
  if (proto !== Object.prototype && proto !== Array.prototype && proto !== null) return true;
  return Object.values(o).some((v) => hasInjectedProto(v, seen));
}

let SIO, SS, C, D, MT, G;
try {
  SIO = await load("data/settings-io.js");
  SS = await load("data/state-storage.js");
  C = await load("data/constants.js");
  D = await load("util/domain.js");
  MT = await load("data/message-types.js");
  G = await load("core/message-gate.js");
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

// ── A. import limit (static) ──
const ui = read(UI_FILE);
const reads = [...ui.matchAll(/\.text\(\)/g)].length;
const reader = ui.match(new RegExp(`async function ${IMPORT_READER}\\(file\\) \\{([\\s\\S]*?)\\n\\}`));
ok("import: one File.text() call, inside the guarded reader", reads === 1 && !!reader && reader[1].includes(".text()"), { reads });
ok("import: the size is checked before the file is read",
   !!reader && reader[1].indexOf("IMPORT_FILE_MAX_BYTES") > -1 && reader[1].indexOf("IMPORT_FILE_MAX_BYTES") < reader[1].indexOf(".text()"));
ok("import: the limit is a named constant", Number.isInteger(C.IMPORT_FILE_MAX_BYTES) && C.IMPORT_FILE_MAX_BYTES > 0);
ok("import: both import paths use the reader", (ui.match(new RegExp(`${IMPORT_READER}\\(file\\)`, "g")) || []).length >= 3);

// ── B. settings import ──
const LEVELS = new Set(Object.values(C.LEVEL));
let bOut = { threw: 0, ok: 0, bad: [] };
for (let i = 0; i < ITERATIONS; i++) {
  const settings = value(0);
  const file = asFile(rnd() < 0.8 ? { format: SIO.SETTINGS_FORMAT, stateSchema: value(MAX_DEPTH), settings } : value(0));
  try {
    const state = SS.normalizeState(SIO.fromSettingsFile(file));
    if (!LEVELS.has(state.level) || !LEVELS.has(state.startupLevel) || hasInjectedProto(state)) bOut.bad.push(file);
    else bOut.ok++;
  } catch (e) {
    if (!(e instanceof Error)) bOut.bad.push({ thrown: String(e) });
    else bOut.threw++;
  }
}
ok(`settings import: ${ITERATIONS} random/hostile files → an Error or a valid state (${bOut.ok} accepted, ${bOut.threw} refused)`,
   bOut.bad.length === 0, bOut.bad.slice(0, 2));

// ── C. domain helpers ──
let cBad = [];
for (let i = 0; i < ITERATIONS; i++) {
  const s = rnd() < 0.5 ? str() : pick(URL_PIECES) + str() + pick(URL_PIECES) + str();
  try {
    const p = D.parseHttpUrl(s);
    if (p !== null && (typeof p !== "object" || typeof p.host !== "string")) cBad.push({ fn: "parseHttpUrl", s });
    for (const fn of ["registeredDomain", "tldOf"]) {
      const r = D[fn](s);
      if (typeof r !== "string") cBad.push({ fn, s, r });
    }
    if (typeof D.isPrivateHost(s) !== "boolean") cBad.push({ fn: "isPrivateHost", s });
  } catch (e) { cBad.push({ s, error: e.message }); }
}
ok(`domain helpers: ${ITERATIONS} random hosts/URLs, no throw, promised types`, cBad.length === 0, cBad.slice(0, 3));

// ── D. message gate ──
const allTypes = Object.entries(MT).filter(([k, v]) => k.startsWith("MSG_") && typeof v === "string").map(([, v]) => v);
const origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
let dBad = [];
for (let i = 0; i < ITERATIONS; i++) {
  const sender = pick([
    { url: str(), tab: { id: int(100) } },
    { url: `https://${str()}`, tab: { id: int(100) } },
    { url: str() },
    { url: `${origin}${str()}` },
    { tab: { id: str() } },
    value(1)
  ]);
  const type = rnd() < 0.8 ? pick(allTypes) : str();
  const kind = G.senderKind(sender, origin);
  const allowed = G.isMessageAllowed(type, kind);
  if (kind === MT.SENDER_KIND.CONTENT_SCRIPT && allowed && !MT.CONTENT_SCRIPT_MESSAGES.has(type)) dBad.push({ sender, type });
  if (kind === null && allowed) dBad.push({ sender, type, unknown: true });
}
ok(`message gate: ${ITERATIONS} random senders/types, never more than declared`, dBad.length === 0, dBad.slice(0, 2));

// ── E. ClickFix patterns on worst-case inputs ──
const cf = read(CLICKFIX_FILE);
const maxChars = Number((cf.match(/const MAX_INSPECTED_CHARS = (\d+);/) || [])[1]);
const block = (cf.match(/const STRONG_PATTERNS = \[([\s\S]*?)\n\s*\];/) || [])[1] || "";
const patterns = [...block.matchAll(/^\s*\/(.+)\/([a-z]*),\s*$/gm)].map(([, src, flags]) => new RegExp(src, flags));
ok("ClickFix: patterns and input limit read from the shipped scriptlet", patterns.length > 0 && maxChars > 0, { patterns: patterns.length, maxChars });
const words = ["powershell ", "pwsh ", "iex ", "curl ", "wget ", "nohup ", "xattr -", "base64 -d ", "python -c ", "osascript ", "| ", "/c ", "-w ", "http:", " "];
const worst = [
  ...words.map((w) => w.repeat(Math.ceil(maxChars / w.length)).slice(0, maxChars)),
  " ".repeat(maxChars), "a".repeat(maxChars),
  Array.from({ length: maxChars }, () => pick(words)[0]).join("")
];
let slowest = { ms: 0 };
for (const re of patterns) {
  for (const input of worst) {
    const t0 = performance.now();
    re.test(input);
    const ms = performance.now() - t0;
    if (ms > slowest.ms) slowest = { ms, re: re.source.slice(0, 60), input: input.slice(0, 20) };
  }
}
ok(`ClickFix: ${patterns.length} patterns × ${worst.length} worst-case inputs of ${maxChars} chars, each under ${SLOW_PATTERN_MS} ms`,
   slowest.ms < SLOW_PATTERN_MS, slowest);

// ── F. logs ──
function listJs(rel) {
  const p = join(EXT, rel);
  if (!existsSync(p)) return [];
  if (statSync(p).isFile()) return rel.endsWith(".js") ? [rel] : [];
  return readdirSync(p).flatMap((n) => listJs(`${rel}/${n}`));
}
const logHits = [];
for (const rel of LOG_SCAN_DIRS.flatMap(listJs)) {
  for (const m of read(rel).matchAll(LOG_CALL_RE)) {
    const args = m[1].replace(/(["'`])(?:\\.|(?!\1).)*\1/g, "");      // ignore text inside string literals
    if (ADDRESS_ARG_RE.test(args)) logHits.push(`${rel}: ${m[0].slice(0, 90)}`);
  }
}
ok("logs: no console call prints an address variable (C52)", logHits.length === 0, logHits.slice(0, 3));
const label = G.senderLabel({ url: "https://bank.example/login?token=abc#x", tab: { id: 1 } });
ok("logs: a refused sender is named by origin only", label === "https://bank.example", label);

console.log(failures ? `test-untrusted-input: FAIL — ${failures} case(s)` : "test-untrusted-input: ALL PASS");
process.exit(failures ? EXIT.FAILED : EXIT.OK);
