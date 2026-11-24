#!/usr/bin/env node
// ── tools/complete-check.mjs ─────────────────────────────────────────────────────
// THE check suite (Xplainer audit Part D; audit 2026-10-19, finding 23). Runs every check and test in
// a fixed order and reports one line per step. Each step has three outcomes (C38):
//   PASS · FAIL (it ran and found a problem) · DID NOT RUN (missing tool, browser, folder …)
// "Did not run" is never a pass. A step can be skipped on purpose with --skip <id>, but the suite then
// ends INCOMPLETE (exit 3), so a skipped check can never be mistaken for a passed one.
//
// Usage:  node complete-check.mjs [--extension <folder>] [--docs <folder>] [--skip e2e-flows] [--chromium <path>]
//         (5.0.9: without --extension / --docs, repo-layout.mjs defaultRoots() decides — the repo root in the GitHub
//          layout, ../3P-Matrix and ../3P-Matrix-docs when the three release zips are unpacked side by side)
//         (npm run check  — from this folder, after npm install)
// Exit:   0 = every step passed · 1 = a step failed · 2 = a step did not run · 3 = incomplete (skipped)
//
// Every check script in this folder must appear in STEPS (or in STANDALONE with a reason) —
// the suite itself fails otherwise, so a new check can never sit unwired (Part D maintenance rule).
// ─────────────────────────────────────────────────────────────────────────────

import { spawnSync } from "node:child_process";
import { readdirSync, existsSync, readFileSync } from "node:fs";
import { join, resolve, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { defaultRoots, listExtensionFiles } from "./repo-layout.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2, INCOMPLETE: 3 });
const OUTCOME = Object.freeze({ PASS: "PASS", FAIL: "FAIL", DID_NOT_RUN: "DID NOT RUN", SKIPPED: "SKIPPED" });
const STEP_TIMEOUT_MS = 5 * 60 * 1000;
const CHECK_FILE_RE = /^(check|test|e2e)-.*\.mjs$/;
const ESLINT_BIN = join(HERE, "node_modules", "eslint", "bin", "eslint.js");
const ESLINT_CONFIG = join(HERE, "eslint.config.json");
// Vendored DownloadSentinel code. 4.3.0: was "lib/**", which ESLint resolves against the tools folder
// (the cwd), so it never matched ../3P-Matrix/lib — it only passed because the old subset had no hits.
const SKIP_LIB_PATTERN = "**/lib/downloadsentinel/**";
const VENDORED_DIR = "lib";                                     // first-party walks skip the vendored library
const SCRIPT_DIRS = Object.freeze(["security"]);                    // classic scripts, not modules
const SYNTAX_ERROR_LINES = 3;                                       // lines of node's error kept per file

// Ordered steps. args(ext, opts) builds the command line; a step's own exit code follows the
// 0 = pass / 1 = fail / 2 = did not run convention.
const STEPS = Object.freeze([
  { id: "syntax",                what: "node --check on every first-party .js",           run: runSyntax },
  { id: "eslint",                what: "ESLint: no-undef, no-unused-vars, func-style (C9a)", run: runEslint },
  { id: "list-freshness",        what: "shipped data lists rebuilt for this minor version (data-sources.json)", script: "check-list-freshness.mjs" },
  { id: "whitelist",             what: "built-in whitelist: one category + reason per entry, never a download-risk host, removals stay out (4.5.6)", script: "check-whitelist.mjs" },
  { id: "compat-remove",         what: "no backward-compatibility block outlives its COMPAT-REMOVE ≥x.y version (4.5.4)", script: "check-compat-remove.mjs" },
  { id: "dnr-filter",            what: "list rules DNR cannot express are dropped on purpose, unknown shapes fail (4.4.0)", script: "test-dnr-filter.mjs" },
  { id: "spam-tlds-source",      what: "data/spam-tlds.js matches its recorded source (C13a)", script: "build-spam-tlds.mjs", args: (ext) => ["--extension", ext, "--check"] },
  { id: "protection-keys",       what: "registry ↔ PROTECTION_KEY, numbering in display order, no quoted keys (finding 8, 5.0.7)", script: "check-protection-keys.mjs" },
  { id: "protection-refs",       what: "code, tests and README name protections by key, never by display number (C25, 5.0.7)", script: "check-protection-refs.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.docs ? ["--docs", resolve(opts.docs)] : [])] },
  { id: "magic-numbers",         what: "no typed number outside a named constant (B1)",   script: "check-magic-numbers.mjs" },
  { id: "no-eval",               what: "no eval()/Function()/string-timer call sites in first-party code (C43, 4.5.1)", script: "check-no-eval.mjs" },
  { id: "derived-literals",      what: "UI shows derived values, never typed copies (C39a)", script: "check-derived-literals.mjs" },
  { id: "shipped-terms",         what: "LOG_PREFIX + obfuscation thresholds in sync; no uBD-only terms", script: "check-shipped-terms.mjs" },
  { id: "obfuscation-shape",     what: "shared obfuscation-shape detector behind blockObfuscatedEval: eval, Function, string timers in one scriptlet (4.4.3, merged 5.1.2)", script: "test-obfuscation-shape.mjs" },
  { id: "perf-guards",           what: "4.5.4 perf: lazy list modules, merged script scopes, apply dirty check, state snapshot", script: "test-perf-guards.mjs" },
  { id: "state-migration",       what: "schema migrations + Show Matrix normalization",   script: "test-matrix-migration.mjs" },
  { id: "tab-band",              what: "locks reach embedded frames: level-1 allowAllRequests, tab-band session rules, tab bookkeeping, shared-host domains (4.4.5)", script: "test-tab-band.mjs" },
  { id: "compiled-rules",        what: "rule replay cache (Show Matrix, badge, exfil warning) is complete after a SW restart, any wake-up order (5.0.3)", script: "test-compiled-rules.mjs" },
  { id: "small-signals",         what: "small signals add up only with heuristics alone + a dubious source: site check, floor, real Drive case (5.0.4, DS 3.5.6)", script: "test-small-signals.mjs" },
  { id: "site-scorer",           what: "site check: shared weights from DS, platform rule, brand on platform (4.4.0)", script: "test-site-scorer.mjs" },
  { id: "download-active-threat", what: "download check: active-threat floor is the ported site-scorer mechanism (C21), not reinvented (4.5.1)", script: "test-download-active-threat.mjs" },
  { id: "large-binary",          what: "download check: large (32 MB) and huge (650 MB) extensionless binary from a file-sharing host (4.5.6, 4.5.8)", script: "test-large-binary.mjs" },
  { id: "exfil-and-password",    what: "exfiltration rules per level/exemption + channel attribution, password-form decision, ISOLATED twin (4.6.0)", script: "test-exfil-and-password.mjs" },
  { id: "tamper-guard",          what: "Tamper Guard: page-script copies = rules table, levels/arming, destination checks, own wrappers ignored, exceptions, caps (5.1.0)", script: "test-tamper-guard.mjs" },
  { id: "allow-list",            what: "the one allow list: Category: domain format, storage per category, Always allow/ignore, exclusions and warnings per category (5.1.3)", script: "test-allow-list.mjs" },
  { id: "message-gate",          what: "sender kinds per message, fake sign-in warning on the warning page, window-capture listeners, page CSP (C46/C47/C19, 5.0.6); no document listener or MutationObserver in page scripts (5.0.7)", script: "test-message-gate.mjs" },
  { id: "dns-block-styles",      what: "site-check DNS: 5 providers' block rules + default pair and its schema-5 migration (4.5.8)", script: "test-dns-block-styles.mjs" },
  { id: "wasm-wrappers",         what: "blockWebAssembly never wraps fetch (5.1.3); its arrayBuffer/XHR wrappers hand back the native result; behaviour kept", script: "test-wasm-wrappers.mjs" },
  { id: "untrusted-input",       what: "seeded fuzz: settings import, domain helpers, message gate, ClickFix pattern cost; import size limit (C50, C51, 5.0.7)", script: "test-untrusted-input.mjs" },
  { id: "permission-additions",  what: "no permission added since the previous release without a stated approval (C36, 5.0.7)", script: "check-permission-additions.mjs" },
  { id: "release-contents",      what: "each release zip holds only what tools/package-release.mjs declares; changelog versions congruent (5.0.7)", script: "package-release.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.docs ? ["--docs", resolve(opts.docs)] : [])] },
  { id: "mv3",                   what: "Manifest V3 compliance: manifest + code (shared with DownloadSentinel, 4.4.0)", script: "check-mv3.mjs",
    args: (ext) => ["--extension", ext] },
  { id: "e2e-embedded-frames",   what: "real Chromium: locks hold for nested frames — allowAllRequests + tab band (4.4.5)", script: "e2e-embedded-frames.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.chromium ? ["--chromium", opts.chromium] : [])] },
  { id: "e2e-flows",             what: "real Chromium: every router flow end to end",     script: "e2e-flows.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.chromium ? ["--chromium", opts.chromium] : [])] },
  { id: "e2e-page-protections",  what: "real Chromium: browser-locker, notification prompts, password-form warning, exfiltration warning (4.6.0); ClickFix/skimmer warnings against a hostile page (5.0.7)", script: "e2e-page-protections.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.chromium ? ["--chromium", opts.chromium] : [])] },
  { id: "e2e-worker-blocks",     what: "real Chromium: WebAssembly/WebSocket blocks hold in dedicated and shared workers; blockWasmDubious and blockAbusedTlds by host (5.0.5)", script: "e2e-worker-blocks.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.chromium ? ["--chromium", opts.chromium] : [])] },
  { id: "e2e-tamper-guard",      what: "real Chromium: Tamper Guard warning windows — json-edit-like data edit, hostile page, card skimmer, exceptions, level 4 (5.1.0)", script: "e2e-tamper-guard.mjs",
    args: (ext, opts) => ["--extension", ext, ...(opts.chromium ? ["--chromium", opts.chromium] : [])] }
]);
// Scripts in this folder that are deliberately NOT suite steps, with the reason.
const STANDALONE = Object.freeze({
  "package-release-state.mjs": "release step: run when packaging, writes package-release-state.json",
  "build-spam-tlds.mjs":       "generator; the suite runs it only in --check mode (step spam-tlds-source)",
  "update-top-sites.mjs":      "list rebuild (network — CrUX fetched on demand); once per minor release — the suite enforces it via list-freshness"
});

function parseArgs(argv) {
  const opts = { extension: null, docs: null, skip: new Set(), chromium: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--extension") opts.extension = argv[++i];
    else if (argv[i] === "--skip") opts.skip.add(argv[++i]);
    else if (argv[i] === "--chromium") opts.chromium = argv[++i];
    else if (argv[i] === "--docs") opts.docs = argv[++i];
  }
  return opts;
}

function outcomeOf(status) {
  if (status === EXIT.OK) return OUTCOME.PASS;
  if (status === EXIT.FAILED) return OUTCOME.FAIL;
  return OUTCOME.DID_NOT_RUN;                                       // 2, a crash, a timeout, a signal
}

function exec(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: HERE, encoding: "utf8", timeout: STEP_TIMEOUT_MS });
  return { status: r.error ? EXIT.DID_NOT_RUN : r.status, output: `${r.stdout || ""}${r.stderr || ""}${r.error ? r.error.message : ""}` };
}

// 5.0.9: the extension's own files only (repo layout: tools/ and the documents are left out — repo-layout.mjs).
function listFirstPartyJs(dir) {
  return listExtensionFiles(dir, { skipDirs: [VENDORED_DIR], exts: [".js"] });
}

// Syntax only — nothing is executed: modules are fed to `node --check --input-type=module` on stdin,
// the classic MAIN-world scripts (security/) to plain `node --check`.
function runSyntax(ext) {
  const failures = [];
  for (const f of listFirstPartyJs(ext)) {
    const isScript = SCRIPT_DIRS.some((d) => f.startsWith(join(ext, d) + sep));
    const r = isScript
      ? spawnSync(process.execPath, ["--check", f], { encoding: "utf8", timeout: STEP_TIMEOUT_MS })
      : spawnSync(process.execPath, ["--check", "--input-type=module"], { input: readFileSync(f, "utf8"), encoding: "utf8", timeout: STEP_TIMEOUT_MS });
    if (r.error) return { status: EXIT.DID_NOT_RUN, output: r.error.message };
    if (r.status !== EXIT.OK) failures.push(`${relative(ext, f)}: ${(r.stderr || "").trim().split("\n").slice(0, SYNTAX_ERROR_LINES).join(" | ")}`);
  }
  return failures.length ? { status: EXIT.FAILED, output: failures.join("\n") } : { status: EXIT.OK, output: "" };
}

function runEslint(ext) {
  if (!existsSync(ESLINT_BIN)) return { status: EXIT.DID_NOT_RUN, output: "eslint not installed (npm install in the tools folder)" };
  const r = exec(process.execPath, [ESLINT_BIN, "--no-eslintrc", "-c", ESLINT_CONFIG, "--ignore-pattern", SKIP_LIB_PATTERN, ext]);
  return { status: r.status === EXIT.OK ? EXIT.OK : r.status === EXIT.FAILED ? EXIT.FAILED : EXIT.DID_NOT_RUN, output: r.output };
}

function unwiredScripts() {
  const wired = new Set(STEPS.filter((s) => s.script).map((s) => s.script));
  return readdirSync(HERE).filter((n) => (CHECK_FILE_RE.test(n) || n in STANDALONE) && !wired.has(n) && !(n in STANDALONE));
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const fallback = defaultRoots(HERE);
  opts.extension = opts.extension || fallback.extension;
  opts.docs = opts.docs || fallback.docs;
  if (!opts.extension || !existsSync(join(opts.extension, "manifest.json"))) {
    console.error("complete-check: DID NOT RUN — missing or invalid --extension <folder>");
    process.exit(EXIT.DID_NOT_RUN);
  }
  const ext = resolve(opts.extension);
  const results = [];
  const unwired = unwiredScripts();
  results.push({ id: "suite-wiring", what: "every check script is a step or declared standalone",
    outcome: unwired.length ? OUTCOME.FAIL : OUTCOME.PASS, output: unwired.length ? `unwired: ${unwired.join(", ")}` : "" });

  for (const step of STEPS) {
    if (opts.skip.has(step.id)) { results.push({ ...step, outcome: OUTCOME.SKIPPED, output: "" }); continue; }
    const r = step.run ? step.run(ext, opts)
                       : exec(process.execPath, [join(HERE, step.script), ...(step.args ? step.args(ext, opts) : ["--extension", ext])]);
    results.push({ ...step, outcome: outcomeOf(r.status), output: r.output });
  }

  const width = Math.max(...results.map((r) => r.id.length));
  for (const r of results) {
    console.log(`${r.outcome.padEnd(OUTCOME.DID_NOT_RUN.length)}  ${r.id.padEnd(width)}  ${r.what}`);
    if (r.outcome === OUTCOME.FAIL || r.outcome === OUTCOME.DID_NOT_RUN) {
      for (const line of r.output.trim().split("\n")) console.log(`      ${line}`);
    }
  }
  const count = (o) => results.filter((r) => r.outcome === o).length;
  const summary = `${count(OUTCOME.PASS)} passed, ${count(OUTCOME.FAIL)} failed, ${count(OUTCOME.DID_NOT_RUN)} did not run, ${count(OUTCOME.SKIPPED)} skipped`;
  if (count(OUTCOME.FAIL)) { console.log(`complete-check: FAIL — ${summary}`); process.exit(EXIT.FAILED); }
  if (count(OUTCOME.DID_NOT_RUN)) { console.log(`complete-check: DID NOT COMPLETE — ${summary}`); process.exit(EXIT.DID_NOT_RUN); }
  if (count(OUTCOME.SKIPPED)) { console.log(`complete-check: INCOMPLETE — ${summary} (a skipped check has not passed)`); process.exit(EXIT.INCOMPLETE); }
  console.log(`complete-check: PASS — ${summary}`);
  process.exit(EXIT.OK);
}

main();
