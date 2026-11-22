#!/usr/bin/env node
// ── tools/test-compiled-rules.mjs ────────────────────────────────────────────────
// Unit test (5.0.3) for core/apply-manager.js's compiled-rule cache, the ONE copy of "the rules Chrome
// has" that Show Matrix (Script/Frame/Level mode), the badge counter and the exfiltration warning replay.
// Real report: www.foxnews.com at level 3 — Chrome blocked the .fox scripts, Show Matrix showed them
// allowed. Cause: after an idle service-worker restart the start-up session apply compiled "session
// rules + an EMPTY dynamic set" as if complete, so the lazy load from Chrome never ran.
// Each case drives the REAL module against a stub that holds the rules Chrome kept across the restart.
// No level, host or TLD is typed into an assertion: they come from the settings block or the extension.
//
// Usage:  node test-compiled-rules.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const SCENARIO = Object.freeze({
  pageHost:  "www.foxnews.com",            // the reported page (on a safer-region TLD)
  outsideTld: "fox",                       // the reported script TLD — asserted NOT to be a safer region below
  scriptHost: "prod-foxkit.kts.fox",       // the reported blocked script host
  tabId: 1
});
const SAFER_TLDS_OF_REPORT = Object.freeze(["com", "net", "org", "io", "ai", "edu", "gov", "nl", "uk", "eu"]);   // the user's list in the report
const SCRIPT_PATH = "/js/sdk/event.js";

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-compiled-rules: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const extUrl = (rel) => pathToFileURL(resolve(ext, rel)).href;

// ── Chrome stub: what Chrome itself holds (survives a SW restart); guarded reset per case ────
const chromeHas = { dynamic: [], session: [] };
let readGate = null;                       // when set, getDynamicRules waits for it (in-flight read case)
function resetChrome() { chromeHas.dynamic = []; chromeHas.session = []; readGate = null; }
const clone = (x) => JSON.parse(JSON.stringify(x));
globalThis.chrome = {
  declarativeNetRequest: {
    getDynamicRules: async () => { if (readGate) await readGate; return clone(chromeHas.dynamic); },
    getSessionRules: async () => clone(chromeHas.session),
    updateDynamicRules: async ({ addRules }) => { chromeHas.dynamic = clone(addRules); },
    updateSessionRules: async ({ addRules }) => { chromeHas.session = clone(addRules); },
    isRegexSupported: async () => ({ isSupported: true })
  },
  storage: { session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
             local:   { get: async () => ({}), set: async () => {}, remove: async () => {} },
             onChanged: { addListener() {} } },
  tabs: { query: async () => [] },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setIcon: async () => {} },
  runtime: { getURL: (p) => p, getManifest: () => ({ version: "0" }), lastError: null }
};

let C, S, RB, RM;
try {
  C = await import(extUrl("data/constants.js"));
  S = await import(extUrl("data/state-storage.js"));
  RB = await import(extUrl("core/rule-builder.js"));
  RM = await import(extUrl("core/rule-matcher.js"));
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

// A fresh apply-manager module instance = a fresh service-worker life (module state starts empty).
let swLife = 0;
async function freshServiceWorker() {
  swLife++;
  try { return await import(`${extUrl("core/apply-manager.js")}?sw=${swLife}`); }
  catch (e) { didNotRun(`cannot import core/apply-manager.js: ${e.message}`); }
  return null;
}

let failed = 0;
function ok(name, cond, detail = "") { console.log(`${cond ? "      PASS" : "      FAIL"} ${name}${cond ? "" : "  " + detail}`); if (!cond) failed++; }

const state = S.defaultState();
state.level = C.LEVEL.SMART;
state.safeZone.tlds = SAFER_TLDS_OF_REPORT.slice();
const req = Object.freeze({ url: `https://${SCENARIO.scriptHost}${SCRIPT_PATH}`, type: "script", initiator: `https://${SCENARIO.pageHost}`, tabId: SCENARIO.tabId });
const BLOCK = C.MATRIX_ACTION.BLOCK;

// Ground truth: the rules Chrome would hold for this state block the request (if not, the cases below prove nothing).
const truth = RM.matchOutcome(RM.compileRules(RB.buildDynamicRules(state, { cdnRegexSupported: true })), req).action;
ok("precondition: the script TLD is not a safer region", !state.safeZone.tlds.includes(SCENARIO.outsideTld));
ok("precondition: the level rules block the request", truth === BLOCK, `got ${truth}`);

async function replay(AM) {
  const [all, mode] = await Promise.all([AM.getCompiledRules(), AM.getCompiledModeRules()]);
  return { all: RM.matchOutcome(all, req).action, mode: RM.matchOutcome(mode, req).action };
}
function seedChromeAsBeforeRestart() {
  resetChrome();
  chromeHas.dynamic = clone(RB.buildDynamicRules(state, { cdnRegexSupported: true }));
}

// 1 — the reported order: SW restart, start-up session apply finishes BEFORE anything reads the cache.
seedChromeAsBeforeRestart();
let AM = await freshServiceWorker();
await AM.applySessionRules(state);
let r = await replay(AM);
ok("restart, session apply first: replay blocks (Show Matrix Script, badge, exfil)", r.all === BLOCK, `got ${r.all}`);
ok("restart, session apply first: Level mode blocks", r.mode === BLOCK, `got ${r.mode}`);

// 2 — the order that always worked: a reader loads from Chrome first.
seedChromeAsBeforeRestart();
AM = await freshServiceWorker();
r = await replay(AM);
ok("restart, read first: replay blocks", r.all === BLOCK && r.mode === BLOCK, JSON.stringify(r));

// 3 — a read in flight while the session apply lands: the applied half is kept, the other half is read.
seedChromeAsBeforeRestart();
AM = await freshServiceWorker();
let open; readGate = new Promise((res) => { open = res; });
const pending = replay(AM);
await AM.applySessionRules(state);
open();
r = await pending;
ok("restart, read in flight during session apply: replay blocks", r.all === BLOCK && r.mode === BLOCK, JSON.stringify(r));

// 4 — a full apply in this SW life: the cache follows the new state without asking Chrome.
resetChrome();
AM = await freshServiceWorker();
const lifeBefore = { ...state, safeZone: { ...state.safeZone, tlds: state.safeZone.tlds.concat(SCENARIO.outsideTld) } };   // the TLD made a safer region…
const registered = new Map();                                                                                               // stateful: no false "missing" retries
chrome.scripting = { getRegisteredContentScripts: async () => [...registered.values()],
                     unregisterContentScripts: async ({ ids }) => { for (const id of ids) registered.delete(id); },
                     registerContentScripts: async (regs) => { for (const reg of regs) registered.set(reg.id, clone(reg)); } };
await AM.applyState(lifeBefore);
ok("apply: a safer-region TLD is allowed", (await replay(AM)).all !== BLOCK);
await AM.applyState(state);                                                                                                 // …and removed again
ok("apply: removing it from safer regions blocks again", (await replay(AM)).all === BLOCK);

resetChrome();
console.log(failed ? `test-compiled-rules: ${failed} FAILED` : "test-compiled-rules: all pass");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
