#!/usr/bin/env node
// ── tools/test-tab-band.mjs ──────────────────────────────────────────────────────
// Unit test (4.4.5) for site locks reaching EMBEDDED frames: the level-1 allowAllRequests rule, the
// tab band (session rules scoped by tabId), their replay in core/rule-matcher.js (badge counter and
// Show Matrix), the tab bookkeeping (core/tab-locks.js) and the shared-hosting registered domain.
// Scenario = the bug that started it: hogeschooltio-my.sharepoint.com locked, its Word Online page
// embeds word-edit.officeapps.live.com, whose requests have THAT frame as initiator.
// Every value comes from the extension's own constants — no priority, id or level is typed here.
//
// Usage:  node test-tab-band.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-tab-band: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);

// Minimal chrome stub: tab-locks.rebuild() reads chrome.tabs.query.
let _tabs = [];
globalThis.chrome = { tabs: { query: async () => _tabs }, runtime: { getURL: (p) => p, getManifest: () => ({ version: "0" }) } };

let C, S, RB, RM, TL, D, MD;
try {
  C = await load("data/constants.js");
  S = await load("data/state-storage.js");
  RB = await load("core/rule-builder.js");
  RM = await load("core/rule-matcher.js");
  TL = await load("core/tab-locks.js");
  D = await load("util/domain.js");
  MD = await load("core/matrix-disposition.js");
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

let failed = 0;
function ok(name, cond, detail = "") { console.log(`${cond ? "      PASS" : "      FAIL"} ${name}${cond ? "" : "  " + detail}`); if (!cond) failed++; }
function eq(name, got, want) { ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); }

const TOP = "hogeschooltio-my.sharepoint.com";
const FRAME_HOST = "word-edit.officeapps.live.com";
const TAB = 7, OTHER_TAB = 8;
const SITE = D.registeredDomain(TOP);
// The requests Word Online makes from its iframe (initiator = the frame), and one from the page itself.
const REQS = Object.freeze({
  cdnScript:   { url: "https://res-1.cdn.office.net/x.js",           type: "script",    initiator: "https://" + FRAME_HOST },
  telemetry:   { url: "https://browser.pipe.aria.microsoft.com/x.js", type: "script",    initiator: "https://" + FRAME_HOST },
  backToSite:  { url: `https://${TOP}/_api/x.js`,                     type: "script",    initiator: "https://" + FRAME_HOST },
  loginFrame:  { url: "https://login.microsoftonline.com/x",          type: "sub_frame", initiator: "https://" + FRAME_HOST },
  plainHttp:   { url: "http://tracker.example/x.png",                 type: "image",     initiator: "https://" + FRAME_HOST }
});

// A request from an unrelated site to a host on no allow list at any level (judged by the session level only).
const UNLISTED = Object.freeze({ url: "https://unlisted-3p.example/x.js", type: "script", initiator: "https://other.example" });

function stateWith(sessionLevel, lockLevel) {
  const s = S.normalizeState(S.defaultState());
  s.level = sessionLevel;
  s.siteLocks[SITE] = lockLevel; s.siteLocksOrder = [SITE];
  return s;
}
const OPTS = { cdnRegexSupported: true };
// What Chrome would decide for a request in tab `tabId` (dynamic + session rules replayed together).
function outcome(state, req, tabId, topHost = TOP) {
  const tabsByLevel = TL.tabsByLevel();
  const rules = [...RB.buildDynamicRules(state, OPTS), ...RB.buildSessionRules(state, tabsByLevel, [], OPTS)];
  return RM.matchOutcome(RM.compileRules(rules), { ...req, tabId }, topHost).action;
}
async function bandTab(state, tabId, host = TOP) {
  _tabs = [{ id: tabId, url: `https://${host}/x` }];
  await TL.rebuild(state);
}

// ── shared hosting: one lock = one tenant ─────────────────────────────────────
const [SUFFIX] = C.SHARED_HOSTING_SUFFIXES;
eq("tenant host is its own registered domain", D.registeredDomain(TOP), TOP);
eq("sub-hosts of a tenant share the tenant's domain", D.registeredDomain("a.b." + TOP), TOP);
ok("two tenants differ", D.registeredDomain("a." + SUFFIX) !== D.registeredDomain("b." + SUFFIX));
eq("the bare suffix is itself", D.registeredDomain(SUFFIX), SUFFIX);
eq("ordinary domains unchanged", D.registeredDomain("www.bbc.co.uk"), "bbc.co.uk");
eq("chromeSite stays PSL-only (Chrome's own 3P test)", D.chromeSite(TOP), SUFFIX);

// ── level 1: allowAllRequests ─────────────────────────────────────────────────
{
  const rules = RB.buildDynamicRules(stateWith(C.LEVEL.STRICT, C.LEVEL.ALLOW_ALL), OPTS);
  const aar = rules.filter((r) => r.action.type === "allowAllRequests");
  eq("one allowAllRequests rule for a level-1 lock", aar.length, 1);
  eq("it covers the locked site's main frames only", [aar[0].condition.requestDomains, aar[0].condition.resourceTypes], [[SITE], ["main_frame"]]);
  ok("it outranks every block rule", rules.filter((r) => r.action.type === "block").every((r) => r.priority < aar[0].priority));
  eq("no allowAllRequests without a level-1 lock", RB.buildDynamicRules(stateWith(C.LEVEL.STRICT, C.LEVEL.HIGH), OPTS).filter((r) => r.action.type === "allowAllRequests").length, 0);
  eq("no dynamic rules at all for session level 1 + level-1 lock but the allow rule", RB.buildDynamicRules(stateWith(C.LEVEL.ALLOW_ALL, C.LEVEL.ALLOW_ALL), OPTS).length, 1);
}
for (const session of [C.LEVEL.MILD, C.LEVEL.SMART, C.LEVEL.HIGH, C.LEVEL.STRICT]) {
  const s = stateWith(session, C.LEVEL.ALLOW_ALL);
  await bandTab(s, TAB);
  const blocked = Object.entries(REQS).filter(([, r]) => outcome(s, r, TAB) === "block").map(([k]) => k);
  eq(`level-1 lock, session level ${session}: nothing from the embedded frame is blocked`, blocked, []);
  ok(`level-1 lock, session level ${session}: another site's frame is still judged by the session level`,
     session < C.LEVEL.SMART || outcome(s, UNLISTED, OTHER_TAB, "other.example") === "block");
}

// ── tab band: lock at 2–5, session level anything ─────────────────────────────
function expectedBlocks(lockLevel) {   // what a PAGE at that level blocks among REQS (3P scripts/frames; L2 only the security rules)
  if (lockLevel === C.LEVEL.STRICT) return ["cdnScript", "telemetry", "backToSite", "loginFrame"];
  if (lockLevel === C.LEVEL.HIGH)   return ["telemetry", "backToSite"];                  // cdn host + built-in login frame allowed
  return [];
}
for (const lock of C.TAB_BAND_LEVELS) {
  for (const session of [C.LEVEL.ALLOW_ALL, C.LEVEL.MILD, C.LEVEL.HIGH, C.LEVEL.STRICT]) {
    const s = stateWith(session, lock);
    await bandTab(s, TAB);
    const blocked = Object.entries(REQS).filter(([k, r]) => k !== "plainHttp" && outcome(s, r, TAB) === "block").map(([k]) => k);
    const want = lock === C.LEVEL.SMART ? blocked : expectedBlocks(lock);   // L3 depends on safer regions/built-in: compared below instead
    eq(`lock ${lock}, session ${session}: embedded frame treated at the LOCK's level`, blocked, want);
  }
}
{
  // Level 3 is data dependent (safer regions, built-in list) — inside the band it must equal what a
  // plain session at level 3 decides for the very same request (no lock, no band).
  const s = stateWith(C.LEVEL.STRICT, C.LEVEL.SMART);
  await bandTab(s, TAB);
  const ref = stateWith(C.LEVEL.SMART, C.LEVEL.SMART); ref.siteLocks = {}; ref.siteLocksOrder = [];
  for (const [k, r] of Object.entries(REQS)) {
    const fromPage = outcome(ref, r, OTHER_TAB, "other.example");
    ok(`lock 3, session 5: ${k} same as a plain level-3 session`, (outcome(s, r, TAB) || null) === (fromPage || null), `${outcome(s, r, TAB)} vs ${fromPage}`);
  }
}
{
  const s = stateWith(C.LEVEL.STRICT, C.LEVEL.MILD);
  await bandTab(s, TAB);
  ok("band is scoped to its tab: the same frame in ANOTHER tab keeps the session level",
     outcome(s, REQS.telemetry, OTHER_TAB, "other.example") === "block");
  ok("high-priority security block (plain-HTTP 3P) still applies inside a level-2 band", outcome(s, { ...REQS.plainHttp, type: "script", url: "http://tracker.example/x.js" }, TAB) === "block");
}

// ── band rules: shape and guards ──────────────────────────────────────────────
{
  const s = stateWith(C.LEVEL.STRICT, C.LEVEL.HIGH);
  const tabs = new Map([[C.LEVEL.HIGH, [TAB]]]);
  const rules = RB.buildSessionRules(s, tabs, [], OPTS);
  ok("session rules exist for a banded tab", rules.length > 0);
  ok("every session rule is tab-scoped", rules.every((r) => Array.isArray(r.condition.tabIds) && r.condition.tabIds.includes(TAB)));
  ok("every session rule outranks every dynamic rule except none (priority ≥ TAB_BAND_BASE)", rules.every((r) => r.priority >= C.TAB_BAND_BASE));
  const dyn = RB.buildDynamicRules(s, OPTS);
  ok("dynamic rules stay below the band", dyn.every((r) => r.priority < C.TAB_BAND_BASE));
  eq("session rule ids are unique", new Set(rules.map((r) => r.id)).size, rules.length);
  ok("no main-frame header rule in the band (headers never appended twice)", !rules.some((r) => r.action.type === "modifyHeaders" && r.condition.resourceTypes.includes("main_frame")));
  eq("no banded tab → no session rules", RB.buildSessionRules(s, new Map(), [], OPTS), []);
  // Show Matrix overrides must also hold inside the band (the reset allow would otherwise cancel them).
  const m = stateWith(C.LEVEL.STRICT, C.LEVEL.HIGH);
  m.matrixRules = { [C.MATRIX_SITE_ALL]: { "login.microsoftonline.com": { frame: C.MATRIX_ACTION.BLOCK } } };
  await bandTab(m, TAB);
  eq("Show Matrix block override applies inside the band", outcome(m, REQS.loginFrame, TAB), "block");
  m.matrixRules = { [C.MATRIX_SITE_ALL]: { "browser.pipe.aria.microsoft.com": { script: C.MATRIX_ACTION.ALLOW } } };
  eq("Show Matrix allow override applies inside the band", outcome(m, REQS.telemetry, TAB), "allow");
  // Guard: too many rules → none (a half band would be worse than none).
  const many = stateWith(C.LEVEL.STRICT, C.LEVEL.HIGH);
  const overrides = {};
  for (let i = 0; i < C.MATRIX_RULES_MAX; i++) overrides[`d${i}.example`] = { script: C.MATRIX_ACTION.BLOCK, frame: C.MATRIX_ACTION.BLOCK };
  many.matrixRules = { [C.MATRIX_SITE_ALL]: overrides };
  const tabs4 = new Map(C.TAB_BAND_LEVELS.map((l) => [l, [TAB]]));
  const warn = console.warn; console.warn = () => {};
  eq("rule-count guard: over the limit → no session rules", RB.buildSessionRules(many, tabs4, [], OPTS), []);
  console.warn = warn;
}

// ── Show Matrix replay follows the band ───────────────────────────────────────
{
  const s = stateWith(C.LEVEL.STRICT, C.LEVEL.MILD);
  await bandTab(s, TAB);
  const rules = [...RB.buildDynamicRules(s, OPTS), ...RB.buildSessionRules(s, TL.tabsByLevel(), [], OPTS)];
  const input = { entries: [{ domain: "unlisted-3p.example", types: ["script"], sampleUrls: { script: UNLISTED.url }, count: 1 }], overrides: {}, level: C.LEVEL.MILD, host: TOP,
                  compiled: RM.compileRules(rules), compiledMode: RM.compileRules(rules.filter(RB.isLevelMechanismRule)) };
  eq("Show Matrix: banded tab at level 2 shows allow", MD.buildMatrixRows({ ...input, tabId: TAB })[0].script.effective, "allow");
  eq("Show Matrix: same rules, an unlocked site in another tab → session level (5) block",
     MD.buildMatrixRows({ ...input, host: "other.example", level: C.LEVEL.STRICT, tabId: OTHER_TAB })[0].script.effective, "block");
}

// ── tab bookkeeping (core/tab-locks.js) ───────────────────────────────────────
{
  const s = stateWith(C.LEVEL.STRICT, C.LEVEL.HIGH);
  _tabs = []; await TL.rebuild(s);
  eq("empty at start", [...TL.tabsByLevel().keys()], []);
  ok("assign: a locked page joins its band", TL.assign(s, TAB, `https://${TOP}/doc`));
  eq("assign: band level", TL.tabsByLevel().get(C.LEVEL.HIGH), [TAB]);
  ok("assign: same page again → no change (no needless re-apply)", !TL.assign(s, TAB, `https://${TOP}/other`));
  ok("assign: navigation to an unlocked site leaves the band", TL.assign(s, TAB, "https://unlocked.example/"));
  eq("assign: band now empty", [...TL.tabsByLevel().keys()], []);
  TL.assign(s, TAB, `https://${TOP}/doc`);
  ok("release: closing the tab frees it", TL.release(TAB));
  ok("release: unknown tab → false", !TL.release(TAB));
  ok("non-web pages never join", !TL.assign(s, TAB, "chrome://extensions") && !TL.assign(s, -1, `https://${TOP}/`));
  const l1 = stateWith(C.LEVEL.STRICT, C.LEVEL.ALLOW_ALL);
  ok("level-1 locks never join a band (allowAllRequests handles them)", !TL.assign(l1, TAB, `https://${TOP}/`));
  // cap guard: more tabs than the band holds → the oldest are dropped, the map stays bounded
  const cap = C.TAB_BAND_TABS_MAX * C.TAB_BAND_LEVELS.length;
  for (let i = 0; i < cap + 50; i++) TL.assign(s, 1000 + i, `https://${TOP}/`);
  const total = [...TL.tabsByLevel().values()].reduce((n, a) => n + a.length, 0);
  ok("cap: total banded tabs never exceed the guard", total <= cap, String(total));
  ok("cap: a band never lists more than TAB_BAND_TABS_MAX tabs in the rules",
     RB.buildSessionRules(s, TL.tabsByLevel(), [], OPTS).every((r) => !r.condition.tabIds || r.condition.tabIds.length <= C.TAB_BAND_TABS_MAX));
  _tabs = []; await TL.rebuild(s);
  eq("rebuild with no tabs releases everything", [...TL.tabsByLevel().keys()], []);
}

console.log(failed ? `test-tab-band: ${failed} FAILED` : "test-tab-band: ALL PASS");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
