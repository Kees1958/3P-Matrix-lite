#!/usr/bin/env node
// ── tools/test-perf-guards.mjs ───────────────────────────────────────────────────
// Unit test (4.5.4) for the performance changes and the guards they rely on
// (project doc PERF_4.5.3_chrome_engine_and_proposals.md):
//   P4  list modules are precompiled JSON strings, parsed on FIRST LOOKUP only (no JSON.parse at import);
//       every wrapper answers like the shipped data, and resetToDefault() releases + rebuilds (C-lifecycle)
//   P5  merged content-script registrations change no file's scope (same matches + excludeMatches)
//   P2  applying the same state twice makes NO second Chrome write (dynamic, session, scripts)
//   P3  the state snapshot: callers get private copies, saveState() replaces it, a storage change drops it
// Every expected value comes from the extension's own data and constants — nothing is typed here.
//
// Usage:  node test-perf-guards.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { readListData, LIB_UTIL } from "./list-modules.mjs";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-perf-guards: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);
const lib = (name) => load(join(LIB_UTIL, `${name}.js`));

let failed = 0;
function ok(name, cond, info) {
  if (!cond) failed++;
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : "  " + JSON.stringify(info)}`);
}

// ── Chrome mock (only what the modules under test call); every write is counted ──
const writes = { dynamic: 0, session: 0, register: 0, unregister: 0 };
const chromeState = { dynamic: [], session: [], scripts: [], local: {}, listeners: [] };
globalThis.chrome = {
  runtime: { getURL: (p) => p, getManifest: () => ({ version: "0" }) },
  tabs: { query: async () => [] },
  declarativeNetRequest: {
    isRegexSupported: async () => ({ isSupported: true }),
    getDynamicRules: async () => structuredClone(chromeState.dynamic),
    getSessionRules: async () => structuredClone(chromeState.session),
    updateDynamicRules: async ({ removeRuleIds, addRules }) => { writes.dynamic++; chromeState.dynamic = chromeState.dynamic.filter((r) => !removeRuleIds.includes(r.id)).concat(structuredClone(addRules)); },
    updateSessionRules: async ({ removeRuleIds, addRules }) => { writes.session++; chromeState.session = chromeState.session.filter((r) => !removeRuleIds.includes(r.id)).concat(structuredClone(addRules)); }
  },
  scripting: {
    getRegisteredContentScripts: async () => structuredClone(chromeState.scripts),
    registerContentScripts: async (regs) => { writes.register++; chromeState.scripts.push(...structuredClone(regs)); },
    unregisterContentScripts: async ({ ids }) => { writes.unregister++; chromeState.scripts = chromeState.scripts.filter((s) => !ids.includes(s.id)); }
  },
  storage: {
    local: {
      get: async (key) => ({ [key]: structuredClone(chromeState.local[key]) }),
      set: async (obj) => { Object.assign(chromeState.local, structuredClone(obj)); for (const l of chromeState.listeners) l(Object.fromEntries(Object.keys(obj).map((k) => [k, {}])), "local"); }
    },
    onChanged: { addListener: (fn) => chromeState.listeners.push(fn) }
  }
};

// ── P4: lazy, precompiled list modules ───────────────────────────────────────
const LIST_WRAPPERS = ["PublicSuffixList", "HostList", "TopSitesFilter", "Brands", "SuspiciousTlds", "SuspiciousDomains",
                       "RiskyHostingSites", "UrlShorteners", "GovSuffixes", "RdapCctlds", "PlatformSuffixes"];
const nativeParse = JSON.parse;
let parses = 0;
JSON.parse = function countingParse(...a) { parses++; return Reflect.apply(nativeParse, JSON, a); };
let W = {};
try { for (const n of LIST_WRAPPERS) W[n] = (await lib(n))[n]; } catch (e) { didNotRun(`cannot import list wrappers: ${e.message}`); }
ok("P4: importing all list wrappers parses nothing (data is parsed on first lookup)", parses === 0, { parses });

const data = {};
for (const n of LIST_WRAPPERS) data[n] = await readListData(ext, n);
JSON.parse = nativeParse;

{
  const [plain] = data.PublicSuffixList.rules.filter((r) => r.includes("."));
  ok("P4: PublicSuffixList answers from the shipped rules", W.PublicSuffixList.getRegisteredDomain(`a.b.${plain}`) === `b.${plain}`, plain);
  const [host, hit] = Object.entries(data.HostList)[0];
  ok("P4: HostList answers from the shipped table", W.HostList.lookup(host)?.score === hit.score, host);
  const [tld, tScore] = Object.entries(data.SuspiciousTlds)[0];
  ok("P4: SuspiciousTlds answers from the shipped table", W.SuspiciousTlds.lookup(tld)?.score === tScore, tld);
  const [dom, dScore] = Object.entries(data.SuspiciousDomains)[0];
  ok("P4: SuspiciousDomains answers from the shipped table", W.SuspiciousDomains.lookup(dom)?.score === dScore, dom);
  const site = data.RiskyHostingSites[0];
  ok("P4: RiskyHostingSites answers from the shipped list", W.RiskyHostingSites.lookup(site.host)?.score === site.score, site.host);
  for (const n of ["UrlShorteners", "GovSuffixes", "RdapCctlds", "PlatformSuffixes"]) {
    ok(`P4: ${n} list + set equal the shipped list`, JSON.stringify(W[n].list) === JSON.stringify(data[n]) && W[n].set.size === new Set(data[n]).size, n);
  }
  const brand = data.Brands.find((b) => !b.wholeNameOnly && !b.keyword.includes("."));
  ok("P4: Brands knows the shipped brand websites", W.Brands.isExemptHost(brand.domains[0]) && W.Brands.list.length === data.Brands.length, brand.keyword);
  ok("P4: TopSitesFilter contains a brand website (built into the filter)", W.TopSitesFilter.mightBeTopSite(brand.domains[0]), brand.domains[0]);
  // init / clear / release: resetToDefault() releases the derived structures; the next lookup rebuilds them
  for (const n of LIST_WRAPPERS) W[n].resetToDefault();
  ok("P4: after resetToDefault() every wrapper answers again (lazy rebuild)",
     W.PublicSuffixList.getRegisteredDomain(`a.b.${plain}`) === `b.${plain}` && W.HostList.lookup(host)?.score === hit.score &&
     W.UrlShorteners.set.size === new Set(data.UrlShorteners).size && W.Brands.list.length === data.Brands.length);
}

// ── P5: merged registrations change no file's scope ──────────────────────────
let C, S, SB;
try {
  C = await load("data/constants.js");
  S = await load("data/state-storage.js");
  SB = await load("core/script-builder.js");
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

const scopeOf = (r) => JSON.stringify([[...r.matches].sort(), [...(r.excludeMatches || [])].sort()]);
function fileScopes(regs) {
  const m = new Map();                                     // file → sorted list of scope keys
  for (const r of regs) for (const f of r.js) m.set(f, [...(m.get(f) || []), scopeOf(r)].sort());
  return JSON.stringify([...m.entries()].sort());
}
function sampleState(level) {
  const s = S.defaultState();
  s.level = level;
  const [lockSite] = Object.keys(data.SuspiciousDomains);   // any real host from shipped data
  s.siteLocks = { [lockSite]: C.LEVEL_MAX }; s.siteLocksOrder = [lockSite];
  return s;
}
for (let level = C.LEVEL_MIN; level <= C.LEVEL_MAX; level++) {
  const st = sampleState(level);
  const grouped = SB.buildScriptRegistrations(st), single = SB.buildScriptRegistrations(st, { grouped: false });
  ok(`P5: level ${level} — every script file keeps exactly its scope after merging (${single.length} → ${grouped.length})`,
     fileScopes(grouped) === fileScopes(single) && new Set(grouped.map((r) => r.id)).size === grouped.length);
}

// ── P2: the same state applied twice → no second write ───────────────────────
let AM;
try { AM = await load("core/apply-manager.js"); } catch (e) { didNotRun(`cannot import core/apply-manager.js: ${e.message}`); }
{
  const st = sampleState(C.LEVEL_MAX - 1);
  await AM.applyState(st);
  const first = { ...writes };
  ok("P2: the first apply writes rules and scripts", first.dynamic === 1 && first.register >= 1, first);
  await AM.applyState(st);
  ok("P2: the same state again → no Chrome write at all", JSON.stringify(writes) === JSON.stringify(first), { first, now: writes });
  const changed = sampleState(C.LEVEL_MAX);
  await AM.applyState(changed);
  ok("P2: a changed state is written", writes.dynamic === first.dynamic + 1, writes);
}

// ── P3: state snapshot ────────────────────────────────────────────────────────
{
  const a = await S.loadState();
  a.level = C.LEVEL_MIN;                                     // a caller changes ITS copy …
  const b = await S.loadState();
  ok("P3: loadState() hands out private copies (a caller's change never reaches the snapshot)", b.level !== C.LEVEL_MIN || S.defaultState().level === C.LEVEL_MIN);
  b.level = C.LEVEL_MAX;
  await S.saveState(b);
  ok("P3: saveState() → the next load sees the new value", (await S.loadState()).level === C.LEVEL_MAX);
  const raw = structuredClone(chromeState.local[C.STORAGE_KEY_STATE]);
  raw.level = C.LEVEL_MIN;
  chromeState.local[C.STORAGE_KEY_STATE] = raw;              // a write by another writer …
  for (const l of chromeState.listeners) l({ [C.STORAGE_KEY_STATE]: {} }, C.STORAGE_AREA_LOCAL);   // … announced by Chrome
  ok("P3: a storage change drops the snapshot → the next load reads the other writer's value", (await S.loadState()).level === C.LEVEL_MIN);
}

console.log(failed ? `test-perf-guards: ${failed} FAILED` : "test-perf-guards: ALL PASS");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
