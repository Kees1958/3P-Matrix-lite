// ── core/apply-manager.js ─────────────────────────────────────────────────────
// The ONE place that pushes state into Chrome: dynamic DNR rules, session DNR rules (the 4.4.5
// tab band) and content-script registrations. Everything it applies is computed by the pure
// builders (core/rule-builder.js, core/script-builder.js).
//
// Public interface:
//   applyState(state)     — Promise<{ ruleCount, scriptCount }> (dynamic rules + session rules + scripts)
//   applySessionRules(state) — Promise<number> — only the tab-band session rules (a tab was banded,
//                           unbanded or closed: core/tab-locks.js has the new assignment)
//   getCompiledRules()    — Promise<compiled rules> for core/rule-matcher.js (our own
//                           blocks only — badge counter, exfiltration warning, Show Matrix): dynamic +
//                           session rules together; rebuilt after every apply, and after a service-worker
//                           restart the half not yet applied in this SW life is loaded from Chrome
//   getCompiledModeRules() — Promise<compiled rules> without built-in allows / Show Matrix
//                           overrides (Show Matrix "Level mode"), same lifecycle
//
// Guards:
//   - Serialized: a new apply waits for the running one; only the LATEST
//     requested state is applied once the running apply finishes (coalescing). Dynamic+scripts
//     and session rules each have their own coalescer (makeCoalescer), so a tab event never waits
//     for a script re-registration; the session apply reads the tab assignment when it RUNS.
//   - Every regexFilter is validated with isRegexSupported() first (cached):
//     updateDynamicRules() is atomic, so one rejected regex would otherwise
//     fail the whole batch and leave the user unprotected.
//   - 4.5.4 (perf P2) dirty check: each of the three sets (dynamic rules, session rules, script
//     registrations) is compared with what Chrome already has (canonicalKey) and the Chrome call is
//     SKIPPED when they are equal — a setting that does not change them (DNS resolver, VirusTotal key,
//     download settings …) and a service-worker restart no longer re-index DNR or re-register scripts in
//     every renderer. The last-applied key is kept in memory; after a SW restart (key unknown) the
//     comparison is made against Chrome's own get*() result. A failed apply forgets the key, so the next
//     apply always writes.
//   - Script registrations are replaced as a set: our old ids are always
//     unregistered before the new set is registered (nothing stale survives), one id at a
//     time so a stale id from a previous version cannot abort the whole batch, and the
//     result is verified and retried once — an extension UPDATE must never leave the user
//     with no content scripts.
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX, CDN_HOST_REGEX, SCRIPT_ID_PREFIX } from "../data/constants.js";
import { buildDynamicRules, buildSessionRules, collectRegexes, isLevelMechanismRule } from "./rule-builder.js";
import * as TabLocks from "./tab-locks.js";
import * as Badge from "./badge.js";       // 4.7.0 — allHighRisk(): tabs scored phishing this session (alsoHighRisk band)
import { buildScriptRegistrations } from "./script-builder.js";
import { compileRules } from "./rule-matcher.js";

// ── Compiled copies of the rules currently in Chrome (guarded: replaced wholesale) ──
//   _compiled      every rule — the real decision (badge attribution, exfiltration warning, Show Matrix Script/Frame)
//   _compiledMode  the same rules minus built-in allows and Show Matrix overrides (4.2.1:
//                  Show Matrix "Level mode" column) — derived from the SAME array, never rebuilt
// 5.0.3 guard — never compile HALF a rule set. Each half is null until it is known in this SW life
// (applied by us, or read from Chrome). Bug fixed: after an idle SW restart the start-up session
// apply compiled "session rules + an EMPTY dynamic set" as if complete, so the lazy load never ran:
// Show Matrix showed every third party allowed, the badge stopped counting and the exfiltration
// warning stopped opening — until the next settings change.
let _compiled = null;          // compiled rules, or null = not (completely) known yet
let _compiledMode = null;
let _compiledLoading = null;   // in-flight lazy load (shared by concurrent callers)
let _dynamicRules = null;      // dynamic rules Chrome has, or null = unknown in this SW life
let _sessionRules = null;      // session rules (4.4.5 tab band) Chrome has, or null = unknown

function clearCompiled() { _compiled = null; _compiledMode = null; }

function recompile() {
  if (!_dynamicRules || !_sessionRules) { clearCompiled(); return; }   // half known: the next reader loads the rest
  const all = _dynamicRules.concat(_sessionRules);
  _compiled = compileRules(all);
  _compiledMode = compileRules(all.filter(isLevelMechanismRule));
}

// Reads from Chrome only the half (or halves) still unknown; a half applied while the read was in
// flight is newer than what Chrome returned, so it is kept.
function loadCompiled() {
  if (_compiled) return Promise.resolve();
  if (!_compiledLoading) {
    _compiledLoading = Promise.all([
      _dynamicRules || chrome.declarativeNetRequest.getDynamicRules(),
      _sessionRules || chrome.declarativeNetRequest.getSessionRules()
    ])
      .then(([dynamic, session]) => {
        if (!_dynamicRules) _dynamicRules = dynamic;
        if (!_sessionRules) _sessionRules = session;
        recompile();
      })
      .catch((e) => { console.error(LOG_PREFIX, "reading the active rules failed:", e); clearCompiled(); })
      .finally(() => { _compiledLoading = null; });   // release the in-flight guard
  }
  return _compiledLoading;
}

export function getCompiledRules() {
  return loadCompiled().then(() => _compiled || []);
}

export function getCompiledModeRules() {
  return loadCompiled().then(() => _compiledMode || []);
}

// ── Dirty check (4.5.4, perf P2) ─────────────────────────────────────────────
// canonicalKey(list): order-independent text of a rule / registration list — list sorted by id, object
// keys sorted at every depth (array order inside one item is kept: Chrome keeps it). Equal key = equal set.
function canonicalValue(v) {
  if (Array.isArray(v)) return v.map(canonicalValue);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonicalValue(v[k])]));
  return v;
}
function canonicalKey(list) {
  return JSON.stringify([...list].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(canonicalValue));
}

// Script registrations as Chrome reports them carry fields we never set; compare only the fields our
// builder sets (core/script-builder.js baseRegistration), with Chrome's defaults for absent ones.
// Chrome returns match patterns SORTED (verified in Chromium 2026-11), and their order means nothing for
// matching — so pattern lists are compared sorted. `js` keeps its order: it is the execution order.
const SCRIPT_KEY_FIELDS = Object.freeze(["id", "js", "matches", "excludeMatches", "allFrames", "runAt", "world", "persistAcrossSessions"]);
const SCRIPT_PATTERN_FIELDS = new Set(["matches", "excludeMatches"]);
function scriptProjection(reg) {
  const out = {};
  for (const f of SCRIPT_KEY_FIELDS) {
    const v = reg[f];
    if (v === undefined || (Array.isArray(v) && !v.length)) continue;
    out[f] = SCRIPT_PATTERN_FIELDS.has(f) ? [...v].sort() : v;
  }
  return out;
}

// Last-applied keys (null = unknown: first apply after a SW start, or the last apply failed).
let _dynamicKey = null;
let _sessionKey = null;
let _scriptsKey = null;

// ── Regex validation cache (lives for the service worker's lifetime) ────────
const _regexOk = new Map();   // regex → boolean

async function isRegexOk(regex) {
  if (_regexOk.has(regex)) return _regexOk.get(regex);
  let ok = false;
  try {
    const res = await chrome.declarativeNetRequest.isRegexSupported({ regex, isCaseSensitive: false });
    ok = !!(res && res.isSupported);
    if (!ok) console.warn(LOG_PREFIX, "regex rejected by DNR:", res && res.reason, regex);
  } catch (e) {
    console.warn(LOG_PREFIX, "isRegexSupported failed:", e);
  }
  _regexOk.set(regex, ok);
  return ok;
}

async function applyRules(state) {
  const cdnRegexSupported = await isRegexOk(CDN_HOST_REGEX);
  let rules = buildDynamicRules(state, { cdnRegexSupported });

  // Drop any rule whose regex this Chrome refuses — degrade one rule, never the batch.
  const bad = new Set();
  for (const rx of collectRegexes(rules)) if (!(await isRegexOk(rx))) bad.add(rx);
  if (bad.size) rules = rules.filter((r) => !bad.has(r.condition.regexFilter));

  const key = canonicalKey(rules);
  if (key === _dynamicKey) return rules.length;              // unchanged since our last apply: nothing to do
  _dynamicKey = null;                                        // guard: unknown until this apply succeeds
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  if (canonicalKey(existing) !== key) {
    const removeRuleIds = existing.map((r) => r.id);         // full replace — matrix rules are rebuilt too
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: rules });
  }
  _dynamicKey = key;
  _dynamicRules = rules;
  recompile();                                               // matcher follows exactly what Chrome has
  return rules.length;
}

// 4.4.5 tab band: session rules, fully replaced on every run (they are tiny: one band per level that has tabs).
// Same regex guard as the dynamic rules. A failed update leaves Chrome's previous (atomic) set in place.
async function applySession(state) {
  const cdnRegexSupported = await isRegexOk(CDN_HOST_REGEX);
  await Badge.ready();                                               // 4.7.0: allHighRisk() needs the restored map
  let rules = buildSessionRules(state, TabLocks.tabsByLevel(), Badge.allHighRisk(), { cdnRegexSupported });
  const bad = new Set();
  for (const rx of collectRegexes(rules)) if (!(await isRegexOk(rx))) bad.add(rx);
  if (bad.size) rules = rules.filter((r) => !bad.has(r.condition.regexFilter));

  const key = canonicalKey(rules);
  if (key === _sessionKey) return rules.length;              // unchanged since our last apply
  _sessionKey = null;
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  if (canonicalKey(existing) !== key) {                      // a SW restart with the same band: no rewrite
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: existing.map((r) => r.id), addRules: rules });
  }
  _sessionKey = key;
  _sessionRules = rules;
  recompile();
  return rules.length;
}

// Guard: after an extension UPDATE, Chrome may still hold persisted registrations from the
// previous version (including scripts whose file no longer exists), which makes a batch
// register fail with "Duplicate script ID" and would leave the user with NO scripts at all.
// So: unregister our ids one by one (never let one stale id abort the rest), register the
// wanted set, and verify; on a mismatch, register one by one and report what did not take.
async function unregisterOurs() {
  let ours = [];
  try {
    const current = await chrome.scripting.getRegisteredContentScripts();
    ours = current.map((s) => s.id).filter((id) => id.startsWith(SCRIPT_ID_PREFIX));
  } catch (e) { console.warn(LOG_PREFIX, "getRegisteredContentScripts failed:", e); }
  for (const id of ours) {
    try { await chrome.scripting.unregisterContentScripts({ ids: [id] }); }
    catch (e) { console.warn(LOG_PREFIX, "unregister failed for", id, e); }
  }
}

async function registerOneByOne(wanted) {
  let n = 0;
  for (const reg of wanted) {
    try { await chrome.scripting.registerContentScripts([reg]); n++; }
    catch (e) { console.error(LOG_PREFIX, "register failed for", reg.id, e); }
  }
  return n;
}

// Chrome's current registrations of OURS, as a canonical key (null when Chrome cannot be read).
async function registeredKey() {
  try {
    const current = await chrome.scripting.getRegisteredContentScripts();
    return canonicalKey(current.filter((s) => s.id.startsWith(SCRIPT_ID_PREFIX)).map(scriptProjection));
  } catch (e) { console.warn(LOG_PREFIX, "getRegisteredContentScripts failed:", e); return null; }
}

async function applyScripts(state) {
  const wanted = buildScriptRegistrations(state);
  const key = canonicalKey(wanted.map(scriptProjection));
  if (key === _scriptsKey) return wanted.length;            // unchanged since our last apply
  _scriptsKey = null;                                       // guard: unknown until verified below
  if (key === await registeredKey()) { _scriptsKey = key; return wanted.length; }   // Chrome has exactly this set
  await unregisterOurs();                                   // release before re-registering
  if (!wanted.length) return 0;
  try { await chrome.scripting.registerContentScripts(wanted); }
  catch (e) {
    console.warn(LOG_PREFIX, "batch register failed, retrying one by one:", e);
    await unregisterOurs();
    return registerOneByOne(wanted);
  }
  // Verify: the batch can report success while Chrome kept stale state (seen on update).
  try {
    const now = await chrome.scripting.getRegisteredContentScripts();
    const have = new Set(now.map((s) => s.id));
    const missing = wanted.filter((w) => !have.has(w.id));
    if (missing.length) {
      console.warn(LOG_PREFIX, "scripts missing after register:", missing.map((m) => m.id));
      await unregisterOurs();
      return registerOneByOne(wanted);                      // key stays unknown: the next apply re-checks
    }
    _scriptsKey = key;                                      // verified: Chrome holds exactly the wanted set
  } catch (e) { console.warn(LOG_PREFIX, "script verification failed:", e); }
  return wanted.length;
}

// ── Serialized, coalescing apply ────────────────────────────────────────────
// makeCoalescer(run) → apply(state): one run at a time; while one runs, only the LATEST requested
// state waits, and every waiter gets that run's result. All bookkeeping is released after each run.
function makeCoalescer(run) {
  let running = null;      // Promise of the run in progress, or null
  let pending = null;      // latest state waiting to be applied, or null
  let waiters = [];        // resolvers for callers waiting on the pending run

  function apply(state) {
    if (!running) {
      running = run(state).finally(() => { running = null; drain(); });
      return running;
    }
    pending = state;                                  // newer state replaces any older pending one
    return new Promise((resolve) => waiters.push(resolve));
  }

  function drain() {
    if (!pending) return;
    const next = pending;
    const mine = waiters;
    pending = null;
    waiters = [];                                     // release: the waiters are owned by this run now
    apply(next).then((res) => mine.forEach((w) => w(res)));
  }
  return apply;
}

export const applySessionRules = makeCoalescer(async (state) => {
  try { return await applySession(state); }
  catch (e) { console.error(LOG_PREFIX, "applySession failed:", e); return 0; }
});

async function _runOnce(state) {
  const result = { ruleCount: 0, scriptCount: 0 };
  try { result.ruleCount = await applyRules(state); }
  catch (e) { console.error(LOG_PREFIX, "applyRules failed:", e); }
  await applySessionRules(state);                     // never throws (see above)
  try { result.scriptCount = await applyScripts(state); }
  catch (e) { console.error(LOG_PREFIX, "applyScripts failed:", e); }
  return result;
}

export const applyState = makeCoalescer(_runOnce);
