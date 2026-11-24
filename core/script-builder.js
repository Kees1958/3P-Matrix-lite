// ── core/script-builder.js ────────────────────────────────────────────────────
// Pure computation of content-script registrations for every SCRIPT protection.
// No Chrome API calls.
//
// Public interface:
//   buildScriptRegistrations(state, { grouped }) — RegisteredContentScript[] for chrome.scripting
//
// For each protection with scripts, where does it run?
//   active globally (state.level >= fromLevel, enabled):
//       matches  = <all_urls>  (or its fixed host list)
//       excludes = sites locked BELOW fromLevel
//                + safer regions, when scoped outside them AND the global level is 3
//                + the built-in whitelist (data/builtin-domains.js), when scoped outside
//                  safer regions AND the global level is 3 or 4 — 0.2.4, matches the built-in
//                  whitelist's own 3P-content exemption (never at level 5); a first-party visit
//                  to a trusted host is exempt here too, not just its third-party embeds
//                + locked sites that sit in safer regions at a locked level 3
//       plus a second registration (id suffix SCRIPT_ID_SUFFIX.SAFER_LOCKED) for sites locked at
//       level 4–5 that the global level-3 safer-regions exclude would otherwise skip
//   not active globally:
//       matches  = sites locked AT/ABOVE fromLevel (intersected with a fixed host list),
//                  minus sites in safer regions locked at level 3, minus built-in-whitelist
//                  sites locked at level 3 or 4
// 4.2: the same built-in exemption also applies to an EVERY_SITE protection that names its own
// trustedExempt host list (blockPaymentHandlers: payment hosts), at the same levels (3–4, never 2 or 5).
// Safer regions only count at SAFER_REGIONS_LEVELS (level 3); levels 4–5 run every
// protection on every site except the built-in whitelist (3, 4 only). Every script: MAIN
// world, all frames, document_start, persisted across sessions.
// 4.5.4 (perf P5): registrations that end up with the SAME matches + excludeMatches are merged into one
// (groupRegistrations): Chrome matches every registration's patterns against every frame and keeps a copy
// of each list in every renderer, so five protections repeating the same ~320-site exclude list cost five
// times the matching. A merged registration runs its members' files in PROTECTIONS order (the order they
// ran in before); its id is SCRIPT_ID_PREFIX + the member ids joined by SCRIPT_ID_GROUP_JOIN. Unticking
// a protection simply yields a different grouping — every apply replaces the whole set anyway.
// 4.6.0: a protection may also name `isolatedScripts` (ISOLATED world — code that must message the service
// worker): they get exactly the registrations of its MAIN-world `scripts` (same matches/excludes), id suffix
// SCRIPT_ID_SUFFIX.ISOLATED, world ISOLATED. The world is part of the merge key — two worlds never merge.
// 4.7.0: a protection may have ONLY `isolatedScripts` (blockConsentFix): its registrations are computed exactly as
// for MAIN-world scripts (same scope rules), then all of them run in the ISOLATED world.
// 4.7.0: a protection with alsoHighRisk (data/protections.js) gets ONE MORE registration — the STATIC half of
// that escalation (data/network-data.js HIGH_RISK_HOSTNAMES — unconditional on level) — via
// highRiskRegistrationsFor(): matches = that fixed host list, no excludes, independent of everything above. It
// never shares a script file's SCOPE with the protection's own ordinary registration (different matches), so
// the P5 merge invariant (tools/test-perf-guards.mjs) holds; it DOES share scope with every OTHER alsoHighRisk
// protection's high-risk registration (same fixed host list, same empty excludes) and so merges with them.
// The DYNAMIC half (a site scored phishing this session) cannot reach a SCRIPT-mechanism protection at all — see
// data/protections.js' 4.7.0 alsoHighRisk comment — so there is no dynamic counterpart here.
// ─────────────────────────────────────────────────────────────────────────────

import { SCRIPT_ID_PREFIX, SCRIPT_ID_SUFFIX, SCRIPT_ID_GROUP_JOIN, BUILTIN_EXEMPT_LEVELS, LEVEL } from "../data/constants.js";
import { PROTECTIONS, SCOPE, tabOf } from "../data/protections.js";
import { ALLOW_CATEGORY_OF_TAB } from "../data/allow-categories.js";
import { isProtectionEnabled, saferRegionsApply, allowSitesOf } from "./policy.js";
import { hostMatchPattern, tldMatchPattern, isInDomainList } from "../util/domain.js";
import { BUILTIN_ALL } from "../data/builtin-domains.js";
import { HIGH_RISK_HOSTNAMES } from "../data/network-data.js";

const ALL_URLS = "<all_urls>";
const WORLD = Object.freeze({ MAIN: "MAIN", ISOLATED: "ISOLATED" });
function builtinExemptAt(level) { return BUILTIN_EXEMPT_LEVELS.includes(level); }

// Host list exempt from protection p on a first-party visit (at BUILTIN_EXEMPT_LEVELS), or null.
//   OUTSIDE_SAFER_REGIONS protections → the whole built-in whitelist (0.2.4)
//   EVERY_SITE protection with trustedExempt → that list (4.2: blockPaymentHandlers → payment hosts)
function trustedHostsFor(p) {
  if (p.scope === SCOPE.OUTSIDE_SAFER_REGIONS) return BUILTIN_ALL;
  return p.trustedExempt && p.trustedExempt.length ? p.trustedExempt : null;
}

// The files of the scope computation: the MAIN-world scripts, or (4.7.0) the isolated ones when there are none.
function scopeFiles(p) {
  return p.scripts && p.scripts.length ? p.scripts : (p.isolatedScripts || []);
}

// 5.1.3 — the allow list's sites for p's category (data/allow-categories.js ALLOW_CATEGORY_OF_TAB).
function categoryAllowed(state, p) {
  return allowSitesOf(state, ALLOW_CATEGORY_OF_TAB[tabOf(p)]);
}

function baseRegistration(id, p, matches, excludeMatches) {
  const reg = {
    id,
    js: [...scopeFiles(p)],
    matches,
    allFrames: true,
    runAt: "document_start",
    world: WORLD.MAIN,
    persistAcrossSessions: true
  };
  if (excludeMatches.length) reg.excludeMatches = [...new Set(excludeMatches)];
  return reg;
}

function registrationsFor(state, p) {
  const main = mainRegistrationsFor(state, p);
  if (!p.isolatedScripts || !p.isolatedScripts.length) return main;
  // 4.7.0: isolated-only protection — the computed registrations ARE the isolated ones.
  if (!p.scripts || !p.scripts.length) return main.map((reg) => ({ ...reg, id: reg.id + SCRIPT_ID_SUFFIX.ISOLATED, world: WORLD.ISOLATED }));
  // Same scope as the MAIN-world registrations, other world and files (4.6.0).
  return [...main, ...main.map((reg) => ({ ...reg, id: reg.id + SCRIPT_ID_SUFFIX.ISOLATED, js: [...p.isolatedScripts], world: WORLD.ISOLATED }))];
}

function mainRegistrationsFor(state, p) {
  if (!scopeFiles(p).length || !isProtectionEnabled(state, p.key)) return [];

  const scoped = p.scope === SCOPE.OUTSIDE_SAFER_REGIONS;
  const saferTlds = state.safeZone.tlds;
  function inSafer(site) { return scoped && isInDomainList(site, saferTlds); }
  const trustedHosts = trustedHostsFor(p);
  function inBuiltin(site) { return !!trustedHosts && isInDomainList(site, trustedHosts); }
  const locks = state.siteLocksOrder.map((site) => ({ site, level: state.siteLocks[site] }));
  const fixedHosts = p.matchHosts ? [...p.matchHosts] : null;
  function allowedHost(site) { return !fixedHosts || fixedHosts.includes(site); }
  // 5.1.3: the sites on the allow list under this protection's category (its tab's) never get its scripts.
  const extraExcludes = [...(p.extraExcludes || []), ...categoryAllowed(state, p).map(hostMatchPattern)];
  const id = SCRIPT_ID_PREFIX + p.key;

  // Locked sites where this protection runs: level high enough, not exempt by safer regions
  // or by the built-in whitelist (checked at the SITE'S OWN locked level, same as safer regions).
  function runsOnLock({ site, level }) {
    return level >= p.fromLevel && !(saferRegionsApply(level) && inSafer(site)) && !(builtinExemptAt(level) && inBuiltin(site));
  }

  if (state.level < p.fromLevel) {
    const hosts = locks.filter(runsOnLock).map((l) => l.site).filter(allowedHost);
    return hosts.length ? [baseRegistration(id, p, hosts.map(hostMatchPattern), extraExcludes)] : [];
  }

  const globalSaferExclude = scoped && saferRegionsApply(state.level);
  const globalBuiltinExclude = !!trustedHosts && builtinExemptAt(state.level);
  const excludeSites = locks.filter((l) => !runsOnLock(l)).map((l) => l.site);
  const excludes = [
    ...excludeSites.map(hostMatchPattern),
    ...(globalSaferExclude ? saferTlds.map(tldMatchPattern) : []),
    ...(globalBuiltinExclude ? trustedHosts.map(hostMatchPattern) : []),
    ...extraExcludes
  ];
  const matches = fixedHosts ? fixedHosts.map(hostMatchPattern) : [ALL_URLS];
  const regs = [baseRegistration(id, p, matches, excludes)];

  const rescuedSites = new Set();                 // guard: a site gets at most ONE rescue registration
  if (globalSaferExclude) {
    // Locks at levels without safer regions (4–5) that the TLD exclude above skipped.
    const rescued = locks.filter((l) => runsOnLock(l) && inSafer(l.site)).map((l) => l.site).filter(allowedHost);
    rescued.forEach((s) => rescuedSites.add(s));
    if (rescued.length) regs.push(baseRegistration(id + SCRIPT_ID_SUFFIX.SAFER_LOCKED, p, rescued.map(hostMatchPattern), extraExcludes));
  }
  if (globalBuiltinExclude) {
    // A built-in-whitelist site locked at level 5 (STRICT): the lock is a deliberate choice for
    // maximum protection there, so the built-in exemption does NOT apply (runsOnLock already
    // reflects that) — but the blanket trusted-host exclude above would still hide it, so rescue it.
    // 4.2.3 (audit finding 12): a site already rescued above (in safer regions AND built-in) is
    // skipped here, so its script is never injected twice.
    const builtinRescued = locks.filter((l) => runsOnLock(l) && inBuiltin(l.site) && !rescuedSites.has(l.site))
      .map((l) => l.site).filter(allowedHost);
    if (builtinRescued.length) regs.push(baseRegistration(id + SCRIPT_ID_SUFFIX.BUILTIN_LOCKED, p, builtinRescued.map(hostMatchPattern), extraExcludes));
  }
  return regs;
}

// 4.7.0 — alsoHighRisk STATIC half (see file header). Allow-listed sites (locked at LEVEL.ALLOW_ALL,
// "Trust this site") are excluded — explicit trust always wins, same rule as core/policy.js isHighRiskSite().
function highRiskRegistrationsFor(state, p) {
  if (!p.alsoHighRisk || !scopeFiles(p).length || !isProtectionEnabled(state, p.key)) return [];
  const trusted = new Set(state.siteLocksOrder.filter((s) => state.siteLocks[s] === LEVEL.ALLOW_ALL));
  const allowed = new Set(categoryAllowed(state, p));                 // 5.1.3
  const hosts = HIGH_RISK_HOSTNAMES.filter((h) => !trusted.has(h) && !allowed.has(h));
  if (!hosts.length) return [];
  return [baseRegistration(SCRIPT_ID_PREFIX + p.key + SCRIPT_ID_SUFFIX.HIGH_RISK, p, hosts.map(hostMatchPattern), [])];
}

// Same match scope = same world + sorted matches + sorted excludeMatches.
function scopeKey(reg) {
  return JSON.stringify([reg.world, [...reg.matches].sort(), [...(reg.excludeMatches || [])].sort()]);
}

// Merges registrations with the same scope (input order = PROTECTIONS order, kept for files and groups).
function groupRegistrations(regs) {
  const groups = new Map();                       // scopeKey → { members: reg[] }
  for (const reg of regs) {
    const key = scopeKey(reg);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(reg);
  }
  return [...groups.values()].map((members) => {
    if (members.length === 1) return members[0];
    const first = members[0];
    return {
      ...first,
      id: SCRIPT_ID_PREFIX + members.map((m) => m.id.slice(SCRIPT_ID_PREFIX.length)).join(SCRIPT_ID_GROUP_JOIN),
      js: [...new Set(members.flatMap((m) => m.js))]
    };
  });
}

// opts.grouped (default true) — false returns the per-protection registrations before merging; used
// only by tools/test-perf-guards.mjs to prove the merge changes no file's scope.
export function buildScriptRegistrations(state, { grouped = true } = {}) {
  const regs = PROTECTIONS.flatMap((p) => [...registrationsFor(state, p), ...highRiskRegistrationsFor(state, p)]);
  return grouped ? groupRegistrations(regs) : regs;
}
