// ── core/policy.js ────────────────────────────────────────────────────────────
// Pure policy resolution — answers "which level applies where, and which
// protections are active at that level". No Chrome API calls, no side effects.
//
// Public interface:
//   effectiveLevel(state, host)         — lock level of the host's registered domain, else state.level
//   lockedLevelOf(state, host)          — lock level or null
//   isProtectionEnabled(state, key)     — user has not unticked it
//   isProtectionActive(state, key, lvl) — enabled AND lvl >= its fromLevel
//   ruleGroups(state)                   — the rule groups the builders iterate over:
//        [{ index: 0, level: state.level, kind: "global", sites: [all locked sites] },
//         { index: L, level: L,           kind: "locked", sites: [sites locked at L] }, ...]
//     Global rules EXCLUDE every locked site; each locked group INCLUDES only its sites.
//     One group per level (not per site) keeps the rule count independent of the
//     number of locks.
//   tabBandGroups(tabsByLevel)          — 4.4.5: one TAB group per level 2–5 that has tabs, for the
//                                         session rules (core/rule-builder.js buildSessionRules):
//        [{ index: L, level: L, kind: "tab", sites: [], tabIds: [...], priorityBase: TAB_BAND_BASE }]
//   highRiskTabGroups(tabIds)           — 4.7.0: one TAB group (or []) for tabs scored phishing this
//                                         session — see data/protections.js' 4.7.0 alsoHighRisk comment:
//        [{ index: HIGH_RISK_GROUP_INDEX, level: LEVEL_MAX, kind: "tab", sites: [], tabIds: [...],
//           priorityBase: HIGH_RISK_TAB_BASE, highRiskOnly: true }]
//      highRiskOnly tells core/rule-builder.js's `on()` to require p.alsoHighRisk instead of the
//      ordinary level gate — every OTHER protection is skipped for this group, level or no level.
//   isHighRiskSite(state, host, risk)   — 4.7.0: HIGH_RISK_HOSTNAMES (static) OR `risk` (the tab's
//                                         own core/badge.js getRisk() result, passed in — this module
//                                         makes no Chrome calls) says SEVERITY.PHISHING for this site;
//                                         false when the site is allow-listed (locked at ALLOW_ALL)
//   isProtectionActiveOrHighRisk(...)   — isProtectionActive() OR (p.alsoHighRisk AND isHighRiskSite())
//                                         — for a mechanism that decides per request (DOWNLOAD today)
//   protectionCounts(state, level)      — { active, total } for the popup
//   saferRegionsApply(level)            — does the safer-regions list have any effect at this level?
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, LEVEL_MIN, LEVEL_MAX, SAFER_REGIONS_LEVELS, LOG_PREFIX, SEVERITY,
         TAB_BAND_BASE, TAB_BAND_LEVELS, TAB_BAND_TABS_MAX, HIGH_RISK_GROUP_INDEX, HIGH_RISK_TAB_BASE } from "../data/constants.js";
import { PROTECTIONS, PROTECTION_BY_KEY } from "../data/protections.js";
import { HIGH_RISK_HOSTNAMES } from "../data/network-data.js";
import { registeredDomain } from "../util/domain.js";

export const GROUP_KIND = Object.freeze({ GLOBAL: "global", LOCKED: "locked", TAB: "tab" });

export function lockedLevelOf(state, host) {
  if (!host) return null;
  const site = registeredDomain(host);
  return Object.prototype.hasOwnProperty.call(state.siteLocks, site) ? state.siteLocks[site] : null;
}

export function effectiveLevel(state, host) {
  const locked = lockedLevelOf(state, host);
  return locked === null ? state.level : locked;
}

export function isProtectionEnabled(state, key) {
  return state.disabledProtections[key] !== true;
}

export function saferRegionsApply(level) {
  return SAFER_REGIONS_LEVELS.includes(level);
}

export function isProtectionActive(state, key, level) {
  const p = PROTECTION_BY_KEY[key];
  // Guard (4.2.3, audit finding 8): an unknown key is a coding error — say so loudly instead of
  // silently treating the protection as off. tools/check-protection-keys.mjs catches it statically.
  if (!p) { console.error(LOG_PREFIX, "unknown protection key:", key); return false; }
  return isProtectionEnabled(state, key) && level >= p.fromLevel;
}

export function ruleGroups(state) {
  const allLocked = state.siteLocksOrder.slice();
  const groups = [{ index: 0, level: state.level, kind: GROUP_KIND.GLOBAL, sites: allLocked }];
  for (let lvl = LEVEL_MIN; lvl <= LEVEL_MAX; lvl++) {
    const sites = allLocked.filter((s) => state.siteLocks[s] === lvl);
    if (sites.length) groups.push({ index: lvl, level: lvl, kind: GROUP_KIND.LOCKED, sites });
  }
  return groups;
}

// tabsByLevel: Map<level, Iterable<tabId>> (core/tab-locks.js). Capped per band (guard).
export function tabBandGroups(tabsByLevel) {
  const groups = [];
  for (const level of TAB_BAND_LEVELS) {
    const tabIds = [...(tabsByLevel.get(level) || [])].slice(0, TAB_BAND_TABS_MAX);
    if (tabIds.length) groups.push({ index: level, level, kind: GROUP_KIND.TAB, sites: [], tabIds, priorityBase: TAB_BAND_BASE });
  }
  return groups;
}

// 4.7.0 — see data/constants.js' "High-risk tab override" comment: one group, reserved index/priority
// band, so it can be active on a tab at the SAME TIME as that tab's own level-lock band.
export function highRiskTabGroups(tabIds) {
  const ids = [...(tabIds || [])].slice(0, TAB_BAND_TABS_MAX);
  if (!ids.length) return [];
  return [{ index: HIGH_RISK_GROUP_INDEX, level: LEVEL_MAX, kind: GROUP_KIND.TAB, sites: [], tabIds: ids, priorityBase: HIGH_RISK_TAB_BASE, highRiskOnly: true }];
}

// 4.7.0 — `risk` is the tab's own core/badge.js getRisk(tabId) result ({ site, severity } | null), passed
// in by the caller (this module makes no Chrome calls). Allow-listed (explicit trust) always wins.
export function isHighRiskSite(state, host, risk = null) {
  if (!host) return false;
  const site = registeredDomain(host);
  if (lockedLevelOf(state, site) === LEVEL.ALLOW_ALL) return false;
  if (HIGH_RISK_HOSTNAMES.includes(site)) return true;
  return !!(risk && risk.severity === SEVERITY.PHISHING && registeredDomain(risk.site) === site);
}

// 4.7.0 — for a mechanism that decides against a SPECIFIC host/request at the moment it happens
// (today: DOWNLOAD — core/download-guard.js), rather than through a declarative rule/registration.
export function isProtectionActiveOrHighRisk(state, key, level, host, risk = null) {
  if (isProtectionActive(state, key, level)) return true;
  const p = PROTECTION_BY_KEY[key];
  return !!(p && p.alsoHighRisk && isProtectionEnabled(state, key) && isHighRiskSite(state, host, risk));
}

export function protectionCounts(state, level) {
  const applicable = PROTECTIONS.filter((p) => level >= p.fromLevel);
  const active = applicable.filter((p) => isProtectionEnabled(state, p.key)).length;
  return { active, total: applicable.length };
}
