// ── core/tab-locks.js ─────────────────────────────────────────────────────────
// Which open tab belongs to which level-2–5 site lock (4.4.5 "tab band"). A lock is an
// initiator-scoped rule group, so a request made by an EMBEDDED frame (Word Online's
// officeapps.live.com inside a locked SharePoint page) never matched it and got the session level.
// The band closes that gap: core/rule-builder.js buildSessionRules() scopes the lock's rules by
// tabId, and this module is the bookkeeping behind it — tab → locked level of the page it shows.
// Level 1 locks are not here: they use one allowAllRequests rule (core/rule-builder.js).
//
// Public interface:
//   assign(state, tabId, url)   — remember the band level of the page `tab` shows (or forget the
//                                 tab); true when the tab's band CHANGED (rules must be re-applied)
//   release(tabId)              — tab closed/replaced: forget it; true when it was banded
//   rebuild(state)              — Promise<void> — recompute every tab from chrome.tabs.query
//                                 (lock/level change, browser start, service-worker restart)
//   tabsByLevel()               — Map<level, tabId[]> snapshot for the rule builder
//   bandLevelOf(state, url)     — pure: band level (2–5) a page URL falls in, or null
//
// Guards / bounded state: one Map entry per banded tab, capped at TAB_BAND_TABS_MAX per level
// (oldest dropped first), released on tab close / replace / navigation to an unlocked site.
// In memory only — a service-worker restart refills it with rebuild() (background.js).
// ─────────────────────────────────────────────────────────────────────────────

import { TAB_BAND_LEVELS, TAB_BAND_TABS_MAX, LOG_PREFIX } from "../data/constants.js";
import { lockedLevelOf } from "./policy.js";
import { parseHttpUrl } from "../util/domain.js";

const TOTAL_CAP = TAB_BAND_TABS_MAX * TAB_BAND_LEVELS.length;   // guard: whole map
let _levels = new Map();                                        // tabId → band level (insertion order = age)

export function bandLevelOf(state, url) {
  const p = parseHttpUrl(url || "");
  if (!p) return null;
  const level = lockedLevelOf(state, p.host);
  return TAB_BAND_LEVELS.includes(level) ? level : null;
}

function isTabId(tabId) { return Number.isInteger(tabId) && tabId >= 0; }

export function assign(state, tabId, url) {
  if (!isTabId(tabId)) return false;
  const level = bandLevelOf(state, url);
  const before = _levels.has(tabId) ? _levels.get(tabId) : null;
  if (level === before) return false;
  _levels.delete(tabId);                                        // re-insert = newest
  if (level !== null) {
    if (_levels.size >= TOTAL_CAP) _levels.delete(_levels.keys().next().value);   // guard: drop the oldest
    _levels.set(tabId, level);
  }
  return true;
}

export function release(tabId) {
  return _levels.delete(tabId);
}

export async function rebuild(state) {
  const next = new Map();
  try {
    for (const tab of await chrome.tabs.query({})) {
      const level = isTabId(tab.id) ? bandLevelOf(state, tab.pendingUrl || tab.url) : null;
      if (level !== null && next.size < TOTAL_CAP) next.set(tab.id, level);
    }
  } catch (e) {
    console.warn(LOG_PREFIX, "tab band rebuild failed — keeping the previous assignment:", e);
    return;
  }
  _levels = next;                                               // old map released wholesale
}

export function tabsByLevel() {
  const out = new Map();
  for (const [tabId, level] of _levels) {
    if (!out.has(level)) out.set(level, []);
    out.get(level).push(tabId);
  }
  return out;
}
