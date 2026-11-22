// ── core/site-locks.js ────────────────────────────────────────────────────────
// Site locks and the allow list — pure operations on state.siteLocks / state.siteLocksOrder.
// No Chrome API calls. The allow list IS the set of sites locked at LEVEL.ALLOW_ALL.
// (4.2.3: moved out of background.js — audit finding 6; behaviour unchanged.)
//
// Public interface:
//   isLocked(state, site)              — site has a lock (any level)
//   lockSite(state, site, level)       — add/replace a lock; FIFO eviction at SITE_LOCKS_CAP
//   unlockSite(state, site)            — remove a lock (no-op when absent)
//   toggleLock(state, site)            — popup lock button: unlock, or pin the CURRENT session level
//                                        to the site and restore the previous session level
//                                        (3P-Matrix-lite behaviour)
//   allowListSites(state)              — sites locked at LEVEL.ALLOW_ALL, in lock order
//   parseAllowListText(text)           — options textarea → distinct registered domains
//   replaceAllowList(state, sites)     — make the allow list exactly `sites`; locks at other
//                                        levels are never touched
//
// Guards: siteLocks and siteLocksOrder are always changed together here (normalizeState()
// rebuilds them together too), so they cannot drift apart.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, SITE_LOCKS_CAP, ALLOW_LIST_LINE_MAX } from "../data/constants.js";
import { isValidHost } from "../data/state-storage.js";
import { registeredDomain } from "../util/domain.js";

const LINE_SPLIT_RE    = /\r?\n/;
const URL_SCHEME_RE    = /^https?:\/\//i;
const AFTER_HOST_RE    = /[/:?#].*$/;
const COMMENT_PREFIX   = "#";

export function isLocked(state, site) {
  return Object.prototype.hasOwnProperty.call(state.siteLocks, site);
}

export function lockSite(state, site, level) {
  if (!isLocked(state, site)) {
    if (state.siteLocksOrder.length >= SITE_LOCKS_CAP) delete state.siteLocks[state.siteLocksOrder.shift()]; // FIFO
    state.siteLocksOrder.push(site);
  }
  state.siteLocks[site] = level;
}

export function unlockSite(state, site) {
  delete state.siteLocks[site];
  state.siteLocksOrder = state.siteLocksOrder.filter((s) => s !== site);
}

export function toggleLock(state, site) {
  if (isLocked(state, site)) { unlockSite(state, site); return; }
  lockSite(state, site, state.level);
  state.level = state.prevLevel;
}

export function allowListSites(state) {
  return state.siteLocksOrder.filter((s) => state.siteLocks[s] === LEVEL.ALLOW_ALL);
}

export function parseAllowListText(text) {
  const wanted = [];
  for (const line of String(text || "").split(LINE_SPLIT_RE)) {
    const h = line.trim().replace(URL_SCHEME_RE, "").replace(AFTER_HOST_RE, "").toLowerCase();
    if (!h || h.startsWith(COMMENT_PREFIX) || h.length > ALLOW_LIST_LINE_MAX || !isValidHost(h)) continue;
    const site = registeredDomain(h);
    if (!wanted.includes(site)) wanted.push(site);
  }
  return wanted;
}

export function replaceAllowList(state, sites) {
  allowListSites(state).filter((s) => !sites.includes(s)).forEach((s) => unlockSite(state, s));
  sites.forEach((site) => lockSite(state, site, LEVEL.ALLOW_ALL));
}
