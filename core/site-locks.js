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
//   parseAllowListText(text)           — 5.1.3: the allow-list textarea ("Category: domain" per line, a bare
//                                        domain = All) → { entries: {category → domains[]}, errors: lines[] }
//   replaceAllowList(state, entries)   — make every category exactly its list ("All" = the level-1 locks; locks
//                                        at other levels are never touched); "All" for a domain drops its other lines
//   allowListText(state)               — 5.1.3: the list as text, sorted by category then domain
//   addToAllowList(state, category, host) — 5.1.3: "Always allow" / "Always ignore" in a warning
//
// Guards: siteLocks and siteLocksOrder are always changed together here (normalizeState()
// rebuilds them together too), so they cannot drift apart.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, SITE_LOCKS_CAP, ALLOW_LIST_LINE_MAX, ALLOW_CATEGORY_CAP, TRUSTED_DOWNLOAD_DOMAINS_MAX } from "../data/constants.js";
import { ALLOW_CATEGORY, ALLOW_CATEGORY_ORDER, ALLOW_CATEGORY_LABEL, ALLOW_CATEGORIES_STORED } from "../data/allow-categories.js";
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

// One line: an optional "Category:" and one domain (an address is cut back to its host). Named groups (C9).
const ALLOW_LINE_RE = /^(?:(?<category>[a-z]+)\s*:\s*)?(?<host>\S+)$/i;
const CATEGORY_BY_WORD = Object.freeze(Object.fromEntries(ALLOW_CATEGORY_ORDER.map((c) => [ALLOW_CATEGORY_LABEL[c].toLowerCase(), c])));
const CATEGORY_SEPARATOR = ": ";
// Download lines keep the host as written (matched with its subdomains, as the former trusted domains); the other
// categories are kept per site (registered domain), like the locks.
function entryOf(category, host) { return category === ALLOW_CATEGORY.DOWNLOAD ? host : registeredDomain(host); }
function emptyEntries() { return Object.fromEntries(ALLOW_CATEGORY_ORDER.map((c) => [c, []])); }

export function parseAllowListText(text) {
  const entries = emptyEntries();
  const errors = [];
  for (const raw of String(text || "").split(LINE_SPLIT_RE)) {
    const line = raw.trim();
    if (!line || line.startsWith(COMMENT_PREFIX)) continue;
    // An address ("https://…") is a bare domain — its scheme is not a category word.
    const m = URL_SCHEME_RE.test(line) ? { groups: { category: undefined, host: line } } : ALLOW_LINE_RE.exec(line);
    const category = m && (m.groups.category ? CATEGORY_BY_WORD[m.groups.category.toLowerCase()] : ALLOW_CATEGORY.ALL);
    const h = m ? m.groups.host.replace(URL_SCHEME_RE, "").replace(AFTER_HOST_RE, "").toLowerCase() : "";
    if (!category || !h || h.length > ALLOW_LIST_LINE_MAX || !isValidHost(h)) { errors.push(line); continue; }
    const entry = entryOf(category, h);
    if (!entries[category].includes(entry)) entries[category].push(entry);
  }
  // "All" covers everything else for that site.
  const all = new Set(entries[ALLOW_CATEGORY.ALL]);
  for (const c of ALLOW_CATEGORY_ORDER) {
    if (c !== ALLOW_CATEGORY.ALL) entries[c] = entries[c].filter((e) => !all.has(registeredDomain(e)));
  }
  return { entries, errors };
}

export function replaceAllowList(state, entries) {
  const sites = entries[ALLOW_CATEGORY.ALL];
  allowListSites(state).filter((s) => !sites.includes(s)).forEach((s) => unlockSite(state, s));
  sites.forEach((site) => lockSite(state, site, LEVEL.ALLOW_ALL));
  state.downloads.trustedDomains = entries[ALLOW_CATEGORY.DOWNLOAD].slice(0, TRUSTED_DOWNLOAD_DOMAINS_MAX);
  for (const c of ALLOW_CATEGORIES_STORED) state.allowCategories[c] = entries[c].slice(0, ALLOW_CATEGORY_CAP);
}

function entriesOf(state) {
  const entries = emptyEntries();
  entries[ALLOW_CATEGORY.ALL] = allowListSites(state);
  entries[ALLOW_CATEGORY.DOWNLOAD] = state.downloads.trustedDomains.slice();
  for (const c of ALLOW_CATEGORIES_STORED) entries[c] = state.allowCategories[c].slice();
  return entries;
}

export function allowListText(state) {
  const entries = entriesOf(state);
  return ALLOW_CATEGORY_ORDER.flatMap((c) => [...entries[c]].sort()
    .map((e) => `${ALLOW_CATEGORY_LABEL[c]}${CATEGORY_SEPARATOR}${e}`)).join("\n");
}

// "Always allow" / "Always ignore": adds one site under one category (no-op when "All" already covers it).
export function addToAllowList(state, category, host) {
  if (!ALLOW_CATEGORY_ORDER.includes(category) || !isValidHost(host)) throw new Error("bad allow-list entry");
  const entries = entriesOf(state);
  if (entries[ALLOW_CATEGORY.ALL].includes(registeredDomain(host))) return;
  const entry = entryOf(category, host);
  if (!entries[category].includes(entry)) entries[category].push(entry);
  if (category === ALLOW_CATEGORY.ALL) {                       // "All" covers the site's other lines: drop them
    for (const c of ALLOW_CATEGORY_ORDER) if (c !== category) entries[c] = entries[c].filter((e) => registeredDomain(e) !== entry);
  }
  replaceAllowList(state, entries);
}
