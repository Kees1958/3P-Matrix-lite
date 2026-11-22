// ── core/badge.js ─────────────────────────────────────────────────────────────
// Toolbar badge + icon, per tab.
//   text   = requests blocked on this tab, counted HERE (not Chrome's built-in
//            action count, which also counts every modifyHeaders match)
//   colour = risk of the tab's current site: grey / orange / red (+ "!")
//   icon   = 3P-Matrix-lite brick wall in the colour of the tab's effective level
//
// Public interface:
//   ready()                             — Promise: per-tab state restored (await before reading)
//   noteBlocked(tabId)                  — one more blocked request on the tab
//   resetCount(tabId)                   — new top-level page committed
//   setRisk(tabId, site, severity)      — remember the risk of the site in the tab
//   clearRiskIfOtherSite(tabId, site)   — committed page belongs to another site
//   getCount(tabId) / getRisk(tabId)    — current values (after ready())
//   allHighRisk()                       — 4.7.0: tabId[] currently at SEVERITY.PHISHING (after ready()) —
//                                         core/apply-manager.js's high-risk tab band (data/protections.js
//                                         alsoHighRisk)
//   setLevelIcon(level, tabId?)         — global (no tabId) or per-tab icon
//   releaseTab(tabId)                   — tab closed: drop everything we hold for it
//
// State — 4.5.4: one entry per tab in a session store (core/session-map.js, SESSION_KEY.BADGE),
// so the count and risk colour survive a service-worker restart (they used to reset after ~30 s idle):
//   _tabs.map  Map<tabId, { count, site, severity }>   bounded by open tabs: releaseTab() on tabs.onRemoved
// Every change waits for the restore (_tabs.ready()), so an event that wakes the worker never works on an
// empty map, and applies in arrival order.
//
// 4.5.4 (perf P6) — render coalescing: a change only marks the tab dirty; one timer per tab
// (BADGE_RENDER_DELAY_MS) draws it and saves the session entry, so a burst of N blocked requests costs one
// badge update + one session write instead of 2N Chrome calls. Text and colour already shown are not sent
// again.
//   _timers  Map<tabId, timeoutId>         — pending draw; cleared by releaseTab()
//   _shown   Map<tabId, { text, color }>   — what Chrome shows now; deleted by releaseTab()
// ─────────────────────────────────────────────────────────────────────────────

import { BADGE_COLOR, BADGE_PHISHING_PREFIX, BADGE_MAX_COUNT, BADGE_RENDER_DELAY_MS, SESSION_KEY, SEVERITY,
         LEVEL_INFO, ICON_SIZES, ICON_DIR } from "../data/constants.js";
import { createSessionMap } from "./session-map.js";

const _tabs = createSessionMap(SESSION_KEY.BADGE);
const _timers = new Map();
const _shown = new Map();

export function ready() { return _tabs.ready(); }

function entryOf(tabId) {
  if (!_tabs.map.has(tabId)) _tabs.map.set(tabId, { count: 0, site: "", severity: SEVERITY.NONE });
  return _tabs.map.get(tabId);
}

function badgeOf(entry) {
  const n = entry.count;
  let text = n === 0 ? "" : n > BADGE_MAX_COUNT ? `${BADGE_MAX_COUNT}+` : String(n);
  if (entry.severity === SEVERITY.PHISHING) text = BADGE_PHISHING_PREFIX + text;
  const color = entry.severity === SEVERITY.PHISHING ? BADGE_COLOR.PHISHING
    : entry.severity === SEVERITY.SUSPECT ? BADGE_COLOR.SUSPECT : BADGE_COLOR.NORMAL;
  return { text, color };
}

// Draws the tab now (only what changed) and saves the session store.
function draw(tabId) {
  _timers.delete(tabId);
  const entry = _tabs.map.get(tabId);
  if (!entry) return;                                         // released meanwhile
  const want = badgeOf(entry);
  const shown = _shown.get(tabId) || {};
  // Best effort: the tab may close between the event and these calls.
  if (want.text !== shown.text) chrome.action.setBadgeText({ tabId, text: want.text }).catch(() => { /* tab closed meanwhile */ });
  if (want.color !== shown.color) chrome.action.setBadgeBackgroundColor({ tabId, color: want.color }).catch(() => { /* tab closed meanwhile */ });
  _shown.set(tabId, want);
  _tabs.save();
}

function scheduleDraw(tabId) {
  if (_timers.has(tabId)) return;                            // a draw is already due: it will include this change
  _timers.set(tabId, setTimeout(() => draw(tabId), BADGE_RENDER_DELAY_MS));
}

// Runs `change(entry)` once the store is restored, then schedules the draw.
function update(tabId, change) {
  if (tabId < 0) return;
  _tabs.ready().then(() => {
    if (change(entryOf(tabId)) !== false) scheduleDraw(tabId);
  });
}

export function noteBlocked(tabId) {
  update(tabId, (e) => { e.count += 1; });
}

export function resetCount(tabId) {
  update(tabId, (e) => { e.count = 0; });
}

export function getCount(tabId) { return (_tabs.map.get(tabId) || {}).count || 0; }

export function getRisk(tabId) {
  const e = _tabs.map.get(tabId);
  return e && e.severity !== SEVERITY.NONE ? { site: e.site, severity: e.severity } : null;
}

export function allHighRisk() {
  const out = [];
  for (const [tabId, e] of _tabs.map) if (e.severity === SEVERITY.PHISHING) out.push(tabId);
  return out;
}

export function setRisk(tabId, site, severity) {
  update(tabId, (e) => {
    if (severity === SEVERITY.NONE) { e.site = ""; e.severity = SEVERITY.NONE; } else { e.site = site; e.severity = severity; }
  });
}

export function clearRiskIfOtherSite(tabId, site) {
  update(tabId, (e) => {
    if (e.severity === SEVERITY.NONE || e.site === site) return false;   // nothing changes: no draw
    e.site = ""; e.severity = SEVERITY.NONE;
    return true;
  });
}

export function setLevelIcon(level, tabId) {
  const info = LEVEL_INFO[level - 1] || LEVEL_INFO[0];
  const path = Object.fromEntries(ICON_SIZES.map((s) => [String(s), `${ICON_DIR}/${info.icon}_${s}.png`]));
  const details = tabId === undefined ? { path } : { path, tabId };
  chrome.action.setIcon(details).catch(() => { /* tab closed meanwhile */ });
}

export function releaseTab(tabId) {
  clearTimeout(_timers.get(tabId));
  _timers.delete(tabId);
  _shown.delete(tabId);
  _tabs.ready().then(() => { if (_tabs.map.delete(tabId)) _tabs.save(); });
}
