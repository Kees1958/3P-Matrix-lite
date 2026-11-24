// ── core/badge.js ─────────────────────────────────────────────────────────────
// Toolbar badge + icon, per tab. 5.1.3 (owner, 2026-11-24): the HIGHEST problem wins, one symbol (data/constants.js
// BADGE_TEXT, SEVERITY_ORDER): the worst of the site's risk and the page's tamper rating (TAMPER_BADGE_SEVERITY) —
//   "!" red = dangerous, "?" orange = suspicious; nothing → the badge is handed back to Chrome's own count of the
//   requests 3P Matrix's rules blocked on the page (init: displayActionCountAsBadgeText; grey global colour).
// No listener counts anything (the 5.1.2 count needed one on every failed request of every page).
//   icon   = 3P-Matrix-lite brick wall in the colour of the tab's effective level
//
// Public interface:
//   init()                              — every service-worker start: Chrome's block count on, grey global colour (idempotent)
//   ready()                             — Promise: per-tab state restored (await before reading)
//   resetPage(tabId)                    — new top-level page committed: the tamper rating belongs to the old page
//   setRisk(tabId, site, severity)      — remember the risk of the site in the tab
//   clearRiskIfOtherSite(tabId, site)   — committed page belongs to another site
//   setTamperRating(tabId, rating)      — 5.1.3: the page's tamper rating (core/tamper-guard.js, via setMarkSink)
//   getRisk(tabId)                      — the site's risk (after ready())
//   allHighRisk()                       — 4.7.0: tabId[] currently at SEVERITY.PHISHING (after ready()) —
//                                         core/apply-manager.js's high-risk tab band (data/protections.js alsoHighRisk)
//   setLevelIcon(level, tabId?)         — global (no tabId) or per-tab icon
//   releaseTab(tabId)                   — tab closed: drop everything we hold for it
//
// State — one entry per tab in a session store (core/session-map.js, SESSION_KEY.BADGE), so the risk survives a
// service-worker restart: _tabs.map  Map<tabId, { site, severity, tamper }> (tamper = a SEVERITY), bounded by open tabs (releaseTab on
// tabs.onRemoved). Every change waits for the restore (_tabs.ready()) and applies in arrival order.
// Render coalescing (4.5.4): a change marks the tab dirty; one timer per tab (BADGE_RENDER_DELAY_MS) draws it and
// saves the session entry. Text and colour already shown are not sent again.
//   _timers  Map<tabId, timeoutId>         — pending draw; cleared by releaseTab()
//   _shown   Map<tabId, { text, color }>   — what Chrome shows now; deleted by releaseTab()
// ─────────────────────────────────────────────────────────────────────────────

import { BADGE_COLOR, BADGE_TEXT, BADGE_RENDER_DELAY_MS, BADGE_SHOWS_BLOCK_COUNT, SESSION_KEY, SEVERITY, SEVERITY_ORDER,
         TAMPER_BADGE_SEVERITY, LOG_PREFIX, LEVEL_INFO, ICON_SIZES, ICON_DIR } from "../data/constants.js";
import { createSessionMap } from "./session-map.js";

const _tabs = createSessionMap(SESSION_KEY.BADGE);
const _timers = new Map();
const _shown = new Map();

export function ready() { return _tabs.ready(); }

// Every service-worker start (Chrome keeps the option, setting it again is harmless). Guarded: a failure is logged,
// the symbols still work.
export function init() {
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR.NORMAL })
    .catch((e) => console.warn(LOG_PREFIX, "badge colour:", e));
  chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: BADGE_SHOWS_BLOCK_COUNT })
    .catch((e) => console.warn(LOG_PREFIX, "badge block count:", e));
}

// A stored entry from before (tamper was a boolean mark) or anything unexpected counts as nothing (guard).
function severityOf(value) { return SEVERITY_ORDER.includes(value) ? value : SEVERITY.NONE; }

function entryOf(tabId) {
  if (!_tabs.map.has(tabId)) _tabs.map.set(tabId, { site: "", severity: SEVERITY.NONE, tamper: SEVERITY.NONE });
  return _tabs.map.get(tabId);
}

const TEXT_OF = Object.freeze({ [SEVERITY.SUSPECT]: BADGE_TEXT.SUSPECT, [SEVERITY.PHISHING]: BADGE_TEXT.PHISHING });
const COLOR_OF = Object.freeze({ [SEVERITY.NONE]: BADGE_COLOR.NORMAL, [SEVERITY.SUSPECT]: BADGE_COLOR.SUSPECT,
                                 [SEVERITY.PHISHING]: BADGE_COLOR.PHISHING });
// The worst of the site's risk and the tamper rating; text null = Chrome's block count.
function badgeOf(entry) {
  const site = severityOf(entry.severity), tamper = severityOf(entry.tamper);
  const worst = SEVERITY_ORDER.indexOf(tamper) > SEVERITY_ORDER.indexOf(site) ? tamper : site;
  return { text: TEXT_OF[worst] || null, color: COLOR_OF[worst] };
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

// Chrome clears a tab's own badge text and colour when it navigates: forget what was shown and draw again (the site's
// risk stays when the site stays; the tamper rating belonged to the old page).
export function resetPage(tabId) {
  _shown.delete(tabId);
  update(tabId, (e) => { e.tamper = SEVERITY.NONE; });
}

// `rating`: a TAMPER_RATING (Low and unknown values give nothing).
export function setTamperRating(tabId, rating) {
  const sev = Object.prototype.hasOwnProperty.call(TAMPER_BADGE_SEVERITY, rating) ? TAMPER_BADGE_SEVERITY[rating] : SEVERITY.NONE;
  update(tabId, (e) => {
    if (e.tamper === sev) return false;                      // nothing changes: no draw
    e.tamper = sev;
    return true;
  });
}

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
