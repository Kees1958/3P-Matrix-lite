// ── core/tamper-warnings.js ───────────────────────────────────────────────────
// 5.1.0 — Tamper Guard's warning windows. A warning is an extension page in its own small window
// (ui/tamper-warning.html), never UI drawn into the web page: the page that is being tampered with cannot remove,
// hide or click it (C47).
// 5.1.3 — ONE window per page, with the page's risk rating and EVERY finding (core/tamper-guard.js decides when):
// a later finding while the window is open UPDATES it — the record is replaced and the window is told
// (MSG_TAMPER_WARNING_CHANGED) to fetch its model again.
//
// Public interface:
//   hasOpenWarning(tabId)          — a warning window is open (or opening) for this tab
//   showWarning(w)                 — Promise<bool>; opens the tab's window or updates the open one;
//                                    w = { tabId, site, rating, score, sensitive, signals: [{ rule, kind, items }] }
//   warningModel(id)               — the window's model (texts from data/tamper-rules.js), or null
//   warningRecord(id)              — { tabId, site } for an action, or null
//   closeWarning(id)               — Promise — closes the window and releases the record
//   onWindowRemoved(windowId)      — the user closed it (or the countdown did): release
//   releaseTab(tabId)              — the tab closed: close its window, release
//
// State owned: _warnings (id → record), _byTab, _byWindow — in memory only (released with the service worker; a
// window left open across a service-worker restart shows "This warning is no longer available" and closes).
// Guards (B6/B10): at most TAMPER_TABS_CAP records; at most TAMPER_DETAIL_ITEMS_MAX items per signal; every path that
// ends a warning releases all three maps.
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX, TAMPER_WARNING_PAGE, TAMPER_WARNING_ID_PARAM, TAMPER_WARNING_WINDOW, TAMPER_TABS_CAP,
         TAMPER_RATING, TAMPER_COUNTDOWN_S, TAMPER_DETAIL_ITEMS_MAX } from "../data/constants.js";
import { MSG_TAMPER_WARNING_CHANGED } from "../data/message-types.js";
import { TAMPER_RULE_BY_ID, TAMPER_RATING_LABEL } from "../data/tamper-rules.js";

const WINDOW_TYPE_POPUP = "popup";

const _warnings = new Map();      // id → { id, tabId, windowId, site, rating, score, sensitive, signals }
const _byTab = new Map();         // tabId → id
const _byWindow = new Map();      // windowId → id
let _nextId = 1;

function release(id) {
  const w = _warnings.get(id);
  if (!w) return null;
  _warnings.delete(id);
  if (_byTab.get(w.tabId) === id) _byTab.delete(w.tabId);
  if (w.windowId !== null && _byWindow.get(w.windowId) === id) _byWindow.delete(w.windowId);
  return w;
}

export function hasOpenWarning(tabId) { return _byTab.has(tabId); }

// Only the known rules, with bounded items — the window never shows anything the rules table does not name.
function cleanSignals(signals) {
  return (Array.isArray(signals) ? signals : []).filter((s) => s && TAMPER_RULE_BY_ID[s.rule])
    .map((s) => ({ rule: s.rule, kind: s.kind, items: (Array.isArray(s.items) ? s.items : []).slice(0, TAMPER_DETAIL_ITEMS_MAX) }));
}
function fill(rec, w) {
  rec.site = w.site;
  rec.rating = w.rating;
  rec.score = w.score;
  rec.sensitive = !!w.sensitive;
  rec.signals = cleanSignals(w.signals);
}

export async function showWarning(w) {
  const openId = _byTab.get(w.tabId);
  if (openId !== undefined) {                                   // update the open window
    fill(_warnings.get(openId), w);
    chrome.runtime.sendMessage({ type: MSG_TAMPER_WARNING_CHANGED, id: openId }).catch(() => { /* still loading: it reads the new model */ });
    return true;
  }
  if (_warnings.size >= TAMPER_TABS_CAP) return false;           // guard
  const id = String(_nextId++);
  const rec = { id, windowId: null, tabId: w.tabId };
  fill(rec, w);
  _warnings.set(id, rec);
  _byTab.set(w.tabId, id);
  try {
    const url = `${chrome.runtime.getURL(TAMPER_WARNING_PAGE)}?${TAMPER_WARNING_ID_PARAM}=${encodeURIComponent(id)}`;
    const win = await chrome.windows.create({ url, type: WINDOW_TYPE_POPUP, width: TAMPER_WARNING_WINDOW.width,
                                              height: TAMPER_WARNING_WINDOW.height, focused: true });
    if (!win || win.id === undefined) throw new Error("no window");
    if (!_warnings.has(id)) { chrome.windows.remove(win.id).catch(() => {}); return false; }   // released meanwhile
    rec.windowId = win.id;
    _byWindow.set(win.id, id);
    return true;
  } catch (e) {
    console.error(LOG_PREFIX, "Tamper Guard warning window failed:", e);
    release(id);
    return false;
  }
}

export function warningModel(id) {
  const w = _warnings.get(id);
  if (!w) return null;
  const critical = w.rating >= TAMPER_RATING.CRITICAL;
  return {
    site: w.site, rating: w.rating, ratingLabel: TAMPER_RATING_LABEL[w.rating], score: w.score, sensitive: w.sensitive,
    critical, countdownS: critical ? 0 : TAMPER_COUNTDOWN_S,
    signals: w.signals.map((s) => {
      const rule = TAMPER_RULE_BY_ID[s.rule];
      return { rule: s.rule, label: rule.label, description: rule.description, points: rule.points,
               detailKind: s.kind, detailHead: rule.detailHead || "", items: s.items.slice() };
    })
  };
}

export function warningRecord(id) {
  const w = _warnings.get(id);
  return w ? { tabId: w.tabId, site: w.site } : null;
}

export async function closeWarning(id) {
  const w = release(id);
  if (w && w.windowId !== null) await chrome.windows.remove(w.windowId).catch(() => { /* already closed */ });
}

export function onWindowRemoved(windowId) {
  const id = _byWindow.get(windowId);
  if (id !== undefined) release(id);
}

export function releaseTab(tabId) {
  const id = _byTab.get(tabId);
  if (id !== undefined) closeWarning(id).catch((e) => console.warn(LOG_PREFIX, "Tamper Guard window close:", e));
}
