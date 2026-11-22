// ── core/matrix-windows.js ────────────────────────────────────────────────────
// Show Matrix panel windows: one panel window per observed tab. Owns the tab → window map and
// both ends of its lifecycle (open / focus, and close on tab close, window close or the
// observation timeout). Observation itself is core/connection-matrix.js.
// (4.2.3: moved out of background.js — audit finding 6; behaviour unchanged.)
//
// Public interface:
//   openMatrixPanel(tabId, host)   — start observing, focus the existing panel or open one, reload
//                                    the tab so every request is seen from the start
//   closeMatrixPanel(tabId)        — stop observing and close the tab's panel (tab closed, timeout)
//   onWindowRemoved(windowId)      — a panel window was closed by the user: stop observing its tab
//
// Guards: _windows holds at most one entry per open panel; every path that ends a panel deletes
// its entry; a stale window id (closed elsewhere) is detected on focus and dropped. In memory
// only — after a service-worker restart the panel closes itself (ui/matrix.js), so nothing leaks.
// ─────────────────────────────────────────────────────────────────────────────

import { MATRIX_PAGE, MATRIX_WINDOW, MATRIX_TAB_PARAM } from "../data/constants.js";
import * as Matrix from "./connection-matrix.js";

const _windows = new Map();                      // observed tabId → panel windowId

export function closeMatrixPanel(tabId) {
  Matrix.stopMatrix(tabId);
  const win = _windows.get(tabId);
  if (win !== undefined) { _windows.delete(tabId); chrome.windows.remove(win).catch(() => { /* already closed */ }); }
}

export function onWindowRemoved(windowId) {
  for (const [tabId, win] of _windows) {
    if (win === windowId) { _windows.delete(tabId); Matrix.stopMatrix(tabId); }
  }
}

export async function openMatrixPanel(tabId, host) {
  Matrix.startMatrix(tabId, host, closeMatrixPanel);              // timeout closes the panel too
  const existing = _windows.get(tabId);
  if (existing !== undefined) {
    try { await chrome.windows.update(existing, { focused: true }); }
    catch { _windows.delete(tabId); }                            // stale — window closed elsewhere
  }
  if (!_windows.has(tabId)) {
    const url = `${chrome.runtime.getURL(MATRIX_PAGE)}?${MATRIX_TAB_PARAM}=${tabId}`;
    const win = await chrome.windows.create({ url, type: "popup", width: MATRIX_WINDOW.width, height: MATRIX_WINDOW.height });
    _windows.set(tabId, win.id);
  }
  await chrome.tabs.reload(tabId).catch(() => { /* tab gone — observation ends with it */ });
}
