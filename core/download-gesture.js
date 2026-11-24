// ── core/download-gesture.js ──────────────────────────────────────────────────
// 5.1.3 — Download protection signal "Download started without a click on the page" (Sentinel idea, user decision 2026-11-24):
// a drive-by download starts on its own, a real one follows a click. When a monitored download starts, the tab whose
// address equals the download's referrer is asked — once, on demand, no content script stays behind — whether its
// page has transient user activation (navigator.userActivation.isActive: a click or key press within the last few
// seconds; a click inside a frame also activates the page).
//
// Public interface:
//   startedWithoutClick(referrer)   — Promise<true | false | null>: true = no click, false = clicked, null = unknown
//                                     (no referrer, no matching tab, the page cannot be asked, or no answer in time)
//
// State owned: none (one timer per call, always cleared). Guards (B6): at most DOWNLOAD_GESTURE.TABS_MAX tabs
// compared, at most DOWNLOAD_GESTURE.TIMEOUT_MS waited.
// ─────────────────────────────────────────────────────────────────────────────

import { DOWNLOAD_GESTURE } from "../data/constants.js";

// Runs in the page's isolated world: only reads the activation flag.
function readActivation() {
  const u = navigator.userActivation;
  return u ? u.isActive === true : null;
}

async function tabOf(referrer) {
  const tabs = (await chrome.tabs.query({})).slice(0, DOWNLOAD_GESTURE.TABS_MAX).filter((t) => t.url === referrer);
  return tabs.find((t) => t.active) || tabs[0] || null;
}

function withTimeout(promise) {
  let timer = null;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), DOWNLOAD_GESTURE.TIMEOUT_MS); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));   // release (B10)
}

async function ask(referrer) {
  const tab = await tabOf(referrer);
  if (!tab || !Number.isInteger(tab.id)) return null;
  const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: readActivation });
  const active = res ? res.result : null;
  return typeof active === "boolean" ? !active : null;
}

export async function startedWithoutClick(referrer) {
  if (typeof referrer !== "string" || !referrer) return null;
  try { return await withTimeout(ask(referrer)); }
  catch { return null; }                                       // a page that cannot be scripted (store, PDF viewer)
}
