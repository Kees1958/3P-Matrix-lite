// ── core/leave-site.js ────────────────────────────────────────────────────────
// 4.6.0 — "Go back" that leaves a site for good: used by the exfiltration warning (core/exfil-guard.js via the
// warning page) and the password-form warning (security/password-form-guard.js). A phishing kit is often several
// pages of ONE site (e-mail address → password), so one step back would land on its first page again.
//
// Public interface:
//   leaveSite(tabId, site) — Promise: steps back one history entry at a time until the tab shows a page of another
//                            website; no earlier website (or a step fails / does not commit in time) → new-tab page.
//   isLeaving(tabId)       — true while leaveSite() walks this tab (core/navigation-guard.js skips its check then,
//                            so passing a suspicious page of the same site does not reopen the warning)
//
// No history is kept (user requirement): nothing about visited sites is recorded or stored. The walk only reads
// the tab's CURRENT address after each step, and forgets it at once.
// Guards: GO_BACK_MAX_STEPS bounds the walk (a page may have pushed many entries), GO_BACK_STEP_TIMEOUT_MS bounds
// each step, and the per-tab walk flag is always released (finally) — also when the tab closes mid-walk.
// ─────────────────────────────────────────────────────────────────────────────

import { CHROME_NEW_TAB_URL, GO_BACK_MAX_STEPS, GO_BACK_STEP_TIMEOUT_MS, LOG_PREFIX } from "../data/constants.js";
import { parseHttpUrl, registeredDomain } from "../util/domain.js";

const TOP_FRAME_ID = 0;
const _walking = new Set();                       // tabIds being walked back (bounded by open tabs; always released)

export function isLeaving(tabId) { return _walking.has(tabId); }

// Resolves true when the tab's top frame commits a navigation, false after GO_BACK_STEP_TIMEOUT_MS.
// Init/release: the listener and the timer are both removed on either outcome.
function nextTopCommit(tabId) {
  return new Promise((resolve) => {
    function done(ok) {
      clearTimeout(timer);
      chrome.webNavigation.onCommitted.removeListener(onCommitted);
      resolve(ok);
    }
    function onCommitted(d) { if (d.tabId === tabId && d.frameId === TOP_FRAME_ID) done(true); }
    const timer = setTimeout(() => done(false), GO_BACK_STEP_TIMEOUT_MS);
    chrome.webNavigation.onCommitted.addListener(onCommitted);
  });
}

// One step back. False when there is no earlier entry or it did not commit in time.
async function stepBack(tabId) {
  const committed = nextTopCommit(tabId);
  try { await chrome.tabs.goBack(tabId); } catch { return false; }       // no earlier entry
  return committed;
}

function siteOfUrl(url) {
  const p = parseHttpUrl(url || "");
  return p ? registeredDomain(p.host) : null;                           // extension / chrome pages: null
}

export async function leaveSite(tabId, site) {
  if (_walking.has(tabId)) return;                                      // guard: one walk per tab
  _walking.add(tabId);
  try {
    for (let step = 0; step < GO_BACK_MAX_STEPS; step++) {
      if (!(await stepBack(tabId))) break;
      const now = siteOfUrl((await chrome.tabs.get(tabId)).url);
      if (now && now !== site) return;                                  // another website: done
    }
    await chrome.tabs.update(tabId, { url: CHROME_NEW_TAB_URL });       // nothing earlier: leave to a new-tab page
  } catch (e) {
    console.warn(LOG_PREFIX, "leave site:", e);                         // tab closed mid-walk is the usual cause
  } finally {
    _walking.delete(tabId);
  }
}
