// ── core/tab-sites.js ─────────────────────────────────────────────────────────
// Remembers each tab's top-level host, so a request whose initiator is opaque ("null" — a
// sandboxed, data: or srcdoc frame, typical for ad scripts) can still be attributed by
// core/rule-matcher.js. Chrome's own DNR matching uses the opaque origin's precursor (the
// site that created the frame), which for these frames is the tab's own site; webRequest only
// reports "null", so the tab's top-level host is the closest stand-in we have. (4.2.1)
//
// Public interface:
//   setTopHost(tabId, host)    — top frame committed (background.js webNavigation.onCommitted)
//   topHostOf(tabId)           — Promise<string> — remembered host, else looked up once via
//                                chrome.tabs.get (service-worker restart), "" when unknown
//   releaseTab(tabId)          — tab closed: forget it
//
// Guards: one Map entry per tab, capped at TAB_SITES_CAP (oldest dropped first), released on
// tab close; in memory only — a service-worker restart refills it lazily via topHostOf().
// ─────────────────────────────────────────────────────────────────────────────

import { TAB_SITES_CAP } from "../data/constants.js";
import { parseHttpUrl } from "../util/domain.js";

const _hosts = new Map();   // tabId → top-level host

export function setTopHost(tabId, host) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  _hosts.delete(tabId);                                           // re-insert = newest
  if (!host) return;
  if (_hosts.size >= TAB_SITES_CAP) _hosts.delete(_hosts.keys().next().value);
  _hosts.set(tabId, host);
}

export async function topHostOf(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return "";
  if (_hosts.has(tabId)) return _hosts.get(tabId);
  try {
    const tab = await chrome.tabs.get(tabId);
    const p = tab && parseHttpUrl(tab.url || "");
    const host = p ? p.host : "";
    setTopHost(tabId, host);
    return host;
  } catch {
    return "";                                                    // tab already gone
  }
}

export function releaseTab(tabId) {
  _hosts.delete(tabId);
}
