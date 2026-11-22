// ── core/exfil-guard.js ───────────────────────────────────────────────────────
// 4.6.0 — protections "Block exfiltrating (phishing) data to messaging bots" (blockExfilMessagingBots) and
// "… to web services" (blockExfilWebServices). The DNR rules (core/rule-builder.js exfilRules) stop the request;
// this module turns such a block into the site warning, so the user learns WHY the page is dangerous.
//
// Public interface:
//   onBlockedRequest(tabId, ruleId) — called by background.js onRequestError for every request OUR rules blocked
//                                     (core/rule-matcher.js attribution); does nothing unless the rule is an
//                                     exfiltration rule.
//
// When: the tab still shows an http(s) page (not already the warning), the user did not choose "Continue once"
// for this site in this tab (core/navigation-guard.js isAllowedOnce — the block stays, only the dialog is
// skipped), and no warning is already being opened for this tab (guard against a burst of blocked requests).
// The warning page then reads the channel from its URL (WARNING_REASON_PARAM) and its "Go back" leaves the site
// (core/leave-site.js).
// ─────────────────────────────────────────────────────────────────────────────

import { GROUP_ID_STRIDE, LOG_PREFIX } from "../data/constants.js";
import { exfilChannelForRule } from "../data/exfil-channels.js";
import { isAllowedOnce, warningUrlFor } from "./navigation-guard.js";
import { parseHttpUrl, registeredDomain } from "../util/domain.js";

const _opening = new Set();                       // tabIds whose warning is being opened (released in finally)

export async function onBlockedRequest(tabId, ruleId) {
  const channel = exfilChannelForRule(ruleId, GROUP_ID_STRIDE);
  if (!channel || _opening.has(tabId)) return;
  _opening.add(tabId);
  try {
    const tab = await chrome.tabs.get(tabId);
    const p = parseHttpUrl(tab.url || "");
    if (!p) return;                                                     // already on the warning / a browser page
    if (await isAllowedOnce(tabId, registeredDomain(p.host))) return;  // "Continue once": keep blocking, no dialog
    await chrome.tabs.update(tabId, { url: warningUrlFor(tab.url, channel.id) });
  } catch (e) {
    console.warn(LOG_PREFIX, "exfiltration warning failed:", e);       // tab closed meanwhile is the usual cause
  } finally {
    _opening.delete(tabId);
  }
}
