// ── core/navigation-guard.js ──────────────────────────────────────────────────
// First-party site check on every top-level navigation — warnSuspiciousSites
// "Warn when opening suspicious sites" (PROTECTION_KEY.WARN_SUSPICIOUS_SITES).
// Timing (4.2.3): the listener cannot hold a navigation — the tab is redirected to the warning
// page as fast as possible, but the first request to the site may already have been sent. The user
// is always warned before using the page; "when", not "before", is the honest promise.
// Active when the site's effective level ≥ its fromLevel (2) AND the user has not
// unticked it in the popup. Inactive → nothing is scored, no dialog, neutral badge.
// Stage 1 (local, ~0.4 ms) runs here. 4.4.1: the dialog opens when site-scorer dialogDecision() says so —
// score at or below SITE_DIALOG_FROM[the site's level], or a site exception (known bad, impersonation);
// the dialog page then asks for stage 2. A suspicious score below the line gets the orange badge only.
//
// Public interface:
//   checkNavigation(details, state, warn = true) — 5.1.3: part of background.js's top-page request listener
//                                     (webRequest.onBeforeRequest, main_frame; was webNavigation.onBeforeNavigate, which
//                                     fires for every frame). warn = false: score and remember the risk, no redirect
//                                     (another warning already took this navigation)
//   allowOnce(tabId, site)          — Promise: "Continue once" — skip the check for this tab + site
//   releaseTab(tabId)               — tab closed: drop its one-time allowances
//   (4.5.4) the allowances live in a session store (core/session-map.js, SESSION_KEY.ALLOWED_ONCE):
//   they used to be forgotten when the idle service worker stopped (~30 s), so the user was warned again
//   for a site they had just chosen to continue to. checkNavigation() awaits the restore.
//   warningUrlFor(url, reason?, referrer?) — extension URL of the warning dialog for `url`; 4.6.0: `reason` = an
//                                     exfiltration channel id (data/exfil-channels.js) the page tried to use;
//                                     4.7.0: or a page-scam reason id (data/page-scam-reasons.js); `referrer` = the
//                                     site that sent the user (device-code warning — display only)
//   isAllowedOnce(tabId, site)      — 4.6.0: Promise<boolean> — "Continue once" given for this tab + site
//   4.6.0: skipped while core/leave-site.js walks the tab back (isLeaving) — passing the site's own pages on the
//   way out must not reopen the warning.
//
// Skipped (never scored): non-http(s), private/local hosts, the built-in
// whitelist, sites where warnSuspiciousSites is not active (level 1 / allow list,
// or unticked), and sites allowed once in this tab.
// ─────────────────────────────────────────────────────────────────────────────

import { SEVERITY, WARNING_PAGE, WARNING_TARGET_PARAM, WARNING_REASON_PARAM, WARNING_REFERRER_PARAM, LOG_PREFIX, SESSION_KEY } from "../data/constants.js";
import { isLeaving } from "./leave-site.js";
import { createSessionMap } from "./session-map.js";
import { BUILTIN_ALL } from "../data/builtin-domains.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { effectiveLevel, isProtectionActive, isAllowedFor } from "./policy.js";
import { ALLOW_CATEGORY } from "../data/allow-categories.js";
import { scoreLocal, dialogDecision } from "./site-scorer.js";
import { setRisk } from "./badge.js";
import { parseHttpUrl, registeredDomain, isInDomainList } from "../util/domain.js";

// tabId → site[] allowed once ("Continue once"). Bounded by open tabs (releaseTab on tabs.onRemoved).
const _allowedOnce = createSessionMap(SESSION_KEY.ALLOWED_ONCE);

export async function allowOnce(tabId, site) {
  await _allowedOnce.ready();
  const sites = _allowedOnce.map.get(tabId) || [];
  if (!sites.includes(site)) _allowedOnce.map.set(tabId, sites.concat(site));
  await _allowedOnce.save();                                  // saved before the caller reloads the tab
}

export function releaseTab(tabId) {
  _allowedOnce.ready().then(() => { if (_allowedOnce.map.delete(tabId)) _allowedOnce.save(); });
}

export function warningUrlFor(url, reason = null, referrer = "") {
  const extra = (reason ? `&${WARNING_REASON_PARAM}=${encodeURIComponent(reason)}` : "") +
                (referrer ? `&${WARNING_REFERRER_PARAM}=${encodeURIComponent(referrer)}` : "");
  return `${chrome.runtime.getURL(WARNING_PAGE)}?${WARNING_TARGET_PARAM}=${encodeURIComponent(url)}${extra}`;
}

export async function isAllowedOnce(tabId, site) {
  await _allowedOnce.ready();
  const sites = _allowedOnce.map.get(tabId);
  return !!sites && sites.includes(site);
}

export async function checkNavigation(details, state, warn = true) {
  if (details.frameId !== 0 || details.tabId < 0 || isLeaving(details.tabId)) return;
  const p = parseHttpUrl(details.url);
  if (!p) return;
  const site = registeredDomain(p.host);

  const level = effectiveLevel(state, p.host);
  // 5.1.3: "Scam: site" on the allow list = this warning is ignored for the site being opened.
  if (!isProtectionActive(state, PROTECTION_KEY.WARN_SUSPICIOUS_SITES, level) || isAllowedFor(state, ALLOW_CATEGORY.SCAM, p.host)) {
    setRisk(details.tabId, site, SEVERITY.NONE);               // level 1 / allow list / unticked
    return;
  }
  if (isInDomainList(p.host, BUILTIN_ALL)) { setRisk(details.tabId, site, SEVERITY.NONE); return; }
  await _allowedOnce.ready();
  const once = _allowedOnce.map.get(details.tabId);
  if (once && once.includes(site)) return;                          // keep the risk colour, no dialog

  const local = scoreLocal(details.url);
  if (!local) { setRisk(details.tabId, site, SEVERITY.NONE); return; }
  setRisk(details.tabId, site, local.severity);                // badge colour: severity, whatever the dialog decision
  if (!warn || !dialogDecision(local, level).warn) return;      // 4.4.1: staged by level, exceptions always open it

  // Not silent: a failed redirect means the user was NOT warned (tab closed meanwhile is the usual cause).
  chrome.tabs.update(details.tabId, { url: warningUrlFor(details.url) }).catch((e) => console.warn(LOG_PREFIX, "warning redirect failed:", e));
}
