// ── core/device-code-guard.js ─────────────────────────────────────────────────
// 4.7.0 — warnDeviceCodePages "Warn when a site sends you to enter a sign-in code".
// Device-code phishing: a scam page tells the user to "enter this code at microsoft.com/devicelogin". The page is
// real; the code is the attacker's, and entering it signs the ATTACKER's device into the user's account.
//
// Public interface:
//   deviceCodeDecision(state, url, initiator) → { warn: boolean, referrer: string }   (pure, no Chrome API)
//   onDeviceCodeRequest(details, state)       — webRequest.onBeforeRequest body (main_frame, filtered by
//                                               data/device-code-pages.js DEVICE_CODE_URL_PATTERNS)
//
// Who sent the user: the request's `initiator` — the origin of the page whose link, form, script or window.open()
// started the navigation. Chrome sets it itself (a page cannot fake or hide it, unlike the Referer header), it
// survives the provider's own server redirects, and it is ABSENT when the user typed the address, used a bookmark
// or another app opened it (`gh auth login`, `az login --use-device-code`) — exactly the cases that are fine.
//   no initiator / not a website (extension page)      → no warning
//   initiator on the provider's own domains (ownDomains) → no warning
//   any other website, or an opaque ("null") origin    → warning (amber page, reason deviceCode)
// Level: the SENDING site's level decides (its allow-list entry = no warning); an opaque origin → the global level.
// Accepted false negative: a link in a desktop mail app has no initiator — not warned.
//
// Timing: as warnSuspiciousSites, the tab is sent to the warning as fast as possible; the real page may already load,
// but no code can be entered before the user answers. "Yes, I started it" = Continue once for this tab + site
// (core/navigation-guard.js allowOnce); "No, leave" opens a new-tab page (going back would return to the sender).
// Guard: one warning being opened per tab at a time (_opening, released in finally).
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX } from "../data/constants.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { DEVICE_CODE_PAGES } from "../data/device-code-pages.js";
import { PAGE_SCAM_KIND } from "../data/page-scam-reasons.js";
import { effectiveLevel, isProtectionActive, isAllowedFor } from "./policy.js";
import { ALLOW_CATEGORY } from "../data/allow-categories.js";
import { isAllowedOnce, warningUrlFor } from "./navigation-guard.js";
import { parseHttpUrl, registeredDomain, isInDomainList } from "../util/domain.js";

const NO_WARNING = Object.freeze({ warn: false, referrer: "" });
const OPAQUE_ORIGIN = "null";
const GLOB_STAR = "*";
const REGEX_SPECIALS = /[.+?^${}()|[\]\\]/g;

// Path globs → anchored regexes, compiled once.
const PAGES = DEVICE_CODE_PAGES.map((p) => ({
  ...p,
  pathRe: new RegExp("^" + p.path.replace(REGEX_SPECIALS, "\\$&").split(GLOB_STAR).join(".*"))
}));

function pageFor(url) {
  const p = parseHttpUrl(url);
  if (!p) return null;
  let path = "";
  try { const u = new URL(url); path = u.pathname + u.search; } catch { return null; }
  return PAGES.find((pg) => isInDomainList(p.host, [pg.host]) && pg.pathRe.test(path)) || null;
}

export function deviceCodeDecision(state, url, initiator) {
  const page = pageFor(String(url || ""));
  if (!page || !initiator) return NO_WARNING;                        // not a device page / typed, bookmark, other app
  const opaque = initiator === OPAQUE_ORIGIN;
  const from = opaque ? null : parseHttpUrl(String(initiator));
  if (!opaque && !from) return NO_WARNING;                            // an extension or browser page started it
  if (from && isInDomainList(from.host, page.ownDomains)) return NO_WARNING;
  const level = from ? effectiveLevel(state, from.host) : state.level;
  if (!isProtectionActive(state, PROTECTION_KEY.WARN_DEVICE_CODE_PAGES, level)) return NO_WARNING;
  if (from && isAllowedFor(state, ALLOW_CATEGORY.SCAM, from.host)) return NO_WARNING;   // 5.1.3: the sending site is allowed
  return { warn: true, referrer: from ? registeredDomain(from.host) : "" };
}

const _opening = new Set();                       // tabIds whose warning is being opened (released in finally)

export async function onDeviceCodeRequest(details, state) {
  if (details.tabId < 0 || details.type !== "main_frame" || _opening.has(details.tabId)) return;
  const decision = deviceCodeDecision(state, details.url, details.initiator);
  if (!decision.warn) return;
  _opening.add(details.tabId);
  try {
    const target = parseHttpUrl(details.url);
    if (await isAllowedOnce(details.tabId, registeredDomain(target.host))) return;   // "Yes, I started it"
    await chrome.tabs.update(details.tabId, { url: warningUrlFor(details.url, PAGE_SCAM_KIND.DEVICE_CODE, decision.referrer) });
  } catch (e) {
    console.warn(LOG_PREFIX, "device-code warning failed:", e);       // tab closed meanwhile is the usual cause
  } finally {
    _opening.delete(details.tabId);
  }
}
