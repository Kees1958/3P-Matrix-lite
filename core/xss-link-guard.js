// ── core/xss-link-guard.js ────────────────────────────────────────────────────
// 5.1.2 — warnXssLinks "Warn when another site sends you a link with script code in it" (reflected XSS).
// A reflected cross-site-scripting attack is a link, on the attacker's site or in their message, to a page of a site
// the user is signed in to, with script code in the address; the vulnerable site copies it into its page, where it
// runs as the user. Chrome dropped its own XSS filter in 2019. NoScript's InjectionChecker is the prior art; this is
// the MV3 version: observe, never hold the request, and send the tab to a warning as fast as possible.
//
// Public interface:
//   xssLinkDecision(state, url, initiator) → { warn: boolean, referrer: string }   (pure, no Chrome API)
//   hasScriptMarkup(text)                   — the address test (exported for tests)
//   onXssLinkRequest(details, state)        — Promise<boolean warned> — part of background.js's top-page request listener;
//                                             5.1.3: true = this navigation's warning is the XSS one (the site check then
//                                             does not redirect: one warning per navigation)
//   mayBeXssLink(details)                   — cheap pre-check, run BEFORE the state is loaded (background.js)
//
// Who sent the user: the request's `initiator`, as warnDeviceCodePages (core/device-code-guard.js) — Chrome sets it, a
// page cannot fake or hide it, and it is absent for a typed address, a bookmark or another app.
//   no initiator / not a website                → no warning
//   initiator of the SAME site as the target    → no warning (a site's own links are its own business)
//   another website, or an opaque ("null") one  → warning, IF the address carries script markup
// The address: path and query (the part after "#" never reaches the network layer — that half is Tamper
// Protection's tgAddressScript), "+" read as a space, percent-decoded up to XSS_DECODE_ROUNDS times, at most
// XSS_ADDRESS_CHARS_MAX characters. Script markup = data/constants.js XSS_MARKUP_PATTERNS.
// Level: the SENDING site's level decides (its allow-list entry = no warning); an opaque origin → the global level.
// "Continue anyway" = Continue once for this tab + site (core/navigation-guard.js allowOnce); "Leave" opens a new-tab
// page (going back would return to the sender). Known limits: form POSTs are not checked; a payload split over
// several parameters or encoded otherwise (HTML entities, base64) is not seen.
// Guard: one warning being opened per tab at a time (_opening, released in finally).
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX, XSS_MARKUP_PATTERNS, XSS_MARKUP_FLAGS, XSS_DECODE_ROUNDS, XSS_ADDRESS_CHARS_MAX } from "../data/constants.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { PAGE_SCAM_KIND } from "../data/page-scam-reasons.js";
import { effectiveLevel, isProtectionActive, isAllowedFor } from "./policy.js";
import { ALLOW_CATEGORY } from "../data/allow-categories.js";
import { isAllowedOnce, warningUrlFor } from "./navigation-guard.js";
import { parseHttpUrl, registeredDomain } from "../util/domain.js";

const NO_WARNING = Object.freeze({ warn: false, referrer: "" });
const OPAQUE_ORIGIN = "null";
const FORM_SPACE_RE = /\+/g;                      // "+" is a space in a query string
const MARKUP_RES = Object.freeze(XSS_MARKUP_PATTERNS.map((src) => new RegExp(src, XSS_MARKUP_FLAGS)));
const LT_CHAR = "<";
const ENCODED_LT_RE = /%(?:25)*3c/i;               // "<", percent-encoded once or more
const JS_SCHEME_RE = /javascript/i;                // the javascript: pattern's word (cheap pre-check)

export function hasScriptMarkup(text) {
  let t = String(text || "").slice(0, XSS_ADDRESS_CHARS_MAX).replace(FORM_SPACE_RE, " ");
  for (let round = 0; ; round++) {
    if (MARKUP_RES.some((re) => re.test(t))) return true;
    if (round >= XSS_DECODE_ROUNDS) return false;
    let next;
    try { next = decodeURIComponent(t); } catch { return false; }   // malformed escape: as far as it decoded
    if (next === t) return false;
    t = next;
  }
}

// The address part that reaches the server: path + query.
function addressText(url) {
  try { const u = new URL(url); return u.pathname + u.search; } catch { return ""; }
}

// Cheap, before any state is loaded: a page without "<" (plain or encoded) or "javascript" in its address cannot match.
export function mayBeXssLink(details) {
  if (!details || details.tabId < 0 || details.type !== "main_frame" || !details.initiator) return false;
  const text = addressText(details.url);
  return text.includes(LT_CHAR) || ENCODED_LT_RE.test(text) || JS_SCHEME_RE.test(text);
}

export function xssLinkDecision(state, url, initiator) {
  if (!initiator) return NO_WARNING;                                   // typed, bookmark, another app
  const target = parseHttpUrl(String(url || ""));
  if (!target) return NO_WARNING;
  const opaque = initiator === OPAQUE_ORIGIN;
  const from = opaque ? null : parseHttpUrl(String(initiator));
  if (!opaque && !from) return NO_WARNING;                              // an extension or browser page started it
  if (from && registeredDomain(from.host) === registeredDomain(target.host)) return NO_WARNING;
  if (!hasScriptMarkup(addressText(url))) return NO_WARNING;
  const level = from ? effectiveLevel(state, from.host) : state.level;
  if (!isProtectionActive(state, PROTECTION_KEY.WARN_XSS_LINKS, level)) return NO_WARNING;
  if (from && isAllowedFor(state, ALLOW_CATEGORY.SCAM, from.host)) return NO_WARNING;   // 5.1.3: the sending site is allowed
  return { warn: true, referrer: from ? registeredDomain(from.host) : "" };
}

const _opening = new Set();                       // tabIds whose warning is being opened (released in finally)

export async function onXssLinkRequest(details, state) {
  if (details.tabId < 0 || details.type !== "main_frame") return false;
  if (_opening.has(details.tabId)) return true;                        // its warning is already being opened
  const decision = xssLinkDecision(state, details.url, details.initiator);
  if (!decision.warn) return false;
  _opening.add(details.tabId);
  try {
    const target = parseHttpUrl(details.url);
    if (await isAllowedOnce(details.tabId, registeredDomain(target.host))) return false;   // "Continue anyway"
    await chrome.tabs.update(details.tabId, { url: warningUrlFor(details.url, PAGE_SCAM_KIND.XSS_LINK, decision.referrer) });
    return true;
  } catch (e) {
    console.warn(LOG_PREFIX, "XSS link warning failed:", e);          // tab closed meanwhile is the usual cause
    return false;
  } finally {
    _opening.delete(details.tabId);
  }
}
