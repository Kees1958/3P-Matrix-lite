// ── core/page-scam-guard.js ───────────────────────────────────────────────────
// 4.7.0 — turns a page scam that a content script BLOCKED into the red warning page, so the user learns why the
// page is dangerous (as core/exfil-guard.js does for exfiltration):
//   clickFix   — blockClickFix, security/scam-guard-page.js via security/scam-guard-bridge.js (5.1.3 bundles)
//   consentFix — blockConsentFix, security/scam-guard-bridge.js
//   sharedCode — blockSharedCodes (5.1.3), security/scam-guard-bridge.js
//   paymentSkimmer — warnPaymentSkimmer, security/sec-skimmer-warn.js via security/skimmer-bridge.js
//   fakeSignInWindow — blockFakeSignInWindow (5.0.6): NOT sent by a content script as a kind — the service worker decides
//                (core/password-form.js fakeWindowDecision) and calls openPageScamWarning() itself (C47)
//
// Public interface:
//   onPageScamBlocked(state, kind, sender) — MSG_PAGE_SCAM_BLOCKED body. `kind` is checked against the content-script
//                                            kinds; the tab and its page come from the SENDER only (C28).
//   protectionForKind(kind)                — 5.1.3: the protection behind a content-script kind, or null
//   openPageScamWarning(state, kind, key, sender) — 5.0.6: the shared opener (also used for fakeSignInWindow,
//                                            whose decision the service worker makes itself).
//
// No warning when: the kind is unknown (or deviceCode — that one only comes from core/device-code-guard.js); the tab
// does not show an http(s) page (already on the warning); the protection is not active at the TOP page's level (a
// content script outlives a level change until the page reloads); the user chose "Continue once" for this site in
// this tab (the block stays, only the dialog is skipped); a warning is already being opened for this tab.
// Guard: _opening is released in finally.
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX } from "../data/constants.js";
import { PROTECTION_KEY, PROTECTION_BY_KEY, tabOf } from "../data/protections.js";
import { PAGE_SCAM_KIND } from "../data/page-scam-reasons.js";
import { effectiveLevel, isProtectionActive, isAllowedFor } from "./policy.js";
import { ALLOW_CATEGORY_OF_TAB } from "../data/allow-categories.js";
import { isAllowedOnce, warningUrlFor } from "./navigation-guard.js";
import { parseHttpUrl, registeredDomain } from "../util/domain.js";

// Content-script kinds → the protection that must be active (one place).
const PROTECTION_FOR_KIND = Object.freeze({
  [PAGE_SCAM_KIND.CLICK_FIX]:       PROTECTION_KEY.BLOCK_CLICK_FIX,
  [PAGE_SCAM_KIND.CONSENT_FIX]:     PROTECTION_KEY.BLOCK_CONSENT_FIX,
  [PAGE_SCAM_KIND.PAYMENT_SKIMMER]: PROTECTION_KEY.WARN_PAYMENT_SKIMMER,  // 5.0.2 — C21 reuse, no other change needed
  [PAGE_SCAM_KIND.SHARED_CODE]:     PROTECTION_KEY.BLOCK_SHARED_CODES     // 5.1.3 — never-share codes
});

const _opening = new Set();                       // tabIds whose warning is being opened (released in finally)

// 5.1.3: the protection behind a content-script kind (null when unknown) — also used by background.js for the tamper finding.
export function protectionForKind(kind) {
  return Object.prototype.hasOwnProperty.call(PROTECTION_FOR_KIND, kind) ? PROTECTION_FOR_KIND[kind] : null;
}

export async function onPageScamBlocked(state, kind, sender) {
  const key = protectionForKind(kind);
  if (!key) throw new Error("unknown page-scam kind");
  return openPageScamWarning(state, kind, key, sender);
}

// Opens the warning page for `kind` in the sender's tab when protection `key` is active at the top page's level.
export async function openPageScamWarning(state, kind, key, sender) {
  const tab = sender && sender.tab;
  if (!tab || !Number.isInteger(tab.id) || _opening.has(tab.id)) return false;
  const page = parseHttpUrl(tab.url || "");
  if (!page) return false;                                                   // already on the warning / a browser page
  if (!isProtectionActive(state, key, effectiveLevel(state, page.host))) return false;
  if (isAllowedFor(state, ALLOW_CATEGORY_OF_TAB[tabOf(PROTECTION_BY_KEY[key])], page.host)) return false;   // 5.1.3: allow list
  _opening.add(tab.id);
  try {
    if (await isAllowedOnce(tab.id, registeredDomain(page.host))) return false;   // "Continue once": block, no dialog
    await chrome.tabs.update(tab.id, { url: warningUrlFor(tab.url, kind) });
    return true;
  } catch (e) {
    console.warn(LOG_PREFIX, "page-scam warning failed:", e);               // tab closed meanwhile is the usual cause
    return false;
  } finally {
    _opening.delete(tab.id);
  }
}
