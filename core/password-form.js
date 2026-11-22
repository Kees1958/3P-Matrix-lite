// ── core/password-form.js ─────────────────────────────────────────────────────
// 4.6.0 — protection "Warn when a password form sends to another site" (warnPasswordForms). Pure decision, no
// Chrome API calls: the ISOLATED-world script security/password-form-guard.js asks the service worker when a form
// WITH a password field is submitted, and shows its in-page warning when this says so.
//
// Public interface:
//   passwordFormDecision(state, pageUrl, actionUrl) → { warn: boolean, destHost: string }
//     pageUrl   — the page the form is on; the service worker takes it from the message SENDER (C28), never from
//                 the message itself
//     actionUrl — where the form sends to (form.action / the submitter's formaction, resolved by the browser)
//
// No warning when: the page is not http(s); the protection is not active at the page's level (unticked, level 1,
// allow list); the destination is not http(s) (javascript:, mailto: …: nothing is posted to a server); the
// destination is the SAME site; it is a built-in sign-in or payment service (Google, Microsoft, DigiD, banks …,
// data/builtin-domains.js); or the user trusts the destination site (allow list = locked at level 1).
// Why not "warn when the page lacks CSP form-action 'self'": only ~22% of pages send any CSP and form-action is
// rare among them — it would warn on most legitimate sites (Web Almanac 2025; discussed with the user 2026-11-06).
//
// 4.7.0 — fakeWindowDecision(state, pageUrl, shownText) → { warn, shownHost }  (blockFakeSignInWindow,
//   Browser-in-the-Browser): the ISOLATED-world script found a drawn "window" around a password field whose own
//   text contains a URL-shaped token (`shownText`, the FULL matched token — the content script does no provider
//   matching itself, so the list below is never duplicated outside this module). Warns when that token names a
//   known sign-in provider (BUILTIN_SIGN_IN) that is NOT the real page's own site — the provider's own real sign-in
//   page legitimately shows its own name. No level/allow-list exemption: a drawn fake window is never legitimate
//   on an allow-listed site either, and the allow list is for THIRD-PARTY content, not the first-party page itself.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL } from "../data/constants.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { BUILTIN_SIGN_IN, BUILTIN_PAYMENT } from "../data/builtin-domains.js";
import { effectiveLevel, isProtectionActive, lockedLevelOf } from "./policy.js";
import { parseHttpUrl, registeredDomain, isInDomainList } from "../util/domain.js";

const NO_WARNING = Object.freeze({ warn: false, destHost: "" });
const NO_FAKE_WINDOW = Object.freeze({ warn: false, shownHost: "" });
const TRUSTED_DESTINATIONS = Object.freeze([...BUILTIN_SIGN_IN, ...BUILTIN_PAYMENT]);
const SHOWN_TEXT_MAX = 400;          // mirrors MAX_WINDOW_TEXT_CHARS in security/password-form-guard.js

export function passwordFormDecision(state, pageUrl, actionUrl) {
  const page = parseHttpUrl(String(pageUrl || ""));
  if (!page) return NO_WARNING;
  if (!isProtectionActive(state, PROTECTION_KEY.WARN_PASSWORD_FORMS, effectiveLevel(state, page.host))) return NO_WARNING;
  const dest = parseHttpUrl(String(actionUrl || ""));
  if (!dest) return NO_WARNING;
  if (registeredDomain(dest.host) === registeredDomain(page.host)) return NO_WARNING;
  if (isInDomainList(dest.host, TRUSTED_DESTINATIONS)) return NO_WARNING;
  if (lockedLevelOf(state, dest.host) === LEVEL.ALLOW_ALL) return NO_WARNING;
  return { warn: true, destHost: dest.host };
}

export function fakeWindowDecision(state, pageUrl, shownText) {
  const page = parseHttpUrl(String(pageUrl || ""));
  const text = String(shownText || "").slice(0, SHOWN_TEXT_MAX).toLowerCase();
  if (!page || !text) return NO_FAKE_WINDOW;
  if (!isProtectionActive(state, PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW, effectiveLevel(state, page.host))) return NO_FAKE_WINDOW;
  const shown = BUILTIN_SIGN_IN.find((host) => isInDomainList(text.replace(/^https?:\/\//, ""), [host]) || text.includes(host));
  if (!shown || registeredDomain(shown) === registeredDomain(page.host)) return NO_FAKE_WINDOW;
  return { warn: true, shownHost: shown };
}
