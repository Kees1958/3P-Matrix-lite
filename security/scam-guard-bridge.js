/*
 * scam-guard-bridge.js — Scam protection, ISOLATED-world bundle (3P Matrix 5.1.3, owner decision 2026-11-24).
 *
 * The parts that must message the service worker or read pasted text without the page interfering:
 *   ClickFix bridge (forwards the MAIN part's block) · ConsentFix (pasting a sign-in return address) ·
 *   never-share codes (5.1.3, new: pasting a one-time/2FA/recovery code into a message box).
 * Each part is in its own closure. The MAIN-world half is security/scam-guard-page.js.
 *
 * Registered by: core/script-builder.js — ISOLATED world, all frames, document_start.
 */

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: clickfix-bridge.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * clickfix-bridge.js — blockClickFix (3P Matrix 4.7.0), ISOLATED-world half.
 *
 * The MAIN-world scriptlet security/sec-clickfix-clipboard.js blocks the clipboard write but cannot talk to the
 * service worker; on its first block in a page it dispatches CLICKFIX_BLOCKED_EVENT on the document. This bridge
 * forwards that to the service worker, which opens the red ClickFix warning for the tab (core/page-scam-guard.js).
 *
 * Trust: the event carries no data, and the service worker takes the page from the message SENDER (C28) — a page
 * that fires the event itself can only send ITSELF to a warning about itself. A frame inside a page can do the
 * same to its top page; that is accepted (a ClickFix frame on a compromised site is exactly the case to warn about).
 * Cost: one listener, nothing until the event. Guard: forwarded once per page (`sent`); a failed message is logged
 * (the block itself already happened). World: ISOLATED, all frames, document_start. Classic script.
 * Listener (5.0.7, C47): on WINDOW, capture phase, registered at document_start — before any page script. The
 * event is dispatched on the document, so its path starts at window; a page that adds its own window-capture
 * listener later cannot stop it before this one runs. (On document, as before 5.0.7, a page could silence the
 * warning with one stopImmediatePropagation — proven in tools/e2e-page-protections.mjs.)
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies (content scripts cannot import), kept equal to their sources by
    // tools/check-shipped-terms.mjs: LOG_PREFIX (data/constants.js), MSG_* (data/message-types.js),
    // CLICKFIX_BLOCKED_EVENT (security/sec-clickfix-clipboard.js), PAGE_SCAM_CLICK_FIX (data/page-scam-reasons.js).
    const LOG_PREFIX = '[3PMCF]';
    const MSG_PAGE_SCAM_BLOCKED = 'PAGE_SCAM_BLOCKED';
    const CLICKFIX_BLOCKED_EVENT = '3pmcf-clickfix-blocked';
    const PAGE_SCAM_CLICK_FIX = 'clickFix';
    // 5.1.5 — a support-scam sign (security/scam-guard-page.js LOCKER_SIGN_EVENT: dialog loop, keyboard lock, fullscreen
    // re-entry) → the red warning page; PAGE_SCAM_BROWSER_LOCKER = data/page-scam-reasons.js PAGE_SCAM_KIND.BROWSER_LOCKER.
    const LOCKER_SIGN_EVENT = '3pmcf-browser-locker';
    const PAGE_SCAM_BROWSER_LOCKER = 'browserLocker';

    let sent = false;                                    // guard: one warning request per page
    let lockerSent = false;                              // 5.1.5: the same for the browser-locker warning

    window.addEventListener(LOCKER_SIGN_EVENT, () => {
        if (lockerSent) return;
        lockerSent = true;
        chrome.runtime.sendMessage({ type: MSG_PAGE_SCAM_BLOCKED, kind: PAGE_SCAM_BROWSER_LOCKER })
            .catch((err) => console.warn(LOG_PREFIX, 'browser-locker warning could not be opened', err));
    }, true);

    window.addEventListener(CLICKFIX_BLOCKED_EVENT, () => {
        if (sent) return;
        sent = true;
        chrome.runtime.sendMessage({ type: MSG_PAGE_SCAM_BLOCKED, kind: PAGE_SCAM_CLICK_FIX })
            .catch((err) => console.warn(LOG_PREFIX, 'ClickFix warning could not be opened', err));
    }, true);
})();

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: consentfix-paste-guard.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * consentfix-paste-guard.js — blockConsentFix (3P Matrix 4.7.0)
 * "Block pasting a sign-in address into a website". ISOLATED world only (a paste event is a DOM event: this world
 * sees it, can cancel it and can message the service worker; no MAIN-world half is needed).
 *
 * ConsentFix (2025–2026): a fake page starts a REAL Microsoft sign-in. Microsoft then sends the browser to a return
 * address such as http://localhost:1605/?code=…&session_state=… ; nothing listens there, so Chrome shows "This site
 * can't be reached". The fake page asks the user to copy that address and paste it back in. The code in it lets
 * the attacker sign in as the user — no password, no MFA, no consent prompt (Azure CLI and other trusted apps).
 * Nothing touches the computer, so ClickFix protection never sees it.
 *
 * Blocked: a paste whose text is ONE address that is either
 *   • a loopback address (localhost, 127.x.x.x, [::1]) carrying code=, access_token= or id_token=, or
 *   • any address carrying both code= and session_state= (Microsoft's sign-in return; covers the variant whose
 *     return page is a real web page instead of localhost).
 * Not blocked: the same paste on a loopback page itself (a developer's own local app), anything else.
 * On a block the paste does not happen, and the service worker opens the red warning (core/page-scam-guard.js;
 * page = sender, C28). Accepted false positive: a developer pasting such an address into a website (issue tracker,
 * OAuth debugger) — "Trust this site" or untick the protection.
 *
 * Cost: nothing until the user pastes; then a length check and two bounded regexes.
 * Guard: the warning is requested once per page (`sent`); a failed message is logged — the paste stays blocked.
 * World: ISOLATED, all frames, document_start. Classic script (content scripts cannot import).
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies (content scripts cannot import), kept equal to their sources by
    // tools/check-shipped-terms.mjs: LOG_PREFIX (data/constants.js), MSG_* (data/message-types.js),
    // PAGE_SCAM_CONSENT_FIX (data/page-scam-reasons.js).
    const LOG_PREFIX = '[3PMCF]';
    const MSG_PAGE_SCAM_BLOCKED = 'PAGE_SCAM_BLOCKED';
    const PAGE_SCAM_CONSENT_FIX = 'consentFix';
    const MAX_PASTE_CHARS = 4096;                      // a sign-in return address is far shorter; longer = not one
    const SINGLE_URL_RE = /^https?:\/\/\S+$/i;
    const LOOPBACK_WITH_TOKEN_RE = /^https?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?\/\S*?[?&#](?:code|access_token|id_token)=/i;
    const SIGN_IN_CODE_RE = /[?&#]code=/i;
    const SIGN_IN_SESSION_RE = /[?&#]session_state=/i;
    const LOOPBACK_HOSTS = Object.freeze(['localhost', '127.0.0.1', '[::1]']);

    let sent = false;                                   // guard: one warning request per page

    function isSignInReturnAddress(raw) {
        if (typeof raw !== 'string' || raw.length > MAX_PASTE_CHARS) return false;
        const text = raw.trim();
        if (!SINGLE_URL_RE.test(text)) return false;
        return LOOPBACK_WITH_TOKEN_RE.test(text) || (SIGN_IN_CODE_RE.test(text) && SIGN_IN_SESSION_RE.test(text));
    }

    if (LOOPBACK_HOSTS.includes(location.hostname)) return;    // a local development page: never interfere

    window.addEventListener('paste', (e) => {
        const dt = e.clipboardData;
        if (!dt || typeof dt.getData !== 'function') return;
        if (!isSignInReturnAddress(dt.getData('text/plain'))) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        console.warn(LOG_PREFIX, 'paste blocked — a sign-in return address (ConsentFix). If this site is legitimate, trust it in 3P Matrix.');
        if (sent) return;
        sent = true;
        chrome.runtime.sendMessage({ type: MSG_PAGE_SCAM_BLOCKED, kind: PAGE_SCAM_CONSENT_FIX })
            .catch((err) => console.warn(LOG_PREFIX, 'ConsentFix warning could not be opened', err));
    }, true);
})();

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: never-share codes (5.1.3, new — blockSharedCodes) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * "Block pasting a one-time or recovery code into a message". The scam: someone on the phone or in a chat asks for
 * "the code we just sent you" — a sign-in, 2FA or recovery code — and the user pastes it into a chat, mail or other
 * message box. A code belongs only in the field that asked for it, which is an INPUT; a message box is a TEXTAREA
 * or an editable element (contenteditable).
 * Blocked: a paste into a textarea / contenteditable whose whole text is ONE code:
 *   • 4–8 digits (spaces or one dash allowed between groups) — one-time, SMS and authenticator codes, or
 *   • 2–4 groups of 4–5 letters/digits separated by - or space, with at least one digit — recovery/backup codes.
 * Not blocked: a paste into an input (a code field), longer text, a local development page.
 * On a block the paste does not happen and the service worker opens the warning (core/page-scam-guard.js, kind
 * sharedCode; page = sender, C28); "Continue anyway" there skips the dialog for this site in this tab (the paste
 * stays blocked — the user can type the text if it really is not a code).
 * Cost: nothing until the user pastes; then a length check and two bounded regexes. Guard: one warning request
 * per page (`sent`). Idea from Sentinel 1.0.3's never-share list (own code; its licence allows no reuse).
 */
(function(){
    'use strict';
    // ── Settings (one place) ── copies (content scripts cannot import), kept equal by tools/check-shipped-terms.mjs
    const LOG_PREFIX = '[3PMCF]';
    const MSG_PAGE_SCAM_BLOCKED = 'PAGE_SCAM_BLOCKED';
    const PAGE_SCAM_SHARED_CODE = 'sharedCode';
    const MAX_CODE_CHARS = 32;                          // a code is short; longer text is a message, not a code
    const DIGIT_CODE_RE = /^\d{2,4}(?:[ -]?\d{2,4}){0,2}$/;
    const DIGIT_COUNT = Object.freeze({ MIN: 4, MAX: 8 });
    const RECOVERY_CODE_RE = /^[a-z0-9]{4,5}(?:[ -][a-z0-9]{4,5}){1,3}$/i;
    const HAS_DIGIT_RE = /\d/;
    const NON_DIGIT_RE = /\D/g;
    const MESSAGE_TAG = 'TEXTAREA';
    const LOOPBACK_HOSTS = Object.freeze(['localhost', '127.0.0.1', '[::1]']);

    let sent = false;                                   // guard: one warning request per page

    function isCode(raw) {
        if (typeof raw !== 'string' || raw.length > MAX_CODE_CHARS) return false;
        const text = raw.trim();
        if (DIGIT_CODE_RE.test(text)) {
            const n = text.replace(NON_DIGIT_RE, '').length;
            return n >= DIGIT_COUNT.MIN && n <= DIGIT_COUNT.MAX;
        }
        return RECOVERY_CODE_RE.test(text) && HAS_DIGIT_RE.test(text);
    }
    function isMessageBox(el) {
        if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
        if (el.tagName === MESSAGE_TAG) return true;
        return !!el.isContentEditable;
    }

    if (LOOPBACK_HOSTS.includes(location.hostname)) return;    // a local development page: never interfere

    window.addEventListener('paste', (e) => {
        if (!isMessageBox(e.target)) return;
        const dt = e.clipboardData;
        if (!dt || typeof dt.getData !== 'function') return;
        if (!isCode(dt.getData('text/plain'))) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        console.warn(LOG_PREFIX, 'paste blocked — a one-time or recovery code into a message box. Never share such a code.');
        if (sent) return;
        sent = true;
        chrome.runtime.sendMessage({ type: MSG_PAGE_SCAM_BLOCKED, kind: PAGE_SCAM_SHARED_CODE })
            .catch((err) => console.warn(LOG_PREFIX, 'shared-code warning could not be opened', err));
    }, true);
})();
