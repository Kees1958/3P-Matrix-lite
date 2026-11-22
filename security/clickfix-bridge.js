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

    let sent = false;                                    // guard: one warning request per page

    window.addEventListener(CLICKFIX_BLOCKED_EVENT, () => {
        if (sent) return;
        sent = true;
        chrome.runtime.sendMessage({ type: MSG_PAGE_SCAM_BLOCKED, kind: PAGE_SCAM_CLICK_FIX })
            .catch((err) => console.warn(LOG_PREFIX, 'ClickFix warning could not be opened', err));
    }, true);
})();
