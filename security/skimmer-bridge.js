/*
 * skimmer-bridge.js — warnPaymentSkimmer (3P Matrix 5.0.2), ISOLATED-world half.
 *
 * The MAIN-world scriptlet security/sec-skimmer-warn.js detects the payment-skimmer signal but cannot talk to
 * the service worker; on its first warning on a page it dispatches SKIMMER_BLOCKED_EVENT on the document. This
 * bridge forwards that to the service worker, which opens the red skimmer warning for the tab
 * (core/page-scam-guard.js) — exactly the same shape as security/clickfix-bridge.js.
 *
 * Trust: the event carries no data, and the service worker takes the page from the message SENDER (C28) — a
 * page that fires the event itself can only send ITSELF to a warning about itself. A frame inside a page can do
 * the same to its top page; that is accepted (a skimmer frame on a compromised site is exactly the case to warn
 * about).
 * Cost: one listener, nothing until the event. Guard: forwarded once per page (`sent`); a failed message is
 * logged (the detection itself already happened and was logged by the MAIN-world half).
 * Listener (5.0.7, C47): on WINDOW, capture phase, registered at document_start — before any page script. The
 * event is dispatched on the document, so its path starts at window; a page that adds its own window-capture
 * listener later cannot stop it before this one runs. (On document, as before 5.0.7, a page could silence the
 * warning with one stopImmediatePropagation — proven in tools/e2e-page-protections.mjs.)
 * World: ISOLATED, all frames, document_start. Classic script.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies (content scripts cannot import), kept equal to their sources
    // by check-shipped-terms.mjs: LOG_PREFIX (data/constants.js), MSG_* (data/message-types.js),
    // SKIMMER_BLOCKED_EVENT (security/sec-skimmer-warn.js, SHARED_SCRIPT_CONSTS).
    const LOG_PREFIX = '[3PMCF]';
    const MSG_PAGE_SCAM_BLOCKED = 'PAGE_SCAM_BLOCKED';
    const SKIMMER_BLOCKED_EVENT = '3pmcf-skimmer-blocked';
    const PAGE_SCAM_PAYMENT_SKIMMER = 'paymentSkimmer';   // data/page-scam-reasons.js PAGE_SCAM_KIND.PAYMENT_SKIMMER

    let sent = false;                                    // guard: one warning request per page

    window.addEventListener(SKIMMER_BLOCKED_EVENT, () => {
        if (sent) return;
        sent = true;
        chrome.runtime.sendMessage({ type: MSG_PAGE_SCAM_BLOCKED, kind: PAGE_SCAM_PAYMENT_SKIMMER })
            .catch((err) => console.warn(LOG_PREFIX, 'payment-skimmer warning could not be opened', err));
    }, true);
})();
