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
