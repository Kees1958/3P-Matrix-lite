/*
 * fake-window-guard.js — blockFakeSignInWindow (3P Matrix 4.7.0), ISOLATED-world only.
 * "Warn about a fake sign-in window drawn on a page" — Browser-in-the-Browser: a page draws a fake OS/browser
 * chrome (title bar, address bar showing "accounts.google.com") around an ordinary login form. There is no real
 * second window and no real address bar — the drawn text can say anything.
 *
 * Own file (not shared with security/password-form-guard.js, warnPasswordForms): two protections sharing one content
 * script would make core/script-builder.js merge their registrations whenever both are active, which is fine for
 * injection but defeats tools/test-perf-guards.mjs's per-file scope invariant — kept separate on purpose.
 *
 * Check (cheap, runs only at the moment a password field is focused, no MutationObserver watching the page):
 *   1. From the focused field, walk up to MAX_ANCESTOR_WALK ancestors for the nearest one the PAGE styled
 *      position:fixed/absolute (a drawn "window"; <html>/<body> never count).
 *   2. Read that one ancestor's own text (not the whole page) for a URL-shaped token (SHOWN_URL_RE) — the drawn
 *      "address bar".
 *   3. Send ONLY that token to the service worker (core/password-form.js fakeWindowDecision) — it matches it
 *      against known sign-in providers and decides there, so no provider list is duplicated in a classic script.
 *      Nothing is sent when no drawn window or no URL-shaped text is found (the overwhelmingly common case).
 * Accepted false positive: a real page with a styled box around its OWN login form that also shows another
 * provider's name/logo nearby. Accepted false negative: a shown name/brand instead of a URL-shaped address.
 *
 * On a hit the SERVICE WORKER opens the red warning page in this tab (5.0.6, core/page-scam-guard.js — kind
 * fakeSignInWindow). Until 5.0.5 this file drew its own in-page dialog; a page can remove or hide anything drawn
 * into its own DOM, and a phishing page is exactly the page that wants to (C47). The warning page is an extension
 * page the site cannot touch, with the same Go back / Continue once / Trust buttons as the other page-scam warnings.
 * Listener: `focusin` on WINDOW, capture phase, registered at document_start — the earliest point in the event's
 * path, so a page's own capture listener cannot stop it first (C47).
 * Cost: nothing until a password field is focused; then one bounded DOM walk, and only on a hit, one message
 * round-trip. Fail-silent guard: an unreachable service worker means no warning, never a broken page.
 * World: ISOLATED, all frames, document_start. Classic script (content scripts cannot import).
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies of shared values (this script cannot import); kept equal to their sources
    // by tools/check-shipped-terms.mjs: LOG_PREFIX (data/constants.js), MSG_* (data/message-types.js).
    const LOG_PREFIX = '[3PMCF]';
    const MSG_CHECK_FAKE_WINDOW = 'CHECK_FAKE_WINDOW';
    const MAX_ANCESTOR_WALK = 8;                        // bounds the walk from the field to <html>
    const MAX_WINDOW_TEXT_CHARS = 400;                  // the drawn chrome's own text is short (title bar + address)
    const SHOWN_URL_RE = /\b(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/i;
    const DRAWN_POSITIONS = Object.freeze(['fixed', 'absolute']);
    const checkedBoxes = new WeakSet();                 // guard: ask about the same drawn box only once per page

    function drawnWindowAncestorOf(field) {
        let el = field.parentElement;
        for (let i = 0; i < MAX_ANCESTOR_WALK && el; i++, el = el.parentElement) {
            if (el === document.documentElement || el === document.body) break;
            let position = '';
            try { position = window.getComputedStyle(el).position; } catch { continue; }
            if (DRAWN_POSITIONS.includes(position)) return el;
        }
        return null;
    }

    function shownUrlTextOf(box) {
        let text = '';
        try { text = String(box.textContent || ''); } catch { return ''; }
        if (text.length > MAX_WINDOW_TEXT_CHARS) text = text.slice(0, MAX_WINDOW_TEXT_CHARS);
        const m = SHOWN_URL_RE.exec(text);
        return m ? m[0] : '';
    }

    async function checkFakeWindow(field) {
        const box = drawnWindowAncestorOf(field);
        if (!box || checkedBoxes.has(box)) return;
        const shownText = shownUrlTextOf(box);
        if (!shownText) return;
        checkedBoxes.add(box);
        // The service worker decides and, on a hit, opens the warning page in this tab itself.
        try { await chrome.runtime.sendMessage({ type: MSG_CHECK_FAKE_WINDOW, shownText }); }
        catch (err) { console.warn(LOG_PREFIX, 'fake-window check unavailable', err); }   // fail silent
    }

    window.addEventListener('focusin', (e) => {
        const field = e.target;
        if (field instanceof HTMLInputElement && field.type === 'password') checkFakeWindow(field).catch(() => {});
    }, true);
})();
