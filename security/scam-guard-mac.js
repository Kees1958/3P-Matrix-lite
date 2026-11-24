/*
 * scam-guard-mac.js — part of blockClickFix (Scam protection), macOS only (3P Matrix 5.1.5, owner decision 2026-11-24).
 *
 * A link to applescript:// opens Script Editor with a script already filled in (a macOS variant of ClickFix). A
 * click on such a link, or window.open() of one, is blocked and reported like any ClickFix block: CLICKFIX_BLOCKED_EVENT
 * on the document → security/scam-guard-bridge.js → the red warning page. Not covered: a page that sets location.href
 * to such an address itself (not hookable from a page script).
 *
 * Registered ONLY on macOS: core/apply-manager.js asks Chrome once for the operating system
 * (chrome.runtime.getPlatformInfo) and core/script-builder.js adds this file to Scam protection's registrations there
 * (data/protections.js macScripts). On Windows, Linux and ChromeOS it never reaches a page — no click listener at all.
 * (Until 5.1.3 this was section 4 of the ClickFix part of security/scam-guard-page.js, on every system.)
 *
 * Captured builtins (C35); Proxy handler with `__proto__: null`. World: MAIN, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies: MAIN-world scripts cannot import. LOG_PREFIX = data/constants.js;
    // CLICKFIX_BLOCKED_EVENT = the same constant in security/scam-guard-page.js and security/scam-guard-bridge.js.
    // Kept equal by tools/check-shipped-terms.mjs.
    const LOG_PREFIX = '[3PMCF]';
    const CLICKFIX_BLOCKED_EVENT = '3pmcf-clickfix-blocked';
    const APPLESCRIPT_SCHEME = 'applescript:';
    const LINK_SELECTOR = 'a[href]';
    try {
        // ── Captured builtins (C35) ──────────────────────────────────────
        const reflectApply = Reflect.apply;
        const strSlice = String.prototype.slice;
        const strToLowerCase = String.prototype.toLowerCase;
        const strTrimStart = String.prototype.trimStart;
        const toStr = String;
        const logWarn = console.warn.bind(console);
        const closest = Element.prototype.closest;
        const getAttr = Element.prototype.getAttribute;
        const dispatch = EventTarget.prototype.dispatchEvent;
        const addListener = EventTarget.prototype.addEventListener;
        const CustomEventCtor = CustomEvent;
        const ElementCtor = Element;
        const doc = document;

        let warned = false;                  // guard: the warning is requested once per page

        function isAppleScriptUrl(u) {
            const s = reflectApply(strToLowerCase, reflectApply(strTrimStart, toStr(u ?? ''), []), []);
            return reflectApply(strSlice, s, [ 0, APPLESCRIPT_SCHEME.length ]) === APPLESCRIPT_SCHEME;
        }
        function blocked(via) {
            logWarn(`${LOG_PREFIX} blocked an applescript: link (${via}) — it would open Script Editor with a script filled in.`);
            if ( warned ) { return; }
            warned = true;
            try { reflectApply(dispatch, doc, [ new CustomEventCtor(CLICKFIX_BLOCKED_EVENT) ]); }
            catch { /* the block stands; only the warning is lost */ }
        }

        // On window, capture phase, at document_start — before any page listener (C47).
        reflectApply(addListener, window, [ 'click', ev => {
            const t = ev.target;
            if ( !(t instanceof ElementCtor) ) { return; }
            const a = reflectApply(closest, t, [ LINK_SELECTOR ]);
            if ( a === null || !isAppleScriptUrl(reflectApply(getAttr, a, [ 'href' ])) ) { return; }
            blocked('link click');
            ev.preventDefault();
            ev.stopImmediatePropagation();
        }, true ]);
        if ( typeof window.open === 'function' ) {
            window.open = new Proxy(window.open, {
                __proto__: null,
                apply(target, thisArg, args) {
                    if ( isAppleScriptUrl(args[0]) ) { blocked('window.open'); return null; }
                    return reflectApply(target, thisArg, args);
                },
            });
        }
    } catch {
        // Never break the page: a protection that throws at document_start would be worse than one that is absent.
    }
})();
