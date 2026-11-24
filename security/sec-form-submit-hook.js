/*
 * sec-form-submit-hook.js — Security scriptlet: warnPasswordForms toggle (3P Matrix 4.6.0), MAIN-world half
 * "Warn when a password form sends to another site".
 *
 * A script can send a form with form.submit(), which fires NO submit event — the ISOLATED-world guard
 * (security/password-form-guard.js) would never see it. This hook catches form.submit() on a form WITH a password
 * field and hands it to the guard as a PASSWORD_SUBMIT_EVENT on the form instead of submitting; the guard checks
 * the destination and submits itself (its own, unhooked form.submit) when that is fine or the user says Continue.
 * Forms without a password field submit untouched. 5.1.5: so do password forms whose action is the page's own host
 * (nothing to check there — see security/password-form-guard.js). Cost: one selector query per submit() call.
 *
 * Captured builtins (C35); Proxy handler with `__proto__: null`. World: MAIN, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies: MAIN-world scripts cannot import. LOG_PREFIX = data/constants.js;
    // PASSWORD_SUBMIT_EVENT = the same constant in security/password-form-guard.js. Both kept equal by
    // tools/check-shipped-terms.mjs.
    const LOG_PREFIX = '[3PMCF]';
    const PASSWORD_SUBMIT_EVENT = '3pmcf-password-submit';
    const PASSWORD_SELECTOR = 'input[type="password"]';

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    const logInfo = console.info.bind(console);
    const { apply } = Reflect;
    const formQuery = Element.prototype.querySelector;
    const dispatch = EventTarget.prototype.dispatchEvent;
    const CustomEventCtor = CustomEvent;
    const formActionGet = Reflect.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'action').get;   // 5.1.5
    const URLCtor = URL;
    const urlHostGet = Reflect.getOwnPropertyDescriptor(URL.prototype, 'host').get;
    const locationObj = location;                       // unforgeable: a page cannot redefine its properties
    function sameHost(form) {
        try { return apply(urlHostGet, new URLCtor(apply(formActionGet, form, []), locationObj.href), []) === locationObj.host; }
        catch { return false; }
    }

    HTMLFormElement.prototype.submit = new Proxy(HTMLFormElement.prototype.submit, { __proto__: null, apply: function(target, self, args) {
        let hasPassword = false;
        try { hasPassword = !!apply(formQuery, self, [PASSWORD_SELECTOR]); } catch { /* not a form element */ }
        if (!hasPassword || sameHost(self)) return apply(target, self, args);     // 5.1.5: own host — untouched
        logInfo(LOG_PREFIX + ' password form submit() handed to the password-form check');
        apply(dispatch, self, [new CustomEventCtor(PASSWORD_SUBMIT_EVENT)]);
        return undefined;
    } });
})();
