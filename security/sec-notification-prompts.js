/*
 * sec-notification-prompts.js — Security scriptlet: blockNotificationPrompts toggle (3P Matrix 4.6.0)
 * "Block notification prompts that appear without a click" — outside safer regions, from level 3.
 *
 * Fake "click Allow to continue" pages ask for notification permission the moment they load; one click and the
 * desktop keeps showing fake virus alerts and prize messages. Real sites usually ask after the user presses a
 * bell or "turn on notifications" button. So a request made WITHOUT a click (no transient user activation) is
 * answered without showing Chrome's prompt:
 *   Notification.requestPermission()  → "default" (also to the legacy callback), as if the user dismissed it
 *   PushManager.prototype.subscribe() → rejected with NotAllowedError
 * With a click, both behave exactly as before. Chrome is testing the same rule ("gesture-gated prompts",
 * Canary 2026); this applies it now.
 *
 * Captured builtins (C35); Proxy handlers with `__proto__: null`. World: MAIN, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── LOG_PREFIX: copy of data/constants.js (MAIN world cannot import); kept equal by
    // tools/check-shipped-terms.mjs.
    const LOG_PREFIX = '[3PMCF]';
    const PERMISSION_DEFAULT = 'default';                        // "not decided" — what a dismissed prompt returns
    const NOT_ALLOWED = 'NotAllowedError';

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    const logInfo = console.info.bind(console);
    const { apply, getOwnPropertyDescriptor, getPrototypeOf } = Reflect;
    const PromiseResolve = Promise.resolve.bind(Promise);
    const PromiseReject = Promise.reject.bind(Promise);
    const DOMExceptionCtor = DOMException;
    const userActivation = navigator.userActivation || null;
    const activationGet = userActivation ? getOwnPropertyDescriptor(getPrototypeOf(userActivation), 'isActive').get : null;
    function clickedNow() { return activationGet ? !!apply(activationGet, userActivation, []) : true; }  // no API: do not interfere

    if (typeof Notification === 'function' && typeof Notification.requestPermission === 'function') {
        Notification.requestPermission = new Proxy(Notification.requestPermission, { __proto__: null, apply: function(target, self, args) {
            if (clickedNow()) return apply(target, self, args);
            logInfo(LOG_PREFIX + ' blocked a notification prompt without a click');
            if (typeof args[0] === 'function') { try { args[0](PERMISSION_DEFAULT); } catch { /* page callback threw */ } }
            return PromiseResolve(PERMISSION_DEFAULT);
        } });
    }
    if (typeof PushManager === 'function' && typeof PushManager.prototype.subscribe === 'function') {
        PushManager.prototype.subscribe = new Proxy(PushManager.prototype.subscribe, { __proto__: null, apply: function(target, self, args) {
            if (clickedNow()) return apply(target, self, args);
            logInfo(LOG_PREFIX + ' blocked a push subscription without a click');
            return PromiseReject(new DOMExceptionCtor('push subscription without a click blocked by 3P Matrix', NOT_ALLOWED));
        } });
    }
})();
