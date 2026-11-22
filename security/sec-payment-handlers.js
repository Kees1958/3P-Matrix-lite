/*
 * sec-payment-handlers.js — Security scriptlet: blockPaymentHandlers toggle
 *
 * Blocks a website from installing itself as a payment handler: the
 * `registration.paymentManager` API (PaymentManager / PaymentInstruments) of a
 * service worker registration is removed, so a page that feature-detects it
 * sees "not supported". Paying through PaymentRequest (Google Pay, Apple Pay,
 * card forms) is NOT touched — only the installing side is.
 *
 * Plain on/off ("Safe privacy and security enhancements" group, default on):
 * no Worry-free relationship and no tier — same shape as sec-pings.js. A
 * scriptlet, not a header rule, so the toolbar badge count stays accurate
 * (an all-sites modifyHeaders rule would count on the badge like a real block).
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 * World:         MAIN, all frames, document_start
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    // Taken at injection (document_start, before any page script). Proxy
    // handlers use `__proto__: null` so a page cannot intercept the trap
    // lookup through Object.prototype.
    const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const defineProperty = Object.defineProperty;
    const deleteProperty = Reflect.deleteProperty;
    const logInfo = console.info.bind(console);

    const registrationProto = window.ServiceWorkerRegistration?.prototype;
    if ( registrationProto === undefined ) { return; }
    const descriptor = getOwnPropertyDescriptor(registrationProto, 'paymentManager');
    if ( descriptor === undefined ) { return; }

    // Preferred: delete the property, so `'paymentManager' in registration`
    // is false and feature detection fails cleanly.
    if ( deleteProperty(registrationProto, 'paymentManager') ) {
        logInfo(LOG_PREFIX + ' removed registration.paymentManager (payment handler install blocked)');
        return;
    }
    // Fallback (non-configurable property): a getter that returns nothing.
    if ( typeof descriptor.get === 'function' ) {
        defineProperty(registrationProto, 'paymentManager', {
            configurable: descriptor.configurable,
            enumerable: descriptor.enumerable,
            get: new Proxy(descriptor.get, { __proto__: null, apply: function() {
                logInfo(LOG_PREFIX + ' blocked registration.paymentManager read');
                return undefined;
            } }),
        });
    }
})();
