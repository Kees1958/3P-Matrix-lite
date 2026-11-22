/*
 * sec-protocol-handlers.js — Security scriptlet: blockProtocolHandlers toggle
 *
 * Blocks a website from registering itself as the handler for a link scheme
 * (mailto:, web+something, ...): navigator.registerProtocolHandler() becomes a
 * silent no-op, so the browser's "use this site to open mailto links" offer is
 * never shown. Opening such links with an already-registered handler, and
 * navigator.unregisterProtocolHandler(), are not touched.
 *
 * Worry-free-gated, tier `extra` ("Very low website breakage risk" group):
 * active only during a running Worry-free session with the "extra" box ticked
 * and its own checkbox not unticked (worryFreeGatedOptOut).
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
    // Same approach as sec-battery.js: take what is needed at injection, and
    // give the Proxy a `__proto__: null` handler so a page cannot intercept the
    // trap lookup through Object.prototype.
    const logInfo = console.info.bind(console);
    const navigatorProto = Object.getPrototypeOf(navigator);
    if ( typeof navigatorProto.registerProtocolHandler === 'function' ) {
        navigatorProto.registerProtocolHandler = new Proxy(navigatorProto.registerProtocolHandler, { __proto__: null, apply: function() {
            logInfo(LOG_PREFIX + ' blocked navigator.registerProtocolHandler');
            return undefined;
        } });
    }
})();
