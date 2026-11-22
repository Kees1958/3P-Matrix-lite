/*
 * sec-adult-noeval.js — Security scriptlet: blockAdultNoEval toggle
 *
 * Strict eval() blocker for the adult-site match list in compiled-filters.js
 * (ADULT_SITE_MATCHES). Also blocks setTimeout()/setInterval() when called
 * with a STRING as the first argument — the browser evaluates that string
 * the same way eval() would, so it is the same code-execution vector under
 * a different name. A function-argument call (the normal, non-string form)
 * is untouched.
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
    // ── Captured builtins (audit 9.7.5, C35) ────────────────────────────────
    // Taken at injection (document_start, before any page script). A page
    // that replaced Function.prototype.apply would previously have been
    // handed the native setTimeout/setInterval as `this` — and could then
    // run string handlers through them, bypassing this block.
    const reflectApply = Reflect.apply;
    const logInfo = console.info.bind(console);
    const nativeEval = window.eval;
    window.eval = function() {
        logInfo(LOG_PREFIX + ' strict eval blocked');
        return undefined;
    };
    window.eval.toString = nativeEval.toString.bind(nativeEval);

    function blockStringTimer(native, label) {
        function wrapped(handler) {
            if ( typeof handler === 'string' ) {
                logInfo(LOG_PREFIX + ' strict eval blocked (' + label + ' string handler)');
                return 0;
            }
            return reflectApply(native, this, arguments);
        }
        wrapped.toString = native.toString.bind(native);
        return wrapped;
    }
    window.setTimeout = blockStringTimer(window.setTimeout, 'setTimeout');
    window.setInterval = blockStringTimer(window.setInterval, 'setInterval');
})();
