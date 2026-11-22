/*
 * sec-alertbuster.js — Security scriptlet: blockDialogSpam toggle
 * (3P Matrix blockDialogSpam runs this file together with sec-dialogbuster.js)
 *
 * Silences window.alert() — used by tech-support fraud sites to lock the
 * browser in an endless dialog loop. Proxies alert to console.info and
 * spoofs .toString() so native-code detection checks still pass.
 * Source: originally scriptlets.js alertBuster (uBO-lite resources).
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 * World:         MAIN, all frames, document_start
 */
'use strict';
(function(){'use strict';
            // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
            // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
            const LOG_PREFIX = '[3PMCF]';
            // ── Captured builtins (audit 9.7.5, C35) ────────────────────────────────
            // Taken at injection (document_start, before any page script), so page
            // code that later replaces a builtin can neither switch this protection
            // off nor be handed the unprotected original. Handlers use
            // `__proto__: null` — Proxy looks traps up through the handler's
            // prototype chain, so an ordinary `{}` handler lets a page define
            // Object.prototype.get/apply and receive `target` itself.
            const reflectGet = Reflect.get;
            const logInfo = console.info.bind(console);
            const nativeAlert = window.alert;
            // Bound once, here — previously built at call time through
            // target.toString.bind, both page-replaceable, and a replaced
            // bind would have been handed the original alert as `this`.
            const nativeToString = nativeAlert.toString.bind(nativeAlert);
            window.alert = new Proxy(nativeAlert, {
                __proto__: null,
                apply: function(target, thisArg, args) {
                    logInfo(LOG_PREFIX + ' alert blocked:', args[0]);
                },
                get(target, prop) {
                    if ( prop === 'toString' ) { return nativeToString; }
                    return reflectGet(target, prop);
                },
            });
        })();
