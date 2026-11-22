/*
 * sec-dialogbuster.js — Security scriptlet: blockDialogSpam toggle
 * (3P Matrix blockDialogSpam runs this file together with sec-alertbuster.js)
 *
 * Silences window.confirm() -> false and window.prompt() -> null.
 * Tech-support fraud sites loop these dialogs to lock the browser; false and
 * null are always the safe/cancel outcome for the calling page.
 * Source: originally scriptlets.js dialogBuster (uBO-lite resources).
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 * World:         MAIN, all frames, document_start
 *
 * Uses const/let, not var: this whole file's body sits inside the
 * (function(){...})() IIFE below, so each re-injection gets a fresh
 * function scope — no top-level redeclaration hazard to guard against.
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
            function _makeDialogProxy(native, returnValue, label) {
                // Bound once, at install — see sec-alertbuster.js.
                const nativeToString = native.toString.bind(native);
                return new Proxy(native, {
                    __proto__: null,
                    apply: function(target, thisArg, args) {
                        logInfo(LOG_PREFIX + ' ' + label + ' blocked:', args[0]);
                        return returnValue;
                    },
                    get(target, prop) {
                        if ( prop === 'toString' ) { return nativeToString; }
                        return reflectGet(target, prop);
                    },
                });
            }
            window.confirm = _makeDialogProxy(window.confirm, false,  'confirm');
            window.prompt  = _makeDialogProxy(window.prompt,  null,   'prompt');
        })();
