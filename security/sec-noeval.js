/*
 * sec-noeval.js — Security scriptlet: blockObfuscatedEval toggle
 *
 * Blocks eval() calls whose payload matches the *shape* of known
 * obfuscation techniques (Dean Edwards packer bootstrap, a real
 * obfuscator.io-style density of `_0x..` identifiers, a genuinely
 * long base64 blob passed to atob(), or a real char-code-encoded
 * string passed to String.fromCharCode()) — not merely the presence
 * of a function name. Clean payloads (webpack HMR, REPL, Monaco, and
 * ordinary pages that happen to call atob()/fromCharCode() once for
 * a short, unrelated value) pass through unaffected.
 *
 * v6.1.3 rewrite: the earlier version matched on bare substrings
 * (`atob(`, `String.fromCharCode(`, one `_0x..` identifier), so any
 * eval'd bundle containing a single, ordinary, non-obfuscation call
 * to either function anywhere in its text was blocked in full —
 * silently discarding the entire script, not just the "suspicious"
 * part. Confirmed false positive: youtube.com. Thresholds below
 * require the pattern to look like real obfuscation (a long encoded
 * literal, or several renamed identifiers), not just a function name.
 *
 * Note: Cloudflare bot-challenge pages use packed eval — add to the
 * 3P Matrix allow list (Options) if affected, or untick the protection.
 * Converted from AG corelibs prevent-eval-if to a self-contained IIFE
 * because that function body contains regex literals Brave rejects.
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 *
 * Architecture note: files under js/security/ run in the page (content
 * script) execution context, one independent scriptlet per toggle. They
 * are outside the five-tier ui/workflow/core/util/data dependency model
 * — see ARCHITECTURE.md.
 * World:         MAIN, all frames, document_start
 *
 * Uses const/let, not var: this whole file's body sits inside the
 * (function(){...})() IIFE below, so each re-injection gets a fresh
 * function scope — no top-level redeclaration hazard to guard about.
 * The one cross-injection resource that *does* need a guard is the
 * global window.eval patch itself (see init guard below): a MAIN-world
 * content script can in principle run more than once in the same
 * realm (e.g. a same-document navigation), and wrapping an
 * already-wrapped eval a second time would stack proxies and leak the
 * previous native-eval closure for the life of the page.
 */
'use strict';
(function(){'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

            // ── init guard: install exactly once per realm ──────────────────
            // Resource being guarded: the single global window.eval binding.
            // If already installed (re-injection into the same realm), skip
            // re-wrapping rather than stacking a second proxy over the first.
            if ( window.eval && window.eval.__uBolNoEvalInstalled === true ) {
                return;
            }

            // ── obfuscation-signal thresholds — single source, tune here only ──
            // Minimum length of a base64 literal passed to atob() before it's
            // treated as a real encoded payload rather than a short, ordinary
            // token/config value.
            // ── Captured builtins (audit 9.7.5, C35) ────────────────────────
            // Taken at injection (document_start, before any page script), so
            // page code that later replaces a builtin can neither switch this
            // protection off (e.g. RegExp.prototype.test / String.prototype.
            // match returning "no match" lets obfuscated code through) nor be
            // handed the native eval (a replaced Function.prototype.call
            // would receive it as `this`).
            const reflectApply = Reflect.apply;
            // Native exec called directly, never test()/match(): test()
            // looks up `this.exec`, and match() goes through the
            // replaceable Symbol.match and `flags` lookups — either would
            // let a page make every pattern report "no match".
            const regexExec = RegExp.prototype.exec;
            const toStr = String;
            const logInfo = console.info.bind(console);

            const OBFUSC_MIN_B64_LEN = 40;
            // Minimum count of numeric arguments to String.fromCharCode()
            // before it's treated as a real encoded string rather than one or
            // two ordinary characters (e.g. a single accented letter).
            const OBFUSC_MIN_CHARCODE_ARGS = 10;
            // Minimum count of `_0x..`-style identifiers before it's treated
            // as real obfuscator.io renaming rather than one coincidental
            // hex-looking variable name.
            const OBFUSC_MIN_HEX_IDENTS = 3;

            // ── obfuscation-shape patterns ───────────────────────────────────
            const _packerSig   = /eval\(function\(p,a,c,k,e,d/;
            const _hexIdentsRe = /_0x[0-9a-f]{4,6}/g;
            const _b64AtobRe   = new RegExp(
                'atob\\(\\s*[\'"][A-Za-z0-9+/=]{' + OBFUSC_MIN_B64_LEN + ',}[\'"]\\s*\\)'
            );
            const _charCodeRe  = new RegExp(
                'String\\.fromCharCode\\(\\s*(?:\\d+\\s*,\\s*){' +
                (OBFUSC_MIN_CHARCODE_ARGS - 1) + ',}\\d+\\s*\\)'
            );

            // Counts matches of a /g pattern with the captured native exec
            // (it honours the regex's own global flag internally, not the
            // replaceable `flags` getter). Stops early at the threshold —
            // the caller only needs to know whether it was reached.
            function countMatches(re, s) {
                re.lastIndex = 0;
                let n = 0;
                while ( n < OBFUSC_MIN_HEX_IDENTS && reflectApply(regexExec, re, [ s ]) !== null ) { n += 1; }
                re.lastIndex = 0;
                return n;
            }

            // Returns a short reason string when payload looks obfuscated,
            // or null when it should be allowed through unmodified.
            function detectObfuscation(payload) {
                const s = toStr(payload);
                if ( reflectApply(regexExec, _packerSig, [ s ]) !== null ) { return 'packer'; }
                if ( reflectApply(regexExec, _b64AtobRe, [ s ]) !== null ) { return 'base64-blob'; }
                if ( reflectApply(regexExec, _charCodeRe, [ s ]) !== null ) { return 'char-code-array'; }
                if ( countMatches(_hexIdentsRe, s) >= OBFUSC_MIN_HEX_IDENTS ) {
                    return 'hex-identifiers';
                }
                return null;
            }

            const _nativeEval = window.eval;
            window.eval = function(payload) {
                const reason = detectObfuscation(payload);
                if ( reason !== null ) {
                    logInfo(LOG_PREFIX + ' blocked obfuscated eval (' + reason + ')');
                    return;
                }
                return reflectApply(_nativeEval, window, [ payload ]);
            };
            window.eval.toString = _nativeEval.toString.bind(_nativeEval);
            window.eval.__uBolNoEvalInstalled = true;
        })();
