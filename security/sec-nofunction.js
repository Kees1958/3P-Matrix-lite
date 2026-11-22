/*
 * sec-nofunction.js — Security scriptlet: blockObfuscatedFunction toggle
 *
 * Blocks Function() / new Function() calls whose BODY (the last argument —
 * the one Function() compiles and runs, as opposed to the earlier, named
 * parameters) matches the *shape* of known obfuscation techniques: a real
 * obfuscator.io-style density of `_0x..` identifiers, a genuinely long
 * base64 blob passed to atob() inside that body, or a real char-code-encoded
 * string passed to String.fromCharCode() inside it. Presence of Function()
 * alone is never enough — `new Function("a", "b", "return a + b")` passes
 * through unaffected; it is dynamic code generation, but that alone proves
 * nothing.
 *
 * Detection shape is the single source at util/ObfuscationShape.js
 * (detectObfuscation, OBFUSCATION_CONFIG) — this file carries its own
 * inlined copy because MAIN-world content scripts cannot import ES modules
 * (see sec-noeval.js's own note on this). tools/check-shipped-terms.mjs
 * fails if this copy drifts from that module.
 *
 * Registered by: data/protections.js (script-builder.js reads p.scripts)
 * Injected by:   core/script-builder.js → chrome.scripting.registerContentScripts
 * World:         MAIN, all frames, document_start
 *
 * Architecture note: files under security/ run in the page (content script)
 * execution context, one independent scriptlet per toggle — see ARCHITECTURE.md.
 *
 * Uses const/let, not var: this whole file's body sits inside the IIFE below,
 * so each re-injection gets a fresh function scope. The one cross-injection
 * resource that DOES need a guard is the global window.Function binding
 * itself (a MAIN-world content script can run more than once in the same
 * realm — e.g. a same-document navigation — and wrapping an already-wrapped
 * Function a second time would stack proxies and leak the previous native
 * closure for the life of the page).
 */
'use strict';
(function(){'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── init guard: install exactly once per realm ──────────────────────
    // Resource being guarded: the single global window.Function binding.
    if ( window.Function && window.Function.__uBolNoFunctionInstalled === true ) {
        return;
    }

    // ── Captured builtins (audit 9.7.5, C35) ────────────────────────────
    // Taken at injection (document_start, before any page script), so page
    // code that later replaces a builtin cannot switch this protection off.
    const reflectApply     = Reflect.apply;
    const reflectConstruct = Reflect.construct;
    const regexExec = RegExp.prototype.exec;
    const toStr = String;
    const logInfo = console.info.bind(console);

    // ── obfuscation-signal thresholds — single source: util/ObfuscationShape.js ──
    const OBFUSC_MIN_B64_LEN = 40;
    const OBFUSC_MIN_CHARCODE_ARGS = 10;
    const OBFUSC_MIN_HEX_IDENTS = 3;

    const _packerSig   = /eval\(function\(p,a,c,k,e,d/;
    const _hexIdentsRe = /_0x[0-9a-f]{4,6}/g;
    const _b64AtobRe   = new RegExp(
        'atob\\(\\s*[\'"][A-Za-z0-9+/=]{' + OBFUSC_MIN_B64_LEN + ',}[\'"]\\s*\\)'
    );
    const _charCodeRe  = new RegExp(
        'String\\.fromCharCode\\(\\s*(?:\\d+\\s*,\\s*){' +
        (OBFUSC_MIN_CHARCODE_ARGS - 1) + ',}\\d+\\s*\\)'
    );

    function countMatches(re, s) {
        re.lastIndex = 0;
        let n = 0;
        while ( n < OBFUSC_MIN_HEX_IDENTS && reflectApply(regexExec, re, [ s ]) !== null ) { n += 1; }
        re.lastIndex = 0;
        return n;
    }

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

    const _nativeFunction = window.Function;

    function wrappedFunction(...args) {
        // The body is always the LAST argument (Function(arg1, arg2, ..., body)).
        // No arguments at all → an empty body, nothing to inspect.
        const body = args.length ? args[args.length - 1] : '';
        const reason = detectObfuscation(body);
        if ( reason !== null ) {
            logInfo(LOG_PREFIX + ' blocked obfuscated Function() (' + reason + ')');
            // A no-op function, never a thrown error — matches sec-noeval.js's
            // "quietly do nothing" behaviour so page code that checks the return
            // type (rather than calling it) does not itself throw.
            return reflectConstruct(_nativeFunction, []);
        }
        // new Function(...) and Function(...) (no `new`) both reach this via a
        // plain function's [[Construct]]/[[Call]]: an explicit object return
        // from a constructor call replaces the implicit `this`, and the same
        // return value is simply handed back on a non-constructor call.
        return reflectConstruct(_nativeFunction, args);
    }
    wrappedFunction.prototype = _nativeFunction.prototype;
    wrappedFunction.toString = _nativeFunction.toString.bind(_nativeFunction);
    wrappedFunction.__uBolNoFunctionInstalled = true;
    window.Function = wrappedFunction;
})();
