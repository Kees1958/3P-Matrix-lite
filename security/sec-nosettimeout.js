/*
 * sec-nosettimeout.js — Security scriptlet: blockObfuscatedSetTimeout toggle
 *
 * Blocks setTimeout() calls whose FIRST ARGUMENT is a string (the browser
 * evaluates that string as code when the timer fires — the same execution
 * vector as eval(), under a different name) that matches the *shape* of
 * known obfuscation techniques: a real obfuscator.io-style density of
 * `_0x..` identifiers, a genuinely long base64 blob passed to atob(), or a
 * real char-code-encoded string passed to String.fromCharCode(). The delay
 * (second argument) is never inspected.
 *
 * Presence of a string argument alone is never enough: an ordinary,
 * non-obfuscated string handler (legacy code, not malicious) passes through
 * unaffected, same as a function reference. `setTimeout(() => refresh(),
 * 1000)` is never touched — only a STRING first argument is even looked at.
 *
 * Narrower and more permissive than blockHighRiskEval's sec-adult-noeval.js,
 * which blocks every string handler unconditionally on a fixed, known
 * high-risk host list; this protection runs on the open web and so only
 * acts on a recognized obfuscation shape, exactly like blockObfuscatedEval's
 * eval() detector.
 *
 * Detection shape is the single source at util/ObfuscationShape.js
 * (detectObfuscation, OBFUSCATION_CONFIG) — this file carries its own
 * inlined copy because MAIN-world content scripts cannot import ES modules.
 * tools/check-shipped-terms.mjs fails if this copy drifts from that module.
 *
 * Registered by: data/protections.js (script-builder.js reads p.scripts)
 * Injected by:   core/script-builder.js → chrome.scripting.registerContentScripts
 * World:         MAIN, all frames, document_start
 *
 * Uses const/let, not var: this whole file's body sits inside the IIFE
 * below. The one cross-injection resource that DOES need a guard is the
 * global window.setTimeout binding itself.
 */
'use strict';
(function(){'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── init guard: install exactly once per realm ──────────────────────
    if ( window.setTimeout && window.setTimeout.__uBolNoSetTimeoutInstalled === true ) {
        return;
    }

    // ── Captured builtins (audit 9.7.5, C35) ────────────────────────────
    const reflectApply = Reflect.apply;
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

    const _nativeSetTimeout = window.setTimeout;
    // 4.5.4 (perf P7): `arguments` passed straight through — no rest array + spread copy on every call
    // (timer-heavy pages call this thousands of times; same pattern as sec-adult-noeval.js).
    function wrappedSetTimeout(handler) {
        if ( typeof handler === 'string' ) {
            const reason = detectObfuscation(handler);
            if ( reason !== null ) {
                logInfo(LOG_PREFIX + ' blocked obfuscated setTimeout() string handler (' + reason + ')');
                // Mimic a scheduled-but-inert timer id, never a thrown error.
                return 0;
            }
        }
        return reflectApply(_nativeSetTimeout, window, arguments);
    }
    wrappedSetTimeout.toString = _nativeSetTimeout.toString.bind(_nativeSetTimeout);
    wrappedSetTimeout.__uBolNoSetTimeoutInstalled = true;
    window.setTimeout = wrappedSetTimeout;
})();
