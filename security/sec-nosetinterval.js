/*
 * sec-nosetinterval.js — Security scriptlet: blockObfuscatedSetInterval toggle
 *
 * Same test as sec-nosettimeout.js, applied to setInterval() instead: blocks
 * a STRING first argument only when it matches a recognized obfuscation
 * shape (packer bootstrap, long base64 blob, char-code array, or enough
 * `_0x..` identifiers). A function reference, or a plain non-obfuscated
 * string, passes through unaffected — `setInterval(checkStatus, 5000)` is
 * never touched. Repetition itself is not a signal this file checks for;
 * the obfuscated string, once recognized, is blocked on every would-be tick
 * the same way a single setTimeout() call is blocked once.
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
 * global window.setInterval binding itself.
 */
'use strict';
(function(){'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── init guard: install exactly once per realm ──────────────────────
    if ( window.setInterval && window.setInterval.__uBolNoSetIntervalInstalled === true ) {
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

    const _nativeSetInterval = window.setInterval;
    // 4.5.4 (perf P7): `arguments` passed straight through — no rest array + spread copy on every call
    // (timer-heavy pages call this thousands of times; same pattern as sec-adult-noeval.js).
    function wrappedSetInterval(handler) {
        if ( typeof handler === 'string' ) {
            const reason = detectObfuscation(handler);
            if ( reason !== null ) {
                logInfo(LOG_PREFIX + ' blocked obfuscated setInterval() string handler (' + reason + ')');
                return 0;
            }
        }
        return reflectApply(_nativeSetInterval, window, arguments);
    }
    wrappedSetInterval.toString = _nativeSetInterval.toString.bind(_nativeSetInterval);
    wrappedSetInterval.__uBolNoSetIntervalInstalled = true;
    window.setInterval = wrappedSetInterval;
})();
