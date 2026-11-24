/*
 * sec-no-obfuscated-code.js — Security scriptlet: blockObfuscatedEval toggle ("Block obfuscated code execution")
 *
 * 5.1.2 (user decision): the four former scriptlets sec-noeval.js, sec-nofunction.js, sec-nosettimeout.js and
 * sec-nosetinterval.js (protections blockObfuscatedEval / -Function / -SetTimeout / -SetInterval) in ONE file and ONE
 * protection: one copy of the detector, one injection per frame instead of four. Behaviour per entry point is
 * unchanged:
 *   • eval(payload)                      — an obfuscated payload is not run (returns undefined)
 *   • Function(…, body) / new Function   — an obfuscated BODY (the last argument) gives a no-op function
 *   • setTimeout / setInterval(string)   — an obfuscated STRING handler is not scheduled (returns 0); a function
 *                                          handler or a plain string is never touched
 * Never on the mere presence of a name: only a recognised obfuscation SHAPE (Dean Edwards packer bootstrap, a real
 * obfuscator.io density of `_0x..` identifiers, a long base64 blob passed to atob(), a real char-code array passed to
 * String.fromCharCode()). Clean payloads (webpack HMR, REPLs, Monaco, a short atob()) pass through.
 * Note: Cloudflare bot-challenge pages use packed eval — add the site to the allow list if affected.
 *
 * Detection shape: the single source is util/ObfuscationShape.js (detectObfuscation, OBFUSCATION_CONFIG); this file
 * carries an inlined copy because MAIN-world content scripts cannot import ES modules — tools/check-shipped-terms.mjs
 * fails if the thresholds drift.
 *
 * Registered by: data/protections.js (core/script-builder.js reads p.scripts)
 * Injected by:   core/script-builder.js → chrome.scripting.registerContentScripts
 * World:         MAIN, all frames, document_start
 *
 * Guards: each of the four global bindings has its own install flag, so a re-injection into the same realm (a
 * same-document navigation) never stacks a second wrapper (which would also keep the previous native closure alive).
 * `__uBolNoEvalInstalled` is shared with uBlock Stripped Dynamic, so eval is wrapped once when both extensions run.
 * Trust (C35): every built-in used here is captured at injection, before any page script — a page that later replaces
 * RegExp.prototype.test, String.prototype.match or Function.prototype.call can neither switch this off nor be handed
 * a native function.
 */
'use strict';
(function(){'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';
    // obfuscation-signal thresholds — single source: util/ObfuscationShape.js OBFUSCATION_CONFIG
    const OBFUSC_MIN_B64_LEN = 40;            // a base64 literal passed to atob() at least this long
    const OBFUSC_MIN_CHARCODE_ARGS = 10;      // String.fromCharCode() with at least this many numbers
    const OBFUSC_MIN_HEX_IDENTS = 3;          // at least this many `_0x..` identifiers
    const BLOCKED_TIMER_ID = 0;               // what a blocked setTimeout/setInterval returns (an inert timer id)
    // 5.1.3 — a block is also told to Tamper Protection (the protection is part of it since 5.1.3): this event, with the
    // entry point's name as detail, is forwarded by security/tamper-guard-bridge.js as tgObfuscatedCode (only raises
    // the page's risk rating; a page faking it only rates itself higher). = the bridge's TG_OBFUSCATED_EVENT.
    const TG_OBFUSCATED_EVENT = '3pmcf-tg-obfuscated';
    const SINK = Object.freeze({ EVAL: 'eval', FUNCTION: 'Function' });   // = data/tamper-rules.js OBFUSCATED_CODE.sinks
    // install flags, one per wrapped binding (see Guards above)
    const FLAG = Object.freeze({ EVAL: '__uBolNoEvalInstalled', FUNCTION: '__uBolNoFunctionInstalled',
                                 SET_TIMEOUT: '__uBolNoSetTimeoutInstalled', SET_INTERVAL: '__uBolNoSetIntervalInstalled' });

    // ── Captured builtins (C35) ──────────────────────────────────────────
    const reflectApply = Reflect.apply;
    const reflectConstruct = Reflect.construct;
    // Native exec called directly, never test()/match(): those look up replaceable `exec` / Symbol.match / flags.
    const regexExec = RegExp.prototype.exec;
    const toStr = String;
    const logInfo = console.info.bind(console);
    const dispatchEvt = EventTarget.prototype.dispatchEvent;   // 5.1.3
    const CustomEventCtor = CustomEvent;

    // ── Obfuscation shape (inlined copy of util/ObfuscationShape.js) ────
    const _packerSig   = /eval\(function\(p,a,c,k,e,d/;
    const _hexIdentsRe = /_0x[0-9a-f]{4,6}/g;
    const _b64AtobRe   = new RegExp(
        'atob\\(\\s*[\'"][A-Za-z0-9+/=]{' + OBFUSC_MIN_B64_LEN + ',}[\'"]\\s*\\)'
    );
    const _charCodeRe  = new RegExp(
        'String\\.fromCharCode\\(\\s*(?:\\d+\\s*,\\s*){' +
        (OBFUSC_MIN_CHARCODE_ARGS - 1) + ',}\\d+\\s*\\)'
    );
    // Counts /g matches with the captured exec; stops at the threshold (only "reached?" is asked).
    function countMatches(re, s) {
        re.lastIndex = 0;
        let n = 0;
        while ( n < OBFUSC_MIN_HEX_IDENTS && reflectApply(regexExec, re, [ s ]) !== null ) { n += 1; }
        re.lastIndex = 0;
        return n;
    }
    // A short reason when the payload looks obfuscated, null when it may run.
    function detectObfuscation(payload) {
        const s = toStr(payload);
        if ( reflectApply(regexExec, _packerSig, [ s ]) !== null ) { return 'packer'; }
        if ( reflectApply(regexExec, _b64AtobRe, [ s ]) !== null ) { return 'base64-blob'; }
        if ( reflectApply(regexExec, _charCodeRe, [ s ]) !== null ) { return 'char-code-array'; }
        if ( countMatches(_hexIdentsRe, s) >= OBFUSC_MIN_HEX_IDENTS ) { return 'hex-identifiers'; }
        return null;
    }
    function blocked(sink, what, reason) {
        logInfo(LOG_PREFIX + ' blocked obfuscated ' + what + ' (' + reason + ')');
        try { reflectApply(dispatchEvt, window, [new CustomEventCtor(TG_OBFUSCATED_EVENT, { detail: sink })]); }
        catch { /* never the page's problem */ }
    }
    function installed(fn, flag) { return !!fn && fn[flag] === true; }
    function markInstalled(wrapper, native, flag) {
        wrapper.toString = native.toString.bind(native);
        wrapper[flag] = true;
    }

    // ── eval ──
    if ( !installed(window.eval, FLAG.EVAL) ) {
        const _nativeEval = window.eval;
        window.eval = function(payload) {
            const reason = detectObfuscation(payload);
            if ( reason !== null ) { blocked(SINK.EVAL, 'eval', reason); return; }
            return reflectApply(_nativeEval, window, [ payload ]);
        };
        markInstalled(window.eval, _nativeEval, FLAG.EVAL);
    }

    // ── Function() / new Function() — the body is the LAST argument ──
    if ( !installed(window.Function, FLAG.FUNCTION) ) {
        const _nativeFunction = window.Function;
        function wrappedFunction(...args) {
            const body = args.length ? args[args.length - 1] : '';
            const reason = detectObfuscation(body);
            if ( reason !== null ) {
                blocked(SINK.FUNCTION, 'Function()', reason);
                return reflectConstruct(_nativeFunction, []);       // a no-op function, never a thrown error
            }
            // Function(...) and new Function(...) both arrive here; an object returned from a constructor call
            // replaces the implicit `this`, so both get the native result.
            return reflectConstruct(_nativeFunction, args);
        }
        wrappedFunction.prototype = _nativeFunction.prototype;
        markInstalled(wrappedFunction, _nativeFunction, FLAG.FUNCTION);
        window.Function = wrappedFunction;
    }

    // ── setTimeout / setInterval with a STRING handler ──
    // `arguments` passed straight through (4.5.4 perf P7): timer-heavy pages call these thousands of times.
    function wrapTimer(name, flag) {
        const native = window[name];
        if ( typeof native !== 'function' || installed(native, flag) ) { return; }   // absent here, or already wrapped
        function wrapped(handler) {
            if ( typeof handler === 'string' ) {
                const reason = detectObfuscation(handler);
                if ( reason !== null ) { blocked(name, name + '() string handler', reason); return BLOCKED_TIMER_ID; }
            }
            return reflectApply(native, window, arguments);
        }
        markInstalled(wrapped, native, flag);
        window[name] = wrapped;
    }
    wrapTimer('setTimeout', FLAG.SET_TIMEOUT);
    wrapTimer('setInterval', FLAG.SET_INTERVAL);
})();
