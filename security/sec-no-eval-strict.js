/*
 * sec-no-eval-strict.js — blockObfuscatedEval at level 5 (5.1.3, owner decision): plain eval() is not run at all.
 *
 * Only eval() itself — not Function(), not string setTimeout()/setInterval() (those keep the obfuscated-code check
 * of security/sec-no-obfuscated-code.js). Returns undefined instead of running the code, like the obfuscated block.
 * Replaces the former blockHighRiskEval (every eval on known high-risk sites, sec-adult-noeval.js), which is gone.
 *
 * Registered by: core/script-builder.js strictRegistrationsFor — MAIN world, all frames, document_start, from the
 * protection's strictFromLevel (data/protections.js). Runs after sec-no-obfuscated-code.js when both apply.
 * Guard: the install flag stops a second wrapper in the same realm (a same-document re-injection).
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX (kept equal by tools/check-shipped-terms.mjs)
    const LOG_PREFIX = '[3PMCF]';
    const FLAG = '__3pmNoEvalStrictInstalled';
    const logInfo = console.info.bind(console);

    const native = window.eval;
    if ( typeof native !== 'function' || native[FLAG] === true ) { return; }
    function evalBlocked() {
        logInfo(LOG_PREFIX + ' blocked eval() (level 5)');
        return undefined;
    }
    evalBlocked.toString = native.toString.bind(native);
    evalBlocked[FLAG] = true;
    window.eval = evalBlocked;
})();
