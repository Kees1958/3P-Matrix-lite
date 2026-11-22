/*
 * sec-no-webtransport.js — blockWebtransport.
 *
 * 4.7.1 (user request): no longer deletes window.WebTransport outright (that also broke first-party use)
 * — a WebTransport connection's target URL is known right at the constructor call (`new
 * WebTransport(url)`), unlike WebAssembly's bufferSource form (see sec-no-wasm.js), so this can check the
 * URL's origin directly: window.WebTransport is replaced with a thin wrapper that only blocks when the
 * url argument is cross-origin, and otherwise constructs the real WebTransport unchanged. WebTransport
 * has no Permissions-Policy token, and its own scheme ("https") means a CSP connect-src exclusion cannot
 * separate it from ordinary fetch/XHR (see data/constants.js CSP_NO_WS_VALUE's comment) — hence script,
 * not CSP, as the mechanism.
 *
 * Must run at document_start, before any page script can read the constructor — a page already running
 * when this protection is turned on, or on a site only flagged high-risk mid-session, is NOT
 * retroactively covered (data/protections.js' 4.7.0 alsoHighRisk comment: the dynamic half of that
 * escalation is deliberately left to the HEADER/DNR/DOWNLOAD-mechanism protections, which decide per
 * request and so are never "too late" the way a one-shot global-replacement script is).
 *
 * Registered by: core/script-builder.js — MAIN world, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── init guard: install exactly once per realm (see sec-no-wasm.js header for why) ──────────────
    if ( window.WebTransport && window.WebTransport.__uBolWtGuardInstalled === true ) { return; }
    if ( !('WebTransport' in window) ) { return; }   // nothing to protect — already absent

    // ── Captured builtins (audit 9.7.5, C35) — taken before any page script can replace them ─────────
    const logInfo = console.info.bind(console);
    const _nativeWebTransport = window.WebTransport;

    function sameOrigin(url) {
        try { return new URL(url, location.href).origin === location.origin; }
        catch { return true; }   // unparsable → fail open; this is a usability scope, not a security boundary
    }

    function WebTransportGuard(url, options) {
        if ( !sameOrigin(url) ) {
            logInfo(LOG_PREFIX + ' blocked third-party WebTransport connection: ' + url);
            throw new TypeError('WebTransport blocked: third-party endpoint');
        }
        return Reflect.construct(_nativeWebTransport, arguments, new.target || WebTransportGuard);
    }
    WebTransportGuard.prototype = _nativeWebTransport.prototype;
    WebTransportGuard.__uBolWtGuardInstalled = true;

    try {
        Object.defineProperty(window, 'WebTransport', { value: WebTransportGuard, configurable: true, writable: true });
    } catch { /* already locked down by the page or another extension — leave it */ }
})();
