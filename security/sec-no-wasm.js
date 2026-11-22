/*
 * sec-no-wasm.js — blockWebAssembly.
 *
 * 4.7.1 (user request): no longer deletes window.WebAssembly outright — that broke any FIRST-PARTY use
 * of WASM too (video/image codecs, password-strength tools, design/CAD apps, crypto libraries, game
 * engines), which is disproportionate for a THIRD-PARTY content firewall. Instead this scopes the block
 * to WebAssembly bytes pulled in from a different origin than the page, via the two real-world loading
 * paths:
 *   - WebAssembly.instantiateStreaming(response) / compileStreaming(response) — the response carries its
 *     own .url, checked directly against location.origin. This is the recommended, fast-path way to load
 *     WASM (`WebAssembly.instantiateStreaming(fetch(url))`), so it covers the common case.
 *   - WebAssembly.instantiate(bytes, imports) / compile(bytes) — the byte-array form carries no origin
 *     info by the time it reaches WebAssembly, so origin is tracked further upstream: fetch()'s
 *     Response.arrayBuffer() and XMLHttpRequest's `response` getter (responseType "arraybuffer") tag the
 *     ArrayBuffer they hand back, IF the request's URL was cross-origin, in CROSS_ORIGIN_BUFFERS (a
 *     WeakSet — self-clearing: an untagged buffer is simply garbage-collected like any other, no manual
 *     release needed, so this doubles as the "guard" for that resource). WebAssembly.instantiate/compile
 *     then check the buffer they were given against that set.
 * Not covered (documented limitation, not a silent gap): WASM bytes obtained any other way — inlined/
 * base64-decoded in page script, delivered over a WebSocket, postMessage'd from a frame, or passed to the
 * legacy synchronous `new WebAssembly.Module(bytes)` / `new WebAssembly.Instance(...)` constructors
 * (discouraged by the spec itself for anything beyond tiny modules; main-thread-blocking) — carry no
 * reliable origin signal without much heavier instrumentation, so they are left alone rather than guessed
 * at (a wrong guess reintroduces the exact false-positive problem this rewrite fixes).
 *
 * Must run at document_start, before any page script can reach window.fetch / XMLHttpRequest / WebAssembly
 * — see sec-no-webtransport.js's header for the same "not retroactive" note (data/protections.js' 4.7.0
 * alsoHighRisk comment applies here too: the dynamic (mid-session) half of alsoHighRisk cannot reach a
 * SCRIPT-mechanism protection like this one for a page that already started loading).
 *
 * Registered by: core/script-builder.js — MAIN world, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── init guard: install exactly once per realm ──────────────────────────────
    // Resource being guarded: window.fetch, XMLHttpRequest.prototype.response and the WebAssembly
    // methods below. A MAIN-world content script can in principle run more than once in the same realm
    // (e.g. a same-document navigation) — re-wrapping an already-wrapped function would stack wrappers
    // and leak the previous native function's closure for the life of the page.
    if ( window.WebAssembly && window.WebAssembly.__uBolWasmGuardInstalled === true ) { return; }
    if ( !('WebAssembly' in window) ) { return; }   // nothing to protect — already absent

    // ── Captured builtins (audit 9.7.5, C35) ──────────────────────────────────────
    // Taken at injection (document_start, before any page script), so page code that later replaces a
    // builtin can neither switch this protection off nor be handed the native function as `this`.
    const reflectApply = Reflect.apply;
    const logInfo = console.info.bind(console);
    const WA = window.WebAssembly;
    const _nativeFetch = window.fetch;
    const _nativeXhrOpen = window.XMLHttpRequest && window.XMLHttpRequest.prototype.open;
    const _responseDesc = window.XMLHttpRequest &&
        Object.getOwnPropertyDescriptor(window.XMLHttpRequest.prototype, 'response');
    const _nativeInstantiate = WA.instantiate;
    const _nativeCompile = WA.compile;
    const _nativeInstantiateStreaming = WA.instantiateStreaming;
    const _nativeCompileStreaming = WA.compileStreaming;

    // ArrayBuffers known to have come from a cross-origin fetch()/XHR response. WeakSet so a buffer the
    // page drops is simply garbage-collected like any other — no manual release needed (see header).
    const CROSS_ORIGIN_BUFFERS = new WeakSet();

    // Marks a rejection as "the origin check failed" so it is reported as a block rather than mistaken
    // for a real network/compile error further down the chain.
    class WasmOriginBlocked extends Error {}

    function sameOrigin(url) {
        try { return new URL(url, location.href).origin === location.origin; }
        catch { return true; }   // unparsable → fail open; this is a usability scope, not a security boundary
    }

    function tagIfCrossOrigin(buffer, url) {
        if ( buffer instanceof ArrayBuffer && !sameOrigin(url) ) { CROSS_ORIGIN_BUFFERS.add(buffer); }
        return buffer;
    }

    function bufferOf(src) {
        if ( src instanceof ArrayBuffer ) { return src; }
        if ( ArrayBuffer.isView(src) ) { return src.buffer; }
        return null;
    }

    function blockedPromise(reason) {
        logInfo(LOG_PREFIX + ' blocked third-party WebAssembly (' + reason + ')');
        return Promise.reject(new TypeError('WebAssembly blocked: third-party module'));
    }

    // ── fetch(): tag the ArrayBuffer behind a cross-origin response's .arrayBuffer() ─────────────────
    // 5.0.7 — TRANSPARENT: the page gets the browser's OWN promise back, never one built with .then(). Until 5.0.6
    // the wrapper returned its own .then() chain, so a fetch failure the page left unhandled (on a level 4–5 page
    // often a request 3P Matrix itself blocked) was reported as an error OF THIS EXTENSION on the browser's
    // extension error page. Now the tagging runs on a side branch: it is registered on the native promise BEFORE
    // the promise is returned, so it runs before any reaction the page adds (reactions run in registration
    // order) — the page's own .then/await already sees the tagging arrayBuffer(). The side branch handles a
    // rejection with a noop so it never creates an extension-owned unhandled rejection; a page that handles the
    // failure still gets the very same error on the promise it holds. Accepted side effect: because the side
    // branch counts as a handler, a failure the page IGNORES raises no "unhandled rejection" any more (not under
    // this extension, not in the page's console; Chrome still logs the failed request itself). The alternative —
    // a side branch without a rejection handler — is exactly the bug fixed here. Guarded by tools/test-wasm-wrappers.mjs.
    function noop() {}
    function wrapArrayBuffer(response, url) {
        if ( !response || typeof response.arrayBuffer !== 'function' ) { return; }
        const _nativeArrayBuffer = response.arrayBuffer.bind(response);
        response.arrayBuffer = function() {
            const pending = _nativeArrayBuffer();
            pending.then((buf) => { tagIfCrossOrigin(buf, response.url || url); }, noop);
            return pending;
        };
    }
    if ( typeof _nativeFetch === 'function' ) {
        window.fetch = function(...args) {
            const url = (args[0] && args[0].url) || args[0] || location.href;
            const pending = reflectApply(_nativeFetch, this, args);
            pending.then((response) => { wrapArrayBuffer(response, url); }, noop);
            return pending;
        };
    }

    // ── XMLHttpRequest: tag the ArrayBuffer behind a cross-origin response's `.response` getter ──────
    if ( typeof _nativeXhrOpen === 'function' && _responseDesc && typeof _responseDesc.get === 'function' ) {
        const xhrUrls = new WeakMap();
        window.XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            try { xhrUrls.set(this, new URL(url, location.href).href); } catch { /* keep default (same-origin) */ }
            return reflectApply(_nativeXhrOpen, this, [ method, url, ...rest ]);
        };
        const _nativeResponseGetter = _responseDesc.get;
        Object.defineProperty(window.XMLHttpRequest.prototype, 'response', Object.assign({}, _responseDesc, {
            get: function() {
                const value = reflectApply(_nativeResponseGetter, this, []);
                if ( this.responseType === 'arraybuffer' ) { tagIfCrossOrigin(value, xhrUrls.get(this) || location.href); }
                return value;
            }
        }));
    }

    // ── WebAssembly.instantiate() / compile(): block a tagged cross-origin buffer ─────────────────────
    WA.instantiate = function(src, imports) {
        const buf = bufferOf(src);
        if ( buf !== null && CROSS_ORIGIN_BUFFERS.has(buf) ) { return blockedPromise('cross-origin buffer'); }
        return reflectApply(_nativeInstantiate, WA, arguments);
    };
    WA.compile = function(src) {
        const buf = bufferOf(src);
        if ( buf !== null && CROSS_ORIGIN_BUFFERS.has(buf) ) { return blockedPromise('cross-origin buffer'); }
        return reflectApply(_nativeCompile, WA, arguments);
    };

    // ── WebAssembly.instantiateStreaming() / compileStreaming(): block a cross-origin response ────────
    function checkStreamingOrigin(respOrPromise) {
        return Promise.resolve(respOrPromise).then((response) => {
            if ( response && !sameOrigin(response.url || location.href) ) { throw new WasmOriginBlocked(); }
            return response;
        });
        // A genuine fetch/network rejection on respOrPromise is NOT caught here — it propagates unchanged.
        // 5.0.7 note: these two streaming wrappers keep their own promise chain on purpose — they must be able to
        // REJECT a blocked module, which a side branch cannot. A failure the page leaves unhandled here is
        // therefore still listed under this extension; it happens only when a page loads WebAssembly by streaming.
    }
    WA.instantiateStreaming = function(source, imports) {
        return checkStreamingOrigin(source)
            .then((response) => reflectApply(_nativeInstantiateStreaming, WA, [ response, imports ]))
            .catch((err) => { if ( err instanceof WasmOriginBlocked ) { return blockedPromise('cross-origin streaming source'); } throw err; });
    };
    WA.compileStreaming = function(source) {
        return checkStreamingOrigin(source)
            .then((response) => reflectApply(_nativeCompileStreaming, WA, [ response ]))
            .catch((err) => { if ( err instanceof WasmOriginBlocked ) { return blockedPromise('cross-origin streaming source'); } throw err; });
    };

    WA.__uBolWasmGuardInstalled = true;
})();
