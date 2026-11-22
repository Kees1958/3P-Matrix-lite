/*
 * sec-browser-locker.js — Security scriptlet: blockDialogSpam toggle (3P Matrix, 4.6.0)
 * "Block browser-locker scams (popups, keyboard lock)" — runs together with sec-alertbuster.js and
 * sec-dialogbuster.js (the popup loops). Fake "your PC is infected" pages trap the user with four more tricks;
 * each is taken away here, without touching ordinary use (user decisions 2026-11-06):
 *
 *   1. Keyboard lock — navigator.keyboard.lock() makes Esc have to be HELD to leave fullscreen. Always refused,
 *      so Esc works normally. (Cloud-gaming sites that need it: trust the site = level 1, no protections.)
 *   2. Fullscreen re-entry — after the user has left fullscreen, the page cannot enter it again until it reloads.
 *      Exception: a video player — the <video> itself, or a player element holding a video with a source; the
 *      whole page (html/body) never counts, so a scam cannot pass by containing a video somewhere.
 *   3. "Leave site?" — the prompt is allowed only after the user typed on the page (the real "unsaved changes"
 *      case). Covers event.preventDefault(), event.returnValue = … and window.onbeforeunload = () => "…".
 *   4. Back-button trap — history entries a page adds WITHOUT a click are counted; the user's first Back press on
 *      such a page skips all of them at once (the page's own popstate handlers do not run). No earlier entry →
 *      about:blank (a page cannot open the browser's new-tab page).
 *      5.0.4: only the USER's Back press is a trap escape. A page stepping back itself (history.back/go,
 *      navigation.back/traverseTo — e.g. a cookie dialog removing the entry it added) only lowers the count by the
 *      steps it took. Who stepped is Chrome's own mark on the traversal (NavigateEvent.userInitiated: browser Back
 *      button / gesture), which a page cannot forge. Bug fixed: euroingro.com's cookie banner closed with
 *      history.back() and 3P Matrix skipped past the page to the previous site or the new-tab page.
 *
 * Keeps no history: only this page's own counters/flags, in this page's memory, gone when the page is.
 * Captured builtins (C35); Proxy handlers with `__proto__: null`.
 * World: MAIN, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── LOG_PREFIX: copy of data/constants.js (MAIN world cannot import); kept equal by
    // tools/check-shipped-terms.mjs.
    const LOG_PREFIX = '[3PMCF]';
    const NOT_ALLOWED = 'NotAllowedError';                       // DOMException name for a refused request
    const BEFOREUNLOAD = 'beforeunload';
    const VIDEO_WITH_SOURCE = 'video[src], video > source[src]';   // a player holds a video that has a source
    const VIDEO_TAG = 'VIDEO';
    const PAGE_ROOT_TAGS = Object.freeze(['HTML', 'BODY']);       // the whole page is never "a video player"
    const LEAVE_URL = 'about:blank';                             // back-button trap with no earlier entry
    const NAVIGATE = 'navigate';                                 // Navigation API event, fired before popstate
    const TRAVERSE = 'traverse';                                 // NavigateEvent.navigationType of a Back/Forward step
    const EDITABLE_TAGS = Object.freeze(['INPUT', 'TEXTAREA', 'SELECT']);

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    const logInfo = console.info.bind(console);
    const { apply, getOwnPropertyDescriptor, defineProperty, getPrototypeOf } = Reflect;
    const PromiseReject = Promise.reject.bind(Promise);
    const DOMExceptionCtor = DOMException;
    const addListener = EventTarget.prototype.addEventListener;
    const stopImmediate = Event.prototype.stopImmediatePropagation;
    const elemQuery = Element.prototype.querySelector;
    const tagNameGet = getOwnPropertyDescriptor(Element.prototype, 'tagName').get;
    const fsElementGet = getOwnPropertyDescriptor(Document.prototype, 'fullscreenElement').get;
    const editableGet = getOwnPropertyDescriptor(HTMLElement.prototype, 'isContentEditable').get;
    const eventTypeGet = getOwnPropertyDescriptor(Event.prototype, 'type').get;
    const eventTargetGet = getOwnPropertyDescriptor(Event.prototype, 'target').get;
    const historyGo = History.prototype.go;
    const historyLengthGet = getOwnPropertyDescriptor(History.prototype, 'length').get;
    const navigationApi = window.navigation || null;            // Chrome ≥ 102 (manifest minimum is higher)
    const navTypeGet = navigationApi ? getOwnPropertyDescriptor(NavigateEvent.prototype, 'navigationType').get : null;
    const navUserGet = navigationApi ? getOwnPropertyDescriptor(NavigateEvent.prototype, 'userInitiated').get : null;
    const navDestGet = navigationApi ? getOwnPropertyDescriptor(NavigateEvent.prototype, 'destination').get : null;
    const destIndexGet = navigationApi ? getOwnPropertyDescriptor(NavigationDestination.prototype, 'index').get : null;
    const currentEntryGet = navigationApi ? getOwnPropertyDescriptor(Navigation.prototype, 'currentEntry').get : null;
    const entryIndexGet = navigationApi ? getOwnPropertyDescriptor(NavigationHistoryEntry.prototype, 'index').get : null;
    const userActivation = navigator.userActivation || null;
    const activationGet = userActivation ? getOwnPropertyDescriptor(getPrototypeOf(userActivation), 'isActive').get : null;
    const doc = document;
    // event.isTrusted and location.replace are [LegacyUnforgeable] — own, non-configurable properties of each
    // event / of the location object, so a page cannot replace them: used directly, nothing to capture.

    function refused(what) { logInfo(LOG_PREFIX + ' blocked ' + what); return new DOMExceptionCtor(what + ' blocked by 3P Matrix', NOT_ALLOWED); }
    function clickedNow() { return activationGet ? !!apply(activationGet, userActivation, []) : false; }

    // ── Page-local state (no history kept) ──────────────────────────────────
    let leftFullscreen = false;      // the user has left fullscreen at least once on this page
    let wasFullscreen = false;
    let typed = false;               // the user typed into an editable field on this page
    let pushedWithoutClick = 0;      // history entries this page added without a click
    let userSteppedBack = false;     // the traversal now running is the user's own Back press (set by 'navigate')

    // 1. Keyboard lock ───────────────────────────────────────────────────────
    const keyboard = navigator.keyboard;
    if (keyboard && typeof keyboard.lock === 'function') {
        const proto = getPrototypeOf(keyboard);
        proto.lock = new Proxy(proto.lock, { __proto__: null, apply: function() { return PromiseReject(refused('keyboard lock')); } });
    }

    // 2. Fullscreen re-entry ──────────────────────────────────────────────────
    // 5.0.8 (C47): on WINDOW, capture, registered at document_start — before any page script. On `document` (until
    // 5.0.7) a page's own window-capture listener could stop fullscreenchange first: "the user left fullscreen" was
    // never seen and the page could force fullscreen again (proven in tools/e2e-page-protections.mjs).
    apply(addListener, window, ['fullscreenchange', function() {
        const nowFs = !!apply(fsElementGet, doc, []);
        if (wasFullscreen && !nowFs) leftFullscreen = true;
        wasFullscreen = nowFs;
    }, true]);
    // A video player: the <video> itself, or a player element (never the whole page) holding a video with a
    // source. A scam page cannot pass by wrapping the page in fullscreen: html/body never count.
    function isVideoPlayer(el) {
        try {
            const tag = apply(tagNameGet, el, []);
            if (tag === VIDEO_TAG) return true;
            if (PAGE_ROOT_TAGS.includes(tag)) return false;
            return !!apply(elemQuery, el, [VIDEO_WITH_SOURCE]);
        } catch { return false; }
    }
    for (const name of ['requestFullscreen', 'webkitRequestFullscreen', 'webkitRequestFullScreen']) {
        const orig = Element.prototype[name];
        if (typeof orig !== 'function') continue;
        const promiseApi = name === 'requestFullscreen';             // the webkit variants return nothing
        Element.prototype[name] = new Proxy(orig, { __proto__: null, apply: function(target, self, args) {
            if (leftFullscreen && !isVideoPlayer(self)) {
                const err = refused('fullscreen re-entry');
                return promiseApi ? PromiseReject(err) : undefined;
            }
            return apply(target, self, args);
        } });
    }

    // 3. "Leave site?" only after typing ──────────────────────────────────────
    // 5.0.8 (C47): on window, capture, like every page-script listener (a page stopping it would only keep its own
    // "Leave site?" prompt blocked — the safe side — but one rule for all listeners keeps the check simple).
    apply(addListener, window, ['input', function(e) {
        if (!e.isTrusted) return;
        const t = apply(eventTargetGet, e, []);
        try {
            if (EDITABLE_TAGS.includes(apply(tagNameGet, t, [])) || apply(editableGet, t, [])) typed = true;
        } catch { /* not an element */ }
    }, true]);
    function isBeforeUnload(ev) { try { return apply(eventTypeGet, ev, []) === BEFOREUNLOAD; } catch { return false; } }
    Event.prototype.preventDefault = new Proxy(Event.prototype.preventDefault, { __proto__: null, apply: function(target, self, args) {
        if (!typed && isBeforeUnload(self)) { logInfo(LOG_PREFIX + ' blocked "Leave site?" prompt'); return undefined; }
        return apply(target, self, args);
    } });
    const rvDesc = typeof BeforeUnloadEvent === 'function' ? getOwnPropertyDescriptor(BeforeUnloadEvent.prototype, 'returnValue') : null;
    if (rvDesc && rvDesc.set) {
        defineProperty(BeforeUnloadEvent.prototype, 'returnValue', { __proto__: null, configurable: true, enumerable: rvDesc.enumerable,
            get: rvDesc.get,
            set: function(v) { if (!typed) { logInfo(LOG_PREFIX + ' blocked "Leave site?" prompt'); return; } apply(rvDesc.set, this, [v]); } });
    }
    // window.onbeforeunload = () => "…": the handler's RETURN value shows the prompt — wrap the handler.
    let ownerOfHandler = window;
    while (ownerOfHandler && !getOwnPropertyDescriptor(ownerOfHandler, 'onbeforeunload')) ownerOfHandler = getPrototypeOf(ownerOfHandler);
    const handlerDesc = ownerOfHandler ? getOwnPropertyDescriptor(ownerOfHandler, 'onbeforeunload') : null;
    if (handlerDesc && handlerDesc.set) {
        let pageHandler = null;
        defineProperty(window, 'onbeforeunload', { __proto__: null, configurable: true, enumerable: true,
            get: function() { return pageHandler; },
            set: function(fn) {
                pageHandler = typeof fn === 'function' ? fn : null;
                apply(handlerDesc.set, window, [pageHandler === null ? null : function(ev) {
                    const r = apply(pageHandler, this, [ev]);
                    if (!typed) { if (r !== undefined) logInfo(LOG_PREFIX + ' blocked "Leave site?" prompt'); return undefined; }
                    return r;
                }]);
            } });
    }

    // 4. Back-button trap ─────────────────────────────────────────────────────
    History.prototype.pushState = new Proxy(History.prototype.pushState, { __proto__: null, apply: function(target, self, args) {
        if (!clickedNow()) pushedWithoutClick++;
        return apply(target, self, args);
    } });
    // Who steps back: Chrome marks a traversal started by its Back button / gesture as userInitiated. A step the
    // page takes itself removes its own entries — lower the count, never below 0. Registered at document_start,
    // so it runs before any listener the page adds; synthetic (untrusted) events are ignored.
    if (navigationApi) apply(addListener, navigationApi, [NAVIGATE, function(e) {
        if (!e.isTrusted) return;
        try {
            if (apply(navTypeGet, e, []) !== TRAVERSE) return;
            const from = apply(entryIndexGet, apply(currentEntryGet, navigationApi, []), []);
            const steps = from - apply(destIndexGet, apply(navDestGet, e, []), []);   // > 0 = backwards
            if (apply(navUserGet, e, [])) { userSteppedBack = steps > 0; return; }
            userSteppedBack = false;
            if (steps > 0) pushedWithoutClick = pushedWithoutClick > steps ? pushedWithoutClick - steps : 0;
        } catch { userSteppedBack = false; }
    }]);
    apply(addListener, window, ['popstate', function(e) {
        if (pushedWithoutClick === 0) return;
        if (navigationApi) {                                          // only the user's own Back press escapes the trap
            const byUser = userSteppedBack;
            userSteppedBack = false;
            if (!byUser) return;
        }
        apply(stopImmediate, e, []);                                  // the page's own handlers must not re-trap
        const skip = pushedWithoutClick;
        pushedWithoutClick = 0;
        logInfo(LOG_PREFIX + ' back-button trap: skipping ' + skip + ' added history entries');
        // No entry before the page's own (opened in a new tab): leave to a blank page.
        if (apply(historyLengthGet, history, []) <= skip + 1) { location.replace(LEAVE_URL); return; }
        apply(historyGo, history, [-skip]);
    }, true]);
})();
