/*
 * scam-guard-page.js — Scam protection, MAIN-world bundle (3P Matrix 5.1.3, owner decision 2026-11-24).
 *
 * ONE file for the switch "Enable scam protection" (data/protections.js ENABLE_SCAM_PROTECTION) — one injection per
 * frame instead of seven. Each part below is the former separate scriptlet, unchanged, in its own closure (they share
 * no variables), in the order they used to run:
 *   browser-locker scams (alertbuster, dialogbuster, browser-locker) · ClickFix · notification prompts without a click ·
 *   fake payment handlers · custom protocol handlers.
 * The ISOLATED-world half is security/scam-guard-bridge.js. Scope: level 2 and up on every site (the switch's); the
 * notification-prompt part used to start at level 3 outside safer regions (owner accepted the wider scope).
 *
 * Registered by: core/script-builder.js — MAIN world, all frames, document_start.
 */

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-alertbuster.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * sec-alertbuster.js — Security scriptlet: blockDialogSpam toggle
 * (3P Matrix blockDialogSpam runs this file together with sec-dialogbuster.js)
 *
 * Silences window.alert() — used by tech-support fraud sites to lock the
 * browser in an endless dialog loop. Proxies alert to console.info and
 * spoofs .toString() so native-code detection checks still pass.
 * Source: originally scriptlets.js alertBuster (uBO-lite resources).
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 * World:         MAIN, all frames, document_start
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
            const nativeAlert = window.alert;
            // Bound once, here — previously built at call time through
            // target.toString.bind, both page-replaceable, and a replaced
            // bind would have been handed the original alert as `this`.
            const nativeToString = nativeAlert.toString.bind(nativeAlert);
            window.alert = new Proxy(nativeAlert, {
                __proto__: null,
                apply: function(target, thisArg, args) {
                    logInfo(LOG_PREFIX + ' alert blocked:', args[0]);
                },
                get(target, prop) {
                    if ( prop === 'toString' ) { return nativeToString; }
                    return reflectGet(target, prop);
                },
            });
        })();

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-dialogbuster.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-browser-locker.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-clickfix-clipboard.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/* Blocks clipboard writes whose text looks like a ClickFix attack payload (blockClickFix).

   ClickFix: a page silently puts a command line on the clipboard and then
   socially engineers the visitor into pasting it into Win+R, PowerShell,
   the File Explorer address bar (FileFix), Terminal or a Linux terminal
   ("press Ctrl+V to verify you are human"). The clipboard write itself is
   the automated step, and it is the one this blocks.

   DESIGN — why this matches EXECUTION+OBFUSCATION MARKERS, not "shell-like
   text": developer documentation sites legitimately put commands on the
   clipboard from copy buttons (npm install…, docker run…, curl … | sh), so
   a pattern for shell syntax in general would fire on exactly those.

   4.7.0 — TWO LEVELS (user decision 2026-11-06), every OS's patterns on every
   OS (a scam page picks its payload from the user agent; checking costs nothing):
     STRONG — a hidden/encoded execution flag, a download-and-execute chain, a
              LOLBin fetching from a URL, decoding base64 into a shell, removing
              the macOS quarantine flag together with a download, backgrounding
              a download with its output thrown away, or FileFix padding (a long
              run of spaces that pushes a command out of the visible part of
              the address bar). Always blocked.
     WEAK   — what real install guides also use: plain `curl … | sh`,
              `bash -c "$(curl …)"` (Homebrew), `xattr -d com.apple.quarantine`,
              download + chmod +x + run. Blocked ONLY when the page also shows
              ClickFix instructions (INSTRUCTION_PHRASES: Win+R, Ctrl+Alt+T,
              Ctrl+Shift+V, "verify you are human" …). The page text is read
              once, at that clipboard write only. Accepted false negative: a scam
              page with a weak payload and no such words gets through.
   macOS Script Editor: a link to applescript:// opens Script Editor with a
   script already filled in (a newer macOS variant) — a click on such a link,
   or window.open() of one, is blocked the same way. Not covered: a page that
   sets location.href to such an address itself (not hookable from a page script).

   4.7.0 — VISIBLE WARNING (was silent): the first block on a page dispatches
   CLICKFIX_BLOCKED_EVENT; the ISOLATED-world bridge (security/clickfix-bridge.js)
   tells the service worker, which opens the red warning page (an extension
   page: the scam page can neither cover nor read it). No DOM work is done on
   the hostile page — the reason the protection was silent before.
   The clipboard is left as it was (user decision 2026-11-06): the page's
   command is simply not copied.

   Reads nothing from the clipboard: this only inspects the string the PAGE
   passes to a clipboard write. No clipboardRead/clipboardWrite permission is
   needed (those govern the EXTENSION touching the clipboard).

   Hardened per C35 (Xplainer programming principles): every builtin it relies
   on is captured at injection (document_start, before any page script),
   and every Proxy handler is declared `__proto__: null`, because Proxy
   looks traps up through the handler's prototype chain.
   Cost: nothing until the page writes to the clipboard or clicks a link; then
   a substring pass and, only on a marker hit, a few bounded regexes.
*/
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies of data/constants.js LOG_PREFIX and of the
    // event name in security/clickfix-bridge.js: MAIN-world scripts cannot import.
    // Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';
    const CLICKFIX_BLOCKED_EVENT = '3pmcf-clickfix-blocked';
    try {
        // ── Captured builtins (C35) ──────────────────────────────────────
        const reflectApply = Reflect.apply;
        const regexExec = RegExp.prototype.exec;
        const regexTest = RegExp.prototype.test;
        const strSlice = String.prototype.slice;
        const strToLowerCase = String.prototype.toLowerCase;
        const strIncludes = String.prototype.includes;
        const strReplace = String.prototype.replace;
        const strTrimStart = String.prototype.trimStart;
        const toStr = String;
        const logWarn = console.warn.bind(console);
        const textContentGet = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent').get;
        const closest = Element.prototype.closest;
        const getAttr = Element.prototype.getAttribute;
        const dispatch = EventTarget.prototype.dispatchEvent;
        const CustomEventCtor = CustomEvent;
        const ElementCtor = Element;
        const doc = document;

        // ── CONFIG ───────────────────────────────────────────────────────
        // Only the start of the text is inspected: a ClickFix payload is a
        // command line, while a page legitimately copying an article would
        // otherwise cost a scan of the whole body. FileFix pads with ~140
        // spaces, so the window must hold the padding AND the command.
        const MAX_INSPECTED_CHARS = 2048;
        // Page text read for INSTRUCTION_PHRASES (weak level only): bounded so
        // a huge page cannot make the one read expensive.
        const MAX_PAGE_TEXT_CHARS = 200000;
        // Cheap first pass: if none of these appears, no pattern runs at all
        // (FileFix padding is the exception: checked whenever the text has it).
        // Windows, macOS and Linux execution vectors seen in real campaigns.
        const CHEAP_MARKERS = [
            'powershell', 'pwsh', 'mshta', 'certutil', 'bitsadmin', 'regsvr32',
            'rundll32', 'msiexec', 'conhost', 'wscript', 'cscript', 'curl',
            'wget', 'iex', 'invoke-expression', 'invoke-webrequest', 'irm ',
            'finger', 'cmd', 'osascript', 'base64', 'xattr', 'chmod', 'nohup',
            'python', 'bash', 'sh -c',
        ];
        // STRONG — each requires an execution/obfuscation COMBINATION, never a
        // bare tool name. Always blocked.
        const STRONG_PATTERNS = [
            // Windows
            // powershell/pwsh with a hidden-window, no-profile or encoded flag
            /\b(?:powershell|pwsh)(?:\.exe)?[^\n]{0,120}?[-/](?:w(?:indowstyle)?\s+hidden|nop(?:rofile)?\b|e(?:nc|ncodedcommand)\b)/i,
            // download-and-execute in PowerShell (IEX over a downloaded string)
            /\b(?:iex|invoke-expression)\b[^\n]{0,160}?(?:downloadstring|invoke-(?:webrequest|restmethod)|\birm\b|\biwr\b|net\.webclient)/i,
            /(?:downloadstring|invoke-(?:webrequest|restmethod)|net\.webclient)[^\n]{0,160}?\b(?:iex|invoke-expression)\b/i,
            // LOLBins fetching from a URL
            /\bmshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)/i,
            /\bcertutil(?:\.exe)?[^\n]{0,80}?-(?:urlcache|decode)\b/i,
            /\bbitsadmin(?:\.exe)?[^\n]{0,80}?\/transfer\b/i,
            /\bregsvr32(?:\.exe)?[^\n]{0,80}?(?:\/i:\s*https?:|scrobj\.dll)/i,
            /\brundll32(?:\.exe)?[^\n]{0,80}?(?:javascript:|https?:)/i,
            /\bmsiexec(?:\.exe)?[^\n]{0,80}?\/i\s+https?:/i,
            // finger.exe fetching a "reply" that is piped into cmd (4.7.0)
            /\bfinger(?:\.exe)?\s+\S+@\S+[^\n]{0,40}?\|\s*cmd\b/i,
            // hidden cmd launch
            /\bcmd(?:\.exe)?\s+\/c\s+start\s+\/(?:min|b)\b/i,
            // headless conhost (used to hide a spawned console window)
            /\bconhost(?:\.exe)?[^\n]{0,60}?--headless\b/i,
            // macOS (4.7.0)
            // AppleScript running a download or a shell command
            /\bosascript\b[^\n]{0,200}?(?:\bcurl\b|https?:|do shell script)/i,
            // quarantine flag removed in the same command line as a download
            /\b(?:curl|wget)\b[^\n]{0,240}?\bxattr\s+-[a-z]*[cd]/i,
            /\bxattr\s+-[a-z]*[cd][^\n]{0,240}?\b(?:curl|wget)\b/i,
            // Every OS with a POSIX shell (4.7.0)
            // base64 decoded straight into a shell
            /\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,80}?\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i,
            // download started in the background with its output thrown away
            /\bnohup\b[^\n]{0,200}?\b(?:curl|wget)\b[^\n]{0,200}?>\s*\/dev\/null/i,
            /\b(?:curl|wget)\b[^\n]{0,200}?\bnohup\b[^\n]{0,200}?>\s*\/dev\/null/i,
            // python one-liner downloading and executing
            /\bpython[0-9.]*\s+-c\b[^\n]{0,240}?urllib[^\n]{0,240}?\bexec\b/i,
        ];
        // FileFix (4.7.0): a long run of spaces on one line pushes the command
        // out of the visible part of the address bar. Strong when the text also
        // holds an execution marker or a '#' (the comment that hides the rest).
        const FILEFIX_PADDING = /[ \t\u00a0\u2000-\u200b\u3000]{40,}/;
        const FILEFIX_COMMENT = '#';
        const NEWLINE = '\n';
        // WEAK — also used by real install guides: blocked only together with
        // INSTRUCTION_PHRASES on the page.
        const WEAK_PATTERNS = [
            // curl/wget piped straight into a shell (rustup, nvm …)
            /\b(?:curl|wget)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i,
            // bash -c "$(curl …)" (Homebrew)
            /\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/i,
            // macOS quarantine flag removed (unsigned open-source apps document it)
            /\bxattr\s+-[a-z]*[cd][a-z]*\b[^\n]{0,60}?com\.apple\.quarantine/i,
            /\bxattr\s+-[a-z]*c[a-z]*\s/i,
            // download, make executable, run
            /\b(?:curl|wget)\b[^\n]{0,200}?\bchmod\s+(?:\+x|[0-7]{3,4})\b[^\n]{0,120}?(?:&&|;)\s*(?:\.\/|\/tmp\/|\$TMPDIR|~\/)/i,
        ];
        // Instructions only a ClickFix page shows (lower case; '+' compared without
        // the spaces around it — "Win + R" = "win+r").
        const INSTRUCTION_PHRASES = [
            'win+r', 'windows+r', 'windows key+r', '⊞+r', 'ctrl+v', 'cmd+v', '⌘+v',
            'cmd+space', 'command+space', '⌘+space', 'ctrl+alt+t', 'ctrl+shift+v',
            'alt+f2', 'verify you are human', 'verify you\'re human', 'i am not a robot',
            'i\'m not a robot', 'press enter', 'run dialog', 'open terminal',
            'open the terminal', 'open powershell', 'verification steps',
        ];
        const PLUS_SPACING = /\s*\+\s*/g;
        const APPLESCRIPT_SCHEME = 'applescript:';

        let warned = false;                  // guard: the warning is requested once per page

        function lower(s) { return reflectApply(strToLowerCase, s, []); }

        function firstMatch(patterns, text) {
            for ( const pattern of patterns ) {
                const m = reflectApply(regexExec, pattern, [ text ]);
                if ( m !== null ) { return m[0]; }
            }
            return null;
        }

        function pageShowsInstructions() {
            let text = '';
            try { text = toStr(reflectApply(textContentGet, doc.documentElement || doc, []) || ''); }
            catch { return false; }
            const head = reflectApply(strReplace, lower(reflectApply(strSlice, text, [ 0, MAX_PAGE_TEXT_CHARS ])), [ PLUS_SPACING, '+' ]);
            for ( const phrase of INSTRUCTION_PHRASES ) {
                if ( reflectApply(strIncludes, head, [ phrase ]) ) { return true; }
            }
            return false;
        }

        // → the matched text when the write must be blocked, else null.
        function looksLikeClickFix(text) {
            if ( typeof text !== 'string' || text === '' ) { return null; }
            const head = reflectApply(strSlice, text, [ 0, MAX_INSPECTED_CHARS ]);
            const lowerHead = lower(head);
            let cheapHit = false;
            for ( const marker of CHEAP_MARKERS ) {
                if ( reflectApply(strIncludes, lowerHead, [ marker ]) ) { cheapHit = true; break; }
            }
            // One line only: an address-bar payload is a single line, while code
            // copied from a documentation site (aligned comments) has several.
            if ( !reflectApply(strIncludes, head, [ NEWLINE ]) && reflectApply(regexTest, FILEFIX_PADDING, [ head ]) &&
                 (cheapHit || reflectApply(strIncludes, head, [ FILEFIX_COMMENT ])) ) {
                return 'FileFix padding';
            }
            if ( cheapHit === false ) { return null; }
            const strong = firstMatch(STRONG_PATTERNS, head);
            if ( strong !== null ) { return strong; }
            const weak = firstMatch(WEAK_PATTERNS, head);
            if ( weak !== null && pageShowsInstructions() ) { return weak + ' (with ClickFix instructions on the page)'; }
            return null;
        }

        function blocked(matched, via) {
            logWarn(`${LOG_PREFIX} clipboard write blocked (${via}) — looks like a ClickFix command payload: ${matched}. ` +
                'If this site is legitimate, add it to the 3P Matrix allow list (Options) to stop this check there.');
            if ( warned ) { return; }
            warned = true;
            try { reflectApply(dispatch, doc, [ new CustomEventCtor(CLICKFIX_BLOCKED_EVENT) ]); }
            catch { /* the block stands; only the warning is lost */ }
        }

        function isAppleScriptUrl(u) {
            const s = lower(reflectApply(strTrimStart, toStr(u ?? ''), []));
            return reflectApply(strSlice, s, [ 0, APPLESCRIPT_SCHEME.length ]) === APPLESCRIPT_SCHEME;
        }

        // ── 1. navigator.clipboard.writeText() ───────────────────────────
        const clipboard = navigator.clipboard;
        if ( clipboard && typeof clipboard.writeText === 'function' ) {
            clipboard.writeText = new Proxy(clipboard.writeText, {
                __proto__: null,
                apply(target, thisArg, args) {
                    const matched = looksLikeClickFix(toStr(args[0]));
                    if ( matched !== null ) {
                        blocked(matched, 'writeText');
                        // Resolve, not reject: a rejection is a signal the
                        // page can branch on to try another route.
                        return Promise.resolve();
                    }
                    return reflectApply(target, thisArg, args);
                },
            });
        }

        // ── 2. navigator.clipboard.write() (ClipboardItem) ───────────────
        // Text is inside a Blob here, so it cannot be inspected without
        // awaiting it. The payload still has to be text/plain to be
        // pasteable into a shell, so a text/plain item is read and checked.
        if ( clipboard && typeof clipboard.write === 'function' ) {
            clipboard.write = new Proxy(clipboard.write, {
                __proto__: null,
                async apply(target, thisArg, args) {
                    try {
                        const items = args[0];
                        for ( const item of (items ?? []) ) {
                            if ( item?.types?.includes('text/plain') !== true ) { continue; }
                            const text = await (await item.getType('text/plain')).text();
                            const matched = looksLikeClickFix(text);
                            if ( matched !== null ) { blocked(matched, 'write'); return; }
                        }
                    } catch {
                        // Unreadable item: fall through and let it proceed
                        // rather than breaking a legitimate write.
                    }
                    return reflectApply(target, thisArg, args);
                },
            });
        }

        // ── 3. The copy event (setData) ──────────────────────────────────
        // document.execCommand('copy') and programmatic copy events route
        // through here. Registered on window in the capture phase, before
        // any page listener, so the page cannot stop it first.
        window.addEventListener('copy', ev => {
            const dt = ev.clipboardData;
            if ( dt === null || typeof dt?.getData !== 'function' ) { return; }
            const matched = looksLikeClickFix(dt.getData('text/plain'));
            if ( matched === null ) { return; }
            blocked(matched, 'copy event');
            ev.preventDefault();
            ev.stopImmediatePropagation();
        }, true);

        // ── 4. macOS Script Editor links (4.7.0) ─────────────────────────
        window.addEventListener('click', ev => {
            const t = ev.target;
            if ( !(t instanceof ElementCtor) ) { return; }
            const a = reflectApply(closest, t, [ 'a[href]' ]);
            if ( a === null || !isAppleScriptUrl(reflectApply(getAttr, a, [ 'href' ])) ) { return; }
            blocked('applescript: link', 'link click');
            ev.preventDefault();
            ev.stopImmediatePropagation();
        }, true);
        if ( typeof window.open === 'function' ) {
            window.open = new Proxy(window.open, {
                __proto__: null,
                apply(target, thisArg, args) {
                    if ( isAppleScriptUrl(args[0]) ) { blocked('applescript: address', 'window.open'); return null; }
                    return reflectApply(target, thisArg, args);
                },
            });
        }
    } catch {
        // Never break the page: a protection that throws at document_start
        // would be worse than one that is absent.
    }
})();

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-notification-prompts.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * sec-notification-prompts.js — Security scriptlet: blockNotificationPrompts toggle (3P Matrix 4.6.0)
 * "Block notification prompts that appear without a click" — outside safer regions, from level 3.
 *
 * Fake "click Allow to continue" pages ask for notification permission the moment they load; one click and the
 * desktop keeps showing fake virus alerts and prize messages. Real sites usually ask after the user presses a
 * bell or "turn on notifications" button. So a request made WITHOUT a click (no transient user activation) is
 * answered without showing Chrome's prompt:
 *   Notification.requestPermission()  → "default" (also to the legacy callback), as if the user dismissed it
 *   PushManager.prototype.subscribe() → rejected with NotAllowedError
 * With a click, both behave exactly as before. Chrome is testing the same rule ("gesture-gated prompts",
 * Canary 2026); this applies it now.
 *
 * Captured builtins (C35); Proxy handlers with `__proto__: null`. World: MAIN, all frames, document_start.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── LOG_PREFIX: copy of data/constants.js (MAIN world cannot import); kept equal by
    // tools/check-shipped-terms.mjs.
    const LOG_PREFIX = '[3PMCF]';
    const PERMISSION_DEFAULT = 'default';                        // "not decided" — what a dismissed prompt returns
    const NOT_ALLOWED = 'NotAllowedError';

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    const logInfo = console.info.bind(console);
    const { apply, getOwnPropertyDescriptor, getPrototypeOf } = Reflect;
    const PromiseResolve = Promise.resolve.bind(Promise);
    const PromiseReject = Promise.reject.bind(Promise);
    const DOMExceptionCtor = DOMException;
    const userActivation = navigator.userActivation || null;
    const activationGet = userActivation ? getOwnPropertyDescriptor(getPrototypeOf(userActivation), 'isActive').get : null;
    function clickedNow() { return activationGet ? !!apply(activationGet, userActivation, []) : true; }  // no API: do not interfere

    if (typeof Notification === 'function' && typeof Notification.requestPermission === 'function') {
        Notification.requestPermission = new Proxy(Notification.requestPermission, { __proto__: null, apply: function(target, self, args) {
            if (clickedNow()) return apply(target, self, args);
            logInfo(LOG_PREFIX + ' blocked a notification prompt without a click');
            if (typeof args[0] === 'function') { try { args[0](PERMISSION_DEFAULT); } catch { /* page callback threw */ } }
            return PromiseResolve(PERMISSION_DEFAULT);
        } });
    }
    if (typeof PushManager === 'function' && typeof PushManager.prototype.subscribe === 'function') {
        PushManager.prototype.subscribe = new Proxy(PushManager.prototype.subscribe, { __proto__: null, apply: function(target, self, args) {
            if (clickedNow()) return apply(target, self, args);
            logInfo(LOG_PREFIX + ' blocked a push subscription without a click');
            return PromiseReject(new DOMExceptionCtor('push subscription without a click blocked by 3P Matrix', NOT_ALLOWED));
        } });
    }
})();

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-payment-handlers.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * sec-payment-handlers.js — Security scriptlet: blockPaymentHandlers toggle
 *
 * Blocks a website from installing itself as a payment handler: the
 * `registration.paymentManager` API (PaymentManager / PaymentInstruments) of a
 * service worker registration is removed, so a page that feature-detects it
 * sees "not supported". Paying through PaymentRequest (Google Pay, Apple Pay,
 * card forms) is NOT touched — only the installing side is.
 *
 * Plain on/off ("Safe privacy and security enhancements" group, default on):
 * no Worry-free relationship and no tier — same shape as sec-pings.js. A
 * scriptlet, not a header rule, so the toolbar badge count stays accurate
 * (an all-sites modifyHeaders rule would count on the badge like a real block).
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 * World:         MAIN, all frames, document_start
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    // Taken at injection (document_start, before any page script). Proxy
    // handlers use `__proto__: null` so a page cannot intercept the trap
    // lookup through Object.prototype.
    const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const defineProperty = Object.defineProperty;
    const deleteProperty = Reflect.deleteProperty;
    const logInfo = console.info.bind(console);

    const registrationProto = window.ServiceWorkerRegistration?.prototype;
    if ( registrationProto === undefined ) { return; }
    const descriptor = getOwnPropertyDescriptor(registrationProto, 'paymentManager');
    if ( descriptor === undefined ) { return; }

    // Preferred: delete the property, so `'paymentManager' in registration`
    // is false and feature detection fails cleanly.
    if ( deleteProperty(registrationProto, 'paymentManager') ) {
        logInfo(LOG_PREFIX + ' removed registration.paymentManager (payment handler install blocked)');
        return;
    }
    // Fallback (non-configurable property): a getter that returns nothing.
    if ( typeof descriptor.get === 'function' ) {
        defineProperty(registrationProto, 'paymentManager', {
            configurable: descriptor.configurable,
            enumerable: descriptor.enumerable,
            get: new Proxy(descriptor.get, { __proto__: null, apply: function() {
                logInfo(LOG_PREFIX + ' blocked registration.paymentManager read');
                return undefined;
            } }),
        });
    }
})();

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
// ── part: sec-protocol-handlers.js (until 5.1.2 a separate file) ──
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
/*
 * sec-protocol-handlers.js — Security scriptlet: blockProtocolHandlers toggle
 *
 * Blocks a website from registering itself as the handler for a link scheme
 * (mailto:, web+something, ...): navigator.registerProtocolHandler() becomes a
 * silent no-op, so the browser's "use this site to open mailto links" offer is
 * never shown. Opening such links with an already-registered handler, and
 * navigator.unregisterProtocolHandler(), are not touched.
 *
 * Worry-free-gated, tier `extra` ("Very low website breakage risk" group):
 * active only during a running Worry-free session with the "extra" box ticked
 * and its own checkbox not unticked (worryFreeGatedOptOut).
 *
 * Registered by: js/core/compiled-filters.js (SECURITY_SCRIPTLETS)
 * Injected by:   js/core/scripting-manager.js (registerSecurityContentScripts)
 * World:         MAIN, all frames, document_start
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of data/constants.js LOG_PREFIX: MAIN-world scripts cannot
    // import it. Kept equal by tools/check-shipped-terms.mjs (fails on any difference).
    const LOG_PREFIX = '[3PMCF]';

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    // Same approach as sec-battery.js: take what is needed at injection, and
    // give the Proxy a `__proto__: null` handler so a page cannot intercept the
    // trap lookup through Object.prototype.
    const logInfo = console.info.bind(console);
    const navigatorProto = Object.getPrototypeOf(navigator);
    if ( typeof navigatorProto.registerProtocolHandler === 'function' ) {
        navigatorProto.registerProtocolHandler = new Proxy(navigatorProto.registerProtocolHandler, { __proto__: null, apply: function() {
            logInfo(LOG_PREFIX + ' blocked navigator.registerProtocolHandler');
            return undefined;
        } });
    }
})();
