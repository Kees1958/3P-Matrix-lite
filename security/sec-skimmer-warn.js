/*
 * sec-skimmer-warn.js — warnPaymentSkimmer (3P Matrix 5.0.2), MAIN-world half.
 *
 * "SuperPixel"/Magecart card-skimming scam: a compromised or malicious checkout page runs a script that
 * disguises itself as a well-known analytics loader to blend in, and/or draws its own payment-entry box over
 * (or instead of) the site's real one — in both cases to quietly copy card details as the shopper types them.
 *
 * TWO independent, cheap signals; either one alone triggers the warning:
 *   1. FAKE PIXEL LOADER — a <script src> whose path is the Facebook Pixel loader's own filename (fbevents.js)
 *      but is NOT served from one of Facebook's own hosts. A real site includes the real loader straight from
 *      connect.facebook.net; a skimmer imitates the filename from an attacker-controlled host so the request
 *      reads as ordinary marketing-pixel noise in the network tab.
 *   2. PAYMENT OVERLAY — an <iframe> that is NOT same-origin with the top page and whose on-screen box overlaps
 *      a field that looks like a card-payment field (autocomplete="cc-number" and siblings, or a name/id naming
 *      a card/cvv/cvc field). A real payment processor's iframe (Stripe Elements, Adyen, …) is also cross-origin
 *      — the overlap with a field the PAGE already has for the same purpose is what is unusual: a legitimate
 *      processor iframe IS the field, it does not sit on top of another one.
 *
 * Warn-only by design (never blocks): the detector only reports what it saw; the service worker opens the red
 * warning page (core/page-scam-guard.js), same as ClickFix/ConsentFix. Originally (mistakenly) built for the
 * sibling uBlock-Stripped-Dynamic project as an in-page banner; ported here, where it belongs, as a full warning
 * page instead — this project already has that machinery (C21 reuse), so no new UI was written for it.
 *
 * Cost: nothing until a payment-looking field is focused (check 2) or the page finishes loading (check 1, once)
 * — same "nothing until something relevant happens" cost model as the other MAIN-world scriptlets in this
 * directory (sec-clickfix-clipboard.js, fake-window-guard.js).
 * Accepted false positive: a legitimate analytics proxy that happens to re-host fbevents.js under its own domain
 * (rare — real pixel proxies keep the real host via a rewrite, not a re-host). Accepted false negative: a
 * skimmer that skips the pixel-impersonation step and only draws the overlay, or vice versa — either signal
 * alone warns, so only a skimmer using NEITHER signal is missed; one injected after 'load' with no field ever
 * focused is also missed (check 1 does not re-run on a MutationObserver — kept out on purpose, see B6/cost note
 * above; check 2 already re-runs on every relevant focusin, so a late overlay is still caught once a shopper
 * reaches the field).
 *
 * Hardened per C35 (Xplainer programming principles): every builtin it relies on is captured at injection
 * (document_start, before any page script). No builtin is replaced here (only read), so no Proxy is needed.
 * World: MAIN, all frames, document_start. Classic script (content scripts cannot import).
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copy of security/skimmer-bridge.js's event name (MAIN-world scripts cannot
    // import); kept equal to its source by check-shipped-terms.mjs (SHARED_SCRIPT_CONSTS).
    const LOG_PREFIX = '[3PMCF]';
    const SKIMMER_BLOCKED_EVENT = '3pmcf-skimmer-blocked';

    try {
        // ── Captured builtins (C35) ──────────────────────────────────────
        const reflectApply = Reflect.apply;
        const strIncludes = String.prototype.includes;
        const strToLowerCase = String.prototype.toLowerCase;
        const toStr = String;
        const logWarn = console.warn.bind(console);
        const querySelectorAll = Document.prototype.querySelectorAll;
        const getAttr = Element.prototype.getAttribute;
        const closest = Element.prototype.closest;
        const getBoundingClientRect = Element.prototype.getBoundingClientRect;
        const dispatch = EventTarget.prototype.dispatchEvent;
        const CustomEventCtor = CustomEvent;
        const URLCtor = URL;
        const HTMLInputElementCtor = HTMLInputElement;
        const doc = document;
        const win = window;
        const loc = location;
        const addEventListenerFn = EventTarget.prototype.addEventListener;

        // ── CONFIG ───────────────────────────────────────────────────────
        // Check 1 — fake Facebook Pixel loader.
        const PIXEL_LOADER_FILENAME = 'fbevents.js';
        const REAL_PIXEL_HOSTS = Object.freeze(['connect.facebook.net']);
        // Check 2 — payment-field overlay. Matches the field itself (via closest()), not a container.
        const PAYMENT_FIELD_SELECTOR =
            'input[autocomplete="cc-number"],input[autocomplete="cc-exp"],input[autocomplete="cc-exp-month"],' +
            'input[autocomplete="cc-exp-year"],input[autocomplete="cc-csc"],' +
            'input[name*="card" i],input[id*="card" i],input[name*="cvv" i],input[id*="cvv" i],' +
            'input[name*="cvc" i],input[id*="cvc" i]';
        const MAX_IFRAMES_CHECKED = 50;   // bounds the overlap scan on a pathological page

        let warned = false;               // guard: the warning is requested once per page

        function lower(s) { return reflectApply(strToLowerCase, toStr(s), []); }

        function hostOf(url) {
            try { return reflectApply(strToLowerCase, new URLCtor(url, doc.baseURI).hostname, []); }
            catch { return ''; }
        }

        function warn() {
            if (warned) return;
            warned = true;
            logWarn(`${LOG_PREFIX} payment-skimmer signal found on this page. If this site is legitimate, add it to the 3P Matrix allow list (Options) to stop this check there.`);
            try { reflectApply(dispatch, doc, [ new CustomEventCtor(SKIMMER_BLOCKED_EVENT) ]); }
            catch { /* the detection stands; only the warning page is lost */ }
        }

        // ── Check 1 — fake Facebook Pixel loader ─────────────────────────
        function checkFakePixelLoader() {
            if (warned) return;
            let scripts;
            try { scripts = reflectApply(querySelectorAll, doc, [ 'script[src]' ]); } catch { return; }
            for ( const el of scripts ) {
                let src = '';
                try { src = toStr(reflectApply(getAttr, el, [ 'src' ]) || ''); } catch { continue; }
                if ( !reflectApply(strIncludes, lower(src), [ PIXEL_LOADER_FILENAME ]) ) continue;
                const host = hostOf(src);
                if ( host && !REAL_PIXEL_HOSTS.includes(host) ) { warn(); return; }
            }
        }

        // ── Check 2 — payment overlay iframe ─────────────────────────────
        function overlaps(a, b) {
            return a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
        }

        function checkPaymentOverlay(field) {
            if (warned) return;
            let fieldRect;
            try { fieldRect = reflectApply(getBoundingClientRect, field, []); } catch { return; }
            if ( fieldRect.width <= 0 || fieldRect.height <= 0 ) return;
            let iframes;
            try { iframes = reflectApply(querySelectorAll, doc, [ 'iframe' ]); } catch { return; }
            let checked = 0;
            for ( const frame of iframes ) {
                if ( checked++ >= MAX_IFRAMES_CHECKED ) break;
                let src = '';
                try { src = toStr(reflectApply(getAttr, frame, [ 'src' ]) || ''); } catch { continue; }
                if ( !src ) continue;                                    // same-doc/about:blank iframe: not this vector
                const host = hostOf(src);
                if ( !host || host === loc.hostname ) continue;          // same-origin: not what this check is for
                let frameRect;
                try { frameRect = reflectApply(getBoundingClientRect, frame, []); } catch { continue; }
                if ( overlaps(fieldRect, frameRect) ) { warn(); return; }
            }
        }

        // 5.0.7 (C47): on window, capture — a page's own window-capture listener cannot stop focusin before this.
        reflectApply(addEventListenerFn, win, [ 'focusin', (e) => {
            const field = e.target;
            if ( !(field instanceof HTMLInputElementCtor) ) return;
            let matches = false;
            try { matches = reflectApply(closest, field, [ PAYMENT_FIELD_SELECTOR ]) === field; } catch { return; }
            if ( !matches ) return;
            checkFakePixelLoader();
            checkPaymentOverlay(field);
        }, true ]);

        // Check 1 also runs once, lazily, independent of any field being focused — a page can load the fake
        // pixel script long before (or without) the shopper ever reaching the payment step.
        if ( doc.readyState === 'complete' ) { checkFakePixelLoader(); }
        else { reflectApply(addEventListenerFn, win, [ 'load', () => checkFakePixelLoader(), { once: true } ]); }
    } catch {
        // Never break the page: a protection that throws at document_start would be worse than one that is absent.
    }
})();
