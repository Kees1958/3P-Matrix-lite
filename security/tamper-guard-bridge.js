/*
 * tamper-guard-bridge.js — watchTamperSensitive (3P Matrix 5.1.0), ISOLATED-world half of Tamper Guard.
 *
 * 1. Hello (top frame only): asks the service worker whether this page is to be watched closely right away (a known
 *    banking/payment site, "Always watch", or the same site within the cooldown) — core/tamper-guard.js decides.
 * 2. Signals: at DOMContentLoaded, load and SIGNALS_RECHECK_MS after load, looks for card fields, bank-account
 *    fields and frames from other hosts and sends them ONLY when a card or bank field is present or the page
 *    embeds a frame (the service worker scores them against the built-in Payment list). 5.1.3: `hidden` — a password/card
 *    field HIDDEN AS A TRICK (isTrickHidden: a type=hidden field named like a password or card field, or a field that is
 *    itself invisible while the element around it is visible — not a field inside a closed menu, dialog or step); a
 *    trigger for the closer watching, when the user ticked it. An ordinary page without
 *    them sends nothing — no service-worker wake-up per page. 5.1.2: `cardNumber` — a card-NUMBER field in this
 *    frame (named like one, gift cards excluded, or a typed value that is a card number: 13–19 digits, valid Luhn
 *    checksum); the service worker combines it with a payment provider's frame (tgSecondCardForm). A typed card
 *    number is noticed on the field's change event (window, capture) and sends the signals again.
 * 3. Reports: forwards the MAIN-world half's TG_REPORT_EVENT (security/tamper-guard-page.js) after checking its
 *    shape and size (C50); the service worker validates it again against data/tamper-rules.js (C46).
 * 4. Arming: on the service worker's answer { arm: true } or its MSG_TAMPER_ARM message, tells the MAIN-world half
 *    (TG_ARM_EVENT) and starts this half's own closer watching: ONE MutationObserver (allowlisted in
 *    tools/test-message-gate.mjs with these limits) on the document, childList + subtree + the attributes action,
 *    formaction and integrity only; at most MAX_RECORDS_PER_BATCH records and MAX_NODES_PER_BATCH added elements per
 *    callback; disconnected on pagehide. It reports: a sign-in/payment form whose destination changed
 *    (tgFormChanged), a hidden password/card field added (tgHiddenCredential), an invisible frame added
 *    (tgInvisibleFrame) and a script whose integrity attribute was removed or changed (tgIntegrityRemoved). 5.1.2: the
 *    hosts of other sites' scripts (already on the page when armed, and added later) — at most MAX_SCRIPT_HOSTS per
 *    page, batched per scan; the service worker scores them (tgSuspiciousScript). Only host names leave this script,
 *    never a field value.
 *
 * 5. 5.1.3: forwards security/sec-no-obfuscated-code.js's block event as tgObfuscatedCode (once per entry point).
 *
 * Trust: runs in the ISOLATED world (its own built-ins, the page cannot replace them). The service worker takes the
 * page and tab from the message SENDER only (C28). A page can fake TG_REPORT_EVENT about itself; at most
 * MAX_REPORTS_PER_PAGE reports per page are forwarded (guard against a page flooding the service worker).
 * Listeners: window, capture, registered at document_start (C47). World: ISOLATED, all frames, document_start.
 * Classic script (content scripts cannot import).
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies of shared values (this script cannot import); kept equal to their sources by
    // tools/check-shipped-terms.mjs: LOG_PREFIX (data/constants.js), MSG_* (data/message-types.js), the event names
    // (security/tamper-guard-page.js); PAGE_RULES and the limits by tools/test-tamper-guard.mjs (data/tamper-rules.js,
    // data/constants.js TAMPER_DETAIL_ITEMS_MAX / TAMPER_DETAIL_TEXT_MAX / TAMPER_FRAME_HOSTS_MAX).
    const LOG_PREFIX = '[3PMCF]';
    const MSG_TAMPER_HELLO = 'TAMPER_HELLO';
    const MSG_TAMPER_SIGNALS = 'TAMPER_SIGNALS';
    const MSG_TAMPER_REPORT = 'TAMPER_REPORT';
    const MSG_TAMPER_ARM = 'TAMPER_ARM';
    const TG_REPORT_EVENT = '3pmcf-tg-report';
    const TG_ARM_EVENT = '3pmcf-tg-arm';
    const PAGE_RULES = Object.freeze(['tgDataParsing', 'tgNetworkHooks', 'tgFunctionHooks', 'tgPrototypePollution', 'tgArrayExtended',
        'tgCryptoHooks', 'tgInputHooks', 'tgStorageHooks', 'tgDataEdited', 'tgPasswordSent', 'tgCardSent', 'tgFormChanged',
        'tgHiddenCredential', 'tgInvisibleFrame', 'tgIntegrityRemoved', 'tgSuspiciousScript', 'tgAddressScript', 'tgIbanSent',
        'tgObfuscatedCode']);
    const RULE = Object.freeze({ FORM_CHANGED: 'tgFormChanged', HIDDEN_CREDENTIAL: 'tgHiddenCredential',
                                 INVISIBLE_FRAME: 'tgInvisibleFrame', INTEGRITY_REMOVED: 'tgIntegrityRemoved',
                                 SUSPICIOUS_SCRIPT: 'tgSuspiciousScript', OBFUSCATED_CODE: 'tgObfuscatedCode' });
    // 5.1.3 — security/sec-no-obfuscated-code.js's block event (= its TG_OBFUSCATED_EVENT); detail = the entry point.
    const TG_OBFUSCATED_EVENT = '3pmcf-tg-obfuscated';
    const OBFUSCATED_SINKS = Object.freeze(['eval', 'Function', 'setTimeout', 'setInterval']);   // = OBFUSCATED_CODE.sinks
    const DETAIL_KIND = Object.freeze({ TARGETS: 'targets', KEYS: 'keys', DEST: 'dest' });
    const MAX_REPORTED_ITEMS = 12;            // = TAMPER_DETAIL_ITEMS_MAX
    const MAX_ITEM_CHARS = 120;               // = TAMPER_DETAIL_TEXT_MAX
    const MAX_FRAME_HOSTS = 20;               // = TAMPER_FRAME_HOSTS_MAX
    const MAX_SCRIPT_HOSTS = 24;              // = TAMPER_SCRIPT_HOSTS_MAX: other sites' script hosts reported per page
    const MAX_DETAIL_CHARS = 4096;            // a report event larger than this is not read (C50)
    const MAX_REPORTS_PER_PAGE = 40;          // forwarded reports per page (flood guard)
    const SIGNALS_RECHECK_MS = 3000;          // single-page checkouts build their card form late
    const MAX_RECORDS_PER_BATCH = 200;        // MutationObserver records handled per callback (rest ignored)
    const MAX_NODES_PER_BATCH = 100;          // added elements inspected per callback
    const INVISIBLE_MAX_PX = 2;               // a frame or field this small (or hidden) counts as invisible
    const CARD_SELECTOR = 'input[autocomplete^="cc-"], input[name*="cardnumber" i], input[name*="card_number" i], input[id*="cardnumber" i], input[name*="ccnum" i], input[name*="cvc" i], input[name*="cvv" i]';
    // 5.1.2 — a field for the card NUMBER itself (not name/expiry/code), gift-card numbers excluded.
    const CARD_NUMBER_SELECTOR = 'input[autocomplete="cc-number"], input[name*="cardnumber" i]:not([name*="gift" i]), input[name*="card_number" i]:not([name*="gift" i]), input[id*="cardnumber" i]:not([id*="gift" i]), input[name*="ccnum" i]';
    // A card number by its value (= data/constants.js TAMPER_CARD_VALUE_DIGITS / TAMPER_CARD_VALUE_FIELDS_MAX).
    const CARD_VALUE_DIGITS_MIN = 13;
    const CARD_VALUE_DIGITS_MAX = 19;
    const CARD_VALUE_FIELDS_MAX = 50;
    const CARD_VALUE_RE = /^[\d \-]+$/;
    const NON_DIGIT_RE = /\D+/g;
    const VALUE_SCAN_SELECTOR = 'input:not([type]), input[type="text"], input[type="tel"], input[type="number"]';
    const LUHN = Object.freeze({ BASE: 10, DOUBLE: 2, FOLD: 9 });
    const CHAR_CODE_ZERO = 48;
    const BANK_SELECTOR = 'input[name*="iban" i], input[id*="iban" i], input[autocomplete*="iban" i]';
    const CREDENTIAL_SELECTOR = 'input[type="password"], ' + CARD_SELECTOR;
    // 5.1.3 — "Enable when a hidden password or card field is added": checked with the other signals (no observer on
    // unarmed pages); at most HIDDEN_FIELDS_MAX candidate fields are measured per check.
    const HIDDEN_FIELDS_MAX = 20;
    // 5.1.3 (issue 4, user decision 2026-11-24) — only a field HIDDEN AS A TRICK counts (isTrickHidden):
    //   a. a type=hidden field named like a password field (HIDDEN_PASSWORD_SELECTOR) or a card field (CARD_SELECTOR);
    //      names of one-time tokens (HIDDEN_NAME_EXCLUDE_RE: "reset_password_token", CSRF) are page plumbing, not a trick;
    //   b. a password/card field that is ITSELF invisible (its own display/visibility/opacity, at most INVISIBLE_MAX_PX,
    //      or placed entirely off the page) while the element around it (its parent) is visible. A field inside a closed
    //      menu, dialog or sign-in step is hidden with its surroundings — that is layout, not a trick, and never counts.
    const HIDDEN_PASSWORD_SELECTOR = 'input[type="hidden"][name*="password" i], input[type="hidden"][id*="password" i], ' +
                                     'input[type="hidden"][name*="passwd" i], input[type="hidden"][name*="pwd" i]';
    const HIDDEN_CANDIDATE_SELECTOR = CREDENTIAL_SELECTOR + ', ' + HIDDEN_PASSWORD_SELECTOR;
    const HIDDEN_NAME_EXCLUDE_RE = /token|csrf|nonce/i;
    const VISIBILITY_CHECK = Object.freeze({ opacityProperty: true, visibilityProperty: true });   // Element.checkVisibility
    const FRAME_SELECTOR = 'iframe[src]';
    const SCRIPT_SELECTOR = 'script[src]';
    const WATCHED_ATTRIBUTES = Object.freeze(['action', 'formaction', 'integrity']);
    const IS_TOP = window.top === window;

    let armed = false;
    let observer = null;
    let reportsLeft = MAX_REPORTS_PER_PAGE;
    let recheckTimer = null;
    let lastSignals = '';                      // guard: the same signals are not sent twice
    const obfuscatedSinks = new Set();         // 5.1.3: entry points already reported (at most OBFUSCATED_SINKS.length)
    const scriptHosts = new Set();             // 5.1.2: other sites' script hosts already reported (cap MAX_SCRIPT_HOSTS)
    let newScriptHosts = [];                   // found in the current scan, sent at its end

    // Every reply may say { arm: true } — the service worker decided to watch this page closely.
    function onReply(promise) {
        promise.then((res) => { if (res && res.ok && res.data && res.data.arm === true) arm(); })
            .catch((err) => console.warn(LOG_PREFIX, 'Tamper Guard message failed', err));
    }

    // ── Reports ──
    function cleanItems(items) {
        if (!Array.isArray(items)) return null;
        const out = [];
        for (const it of items) {
            if (typeof it !== 'string' || !it) continue;
            out.push(it.slice(0, MAX_ITEM_CHARS));
            if (out.length >= MAX_REPORTED_ITEMS) break;
        }
        return out.length ? out : null;
    }
    function forward(rule, kind, items) {
        if (reportsLeft <= 0 || !PAGE_RULES.includes(rule) || !Object.values(DETAIL_KIND).includes(kind)) return;
        const clean = cleanItems(items);
        if (!clean) return;
        reportsLeft--;
        onReply(chrome.runtime.sendMessage({ type: MSG_TAMPER_REPORT, rule, detail: { kind, items: clean } }));
    }
    window.addEventListener(TG_REPORT_EVENT, (e) => {
        const raw = e && typeof e.detail === 'string' ? e.detail : '';
        if (!raw || raw.length > MAX_DETAIL_CHARS) return;
        let data;
        try { data = JSON.parse(raw); } catch { return; }
        if (data && typeof data === 'object') forward(data.rule, data.kind, data.items);
    }, true);

    // 5.1.3 — obfuscated code was blocked: reported once per entry point. Owner 2026-11-24: only on a page that is
    // watched closely — before arming the entry point is only remembered (obfuscatedSinks) and sent on arm().
    // (The block itself, security/sec-no-obfuscated-code.js, works everywhere regardless.)
    function sendObfuscated() {
        if (armed && obfuscatedSinks.size) forward(RULE.OBFUSCATED_CODE, DETAIL_KIND.TARGETS, [...obfuscatedSinks]);
    }
    window.addEventListener(TG_OBFUSCATED_EVENT, (e) => {
        const sink = e && typeof e.detail === 'string' ? e.detail : '';
        if (!OBFUSCATED_SINKS.includes(sink) || obfuscatedSinks.has(sink)) return;
        obfuscatedSinks.add(sink);
        if (armed) forward(RULE.OBFUSCATED_CODE, DETAIL_KIND.TARGETS, [sink]);
    }, true);

    // ── Signals (banking/payment page?) ──
    function hostOf(url) {
        try { return new URL(url, location.href).hostname; } catch { return ''; }
    }
    function luhnValid(digits) {
        let sum = 0;
        let doubled = false;
        for (let i = digits.length - 1; i >= 0; i--) {
            let d = digits.charCodeAt(i) - CHAR_CODE_ZERO;
            if (doubled) { d *= LUHN.DOUBLE; if (d > LUHN.FOLD) d -= LUHN.FOLD; }
            sum += d;
            doubled = !doubled;
        }
        return sum % LUHN.BASE === 0;
    }
    function isCardValue(v) {
        if (typeof v !== 'string' || !CARD_VALUE_RE.test(v)) return false;
        const digits = v.replace(NON_DIGIT_RE, '');
        return digits.length >= CARD_VALUE_DIGITS_MIN && digits.length <= CARD_VALUE_DIGITS_MAX && luhnValid(digits);
    }
    function hasTypedCardNumber() {
        const list = document.querySelectorAll(VALUE_SCAN_SELECTOR);
        for (let i = 0; i < list.length && i < CARD_VALUE_FIELDS_MAX; i++) if (isCardValue(list[i].value)) return true;
        return false;
    }
    function collectSignals() {
        try {
            const cardNumber = !!document.querySelector(CARD_NUMBER_SELECTOR) || hasTypedCardNumber();
            const card = cardNumber || !!document.querySelector(CARD_SELECTOR);
            const bank = !!document.querySelector(BANK_SELECTOR);
            const hidden = hasHiddenCredential();                     // 5.1.3
            const frames = [];
            for (const f of document.querySelectorAll(FRAME_SELECTOR)) {
                const h = hostOf(f.getAttribute('src'));
                if (h && h !== location.hostname && !frames.includes(h)) frames.push(h);
                if (frames.length >= MAX_FRAME_HOSTS) break;
            }
            if (!card && !bank && !hidden && !frames.length) return;
            const key = JSON.stringify([card, cardNumber, bank, hidden, frames]);
            if (key === lastSignals) return;
            lastSignals = key;
            onReply(chrome.runtime.sendMessage({ type: MSG_TAMPER_SIGNALS, card, cardNumber, bank, hidden, frames }));
        } catch (err) { console.warn(LOG_PREFIX, 'Tamper Guard signals failed', err); }
    }

    // ── Closer watching (armed pages only) ──
    function invisible(el) {
        try {
            const r = el.getBoundingClientRect();
            const cs = getComputedStyle(el);
            return (r.width <= INVISIBLE_MAX_PX && r.height <= INVISIBLE_MAX_PX) || cs.visibility === 'hidden' ||
                   cs.display === 'none' || Number(cs.opacity) === 0;
        } catch { return false; }
    }
    // Placed entirely outside the page (left: -9999px and the like).
    function offPage(el) {
        try {
            const r = el.getBoundingClientRect();
            return r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0;
        } catch { return false; }
    }
    // The element itself can be seen (it and every ancestor shown, not transparent, larger than INVISIBLE_MAX_PX).
    function seen(el) {
        try {
            if (!el.checkVisibility(VISIBILITY_CHECK)) return false;
            const r = el.getBoundingClientRect();
            return r.width > INVISIBLE_MAX_PX && r.height > INVISIBLE_MAX_PX;
        } catch { return false; }
    }
    // Issue 4: a password/card field hidden as a trick (see HIDDEN_PASSWORD_SELECTOR above).
    function isTrickHidden(el) {
        try {
            if (!el.matches(HIDDEN_CANDIDATE_SELECTOR)) return false;
            if (el.type === 'hidden') return !HIDDEN_NAME_EXCLUDE_RE.test(`${el.name || ''} ${el.id || ''}`);
            const around = el.parentElement;
            return !!around && seen(around) && (invisible(el) || offPage(el));
        } catch { return false; }
    }
    function hasHiddenCredential() {
        const list = document.querySelectorAll(HIDDEN_CANDIDATE_SELECTOR);
        for (let i = 0; i < list.length && i < HIDDEN_FIELDS_MAX; i++) {
            if (isTrickHidden(list[i])) return true;
        }
        return false;
    }
    function formHasCredential(form) {
        try { return !!form.querySelector(CREDENTIAL_SELECTOR); } catch { return false; }
    }
    function noteScript(el) {
        if (scriptHosts.size >= MAX_SCRIPT_HOSTS) return;
        const h = hostOf(el.getAttribute('src') || '');
        if (!h || h === location.hostname || scriptHosts.has(h)) return;
        scriptHosts.add(h);
        newScriptHosts.push(h);
    }
    function flushScripts() {
        while (newScriptHosts.length) forward(RULE.SUSPICIOUS_SCRIPT, DETAIL_KIND.DEST, newScriptHosts.splice(0, MAX_REPORTED_ITEMS));
    }
    function scanScripts() {
        try { for (const el of document.querySelectorAll(SCRIPT_SELECTOR)) noteScript(el); } catch { /* never the page's problem */ }
        flushScripts();
    }
    function inspectAdded(el) {
        if (el.tagName === 'SCRIPT') {
            noteScript(el);
        } else if (el.tagName === 'IFRAME') {
            const h = hostOf(el.getAttribute('src') || '');
            if (h && h !== location.hostname && invisible(el)) forward(RULE.INVISIBLE_FRAME, DETAIL_KIND.DEST, [h]);
        } else if (el.tagName === 'INPUT' && isTrickHidden(el)) {                   // issue 4
            forward(RULE.HIDDEN_CREDENTIAL, DETAIL_KIND.DEST, [location.hostname]);
        }
    }
    function onMutations(records) {
        let nodes = 0;
        for (let i = 0; i < records.length && i < MAX_RECORDS_PER_BATCH; i++) {
            const r = records[i];
            if (r.type === 'attributes') {
                const el = r.target;
                if (r.attributeName === 'integrity' && el.tagName === 'SCRIPT') {
                    if (r.oldValue && el.getAttribute('integrity') !== r.oldValue) {
                        forward(RULE.INTEGRITY_REMOVED, DETAIL_KIND.DEST, [hostOf(el.getAttribute('src') || '') || location.hostname]);
                    }
                    continue;
                }
                const form = el.tagName === 'FORM' ? el : el.form;
                const dest = hostOf(el.getAttribute(r.attributeName) || '');
                if (form && dest && dest !== location.hostname && formHasCredential(form)) forward(RULE.FORM_CHANGED, DETAIL_KIND.DEST, [dest]);
                continue;
            }
            for (const n of r.addedNodes) {
                if (nodes >= MAX_NODES_PER_BATCH) { flushScripts(); return; }
                if (n.nodeType !== Node.ELEMENT_NODE) continue;
                nodes++;
                inspectAdded(n);
                for (const inner of n.querySelectorAll('iframe, input, script[src]')) {
                    if (nodes >= MAX_NODES_PER_BATCH) { flushScripts(); return; }
                    nodes++;
                    inspectAdded(inner);
                }
            }
        }
        flushScripts();
    }
    function startObserver() {
        if (observer || !document.documentElement) return;
        scanScripts();                                               // scripts already on the page when armed
        observer = new MutationObserver(onMutations);
        observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true,
                                                      attributeFilter: [...WATCHED_ATTRIBUTES], attributeOldValue: true });
    }
    function arm() {
        if (armed) return;
        armed = true;
        window.dispatchEvent(new CustomEvent(TG_ARM_EVENT));      // the MAIN-world half starts its wrappers
        sendObfuscated();                                          // what was blocked before arming
        if (document.documentElement) startObserver();
        else window.addEventListener('DOMContentLoaded', startObserver, { capture: true, once: true });
    }

    // ── Wiring (window, capture, document_start — C47) ──
    chrome.runtime.onMessage.addListener((msg, sender) => {
        if (sender && sender.id === chrome.runtime.id && !sender.tab && msg && msg.type === MSG_TAMPER_ARM) arm();
        return false;
    });
    window.addEventListener('DOMContentLoaded', collectSignals, true);
    window.addEventListener('change', (e) => {                          // 5.1.2: a card number typed into any field
        const t = e && e.target;
        if (t && t.tagName === 'INPUT' && isCardValue(t.value)) collectSignals();
    }, true);
    window.addEventListener('load', () => {
        collectSignals();
        recheckTimer = setTimeout(() => { recheckTimer = null; collectSignals(); }, SIGNALS_RECHECK_MS);
    }, true);
    window.addEventListener('pagehide', () => {                       // release (B10)
        if (observer) { observer.disconnect(); observer = null; }
        if (recheckTimer !== null) { clearTimeout(recheckTimer); recheckTimer = null; }
    }, true);
    window.addEventListener('pageshow', (e) => {                      // back from the back/forward cache: watch again
        if (e.persisted && armed) startObserver();
    }, true);
    if (IS_TOP) onReply(chrome.runtime.sendMessage({ type: MSG_TAMPER_HELLO }));
})();
