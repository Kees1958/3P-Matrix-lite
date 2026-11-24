/*
 * tamper-guard-page.js — watchTamperSensitive (3P Matrix 5.1.0), MAIN-world half of Tamper Guard.
 *
 * STATIC layer: at document_start (every page where the protection runs) the property descriptors of the built-ins
 * listed in STATIC_TARGETS are saved, plus the own property names of Object.prototype and Array.prototype — the
 * baseline must be taken before any page script runs. Owner decision 2026-11-24 ("need to protect", least overhead):
 * they are COMPARED only on a page that is watched closely (armed by one of the four ticks): when armed, and after
 * that at DOMContentLoaded, load and CHECK_AFTER_LOAD_MS after load. Every target that no longer holds its original
 * (or a new prototype property) is reported ONCE per page to the ISOLATED half (security/tamper-guard-bridge.js) as a
 * TG_REPORT_EVENT. A page that is never armed compares nothing and sends nothing. Anything noticed before arming
 * (the address layer below, an early replaced JSON function) is held in `pending` (≤ MAX_PENDING_REPORTS) and sent
 * when the page is armed; released with the page.
 *
 * DYNAMIC layer (only after TG_ARM_EVENT — the service worker decided to watch this page closely):
 *   • tgDataEdited: when JSON.parse or Response.prototype.json is (or later becomes) something else than the original,
 *     an outer wrapper hands the page the REPLACED function's result unchanged and, on the side, parses the same text
 *     with the saved original and compares the two (field names only, bounded). This is how a json-edit filter rule
 *     becomes visible. While still original on an armed page, the property is an accessor that wraps an assigned
 *     replacement at once (guardData) — a page that reads the descriptor sees get/set instead of a value there.
 *   5.1.3: the outgoing-data parts below start only once a password, card number or IBAN is typed (or filled in) on
 *   the armed page — a skimmer has nothing to send before that, and a page without such input gets no fetch wrapper at
 *   all (a site's own failing fetch() is then never filed under this script by the browser).
 *   • tgPasswordSent / tgCardSent: outer wrappers on fetch, XMLHttpRequest open/send, sendBeacon and WebSocket send
 *     look, BEFORE handing the call on, whether the address or body contains what is in a password field or a card
 *     field right now (raw, URL-encoded or base64). 5.1.2: also the ADDRESS of an image, script, frame or link set by
 *     script (the src/href setters and setAttribute) — the classic `new Image().src = ".../p.gif?d=<card>"` send —
 *     and a card number is also recognised by its VALUE in any text field (13–19 digits with a valid Luhn checksum),
 *     not only in fields named like a card field. 5.1.3: tgIbanSent — the same for an IBAN (a field named like one, or a
 *     typed value that passes the ISO 13616 MOD-97 check). Only the destination HOST is reported — never a value; the values
 *     never leave this function. The service worker decides whether that host is "another site".
 *
 * ADDRESS layer (5.1.2, tgAddressScript — DOM-based XSS; independent of arming): at document_start the page's own
 * query and hash values are decoded (up to XSS_DECODE_ROUNDS times) and those that carry script markup
 * (XSS_MARKUP_PATTERNS) are kept as "address pieces" (at most XSS_PIECES_MAX, each ≥ XSS_PIECE_MIN_CHARS). Only when
 * there is at least one are the HTML/code sinks (ADDRESS_SINKS) wrapped: a value put into one that contains a piece is
 * reported once per sink — the sink NAME only. An ordinary address costs one test and wraps nothing.
 *
 * Trust (C35): every built-in used here is captured in the first statements (Proxy-free; `__proto__: null` objects);
 * the saved originals live in this closure only. A page can fake a report event about ITSELF or fake the arm event
 * (more watching) — both accepted, as for the skimmer bridge; the service worker validates every report against
 * data/tamper-rules.js and decides everything (C46/C47). Known gaps (documented in data/tamper-rules.js and the
 * changelog): a script that ran BEFORE this one (another extension's document_start script) is part of the
 * baseline; a request body that is a Blob/stream is not inspected; a Request object's own body is not read.
 * 5.1.3: an element inserted as HTML text or a CSS url() is caught by ADDRESS once it loads — the resource watcher
 * (PerformanceObserver, type "resource") compares every address the page loads with the typed values; it sees the
 * request only after it started (warn, as everything here), and only its address, never a body.
 * Wrappers (C53): every wrapper returns exactly what the replaced function returned (the native promise for
 * fetch/json) and does its own work on a side branch; a failure in that work is swallowed, never the page's.
 * Cost: an ordinary page pays one descriptor snapshot (~40 lookups) and three comparisons. Armed pages pay one
 * field query per outgoing request and one extra parse per replaced-JSON call (bounded by MAX_INSPECTED_CHARS).
 * Lifecycle: listeners on window, capture phase, document_start (C47); the after-load timer is cleared on pagehide;
 * dedupe sets live as long as the page. World: MAIN, all frames, document_start. Classic script.
 */
'use strict';
(function(){
    'use strict';
    // ── Settings (one place) ── copies (this script cannot import), kept equal to their sources:
    // LOG_PREFIX (data/constants.js) and the event names (security/tamper-guard-bridge.js) by
    // tools/check-shipped-terms.mjs; RULE, STATIC_TARGETS and ADDED_PROPS (data/tamper-rules.js) and
    // MAX_REPORTED_ITEMS / MAX_ITEM_CHARS (TAMPER_DETAIL_ITEMS_MAX / TAMPER_DETAIL_TEXT_MAX) by tools/test-tamper-guard.mjs.
    const LOG_PREFIX = '[3PMCF]';
    const TG_REPORT_EVENT = '3pmcf-tg-report';
    const TG_ARM_EVENT = '3pmcf-tg-arm';
    const RULE = Object.freeze({
        DATA_PARSING: 'tgDataParsing', NETWORK_HOOKS: 'tgNetworkHooks', FUNCTION_HOOKS: 'tgFunctionHooks',
        PROTOTYPE_POLLUTION: 'tgPrototypePollution', ARRAY_EXTENDED: 'tgArrayExtended', CRYPTO_HOOKS: 'tgCryptoHooks',
        INPUT_HOOKS: 'tgInputHooks', STORAGE_HOOKS: 'tgStorageHooks',
        DATA_EDITED: 'tgDataEdited', PASSWORD_SENT: 'tgPasswordSent', CARD_SENT: 'tgCardSent',
        IBAN_SENT: 'tgIbanSent'                                  // 5.1.3
    });
    const STATIC_TARGETS = Object.freeze({
        tgDataParsing: ['JSON.parse', 'JSON.stringify', 'Response.prototype.json', 'Response.prototype.text'],
        tgNetworkHooks: ['fetch', 'XMLHttpRequest.prototype.open', 'XMLHttpRequest.prototype.send', 'XMLHttpRequest.prototype.response',
                         'XMLHttpRequest.prototype.responseText', 'Navigator.prototype.sendBeacon', 'WebSocket.prototype.send',
                         'EventTarget.prototype.addEventListener', 'EventTarget.prototype.removeEventListener'],
        tgFunctionHooks: ['Function.prototype.toString', 'Function.prototype.call', 'Function.prototype.apply', 'Function.prototype.bind'],
        tgCryptoHooks: ['Crypto.prototype.getRandomValues', 'SubtleCrypto.prototype.encrypt', 'SubtleCrypto.prototype.decrypt',
                        'SubtleCrypto.prototype.sign', 'SubtleCrypto.prototype.verify', 'SubtleCrypto.prototype.digest',
                        'SubtleCrypto.prototype.importKey', 'SubtleCrypto.prototype.exportKey', 'SubtleCrypto.prototype.generateKey',
                        'SubtleCrypto.prototype.deriveKey', 'SubtleCrypto.prototype.deriveBits'],
        tgInputHooks: ['HTMLInputElement.prototype.value'],
        tgStorageHooks: ['Document.prototype.cookie', 'Storage.prototype.getItem', 'Storage.prototype.setItem']
    });
    const ADDED_PROPS = Object.freeze({ tgPrototypePollution: 'Object.prototype', tgArrayExtended: 'Array.prototype' });
    const MAX_REPORTED_ITEMS = 12;            // names per report (C50)
    const MAX_ITEM_CHARS = 120;               // characters per reported name
    const CHECK_AFTER_LOAD_MS = 3000;         // the third static comparison, after late scripts
    const MAX_PENDING_REPORTS = 20;           // owner 2026-11-24: reports held until the page is armed (guard)
    const MAX_INSPECTED_CHARS = 524288;       // JSON text compared at most (512 KiB, C50) — longer text is not inspected
    const MAX_DIFF_NODES = 5000;              // JSON values visited per comparison
    const MAX_DIFF_DEPTH = 12;                // nesting depth compared
    const MAX_BODY_CHARS = 262144;            // request address + body text inspected (256 KiB)
    const MAX_SECRET_FIELDS = 20;             // password/card fields read per request
    const MIN_PASSWORD_CHARS = 4;             // shorter field contents are not looked for (too common)
    // 5.1.3 — when the outgoing-data check starts: the first of these events on a field holding a secret (armed pages)
    const SECRET_INPUT_EVENTS = Object.freeze(['input', 'change']);
    const RESOURCE_ENTRY_TYPE = 'resource';   // PerformanceObserver: every address the page loads (img, script, css url(), fetch…)
    const MAX_RESOURCE_ENTRIES_PER_BATCH = 100;   // addresses checked per observer callback (rest ignored)
    const CARD_DIGITS_MIN = 12;               // a card number in a field NAMED like a card field has 12–19 digits
    const CARD_DIGITS_MAX = 19;
    // 5.1.2 — a card number recognised by its value (= data/constants.js TAMPER_CARD_VALUE_DIGITS / _FIELDS_MAX)
    const CARD_VALUE_DIGITS_MIN = 13;
    const CARD_VALUE_DIGITS_MAX = 19;
    const CARD_VALUE_FIELDS_MAX = 50;         // text fields read per check
    const CARD_VALUE_RE = /^[\d \-]+$/;       // only digits, spaces and dashes
    const VALUE_SCAN_SELECTOR = 'input:not([type]), input[type="text"], input[type="tel"], input[type="number"]';
    const LUHN = Object.freeze({ BASE: 10, DOUBLE: 2, FOLD: 9 });   // Luhn checksum: every 2nd digit doubled, 10..18 → 1..9
    const CHAR_CODE_ZERO = 48;                // '0'
    // 5.1.2 — elements whose address, set by script, is checked like a request: element prototype → address property.
    const ADDRESS_SETTERS = Object.freeze([
        Object.freeze(['HTMLImageElement.prototype', 'src']), Object.freeze(['HTMLScriptElement.prototype', 'src']),
        Object.freeze(['HTMLIFrameElement.prototype', 'src']), Object.freeze(['HTMLLinkElement.prototype', 'href'])
    ]);
    const ADDRESS_ATTRIBUTES = Object.freeze(['src', 'href']);    // setAttribute names checked the same way
    // 5.1.2 — tgAddressScript (= data/constants.js XSS_* and data/tamper-rules.js ADDRESS_SCRIPT.sinks)
    const XSS_MARKUP_PATTERNS = Object.freeze(['<\\s*script\\b', '<[a-z][^>]*[\\s/]on[a-z]+\\s*=', 'javascript\\s*:']);
    const XSS_MARKUP_FLAGS = 'i';
    const XSS_DECODE_ROUNDS = 2;
    const XSS_ADDRESS_CHARS_MAX = 8192;
    const XSS_PIECE_MIN_CHARS = 8;
    const XSS_PIECES_MAX = 16;
    const ADDRESS_SCRIPT_RULE = 'tgAddressScript';
    // sink name → [holder path, property, kind]: SETTER = an accessor whose value is the HTML; CALL_ARG = a function,
    // the argument at that index is the HTML (document.write: every argument).
    const SINK_KIND = Object.freeze({ SETTER: 'setter', CALL: 'call' });
    const SINK_FIELD = Object.freeze({ NAME: 0, HOLDER: 1, PROP: 2, KIND: 3 });   // positions in an ADDRESS_SINKS row
    const ADDRESS_SINKS = Object.freeze([
        Object.freeze(['Element.prototype.innerHTML', 'Element.prototype', 'innerHTML', SINK_KIND.SETTER]),
        Object.freeze(['Element.prototype.outerHTML', 'Element.prototype', 'outerHTML', SINK_KIND.SETTER]),
        Object.freeze(['Element.prototype.insertAdjacentHTML', 'Element.prototype', 'insertAdjacentHTML', SINK_KIND.CALL]),
        Object.freeze(['Element.prototype.setHTMLUnsafe', 'Element.prototype', 'setHTMLUnsafe', SINK_KIND.CALL]),
        Object.freeze(['ShadowRoot.prototype.innerHTML', 'ShadowRoot.prototype', 'innerHTML', SINK_KIND.SETTER]),
        Object.freeze(['Document.prototype.write', 'Document.prototype', 'write', SINK_KIND.CALL]),
        Object.freeze(['Document.prototype.writeln', 'Document.prototype', 'writeln', SINK_KIND.CALL]),
        Object.freeze(['Range.prototype.createContextualFragment', 'Range.prototype', 'createContextualFragment', SINK_KIND.CALL]),
        Object.freeze(['HTMLIFrameElement.prototype.srcdoc', 'HTMLIFrameElement.prototype', 'srcdoc', SINK_KIND.SETTER]),
        Object.freeze(['Element.prototype.setAttribute', 'Element.prototype', 'setAttribute', SINK_KIND.CALL])
    ]);
    const QUERY_SEPARATOR = '&';
    const VALUE_SEPARATOR = '=';
    const PATH_SEPARATOR = '.';
    const PASSWORD_SELECTOR = 'input[type="password"]';
    const CARD_SELECTOR = 'input[autocomplete="cc-number"], input[name*="cardnumber" i], input[name*="card_number" i], input[id*="cardnumber" i], input[name*="ccnum" i]';
    const NON_DIGIT_RE = /\D+/g;
    // 5.1.3 — tgIbanSent: an IBAN (ISO 13616) in a field named like one, or a typed value that passes the MOD-97 check.
    // Compared lower case with everything but letters and digits removed (= data/constants.js TAMPER_IBAN_*).
    const IBAN_SELECTOR = 'input[name*="iban" i], input[id*="iban" i], input[autocomplete*="iban" i]';
    const IBAN_RE = /^[a-z]{2}\d{2}[a-z0-9]{11,30}$/;    // country, check digits, 11–30 account characters (15–34 in all)
    const NON_ALNUM_RE = /[^a-z0-9]+/g;
    const IBAN_MOD = Object.freeze({ DIVISOR: 97, VALID: 1, MOVED_CHARS: 4, LETTER_BASE: 87,   // 'a' (97) → 10
                                     TWO_DIGIT_MIN: 10, SHIFT_ONE: 10, SHIFT_TWO: 100 });   // a letter adds two digits
    const CHAR_CODE_A = 97;                   // 'a'
    const FORM_SPACE_RE = /\+/g;              // "+" is a space in form-encoded bodies

    // ── Captured builtins (C35) ──────────────────────────────────────────────
    const logInfo = console.info.bind(console);
    const { apply, getOwnPropertyDescriptor, defineProperty, ownKeys, getPrototypeOf } = Reflect;
    const globalObj = globalThis;
    const StringCtor = String;
    const ArrayIsArray = Array.isArray;
    const SetCtor = Set;
    const setHas = Set.prototype.has;
    const setAdd = Set.prototype.add;
    const WeakMapCtor = WeakMap;
    const weakGet = WeakMap.prototype.get;
    const weakSet = WeakMap.prototype.set;
    const WeakSetCtor = WeakSet;
    const weakHas = WeakSet.prototype.has;
    const weakAdd = WeakSet.prototype.add;
    const strSplit = String.prototype.split;
    const strSlice = String.prototype.slice;
    const strIncludes = String.prototype.includes;
    const strReplace = String.prototype.replace;
    const strToLower = String.prototype.toLowerCase;
    const strCharCode = String.prototype.charCodeAt;
    const reTest = RegExp.prototype.test;
    const arrIncludes = Array.prototype.includes;
    const arrPush = Array.prototype.push;
    const arrJoin = Array.prototype.join;
    const arrSlice = Array.prototype.slice;
    const jsonStringify = JSON.stringify;
    const jsonParse = JSON.parse;
    const JSONObj = JSON;
    const CustomEventCtor = CustomEvent;
    const dispatch = EventTarget.prototype.dispatchEvent;
    const addListener = EventTarget.prototype.addEventListener;
    const setTimer = setTimeout;
    const clearTimer = clearTimeout;
    const URLCtor = URL;
    const urlHostGet = getOwnPropertyDescriptor(URL.prototype, 'hostname').get;
    // Location's properties live on the location OBJECT itself ([LegacyUnforgeable], non-configurable — a page cannot
    // replace them), not on Location.prototype (5.1.2 fix: reading the prototype gave null here).
    const locationObj = location;
    function locationGetter(prop) {
        const d = getOwnPropertyDescriptor(locationObj, prop) || getOwnPropertyDescriptor(Location.prototype, prop);
        return d && typeof d.get === 'function' ? d.get : null;
    }
    const locationHrefGet = locationGetter('href');
    const qsAll = Document.prototype.querySelectorAll;
    const documentObj = document;
    const inputValueGet = getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').get;
    const encodeComponent = encodeURIComponent;
    const decodeComponent = decodeURIComponent;
    const toBase64 = btoa;
    const PromiseThen = Promise.prototype.then;
    const responseClone = Response.prototype.clone;
    const responseText = Response.prototype.text;
    const requestUrlGet = getOwnPropertyDescriptor(Request.prototype, 'url').get;
    const RequestCtor = Request;
    const URLSearchParamsCtor = URLSearchParams;
    const searchParamsToString = URLSearchParams.prototype.toString;
    const FormDataCtor = FormData;
    const formDataEntries = FormData.prototype.entries;
    const iterNext = getPrototypeOf(apply(formDataEntries, new FormDataCtor(), [])).next;
    const wsUrlGet = getOwnPropertyDescriptor(WebSocket.prototype, 'url').get;
    const instanceOf = Function.prototype[Symbol.hasInstance];
    const RegExpCtor = RegExp;
    const strIndexOf = String.prototype.indexOf;
    const locationSearchGet = locationGetter('search');
    // 5.1.3 — resource watcher and secret-input start
    const PerformanceObserverCtor = typeof PerformanceObserver === 'function' ? PerformanceObserver : null;
    const observeFn = PerformanceObserverCtor ? PerformanceObserverCtor.prototype.observe : null;
    const disconnectFn = PerformanceObserverCtor ? PerformanceObserverCtor.prototype.disconnect : null;
    const entryListGetEntries = typeof PerformanceObserverEntryList === 'function' ? PerformanceObserverEntryList.prototype.getEntries : null;
    const entryNameGet = typeof PerformanceEntry === 'function' ? getOwnPropertyDescriptor(PerformanceEntry.prototype, 'name').get : null;
    const removeListener = EventTarget.prototype.removeEventListener;
    const elementMatches = Element.prototype.matches;
    const inputTypeGet = getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
    const HTMLInputCtor = HTMLInputElement;
    const eventTargetGet = getOwnPropertyDescriptor(Event.prototype, 'target').get;
    const locationHashGet = locationGetter('hash');

    // ── Baseline: the original descriptors (taken now, before page scripts run) ──
    // target name → { holderPath, holder, prop, desc } ; holder path is resolved from the saved descriptors only.
    // Null-prototype objects and index loops only from here on: Map/Array iterators are page-replaceable (C35).
    const baseline = { __proto__: null };
    const addedBaseline = { __proto__: null };       // prototype path → Set of own names at document_start
    const reported = new SetCtor();                    // target names / added names already reported (once per page)
    const sentReports = new SetCtor();                 // rule + destination already reported (once per page)
    let armed = false;
    const pending = [];                                // { rule, kind, items } noticed before arming (≤ MAX_PENDING_REPORTS)
    let afterLoadTimer = null;
    let outgoingStarted = false;                       // 5.1.3: the outgoing-data check runs (once per page)
    let resourceObserver = null;                       // 5.1.3: released on pagehide

    function holderOf(path) {                            // 'XMLHttpRequest.prototype' → that object, via descriptors only
        const parts = apply(strSplit, path, [PATH_SEPARATOR]);
        let obj = globalObj;
        for (let i = 0; i < parts.length; i++) {
            if (obj === null || (typeof obj !== 'object' && typeof obj !== 'function')) return null;
            const d = getOwnPropertyDescriptor(obj, parts[i]);
            if (!d || !('value' in d)) return null;      // an accessor on the way: not the original shape
            obj = d.value;
        }
        return obj;
    }
    function splitTarget(name) {
        const parts = apply(strSplit, name, [PATH_SEPARATOR]);
        const prop = parts[parts.length - 1];
        const holderPath = apply(arrJoin, apply(arrSlice, parts, [0, parts.length - 1]), [PATH_SEPARATOR]);
        return { holderPath, prop };
    }
    function snapshot() {
        const rules = ownKeys(STATIC_TARGETS);
        for (let r = 0; r < rules.length; r++) {
            const names = STATIC_TARGETS[rules[r]];
            for (let i = 0; i < names.length; i++) {
                const { holderPath, prop } = splitTarget(names[i]);
                const holder = holderPath ? holderOf(holderPath) : globalObj;
                const desc = holder ? getOwnPropertyDescriptor(holder, prop) : undefined;
                if (desc) baseline[names[i]] = { __proto__: null, holderPath, holder, prop, desc };   // an API this browser lacks is skipped
            }
        }
        const protos = ownKeys(ADDED_PROPS);
        for (let r = 0; r < protos.length; r++) {
            const path = ADDED_PROPS[protos[r]];
            const proto = holderOf(path);
            if (!proto) continue;
            const names = new SetCtor();
            const keys = ownKeys(proto);
            for (let i = 0; i < keys.length; i++) apply(setAdd, names, [keys[i]]);
            addedBaseline[path] = names;
        }
    }
    function sameDescriptor(a, b) {
        return a.value === b.value && a.get === b.get && a.set === b.set;
    }

    // ── Reporting (to the ISOLATED half — names only, bounded) ──
    function clip(s) { return apply(strSlice, StringCtor(s), [0, MAX_ITEM_CHARS]); }
    // Serialized by hand from strings only: JSON.stringify of an OBJECT would consult a page-added toJSON (C35);
    // a string primitive never does.
    function quote(s) { return apply(jsonStringify, JSONObj, [StringCtor(s)]); }
    function report(rule, kind, items) {
        if (!armed) {                                  // not watched closely (yet): hold it, send nothing
            if (pending.length < MAX_PENDING_REPORTS) apply(arrPush, pending, [{ __proto__: null, rule, kind, items }]);
            return;
        }
        const list = [];
        for (let i = 0; i < items.length && list.length < MAX_REPORTED_ITEMS; i++) apply(arrPush, list, [quote(clip(items[i]))]);
        let detail;
        try { detail = '{"rule":' + quote(rule) + ',"kind":' + quote(kind) + ',"items":[' + apply(arrJoin, list, [',']) + ']}'; }
        catch { return; }
        apply(dispatch, globalObj, [new CustomEventCtor(TG_REPORT_EVENT, { __proto__: null, detail })]);
    }

    // ── Static comparison ──
    function compare() {
        const rules = ownKeys(STATIC_TARGETS);
        for (let r = 0; r < rules.length; r++) {
            const rule = rules[r];
            const names = STATIC_TARGETS[rule];
            const changed = [];
            for (let i = 0; i < names.length; i++) {
                const name = names[i];
                const base = baseline[name];
                if (!base || apply(setHas, reported, [name])) continue;
                const holder = base.holderPath ? holderOf(base.holderPath) : globalObj;
                const now = holder === base.holder ? getOwnPropertyDescriptor(holder, base.prop) : undefined;
                if (now && sameDescriptor(now, base.desc)) continue;
                apply(setAdd, reported, [name]);
                apply(arrPush, changed, [name]);
            }
            if (changed.length) report(rule, 'targets', changed);
        }
        const protos = ownKeys(ADDED_PROPS);
        for (let r = 0; r < protos.length; r++) {
            const rule = protos[r];
            const path = ADDED_PROPS[rule];
            const before = addedBaseline[path];
            const proto = before ? holderOf(path) : null;
            if (!proto) continue;
            const added = [];
            const keys = ownKeys(proto);
            for (let i = 0; i < keys.length; i++) {
                const key = keys[i];
                const name = path + PATH_SEPARATOR + StringCtor(key);
                if (apply(setHas, before, [key]) || apply(setHas, reported, [name])) continue;
                apply(setAdd, reported, [name]);
                apply(arrPush, added, [name]);
            }
            if (added.length) report(rule, 'targets', added);
        }
        if (armed) { try { dataWatch(); } catch { /* never the page's problem */ } }   // a value set by defineProperty
    }

    // ── Dynamic: tgDataEdited (JSON parsed differently than the original would) ──
    function diffPaths(clean, edited, path, depth, out, budget) {
        if (budget.left-- <= 0 || out.length >= MAX_REPORTED_ITEMS) return;
        if (clean === edited) return;
        const cleanObj = clean !== null && typeof clean === 'object';
        const editedObj = edited !== null && typeof edited === 'object';
        if (!cleanObj || !editedObj || ArrayIsArray(clean) !== ArrayIsArray(edited)) {
            if (cleanObj || editedObj || clean !== edited) apply(arrPush, out, [path || '(whole value)']);
            return;
        }
        if (depth >= MAX_DIFF_DEPTH) return;
        const seen = new SetCtor();
        const cleanKeys = ownKeys(clean);
        for (let i = 0; i < cleanKeys.length; i++) {
            const k = cleanKeys[i];
            apply(setAdd, seen, [k]);
            const d = getOwnPropertyDescriptor(edited, k);
            const sub = path ? path + PATH_SEPARATOR + StringCtor(k) : StringCtor(k);
            if (!d || !('value' in d)) { apply(arrPush, out, [sub]); continue; }
            diffPaths(getOwnPropertyDescriptor(clean, k).value, d.value, sub, depth + 1, out, budget);
            if (out.length >= MAX_REPORTED_ITEMS) return;
        }
        const editedKeys = ownKeys(edited);
        for (let i = 0; i < editedKeys.length; i++) {
            const k = editedKeys[i];
            if (!apply(setHas, seen, [k])) apply(arrPush, out, [path ? path + PATH_SEPARATOR + StringCtor(k) : StringCtor(k)]);
            if (out.length >= MAX_REPORTED_ITEMS) return;
        }
    }
    function compareParsed(text, edited) {
        try {
            if (typeof text !== 'string' || text.length > MAX_INSPECTED_CHARS) return;
            const clean = apply(jsonParse, JSONObj, [text]);
            const out = [];
            diffPaths(clean, edited, '', 0, out, { left: MAX_DIFF_NODES });
            if (out.length) report(RULE.DATA_EDITED, 'keys', out);
        } catch { /* not comparable — never the page's problem */ }
    }
    // Wraps holder[prop] (the page's CURRENT function) with an outer function that returns its result unchanged.
    // `name` is the static target it replaces: its baseline becomes OUR wrapper, so the static layer never reports
    // Tamper Guard itself — while a later replacement of our wrapper by the page is still seen. (arm() compares first,
    // so a replacement made before the wrapper was already reported.)
    function wrapOuter(holder, prop, name, makeWrapper) {
        const desc = getOwnPropertyDescriptor(holder, prop);
        if (!desc || typeof desc.value !== 'function') return;
        defineProperty(holder, prop, { __proto__: null, value: makeWrapper(desc.value), writable: desc.writable,
                                       enumerable: desc.enumerable, configurable: desc.configurable });
        const base = baseline[name];
        if (base) { base.holder = holder; base.desc = getOwnPropertyDescriptor(holder, prop); }
    }
    // A page armed BEFORE its scripts replace JSON.parse (the usual case: the arm arrives at document start) still has
    // the original there. Then the property becomes an accessor: the page reads the current function as before, and a
    // later ASSIGNMENT (what a json-edit filter rule does) is reported at once (the static finding) and wrapped by our
    // outer comparing function. A later Object.defineProperty replaces the accessor instead: the static comparison sees
    // that and dataWatch() wraps the new value at the next comparison. Our own wrappers are remembered (ownWrappers) so
    // they are never wrapped or reported again.
    const ownWrappers = new WeakSetCtor();
    function guardData(holderPath, prop, name, rule, makeWrapper) {
        const base = baseline[name];
        const holder = holderOf(holderPath);
        if (!base || !holder) return;
        const desc = getOwnPropertyDescriptor(holder, prop);
        if (!desc || !('value' in desc) || typeof desc.value !== 'function' || apply(weakHas, ownWrappers, [desc.value])) return;
        if (desc.value !== base.desc.value) {                       // replaced already: wrap it now
            wrapOuter(holder, prop, name, (current) => {
                const w = makeWrapper(current);
                apply(weakAdd, ownWrappers, [w]);
                return w;
            });
            return;
        }
        if (!desc.configurable) return;
        let current = desc.value;
        defineProperty(holder, prop, { __proto__: null, enumerable: desc.enumerable, configurable: true,
            get: function() { return current; },
            set: function(v) {
                if (typeof v === 'function' && v !== base.desc.value && !apply(weakHas, ownWrappers, [v])) {
                    if (!apply(setHas, reported, [name])) { apply(setAdd, reported, [name]); report(rule, 'targets', [name]); }
                    const w = makeWrapper(v);
                    apply(weakAdd, ownWrappers, [w]);
                    current = w;
                    return;
                }
                current = v;
            } });
        base.holder = holder;
        base.desc = getOwnPropertyDescriptor(holder, prop);          // the accessor is ours: not a static finding
    }
    function parseWrapper(current) {
        return function parse(text, reviver) {
            const result = apply(current, this, arguments);
            if (reviver === undefined) compareParsed(text, result);   // a reviver would run twice: not compared
            return result;
        };
    }
    function jsonWrapper(current) {
        return function json() {
            let copy = null;
            try { copy = apply(responseClone, this, []); } catch { /* body already used */ }
            const result = apply(current, this, arguments);
            if (copy) {
                try {
                    const textPromise = apply(responseText, copy, []);
                    apply(PromiseThen, textPromise, [(text) => {
                        apply(PromiseThen, result, [(edited) => compareParsed(text, edited), () => {}]);
                    }, () => {}]);
                } catch { /* not comparable */ }
            }
            return result;                                            // the page's own promise (C53)
        };
    }
    function dataWatch() {
        guardData('JSON', 'parse', 'JSON.parse', RULE.DATA_PARSING, parseWrapper);
        guardData('Response.prototype', 'json', 'Response.prototype.json', RULE.DATA_PARSING, jsonWrapper);
    }

    // ── Dynamic: tgPasswordSent / tgCardSent (outgoing data) ──
    function fieldValues(selector, max) {
        const out = [];
        let list;
        try { list = apply(qsAll, documentObj, [selector]); } catch { return out; }
        for (let i = 0; i < list.length && i < max; i++) {
            let v = '';
            try { v = apply(inputValueGet, list[i], []); } catch { continue; }
            if (typeof v === 'string' && v.length) apply(arrPush, out, [v]);
        }
        return out;
    }
    function luhnValid(digits) {
        let sum = 0;
        let doubled = false;
        for (let i = digits.length - 1; i >= 0; i--) {
            let d = apply(strCharCode, digits, [i]) - CHAR_CODE_ZERO;
            if (doubled) { d *= LUHN.DOUBLE; if (d > LUHN.FOLD) d -= LUHN.FOLD; }
            sum += d;
            doubled = !doubled;
        }
        return sum % LUHN.BASE === 0;
    }
    // 5.1.2: a card number by its value — only digits/spaces/dashes, 13–19 digits, valid checksum.
    function isCardValue(v) {
        if (typeof v !== 'string' || !apply(reTest, CARD_VALUE_RE, [v])) return false;
        const digits = apply(strReplace, v, [NON_DIGIT_RE, '']);
        return digits.length >= CARD_VALUE_DIGITS_MIN && digits.length <= CARD_VALUE_DIGITS_MAX && luhnValid(digits);
    }
    // 5.1.3 — the IBAN check: move the first four characters to the end, letters → 10..35, remainder mod 97 must be 1
    // (computed digit by digit, so no big numbers).
    function ibanValid(compact) {
        const moved = apply(strSlice, compact, [IBAN_MOD.MOVED_CHARS]) + apply(strSlice, compact, [0, IBAN_MOD.MOVED_CHARS]);
        let rest = 0;
        for (let i = 0; i < moved.length; i++) {
            const c = apply(strCharCode, moved, [i]);
            const value = c >= CHAR_CODE_A ? c - IBAN_MOD.LETTER_BASE : c - CHAR_CODE_ZERO;
            const shift = value >= IBAN_MOD.TWO_DIGIT_MIN ? IBAN_MOD.SHIFT_TWO : IBAN_MOD.SHIFT_ONE;
            rest = (rest * shift + value) % IBAN_MOD.DIVISOR;
        }
        return rest === IBAN_MOD.VALID;
    }
    function compactText(v) { return apply(strReplace, apply(strToLower, StringCtor(v), []), [NON_ALNUM_RE, '']); }
    function isIbanValue(v) {
        if (typeof v !== 'string') return false;
        const compact = compactText(v);
        return apply(reTest, IBAN_RE, [compact]) && ibanValid(compact);
    }
    // IBANs on the page, compacted: every field named like one (valid or not), plus typed values that are one.
    function ibanValues() {
        const out = [];
        const named = fieldValues(IBAN_SELECTOR, MAX_SECRET_FIELDS);
        for (let i = 0; i < named.length; i++) {
            const c = compactText(named[i]);
            if (apply(reTest, IBAN_RE, [c]) && !apply(arrIncludes, out, [c])) apply(arrPush, out, [c]);
        }
        const typed = fieldValues(VALUE_SCAN_SELECTOR, CARD_VALUE_FIELDS_MAX);
        for (let i = 0; i < typed.length; i++) {
            if (isIbanValue(typed[i])) {
                const c = compactText(typed[i]);
                if (!apply(arrIncludes, out, [c])) apply(arrPush, out, [c]);
            }
        }
        return out;
    }
    function cardValues() {
        const out = fieldValues(CARD_SELECTOR, MAX_SECRET_FIELDS);
        const typed = fieldValues(VALUE_SCAN_SELECTOR, CARD_VALUE_FIELDS_MAX);
        for (let i = 0; i < typed.length; i++) {
            if (isCardValue(typed[i]) && !apply(arrIncludes, out, [typed[i]])) apply(arrPush, out, [typed[i]]);
        }
        return out;
    }
    function bodyText(body) {
        if (body === undefined || body === null) return '';
        if (typeof body === 'string') return body;
        try {
            if (apply(instanceOf, URLSearchParamsCtor, [body])) return apply(searchParamsToString, body, []);
            if (apply(instanceOf, FormDataCtor, [body])) {
                const parts = [];
                const it = apply(formDataEntries, body, []);
                for (let step = apply(iterNext, it, []); !step.done; step = apply(iterNext, it, [])) {
                    if (typeof step.value[1] === 'string') apply(arrPush, parts, [step.value[0] + '=' + step.value[1]]);
                }
                return apply(arrJoin, parts, ['&']);
            }
        } catch { /* unreadable body */ }
        return '';                                       // Blob, ArrayBuffer, stream: not inspected (documented gap)
    }
    function containsSecret(text, secret) {
        if (apply(strIncludes, text, [secret])) return true;
        try { if (apply(strIncludes, text, [encodeComponent(secret)])) return true; } catch { /* lone surrogate */ }
        try { if (apply(strIncludes, text, [toBase64(secret)])) return true; } catch { /* not Latin-1 */ }
        return false;
    }
    function pageHost() {
        try { return destinationHost(locationHrefGet ? apply(locationHrefGet, locationObj, []) : ''); } catch { return ''; }
    }
    function destinationHost(address) {
        try {
            const base = locationHrefGet ? apply(locationHrefGet, locationObj, []) : undefined;
            return apply(urlHostGet, new URLCtor(StringCtor(address), base), []);
        } catch { return ''; }
    }
    function checkOutgoing(address, body) {
        try {
            // The destination first (5.1.2): the page's own host is never "another site", so the common case — an
            // image or request to the page's own host — costs no field reads.
            const dest = destinationHost(address);
            if (!dest || dest === pageHost()) return;
            const passwords = fieldValues(PASSWORD_SELECTOR, MAX_SECRET_FIELDS);
            const cards = cardValues();
            const ibans = ibanValues();                                  // 5.1.3
            if (!passwords.length && !cards.length && !ibans.length) return;
            let text = StringCtor(address) + ' ' + bodyText(body);
            if (text.length > MAX_BODY_CHARS) text = apply(strSlice, text, [0, MAX_BODY_CHARS]);
            for (let i = 0; i < passwords.length; i++) {
                const pw = passwords[i];
                if (pw.length >= MIN_PASSWORD_CHARS && containsSecret(text, pw)) { sendOnce(RULE.PASSWORD_SENT, dest); break; }
            }
            // Card digits are looked for in the text as sent AND URL-decoded ("%20" between digit groups would
            // otherwise add digits of its own).
            let decoded = text;
            try { decoded = decodeComponent(apply(strReplace, text, [FORM_SPACE_RE, ' '])); } catch { /* malformed escape: as sent */ }
            const digitsText = apply(strReplace, text, [NON_DIGIT_RE, '']) + ' ' + apply(strReplace, decoded, [NON_DIGIT_RE, '']);
            for (let i = 0; i < cards.length; i++) {
                const digits = apply(strReplace, cards[i], [NON_DIGIT_RE, '']);
                if (digits.length >= CARD_DIGITS_MIN && digits.length <= CARD_DIGITS_MAX && apply(strIncludes, digitsText, [digits])) {
                    sendOnce(RULE.CARD_SENT, dest); break;
                }
            }
            if (ibans.length) {                                          // 5.1.3: as sent and URL-decoded, compacted
                const ibanText = compactText(text) + ' ' + compactText(decoded);
                for (let i = 0; i < ibans.length; i++) {
                    if (apply(strIncludes, ibanText, [ibans[i]])) { sendOnce(RULE.IBAN_SENT, dest); break; }
                }
            }
        } catch { /* never break the page's request */ }
    }
    function sendOnce(rule, dest) {
        const key = rule + ' ' + dest;
        if (apply(setHas, sentReports, [key])) return;
        apply(setAdd, sentReports, [key]);
        report(rule, 'dest', [dest]);
    }
    function requestAddress(input) {
        try { if (apply(instanceOf, RequestCtor, [input])) return apply(requestUrlGet, input, []); } catch { /* not a Request */ }
        return StringCtor(input);
    }
    function armOutgoing() {
        const xhrUrls = new WeakMapCtor();
        wrapOuter(globalObj, 'fetch', 'fetch', (current) => function fetch(input, init) {
            checkOutgoing(requestAddress(input), init && typeof init === 'object' ? init.body : undefined);
            return apply(current, this, arguments);                       // the native promise (C53)
        });
        const xhrProto = holderOf('XMLHttpRequest.prototype');
        if (xhrProto) {
            wrapOuter(xhrProto, 'open', 'XMLHttpRequest.prototype.open', (current) => function open(method, address) {
                try { apply(weakSet, xhrUrls, [this, StringCtor(address)]); } catch { /* not an XHR */ }
                return apply(current, this, arguments);
            });
            wrapOuter(xhrProto, 'send', 'XMLHttpRequest.prototype.send', (current) => function send(body) {
                const address = apply(weakGet, xhrUrls, [this]);
                if (address !== undefined) checkOutgoing(address, body);
                return apply(current, this, arguments);
            });
        }
        const navProto = holderOf('Navigator.prototype');
        if (navProto) {
            wrapOuter(navProto, 'sendBeacon', 'Navigator.prototype.sendBeacon', (current) => function sendBeacon(address, data) {
                checkOutgoing(address, data);
                return apply(current, this, arguments);
            });
        }
        const wsProto = holderOf('WebSocket.prototype');
        if (wsProto) {
            wrapOuter(wsProto, 'send', 'WebSocket.prototype.send', (current) => function send(data) {
                try { checkOutgoing(apply(wsUrlGet, this, []), data); } catch { /* not a WebSocket */ }
                return apply(current, this, arguments);
            });
        }
        armAddresses();
    }
    // 5.1.2 — an image, script, frame or link address set by script is a send too (the data rides in the address).
    // The setter keeps its getter; the new setter checks the address on the side and hands it on unchanged (C53).
    function wrapSetter(holder, prop) {
        const desc = getOwnPropertyDescriptor(holder, prop);
        if (!desc || typeof desc.set !== 'function' || !desc.configurable) return;
        const original = desc.set;
        defineProperty(holder, prop, { __proto__: null, get: desc.get, enumerable: desc.enumerable, configurable: true,
            set: function(v) { checkOutgoing(v, undefined); return apply(original, this, [v]); } });
    }
    function armAddresses() {
        for (let i = 0; i < ADDRESS_SETTERS.length; i++) {
            const holder = holderOf(ADDRESS_SETTERS[i][0]);
            if (holder) wrapSetter(holder, ADDRESS_SETTERS[i][1]);
        }
        const elementProto = holderOf('Element.prototype');
        if (elementProto) {
            wrapOuter(elementProto, 'setAttribute', 'Element.prototype.setAttribute', (current) => function setAttribute(name, value) {
                try { if (apply(arrIncludes, ADDRESS_ATTRIBUTES, [apply(strToLower, StringCtor(name), [])])) checkOutgoing(value, undefined); }
                catch { /* never the page's problem */ }
                return apply(current, this, arguments);
            });
        }
    }

    // ── Address layer: tgAddressScript (DOM-based XSS) ──
    const markupRes = [];
    for (let i = 0; i < XSS_MARKUP_PATTERNS.length; i++) apply(arrPush, markupRes, [new RegExpCtor(XSS_MARKUP_PATTERNS[i], XSS_MARKUP_FLAGS)]);
    function hasMarkup(t) {
        for (let i = 0; i < markupRes.length; i++) if (apply(reTest, markupRes[i], [t])) return true;
        return false;
    }
    function locationPart(getter) {
        try { return getter ? StringCtor(apply(getter, locationObj, [])) : ''; } catch { return ''; }
    }
    // A raw address value and its decoded forms ("+" as a space), each with script markup and long enough.
    function addPieces(raw, out) {
        let t = apply(strSlice, raw, [0, XSS_ADDRESS_CHARS_MAX]);
        for (let round = 0; round <= XSS_DECODE_ROUNDS && out.length < XSS_PIECES_MAX; round++) {
            if (t.length >= XSS_PIECE_MIN_CHARS && hasMarkup(t) && !apply(arrIncludes, out, [t])) apply(arrPush, out, [t]);
            let next;
            try { next = decodeComponent(apply(strReplace, t, [FORM_SPACE_RE, ' '])); } catch { return; }
            if (next === t) return;
            t = next;
        }
    }
    function addressPieces() {
        const out = [];
        const parts = [apply(strSlice, locationPart(locationSearchGet), [1]), apply(strSlice, locationPart(locationHashGet), [1])];
        for (let p = 0; p < parts.length; p++) {
            if (!parts[p]) continue;
            addPieces(parts[p], out);                                 // the whole query / hash (a page may use it whole)
            const pairs = apply(strSplit, parts[p], [QUERY_SEPARATOR]);
            for (let i = 0; i < pairs.length && out.length < XSS_PIECES_MAX; i++) {
                const at = apply(strIndexOf, pairs[i], [VALUE_SEPARATOR]);
                if (at !== -1) addPieces(apply(strSlice, pairs[i], [at + 1]), out);
            }
        }
        return out;
    }
    function containsPiece(value, pieces) {
        if (typeof value !== 'string') { try { value = StringCtor(value); } catch { return false; } }
        for (let i = 0; i < pieces.length; i++) if (apply(strIncludes, value, [pieces[i]])) return true;
        return false;
    }
    function sinkSeen(name) {
        const key = ADDRESS_SCRIPT_RULE + ' ' + name;
        if (apply(setHas, sentReports, [key])) return;
        apply(setAdd, sentReports, [key]);
        report(ADDRESS_SCRIPT_RULE, 'targets', [name]);
    }
    function watchAddressSinks(pieces) {
        for (let i = 0; i < ADDRESS_SINKS.length; i++) {
            const sink = ADDRESS_SINKS[i];                                // index reads only (C35: no iterator)
            const name = sink[SINK_FIELD.NAME], holderPath = sink[SINK_FIELD.HOLDER], prop = sink[SINK_FIELD.PROP], kind = sink[SINK_FIELD.KIND];
            const holder = holderOf(holderPath);
            const desc = holder ? getOwnPropertyDescriptor(holder, prop) : undefined;
            if (!desc || !desc.configurable) continue;                    // an API this browser lacks
            if (kind === SINK_KIND.SETTER && typeof desc.set === 'function') {
                const original = desc.set;
                defineProperty(holder, prop, { __proto__: null, get: desc.get, enumerable: desc.enumerable, configurable: true,
                    set: function(v) {
                        try { if (containsPiece(v, pieces)) sinkSeen(name); } catch { /* never the page's problem */ }
                        return apply(original, this, [v]);
                    } });
            } else if (kind === SINK_KIND.CALL && typeof desc.value === 'function') {
                wrapOuter(holder, prop, name, (current) => function() {
                    try {
                        for (let a = 0; a < arguments.length; a++) if (containsPiece(arguments[a], pieces)) { sinkSeen(name); break; }
                    } catch { /* never the page's problem */ }
                    return apply(current, this, arguments);                // the native result (C53)
                });
            }
        }
    }
    function startAddressWatch() {
        try {
            const pieces = addressPieces();
            if (pieces.length) watchAddressSinks(pieces);
        } catch { /* never the page's problem */ }
    }

    // 5.1.3 — the resource watcher: every address the page loads, compared like a request address (checkOutgoing).
    function onResources(list) {
        try {
            const entries = apply(entryListGetEntries, list, []);
            for (let i = 0; i < entries.length && i < MAX_RESOURCE_ENTRIES_PER_BATCH; i++) {
                checkOutgoing(apply(entryNameGet, entries[i], []), undefined);
            }
        } catch { /* never the page's problem */ }
    }
    function startResourceWatch() {
        if (resourceObserver || !PerformanceObserverCtor || !observeFn || !entryListGetEntries || !entryNameGet) return;
        try {
            resourceObserver = new PerformanceObserverCtor(onResources);
            apply(observeFn, resourceObserver, [{ __proto__: null, type: RESOURCE_ENTRY_TYPE, buffered: false }]);
        } catch { resourceObserver = null; }
    }
    function stopResourceWatch() {
        if (!resourceObserver) return;
        try { apply(disconnectFn, resourceObserver, []); } catch { /* already gone */ }
        resourceObserver = null;
    }
    // 5.1.3 — a field that holds something worth stealing: a password (≥ MIN_PASSWORD_CHARS), a card or IBAN field with
    // a value, or any text field whose value is a card number or an IBAN.
    function holdsSecret(el) {
        try {
            if (!apply(instanceOf, HTMLInputCtor, [el])) return false;
            const v = apply(inputValueGet, el, []);
            if (typeof v !== 'string' || !v) return false;
            if (apply(inputTypeGet, el, []) === 'password') return v.length >= MIN_PASSWORD_CHARS;
            if (apply(elementMatches, el, [CARD_SELECTOR]) || apply(elementMatches, el, [IBAN_SELECTOR])) return true;
            return isCardValue(v) || isIbanValue(v);
        } catch { return false; }
    }
    function anySecretOnPage() {
        return fieldValues(PASSWORD_SELECTOR, MAX_SECRET_FIELDS).length > 0 || cardValues().length > 0 || ibanValues().length > 0;
    }
    function startOutgoing() {
        if (outgoingStarted) return;
        outgoingStarted = true;
        for (let i = 0; i < SECRET_INPUT_EVENTS.length; i++) apply(removeListener, globalObj, [SECRET_INPUT_EVENTS[i], onSecretInput, true]);
        try { armOutgoing(); } catch { /* never the page's problem */ }
        startResourceWatch();
    }
    function onSecretInput(e) {
        if (outgoingStarted || !e) return;
        let target = null;
        try { target = apply(eventTargetGet, e, []); } catch { return; }
        if (holdsSecret(target)) startOutgoing();
    }
    function watchForSecrets() {
        try { if (anySecretOnPage()) { startOutgoing(); return; } } catch { /* fall through to the listeners */ }
        for (let i = 0; i < SECRET_INPUT_EVENTS.length; i++) apply(addListener, globalObj, [SECRET_INPUT_EVENTS[i], onSecretInput, true]);
    }

    function arm() {
        if (armed) return;
        armed = true;
        for (let i = 0; i < pending.length; i++) report(pending[i].rule, pending[i].kind, pending[i].items);
        pending.length = 0;                                          // released
        compare();
        try { dataWatch(); watchForSecrets(); }
        catch { logInfo(LOG_PREFIX + ' Tamper Guard: closer watching could not start on this page'); }
    }

    // ── Wiring (window, capture, document_start — C47) ──
    snapshot();
    startAddressWatch();                                             // 5.1.2: wraps nothing on an ordinary address
    apply(addListener, globalObj, [TG_ARM_EVENT, arm, true]);
    function compareIfArmed() { if (armed) compare(); }              // owner 2026-11-24: unwatched pages compare nothing
    apply(addListener, globalObj, ['DOMContentLoaded', compareIfArmed, true]);
    apply(addListener, globalObj, ['load', () => {
        compareIfArmed();
        afterLoadTimer = setTimer(() => { afterLoadTimer = null; compareIfArmed(); }, CHECK_AFTER_LOAD_MS);
    }, true]);
    apply(addListener, globalObj, ['pagehide', () => {                // release (B10)
        if (afterLoadTimer !== null) { clearTimer(afterLoadTimer); afterLoadTimer = null; }
        stopResourceWatch();                                         // 5.1.3
    }, true]);
    apply(addListener, globalObj, ['pageshow', (e) => {              // back from the back/forward cache: watch again
        if (e && e.persisted && outgoingStarted) startResourceWatch();
    }, true]);
})();
