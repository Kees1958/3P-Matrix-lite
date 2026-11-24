// ── data/tamper-rules.js ──────────────────────────────────────────────────────
// 5.1.0 — THE Tamper Guard rules table (single source of truth): what each finding means, which layer reports it,
// how serious it is and, for the static layer, which built-ins it watches. The service worker
// (core/tamper-guard.js) validates every page report against this table; the Protections page lists it; the warning
// window shows its texts. The page script (security/tamper-guard-page.js) cannot import, so it carries a copy of
// STATIC targets per rule — tools/test-tamper-guard.mjs fails when that copy and this table differ.
//
// Layers
//   STATIC   — security/tamper-guard-page.js (MAIN world, every page where watchTamperSensitive runs): the original
//              built-ins are saved at document_start and compared later; a difference is reported. It sees THAT
//              something changed, not what is done with it.
//   DYNAMIC  — the closer watching, only on armed pages: wrappers on the page's data and network APIs (MAIN world)
//              and a bounded MutationObserver on forms, frames and scripts (ISOLATED world). It sees what is done.
// `points` (5.1.3, user decision 2026-11-24): what the finding adds to the page's risk score (core/tamper-guard.js;
// ratings and the banking/payment factor in data/constants.js TAMPER_RATING_*). A finding no longer warns on its own:
// the page's rating does, in ONE window listing every finding. Low-point findings (10) are common on normal sites
// (frameworks such as Zone.js, site-monitoring scripts and cookie-consent tools replace these functions): alone they
// stay Low, never warn, and never count as a tampering sign (TAMPER_SIGN_POINTS_MIN).
//
// Not built (decided 2026-11-23, see CHANGELOG_HISTORY.md 5.1.0): cookie/storage READS and clipboard reads (normal
// on every site; clipboard reads are already blocked by blockScpPrivacy), fingerprinting (uBD's Fingerprint
// inspector), eval/Function (blockObfuscatedEval and its siblings), workers, permission prompts (3P Matrix's own
// blocks), and "another extension was installed or widened" (needs the `management` permission — C36: an added
// permission disables the extension for every user until they re-approve it).
//
// `ownWarning` (5.1.3): the protection whose own warning this finding comes from (see the last three rules).
// `label`: the finding's name — on the Protections page's Tamper Protection list (5.1.3: plain, points on hover; the
// 5.1.2 `listLabel` "Warn when …" names are gone: one finding alone no longer warns) and in the warning window's list.
// `detailHead` (optional, 5.1.2): the warning window's heading above the detail list, when the kind's default
// (ui/tamper-warning.js DETAIL_HEAD) does not fit the rule.
//
// `wrappedBy`: a target that a 3P Matrix protection itself replaces on purpose (blockWebAssembly wraps the
// XMLHttpRequest `response` getter). When that protection is active for the site, the target is ignored — a report about it would
// otherwise be about 3P Matrix itself. Known gap: on such a site a real replacement of that target is not seen.
// ─────────────────────────────────────────────────────────────────────────────

import { TAMPER_RATING, TAMPER_OWN_WARNING_POINTS } from "./constants.js";
import { PROTECTION_KEY } from "./protections.js";

export const TAMPER_LAYER = Object.freeze({ STATIC: "static", DYNAMIC: "dynamic" });

// Every rule id, once. Values are stored in "never warn again" exceptions (state.tamper.exceptions) — a contract:
// never rename a value.
export const TAMPER_RULE = Object.freeze({
  DATA_PARSING:       "tgDataParsing",
  NETWORK_HOOKS:      "tgNetworkHooks",
  FUNCTION_HOOKS:     "tgFunctionHooks",
  PROTOTYPE_POLLUTION: "tgPrototypePollution",
  ARRAY_EXTENDED:     "tgArrayExtended",
  CRYPTO_HOOKS:       "tgCryptoHooks",
  INPUT_HOOKS:        "tgInputHooks",
  STORAGE_HOOKS:      "tgStorageHooks",
  MANY_HOOKS:         "tgManyHooks",
  DATA_EDITED:        "tgDataEdited",
  PASSWORD_SENT:      "tgPasswordSent",
  CARD_SENT:          "tgCardSent",
  FORM_CHANGED:       "tgFormChanged",
  HIDDEN_CREDENTIAL:  "tgHiddenCredential",
  INVISIBLE_FRAME:    "tgInvisibleFrame",
  INTEGRITY_REMOVED:  "tgIntegrityRemoved",
  SECOND_CARD_FORM:   "tgSecondCardForm",         // 5.1.2
  SUSPICIOUS_SCRIPT:  "tgSuspiciousScript",       // 5.1.2
  ADDRESS_SCRIPT:     "tgAddressScript",          // 5.1.2
  IBAN_SENT:          "tgIbanSent",               // 5.1.3
  SEED_SENT:          "tgSeedSent",               // 5.1.4
  OBFUSCATED_CODE:    "tgObfuscatedCode",         // 5.1.3
  PASSWORD_FORM:      "tgPasswordForm",           // 5.1.3 issue 3 — own warning (warnPasswordForms)
  PAYMENT_SKIMMER:    "tgPaymentSkimmer",         // 5.1.3 issue 3 — own warning (warnPaymentSkimmer)
  FAKE_SIGN_IN:       "tgFakeSignIn"              // 5.1.3 issue 3 — own warning (blockFakeSignInWindow)
});

// What a report's `detail` carries (validated by core/tamper-guard.js; never a value the user typed).
export const TAMPER_DETAIL = Object.freeze({
  TARGETS: "targets",          // static: the built-ins that changed (names from `targets` below)
  KEYS:    "keys",             // tgDataEdited: the data fields that changed (names only, never values)
  DEST:    "dest"              // destination host of data, a form or a frame
});

// Prototype objects whose NEW own properties are reported (names, never values): property additions, not replacements.
export const TAMPER_ADDED_PROPS = Object.freeze({
  [TAMPER_RULE.PROTOTYPE_POLLUTION]: "Object.prototype",
  [TAMPER_RULE.ARRAY_EXTENDED]:      "Array.prototype"
});

export const TAMPER_RULES = Object.freeze([
  // ── Static layer: a built-in is no longer the original ──
  { id: TAMPER_RULE.DATA_PARSING, layer: TAMPER_LAYER.STATIC, points: 20,
    label: "Data reading replaced",
    description: "The functions a page uses to read the data it receives (JSON) were replaced. Ad blockers' filter rules do this on purpose; on a bank page it can also mean the data you see is altered.",
    targets: ["JSON.parse", "JSON.stringify", "Response.prototype.json", "Response.prototype.text"] },
  { id: TAMPER_RULE.NETWORK_HOOKS, layer: TAMPER_LAYER.STATIC, points: 10,
    label: "Network functions replaced",
    description: "The functions a page uses to send and receive data were replaced. Common: frameworks and site-monitoring scripts do this, so it is only noted.",
    targets: ["fetch", "XMLHttpRequest.prototype.open", "XMLHttpRequest.prototype.send", "XMLHttpRequest.prototype.response",
              "XMLHttpRequest.prototype.responseText", "Navigator.prototype.sendBeacon", "WebSocket.prototype.send",
              "EventTarget.prototype.addEventListener", "EventTarget.prototype.removeEventListener"],
    // 5.1.3: blockWebAssembly no longer wraps fetch or XMLHttpRequest.open (it wraps Response.prototype.arrayBuffer,
    // not a target here, and the XHR `response` getter).
    wrappedBy: { "XMLHttpRequest.prototype.response": [PROTECTION_KEY.BLOCK_WEBASSEMBLY] } },
  { id: TAMPER_RULE.FUNCTION_HOOKS, layer: TAMPER_LAYER.STATIC, points: 20,
    label: "Core functions replaced",
    description: "How every function on the page is called or shown was replaced — a way to hide other changes.",
    targets: ["Function.prototype.toString", "Function.prototype.call", "Function.prototype.apply", "Function.prototype.bind"] },
  { id: TAMPER_RULE.PROTOTYPE_POLLUTION, layer: TAMPER_LAYER.STATIC, points: 20,
    label: "Page objects changed",
    description: "A property was added to the base of every object on the page (prototype pollution) — it can change how the whole site behaves.",
    targets: [] },
  { id: TAMPER_RULE.ARRAY_EXTENDED, layer: TAMPER_LAYER.STATIC, points: 10,
    label: "Page lists extended",
    description: "A function was added to every list on the page. Old script libraries do this, so it is only noted.",
    targets: [] },
  { id: TAMPER_RULE.CRYPTO_HOOKS, layer: TAMPER_LAYER.STATIC, points: 40,
    label: "Encryption replaced",
    description: "The browser's encryption or random-number functions were replaced — they protect sign-ins and payments.",
    targets: ["Crypto.prototype.getRandomValues", "SubtleCrypto.prototype.encrypt", "SubtleCrypto.prototype.decrypt",
              "SubtleCrypto.prototype.sign", "SubtleCrypto.prototype.verify", "SubtleCrypto.prototype.digest",
              "SubtleCrypto.prototype.importKey", "SubtleCrypto.prototype.exportKey", "SubtleCrypto.prototype.generateKey",
              "SubtleCrypto.prototype.deriveKey", "SubtleCrypto.prototype.deriveBits"] },
  { id: TAMPER_RULE.INPUT_HOOKS, layer: TAMPER_LAYER.STATIC, points: 40,
    label: "Typing intercepted",
    description: "How the page reads what you type into fields was replaced for every field — a way to capture what you type.",
    targets: ["HTMLInputElement.prototype.value"] },
  { id: TAMPER_RULE.STORAGE_HOOKS, layer: TAMPER_LAYER.STATIC, points: 10,
    label: "Cookies or storage replaced",
    description: "How the page stores cookies or data was replaced. Cookie-consent tools do this, so it is only noted.",
    targets: ["Document.prototype.cookie", "Storage.prototype.getItem", "Storage.prototype.setItem"] },
  { id: TAMPER_RULE.MANY_HOOKS, layer: TAMPER_LAYER.STATIC, points: 20,
    label: "Many functions replaced",
    description: "Several important built-in functions were replaced on the same page (counted by the service worker; the common low-point ones are not included).",
    targets: [] },
  // ── Dynamic layer: what the closer watching saw being done ──
  { id: TAMPER_RULE.DATA_EDITED, layer: TAMPER_LAYER.DYNAMIC, points: 60,
    label: "Site data altered",
    description: "Data the site received was edited on the way in, after it arrived. Shown: which fields changed (never their values)." },
  { id: TAMPER_RULE.PASSWORD_SENT, layer: TAMPER_LAYER.DYNAMIC, points: 100,
    label: "Password copied to another site",
    description: "Something on this page sends what is in a password field to a different site than the one you are on." },
  { id: TAMPER_RULE.CARD_SENT, layer: TAMPER_LAYER.DYNAMIC, points: 100,
    label: "Card number copied to another site",
    description: "Something on this page sends a card number to a site that is neither this site nor a known payment provider (card skimming)." },
  { id: TAMPER_RULE.FORM_CHANGED, layer: TAMPER_LAYER.DYNAMIC, points: 60,
    label: "Sign-in or payment form redirected",
    description: "After the page loaded, a form with a password or card field was changed to send to a different site." },
  { id: TAMPER_RULE.HIDDEN_CREDENTIAL, layer: TAMPER_LAYER.DYNAMIC, points: 20,
    label: "Hidden password or card field",
    description: "A password or card field was hidden as a trick — a hidden field named like one, or a field made invisible while the form around it is visible. Your browser may fill it in without you seeing it. Fields in closed menus or dialogs do not count." },
  { id: TAMPER_RULE.INVISIBLE_FRAME, layer: TAMPER_LAYER.DYNAMIC, points: 10,
    label: "Invisible frame from another site",
    description: "An invisible frame from another site was added after the page loaded. Common for analytics, so it is only noted." },
  { id: TAMPER_RULE.INTEGRITY_REMOVED, layer: TAMPER_LAYER.DYNAMIC, points: 40,
    label: "Script tamper check removed",
    description: "The check that proves a script was not altered (its integrity attribute) was removed or changed." },
  // 5.1.2 — derived by the service worker from the page's signals (core/tamper-guard.js secondCardForm), never reported
  // by a page: a card-NUMBER field in the shop's own page (top page or a same-site frame) while the page also embeds a
  // payment provider's frame. Shops that use such a frame take the card number inside it; a field of their own next
  // to it is the classic Magecart fake form. 60, not 100: a shop can show both briefly (its own form, then a 3-D Secure
  // frame) — "Tamper: site" on the allow list covers such a shop.
  { id: TAMPER_RULE.SECOND_CARD_FORM, layer: TAMPER_LAYER.DYNAMIC, points: 60,
    label: "Fake second card form", detailHead: "The payment provider's secure frame on this page:",
    description: "This page takes card details in a payment provider's secure frame, yet it also has a card-number field of its own — the mark of a fake card form added by a card skimmer." },
  // 5.1.2 — the closer watching reports the hosts of other sites' scripts (security/tamper-guard-bridge.js); the service
  // worker scores each with 3P Matrix's own LOCAL site checks (core/site-scorer.js scoreLocal: look-alike brand/site,
  // abused TLD, free hosting, misused platform — no network) and keeps those rated suspect or worse. 40: High on
  // banking and payment pages (× factor, where skimmers load), elsewhere Suspicious unless other findings add up. Hosts on the built-in
  // whitelist and the page's own site are never scored.
  { id: TAMPER_RULE.SUSPICIOUS_SCRIPT, layer: TAMPER_LAYER.DYNAMIC, points: 40,
    label: "Script from a suspicious domain", detailHead: "Scripts loaded from:",
    description: "A script on this page comes from a domain that imitates a well-known brand or site, or has other warning signs (an often-abused domain ending, free hosting) — how card skimmers usually disguise their code." },
  // 5.1.2 — DOM-based XSS (the Browsing warning warnXssLinks is the reflected half). The page script looks at its own
  // address at document_start; ONLY when a query or hash value carries script markup (data/constants.js
  // XSS_MARKUP_PATTERNS) does it watch the places where HTML or code is put into a page (`sinks`, names reported) —
  // on every page where tamper protection runs, armed or not. A report of this rule arms the page itself (the
  // address with script code is the tampering sign). 60: High wherever it is seen.
  { id: TAMPER_RULE.ADDRESS_SCRIPT, layer: TAMPER_LAYER.DYNAMIC, points: 60,
    label: "Script from the link run on the page", detailHead: "Where it was put:",
    description: "This page's address carries script code, and the page copied that code into itself — a cross-site scripting (XSS) attack that can act as you on this site. Leave the page unless you know why the link looks like this.",
    sinks: ["Element.prototype.innerHTML", "Element.prototype.outerHTML", "Element.prototype.insertAdjacentHTML",
            "Element.prototype.setHTMLUnsafe", "ShadowRoot.prototype.innerHTML", "Document.prototype.write",
            "Document.prototype.writeln", "Range.prototype.createContextualFragment", "HTMLIFrameElement.prototype.srcdoc",
            "Element.prototype.setAttribute"] },
  // 5.1.3 — the outgoing-data check also looks for an IBAN (a field named like one, or a typed value that passes the
  // ISO 13616 MOD-97 check) sent to another site. Payment providers are no finding, as for card numbers.
  { id: TAMPER_RULE.IBAN_SENT, layer: TAMPER_LAYER.DYNAMIC, points: 60,
    label: "IBAN copied to another site", detailHead: "Where to:",
    description: "Your bank-account number (IBAN) is being sent to a site other than the one you are on — a sign that a script is copying it." },
  // 5.1.4 (owner) — a crypto wallet's recovery phrase sent to another site (data/constants.js TAMPER_SEED). Whoever has
  // the phrase owns the wallet: as serious as a password or card number.
  { id: TAMPER_RULE.SEED_SENT, layer: TAMPER_LAYER.DYNAMIC, points: 100,
    label: "Recovery phrase copied to another site", detailHead: "Where to:",
    description: "The recovery phrase of a crypto wallet (the 12 or 24 words) is being sent to a site other than the one you are on. Whoever has it owns the wallet — no real wallet or support desk ever asks for it." },
  // 5.1.3 — blockObfuscatedEval (now under Tamper Protection) blocked obfuscated code on this page: the block still
  // protects; this signal lets the risk rating include it. Reported by security/tamper-guard-bridge.js on the block
  // event of security/sec-no-obfuscated-code.js (only raises scrutiny: a page faking it only rates itself higher).
  { id: TAMPER_RULE.OBFUSCATED_CODE, layer: TAMPER_LAYER.DYNAMIC, points: 40,
    label: "Disguised code stopped", detailHead: "Stopped in:",
    description: "This page tried to run disguised code through eval(), Function() or a timer — the way skimmers and other malicious scripts hide. 3P Matrix stopped it.",
    sinks: ["eval", "Function", "setTimeout", "setInterval"] },
  // 5.1.3 (issue 3, user decision 2026-11-24) — the protections under the tamper switch with a warning of their OWN.
  // They keep that warning (in-page for the password form, the red warning page for the other two) and are ALSO
  // recorded as a finding of TAMPER_OWN_WARNING_POINTS, so the page's risk rating, the popup's "This page" box and
  // any tamper window include them. `ownWarning` = the protection that decides and warns; the service worker records
  // the finding from that decision (core/tamper-guard.js recordOwnWarning) — a page can never report one, and such a
  // finding never opens a tamper window by itself (its own warning already did).
  { id: TAMPER_RULE.PASSWORD_FORM, layer: TAMPER_LAYER.DYNAMIC, points: TAMPER_OWN_WARNING_POINTS,
    ownWarning: PROTECTION_KEY.WARN_PASSWORD_FORMS,
    label: "Password sent to another site", detailHead: "It sends to:",
    description: "You were about to submit a password form that sends to a different site than the one you are on." },
  { id: TAMPER_RULE.PAYMENT_SKIMMER, layer: TAMPER_LAYER.DYNAMIC, points: TAMPER_OWN_WARNING_POINTS,
    ownWarning: PROTECTION_KEY.WARN_PAYMENT_SKIMMER,
    label: "Fake payment overlay (skimmer)", detailHead: "Seen in:",
    description: "The page loaded a fake tracking-pixel script or drew a payment overlay that does not belong to the site — a card-skimming scam." },
  { id: TAMPER_RULE.FAKE_SIGN_IN, layer: TAMPER_LAYER.DYNAMIC, points: TAMPER_OWN_WARNING_POINTS,
    ownWarning: PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW,
    label: "Fake sign-in window", detailHead: "It imitates:",
    description: "The page drew its own browser or system sign-in window for another site around a password field — a phishing trick." }

].map((r) => Object.freeze(r)));

// The popup's "This page" box shows the worst sign's `label` on ONE line (owner, 2026-11-24): every label fits at this
// length (5.1.3: all fit, measured in Chrome up to 51 characters); tools/test-tamper-guard.mjs fails a longer one.
export const TAMPER_LABEL_MAX_CHARS = 38;   // owner: short, plain names — the longest today; a longer one fails the test
export const TAMPER_RULE_BY_ID = Object.freeze(Object.fromEntries(TAMPER_RULES.map((r) => [r.id, r])));
export const TAMPER_RULE_IDS = Object.freeze(TAMPER_RULES.map((r) => r.id));
// Every static target name → its rule (the page reports names; the service worker maps them back here).
export const TAMPER_RULE_OF_TARGET = Object.freeze(Object.fromEntries(
  TAMPER_RULES.flatMap((r) => (r.targets || []).map((t) => [t, r.id]))));
// 5.1.3 — the own-warning rules: protection key → rule (core/tamper-guard.js recordOwnWarning).
export const TAMPER_RULE_OF_OWN_WARNING = Object.freeze(Object.fromEntries(
  TAMPER_RULES.filter((r) => r.ownWarning).map((r) => [r.ownWarning, r.id])));
// Rules the service worker derives itself — a page can never report them (5.1.3: + the own-warning rules).
export const TAMPER_DERIVED_RULES = Object.freeze([TAMPER_RULE.MANY_HOOKS, TAMPER_RULE.SECOND_CARD_FORM,
                                                   ...Object.values(TAMPER_RULE_OF_OWN_WARNING)]);
// Which rules a page may report.
export const TAMPER_PAGE_RULES = Object.freeze(TAMPER_RULE_IDS.filter((id) => !TAMPER_DERIVED_RULES.includes(id)));
// Distinct static targets of tampering-sign rules (data/constants.js TAMPER_SIGN_POINTS_MIN) that make MANY_HOOKS.
export const TAMPER_MANY_HOOKS_MIN = 3;
// 5.1.3 — rating names shown to the user (warning window).
export const TAMPER_RATING_LABEL = Object.freeze({
  [TAMPER_RATING.LOW]: "Low", [TAMPER_RATING.SUSPICIOUS]: "Suspicious", [TAMPER_RATING.HIGH]: "High risk", [TAMPER_RATING.CRITICAL]: "Critical"
});
