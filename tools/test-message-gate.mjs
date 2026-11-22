#!/usr/bin/env node
// ── tools/test-message-gate.mjs ──────────────────────────────────────────────────
// 5.0.6 — the uBO picker-UXSS review (GHSA-cmqw-9r2w-6wv2) ported to 3P Matrix:
//   A. C46 sender kinds — core/message-gate.js: an extension page may send every message except the
//      content-script ones; a content script only CONTENT_SCRIPT_MESSAGES; an unknown sender nothing.
//      Both directions against the real senders: every message type a security/*.js script sends is in
//      CONTENT_SCRIPT_MESSAGES, and every entry there is sent by some script. The router applies the gate
//      before any handler runs.
//   B. C47 in-page UI — the fake sign-in warning is the extension's warning page (no dialog drawn into the
//      page), interception listeners sit on window/capture, dialog buttons act on real clicks only.
//   C. C19/C31 manifest — explicit extension-page CSP with every required directive and no unsafe source;
//      no externally_connectable, no external listener, no message_serialization key.
// Every value comes from the extension's own files; nothing is typed here but the directive list (one place).
//
// Usage:  node test-message-gate.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
// Directives the extension-page CSP must carry (C19) — tighter than Chrome's default, never looser.
const REQUIRED_CSP_DIRECTIVES = Object.freeze(["script-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]);
const UNSAFE_CSP_RE = /unsafe-|https?:|\*/;
const EXT_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";   // mock origin for the pure gate
// 5.0.7 (C47, C25): page scripts listen on window (capture), never on document — a page's own window-capture
// listener runs first and could stop the event (proven for the ClickFix/skimmer bridges in e2e-page-protections).
const PAGE_SCRIPT_DIR = "security";
// 5.0.8: any call form counts — `document.addEventListener(…)`, and a captured addEventListener applied to `document`
// or an alias of it (`apply(addListener, doc, …)`, `reflectApply(fn, doc, …)`, `fn.call(doc, …)`). 5.0.7's pattern
// knew only two spellings and missed sec-browser-locker.js's `apply(addListener, doc, …)` (fullscreenchange, input).
const LISTENER_ALIAS_RE = /(?:const|let|var)\s+(\w+)\s*=\s*EventTarget\.prototype\.addEventListener\b/g;
const DOCUMENT_ALIAS_RE = /(?:const|let|var)\s+(\w+)\s*=\s*document\s*;/g;
function documentListenerCount(src) {
  const docs = ["document", ...[...src.matchAll(DOCUMENT_ALIAS_RE)].map((m) => m[1])].join("|");
  const fns = [...src.matchAll(LISTENER_ALIAS_RE)].map((m) => m[1]);
  const forms = [`\\b(?:${docs})\\.addEventListener\\(`];
  if (fns.length) {
    const f = fns.join("|");
    forms.push(`\\b(?:apply|reflectApply|Reflect\\.apply)\\(\\s*(?:${f})\\s*,\\s*(?:${docs})\\b`);
    forms.push(`\\b(?:${f})\\.call\\(\\s*(?:${docs})\\b`);
  }
  return (src.match(new RegExp(forms.join("|"), "g")) || []).length;
}
// 5.0.7 (C50): page scripts deliberately run no MutationObserver (cost on heavy pages). A new one must be listed
// here with its limits (observed subtree, attributeFilter, work per callback, when it disconnects).
const MUTATION_OBSERVER_RE = /\bnew\s+MutationObserver\b|\bMutationObserverCtor\b/g;
const MUTATION_OBSERVER_ALLOWLIST = Object.freeze({});
// 5.0.7 (C53): a wrapper around a page API hands back the NATIVE promise; side work runs on a side branch. A wrapper
// that returns its own .then() chain makes every failure the page leaves unhandled an error of this extension.
const OWN_CHAIN_RE = /return\s+(?:reflectApply\(\s*_native\w*[^;]*?\)|_native\w*\([^;]*?\))\s*\.then\(/g;
// Classified exceptions (file → count, with the reason). A new document-level listener fails by default.
const DOCUMENT_LISTENER_ALLOWLIST = Object.freeze({
  "password-form-guard.js": { count: 1, reason: "Escape closes the in-page dialog only; a page that stops it keeps the dialog open and nothing is sent" }
});

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-message-gate: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const read = (rel) => readFileSync(resolve(ext, rel), "utf8");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);

let failures = 0;
function ok(label, pass, detail) {
  console.log(`${pass ? "ok  " : "FAIL"} ${label}${pass ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!pass) failures += 1;
}

let M, G;
try {
  M = await load("data/message-types.js");
  G = await load("core/message-gate.js");
} catch (e) { didNotRun(`could not load the extension modules: ${e.message}`); }

// ── A. sender kinds ──
const page = { id: "x", url: `${EXT_ORIGIN}ui/popup.html` };
const tabPage = { id: "x", url: `${EXT_ORIGIN}ui/warning.html?u=x`, tab: { id: 3 } };
const cs = { id: "x", url: "https://phish.example/login", tab: { id: 7 } };
const blankFrame = { id: "x", url: "about:blank", tab: { id: 7 } };
ok("popup is an extension page", G.senderKind(page, EXT_ORIGIN) === M.SENDER_KIND.EXTENSION_PAGE);
ok("warning page in a tab is an extension page", G.senderKind(tabPage, EXT_ORIGIN) === M.SENDER_KIND.EXTENSION_PAGE);
ok("a web page's content script is a content script", G.senderKind(cs, EXT_ORIGIN) === M.SENDER_KIND.CONTENT_SCRIPT);
ok("an about:blank frame's content script is a content script", G.senderKind(blankFrame, EXT_ORIGIN) === M.SENDER_KIND.CONTENT_SCRIPT);
ok("no url, no tab → unknown", G.senderKind({ id: "x" }, EXT_ORIGIN) === null);

const allTypes = Object.entries(M).filter(([k, v]) => k.startsWith("MSG_") && typeof v === "string").map(([, v]) => v);
const csTypes = [...M.CONTENT_SCRIPT_MESSAGES];
const pageOnly = allTypes.filter((t) => !M.CONTENT_SCRIPT_MESSAGES.has(t));
ok("content script: every content-script message allowed", csTypes.every((t) => G.isMessageAllowed(t, M.SENDER_KIND.CONTENT_SCRIPT)));
ok(`content script: all ${pageOnly.length} other messages refused (import, reset, trust …)`, pageOnly.every((t) => !G.isMessageAllowed(t, M.SENDER_KIND.CONTENT_SCRIPT)),
   pageOnly.filter((t) => G.isMessageAllowed(t, M.SENDER_KIND.CONTENT_SCRIPT)));
ok("extension page: every other message allowed", pageOnly.every((t) => G.isMessageAllowed(t, M.SENDER_KIND.EXTENSION_PAGE)));
ok("unknown sender: nothing allowed", allTypes.every((t) => !G.isMessageAllowed(t, null)));

// Every message type the content scripts actually send, read from their own MSG_* copies at their send sites.
const sent = new Set();
for (const f of readdirSync(resolve(ext, "security")).filter((n) => n.endsWith(".js"))) {
  const src = read(`security/${f}`);
  const copies = Object.fromEntries([...src.matchAll(/const (MSG_\w+)\s*=\s*'([^']+)'/g)].map((m) => [m[1], m[2]]));
  for (const m of src.matchAll(/sendMessage\(\{\s*type:\s*(MSG_\w+)/g)) sent.add(copies[m[1]] ?? `?${m[1]}`);
}
ok("every type a content script sends is a content-script message", [...sent].every((t) => M.CONTENT_SCRIPT_MESSAGES.has(t)), [...sent]);
ok("every content-script message is sent by some content script (no dead entry)", csTypes.every((t) => sent.has(t)), csTypes.filter((t) => !sent.has(t)));

const bg = read("background.js");
const listener = bg.slice(bg.indexOf("chrome.runtime.onMessage.addListener("));
ok("the router applies the gate before calling a handler",
   listener.includes("isMessageAllowed(msg.type, senderKind(sender, EXTENSION_ORIGIN))") &&
   listener.indexOf("isMessageAllowed(") < listener.indexOf("handler(msg, sender)"));

// ── B. in-page UI ──
const fw = read("security/fake-window-guard.js");
ok("fake sign-in: no dialog drawn into the page", !/attachShadow|createElement/.test(fw));
ok("fake sign-in: focusin on window, capture", /window\.addEventListener\('focusin',[\s\S]*?\}, true\);/.test(fw));
ok("fake sign-in: the service worker opens the warning page", /openPageScamWarning\(state, PAGE_SCAM_KIND\.FAKE_SIGN_IN_WINDOW/.test(bg));
const R = await load("data/page-scam-reasons.js");
ok("fake sign-in: the warning page has its reason", !!R.PAGE_SCAM_REASON_BY_ID[R.PAGE_SCAM_KIND.FAKE_SIGN_IN_WINDOW]);
const pf = read("security/password-form-guard.js");
ok("password form: submit intercepted on window, capture", /window\.addEventListener\('submit',[\s\S]*?\}, true\);/.test(pf));
ok("password form: no document-level interception left", !/document\.addEventListener\('submit'|document\.addEventListener\(PASSWORD_SUBMIT_EVENT/.test(pf));
ok("password form: dialog buttons act on real clicks only", (pf.match(/if \(!e\.isTrusted\) return;/g) || []).length >= 2);
for (const f of readdirSync(resolve(ext, PAGE_SCRIPT_DIR)).filter((n) => n.endsWith(".js"))) {
  const n = documentListenerCount(read(`${PAGE_SCRIPT_DIR}/${f}`));
  const allowed = DOCUMENT_LISTENER_ALLOWLIST[f] ? DOCUMENT_LISTENER_ALLOWLIST[f].count : 0;
  ok(`page script ${f}: no unclassified document-level listener (C47)`, n <= allowed, { found: n, allowed });
  const obs = (read(`${PAGE_SCRIPT_DIR}/${f}`).match(MUTATION_OBSERVER_RE) || []).length;
  const obsAllowed = MUTATION_OBSERVER_ALLOWLIST[f] ? MUTATION_OBSERVER_ALLOWLIST[f].count : 0;
  ok(`page script ${f}: no unbounded MutationObserver (C50)`, obs <= obsAllowed, { found: obs, allowed: obsAllowed });
  const chains = (read(`${PAGE_SCRIPT_DIR}/${f}`).match(OWN_CHAIN_RE) || []).length;
  ok(`page script ${f}: wrappers return the native promise, not their own .then() chain (C53)`, chains === 0, { found: chains });
}

// ── C. manifest ──
const manifest = JSON.parse(read("manifest.json"));
const csp = manifest.content_security_policy?.extension_pages ?? "";
ok("CSP carries every required directive", REQUIRED_CSP_DIRECTIVES.every((d) => csp.includes(d)), csp);
ok("CSP has no unsafe source", !UNSAFE_CSP_RE.test(csp), csp);
ok("no externally_connectable key", !Object.hasOwn(manifest, "externally_connectable"));
ok("no message_serialization key (C31: JSON mode)", !Object.hasOwn(manifest, "message_serialization"));
ok("no listener for other extensions or web pages", !/onMessageExternal|onConnectExternal/.test(bg));

console.log(failures ? `test-message-gate: FAIL — ${failures} case(s)` : "test-message-gate: PASS");
process.exit(failures ? EXIT.FAILED : EXIT.OK);
