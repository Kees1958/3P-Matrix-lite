#!/usr/bin/env node
// ── tools/test-tamper-guard.mjs ──────────────────────────────────────────────────
// 5.1.0 — Tamper Guard without a browser (the real-browser half is e2e-tamper-guard.mjs):
//   A. copies in the page scripts equal their sources (data/tamper-rules.js, data/constants.js) — content scripts
//      cannot import, so this is the only thing that keeps them from drifting;
//   B. registry: the three Tamper Guard options and their levels, `tab` and `requires` (one level deep, master never
//      from a higher level), blockRiskyDownloads requires warnRiskyDownloads (core/policy.js isProtectionEnabled);
//   C. core/tamper-guard.js decisions with a mocked chrome: which page is armed at which level and by which trigger tick,
//      the risk score and rating (5.1.3), what warns where (one window per page, updated; Suspicious by level and safer
//      regions, else the quiet mark), the destination checks (incl. IBAN), 3P Matrix's own wrappers ignored, the allow
//      list, cooldown, derived MANY_HOOKS, caps;
//   D. exceptions survive normalizeState and a settings-file round trip; invalid ones are dropped.
// Every expected value comes from the extension's own modules (C39a).
//
// Usage:  node test-tamper-guard.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const PAGE_SCRIPT = "security/tamper-guard-page.js";
const BRIDGE_SCRIPT = "security/tamper-guard-bridge.js";
const TAB = Object.freeze({ A: 11, B: 12, C: 13, D: 14, E: 15, F: 16, G: 17, H: 18 });
const ORDINARY = "https://news.example/article";
const OTHER_HOST = "collector.example";
// Owner 2026-11-24: only the four ticks arm a page — an ordinary page that must be watched closely in a test gets a
// checkout word in its address ("Enable on pages with checkout and payment keywords"; not a banking/payment page).
const WATCHED = "https://news.example/checkout";

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-tamper-guard: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const read = (rel) => readFileSync(resolve(ext, rel), "utf8");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);

// ── mocked chrome: records arm messages and warning windows ──
const sent = [];
const windows = [];
const updates = [];              // 5.1.3: MSG_TAMPER_WARNING_CHANGED to an open window
let nextWindow = 1;
globalThis.chrome = {
  runtime: { id: "test", getURL: (p) => `chrome-extension://test/${p}`,
             sendMessage: async (msg) => { updates.push(msg); } },
  tabs: { sendMessage: async (tabId, msg) => { sent.push({ tabId, msg }); } },
  windows: { create: async (o) => { const w = { id: nextWindow++, url: o.url }; windows.push(w); return w; },
             remove: async () => {} },
  storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener() {} } }
};

let failures = 0;
function ok(label, pass, detail) {
  console.log(`${pass ? "PASS" : "FAIL"} ${label}${pass ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!pass) failures += 1;
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

let C, M, P, R, S, IO, G, W, POL, B, X;
try {
  C = await load("data/constants.js");
  M = await load("data/message-types.js");
  P = await load("data/protections.js");
  R = await load("data/tamper-rules.js");
  S = await load("data/state-storage.js");
  IO = await load("data/settings-io.js");
  B = await load("data/builtin-domains.js");
  POL = await load("core/policy.js");
  G = await load("core/tamper-guard.js");
  W = await load("core/tamper-warnings.js");
  X = await load("core/xss-link-guard.js");
} catch (e) { didNotRun(`could not load the extension modules: ${e.message}`); }

// ── A. copies ──
function constIn(src, name) {
  const m = src.match(new RegExp(`const ${name} = Object\\.freeze\\(([\\s\\S]*?)\\);\\n`));
  if (!m) return undefined;
  return Function(`"use strict"; return (${m[1]});`)();     // a test-only literal read of our own shipped file
}
function numIn(src, name) {
  const m = src.match(new RegExp(`const ${name} = (\\d+);`));
  return m ? Number(m[1]) : undefined;
}
const page = read(PAGE_SCRIPT);
const bridge = read(BRIDGE_SCRIPT);
const staticRules = R.TAMPER_RULES.filter((r) => r.layer === R.TAMPER_LAYER.STATIC && (r.targets || []).length);
const expectedTargets = Object.fromEntries(staticRules.map((r) => [r.id, r.targets]));
ok("page script STATIC_TARGETS = data/tamper-rules.js targets", JSON.stringify(constIn(page, "STATIC_TARGETS")) === JSON.stringify(expectedTargets),
   { page: constIn(page, "STATIC_TARGETS") });
ok("page script ADDED_PROPS = TAMPER_ADDED_PROPS", JSON.stringify(constIn(page, "ADDED_PROPS")) === JSON.stringify(R.TAMPER_ADDED_PROPS));
const pageRule = constIn(page, "RULE");
ok("page script RULE values are rule ids", Object.values(pageRule).every((v) => R.TAMPER_RULE_IDS.includes(v)), pageRule);
ok("bridge PAGE_RULES = TAMPER_PAGE_RULES", JSON.stringify(constIn(bridge, "PAGE_RULES")) === JSON.stringify(R.TAMPER_PAGE_RULES));
const bridgeRule = constIn(bridge, "RULE");
ok("bridge RULE values are page rules", Object.values(bridgeRule).every((v) => R.TAMPER_PAGE_RULES.includes(v)), bridgeRule);
ok("bridge DETAIL_KIND = TAMPER_DETAIL", JSON.stringify(constIn(bridge, "DETAIL_KIND")) === JSON.stringify(R.TAMPER_DETAIL));
for (const [file, src] of [[PAGE_SCRIPT, page], [BRIDGE_SCRIPT, bridge]]) {
  ok(`${file}: MAX_REPORTED_ITEMS = TAMPER_DETAIL_ITEMS_MAX`, numIn(src, "MAX_REPORTED_ITEMS") === C.TAMPER_DETAIL_ITEMS_MAX);
  ok(`${file}: MAX_ITEM_CHARS = TAMPER_DETAIL_TEXT_MAX`, numIn(src, "MAX_ITEM_CHARS") === C.TAMPER_DETAIL_TEXT_MAX);
}
ok("bridge MAX_FRAME_HOSTS = TAMPER_FRAME_HOSTS_MAX", numIn(bridge, "MAX_FRAME_HOSTS") === C.TAMPER_FRAME_HOSTS_MAX);
ok("bridge MAX_SCRIPT_HOSTS = TAMPER_SCRIPT_HOSTS_MAX (5.1.2)", numIn(bridge, "MAX_SCRIPT_HOSTS") === C.TAMPER_SCRIPT_HOSTS_MAX);
for (const [file, src] of [[PAGE_SCRIPT, page], [BRIDGE_SCRIPT, bridge]]) {     // 5.1.2 card number by value
  ok(`${file}: CARD_VALUE_DIGITS_MIN/MAX = TAMPER_CARD_VALUE_DIGITS`,
     numIn(src, "CARD_VALUE_DIGITS_MIN") === C.TAMPER_CARD_VALUE_DIGITS.MIN && numIn(src, "CARD_VALUE_DIGITS_MAX") === C.TAMPER_CARD_VALUE_DIGITS.MAX);
  ok(`${file}: CARD_VALUE_FIELDS_MAX = TAMPER_CARD_VALUE_FIELDS_MAX`, numIn(src, "CARD_VALUE_FIELDS_MAX") === C.TAMPER_CARD_VALUE_FIELDS_MAX);
}
{ // 5.1.2 tgAddressScript copies (the page script cannot import)
  ok("page script XSS_MARKUP_PATTERNS = data/constants.js", JSON.stringify(constIn(page, "XSS_MARKUP_PATTERNS")) === JSON.stringify(C.XSS_MARKUP_PATTERNS),
     constIn(page, "XSS_MARKUP_PATTERNS"));
  ok("page script XSS_MARKUP_FLAGS = data/constants.js", new RegExp(`const XSS_MARKUP_FLAGS = '${C.XSS_MARKUP_FLAGS}';`).test(page));
  for (const n of ["XSS_DECODE_ROUNDS", "XSS_ADDRESS_CHARS_MAX", "XSS_PIECE_MIN_CHARS", "XSS_PIECES_MAX"]) {
    ok(`page script ${n} = data/constants.js`, numIn(page, n) === C[n]);
  }
  const sinks = [...page.matchAll(/Object\.freeze\(\['([^']+)', '[^']+', '[^']+', SINK_KIND\.\w+\]\)/g)].map((m) => m[1]);
  ok("page script ADDRESS_SINKS names = data/tamper-rules.js ADDRESS_SCRIPT.sinks",
     JSON.stringify(sinks) === JSON.stringify(R.TAMPER_RULE_BY_ID[R.TAMPER_RULE.ADDRESS_SCRIPT].sinks), sinks);
}
ok("every label fits the popup's one line (TAMPER_LABEL_MAX_CHARS)", R.TAMPER_RULES.every((r) => r.label.length <= R.TAMPER_LABEL_MAX_CHARS),
   R.TAMPER_RULES.filter((r) => r.label.length > R.TAMPER_LABEL_MAX_CHARS).map((r) => r.label));
ok("every rule has points, a label and a description; no severity left (5.1.3)",
   R.TAMPER_RULES.every((r) => Number.isInteger(r.points) && r.points > 0 && r.label && r.description && r.severity === undefined),
   R.TAMPER_RULES.filter((r) => !Number.isInteger(r.points)).map((r) => r.id));
{ // 5.1.3 copies: IBAN check, obfuscated-code event and sinks
  const ibanMod = constIn(page, "IBAN_MOD");
  ok("page script IBAN_MOD.DIVISOR/VALID = data/constants.js TAMPER_IBAN", !!ibanMod && ibanMod.DIVISOR === C.TAMPER_IBAN.DIVISOR &&
     ibanMod.VALID === C.TAMPER_IBAN.VALID, ibanMod);
  const ibanRe = page.match(/const IBAN_RE = \/\^\[a-z\]\{2\}\\d\{2\}\[a-z0-9\]\{(\d+),(\d+)\}\$\//);
  ok("page script IBAN_RE length = TAMPER_IBAN.MIN_CHARS–MAX_CHARS", !!ibanRe && Number(ibanRe[1]) + 4 === C.TAMPER_IBAN.MIN_CHARS &&
     Number(ibanRe[2]) + 4 === C.TAMPER_IBAN.MAX_CHARS, ibanRe && ibanRe.slice(1));
  const obf = read("security/sec-no-obfuscated-code.js");
  const ev = (src) => (src.match(/const TG_OBFUSCATED_EVENT = '([^']+)';/) || [])[1];
  ok("obfuscated-code block event: same name in the blocker and the bridge", !!ev(obf) && ev(obf) === ev(bridge));
  ok("bridge OBFUSCATED_SINKS = OBFUSCATED_CODE.sinks", JSON.stringify(constIn(bridge, "OBFUSCATED_SINKS")) ===
     JSON.stringify(R.TAMPER_RULE_BY_ID[R.TAMPER_RULE.OBFUSCATED_CODE].sinks));
  ok("blocker SINK values are OBFUSCATED_CODE sinks", Object.values(constIn(obf, "SINK")).every((v) =>
     R.TAMPER_RULE_BY_ID[R.TAMPER_RULE.OBFUSCATED_CODE].sinks.includes(v)));
}
ok("derived rules (MANY_HOOKS, SECOND_CARD_FORM) can never be reported by a page",
   R.TAMPER_DERIVED_RULES.every((r) => !R.TAMPER_PAGE_RULES.includes(r)));
ok("page script captures its built-ins: no for…of, no Map in the page script (C35)", !/for \(const \w+ of /.test(page) && !/new Map\(/.test(page));

// ── B. registry ──
const K = P.PROTECTION_KEY;
const byKey = P.PROTECTION_BY_KEY;
ok("\"Enable tamper detection\" (watchTamperSensitive) from level 2 (MILD), no built-in exemption",
   byKey[K.WATCH_TAMPER_SENSITIVE].fromLevel === C.LEVEL.MILD && byKey[K.WATCH_TAMPER_SENSITIVE].scope === P.SCOPE.EVERY_SITE &&
   !byKey[K.WATCH_TAMPER_SENSITIVE].trustedExempt);
ok("owner 2026-11-24: the level slider no longer widens the watching (TAMPER_LEVEL gone)", C.TAMPER_LEVEL === undefined);
const underSwitch = [K.WARN_PASSWORD_FORMS, K.WARN_PAYMENT_SKIMMER, K.BLOCK_FAKE_SIGNIN_WINDOW];
// Owner 2026-11-24 (evening): the obfuscated-code block is a Firewall protection again — own tick, number, not under the switch.
ok("blockObfuscatedEval: Firewall tab, numbered, own tick, not under the tamper switch, no level-5 strict script",
   P.tabOf(byKey[K.BLOCK_OBFUSCATED_EVAL]) === P.PROTECTION_TAB.BROWSING && Number.isInteger(byKey[K.BLOCK_OBFUSCATED_EVAL].num) &&
   byKey[K.BLOCK_OBFUSCATED_EVAL].switchable !== false && !byKey[K.BLOCK_OBFUSCATED_EVAL].requires && !byKey[K.BLOCK_OBFUSCATED_EVAL].strictScripts);
ok("password form, skimmer and fake sign-in run under the tamper switch: no checkbox, no number",
   underSwitch.every((k) => byKey[k].switchable === false && byKey[k].requires === K.WATCH_TAMPER_SENSITIVE && byKey[k].num === undefined));
ok("the Tamper Protection tab has no numbers at all", P.PROTECTIONS.filter((p) => P.tabOf(p) === P.PROTECTION_TAB.TAMPER).every((p) => p.num === undefined));
{
  const s = S.normalizeState({ disabledProtections: { [K.WARN_PASSWORD_FORMS]: true } });
  ok("an old untick of the password-form warning is dropped (it follows the switch now)", !s.disabledProtections[K.WARN_PASSWORD_FORMS] &&
     POL.isProtectionEnabled(s, K.WARN_PASSWORD_FORMS));
  s.disabledProtections[K.WATCH_TAMPER_SENSITIVE] = true;
  ok("tamper switch off → password form, skimmer and fake sign-in off too", underSwitch.every((k) => !POL.isProtectionEnabled(s, k)));
}
const deps = P.PROTECTIONS.filter((p) => p.requires);
ok("requires: every master exists, has no master itself, and is never from a higher level",
   deps.every((p) => byKey[p.requires] && !byKey[p.requires].requires && byKey[p.requires].fromLevel <= p.fromLevel),
   deps.map((p) => [p.key, p.requires]));
ok("blockRiskyDownloads requires warnRiskyDownloads", byKey[K.BLOCK_RISKY_DOWNLOADS].requires === K.WARN_RISKY_DOWNLOADS);
ok("Download tab: warnRiskyDownloads + blockRiskyDownloads", P.PROTECTIONS.filter((p) => P.tabOf(p) === P.PROTECTION_TAB.DOWNLOAD).map((p) => p.key).join() ===
   [K.WARN_RISKY_DOWNLOADS, K.BLOCK_RISKY_DOWNLOADS].join());
const TRIGGERS = [K.TAMPER_ON_SENSITIVE, K.TAMPER_ON_HIDDEN_FIELD, K.TAMPER_ON_CHECKOUT_WORDS, K.TAMPER_ON_LOCKED_PAGES];
ok("Tamper Protection tab: the switch + the three protections under it + the four trigger ticks",
   P.PROTECTIONS.filter((p) => P.tabOf(p) === P.PROTECTION_TAB.TAMPER).length === 8);
ok("trigger ticks: own checkbox, require the switch, level 2", TRIGGERS.every((k) => byKey[k] && byKey[k].switchable !== false &&
   byKey[k].requires === K.WATCH_TAMPER_SENSITIVE && byKey[k].fromLevel === C.LEVEL.MILD));
{
  const s = S.defaultState();
  delete s.disabledProtections[K.BLOCK_RISKY_DOWNLOADS];
  ok("blockRiskyDownloads ticked + warnRiskyDownloads ticked → enabled", POL.isProtectionEnabled(s, K.BLOCK_RISKY_DOWNLOADS));
  s.disabledProtections[K.WARN_RISKY_DOWNLOADS] = true;
  ok("warnRiskyDownloads unticked → blockRiskyDownloads off, its own tick kept",
     !POL.isProtectionEnabled(s, K.BLOCK_RISKY_DOWNLOADS) && POL.isProtectionTicked(s, K.BLOCK_RISKY_DOWNLOADS));
  ok("…and it is no longer active at any level", !POL.isProtectionActive(s, K.BLOCK_RISKY_DOWNLOADS, C.LEVEL_MAX));
}

// ── C. decisions ──
function stateAt(level, edit) {
  const s = S.defaultState();
  s.level = level;
  if (edit) edit(s);
  return S.normalizeState(s);
}
function sender(tabId, url, frameUrl) { return { tab: { id: tabId, url }, url: frameUrl || url }; }
function report(rule, kind, items) { return { type: M.MSG_TAMPER_REPORT, rule, detail: { kind, items } }; }
const T = R.TAMPER_RULE;
const D = R.TAMPER_DETAIL;
const payHost = B.BUILTIN_PAYMENT.find((h) => h.split(".").length === 2) || B.BUILTIN_PAYMENT[0];
const signInHost = B.BUILTIN_SIGN_IN[0];
const PAY = `https://${payHost}/account`;
// What was found on a tab's current page (core/tamper-guard.js pageFindings) — the state argument is not needed.
function eventsFor(tabId) { return G.pageFindings(tabId); }
function armedFor(tabId) { return sent.some((m) => m.tabId === tabId && m.msg.type === M.MSG_TAMPER_ARM); }

G.setCollectMsForTests(0);                       // 5.1.3: the collect delay, shortened (real value tested below)
const marks = [];
G.setMarkSink((tabId, rating) => marks.push({ tabId, rating }));
// The rating the badge was last given for a tab (owner 2026-11-24: full rating on a closely watched page, else Low).
function badgeRatingOf(tabId) { const m = marks.filter((x) => x.tabId === tabId); return m.length ? m[m.length - 1].rating : C.TAMPER_RATING.LOW; }
function markedOn(tabId) { return badgeRatingOf(tabId) === C.TAMPER_RATING.SUSPICIOUS; }
const settle = () => sleep(5);                   // let the collect timer fire
const RT = C.TAMPER_RATING;
function riskOf(tabId) { return G.pageRisk(tabId); }

{ // rating table
  ok("ratingOf: below Suspicious = Low", G.ratingOf(C.TAMPER_RATING_MIN_POINTS[RT.SUSPICIOUS] - 1) === RT.LOW);
  ok("ratingOf: the table's lowest scores", G.ratingOf(C.TAMPER_RATING_MIN_POINTS[RT.SUSPICIOUS]) === RT.SUSPICIOUS &&
     G.ratingOf(C.TAMPER_RATING_MIN_POINTS[RT.HIGH]) === RT.HIGH && G.ratingOf(C.TAMPER_RATING_MIN_POINTS[RT.CRITICAL]) === RT.CRITICAL);
  ok("password, card sent: Critical on their own", G.ratingOf(R.TAMPER_RULE_BY_ID[T.PASSWORD_SENT].points) === RT.CRITICAL &&
     G.ratingOf(R.TAMPER_RULE_BY_ID[T.CARD_SENT].points) === RT.CRITICAL);
  ok("10-point findings alone stay Low", R.TAMPER_RULES.filter((r) => r.points < C.TAMPER_SIGN_POINTS_MIN).every((r) => G.ratingOf(r.points) === RT.LOW));
}
{ // level 1: nothing
  const s = stateAt(C.LEVEL.ALLOW_ALL);
  ok("level 1: hello does not arm", G.onHello(s, sender(TAB.A, PAY)).arm === false);
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["JSON.parse"]), sender(TAB.A, PAY));
  ok("level 1: a report is ignored (no event)", eventsFor(TAB.A).length === 0);
}
{ // level 2, ordinary page
  const s = stateAt(C.LEVEL.MILD);
  ok("level 2, ordinary page: hello does not arm", G.onHello(s, sender(TAB.B, ORDINARY)).arm === false);
  const before = windows.length;
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["JSON.parse"]), sender(TAB.B, ORDINARY));
  await settle();
  ok("level 2, page no tick applies to: a report is ignored — nothing recorded, no warning (owner 2026-11-24)",
     windows.length === before && eventsFor(TAB.B).length === 0);
  ok("…and a report never arms it (only the four ticks do)", !armedFor(TAB.B));
  const r = G.onReport(s, report(T.PASSWORD_SENT, D.DEST, [OTHER_HOST]), sender(TAB.B, ORDINARY));
  ok("a dynamic report on a page that is not armed is dropped", r.arm === false && eventsFor(TAB.B).length === 0);
  ok("an unknown rule is refused", G.onReport(s, report("tgNope", D.TARGETS, ["x"]), sender(TAB.B, ORDINARY)).arm === false);
  G.onReport(s, report(T.ADDRESS_SCRIPT, D.TARGETS, ["Element.prototype.innerHTML"]), sender(TAB.B, ORDINARY));
  ok("an address-script report no longer arms a page (owner 2026-11-24)", !armedFor(TAB.B) && eventsFor(TAB.B).length === 0);
  const tw = 59;
  ok("a checkout word arms a page at hello (tick)", G.onHello(s, sender(tw, WATCHED)).arm === true);
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["JSON.parse"]), sender(tw, WATCHED));
  ok("watched page: a replaced JSON.parse is recorded", eventsFor(tw).length === 1);
  ok("a target of another rule is not taken", (G.onReport(s, report(T.CRYPTO_HOOKS, D.TARGETS, ["JSON.parse"]), sender(tw, WATCHED)), eventsFor(tw).length === 1));
  G.releaseTab(tw);
}
{ // level 2, known payment site: score × factor, Suspicious = quiet mark, then Critical = one window, updated
  const s = stateAt(C.LEVEL.MILD);
  ok(`level 2, known payment site (${payHost}): hello arms`, G.onHello(s, sender(TAB.C, PAY)).arm === true && armedFor(TAB.C));
  const before = windows.length;
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["JSON.parse"]), sender(TAB.C, PAY));
  await settle();
  const expect = Math.round(R.TAMPER_RULE_BY_ID[T.DATA_PARSING].points * C.TAMPER_SENSITIVE_FACTOR);
  ok(`payment page: the score counts × ${C.TAMPER_SENSITIVE_FACTOR}`, riskOf(TAB.C).score === expect, riskOf(TAB.C));
  ok("level 2: Suspicious gives only the badge (Suspicious → \"?\"), no window", riskOf(TAB.C).rating === RT.SUSPICIOUS && windows.length === before &&
     markedOn(TAB.C) && riskOf(TAB.C).outcome === G.TAMPER_OUTCOME.MARKED, riskOf(TAB.C));
  G.onReport(s, report(T.DATA_EDITED, D.KEYS, ["balance"]), sender(TAB.C, PAY));
  ok("edited data on top: Critical — the window opens at once (no collect delay)", windows.length === before + 1 &&
     riskOf(TAB.C).rating === RT.CRITICAL && badgeRatingOf(TAB.C) === RT.CRITICAL);
  const id = new URL(windows[windows.length - 1].url).searchParams.get(C.TAMPER_WARNING_ID_PARAM);
  let m = W.warningModel(id);
  ok("the window lists every finding, most points first, with the rating", !!m && m.signals.length === 2 &&
     m.signals[0].rule === T.DATA_EDITED && m.ratingLabel === R.TAMPER_RATING_LABEL[RT.CRITICAL] && m.critical && m.countdownS === 0, m);
  const nUpdates = updates.length;
  G.onReport(s, report(T.NETWORK_HOOKS, D.TARGETS, ["EventTarget.prototype.addEventListener"]), sender(TAB.C, PAY));
  m = W.warningModel(id);
  ok("a later finding updates the open window — no second window", windows.length === before + 1 && m.signals.length === 3 &&
     updates.length === nUpdates + 1 && updates[updates.length - 1].type === M.MSG_TAMPER_WARNING_CHANGED && updates[updates.length - 1].id === id);
  G.releaseTab(TAB.C);
  ok("releaseTab drops the tab's findings and its window", eventsFor(TAB.C).length === 0 && W.warningModel(id) === null);
}
{ // collect delay and reopen rule
  const s = stateAt(C.LEVEL.MILD);
  const t = 51;
  G.onHello(s, sender(t, WATCHED));
  G.setCollectMsForTests(40);
  const before = windows.length;
  G.onReport(s, report(T.ADDRESS_SCRIPT, D.TARGETS, ["Element.prototype.innerHTML"]), sender(t, WATCHED));   // 60: High
  ok("High: the window waits for the collect delay", windows.length === before && riskOf(t).outcome === G.TAMPER_OUTCOME.COLLECTING, riskOf(t));
  G.onReport(s, report(T.INVISIBLE_FRAME, D.DEST, [OTHER_HOST]), sender(t, WATCHED));                      // 70: still High
  await sleep(80);
  const id = new URL(windows[windows.length - 1].url).searchParams.get(C.TAMPER_WARNING_ID_PARAM);
  ok("…then ONE window with both findings", windows.length === before + 1 && W.warningModel(id).signals.length === 2);
  ok("High risk counts down", W.warningModel(id).countdownS === C.TAMPER_COUNTDOWN_S);
  G.setCollectMsForTests(0);
  await W.closeWarning(id);                                                          // the user chose Ignore
  G.onReport(s, report(T.STORAGE_HOOKS, D.TARGETS, ["Document.prototype.cookie"]), sender(t, WATCHED));
  await settle();
  ok("closed by the user: a finding at the same rating does not reopen it", windows.length === before + 1, riskOf(t));
  G.onReport(s, report(T.PASSWORD_SENT, D.DEST, [OTHER_HOST]), sender(t, WATCHED));
  ok("…a higher rating (Critical) opens it again", windows.length === before + 2);
  G.releaseTab(t);
  ok("the real collect delay is TAMPER_COLLECT_MS (2 s)", C.TAMPER_COLLECT_MS === 2000);
}
{ // Suspicious by level and safer regions
  const t = 52;
  const OUTSIDE = "https://shop.example/checkout/1";                // .example is not in the safer regions; watched (word)
  const s3 = stateAt(C.LEVEL.SMART);
  G.onHello(s3, sender(t, OUTSIDE));
  G.onReport(s3, report(T.CRYPTO_HOOKS, D.TARGETS, ["Crypto.prototype.getRandomValues"]), sender(t, OUTSIDE));   // 40: Suspicious, a sign
  const b3 = windows.length;
  await settle();
  ok("level 3, site outside safer regions: Suspicious warns", windows.length === b3 + 1 || riskOf(t).outcome === G.TAMPER_OUTCOME.WARNED, riskOf(t));
  G.releaseTab(t);
  const s3in = stateAt(C.LEVEL.SMART, (st) => { st.safeZone.tlds = ["example"]; });
  const t2 = 53;
  G.onHello(s3in, sender(t2, OUTSIDE));
  const b4 = windows.length;
  G.onReport(s3in, report(T.CRYPTO_HOOKS, D.TARGETS, ["Crypto.prototype.getRandomValues"]), sender(t2, OUTSIDE));
  await settle();
  ok("level 3, site inside safer regions: Suspicious only marks", windows.length === b4 && markedOn(t2), riskOf(t2));
  G.releaseTab(t2);
  const s4in = stateAt(C.LEVEL.HIGH, (st) => { st.safeZone.tlds = ["example"]; });
  const t3 = 54;
  G.onHello(s4in, sender(t3, OUTSIDE));
  const b5 = windows.length;
  G.onReport(s4in, report(T.CRYPTO_HOOKS, D.TARGETS, ["Crypto.prototype.getRandomValues"]), sender(t3, OUTSIDE));
  await settle();
  ok("level 4: Suspicious warns everywhere", windows.length === b5 + 1, riskOf(t3));
  G.releaseTab(t3);
}
{ // trigger ticks
  const t = 55;
  const sOff = stateAt(C.LEVEL.MILD, (st) => { st.disabledProtections[K.TAMPER_ON_SENSITIVE] = true; });
  ok("\"Enable on banking and payment pages\" unticked: a payment site is not armed at hello", G.onHello(sOff, sender(t, PAY)).arm === false);
  G.releaseTab(t);
  const CART = "https://shop5.example/checkout";
  const sw = stateAt(C.LEVEL.MILD, (st) => { st.disabledProtections[K.TAMPER_ON_CHECKOUT_WORDS] = true; });
  ok("\"…checkout and payment keywords\" unticked: an address word does not arm", G.onHello(sw, sender(56, CART)).arm === false);
  G.releaseTab(56);
  const sh = stateAt(C.LEVEL.MILD);
  const r = G.onSignals(sh, { type: M.MSG_TAMPER_SIGNALS, card: false, bank: false, hidden: true, frames: [] }, sender(57, ORDINARY));
  ok("a hidden password/card field: armed (trigger) and recorded as a finding", r.arm === true &&
     G.pageRisk(57).armedBy === G.ARMED_BY.HIDDEN_FIELD && eventsFor(57).some((e) => e.rule === T.HIDDEN_CREDENTIAL));
  G.releaseTab(57);
  const shOff = stateAt(C.LEVEL.MILD, (st) => { st.disabledProtections[K.TAMPER_ON_HIDDEN_FIELD] = true; });
  ok("…unticked: recorded, not armed", G.onSignals(shOff, { card: false, bank: false, hidden: true, frames: [] }, sender(58, ORDINARY)).arm === false &&
     eventsFor(58).some((e) => e.rule === T.HIDDEN_CREDENTIAL));
  G.releaseTab(58);
  const lock = (lvl) => stateAt(C.LEVEL.MILD, (st) => { st.siteLocks["news.example"] = lvl; st.siteLocksOrder.push("news.example"); });
  ok("\"Enable on locked pages\": a site locked at level 2 is armed", G.onHello(lock(C.LEVEL.MILD), sender(59, ORDINARY)).arm === true &&
     G.pageRisk(59).armedBy === G.ARMED_BY.LOCKED);
  G.releaseTab(59);
  ok("…a site locked at level 1 never", G.onHello(lock(C.LEVEL.ALLOW_ALL), sender(60, ORDINARY)).arm === false);
  G.releaseTab(60);
  const sNoLock = stateAt(C.LEVEL.MILD, (st) => { st.siteLocks["news.example"] = C.LEVEL.MILD; st.siteLocksOrder.push("news.example");
                                                  st.disabledProtections[K.TAMPER_ON_LOCKED_PAGES] = true; });
  ok("…unticked: not armed", G.onHello(sNoLock, sender(61, ORDINARY)).arm === false);
  G.releaseTab(61);
}
{ // signals make a page sensitive: findings recorded before count
  const s = stateAt(C.LEVEL.MILD);
  const SHOP = "https://shop.example/product/42";   // no address word
  G.onHello(s, sender(TAB.D, SHOP));
  const before = windows.length;
  G.onReport(s, report(T.INPUT_HOOKS, D.TARGETS, ["HTMLInputElement.prototype.value"]), sender(TAB.D, SHOP));
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["Response.prototype.json"]), sender(TAB.D, SHOP));
  await settle();
  ok("shop page before its card form: not watched — reports ignored, nothing kept", windows.length === before && eventsFor(TAB.D).length === 0);
  const r = G.onSignals(s, { type: M.MSG_TAMPER_SIGNALS, card: true, bank: false, frames: [] }, sender(TAB.D, SHOP));
  ok("a card field makes it a payment page: armed", r.arm === true);
  // the page scripts held what they noticed and send it now that the page is armed (security/tamper-guard-page.js pending)
  G.onReport(s, report(T.INPUT_HOOKS, D.TARGETS, ["HTMLInputElement.prototype.value"]), sender(TAB.D, SHOP));
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["Response.prototype.json"]), sender(TAB.D, SHOP));
  await settle();
  ok("…and what the page held back counts (× factor): High, a warning", windows.length === before + 1 && riskOf(TAB.D).rating === RT.HIGH, riskOf(TAB.D));
  ok("signals with only frames from unknown hosts do not arm",
     G.onSignals(stateAt(C.LEVEL.MILD), { card: false, bank: false, frames: ["ads.example"] }, sender(TAB.E, "https://blog.example/")).arm === false);
  ok("a frame from a payment host reaches the threshold",
     G.onSignals(s, { card: false, bank: false, frames: [payHost] }, sender(TAB.F, "https://shop2.example/checkout")).arm === true);
}
{ // 5.1.1 address words: armed early, never sensitive by themselves
  const hit = (u) => G.hasAddressWord(u, new URL(u).hostname);
  const HITS = ["https://shop.example/checkout", "https://shop.example/checkout/onepage/", "https://shop.example/onepagecheckout",
    "https://shop.example/firecheckout", "https://shop.example/nl/winkelwagen", "https://shop.example/afrekenen?step=2",
    "https://shop.example/de/kasse", "https://shop.example/warenkorb", "https://shop.example/fr/panier",
    "https://shop.example/es/carrito", "https://shop.example/it/carrello", "https://shop.example/pl/koszyk",
    "https://shop.example/pl/p%C5%82atno%C5%9B%C4%87", "https://shop.example/sv/varukorg", "https://shop.example/no/handlekurv",
    "https://shop.example/da/indk%C3%B8bskurv", "https://shop.example/fi/ostoskori", "https://shop.example/cs/ko%C5%A1%C3%ADk",
    "https://shop.example/hu/p%C3%A9nzt%C3%A1r", "https://shop.example/ro/co%C8%99", "https://shop.example/lt/krep%C5%A1elis",
    "https://shop.example/bg/%D0%BA%D0%BE%D0%BB%D0%B8%D1%87%D0%BA%D0%B0", "https://shop.example/el/%CE%BA%CE%B1%CE%BB%CE%AC%CE%B8%CE%B9",
    "https://checkout.shop.example/", "https://bank.example/onlinebanking/login"];
  const MISSES = ["https://shop.example/kassabon-tips", "https://news.example/article", "https://kassa.example/",
    "https://checkout.example/", "https://blog.example/the-cartography-of-maps", "https://shop.example/product/42",
    "https://shop.example/%E0%A4%A", "https://shop.example/recommandations"];
  const wrongHits = HITS.filter((u) => !hit(u));
  ok(`address words: ${HITS.length} checkout/cart/payment addresses in EU+ languages match`, wrongHits.length === 0, wrongHits);
  const wrongMisses = MISSES.filter(hit);
  ok("address words: parts of words, the site's own name and malformed escapes do not match", wrongMisses.length === 0, wrongMisses);
  ok("address words: a very long address is cut at TAMPER_ADDRESS_TOKENS_MAX tokens",
     !hit(`https://shop.example/${"x/".repeat(C.TAMPER_ADDRESS_TOKENS_MAX)}checkout`));

  const s = stateAt(C.LEVEL.MILD);
  const CART = "https://shop3.example/checkout";
  const t = 31;
  ok("level 2: an address word arms at hello", G.onHello(s, sender(t, CART)).arm === true && armedFor(t));
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["Response.prototype.json"]), sender(t, CART));
  ok("…but the page is not a payment page by it: no factor", riskOf(t).score === R.TAMPER_RULE_BY_ID[T.DATA_PARSING].points, riskOf(t));
  G.onSignals(s, { type: M.MSG_TAMPER_SIGNALS, card: true, bank: false, frames: [] }, sender(t, CART));
  ok("a card field confirms it: the factor applies", riskOf(t).score ===
     Math.round(R.TAMPER_RULE_BY_ID[T.DATA_PARSING].points * C.TAMPER_SENSITIVE_FACTOR), riskOf(t));
  G.releaseTab(t);
  ok("level 1: an address word does nothing", G.onHello(stateAt(C.LEVEL.ALLOW_ALL), sender(32, CART)).arm === false);
}
{ // 5.1.2 second card form: own card-number field + a payment provider's frame
  const s = stateAt(C.LEVEL.MILD);
  const SHOP = "https://shop4.example/pay";
  const t = 33;
  G.onHello(s, sender(t, SHOP));
  G.onSignals(s, { type: M.MSG_TAMPER_SIGNALS, card: true, cardNumber: true, bank: false, frames: [] }, sender(t, SHOP));
  ok("own card-number field alone: no second-card-form finding", !eventsFor(t).some((e) => e.rule === T.SECOND_CARD_FORM));
  const before = windows.length;
  G.onSignals(s, { type: M.MSG_TAMPER_SIGNALS, card: true, cardNumber: true, bank: false, frames: [payHost] }, sender(t, SHOP));
  await settle();
  const f = eventsFor(t).find((e) => e.rule === T.SECOND_CARD_FORM);
  ok("…plus a payment provider's frame: second-card-form finding naming that frame, and a warning",
     !!f && f.items[0] === payHost && windows.length === before + 1, { f, n: windows.length - before });
  G.releaseTab(t);
  const t2 = 34;
  G.onHello(s, sender(t2, SHOP));
  G.onSignals(s, { type: M.MSG_TAMPER_SIGNALS, card: true, cardNumber: false, bank: false, frames: [payHost] }, sender(t2, SHOP));
  G.onSignals(s, { type: M.MSG_TAMPER_SIGNALS, card: true, cardNumber: true, bank: false, frames: [] },
              sender(t2, SHOP, `https://${payHost}/frame`));
  ok("a card-number field INSIDE the payment provider's frame is not a second form", !eventsFor(t2).some((e) => e.rule === T.SECOND_CARD_FORM));
  ok("a page can never report the second card form itself", G.onReport(s, report(T.SECOND_CARD_FORM, D.DEST, ["x.example"]), sender(t2, SHOP)) &&
     !eventsFor(t2).some((e) => e.rule === T.SECOND_CARD_FORM));
  G.releaseTab(t2);
}
{ // 5.1.2 suspicious script hosts
  const IMIT = ["jquery-cdn.net", "googletagmanagr.com", "cdn-stripe.xyz", "jquerycdn.su", "facebook-pixel.top", "shopify-cdn.com"];
  const REAL = ["code.jquery.com", "jqueryui.com", "js.stripe.com", "www.googletagmanager.com", "connect.facebook.net",
                "www.google-analytics.com", "cdn.shopify.com", "js.klarna.com", "pinstripe.com", "bat.bing.com"];
  const missed = IMIT.filter((h) => !G.imitatesProvider(h));
  ok(`imitatesProvider: ${IMIT.length} skimmer-style script hosts imitate a provider`, missed.length === 0, missed);
  const wrong = REAL.filter((h) => G.imitatesProvider(h));
  ok(`imitatesProvider: ${REAL.length} real provider and ordinary hosts do not`, wrong.length === 0, wrong);
  const s = stateAt(C.LEVEL.MILD);
  const t = 35;
  G.clearScriptVerdicts();
  G.onHello(s, sender(t, PAY));
  const before = windows.length;
  G.onReport(s, report(T.SUSPICIOUS_SCRIPT, D.DEST, ["cdn.shopify.com", "www.googletagmanager.com", `cdn.${payHost}`]), sender(t, PAY));
  ok("ordinary script hosts and the page's own site: no finding", !eventsFor(t).some((e) => e.rule === T.SUSPICIOUS_SCRIPT));
  G.onReport(s, report(T.SUSPICIOUS_SCRIPT, D.DEST, ["static.hotjar.com", "g00gle-analytics.com", "jquery-cdn.net"]), sender(t, PAY));
  await settle();
  const f = eventsFor(t).find((e) => e.rule === T.SUSPICIOUS_SCRIPT);
  ok("look-alike and imitating script hosts on a payment page: finding with just those hosts, High (× factor), a warning",
     !!f && JSON.stringify(f.items) === JSON.stringify(["g00gle-analytics.com", "jquery-cdn.net"]) && windows.length === before + 1, f);
  G.releaseTab(t);
}
{ // 5.1.2 warnXssLinks (Browsing): another site's link with script code in the address
  const s = stateAt(C.LEVEL.MILD);
  const TARGET = "https://bank.example/search";
  const FROM = "https://attacker.example";
  const HITS = [`${TARGET}?q=<script>alert(1)</script>`, `${TARGET}?q=%3Cscript%3Ealert(1)%3C/script%3E`,
    `${TARGET}?q=%253Cscript%253E`, `${TARGET}?q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E`, `${TARGET}?next=javascript:alert(1)`,
    `${TARGET}/%3Csvg%2Fonload%3Dalert(1)%3E`];
  const wrongHits = HITS.filter((u) => !X.xssLinkDecision(s, u, FROM).warn);
  ok(`XSS links: ${HITS.length} addresses with script markup (plain, encoded, double-encoded, in the path) warn`, wrongHits.length === 0, wrongHits);
  const MISSES = [[`${TARGET}?q=scripts+for+beginners`, FROM], [`${TARGET}?q=a<b+and+c>d`, FROM], [`${TARGET}?q=%3Cb%3Ebold%3C/b%3E`, FROM],
    [`${TARGET}?q=<script>`, "https://www.bank.example"], [`${TARGET}?q=<script>`, undefined], [`${TARGET}?q=%E0%A4%A`, FROM],
    [`${TARGET}#<script>alert(1)</script>`, FROM]];
  const wrongMisses = MISSES.filter(([u, i]) => X.xssLinkDecision(s, u, i).warn);
  ok("XSS links: harmless markup, the same site, a typed address, a malformed escape and the # part do not warn",
     wrongMisses.length === 0, wrongMisses);
  ok("XSS links: an opaque (sandboxed) sender warns, without a site name", (() => { const d = X.xssLinkDecision(s, HITS[0], "null"); return d.warn && d.referrer === ""; })());
  ok("XSS links: the warning names the sending site", X.xssLinkDecision(s, HITS[0], FROM).referrer === "attacker.example");
  ok("XSS links: level 1 (allow all) — no warning", !X.xssLinkDecision(stateAt(C.LEVEL.ALLOW_ALL), HITS[0], FROM).warn);
  ok("XSS links: the cheap pre-check lets ordinary navigations through without loading state",
     !X.mayBeXssLink({ tabId: 1, type: "main_frame", initiator: FROM, url: `${TARGET}?q=hello` }) &&
     X.mayBeXssLink({ tabId: 1, type: "main_frame", initiator: FROM, url: HITS[1] }) &&
     !X.mayBeXssLink({ tabId: 1, type: "main_frame", url: HITS[0] }));
}
{ // 5.1.2 tgAddressScript (Tamper) — owner 2026-11-24: on a watched page only (it no longer arms a page)
  const s = stateAt(C.LEVEL.MILD);
  const t = 37;
  G.onHello(s, sender(t, WATCHED));
  const before = windows.length;
  G.onReport(s, report(T.ADDRESS_SCRIPT, D.TARGETS, ["Element.prototype.innerHTML"]), sender(t, WATCHED));
  await settle();
  const f = eventsFor(t).find((e) => e.rule === T.ADDRESS_SCRIPT);
  ok("address script put into a watched page: a warning (High)", !!f && windows.length === before + 1, { f });
  G.onHello(s, sender(38, WATCHED));
  G.onReport(s, report(T.ADDRESS_SCRIPT, D.TARGETS, ["not.a.sink"]), sender(38, WATCHED));
  ok("a sink name that is not the rule's own is dropped", !eventsFor(38).some((e) => e.rule === T.ADDRESS_SCRIPT));
  G.releaseTab(t); G.releaseTab(38);
}
{ // 5.1.3 tgObfuscatedCode — owner 2026-11-24: a sign on a watched page only; it never arms a page
  const s2 = stateAt(C.LEVEL.MILD);
  G.onReport(s2, report(T.OBFUSCATED_CODE, D.TARGETS, ["eval"]), sender(62, ORDINARY));
  ok("obfuscated code blocked on a page no tick applies to: nothing kept, not armed", eventsFor(62).length === 0 && !armedFor(62));
  G.onHello(s2, sender(63, WATCHED));
  G.onReport(s2, report(T.OBFUSCATED_CODE, D.TARGETS, ["document.write"]), sender(63, WATCHED));
  ok("…a name that is not one of its entry points is dropped", eventsFor(63).length === 0);
  G.onReport(s2, report(T.OBFUSCATED_CODE, D.TARGETS, ["eval"]), sender(63, WATCHED));
  ok("…on a watched page it is a sign", eventsFor(63).some((e) => e.rule === T.OBFUSCATED_CODE));
  const s3 = stateAt(C.LEVEL.SMART);
  const r = G.onReport(s3, report(T.OBFUSCATED_CODE, D.TARGETS, ["setTimeout"]), sender(64, ORDINARY));
  ok("level 3: it no longer arms a page", r.arm === false && !armedFor(64));
  G.releaseTab(62); G.releaseTab(63); G.releaseTab(64);
}
{ // destinations (incl. 5.1.3 IBAN)
  const s = stateAt(C.LEVEL.MILD);
  G.onHello(s, sender(TAB.G, PAY));
  const n0 = eventsFor(TAB.G).length;
  G.onReport(s, report(T.PASSWORD_SENT, D.DEST, [`api.${payHost}`]), sender(TAB.G, PAY));
  ok("password to the page's own site: no finding", eventsFor(TAB.G).length === n0);
  G.onReport(s, report(T.PASSWORD_SENT, D.DEST, [signInHost]), sender(TAB.G, PAY));
  ok(`password to a known sign-in host (${signInHost}): no finding`, eventsFor(TAB.G).length === n0);
  G.onReport(s, report(T.CARD_SENT, D.DEST, [B.BUILTIN_PAYMENT[1] || payHost]), sender(TAB.G, PAY));
  ok("card number to a known payment provider: no finding", eventsFor(TAB.G).length === n0);
  G.onReport(s, report(T.IBAN_SENT, D.DEST, [B.BUILTIN_PAYMENT[1] || payHost]), sender(TAB.G, PAY));
  ok("IBAN to a known payment provider: no finding", eventsFor(TAB.G).length === n0);
  G.onReport(s, report(T.IBAN_SENT, D.DEST, [OTHER_HOST]), sender(TAB.G, PAY));
  ok("IBAN to another site: a finding", eventsFor(TAB.G).some((e) => e.rule === T.IBAN_SENT));
  G.onReport(s, report(T.CARD_SENT, D.DEST, [OTHER_HOST]), sender(TAB.G, PAY));
  ok("card number to another site: the page is Critical", eventsFor(TAB.G).some((e) => e.rule === T.CARD_SENT) && riskOf(TAB.G).rating === RT.CRITICAL);
  G.onReport(s, report(T.PASSWORD_SENT, D.DEST, ["not a host"]), sender(TAB.G, PAY));
  ok("an invalid destination is dropped", !eventsFor(TAB.G).some((e) => e.rule === T.PASSWORD_SENT));
  G.releaseTab(TAB.G);
}
{ // owner 2026-11-24: no level widens the watching (the Speedometer case); 3P Matrix's own wrappers
  const s3 = stateAt(C.LEVEL.SMART);
  const t = 21;
  G.onHello(s3, sender(t, ORDINARY));
  const r = G.onReport(s3, report(T.FUNCTION_HOOKS, D.TARGETS, ["Function.prototype.toString"]), sender(t, ORDINARY));
  ok("level 3: a replaced core function does not arm a page (only the four ticks do)", r.arm === false && !armedFor(t) && eventsFor(t).length === 0);
  const s4 = stateAt(C.LEVEL.HIGH);
  ok("level 4: an ordinary page is not armed at hello", G.onHello(s4, sender(20, ORDINARY)).arm === false);
  ok("level 4: a page a tick applies to is", G.onHello(s4, sender(22, WATCHED)).arm === true);
  G.onReport(s4, report(T.NETWORK_HOOKS, D.TARGETS, ["XMLHttpRequest.prototype.response", "fetch"]), sender(22, WATCHED));
  const ev = eventsFor(22).find((e) => e.rule === T.NETWORK_HOOKS);
  ok("level 4: the XHR response getter (wrapped by blockWebAssembly there) is ignored, fetch kept (5.1.3: no longer wrapped)",
     !!ev && ev.items.join() === "fetch", ev);
  const s4off = stateAt(C.LEVEL.HIGH, (s) => { s.disabledProtections[K.BLOCK_WEBASSEMBLY] = true; });
  G.onHello(s4off, sender(23, WATCHED));
  G.onReport(s4off, report(T.NETWORK_HOOKS, D.TARGETS, ["XMLHttpRequest.prototype.response"]), sender(23, WATCHED));
  ok("…with blockWebAssembly off, a replaced XHR response getter is a finding", eventsFor(23).some((e) => e.rule === T.NETWORK_HOOKS));
  const sTrust = stateAt(C.LEVEL.HIGH, (s) => { s.siteLocks["news.example"] = C.LEVEL.ALLOW_ALL; s.siteLocksOrder.push("news.example"); });
  ok("a trusted site (allow list) is never watched", G.onHello(sTrust, sender(24, WATCHED)).arm === false);
  const sAlwaysOff = stateAt(C.LEVEL.HIGH, (s) => { s.disabledProtections[K.WATCH_TAMPER_SENSITIVE] = true; });
  ok("master unticked: no tick arms anything", G.onHello(sAlwaysOff, sender(25, WATCHED)).arm === false);
}
{ // MANY_HOOKS, allow list, cooldown
  const s = stateAt(C.LEVEL.MILD);
  const t = 31;
  G.onHello(s, sender(t, PAY));
  G.onReport(s, report(T.FUNCTION_HOOKS, D.TARGETS, ["Function.prototype.toString", "Function.prototype.call"]), sender(t, PAY));
  G.onReport(s, report(T.DATA_PARSING, D.TARGETS, ["JSON.parse"]), sender(t, PAY));
  ok("three sign targets: MANY_HOOKS derived, its points counted", eventsFor(t).some((e) => e.rule === T.MANY_HOOKS) &&
     riskOf(t).score === Math.round((R.TAMPER_RULE_BY_ID[T.FUNCTION_HOOKS].points + R.TAMPER_RULE_BY_ID[T.DATA_PARSING].points +
       R.TAMPER_RULE_BY_ID[T.MANY_HOOKS].points) * C.TAMPER_SENSITIVE_FACTOR), riskOf(t));
  ok("a page can never report MANY_HOOKS itself", !R.TAMPER_PAGE_RULES.includes(T.MANY_HOOKS));
  G.releaseTab(t);
  const sx = stateAt(C.LEVEL.MILD, (st) => { st.allowCategories.tamper.push(payHost); });   // 5.1.3: "Tamper: site"
  const t2 = 32;
  G.onHello(sx, sender(t2, PAY));
  const before = windows.length;
  G.onReport(sx, report(T.PASSWORD_SENT, D.DEST, [OTHER_HOST]), sender(t2, PAY));
  await settle();
  ok("the site on the allow list under Tamper: no warning, outcome says so", windows.length === before &&
     riskOf(t2).outcome === G.TAMPER_OUTCOME.EXCEPTION, riskOf(t2));
  ok("…and nothing on the badge (\"Tamper: site\" = recorded only)", badgeRatingOf(t2) === RT.LOW);
  // cooldown: a closely watched page → another page of the same site is armed at hello; another site is not
  const so = stateAt(C.LEVEL.MILD);
  const t3 = 33;
  G.onHello(so, sender(t3, "https://shop3.example/checkout/pay"));
  G.onSignals(so, { card: true, bank: false, frames: [] }, sender(t3, "https://shop3.example/checkout/pay"));
  G.onCommitted(t3, "https://shop3.example/thanks");
  ok("cooldown: the next page of the same site is armed at hello", G.onHello(so, sender(t3, "https://shop3.example/thanks")).arm === true);
  G.onCommitted(t3, ORDINARY);
  ok("another site: back to standby", G.onHello(so, sender(t3, ORDINARY)).arm === false);
  ok("phases are the declared state machine", Object.values(G.TAMPER_PHASE).length === 3);
}
{ // warning window model
  ok("warning model: nothing for an unknown id", W.warningModel("nope") === null);
}
{ // bounds: one finding per rule per page, detail items and text capped
  const s = stateAt(C.LEVEL.MILD);
  const t = 41;
  G.onHello(s, sender(t, WATCHED));
  for (let i = 0; i < C.TAMPER_DETAIL_ITEMS_MAX * 2; i++) {
    G.onReport(s, report(T.PROTOTYPE_POLLUTION, D.TARGETS, [`Object.prototype.p${i}`]), sender(t, WATCHED));
  }
  ok("a page holds one finding per rule, however many reports", eventsFor(t).filter((e) => e.rule === T.PROTOTYPE_POLLUTION).length === 1);
  ok("…with at most TAMPER_DETAIL_ITEMS_MAX items", eventsFor(t).every((e) => e.items.length <= C.TAMPER_DETAIL_ITEMS_MAX));
  const long = "x".repeat(C.TAMPER_DETAIL_TEXT_MAX * 2);
  G.onReport(s, report(T.ARRAY_EXTENDED, D.TARGETS, [`Array.prototype.${long}`]), sender(t, WATCHED));
  ok("detail text is cut at TAMPER_DETAIL_TEXT_MAX", eventsFor(t).every((e) => e.items.every((x) => x.length <= C.TAMPER_DETAIL_TEXT_MAX)));
  G.onCommitted(t, "https://other.example/");
  ok("a new page starts with no findings and a Low rating", eventsFor(t).length === 0 && riskOf(t).rating === RT.LOW);
}
// 5.1.3 (issue 3) — the protections with their own warning are also 100-point findings, never an extra window.
const own = underSwitch;
const ownRule = (k) => R.TAMPER_RULE_OF_OWN_WARNING[k];
{
  ok("each own-warning protection has exactly one rule, at TAMPER_OWN_WARNING_POINTS",
     own.every((k) => ownRule(k) && R.TAMPER_RULE_BY_ID[ownRule(k)].points === C.TAMPER_OWN_WARNING_POINTS) &&
     Object.keys(R.TAMPER_RULE_OF_OWN_WARNING).length === own.length, R.TAMPER_RULE_OF_OWN_WARNING);
  ok("a page can never report an own-warning finding itself", own.every((k) => !R.TAMPER_PAGE_RULES.includes(ownRule(k))));
  ok("an own-warning finding alone rates Critical", G.ratingOf(C.TAMPER_OWN_WARNING_POINTS) === RT.CRITICAL);
  ok("a protection without a tamper rule (ClickFix) records nothing",
     G.recordOwnWarning(stateAt(C.LEVEL.MILD), K.BLOCK_CLICK_FIX, sender(151, ORDINARY)) === false && eventsFor(151).length === 0);
  for (const [i, k] of own.entries()) {   // owner 2026-11-24: a page no tick applies to keeps nothing (own warning still warns)
    const t = 152 + i;
    const s = stateAt(C.LEVEL.MILD);
    G.onHello(s, sender(t, ORDINARY));
    ok(`${k}: on a page that is not watched closely nothing is recorded`,
       G.recordOwnWarning(s, k, sender(t, ORDINARY), [OTHER_HOST]) === false && eventsFor(t).length === 0);
    const before = windows.length;
    G.onHello(s, sender(160 + i, WATCHED));
    ok(`${k}: on a watched page recorded as ${ownRule(k)} (with its detail host)`,
       G.recordOwnWarning(s, k, sender(160 + i, WATCHED), [OTHER_HOST]) === true &&
       eventsFor(160 + i).some((e) => e.rule === ownRule(k) && e.items.join() === OTHER_HOST));
    await settle();
    ok(`${k}: the page rates Critical, but no tamper window opens`, riskOf(160 + i).rating === RT.CRITICAL && windows.length === before);
    G.releaseTab(t); G.releaseTab(160 + i);
  }
  { // armed (banking) page: still no window of its own …
    const t = 156;
    const s = stateAt(C.LEVEL.MILD);
    G.onHello(s, sender(t, PAY));
    const before = windows.length;
    G.recordOwnWarning(s, K.WARN_PASSWORD_FORMS, sender(t, PAY), [OTHER_HOST]);
    await settle();
    ok("armed page: an own-warning finding opens no tamper window", riskOf(t).armed && windows.length === before);
    ok("…but the badge gets the full rating (highest problem wins: Critical → \"!\")", badgeRatingOf(t) === RT.CRITICAL);
    // … but a window opened by other findings lists it, and the score includes its points
    G.onReport(s, report(T.CARD_SENT, D.DEST, [OTHER_HOST]), sender(t, PAY));
    await settle();
    ok("…a window opened by another finding counts it", windows.length === before + 1 &&
       eventsFor(t).some((e) => e.rule === T.PASSWORD_FORM) && riskOf(t).score >= C.TAMPER_OWN_WARNING_POINTS * 2, riskOf(t));
    const n = updates.length;
    G.recordOwnWarning(s, K.BLOCK_FAKE_SIGNIN_WINDOW, sender(t, PAY), [signInHost]);
    ok("…and a later own-warning finding updates that open window", updates.length > n && windows.length === before + 1);
  }
  { // the switch or the protection off: nothing recorded
    const t = 157;
    const s = stateAt(C.LEVEL.MILD, (x) => { x.disabledProtections[K.WATCH_TAMPER_SENSITIVE] = true; });
    ok("tamper switch off → no own-warning finding", G.recordOwnWarning(s, K.WARN_PAYMENT_SKIMMER, sender(t, ORDINARY)) === false &&
       eventsFor(t).length === 0);
    ok("level 1 → no own-warning finding", G.recordOwnWarning(stateAt(C.LEVEL.ALLOW_ALL), K.WARN_PAYMENT_SKIMMER, sender(158, ORDINARY)) === false);
  }
}
{ // the Protections page list: plain, most points first, points on every row
  const rules = G.tamperView().rules;
  ok("signal list sorted by points, most first", rules.every((r, i) => i === 0 || rules[i - 1].points >= r.points));
  ok("the own-warning signs come first, at TAMPER_OWN_WARNING_POINTS, marked warnsAtOnce (issue 3)",
     rules.slice(0, own.length).map((r) => r.id).join() === own.map(ownRule).join() && rules[0].points === C.TAMPER_OWN_WARNING_POINTS &&
     rules.filter((r) => r.warnsAtOnce).length === own.length);
  ok("every rule is listed once (one source: the rules table), every row has a label, description and points",
     rules.length === R.TAMPER_RULES.length && new Set(rules.map((r) => r.id)).size === rules.length &&
     rules.every((r) => r.label && r.description && Number.isInteger(r.points)));
  const ui = read("ui/protections.js");
  ok("the list's heading (issue 5)", ui.includes(`const TAMPER_LIST_HEAD = "Signs of tampering — points add up to the page's risk rating";`) &&
     /head\.textContent = TAMPER_LIST_HEAD/.test(ui));
}

// (5.1.3: the never-warn list and its storage are gone — the allow list's "Tamper: site" lines replace them; their
//  format, storage and backup file are tested in tools/test-allow-list.mjs.)

if (failures) { console.error(`test-tamper-guard: FAIL — ${failures} case(s)`); process.exit(EXIT.FAILED); }
console.log("test-tamper-guard: ALL PASS");
process.exit(EXIT.OK);
