// ── core/tamper-guard.js ──────────────────────────────────────────────────────
// 5.1.0 — Tamper Guard's decisions in the service worker: which page is watched closely, what a page report means,
// and whether it opens a warning. Pages only REPORT (security/tamper-guard-page.js, security/tamper-guard-bridge.js);
// every decision is made here from the message SENDER (C28) and the rules table (data/tamper-rules.js, C46).
//
// Public interface:
//   onHello(state, sender)          — top frame started → { arm }: "Always watch" level, a known banking/payment site
//                                     (tick tamperOnSensitive), the same site within the cooldown, a checkout/cart/
//                                     payment word in the address (tick tamperOnCheckoutWords) or a locked site
//                                     (tick tamperOnLockedPages, never level 1)
//   hasAddressWord(url, host)       — the address-word test (exported for tests)
//   onSignals(state, msg, sender)   — card/bank fields, hidden password/card fields (5.1.3) and frame hosts → { arm };
//                                     5.1.2: also derives tgSecondCardForm (own card-number field + a payment provider's frame)
//   onReport(state, msg, sender)    — a finding → recorded, the page's risk rating evaluated → { arm }
//   recordOwnWarning(state, key, sender, items) — 5.1.3 (issue 3): protection `key` (warnPasswordForms,
//                                     warnPaymentSkimmer, blockFakeSignInWindow) just decided to give its OWN warning
//                                     on the sender's page → its finding (data/tamper-rules.js ownWarning) is recorded at
//                                     TAMPER_OWN_WARNING_POINTS; it counts in the rating but never opens a window itself
//   onCommitted(tabId, url)         — a new top-level page in a tab that is already tracked
//   releaseTab(tabId)               — the tab closed (also closes its warning window and stops its collect timer)
//   setMarkSink(fn)                 — 5.1.3: fn(tabId, rating) puts the page's rating on the toolbar badge (background.js:
//                                     core/badge.js setTamperRating): the full rating on a closely watched page outside
//                                     "Tamper: site", else Low (owner 2026-11-24: the highest problem wins)
//   showDetails(tabId)              — 5.1.3: the popup's "Details": open (or update) the page's window with every finding,
//                                     whatever its rating; false when nothing was found on the page
//   tamperView(state)               — the Protections page's Tamper Protection signal list (points on hover)
//   ratingOf(score)                 — 5.1.3: score → TAMPER_RATING (exported for tests)
//   pageFindings(tabId) / pageRisk(tabId) — what was found on the tab's current page and what came of it (tests, never
//                                     shown — only what the user can act on is shown, i.e. the warning itself)
//   setCollectMsForTests(ms)        — tests only: shorten TAMPER_COLLECT_MS
//   TAMPER_PHASE                    — the per-tab phases (exported for tests)
//
// 5.1.3 — the RISK RATING (user decision 2026-11-24): every finding adds its points (data/tamper-rules.js); the page's
// score is the sum of its different findings, × TAMPER_SENSITIVE_FACTOR on a banking/payment page; the score gives
// the rating (data/constants.js TAMPER_RATING_MIN_POINTS). On a closely watched page: CRITICAL and HIGH warn;
// SUSPICIOUS warns from TAMPER_SUSPICIOUS_WARN.ALWAYS_FROM, from OUTSIDE_SAFER_FROM only outside the safer regions,
// and otherwise only shows "?" on the toolbar badge; LOW never warns. ONE window per page lists every finding with the
// rating: findings within TAMPER_COLLECT_MS are collected before it opens (CRITICAL opens at once), later findings
// update the open window, and a window the user closed opens again only for a HIGHER rating. "Tamper: site" on the
// allow list: recorded, never warns (EXCEPTION).
//
// One switch, "Enable tamper detection" (watchTamperSensitive, level 2+), and four trigger ticks under it (5.1.3).
// Owner decision 2026-11-24 ("need to protect", least overhead): ONLY the four ticks start the close watching
// (banking/payment page, hidden password/card field, checkout words, locked page) — plus the same-site COOLDOWN that
// continues one of them. No level, no sign and no report arms a page. Pages that are not watched closely send NOTHING
// (the page scripts hold what they noticed and send it only once armed), so every report here comes from an armed
// page; one from an unarmed page is ignored. A site locked at level 1 ("Trust this site") gets nothing: the scripts
// are not even registered there (core/script-builder.js).
//
// Per tab — a state machine (B3a, C14), one phase at a time, transitions only through transition():
//   STANDBY  — not watched closely: nothing is reported, recorded or shown
//   ENHANCED — watched closely: the page's dynamic layer is on, the rating may warn
//   COOLDOWN — the tab left a closely watched page for another page of the SAME site: the next page is armed at its
//              hello while TAMPER_COOLDOWN_MS has not passed (bank and checkout flows hop between pages)
//   STANDBY → ENHANCED (arm) · ENHANCED → COOLDOWN (same-site navigation) · ENHANCED/COOLDOWN → STANDBY (other site,
//   or cooldown over) · COOLDOWN → ENHANCED (armed again at hello)
// Findings recorded before the page was armed count when it is armed (arming evaluates the page again).
//
// State owned: _tabs (tabId → watch record) — in memory only, never stored: the threat model keeps no browsing
// history (README C49). Lost with the service worker (B7): a page open across a restart is treated as new at its
// next message. Guards (B6): at most TAMPER_TABS_CAP tabs (oldest dropped); a page holds at most one finding per rule;
// released on navigation (freshPage) and tab close (releaseTab); the per-page collect timer (B10) is cleared on both.
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX, TAMPER_RATING, TAMPER_RATING_MIN_POINTS, TAMPER_SENSITIVE_FACTOR, TAMPER_SUSPICIOUS_WARN,
         TAMPER_COLLECT_MS, TAMPER_SIGN_POINTS_MIN, TAMPER_SENSITIVE_POINTS, LEVEL,
         TAMPER_SENSITIVE_THRESHOLD, TAMPER_ADDRESS_WORDS, TAMPER_ADDRESS_ENDINGS, TAMPER_ADDRESS_TOKENS_MAX,
         TAMPER_CRYPTO_WORDS, TAMPER_CRYPTO_ENDINGS,
         TAMPER_ADDRESS_LETTER_FOLD, TAMPER_COOLDOWN_MS, TAMPER_TABS_CAP, TAMPER_SCRIPT_VERDICTS_CAP, SEVERITY,
         TAMPER_SCRIPT_PROVIDERS, TAMPER_SCRIPT_TYPO,
         TAMPER_DETAIL_ITEMS_MAX, TAMPER_DETAIL_TEXT_MAX, TAMPER_FRAME_HOSTS_MAX, TAMPER_DEBUG_LOG } from "../data/constants.js";
import { MSG_TAMPER_ARM } from "../data/message-types.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { TAMPER_RULE, TAMPER_RULES, TAMPER_RULE_BY_ID, TAMPER_PAGE_RULES, TAMPER_RULE_OF_TARGET, TAMPER_ADDED_PROPS,
         TAMPER_DETAIL, TAMPER_LAYER, TAMPER_MANY_HOOKS_MIN, TAMPER_RULE_OF_OWN_WARNING } from "../data/tamper-rules.js";
import { BUILTIN_PAYMENT, BUILTIN_SIGN_IN, BUILTIN_ALL } from "../data/builtin-domains.js";
import { isValidHost } from "../data/state-storage.js";
import { effectiveLevel, lockedLevelOf, isProtectionActive, isProtectionActiveOrHighRisk, isAllowedFor,
         isInSaferRegions } from "./policy.js";
import { ALLOW_CATEGORY } from "../data/allow-categories.js";
import * as Warnings from "./tamper-warnings.js";
import { parseHttpUrl, registeredDomain, isInDomainList } from "../util/domain.js";
import { scoreLocal } from "./site-scorer.js";

export const TAMPER_PHASE = Object.freeze({ STANDBY: "standby", ENHANCED: "enhanced", COOLDOWN: "cooldown" });
const TRANSITIONS = Object.freeze({
  [TAMPER_PHASE.STANDBY]:  Object.freeze([TAMPER_PHASE.ENHANCED]),
  [TAMPER_PHASE.ENHANCED]: Object.freeze([TAMPER_PHASE.COOLDOWN, TAMPER_PHASE.STANDBY]),
  [TAMPER_PHASE.COOLDOWN]: Object.freeze([TAMPER_PHASE.ENHANCED, TAMPER_PHASE.STANDBY])
});
// What came of a finding (pageFindings; the page's record only — never shown, never stored).
// 5.1.3: one outcome per PAGE (its rating decides), not per finding. MARKED = Suspicious without a window (only the badge "?").
export const TAMPER_OUTCOME = Object.freeze({
  WARNED: "warned", RECORDED: "recorded", EXCEPTION: "exception", MARKED: "marked", COLLECTING: "collecting"
});
// Why a page counts as a banking/payment page (keys of TAMPER_SENSITIVE_POINTS).
const REASON = Object.freeze({
  KNOWN_PAYMENT_SITE: "KNOWN_PAYMENT_SITE", PAYMENT_FRAME: "PAYMENT_FRAME", CARD_FIELD: "CARD_FIELD", BANK_FIELD: "BANK_FIELD"
});
// Why a page was armed (one per page; shown nowhere, kept for the log and tests).
// ADDRESS (5.1.1): a checkout/cart/payment word in the address — armed at hello, the page is NOT made sensitive by it.
// HIDDEN_FIELD / LOCKED (5.1.3): a hidden password/card field on the page; a site locked at level 2 or more.
// (Owner 2026-11-24: ALWAYS, SIGN and ADDRESS_SCRIPT are gone — only the four ticks and their cooldown arm a page.)
export const ARMED_BY = Object.freeze({ SENSITIVE: "sensitive", COOLDOWN: "cooldown", ADDRESS: "address",
                                        HIDDEN_FIELD: "hiddenField", LOCKED: "locked" });
// Address matching (5.1.1): tokens are runs of letters/digits; accents (combining marks after NFD) are removed.
const TOKEN_SPLIT_RE = /[^\p{L}\p{N}]+/u;
const COMBINING_MARK_RE = /\p{M}+/gu;
const UNICODE_DECOMPOSED = "NFD";
const LETTER_FOLD_RE = new RegExp(`[${Object.keys(TAMPER_ADDRESS_LETTER_FOLD).join("")}]`, "gu");
function foldText(text) {
  return text.toLowerCase().normalize(UNICODE_DECOMPOSED).replace(COMBINING_MARK_RE, "")
    .replace(LETTER_FOLD_RE, (c) => TAMPER_ADDRESS_LETTER_FOLD[c]);
}
// Built once at load from the per-language table (data/constants.js) — the table is the single source.
const ADDRESS_WORDS = new Set(Object.values(TAMPER_ADDRESS_WORDS).flat().map(foldText));
const ADDRESS_ENDINGS = Object.freeze(TAMPER_ADDRESS_ENDINGS.map(foldText));
const CRYPTO_WORDS = new Set(TAMPER_CRYPTO_WORDS.map(foldText));      // 5.1.3: also matched in the site's own name
const CRYPTO_ENDINGS = Object.freeze(TAMPER_CRYPTO_ENDINGS.map(foldText));
// The trigger ticks (5.1.3, data/protections.js), each requiring the switch.
const TRIGGER = Object.freeze({ SENSITIVE: PROTECTION_KEY.TAMPER_ON_SENSITIVE, HIDDEN: PROTECTION_KEY.TAMPER_ON_HIDDEN_FIELD,
                                WORDS: PROTECTION_KEY.TAMPER_ON_CHECKOUT_WORDS, LOCKED: PROTECTION_KEY.TAMPER_ON_LOCKED_PAGES });

const _tabs = new Map();        // tabId → watch record (insertion order = age, for the cap)
const _scriptVerdicts = new Map();   // 5.1.2: script host → suspicious? (local site check; cap TAMPER_SCRIPT_VERDICTS_CAP)
function noMark() { /* no sink set (tests) */ }
let _markSink = noMark;               // 5.1.3: (tabId, rating) → the toolbar badge; set by background.js (setMarkSink)
let _collectMs = TAMPER_COLLECT_MS;  // tests may shorten it (setCollectMsForTests)
let _pageSeq = 0;                    // 5.1.3: page identity for a collect timer that fires after a navigation

function freshPage(rec, site) {
  stopCollect(rec);
  rec.page = ++_pageSeq;
  rec.site = site;
  rec.sensitive = false;
  rec.reasons = new Set();
  rec.staticTargets = new Set();
  rec.findings = new Map();      // rule → { points, items }, this page (one per rule)
  rec.score = 0;                 // 5.1.3: the page's risk score and rating (evaluate) — every finding
  rec.rating = TAMPER_RATING.LOW;
  rec.warnRating = TAMPER_RATING.LOW;   // issue 3: the rating WITHOUT own-warning findings — the one that opens a window
  rec.outcome = TAMPER_OUTCOME.RECORDED;
  rec.shownRating = 0;           // the highest rating a window was opened for on this page (a closed window reopens
                                 // only for a higher one)
  rec.collectTimer = null;       // the collect delay before the window opens (TAMPER_COLLECT_MS)
  rec.armedBy = null;
  rec.paymentHosts = new Set();  // 5.1.2: payment providers' frame hosts on the page (Payment list; ≤ TAMPER_FRAME_HOSTS_MAX)
  rec.ownCardNumber = false;     // 5.1.2: a card-number field in the shop's own page (top page or a same-site frame)
}

function watchOf(tabId, site) {
  let rec = _tabs.get(tabId);
  if (!rec) {
    rec = { phase: TAMPER_PHASE.STANDBY, cooldownUntil: 0 };
    freshPage(rec, site);
    _tabs.set(tabId, rec);
    while (_tabs.size > TAMPER_TABS_CAP) _tabs.delete(_tabs.keys().next().value);   // guard: oldest tab first
  } else if (rec.site !== site) {
    newPage(rec, site, Date.now());   // a navigation we did not see (service-worker restart, prerender swap)
  }
  return rec;
}

function transition(rec, to) {
  if (rec.phase === to) return true;
  if (!TRANSITIONS[rec.phase].includes(to)) { console.warn(LOG_PREFIX, "Tamper Guard: refused phase", rec.phase, "→", to); return false; }
  rec.phase = to;
  return true;
}

function newPage(rec, site, now) {
  const sameSite = rec.site === site;
  if (rec.phase === TAMPER_PHASE.ENHANCED && sameSite) {
    transition(rec, TAMPER_PHASE.COOLDOWN);
    rec.cooldownUntil = now + TAMPER_COOLDOWN_MS;
  } else if (rec.phase !== TAMPER_PHASE.STANDBY && !(rec.phase === TAMPER_PHASE.COOLDOWN && sameSite && now < rec.cooldownUntil)) {
    transition(rec, TAMPER_PHASE.STANDBY);
    rec.cooldownUntil = 0;
  }
  freshPage(rec, site);
}

// The page the user sees (the tab's top page) and the frame that sent the message — both from the SENDER (C28).
function pagesOf(sender) {
  const tab = sender && sender.tab;
  if (!tab || !Number.isInteger(tab.id)) return null;
  const top = parseHttpUrl(tab.url || "");
  if (!top) return null;
  const frame = parseHttpUrl(sender.url || "") || top;
  return { tabId: tab.id, url: top.url, host: top.host, site: registeredDomain(top.host), frameHost: frame.host,
           frameSite: registeredDomain(frame.host) };
}

function modeFor(state, host) {
  const level = effectiveLevel(state, host);
  const on = isProtectionActive(state, PROTECTION_KEY.WATCH_TAMPER_SENSITIVE, level);
  function tick(key) { return on && isProtectionActive(state, key, level); }
  const locked = lockedLevelOf(state, host);
  return { on, level,
           onSensitive: tick(TRIGGER.SENSITIVE), onHidden: tick(TRIGGER.HIDDEN), onWords: tick(TRIGGER.WORDS),
           onLocked: tick(TRIGGER.LOCKED) && locked !== null && locked > LEVEL.ALLOW_ALL };
}

// ── Sensitive pages (banking / payment) ──
function addReason(rec, reason) { rec.reasons.add(reason); }
// 5.1.7 TEMPORARY (TAMPER_DEBUG_LOG): why a page counts as a payment page / what armed it — service-worker console only.
function debugLog(what, info) { if (TAMPER_DEBUG_LOG) console.info(LOG_PREFIX, "Tamper debug:", what, JSON.stringify(info)); }
function sensitivePoints(rec) {
  let points = 0;
  for (const r of rec.reasons) points += TAMPER_SENSITIVE_POINTS[r] || 0;
  return points;
}
// The address's words: the decoded path and the subdomain labels (never the site's own name — "kassa.nl" is a brand).
function addressTokens(url, host) {
  let path;
  try { path = new URL(url).pathname; } catch { return []; }
  try { path = decodeURIComponent(path); } catch { /* malformed %-escape: match the raw path */ }
  const site = registeredDomain(host);
  const sub = host.length > site.length ? host.slice(0, host.length - site.length) : "";
  return foldText(`${sub} ${path}`).split(TOKEN_SPLIT_RE).filter(Boolean).slice(0, TAMPER_ADDRESS_TOKENS_MAX);
}
// The site's own name without its public suffix ("www-featherwallet" for www-featherwallet.com), as tokens.
function siteNameTokens(host) {
  const site = registeredDomain(host);
  const dot = site.indexOf(".");
  return foldText(dot > 0 ? site.slice(0, dot) : site).split(TOKEN_SPLIT_RE).filter(Boolean);
}
function isCryptoToken(t) { return CRYPTO_WORDS.has(t) || CRYPTO_ENDINGS.some((e) => t.endsWith(e)); }
export function hasAddressWord(url, host) {
  const tokens = addressTokens(url, host);
  return tokens.some((t) => ADDRESS_WORDS.has(t) || ADDRESS_ENDINGS.some((e) => t.endsWith(e)) || isCryptoToken(t)) ||
         siteNameTokens(host).some(isCryptoToken);                    // 5.1.3: crypto words in the site name too
}
// A real signal made the page sensitive: its score now counts × TAMPER_SENSITIVE_FACTOR (evaluated again).
function updateSensitive(state, tabId, rec, pages) {
  if (rec.sensitive || sensitivePoints(rec) < TAMPER_SENSITIVE_THRESHOLD) return rec.sensitive;
  rec.sensitive = true;
  evaluate(state, tabId, rec, pages);
  return true;
}

// ── Arming ──
function arm(state, tabId, rec, armedBy, pages) {
  if (rec.phase === TAMPER_PHASE.ENHANCED) return;
  if (!transition(rec, TAMPER_PHASE.ENHANCED)) return;
  rec.armedBy = armedBy;
  debugLog("close watching started", { page: pages.host, armedBy, reasons: [...rec.reasons] });
  chrome.tabs.sendMessage(tabId, { type: MSG_TAMPER_ARM }).catch(() => { /* no listening frame (yet) */ });
  evaluate(state, tabId, rec, pages);                // findings recorded before arming count now
}

function isArmed(rec) { return rec.phase === TAMPER_PHASE.ENHANCED; }

// ── Hello / signals ──
export function onHello(state, sender) {
  const pages = pagesOf(sender);
  if (!pages) return { arm: false };
  const mode = modeFor(state, pages.host);
  if (!mode.on) return { arm: false };
  const rec = watchOf(pages.tabId, pages.site);
  if (isInDomainList(pages.host, BUILTIN_PAYMENT)) { addReason(rec, REASON.KNOWN_PAYMENT_SITE); debugLog("known payment site", { page: pages.host }); }
  const sensitive = updateSensitive(state, pages.tabId, rec, pages);
  if (sensitive && mode.onSensitive) arm(state, pages.tabId, rec, ARMED_BY.SENSITIVE, pages);
  else if (rec.phase === TAMPER_PHASE.COOLDOWN && Date.now() < rec.cooldownUntil) arm(state, pages.tabId, rec, ARMED_BY.COOLDOWN, pages);
  else if (mode.onLocked) arm(state, pages.tabId, rec, ARMED_BY.LOCKED, pages);
  else if (mode.onWords && hasAddressWord(pages.url, pages.host)) arm(state, pages.tabId, rec, ARMED_BY.ADDRESS, pages);
  return { arm: isArmed(rec) };
}

export function onSignals(state, msg, sender) {
  const pages = pagesOf(sender);
  if (!pages || !msg || typeof msg !== "object") return { arm: false };
  const mode = modeFor(state, pages.host);
  if (!mode.on) return { arm: false };
  const rec = watchOf(pages.tabId, pages.site);
  const frames = Array.isArray(msg.frames) ? msg.frames.slice(0, TAMPER_FRAME_HOSTS_MAX)
    .map((h) => String(h).toLowerCase()).filter(isValidHost) : [];
  const payFrames = frames.filter((h) => isInDomainList(h, BUILTIN_PAYMENT));
  // 5.1.6: the reporting frame's own host counts only when that frame can be seen (msg.frameSeen from the bridge).
  if (pages.frameHost !== pages.host && msg.frameSeen === true && isInDomainList(pages.frameHost, BUILTIN_PAYMENT)) payFrames.push(pages.frameHost);
  if (payFrames.length || msg.card === true || msg.bank === true) {
    debugLog("payment signal", { page: pages.host, fromFrame: pages.frameHost, frameSeen: msg.frameSeen, frames,
      payFrames, card: msg.card === true, bank: msg.bank === true });
  }
  if (payFrames.length) {
    addReason(rec, REASON.PAYMENT_FRAME);
    for (const h of payFrames) if (rec.paymentHosts.size < TAMPER_FRAME_HOSTS_MAX) rec.paymentHosts.add(h);
  }
  if (msg.card === true) addReason(rec, REASON.CARD_FIELD);
  if (msg.bank === true) addReason(rec, REASON.BANK_FIELD);
  if (msg.cardNumber === true && pages.frameSite === pages.site && !isInDomainList(pages.host, BUILTIN_PAYMENT)) rec.ownCardNumber = true;
  if (updateSensitive(state, pages.tabId, rec, pages) && mode.onSensitive) arm(state, pages.tabId, rec, ARMED_BY.SENSITIVE, pages);
  if (msg.hidden === true) {                         // 5.1.3: a hidden password/card field — a finding and a trigger
    record(rec, TAMPER_RULE.HIDDEN_CREDENTIAL, { kind: TAMPER_DETAIL.DEST, items: [pages.frameHost] });
    if (mode.onHidden) arm(state, pages.tabId, rec, ARMED_BY.HIDDEN_FIELD, pages);
    evaluate(state, pages.tabId, rec, pages);
  }
  const second = secondCardFormFinding(rec, pages);
  if (second) decide(state, pages.tabId, rec, TAMPER_RULE.SECOND_CARD_FORM, second, pages);
  return { arm: isArmed(rec) };
}

// 5.1.2 — a card-number field of the shop's own next to a payment provider's frame (data/tamper-rules.js
// SECOND_CARD_FORM). Derived here from two signals, once per page; a page that IS a known payment site is never one.
function secondCardFormFinding(rec, pages) {
  if (!rec.paymentHosts.size || !rec.ownCardNumber || rec.findings.has(TAMPER_RULE.SECOND_CARD_FORM)) return null;
  return { kind: TAMPER_DETAIL.DEST, items: [...rec.paymentHosts].slice(0, TAMPER_DETAIL_ITEMS_MAX) };
}

// ── Reports ──
function cleanDetail(detail) {
  if (!detail || typeof detail !== "object" || !Object.values(TAMPER_DETAIL).includes(detail.kind) || !Array.isArray(detail.items)) return null;
  const items = [];
  for (const it of detail.items) {
    if (typeof it === "string" && it) items.push(it.slice(0, TAMPER_DETAIL_TEXT_MAX));
    if (items.length >= TAMPER_DETAIL_ITEMS_MAX) break;
  }
  return items.length ? { kind: detail.kind, items } : null;
}

function isTargetOf(rule, name) {
  if (TAMPER_RULE_OF_TARGET[name] === rule) return true;
  const base = TAMPER_ADDED_PROPS[rule];
  return !!base && name.startsWith(`${base}.`) && name.length > base.length + 1;
}

// A target that 3P Matrix itself replaces on this site (data/tamper-rules.js wrappedBy) is not a finding.
function wrappedByUs(state, def, name, pages, level) {
  const keys = def.wrappedBy && def.wrappedBy[name];
  return !!keys && keys.some((k) => isProtectionActiveOrHighRisk(state, k, level, pages.host));
}

function staticFinding(state, def, detail, pages, rec, mode) {
  if (detail.kind !== TAMPER_DETAIL.TARGETS) return null;
  const fresh = detail.items.filter((n) => isTargetOf(def.id, n) && !wrappedByUs(state, def, n, pages, mode.level) && !rec.staticTargets.has(n));
  if (!fresh.length) return null;
  fresh.forEach((n) => rec.staticTargets.add(n));
  return { kind: TAMPER_DETAIL.TARGETS, items: fresh };
}

// Many important built-ins replaced on one page (low-point rules not counted) — derived here, never reported by a page.
function manyHooksFinding(rec) {
  if (rec.findings.has(TAMPER_RULE.MANY_HOOKS)) return null;
  const counted = [...rec.staticTargets].filter((n) => {
    const rule = TAMPER_RULE_OF_TARGET[n] || Object.keys(TAMPER_ADDED_PROPS).find((r) => n.startsWith(`${TAMPER_ADDED_PROPS[r]}.`));
    return rule && TAMPER_RULE_BY_ID[rule].points >= TAMPER_SIGN_POINTS_MIN;
  });
  return counted.length >= TAMPER_MANY_HOOKS_MIN ? { kind: TAMPER_DETAIL.TARGETS, items: counted.slice(0, TAMPER_DETAIL_ITEMS_MAX) } : null;
}

// 5.1.2 — tgAddressScript, 5.1.3 tgObfuscatedCode: the sink names must be the rule's own (data/tamper-rules.js `sinks`).
function sinkFinding(def, detail) {
  if (detail.kind !== TAMPER_DETAIL.TARGETS) return null;
  const items = detail.items.filter((n) => def.sinks.includes(n));
  return items.length ? { kind: TAMPER_DETAIL.TARGETS, items } : null;
}

// 5.1.2 — tgSuspiciousScript: of the reported script hosts, those that 3P Matrix's own local site check rates suspect
// or worse (core/site-scorer.js), or that imitate a script provider (imitatesProvider). Never the page's own site or a
// host on the built-in whitelist. Verdicts are kept (cap TAMPER_SCRIPT_VERDICTS_CAP).
// Edit distance, stopped early once it exceeds `max` (only "within max?" is asked).
function withinEdits(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return false;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const row = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, row[j]);
    }
    if (best > max) return false;
    prev = row;
  }
  return prev[b.length] <= max;
}
const DASH_RE = /-/g;
const LABEL_SEPARATOR = ".";
const DASH_SEPARATOR = "-";
// A script host whose registered-domain name, or one of its dash-separated parts, STARTS with a script provider's name
// ("jquerycdn", "cdn-stripe"; not "pinstripe"), or is a near-typo of it ("googletagmanagr"), without being
// one of that provider's real domains (data/constants.js TAMPER_SCRIPT_PROVIDERS).
const PROVIDER_REAL_SITES = new Set(Object.values(TAMPER_SCRIPT_PROVIDERS).flat());
export function imitatesProvider(host) {
  const site = registeredDomain(host);
  if (PROVIDER_REAL_SITES.has(site)) return false;
  const label = site.split(LABEL_SEPARATOR)[0];
  const name = label.replace(DASH_RE, "");
  const parts = label.split(DASH_SEPARATOR);
  for (const provider of Object.keys(TAMPER_SCRIPT_PROVIDERS)) {
    if (parts.some((p) => p.startsWith(provider)) ||
        (provider.length >= TAMPER_SCRIPT_TYPO.MIN_CHARS && withinEdits(name, provider, TAMPER_SCRIPT_TYPO.MAX_EDITS))) return true;
  }
  return false;
}
function isSuspiciousHost(host) {
  if (_scriptVerdicts.has(host)) return _scriptVerdicts.get(host);
  const local = scoreLocal(`https://${host}/`);
  const verdict = (!!local && local.severity !== SEVERITY.NONE) || imitatesProvider(host);
  _scriptVerdicts.set(host, verdict);
  while (_scriptVerdicts.size > TAMPER_SCRIPT_VERDICTS_CAP) _scriptVerdicts.delete(_scriptVerdicts.keys().next().value);   // guard
  return verdict;
}
function suspiciousScriptFinding(detail, pages) {
  const hosts = detail.items.map((h) => h.toLowerCase()).filter((h) => isValidHost(h) &&
    registeredDomain(h) !== pages.site && registeredDomain(h) !== pages.frameSite && !isInDomainList(h, BUILTIN_ALL) && isSuspiciousHost(h));
  return hosts.length ? { kind: TAMPER_DETAIL.DEST, items: hosts } : null;
}

// Destination checks: same site as the frame or the page, or a known sign-in / payment / embed host, is no finding.
function dynamicFinding(def, detail, pages) {
  if (def.id === TAMPER_RULE.DATA_EDITED) return detail.kind === TAMPER_DETAIL.KEYS ? detail : null;
  if (detail.kind !== TAMPER_DETAIL.DEST) return null;
  if (def.id === TAMPER_RULE.SUSPICIOUS_SCRIPT) return suspiciousScriptFinding(detail, pages);   // a list of hosts
  const dest = detail.items[0].toLowerCase();
  if (!isValidHost(dest)) return null;
  const destSite = registeredDomain(dest);
  const ownSite = destSite === pages.frameSite || destSite === pages.site;
  switch (def.id) {
    case TAMPER_RULE.PASSWORD_SENT:
    case TAMPER_RULE.FORM_CHANGED:
      if (ownSite || isInDomainList(dest, BUILTIN_SIGN_IN)) return null; break;
    case TAMPER_RULE.SEED_SENT:                       // 5.1.4: only the page's own site (no provider ever needs it)
      if (ownSite) return null; break;
    case TAMPER_RULE.CARD_SENT:
    case TAMPER_RULE.IBAN_SENT:                       // 5.1.3: as for card numbers
      if (ownSite || isInDomainList(dest, BUILTIN_PAYMENT)) return null; break;
    case TAMPER_RULE.INVISIBLE_FRAME:
      if (ownSite || isInDomainList(dest, BUILTIN_ALL)) return null; break;
    default: break;                                   // HIDDEN_CREDENTIAL, INTEGRITY_REMOVED: the host is information only
  }
  return { kind: TAMPER_DETAIL.DEST, items: [dest] };
}

export function onReport(state, msg, sender) {
  const pages = pagesOf(sender);
  if (!pages || !msg || !TAMPER_PAGE_RULES.includes(msg.rule)) return { arm: false };
  const detail = cleanDetail(msg.detail);
  if (!detail) return { arm: false };
  const mode = modeFor(state, pages.host);
  if (!mode.on) return { arm: false };
  const rec = watchOf(pages.tabId, pages.site);
  if (!isArmed(rec)) return { arm: false };            // only closely watched pages report (owner 2026-11-24)
  const def = TAMPER_RULE_BY_ID[msg.rule];
  if (def.layer === TAMPER_LAYER.STATIC) {
    const finding = staticFinding(state, def, detail, pages, rec, mode);
    if (!finding) return { arm: true };
    record(rec, def.id, finding);
    const many = manyHooksFinding(rec);
    if (many) record(rec, TAMPER_RULE.MANY_HOOKS, many);
    evaluate(state, pages.tabId, rec, pages);
  } else if (def.sinks) {                              // tgAddressScript, tgObfuscatedCode: the rule's own sink names
    const finding = sinkFinding(def, detail);
    if (finding) decide(state, pages.tabId, rec, def.id, finding, pages);
  } else {
    const finding = dynamicFinding(def, detail, pages);
    if (finding) decide(state, pages.tabId, rec, def.id, finding, pages);
  }
  return { arm: true };
}

// 5.1.3 (issue 3) — a protection with its own warning just decided to warn on the sender's page: record its finding,
// on a closely watched page only (owner 2026-11-24: nothing is kept for other pages — the own warning itself still
// warns everywhere); never when the switch or that protection is off at the top page's level. `items`: the detail (destination / imitated host); default the frame's host.
export function recordOwnWarning(state, key, sender, items) {
  const rule = Object.prototype.hasOwnProperty.call(TAMPER_RULE_OF_OWN_WARNING, key) ? TAMPER_RULE_OF_OWN_WARNING[key] : null;
  const pages = rule ? pagesOf(sender) : null;
  if (!pages) return false;
  const mode = modeFor(state, pages.host);
  if (!mode.on || !isProtectionActive(state, key, mode.level)) return false;
  const hosts = (Array.isArray(items) ? items : []).map((h) => String(h).toLowerCase()).filter(isValidHost);
  const detail = cleanDetail({ kind: TAMPER_DETAIL.DEST, items: hosts.length ? hosts : [pages.frameHost] });
  if (!detail) return false;
  const rec = watchOf(pages.tabId, pages.site);
  if (!isArmed(rec)) return false;
  decide(state, pages.tabId, rec, rule, detail, pages);
  return true;
}

// ── Deciding: record, score, rate, warn (5.1.3) ──
// One finding per rule per page; a later report of the same rule adds its new items (capped).
function record(rec, rule, detail) {
  const before = rec.findings.get(rule);
  const items = before ? [...new Set([...before.items, ...detail.items])].slice(0, TAMPER_DETAIL_ITEMS_MAX) : detail.items.slice();
  rec.findings.set(rule, { points: TAMPER_RULE_BY_ID[rule].points, items, kind: detail.kind });
}
function decide(state, tabId, rec, rule, detail, pages) {
  record(rec, rule, detail);
  evaluate(state, tabId, rec, pages);
}

// `withOwn` false (issue 3): leave out the findings whose protection gave its own warning — they never open a window.
function scoreOf(rec, withOwn) {
  let points = 0;
  for (const [rule, f] of rec.findings) if (withOwn || !TAMPER_RULE_BY_ID[rule].ownWarning) points += f.points;
  return rec.sensitive ? Math.round(points * TAMPER_SENSITIVE_FACTOR) : points;
}
export function ratingOf(score) {
  for (const rating of [TAMPER_RATING.CRITICAL, TAMPER_RATING.HIGH, TAMPER_RATING.SUSPICIOUS]) {
    if (score >= TAMPER_RATING_MIN_POINTS[rating]) return rating;
  }
  return TAMPER_RATING.LOW;
}
// Does this rating open a window on this closely watched page? (TAMPER_SUSPICIOUS_WARN)
function warns(state, rating, pages, level) {
  if (rating >= TAMPER_RATING.HIGH) return true;
  if (rating !== TAMPER_RATING.SUSPICIOUS) return false;
  if (level >= TAMPER_SUSPICIOUS_WARN.ALWAYS_FROM) return true;
  return level >= TAMPER_SUSPICIOUS_WARN.OUTSIDE_SAFER_FROM && !isInSaferRegions(state, pages.host);
}

// The window's content: every finding, most points first.
function warningOf(rec, pages) {
  const signals = [...rec.findings].sort((a, b) => b[1].points - a[1].points)
    .map(([rule, f]) => ({ rule, items: f.items.slice(), kind: f.kind }));
  return { tabId: pages.tabId, site: pages.site, rating: rec.rating, score: rec.score, sensitive: rec.sensitive, signals };
}

function stopCollect(rec) {
  if (rec.collectTimer !== null && rec.collectTimer !== undefined) clearTimeout(rec.collectTimer);
  rec.collectTimer = null;
}
function openOrUpdate(rec, pages) {
  rec.shownRating = Math.max(rec.shownRating, rec.warnRating);
  rec.outcome = TAMPER_OUTCOME.WARNED;
  Warnings.showWarning(warningOf(rec, pages)).catch((e) => console.error(LOG_PREFIX, "Tamper Guard warning:", e));
}

// The shown score and rating count every finding; whether a window opens (or reopens) is decided on warnRating,
// which leaves out the own-warning findings (issue 3) — an open window is still updated with them.
function evaluate(state, tabId, rec, pages) {
  rec.score = scoreOf(rec, true);
  rec.rating = ratingOf(rec.score);
  rec.warnRating = ratingOf(scoreOf(rec, false));
  const exception = isAllowedFor(state, ALLOW_CATEGORY.TAMPER, pages.site);
  _markSink(tabId, isArmed(rec) && !exception ? rec.rating : TAMPER_RATING.LOW);   // the badge: full rating
  if (!isArmed(rec) || rec.warnRating === TAMPER_RATING.LOW) {                // recorded only (counts once armed)
    if (isArmed(rec) && Warnings.hasOpenWarning(tabId)) openOrUpdate(rec, pages);   // an own-warning finding joins it
    return;
  }
  if (exception) { rec.outcome = TAMPER_OUTCOME.EXCEPTION; return; }
  if (!warns(state, rec.warnRating, pages, modeFor(state, pages.host).level)) {
    rec.outcome = TAMPER_OUTCOME.MARKED;                                     // only the badge says it
    return;
  }
  if (Warnings.hasOpenWarning(tabId)) { openOrUpdate(rec, pages); return; }   // later findings update the window
  if (rec.warnRating <= rec.shownRating) return;                             // closed by the user at this rating
  if (rec.warnRating >= TAMPER_RATING.CRITICAL) { stopCollect(rec); openOrUpdate(rec, pages); return; }
  if (rec.collectTimer !== null) return;                                     // already collecting
  rec.outcome = TAMPER_OUTCOME.COLLECTING;
  const page = rec.page;
  rec.collectTimer = setTimeout(() => {
    rec.collectTimer = null;
    if (rec.page !== page || _tabs.get(tabId) !== rec) return;               // navigated or released meanwhile
    if (rec.warnRating > rec.shownRating || Warnings.hasOpenWarning(tabId)) openOrUpdate(rec, pages);
  }, _collectMs);
}

// ── Lifecycle ──
export function onCommitted(tabId, url) {
  const rec = _tabs.get(tabId);
  if (!rec) return;                                    // only tabs Tamper Guard already talks to
  const p = parseHttpUrl(url || "");
  newPage(rec, p ? registeredDomain(p.host) : "", Date.now());
}

export function releaseTab(tabId) {
  const rec = _tabs.get(tabId);
  if (rec) stopCollect(rec);
  _tabs.delete(tabId);
  Warnings.releaseTab(tabId);
}
export function showDetails(tabId) {
  const rec = _tabs.get(tabId);
  if (!rec || !rec.findings.size) return false;
  Warnings.showWarning(warningOf(rec, { tabId, site: rec.site })).catch((e) => console.error(LOG_PREFIX, "Tamper Guard details:", e));
  return true;
}
export function setMarkSink(fn) { _markSink = typeof fn === "function" ? fn : noMark; }
export function setCollectMsForTests(ms) { _collectMs = Number.isFinite(ms) && ms >= 0 ? ms : TAMPER_COLLECT_MS; }
// Tests only: forget the script-host verdicts (memory is otherwise released by the cap).
export function clearScriptVerdicts() { _scriptVerdicts.clear(); }

// ── Protections page (Tamper Protection tab, 5.1.3): a plain signal list, most points first; the explanation and the
// points are the row's hover/focus tooltip. Issue 3: the own-warning protections are rules of the table now (one
// source); their rows carry `warnsAtOnce` (the list says so). blockObfuscatedEval is a block (its finding is listed).
export function tamperView() {
  const rows = TAMPER_RULES.map((r) => ({ id: r.id, label: r.label, description: r.description, points: r.points,
                                          warnsAtOnce: !!r.ownWarning }));
  // most points first; within equal points the own-warning rows first, then the table's order (stable sort)
  return { rules: rows.sort((a, b) => (b.points - a.points) || (Number(b.warnsAtOnce) - Number(a.warnsAtOnce))) };
}

export function pageFindings(tabId) {
  const rec = _tabs.get(tabId);
  return rec ? [...rec.findings].map(([rule, f]) => ({ rule, points: f.points, items: f.items.slice() })) : [];
}
export function pageRisk(tabId) {
  const rec = _tabs.get(tabId);
  return rec ? { score: rec.score, rating: rec.rating, outcome: rec.outcome, armed: isArmed(rec), armedBy: rec.armedBy,
                 findings: rec.findings.size } : null;
}
