#!/usr/bin/env node
// ── tools/e2e-embedded-frames.mjs ────────────────────────────────────────────────
// End-to-end test (4.4.5) in a real Chromium with the unpacked extension: a site lock must hold for
// EVERYTHING the locked page loads, nested frames included. Real network requests against a local
// server (every *.test host resolves to it), so Chrome itself — not our replay — decides what loads:
//   top.test  ──iframe──►  cdn-frame.test  ──script──►  third.test
// The frame's script request has cdn-frame.test as initiator — the case a plain initiator-scoped lock
// never covered (Word Online inside SharePoint). Checks the three mechanisms in the real browser:
//   level 1 lock  → allowAllRequests lets the whole frame tree through, whatever the session level
//   level 2 lock  → tab band cancels the session level's blocks inside the tab
//   level 4 lock  → tab band blocks the nested script even when the session level is 1
// plus: the badge/popup count follows (our replay agrees with Chrome), the band is released when the
// tab navigates away, when the site is unlocked and when the tab closes.
// Every level, message and key comes from the extension's own modules — nothing typed but test hosts.
//
// Usage:  node e2e-embedded-frames.mjs --extension ../3P-Matrix [--chromium <path>]
// Needs:  the `playwright` package and a Chromium binary.
// Exit:   0 = all pass · 1 = a flow failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const LOCAL_ADDRESS = "127.0.0.1";
const TLD = "test";
const HOST = Object.freeze({ top: `top.${TLD}`, other: `other.${TLD}`, frame: `cdn-frame.${TLD}`, third: `third.${TLD}` });   // frame host contains "cdn": level 4 allows it
const PATH = Object.freeze({ page: "/", frame: "/frame.html", frameScript: "/third.js", pageScript: "/top.js" });
const SW_SETTLE_MS = 1500;           // let onInstalled apply the first rule set
const PAGE_SETTLE_MS = 2500;         // page + frame + scripts + blocked-request events
const SESSION_RULES_SETTLE_MS = 600; // session rules are applied right after the navigation event

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`e2e-embedded-frames: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const EXT = resolve(ext);
let chromium, C, M, P;
try { ({ chromium } = await import("playwright")); } catch { didNotRun("the playwright package is not installed (npm i playwright)"); }
try {
  C = await import(pathToFileURL(join(EXT, "data/constants.js")).href);
  M = await import(pathToFileURL(join(EXT, "data/message-types.js")).href);
  P = await import(pathToFileURL(join(EXT, "data/protections.js")).href);
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

// ── Local site (released in finally) ─────────────────────────────────────────
const hits = new Set();                                  // paths Chrome actually requested
let port = 0;
const url = (host, path) => `http://${host}:${port}${path}`;
const server = createServer((req, res) => {
  hits.add(req.url);
  if (req.url === PATH.page) {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!doctype html><title>top</title><iframe src="${url(HOST.frame, PATH.frame)}"></iframe><script src="${url(HOST.third, PATH.pageScript)}"></script>`);
  } else if (req.url === PATH.frame) {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!doctype html><title>frame</title><script src="${url(HOST.third, PATH.frameScript)}"></script>`);
  } else {
    res.writeHead(200, { "content-type": "text/javascript" }); res.end("");
  }
});
await new Promise((r) => server.listen(0, LOCAL_ADDRESS, r));
port = server.address().port;

let ctx = null, failed = 0;
function ok(name, cond, info) {
  if (!cond) failed++;
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : "  " + JSON.stringify(info)}`);
}

try {
  ctx = await chromium.launchPersistentContext("", {
    headless: false, executablePath: arg("chromium") || undefined,
    args: ["--headless=new", `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
           `--host-resolver-rules=MAP *.${TLD} ${LOCAL_ADDRESS}`, "--no-proxy-server"]
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const extId = new URL(sw.url()).host;
  await sleep(SW_SETTLE_MS);
  const ui = await ctx.newPage(); await ui.goto(`chrome-extension://${extId}/ui/protections.html`);
  const send = (msg) => ui.evaluate((m) => chrome.runtime.sendMessage(m), msg);
  const sessionRuleCount = () => sw.evaluate(async () => (await chrome.declarativeNetRequest.getSessionRules()).length);

  // Plain-HTTP and odd-port blocks (blockSuspicious3p, block3pHttp) would hit every request of this local http test
  // site, and the suspicious-site warning (11) would replace the test page: turn them off, they are not under test.
  async function freshSettings() {
    await send({ type: M.MSG_RESET_SETTINGS });
    for (const key of [P.PROTECTION_KEY.BLOCK_SUSPICIOUS_3P, P.PROTECTION_KEY.BLOCK_3P_HTTP, P.PROTECTION_KEY.WARN_SUSPICIOUS_SITES]) {
      await send({ type: M.MSG_SET_PROTECTION, key, enabled: false });
    }
  }
  // lock the top site at `lock` (null = no lock), then set the session level
  async function arrange({ lock, session }) {
    await freshSettings();
    const topUrl = url(HOST.top, PATH.page);
    if (lock !== null) {
      await send({ type: M.MSG_SET_LEVEL, level: lock, url: topUrl });
      await send({ type: M.MSG_TOGGLE_LOCK, url: topUrl });
    }
    await send({ type: M.MSG_SET_LEVEL, level: session, url: topUrl });
  }
  async function visit(page, host) {
    hits.clear();
    await page.goto(url(host, PATH.page));
    await sleep(PAGE_SETTLE_MS);
    if (process.env.E2E_DEBUG) console.log("tabs:", JSON.stringify(await ui.evaluate(async () => (await chrome.tabs.query({})).map((t) => t.url))));
    const tabId = await ui.evaluate(async (u) => (await chrome.tabs.query({ url: u + "*" }))[0].id, url(host, PATH.page));
    const model = await send({ type: M.MSG_GET_POPUP_STATE, tabId, url: url(host, PATH.page) });
    return { frameLoaded: hits.has(PATH.frame), frameScriptLoaded: hits.has(PATH.frameScript), pageScriptLoaded: hits.has(PATH.pageScript), blocked: model.data.blocked };
  }
  const tab = await ctx.newPage();
  const L = C.LEVEL;

  // Control: no lock, session level 5 — Chrome really blocks the 3P frame in this setup.
  await arrange({ lock: null, session: L.STRICT });
  let r = await visit(tab, HOST.top);
  ok("control: unlocked site at level 5 — the 3P frame and script are blocked", !r.frameLoaded && !r.frameScriptLoaded && !r.pageScriptLoaded && r.blocked > 0, r);

  // Level 1 lock: allowAllRequests
  for (const session of [L.HIGH, L.STRICT]) {
    await arrange({ lock: L.ALLOW_ALL, session });
    r = await visit(tab, HOST.top);
    ok(`level-1 lock, session ${session}: frame and its script load, nothing counted as blocked`, r.frameLoaded && r.frameScriptLoaded && r.pageScriptLoaded && r.blocked === 0, r);
  }

  // Level 2 lock inside a level-5 session: the band cancels the session level inside the tab
  await arrange({ lock: L.MILD, session: L.STRICT });
  r = await visit(tab, HOST.top);
  await sleep(SESSION_RULES_SETTLE_MS);
  ok("level-2 lock, session 5: frame and its script load (tab band)", r.frameLoaded && r.frameScriptLoaded && r.pageScriptLoaded && r.blocked === 0, r);
  ok("level-2 lock: Chrome holds the band's session rules", (await sessionRuleCount()) > 0, await sessionRuleCount());

  // Level 4 lock: the allowed CDN frame loads, its NESTED script does not — even in a level-1 session
  for (const session of [L.ALLOW_ALL, L.STRICT]) {
    await arrange({ lock: L.HIGH, session });
    r = await visit(tab, HOST.top);
    ok(`level-4 lock, session ${session}: cdn frame loads, its nested 3P script is blocked, the page's own 3P script too`,
       r.frameLoaded && !r.frameScriptLoaded && !r.pageScriptLoaded, r);
    ok(`level-4 lock, session ${session}: the popup count agrees with Chrome (blocked > 0)`, r.blocked > 0, r);
  }

  // Release: navigating the tab to an unlocked site (session level 1 → nothing blocks) leaves the band
  await arrange({ lock: L.HIGH, session: L.ALLOW_ALL });
  await visit(tab, HOST.top);
  r = await visit(tab, HOST.other);
  await sleep(SESSION_RULES_SETTLE_MS);
  ok("band released when the tab goes to an unlocked site", r.frameLoaded && r.frameScriptLoaded && (await sessionRuleCount()) === 0, { ...r, rules: await sessionRuleCount() });

  // Release: unlocking the site
  await visit(tab, HOST.top);
  ok("(setup) band active again on the locked site", (await sessionRuleCount()) > 0, await sessionRuleCount());
  await send({ type: M.MSG_TOGGLE_LOCK, url: url(HOST.top, PATH.page) });                 // unlock
  await sleep(SESSION_RULES_SETTLE_MS);
  ok("band released when the site is unlocked", (await sessionRuleCount()) === 0, await sessionRuleCount());

  // Release: closing the tab
  await arrange({ lock: L.HIGH, session: L.ALLOW_ALL });
  await visit(tab, HOST.top);
  await tab.close();
  await sleep(SESSION_RULES_SETTLE_MS);
  ok("band released when the tab is closed", (await sessionRuleCount()) === 0, await sessionRuleCount());
  await freshSettings();
} catch (e) {
  didNotRun(e && e.message || String(e));
} finally {
  if (ctx) await ctx.close().catch(() => {});
  server.close();
}

console.log(failed ? `e2e-embedded-frames: ${failed} FAILED` : "e2e-embedded-frames: ALL PASS");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
