#!/usr/bin/env node
// ── tools/e2e-worker-blocks.mjs ──────────────────────────────────────────────
// Real-Chromium test (5.0.5): the blocks hold inside WORKERS too, not only in the page. Chrome lets an extension
// inject scripts into pages but not into workers, so a page-level mechanism (a page script, or the page's CSP header)
// does not reach a worker loaded from its own URL or a shared worker — tested in 5.0.4: third-party WebSocket and
// WebAssembly got through from both. Covered (each probed from the page, a dedicated worker and a shared worker):
//   blockWebAssembly (levels 4–5) and blockWebsockets — their network half (and blockWebsockets' CSP on the
//     worker's own script, which is what reaches a shared worker);
//   blockWasmDubious (level 3) — 3P .wasm from outside the safer regions, not from an ordinary
//     safer-region host. (Owner decision 2026-11-26: the host-reputation-list half of this protection
//     — "dubious host" — was removed; a domain-list hit is a risk-score signal only now, never a
//     block. This test used to also cover that case with HOST.DUBIOUS; that case is gone with it.)
//   blockAbusedTlds (level 2) — WebSocket to an abused TLD, not to an ordinary host.
// KNOWN CHROME LIMITATION (reported as INFO, not pass/fail): Chrome does not show a shared worker's WebSocket to
// extensions at all (not even webRequest), and CSP cannot say "no WebSocket to *.top" — so blockAbusedTlds's
// WebSocket part cannot reach a shared worker. Probe outcome = did the request reach the local server.
// Test hosts are mapped to a local server (--host-resolver-rules); levels, messages and protection keys come from
// the extension's own modules.
//
// Usage:  node e2e-worker-blocks.mjs --extension ../3P-Matrix [--chromium <path>]
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const HOST = Object.freeze({
  PAGE:          "www.firstparty.com",
  SAFER:         "cdn.vendor.com",            // a safer-region TLD, on no dubious list
  NOT_SAFER:     "cdn.vendor.de",             // outside the test's safer regions
  ABUSED_TLD:    "live.evil.top"              // an abused TLD
});
const SAFER_TLDS = Object.freeze(["com", "net", "org", "io", "ai", "edu", "gov", "nl", "uk", "eu"]);   // the user's list
const WHERE = Object.freeze({ PAGE: "page", DEDICATED: "dedicated", SHARED: "shared" });
const KIND = Object.freeze({ WASM: "wasm", WS: "ws" });
const OUTCOME = Object.freeze({ BLOCKED: "blocked", ALLOWED: "allowed" });
const WASM_BYTES = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);   // smallest valid module
const SETTLE_MS = 1200;                     // rules applied after a level change
const PROBE_MS = 2500;                      // page + workers have run their probes
const SW_READY_MS = 1500;

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`e2e-worker-blocks: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const EXT = resolve(ext);
let chromium, C, M, P;
try { ({ chromium } = await import("playwright")); } catch { didNotRun("the playwright package is not installed"); }
try {
  C = await import(pathToFileURL(join(EXT, "data/constants.js")).href);
  M = await import(pathToFileURL(join(EXT, "data/message-types.js")).href);
  P = await import(pathToFileURL(join(EXT, "data/protections.js")).href);
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }
if (!P.PROTECTION_KEY.BLOCK_WASM_DUBIOUS) didNotRun("this build has no blockWasmDubious — 3P Matrix < 5.0.5");

const ALL = Object.values(WHERE);
const EXPECT_ALL = (o) => Object.fromEntries(ALL.map((w) => [w, o]));
// [what, level, kind, third-party host, expected per place, places that are a known Chrome limitation]
const CASES = [
  ["blockWebAssembly network half: 3P WebAssembly",            C.LEVEL.HIGH,  KIND.WASM, HOST.SAFER,      EXPECT_ALL(OUTCOME.BLOCKED), []],
  ["blockWebsockets network half + worker CSP: 3P WebSocket", C.LEVEL.HIGH,  KIND.WS,   HOST.SAFER,      EXPECT_ALL(OUTCOME.BLOCKED), []],
  ["blockWasmDubious: 3P WebAssembly from outside safer",      C.LEVEL.SMART, KIND.WASM, HOST.NOT_SAFER,  EXPECT_ALL(OUTCOME.BLOCKED), []],
  ["blockWasmDubious: 3P WebAssembly from a safer host",       C.LEVEL.SMART, KIND.WASM, HOST.SAFER,      EXPECT_ALL(OUTCOME.ALLOWED), []],
  ["blockAbusedTlds: WebSocket to an abused TLD",             C.LEVEL.MILD,  KIND.WS,   HOST.ABUSED_TLD, EXPECT_ALL(OUTCOME.BLOCKED), [WHERE.SHARED]],
  ["blockAbusedTlds: WebSocket to an ordinary host",          C.LEVEL.MILD,  KIND.WS,   HOST.SAFER,      EXPECT_ALL(OUTCOME.ALLOWED), []],
];

// ── Local server: the page, its two workers, the .wasm file and the WebSocket endpoint ──
let port = 0, current = null, reached = new Set();
const probe = (where) => current.kind === KIND.WASM
  ? `fetch("http://${current.host}:" + location.port + "/${where}.wasm").then(r => r.arrayBuffer()).catch(() => {});`
  : `try { new WebSocket("ws://${current.host}:" + location.port + "/${where}"); } catch (e) {}`;
const server = createServer((req, res) => {
  const path = req.url.split("?")[0];
  if (path.endsWith(".wasm")) { reached.add(path.slice(1, -".wasm".length)); res.writeHead(200, { "content-type": "application/wasm", "access-control-allow-origin": "*" }); return res.end(WASM_BYTES); }
  if (path === "/dedicated.js") { res.writeHead(200, { "content-type": "text/javascript" }); return res.end(probe(WHERE.DEDICATED)); }
  if (path === "/shared.js") { res.writeHead(200, { "content-type": "text/javascript" }); return res.end(`onconnect = () => { ${probe(WHERE.SHARED)} };`); }
  res.writeHead(200, { "content-type": "text/html" });
  res.end(`<!doctype html><title>workers</title><script>${probe(WHERE.PAGE)}
    new Worker("/dedicated.js"); new SharedWorker("/shared.js?" + Math.random()).port.start();</script>`);
});
server.on("upgrade", (req, sock) => { reached.add(req.url.slice(1)); sock.destroy(); });

let failed = 0;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ctx = null;
try {
  await new Promise((r) => server.listen(0, "127.0.0.1", r)); port = server.address().port;
  const chromiumPath = arg("chromium");
  ctx = await chromium.launchPersistentContext("", { headless: false, ...(chromiumPath ? { executablePath: chromiumPath } : {}),
    args: ["--headless=new", `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--host-resolver-rules=MAP * 127.0.0.1", "--no-proxy-server"] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host; await sleep(SW_READY_MS);
  const ui = await ctx.newPage(); await ui.goto(`chrome-extension://${id}/ui/protections.html`);
  const send = (m) => ui.evaluate((x) => chrome.runtime.sendMessage(x), m);
  const top = `http://${HOST.PAGE}:${port}/`;
  await send({ type: M.MSG_RESET_SETTINGS });
  // The local server runs on an odd port over plain HTTP: blockSuspicious3p/block3pHttp would block every probe for that reason.
  for (const key of [P.PROTECTION_KEY.BLOCK_3P_HTTP, P.PROTECTION_KEY.BLOCK_SUSPICIOUS_3P, P.PROTECTION_KEY.ENABLE_SCAM_PROTECTION])
    await send({ type: M.MSG_SET_PROTECTION, key, enabled: false });
  const popup = await send({ type: M.MSG_GET_POPUP_STATE, url: top });
  for (const t of popup.data.safeZone.tlds) if (!SAFER_TLDS.includes(t)) await send({ type: M.MSG_SET_SAFE_ZONE, removeTld: t });
  for (const t of SAFER_TLDS) await send({ type: M.MSG_SET_SAFE_ZONE, addTld: t });

  for (const [what, level, kind, host, expect, chromeLimit] of CASES) {
    await send({ type: M.MSG_SET_LEVEL, level, url: top }); await sleep(SETTLE_MS);
    current = { kind, host }; reached = new Set();
    const page = await ctx.newPage(); await page.goto(`${top}?${Math.random()}`); await sleep(PROBE_MS); await page.close();
    for (const where of ALL) {
      const got = reached.has(where) ? OUTCOME.ALLOWED : OUTCOME.BLOCKED;
      if (chromeLimit.includes(where)) { console.log(`      INFO level ${level} ${what} — ${where}: ${got} (Chrome does not show this connection to extensions)`); continue; }
      const ok = got === expect[where];
      console.log(`${ok ? "      PASS" : "      FAIL"} level ${level} ${what} — ${where}: ${got}${ok ? "" : ` (expected ${expect[where]})`}`);
      if (!ok) failed++;
    }
  }
} catch (e) {
  console.error(`e2e-worker-blocks: DID NOT RUN — ${e.message}`); process.exitCode = EXIT.DID_NOT_RUN;
} finally {
  if (ctx) await ctx.close().catch(() => {});        // release the browser and the server in every outcome
  server.close();
}
if (process.exitCode !== EXIT.DID_NOT_RUN) {
  console.log(failed ? `e2e-worker-blocks: ${failed} FAILED` : "e2e-worker-blocks: all pass");
  process.exit(failed ? EXIT.FAILED : EXIT.OK);
}
