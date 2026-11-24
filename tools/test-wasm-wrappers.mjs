#!/usr/bin/env node
// ── tools/test-wasm-wrappers.mjs ─────────────────────────────────────────────────
// blockWebAssembly's wrappers (security/sec-no-wasm.js) never make a page's failures the extension's.
// 5.0.7 — the wrappers handed back the browser's OWN promise. 5.1.3 — that was not enough: a failing fetch() was still
// listed under 3P Matrix ("Uncaught (in promise) TypeError: Failed to fetch … sec-no-wasm.js"), because the browser
// files an error under the script of the frame that CALLED the native function. So fetch() and XMLHttpRequest.open are
// no longer wrapped at all; the origin comes from the response itself (Response.url, XMLHttpRequest.responseURL).
// The script is loaded into a sandbox with stand-ins for fetch / Response / XMLHttpRequest / WebAssembly, nothing else.
//   A. fetch() and XMLHttpRequest.prototype.open are the browser's own — not replaced.
//   B. Response.prototype.arrayBuffer() returns exactly the native promise.
//   C. Order: the page's own .then/await on arrayBuffer() already sees the tagged buffer (side branch runs first).
//   D. Behaviour kept: a buffer from a cross-origin response (its own .url) is refused by WebAssembly.instantiate/
//      compile; same-origin and page-made (no url) pass; the XHR `response` getter tags by responseURL.
//   E. A failing body read creates no extension-owned rejection, and a page that handles it gets the same error.
//
// Usage:  node test-wasm-wrappers.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const SCRIPT = "security/sec-no-wasm.js";
const PAGE_ORIGIN = "https://shop.example";
const SAME_URL = `${PAGE_ORIGIN}/app.wasm`;
const CROSS_URL = "https://cdn.other.example/mod.wasm";
const BUFFER_BYTES = 8;
const SETTLE_TURNS = 5;                       // microtask turns to let promise reactions run
const ARRAYBUFFER_TYPE = "arraybuffer";

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-wasm-wrappers: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
let source;
try { source = readFileSync(join(ext, SCRIPT), "utf8"); } catch (e) { didNotRun(e.message); }

let failures = 0;
function ok(label, pass, detail) {
  console.log(`${pass ? "ok  " : "FAIL"} ${label}${pass ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!pass) failures += 1;
}
async function settle() { for (let i = 0; i < SETTLE_TURNS; i++) await Promise.resolve(); }

// A fresh sandboxed "page" per case. Stand-ins: Response with a native-like `url` getter and arrayBuffer() whose
// result the test controls; XMLHttpRequest with `response` / `responseURL` getters and open().
function makePage() {
  const ctx = vm.createContext({ console: { info() {}, warn() {}, error() {} }, URL, ArrayBuffer, WeakSet, WeakMap,
                                 Promise, Reflect, Object, TypeError, Error });
  const page = vm.runInContext("this", ctx);
  page.window = page;
  page.location = { href: `${PAGE_ORIGIN}/page`, origin: PAGE_ORIGIN };
  page.nextBody = () => Promise.resolve(new ArrayBuffer(BUFFER_BYTES));
  page.lastBodyPromise = null;
  class Response {
    constructor(url) { this._url = url; }
    get url() { return this._url; }
    arrayBuffer() { page.lastBodyPromise = page.nextBody(); return page.lastBodyPromise; }
  }
  class XMLHttpRequest {
    constructor(url) { this._url = url; this.responseType = ARRAYBUFFER_TYPE; this._buf = new ArrayBuffer(BUFFER_BYTES); }
    open() {}
    get response() { return this._buf; }
    get responseURL() { return this._url; }
  }
  page.Response = Response;
  page.XMLHttpRequest = XMLHttpRequest;
  page.fetch = function nativeFetch(url) { return Promise.resolve(new Response(url)); };
  page.nativeFetch = page.fetch;
  page.nativeOpen = XMLHttpRequest.prototype.open;
  page.WebAssembly = {
    instantiate: () => Promise.resolve("instantiated"), compile: () => Promise.resolve("compiled"),
    instantiateStreaming: () => Promise.resolve("instantiated"), compileStreaming: () => Promise.resolve("compiled")
  };
  vm.runInContext(source, ctx, { filename: SCRIPT });
  return page;
}
async function refused(page, buf) {
  try { await page.WebAssembly.instantiate(buf); return false; } catch { return true; }
}

const unhandled = [];
process.on("unhandledRejection", (reason, p) => unhandled.push({ reason: String(reason), p }));

// ── A. fetch() and XMLHttpRequest.open are not replaced ──
let page = makePage();
ok("A. fetch() is the browser's own (not wrapped — a failing fetch can never be filed under 3P Matrix)", page.fetch === page.nativeFetch);
ok("A. XMLHttpRequest.prototype.open is the browser's own", page.XMLHttpRequest.prototype.open === page.nativeOpen);

// ── B, C, D. arrayBuffer identity, ordering, behaviour ──
page = makePage();
const res = await page.fetch(CROSS_URL);
const abp = res.arrayBuffer();
ok("B. arrayBuffer() returns the native promise itself", abp === page.lastBodyPromise);
const crossBuf = await abp;                                   // the page's own await, registered after the side branch
ok("C. D. the page's await already sees the tag: a cross-origin buffer is refused by instantiate()", await refused(page, crossBuf));
let compileRefused = false;
try { await page.WebAssembly.compile(crossBuf); } catch { compileRefused = true; }
ok("D. … and by compile()", compileRefused);
page = makePage();
const sameBuf = await (await page.fetch(SAME_URL)).arrayBuffer();
ok("D. a same-origin buffer still instantiates", (await page.WebAssembly.instantiate(sameBuf)) === "instantiated");
page = makePage();
const madeBuf = await new page.Response("").arrayBuffer();
ok("D. a page-made Response (no url) counts as same-origin", (await page.WebAssembly.instantiate(madeBuf)) === "instantiated");
page = makePage();
const xhr = new page.XMLHttpRequest(CROSS_URL);
ok("D. the XHR response getter tags a cross-origin buffer by responseURL", await refused(page, xhr.response));
page = makePage();
const xhrSame = new page.XMLHttpRequest(SAME_URL);
ok("D. … and leaves a same-origin one alone", !(await refused(page, xhrSame.response)));

// ── E. a failing body read: no extension-owned rejection; a page that handles it gets the same error ──
unhandled.length = 0;
page = makePage();
const failure = new TypeError("Failed to read body");
page.nextBody = () => Promise.reject(failure);
let seen = null;
await (await page.fetch(CROSS_URL)).arrayBuffer().catch((e) => { seen = e; });
await new Promise((r) => setTimeout(r, 0));
await settle();
ok("E. the side branch creates no unhandled rejection of its own", unhandled.length === 0, unhandled.map((u) => u.reason));
ok("E. a page that handles the failure gets the very same error object", seen === failure);

console.log(failures ? `test-wasm-wrappers: FAIL — ${failures} case(s)` : "test-wasm-wrappers: ALL PASS");
process.exit(failures ? EXIT.FAILED : EXIT.OK);
