#!/usr/bin/env node
// ── tools/test-wasm-wrappers.mjs ─────────────────────────────────────────────────
// 5.0.7 — blockWebAssembly's fetch()/arrayBuffer() wrappers (security/sec-no-wasm.js) are transparent: they hand
// the page the browser's OWN promise, so a failure the page leaves unhandled is the page's, not the extension's.
// (5.0.6 and earlier returned a promise built with .then(): every unhandled fetch failure on a level 4–5 page —
// often a request 3P Matrix itself blocked — was listed under 3P Matrix on the browser's extension error page.)
// The script is loaded into a sandbox with stand-ins for fetch / Response / WebAssembly, nothing else.
//   A. fetch() returns exactly the promise the native fetch returned — resolved or rejected.
//   B. response.arrayBuffer() returns exactly the native promise.
//   C. Order: the page's own .then on fetch() already sees the tagging arrayBuffer (side branch runs first).
//   D. Behaviour kept: a cross-origin buffer is refused by WebAssembly.instantiate/compile; same-origin passes.
//   E. A failing fetch creates no extension-owned rejection, and the page that handles it gets the very same error.
//      (Accepted side effect: the side branch counts as a handler, so a failure the page ignores raises no
//      "unhandled rejection" at all — it is no longer reported against 3P Matrix, nor in the page's console.)
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
const SETTLE_TURNS = 5;                       // microtask turns to let promise reactions run

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

// A fresh sandboxed "page" per case; the stand-in native fetch hands out promises the test controls.
function makePage() {
  const ctx = vm.createContext({ console: { info() {}, warn() {}, error() {} }, URL, ArrayBuffer, WeakSet, WeakMap,
                                 Promise, Reflect, Object, TypeError, Error });
  const page = vm.runInContext("this", ctx);
  page.window = page;
  page.location = { href: `${PAGE_ORIGIN}/page`, origin: PAGE_ORIGIN };
  page.last = null;                                   // the promise the native fetch handed out
  page.nativeArrayBufferPromise = null;
  page.fetch = function nativeFetch(url) {
    page.last = page.nextResult(url);
    return page.last;
  };
  page.nextResult = (url) => Promise.resolve(makeResponse(page, url));
  page.WebAssembly = {
    instantiate: () => Promise.resolve("instantiated"), compile: () => Promise.resolve("compiled"),
    instantiateStreaming: () => Promise.resolve("instantiated"), compileStreaming: () => Promise.resolve("compiled")
  };
  vm.runInContext(source, ctx, { filename: SCRIPT });
  return page;
}
function makeResponse(page, url) {
  const buf = new ArrayBuffer(8);
  return {
    url,
    arrayBuffer() { page.nativeArrayBufferPromise = Promise.resolve(buf); return page.nativeArrayBufferPromise; }
  };
}

const unhandled = [];
process.on("unhandledRejection", (reason, p) => unhandled.push({ reason: String(reason), p }));

// ── A. fetch() hands back the native promise ──
let page = makePage();
const r1 = page.fetch(CROSS_URL);
ok("A. fetch() returns the native promise itself (resolved case)", r1 === page.last);
page = makePage();
page.nextResult = () => Promise.reject(new TypeError("Failed to fetch"));
const r2 = page.fetch(CROSS_URL);
ok("A. fetch() returns the native promise itself (rejected case)", r2 === page.last);
r2.catch(() => {});                                     // the page handles it here
await settle();

// ── B, C, D. arrayBuffer identity, ordering, behaviour ──
page = makePage();
const res = await page.fetch(CROSS_URL);                // the page's own await, registered after the side branch
const before = page.nativeArrayBufferPromise;
const abp = res.arrayBuffer();
ok("C. the page's await already sees the tagging arrayBuffer()", page.nativeArrayBufferPromise !== before && abp === page.nativeArrayBufferPromise);
ok("B. arrayBuffer() returns the native promise itself", abp === page.nativeArrayBufferPromise);
const crossBuf = await abp;
let blocked = null;
try { await page.WebAssembly.instantiate(crossBuf); blocked = false; } catch { blocked = true; }
ok("D. a cross-origin buffer is still refused by WebAssembly.instantiate()", blocked === true);
try { await page.WebAssembly.compile(crossBuf); blocked = false; } catch { blocked = true; }
ok("D. … and by WebAssembly.compile()", blocked === true);
page = makePage();
const sameBuf = await (await page.fetch(SAME_URL)).arrayBuffer();
ok("D. a same-origin buffer still instantiates", (await page.WebAssembly.instantiate(sameBuf)) === "instantiated");

// ── E. a failing fetch: no extension-owned rejection; a page that handles it gets the same error ──
unhandled.length = 0;
page = makePage();
const failure = new TypeError("Failed to fetch");
page.nextResult = () => Promise.reject(failure);
page.fetch(CROSS_URL);                                  // page does not handle it
await new Promise((r) => setTimeout(r, 0));
ok("E. a failing fetch the page ignores creates no unhandled rejection owned by the wrapper", unhandled.length === 0, unhandled.map((u) => u.reason));
page = makePage();
page.nextResult = () => Promise.reject(failure);
let seen = null;
await page.fetch(CROSS_URL).catch((e) => { seen = e; });
ok("E. a page that handles the failure gets the very same error object", seen === failure);

console.log(failures ? `test-wasm-wrappers: FAIL — ${failures} case(s)` : "test-wasm-wrappers: ALL PASS");
process.exit(failures ? EXIT.FAILED : EXIT.OK);
