# 3P Matrix — content firewall — technical history

The detailed record (Xplainer audit B4): what changed, **why** it was done that way, how, known limitations,
the source version worked from and which of the three zips changed. Written for big changes only (a new
feature, a bug-class fix, a refactor, a batch of principle fixes); every tools version gets at least a
`**tools x.y.z:**` line. The short user-facing summary is `CHANGELOG.md`. Both files live in the docs zip
only — never in the extension zip.

This file starts at 5.0.7. Earlier technical history lives in the version-tagged notes at the top of
`data/protections.js`, the "vN changes" notes of `Xplainer_Programming_principles_audit.md`, and the
analysis documents in this folder.

---

## 5.0.9

**Working from:** 3P Matrix 5.0.8 (GitHub, repo layout) together with DownloadSentinel 3.6.0.
**Zips changed:** all three — extension (comments only, in `lib/downloadsentinel/util/*.js`), tools (repo
layout), docs (this entry, CHANGELOG.md).

**tools 5.0.9:** new `repo-layout.mjs`; defaults and tree walkers follow it; shared `check-mv3.mjs` re-synced with
DownloadSentinel 3.6.0; `list-modules.mjs` header template says `tools/`.

### The tools now run in the repo layout too (C21 — one declaration of where things are)
- **What:** since the repo holds the unpacked source (5.0.8 "lay out like uBlock Dynamic"), `tools/` and the
  documents sit inside the extension folder. Run from the repo, the suite defaulted to `../3P-Matrix` (not
  there), and with `--extension .. --docs ..` three steps failed: protection-refs and shipped-terms scanned the
  documents and tools as if they were shipped, and release-contents counted them as extension files.
- **How:** `tools/repo-layout.mjs` declares both layouts — release (three sibling folders) and repo (the
  extension is the repo root; top-level files other than `EXTENSION_ROOT_FILES` are documents; `README.md`,
  `privacy.md` and the principles PDF are repo-only; `ARCHITECTURE.md` is the docs zip's `README.md`;
  `tools/`, `node_modules/`, `.git/` are never extension code). `defaultRoots()` picks the layout; every default
  folder (complete-check, package-release, the seven list builders, two tests) and every walker of the extension
  (complete-check syntax, protection-refs, shipped-terms, magic-numbers, no-eval, compat-remove) uses it.
  `package-release.mjs releaseTrees()` cuts the three file lists once; `package-release-state.mjs` hashes exactly
  those. `npm run check` = `node complete-check.mjs` (the defaults decide).
- **Proof:** from the repo, releaseTrees() reproduces the recorded 5.0.8 release: extension (169 files), docs (12)
  and tools (58, from the 5.0.8 tools tree) give the same SHA-256 as `package-release-state.json`.
  complete-check from the repo: 35 passed, 0 failed (e2e with the installed Chromium).
- **check-mv3.mjs** (shared with DownloadSentinel, copied unchanged): default extension folder = the folder above
  `tools/` (both repos), `tools` never scanned; the release layout passes `--ext` as before.

### Library comments (extension zip, comments only)
- The vendored DownloadSentinel modules said "EXTENSION/data/… paths below describe DownloadSentinel's own
  repository layout" — DS 3.6.0 has no EXTENSION/ folder any more: now `data/…` (DS's own data/ folder, not
  3P Matrix's), and the generated headers name `tools/…` instead of `3P-Matrix-tools/…`.

**Consumers checked:** every `DEFAULT_EXTENSION` / `join("..", "3P-Matrix")` default and every directory walker in
tools/ (grep on `readdirSync`), package.json scripts, the list-module header template, both projects' check-mv3.mjs
(identical: `cmp`), DS references to 3P Matrix paths (none stale).

---

## 5.0.8

**Working from:** 3P-Matrix-5.0.7 (as published to the Chrome Web Store, 2026-11-22).
**Zips changed:** all three — extension (`security/sec-browser-locker.js`), tools (wider C47 rule, new
real-browser case), docs (this entry, CHANGELOG.md, principles doc v24).

**tools 5.0.8:** `test-message-gate.mjs` recognises every call form of a document-level listener;
`e2e-page-protections.mjs` adds a hostile-page fullscreen case.

### Fullscreen re-entry block could be switched off by the page (C47 — found while reviewing 5.0.7)
- **What:** `blockDialogSpam`'s browser-locker part refuses fullscreen re-entry once the user has left
  fullscreen. It learned "the user left" only from a `fullscreenchange` listener registered on `document`. A
  page that adds a window-capture listener for `fullscreenchange` and stops it hides that fact, and can force
  fullscreen again — the trap this protection exists to stop. Proven in real Chromium: the new hostile-page
  case fails on 5.0.7 ("in") and passes on 5.0.8.
- **How:** the `fullscreenchange` and `input` listeners now listen on `window`, capture phase, registered at
  `document_start`. (`input` only lets a real "Leave site?" prompt through after typing; a page stopping it
  only blocked its own prompt — the safe side — but one rule for all listeners keeps the check simple.)
- **Why the 5.0.7 check missed it:** the C47 static rule knew two spellings
  (`document.addEventListener(…)`, `reflectApply(addEventListenerFn, doc, …)`); the locker uses
  `apply(addListener, doc, …)`. The rule now finds every variable holding `EventTarget.prototype.addEventListener`
  and every alias of `document`, and flags any `apply`/`reflectApply`/`Reflect.apply`/`.call` combination of
  the two. It flags the locker's two listeners on 5.0.7.
- **Consumers checked:** every page script's listener registrations (the widened rule runs over all of
  `security/`); the only remaining document-level listener is the password dialog's Escape key (allowlisted
  with its reason).

### Not done (measured, not worth it)
Frame-injection cost was measured in real Chromium (40 frames × 15 rounds, levels 1/2/4): about 13–14 ms per
frame without page scripts, roughly +1.5–3 ms at levels 2–4; stripping comments made no consistent difference.
Merging the four obfuscation scripts would save three script setups at levels 4–5 only — dropped as not worth
the change.

---

## 5.0.7

**Working from:** 3P-Matrix-5.0.6 (extension, tools and docs zips as published to the Chrome Web Store,
uploaded 2026-11-22).
**Zips changed:** all three — extension (bridge fix, WebAssembly wrapper fix, import limit, log line, registry, comments, files removed),
tools (new checks and tests, suite option `--docs`), docs (this file, README moved in with threat model,
principles doc v23).

**tools 5.0.7:** new `check-protection-refs.mjs`, `check-permission-additions.mjs`, `test-untrusted-input.mjs`,
`package-release.mjs`, `test-wasm-wrappers.mjs`; `check-protection-keys.mjs` checks display order; `test-message-gate.mjs` checks every
page script's listeners and observers and rejects a wrapper that returns its own `.then()` chain (C53); `e2e-page-protections.mjs` covers the ClickFix and skimmer warnings
against a hostile page; `package-release-state.mjs` uses the release declaration; suite option `--docs`.

### 1. A page could silence the ClickFix and skimmer warnings (C47 — audit of 5.0.6)
- **What:** the MAIN-world scriptlets dispatch an event on `document`; the ISOLATED-world bridges listened for
  it on `document`. The event's capture path starts at `window`, so a page that registers a window-capture
  listener for that event name (it is in the shipped source) can `stopImmediatePropagation()` before the
  bridge sees it. ClickFix: the paste is still blocked, the warning never opens. Skimmer: it only warns, so the
  protection was switched off entirely. The skimmer's own `focusin` check sat on `document` too.
- **How:** both bridges and the `focusin` listener now listen on `window`, capture phase. They register at
  `document_start`, before any page script, so they run first.
- **Proof:** new real-browser cases in `e2e-page-protections.mjs` — an ordinary scam page and one that stops
  the event; the second pair FAILED on 5.0.6 and passes now. Static guard in `test-message-gate.mjs`: no
  document-level listener in a page script unless listed with its reason (the password dialog's Escape key —
  stopping it only keeps the dialog open, nothing is sent). It flags all three on 5.0.6.

### 2. Protection numbering: one display order (C21) — audit of 5.0.6
- 5.0.6 had already renumbered (fake sign-in window 30 → 18). Still missing: the settings page worked out the
  order itself, and `check-protection-keys.mjs` only checked "unique, 1…N, no gaps".
- `data/protections.js` exports `protectionsInGroup(group)` and `PROTECTIONS_IN_DISPLAY_ORDER`;
  `core/view-models.js` renders from them; the check requires `num` = position in that list.

### 3. Protections named by key, never by number (C25)
- 5.0.6's renumbering sweep (by hand, as every one since 4.2) left at least 18 references describing the wrong
  protection — e.g. Permissions-Policy "17–19" (now 19–21), the download warning called 13 (14), the
  risky-download block called 25, "15–25" and "1–16" ranges from older versions.
- All references outside the registry now use the key (stale ones corrected by meaning first). HARD
  CONSTRAINT in `README.md`; `check-protection-refs.mjs` rejects "protection N" (181 hits on 5.0.6).
- **Limit:** catches the words "protection(s) N"; other bare-number forms ("items (13, 27)") are not caught —
  four were fixed by hand.

### 4. Outside recommendations, kept where they add robustness (C49–C52)
A review of an external "engineering standards" proposal, judged by robustness and future-proofing:
- **C49 threat model** — table in `README.md` (attacker, reach, risk, stopping rule, fail-safe direction).
- **C50 input limits** — settings and allow-list imports go through one reader that checks the size
  (`IMPORT_FILE_MAX_BYTES`, 8 MiB) before reading. **Deliberately NOT done:** a size cap on content-script
  messages at the router — the password-form check fails open when the service worker refuses, so a cap would
  let a page bypass the warning with an oversized form address. Page scripts run no MutationObserver (verified:
  the two mentions are comments explaining why); a new one must be listed with its limits.
- **C51 seeded fuzz** — `test-untrusted-input.mjs`: 3000 inputs each for settings import (incl. `__proto__`
  keys — no injected prototype reached the state), domain helpers, the message gate; ClickFix patterns on
  worst-case input of the scriptlet's own 2048-char limit. One fixed seed. Fault-verified.
- **C52 logs** — the router logged a refused sender's full address; it now logs the origin (`senderLabel`).
  Static rule: no `console.*` call prints an address variable.
- **C48 navigation targets** — verified: every navigation target is a constant, an extension page or
  `parseHttpUrl` output (http/https only). No code change needed.
- **C36 permission comparison** — `check-permission-additions.mjs` compares the manifest with the previous
  release's record; additions need an approval entry. The principles doc listed this step, but 3P Matrix had
  no such tool.
- **C19 minimum Chrome** — README records: manifest minimum 120, tests pinned to Chromium 129 (Playwright
  1.47.2), 5.0.7 also verified on Chromium 153.
- **Rejected:** `document_idle`/lazy page scripts, lazy service-worker initialisation beyond C16/B7, timing
  budgets as release gates, a JSON-Schema library in the extension, micro-optimisation rules, a stored
  security-event log, restructuring the principles doc. Reasons in the principles doc, v23.

### 5. Release contents declared and guarded
- The extension zip shipped `README.md` and `docs/STYLE_GUIDE.md` (a byte-identical duplicate of the docs
  copy, referenced by nothing). The principles doc said the shipped files were "declared once in
  `tools/package-release.mjs`" — that script did not exist — and contradicted itself on where CHANGELOG.md lives.
- `tools/package-release.mjs` declares each zip's contents and checks version congruence;
  `package-release-state.mjs` refuses to record a release that fails it. README moved to docs; the duplicate
  removed; the principles doc now says plainly: both changelogs in docs, never in the extension.
- **Limit:** the guard checks file types, not "everything the manifest declares or the code imports".

### 6. `blockWebAssembly` made other sites' fetch failures look like 3P Matrix errors (C53 — user report)
- **Report:** Brave's extension error page: `Uncaught (in promise) TypeError: Failed to fetch`, context a video
  page, stack `security/sec-no-wasm.js:96`.
- **Root cause:** to tag cross-origin WebAssembly bytes, the MAIN-world wrapper replaced `window.fetch` with
  `return nativeFetch(...).then((response) => { …patch arrayBuffer…; return response; })`. The page received
  that derived promise. When the page's fetch failed (on a level 4–5 page often a request 3P Matrix itself
  blocked) and the page did not handle it, Chrome attributed the unhandled rejection to the script that created
  the promise: ours. `Response.arrayBuffer()` was wrapped the same way. Behaviour was correct; attribution wrong.
- **Fix:** both wrappers return the native promise itself. The tagging runs on a side branch registered before
  the promise is returned — promise reactions run in registration order, so the page's own `.then`/`await`
  already sees the tagging `arrayBuffer()`. The side branch handles a rejection with a no-op.
- **Accepted side effect:** the side branch counts as a handler, so a failure the page ignores raises no
  "unhandled rejection" at all (not under 3P Matrix, not in the page console; Chrome still logs the failed
  request). A page that handles the failure gets the same error object. The alternative (no rejection handler on
  the side branch) is the original bug.
- **Not changed:** `WebAssembly.instantiateStreaming`/`compileStreaming` keep their own chain — they must reject a
  blocked module. An unhandled failure there is still attributed to 3P Matrix; it occurs only when a page loads
  WebAssembly by streaming. Named in the code.
- **Proof:** `test-wasm-wrappers.mjs` (sandbox, stand-ins for fetch/Response/WebAssembly) fails 5 cases on 5.0.6's
  code (unchanged since 5.0.5), passes now; the real-browser WebAssembly tests (`e2e-worker-blocks.mjs`) still pass. Static C53 rule in
  `test-message-gate.mjs` flags the two old wrappers.
- **Consumers checked:** every page script's promise use (`grep .then(` in `security/`): only `sec-no-wasm.js`
  wraps a promise-returning page API; the other `.then`/`.catch` calls are on our own `chrome.runtime.sendMessage`.

### Injected page-code footprint (manual check at every minor bump — first record)
Page scripts registered per level (`scripts` + `isolatedScripts` of every protection applying at that level,
default-on protections), unique files and total bytes, at 5.0.7:

| Level | Scripts | Bytes |
|---|---|---|
| 1 | 0 | 0 |
| 2 | 14 | 78 221 |
| 3 | 20 | 105 168 |
| 4 | 22 | 117 801 |
| 5 | 22 | 117 801 |

Compare at 5.1.0.

### Consumers checked (Ground Rules)
Display order: `core/view-models.js` (settings page + popup), `ui/protections.js`, `ui/popup.js`,
`ui/derived-text.js`, `check-protection-keys.mjs`. Bridges: `security/clickfix-bridge.js`,
`security/skimmer-bridge.js`, `security/sec-skimmer-warn.js`; every other page script checked by the new static
rule. Import: both paths in `ui/protections.js`. Logs: every `console.*` in first-party code (static rule).
Release declaration: `package-release-state.mjs`, `complete-check.mjs`.
