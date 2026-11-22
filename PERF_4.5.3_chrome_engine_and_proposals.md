# 3P Matrix 4.5.3 — Chrome engine behaviour and performance proposals

Status: analysed on 4.5.3; **implemented in 4.5.4** (section 6). Programming rules derived from it: principles doc C44, C45, Part D steps 53–54.
Scope: everything that 3PM runs outside DNR — service worker (SW), content scripts, extension pages.

---

## 1. How Chrome processes each part (what makes it fast or slow)

| Part | Where it runs | What Chrome does | Cost driver |
|---|---|---|---|
| DNR rules | Browser process, network stack (C++) | Rules are indexed once at `updateDynamicRules`/`updateSessionRules`; every request is matched in the browser without touching JS | Re-indexing on every rule update; regex rules (limit 1000, ≤2 KB compiled each) |
| Service worker | Its own V8 isolate | Starts on an event, **evaluates the full static import graph**, stops after **30 s idle**; any event or extension API call resets the timer. Dynamic `import()` is **not supported** in extension SWs | Every wake = parse + evaluate all modules; every event = IPC |
| Content scripts (MAIN, document_start, all frames) | Each renderer, before page scripts | Chrome matches each registration's `matches`/`excludeMatches` per frame; matching scripts run synchronously before the parser continues. V8 code cache applied to content scripts | Number of registrations × patterns per frame; synchronous work at injection; per-call wrapper overhead |
| Extension pages (popup, options, warning) | Extension process | V8 code cache for `chrome-extension://` pages since Chrome 123 | Small; keep file URLs stable |
| V8 code cache (general) | — | Produced on the 2nd run, used from the 3rd; only functions compiled during the first execution; scripts < 1 KiB are skipped | Lazily compiled functions and object/array **evaluation** are not saved by the cache |

Key consequence: DNR is already the fast path. The cost 3PM adds now sits in (a) how often the SW wakes and what it does at each wake, (b) what it rewrites into Chrome needlessly, (c) per-frame content-script matching.

---

## 2. Measurements (Node 4.5.3 source, no code cache — relative numbers, not Chrome absolutes)

| What | Result |
|---|---|
| SW static import graph | **87 modules, 1.51 MB** source |
| Evaluate `background.js` graph cold | **~148 ms** |
| Largest modules | PSL 261 KB, HostList 228 KB, TopSites 129 KB, PlatformSuffixes 97 KB, ScoringEngineV2 69 KB, Brands 60 KB |
| 4 big lists as object literal / `JSON.parse` / lazy `JSON.parse` | 15–26 ms / 14–15 ms / **5 ms** |
| Content-script registrations, level 3 | **10 registrations, 1 759 `excludeMatches`** (5 registrations repeat the same ~320-pattern exclude list) |
| Content-script registrations, level 5 | 10 registrations, 16 excludes |
| DNR rules, level 3 / 5 | 20 / 15 (5 regex) — well shaped, no change needed |
| `setTimeout` wrapper, rest+spread vs `arguments` | 56–60 ns → 14–33 ns per call (JIT); 320 → 103 ns (jitless) |

Wake triggers found: `alarms` sweep every **5 min** (`SWEEP_ALARM_PERIOD_MINUTES`), every top-frame navigation (2 events), **every `ERR_BLOCKED_BY_CLIENT` from any extension**, downloads, messages.

Work done at every SW wake: full graph evaluation, `TabLocks.rebuild` (`tabs.query`) and a **full rewrite of the session rules** even when nothing changed.

Per navigation: **4 × `chrome.storage.local.get` + 4 × `normalizeState`** (2 in onBeforeNavigate, 2 in onCommitted).

Per blocked request: 1 IPC event + rule replay + **2 badge IPC calls** (`setBadgeText` + `setBadgeBackgroundColor`).

Per mutation (any setting, including DNS resolver, VT key, download settings): full DNR replace + unregister/register of **all** content scripts, which Chrome persists and pushes to every renderer.

---

## 3. Proposals (ranked by gain / effort)

### P1 — Sweep alarm only while downloads are pending
- **Now:** alarm wakes the SW every 5 min forever; on a restarted SW the in-memory maps it sweeps are empty anyway.
- **Change:** create the alarm when the first entry enters `_pending`/`_blocked`; clear it when all maps are empty (in `release`/`releaseAll`/`onAlarm`). `init()` clears a leftover alarm when nothing is pending.
- **Gain:** idle browser → zero periodic wakes (was 12/hour, each ~150 ms evaluation + session-rule rewrite).
- **Consumers:** `core/download-guard.js` (init, onAlarm, release paths), DownloadSentinel itself (same `DS_APP.SWEEP_*` design — sweep the fix into DS too).

### P2 — Apply only what changed (dirty check)
- **Now:** `applyRules`, `applySession`, `applyScripts` always replace everything.
- **Change:** in `core/apply-manager.js`, compare a canonical form (sorted, `JSON.stringify`) of the newly built set with the last-applied set (in memory; after a SW restart, with what Chrome returns from `getDynamicRules`/`getSessionRules`/`getRegisteredContentScripts`). Skip the Chrome call when equal. Each of the three gets its own "last applied" guard, reset on failure.
- **Gain:** SW start no longer rewrites session rules; settings that do not affect rules (DNS, VT key, download settings, startup level) no longer re-index DNR or re-register scripts in all renderers.
- **Consumers:** `applyState`, `applySessionRules`, every `mutate()` caller in `background.js`, SW-start band init.

### P3 — In-memory state cache with explicit invalidation
- **Now:** every event reads and normalizes the full state from storage.
- **Change:** `data/state-storage.js` keeps one normalized, frozen snapshot: filled on first `loadState`, replaced in `saveState`, dropped on `chrome.storage.onChanged` for `STORAGE_KEY_STATE` (covers other contexts). `mutate()` works on a `structuredClone` so the snapshot is never edited in place. Released naturally on SW stop.
- **Gain:** navigation path goes from 4 storage reads to 0–1; the suspicious-site **warning redirect fires sooner** (less of the bad page loads before `tabs.update`).
- **Consumers:** all `loadState()` callers (background router, navigation, downloads, tab band, view models); `withStateLock` unchanged.

### P4 — Lazy data lists (no `import()` needed)
- **Now:** PSL, HostList, PlatformSuffixes, Brands, TopSites are built at module evaluation on every wake, even when the wake is just a badge count.
- **Change:** generated `*.default.js` files export the data as one JSON **string**; the wrapper modules parse and build their Sets/Map/Bloom filter on first lookup (init-once guard, kept for the SW's lifetime). Lookup API unchanged.
- **Gain:** measured 15–26 ms → 5 ms for four lists; the biggest share of the ~150 ms wake cost is deferred to the first navigation/download that needs it.
- **Consumers:** the generators (`tools/rebuild-host-list.mjs`, `tools/update-top-sites.mjs`, DS `gen-data-defaults.mjs`), `ListSetModule.js`, every list wrapper, `tools/check-list-freshness.mjs`; shared DS library → same change in DownloadSentinel.

### P5 — Group content-script registrations
- **Now:** one registration per protection; at level 3, five of them carry the identical ~320-pattern exclude list → Chrome checks ~1 759 patterns per frame and stores five copies in every renderer.
- **Change:** in `core/script-builder.js` (pure), after building, merge registrations whose `matches` + `excludeMatches` are identical into one registration (`js` = members' files in PROTECTIONS order; id = prefix + sorted member keys). Toggling a protection simply produces a different grouping.
- **Gain:** level 3: 10 → ~5 registrations, ~1 759 → ~490 patterns per frame; fewer per-frame injection batches on ad-heavy pages with many iframes.
- **Consumers:** `apply-manager` (id-prefix cleanup already generic), Show Matrix / popup if they read script ids, `tools/test-*` that assert ids.

### P6 — Cheaper badge path
- **Change A:** coalesce `render(tabId)` per tab with one timer (`BADGE_RENDER_DELAY_MS` in constants); remember last text/colour per tab and skip unchanged calls (released in `releaseTab`).
- **Change B:** give the `onErrorOccurred` listener a `types` filter (all sub-resource types) so main-frame errors never cross IPC.
- **Gain:** burst of N blocks → 1–2 IPC calls instead of 2N; SW stays less busy on heavy pages.
- **Consumers:** `core/badge.js` (all setters go through `render`), `background.js` listener, popup count via `getCount`.

### P7 — Wrapper fast path in MAIN-world scripts
- **Change:** in `sec-nosettimeout.js`, `sec-nosetinterval.js` (and the adult-noeval timer wrappers): non-string handler → `reflectApply(native, window, arguments)` instead of `...rest` + array spread.
- **Gain:** roughly halves per-call overhead on timer-heavy pages and in frames before JIT.
- **Consumers:** all four obfuscation scripts share the same shape (`util/ObfuscationShape.js` header) — apply to each; `tools/check-shipped-terms.mjs` / `test-obfuscation-shape.mjs`.

### Not recommended
- Chrome's built-in DNR action count (`displayActionCountAsBadgeText`): also counts modifyHeaders matches — already rejected in `badge.js`, still correct.
- Keep-alive tricks for the SW: cost more than the wakes they avoid.
- `importScripts` / dynamic `import()` for laziness: unsupported for module SWs; P4 achieves it without.

---

## 4. Side findings caused by the same SW lifecycle (correctness, not speed)

- "Continue once" (`_allowedOnce`), badge counts and risk colour live only in SW memory → after 30 s idle the user can be warned again for a site they just continued to, and the badge resets. Candidate: `chrome.storage.session` (same pattern as P3).
- `migrateRaw` / `STATE_MIGRATIONS` still run on every `normalizeState`; compat conversion was due for removal from 4.5 on (with P3 it runs once per wake instead of 4× per navigation, but it should go).

---

## 5. Suggested order
P1 → P2 → P3 (largest effect, smallest change, all inside existing guards), then P6, P5, P4 (tool + DS library change), P7.
New constants go to `data/constants.js` (BADGE_RENDER_DELAY_MS) and DS `AppConstants.js` (sweep alarm lifecycle); no magic numbers elsewhere.

---

## 6. Implemented in 4.5.4

| # | Change | Where | Verified by |
|---|---|---|---|
| P1 | Sweep alarm armed when a download entry appears, cleared by the sweep that empties the maps | `core/download-guard.js` | e2e download flows |
| P2 | Dirty check for dynamic rules, session rules, script registrations (last-applied key; after a SW restart compared with Chrome's own get*()) — pattern lists compared sorted, because Chrome returns them sorted | `core/apply-manager.js` | `test-perf-guards` (no second write); real-Chromium round trip: rules and registrations compare equal |
| P3 | One normalized state snapshot; private `structuredClone` copies; replaced by saveState(); **dropped** by storage.onChanged / dropSnapshot() | `data/state-storage.js`, `core/legacy-suffix-locks.js` | `test-perf-guards`, e2e (harness writes storage directly) |
| P4 | All 11 lists precompiled JSON strings, parsed on first lookup (`util/LazyJson.js`); every list has its tool in 3P-Matrix-tools (`list-modules.mjs`, `update-psl.mjs`, `gen-brands-data.mjs`, `build-curated-lists.mjs`) | `lib/downloadsentinel/util/*` , tools | `test-perf-guards` (0 parses at import), `list-freshness` (completeness, counts, same PSL snapshot); 10 lists bit-identical, PSL refreshed to 4.5's snapshot |
| P5 | Registrations with identical scope merged | `core/script-builder.js` | `test-perf-guards` (every file keeps its exact scope, levels 1–5) |
| P6 | Badge draw coalesced per tab (`BADGE_RENDER_DELAY_MS`), unchanged text/colour skipped; `types` filter on onErrorOccurred with guarded fallback | `core/badge.js`, `background.js` | e2e badge counts |
| P7 | Timer wrappers pass `arguments` | `security/sec-nosettimeout.js`, `sec-nosetinterval.js` | `obfuscation-shape`, `shipped-terms`, e2e |
| Side | Badge count, risk colour, "Continue once" in `chrome.storage.session` | `core/session-map.js` (4.5.5 name; was tab-session-store.js), `core/badge.js`, `core/navigation-guard.js`, `core/view-models.js` | e2e |
| Side | Overdue `COMPAT-REMOVE ≥4.5` blocks removed; `check-compat-remove.mjs` added | `data/state-storage.js`, `data/settings-io.js`, `data/constants.js` | `compat-remove`, `state-migration`, e2e |

Measured after (same Node method as section 2): SW graph 89 modules / 1.37 MB (was 87 / 1.51 MB); evaluation median 112 ms (was 140 ms); level-3 content-script patterns 799 (was 1 759).
Harness fix found on the way: `e2e-flows.mjs` read `page.url()` at Chromium's `page` event (still empty) — the 4.5.3 "an executable opens the warning window" failure was the test, not the product.

**DownloadSentinel:** the shared library files changed in 3P Matrix (`util/LazyJson.js`, `ListSetModule.js`, the 11 list wrappers, the 11 `.default.js` files) should be ported to DS with its `gen-data-defaults.mjs` emitting the same string format — otherwise the two copies of the library drift.

---

## Sources
- V8 — Code caching for JavaScript developers: https://v8.dev/blog/code-caching-for-devs
- Chromium extensions group — V8 compilation cache enabled for chrome-extension:// pages (Chrome 123): https://groups.google.com/a/chromium.org/g/chromium-extensions/c/_QYvKQ5woBI
- Chrome — Extension service worker basics (dynamic import unsupported): https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/basics
- Chrome — Longer extension service worker lifetimes (30 s idle, timer resets): https://developer.chrome.com/blog/longer-esw-lifetimes
- Chrome — declarativeNetRequest reference (rule limits, regex limits, action count): https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
- MDN — setExtensionActionOptions: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/declarativeNetRequest/setExtensionActionOptions
