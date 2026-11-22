# 3P Matrix 4.3.0 — programming-principles analysis + DownloadSentinel merge

**Source:** 3P Matrix 4.2.3 (extension, tools, docs) + DownloadSentinel 3.2.0 extension, uploaded 2026-10-20.
**Result:** 3P Matrix 4.3.0 (not zipped yet). `npm run check`: 11/11 PASS, incl. e2e in real Chromium (+15 download assertions).

## 1. 3P Matrix 4.2.3 against the principles (Xplainer v10)

| Principle | State in 4.2.3 | Note |
|---|---|---|
| B1/B2 single source of truth | Strong: `data/constants.js`, registry, `check-magic-numbers` | One duplicate found: DNS provider table existed in 3PM **and** DS (identical) → 4.3.0 derives 3PM's from DS `APP.DNS_PROVIDERS` |
| C1/C11 one module, one job | Strong: thin router, pure builders, `core/` split | — |
| C4 single storage layer | Strong: one state key, `normalizeState` | DS has its own `Settings` key → not taken over; DS settings live in `state.downloads` |
| C6/C28 input validation, sender-derived ids | Strong (`warningTarget`) | Same pattern used for the download id (`downloadTarget`) |
| C13/C41 guards, release | Strong (status line, timers, panel close) | DS warning windows were never released before the 30-min sweep → 4.3.0 tracks and releases them on close |
| C21 reuse proven code | Applied | Download logic is DS's background.js logic, VT nudge reuses DS `VtKeyPromptPolicy` |
| C22 cross-variant consistency | Gap | DS 3.2.0 already had the 3PM look-alike redesign; 3PM still ran 3.0.4 (three overlapping checks) → upgraded |
| C27 packaging | OK | `update-top-sites.mjs` present; DS build input `GovSuffixes.json` was missing → `tools/gov-suffixes.json` |
| C36 permission added in update | Applies | `downloads` is required by user decision — existing users must re-approve |
| C38 a check that did not run | **Bug found** | ESLint ignore `lib/**` never matched `../3P-Matrix/lib` (cwd-relative); passed by luck → fixed |
| C39 no inert scaffolding | Applied | DS's unwired "submit URL to VT again" flow not ported |
| C39a derived values | Applied | New UI numbers (threshold range, max domains, built-in list, default colour/title, protection 12) via `derived-text.js` |

## 2. DownloadSentinel 3.2.0 against the same principles

- Good: `APP` / `SCORING_CONFIG` constant blocks, pure check modules, reason-code tables, bounded caches, idempotent `FilterDataLoader.init()`.
- Gaps (stay in DS, worth upstreaming): `func-style` (arrow helpers in `BrowserProtection`, `FilterDataLoader`); `GovSuffixes.default.js` shipped but unused at runtime; `SUBMIT_URL_TO_VT` handler with no sender; options lock every section behind a VT key (incl. DNS and trusted domains); warning page treats VT score 0 as unknown; "Unknown to VirusTotal" shown without a key; colours/numbers typed in page JS; message sender check accepts a missing `extensionId`.

## 3. Open (candidates for a later release)

1. One DoH/RDAP implementation for sites and downloads (timeouts 3/4 s vs 8 s; DS "age not published = recent" only on downloads).
2. Register the Brands list (and DS lists refreshed by FilterDataLoader) in `data-sources.json`.
3. FilterDataLoader fetches from the uBol-stripped repo; files not published there yet → bundled lists stay in use.
