# 3P Matrix — content firewall · Programming-practices audit of 4.2.2 → fixed in 4.2.3

Date: 2026-10-19 · Source: 3P-Matrix-4.2.2 extension / tools / docs zips · Fixes in working copy **4.2.3 (not yet zipped)**
Measured against: `claude/Xplainer_Programming_principles_audit.md` (principle IDs in brackets; v10 adds C39a and Part D steps 50–51)
Scope: all first-party code; `lib/downloadsentinel/` (vendored DownloadSentinel 3.0.4) not reviewed.
**Status: all findings resolved.** Verification: `npm run check` in 3P-Matrix-tools → 10/10 PASS (incl. 17 real-Chromium flows and the 4.2.2 → 4.2.3 upgrade); built rules and scripts identical to 4.2.2 where behaviour had to stay the same.

## Findings and resolution

| # | Principle | Finding (4.2.2) | Resolution (4.2.3) |
|---|---|---|---|
| 1 | C41 | Legacy per-site Show Matrix override could not be undone from the panel (per-site model taken from uBD by mistake) | Overrides global-only; per-site data migrated (schema 2); per-site tier removed |
| 2 | B2a, **C39a (new)** | "(5 outside safer regions)" typed — one of 9 typed-value sites (18 hits) | All derived (`ui/derived-text.js`, view-model counts); principle C39a; `check-derived-literals.mjs` |
| 3 | B12 | Silent FIFO eviction at 400 locks | Cap 500 (user decision) |
| 4 | C22 | uBD `$worryfree` advice and `[uBol]`/`[uBlock-Dynamic]` prefixes in page scripts | Removed; per-script `LOG_PREFIX` copy; `check-shipped-terms.mjs` |
| 5 | C24 | Spec promised the site never loads before the warning | Accepted (user): protection renamed "Warn when opening…", spec corrected |
| 6 | C1, C11 | background.js held business logic | Split into core/site-locks, matrix-overrides, matrix-windows, view-models (+ editSaferRegions); 420 → ~290 lines |
| 7 | C2, C12 | data/ imported core/; popup imported core/policy | AUTO_TLD_MODE/BASE_TLDS in data/tld-constants; popup flag from view model |
| 8 | B2, C25 | Protections named by quoted strings — a typo silently disabled one | Full `PROTECTION_KEY` enum; guard in `isProtectionActive`; `check-protection-keys.mjs` |
| 9 | C32 | Schema stayed 1; migrations inline | Schema 2; ordered `STATE_MIGRATIONS` run from one place; upgrade proven in Chromium |
| 10 | C5, C13 | Unhandled rejections; UI failures only in the console | `.catch` everywhere; `ui/status-line.js` on all four pages |
| 11 | C6, C28 | No sender check; unvalidated TLD and tab ids; warning URL from the message | Sender check; `requireTabId`; `isValidTld` with message; target from sender URL |
| 12 | — | Script injected twice on a site in safer regions + built-in, locked at 5 (proven) | One rescue registration per site |
| 13 | B1 | Typed numbers/strings outside constants | None left; `check-magic-numbers.mjs` (acorn) |
| 14 | B2 | Literal log prefixes, colours, icon names | `LOG_PREFIX`; CSS tokens; `LEVEL_INFO` |
| 15 | C9a | 13 named arrow functions | Declarations; ESLint `func-style` in the suite |
| 16 | C5 | Unexplained empty catches | Each states why, or reports (failed warning redirect now logged) |
| 17 | C9 | `clampLevel` validated, did not clamp | `parseLevel` in state-storage |
| 18–20 | C10 | Misplaced / stale comments | Fixed |
| 21 | B4 | Spec stale | In line with 4.2.3 |
| 22 | B4 | No 4.2.0 / 4.2.1 history | Reconstructed (marked as such) |
| 23 | C38, C25 | No check suite | `complete-check.mjs` + package.json + eslint config; fault-verified; also fixed `build-spam-tlds.mjs` writing outside the extension |
| 24 | C19 | No licence files | `LICENSE.txt` (GPLv3) + `THIRD_PARTY_LICENSES.md` |
| 25 | C10 | Reference to a non-existent STYLE_GUIDE | Fixed with 4 |
| 26 | C39a | ▶ typed in matrix.html, its constant unused (found by lint) | Set from the constant |

## Removal schedule
`COMPAT-REMOVE ≥4.5`: schema-1 → 2 matrix migration body, backup format v1 (list in `data/state-storage.js` header).

## Extension recipe (where new work plugs in)
- **New protection**: row in `data/protections.js` + `PROTECTION_KEY` entry → values in `data/constants.js` → branch in
  `core/rule-builder.js` or a `security/` script (declare `LOG_PREFIX` if it logs) → counts follow automatically;
  any number shown about it via `ui/derived-text.js`.
- **New setting**: `defaultState` → `normalizeState` (+ a `STATE_MIGRATIONS` step if the shape changes) →
  `settings-io` export + import → message type → router handler (validate input) → view model → UI with status line (C41).
- **Before packaging**: `npm run check` must PASS.
