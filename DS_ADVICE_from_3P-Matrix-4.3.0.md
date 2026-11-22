# DownloadSentinel 3.2.0 — advised changes (from the 3P Matrix 4.3.0 merge, updated through 4.3.3)

Source: DownloadSentinel 3.2.0 extension zip, read and ported into 3P Matrix 4.3.0 on 2026-10-20.
Updated with what 3P Matrix 4.3.1–4.3.3 changed in the ported download protection (items 22–27), and a user
report of 2026-10-20 (item 28).
**Outcome (2026-10-21):** implemented in DownloadSentinel 3.3.0 and taken over in 3P Matrix 4.3.4 per the
user's Corrections-for-3PM.md (lib now byte-identical; items 20 and 24 by design) — see CHANGELOG_HISTORY.md 4.3.4.
Each item: what is wrong or missing (max 3 lines), then the options. **(R)** = recommended.

## Decided 2026-10-20 (for DownloadSentinel 3.3.0)
| Item | Decision |
|---|---|
| 1 | Port the domain-age skip with its two lists and tool (option R). |
| 12 | Pass settings in (option R). With item 1, 3P Matrix's `lib/downloadsentinel/` becomes byte-identical to DS again (today 2 files differ: `util/Settings.js` adapter, `protection/RdapProtection.js` patch). |
| 19 | The two domain-age lists are rebuilt once per minor release, like the top-sites list (register `updateOn: "minor"`). |
All other items (2–11, 13–18, 20–28): open — choose per item.

---

## A. Behaviour (users see the difference)

### 1. Domain age is looked up where it cannot exist
A site on a hosting platform (`x.github.io`, `y.blogspot.com`) has no domain age of its own: RDAP returns 404.
Country codes without RDAP (.de, .it, .es, .ch, .jp, .ru, .co …) never return an age either.
DS scores both as "recent" (−10), so every download from such a host is penalised.
- **(R) — DECIDED** Port 3P Matrix's `util/domain-age.js` + `data/platform-suffixes.js` + `data/rdap-cctlds.js` + `tools/update-domain-age-lists.mjs`: skip the lookup, score 0, label "not applicable / not published".
- Platform check only; keep −10 for ccTLDs without RDAP.
- Keep as is.

Lists as built for 3P Matrix 4.3.0: 3,447 platform suffixes (Public Suffix List private section, retrieved
2026-10-20) and 72 two-letter ccTLDs with RDAP (IANA `dns.json`, publication 2026-09-30). The PSL comes from
publicsuffix.org (asks to be pulled only from there); `dns.json` from data.iana.org — pass either with `--psl` / `--rdap`.

### 2. A failed RDAP lookup counts as a young domain
Since 3.2.0 a network error or timeout gets the same −10 as "no date published".
An unreachable rdap.org (or a DNS filter blocking it) then makes every download look riskier.
- **(R)** Failed lookup = 0 with "age unavailable"; only a real response without a date = −10.
- Both 0 (neutral).
- Keep as is.

### 3. "Unknown to VirusTotal" is shown without a VirusTotal key
Without a key VT is never asked, yet the VT box says the URL is unknown to VirusTotal.
- **(R)** Hide the VT box without a key (the disclaimer already says no key is set) — as 3P Matrix does.
- Show "Not checked — no VirusTotal key" in the box.

### 4. A VirusTotal score of exactly 0 shows as "unknown"
`WarningPage.js` tests `!data.vtScore`, which is also true for a real score of 0.
- **(R)** Test `data.vtScore === null`.

### 5. All options are locked until a VirusTotal key is set
DNS checks, trusted domains and the warning-page look have nothing to do with VirusTotal, but stay greyed out.
- **(R)** Lock only the VT-dependent sections (false-positive reduction, "Silent when probably safe").
- Keep the lock as a deliberate nudge to get a key.
- Remove the lock entirely.

### 6. Warning windows stay in memory until the 30-minute sweep
Closing the warning window with the window's ✕ (not a button) leaves its check record and dedup entry behind.
- **(R)** Track `windowId → downloadId` and release on `chrome.windows.onRemoved` (no permission needed).
- Keep relying on the sweep.

### 7. A very small download can be checked twice
`onCreated` waits for `Settings.get()`; a tiny file can complete first, so `onChanged` builds a late-entry record,
then `onCreated` builds a second one → double checks, possibly two windows.
- **(R)** In `onCreated`, return when `checkedIds` or `pendingChecks` already has the id.

### 22. Every page-made file gets a false "hidden extension" penalty
A file a site generates itself (`blob:`/`data:` address, e.g. claude.ai, web apps) never shows an extension in
its URL, so `getObfuscationSignal` reports "Dangerous file type … was hidden" (−40) for every such file.
- **(R)** Skip the obfuscation signal when the original URL is `blob:` or `data:` (3P Matrix 4.3.3 `isPageMadeDownload`).
- Keep as is.

---

## B. Security and trust boundaries

### 8. Message sender check is too loose
`if (sender.extensionId && sender.extensionId !== chrome.runtime.id) return;` passes when the field is missing.
- **(R)** `if (!sender || sender.id !== chrome.runtime.id) return;`

### 9. The download id comes from the message, not from the sender
`GET_PENDING_CHECK` / `DISMISS_CHECK` trust `msg.downloadId`; any own page can read or dismiss any check (C28).
- **(R)** Read the id from `sender.url` (`?downloadId=`) and refuse senders that are not the warning page.
- Keep (low risk: only own pages can send).

### 10. web_accessible_resources exposes pages and code to every extension
Warning page, util modules and the scoring engine are listed for `chrome-extension://*/*` — own pages do not need it (C34).
- **(R)** Remove the block (windows opened by the extension itself need no WAR).
- Keep, add `"use_dynamic_url": true`.

### 11. innerHTML for the default title and VT counts suffix
Both are own strings today, but one future edit turns them into an injection path.
- **(R)** `textContent` everywhere; build the FP-reduction link with `createElement`.

---

## C. Structure and principles (Xplainer)

### 12. Settings are hard-wired to DS's own storage key
`BrowserProtection` calls `Settings.get()` itself, so a host extension (3P Matrix) must replace `util/Settings.js`.
- **(R) — DECIDED** Pass the settings in: `checkIfUrlIsMalicious(key, url, cb, originalUrl, settings)`.
- A provider hook: `BrowserProtection.setSettingsProvider(fn)`.
- Keep; 3P Matrix keeps its adapter.

### 13. Settings have no schema version (C32)
Stored "Settings" has no `schema` field; future shape changes have no ordered migration.
- **(R)** Add `schema` + one ordered migration list, as 3P Matrix `data/state-storage.js`.
- Keep merge-with-defaults only.

### 14. func-style: arrow helpers (C9a)
`BrowserProtection` (`doVtCheck`) and `FilterDataLoader` use `const f = () =>` for named functions.
- **(R)** Convert to `function` declarations and add ESLint `func-style` to DS's suite.
- Accept and document as an exception.

### 15. Numbers and colours typed in page code (B1 / C39a)
`WarningPage.js`: fallback colour 179/38/30, label length 200, five hex risk colours; the options HTML repeats 30/100/80 and 12.
- **(R)** Move to `APP`/CSS tokens; port 3P Matrix `check-magic-numbers.mjs` and `check-derived-literals.mjs`.
- Fix the obvious ones only.

### 16. Dead code: the "submit URL to VirusTotal again" flow (C39)
`SUBMIT_URL_TO_VT` + `submitAndPollVt()` + the `VT_RESULT_UPDATE` listener have no sender anywhere.
- Wire it: a "Re-check at VirusTotal" button on the warning page.
- **(R)** Remove until it is wanted (3P Matrix did not port it).

### 17. GovSuffixes.default.js ships but is never imported (C20)
It is a build input for the top-sites filter only.
- **(R)** Keep `data/GovSuffixes.json` for the build tool; drop the generated `.default.js` from the extension.
- Use it at runtime (e.g. gov-site exemption in brand checks).

---

## D. Data lists and tools

### 18. Remote list refresh points to files that do not exist yet
`FilterDataLoader` fetches from `raw.githubusercontent.com/Kees1958/uBol-stripped/main/EXTENSION/data` twice a day.
- **(R)** Publish the `data/*.json` files there (or in the DS repo and change the URL + host permission).
- Remove the loader until there is a publishing process.
- Keep (harmless: falls back to the bundled lists).

### 19. Lists have no freshness register (DS_ALIGNMENT §5)
No record of source release, entry count or "rebuilt for minor version" for TopSites, PSL, HostList, Brands —
and, after item 1, the two domain-age lists.
- **(R)** Port 3P Matrix `data-sources.json` + `check-list-freshness.mjs` into DS's suite. **DECIDED for the two
  domain-age lists:** `updateOn: "minor"` (the suite fails on a minor bump until `update-domain-age-lists.mjs` ran).
- Document manually in the CHANGELOG.

### 20. Two builds of the same top-sites filter
DS `build-top-sites-filter.mjs` and 3P Matrix `update-top-sites.mjs` now produce bit-identical output (verified on CrUX 202609).
- **(R)** Keep one implementation in a shared tools folder, used by both projects.
- Keep both; re-verify bits on every rebuild.

### 21. Two implementations of the DoH / RDAP checks
3P Matrix `core/online-checks.js` (sites, 3 s/4 s timeouts) and DS `DnsThreatProtection`/`RdapProtection` (8 s).
- **(R)** One shared module set (DS's), with timeouts as parameters.
- Keep both; align the scoring rules by hand.

---

## E. From 3P Matrix 4.3.1–4.3.3 (improvements made after the port)

### 23. Warning page is large and wordy
Full-width card, big title/buttons; the intro repeats itself and two closing lines add little
("This is what VirusTotal knows …" after VT answered). 3P Matrix 4.3.1 made it compact and shorter.
- **(R)** Port the 4.3.1 layout: card max 600 px, tighter spacing, intro "… an executable or an archive … Review the results.", no VT-known line.
- Only shorten the texts.
- Keep as is.

### 24. No way to block risky downloads, only to warn
DS always lets the file finish. 3P Matrix 4.3.2 added an opt-in block (protection 18, off by default): the file is
cancelled, a small notice offers OK or "Download anyway", which downloads once more and then ALWAYS runs the check.
- **(R)** Add an option "Block risky downloads" (off by default) with that notice; one-time pass per URL (60 s, max 20).
- Block only when the heuristic score is already below a threshold (warn otherwise).
- Keep warn-only.

### 25. AI assistants' own files are checked
Sites that generate files in the page (claude.ai artifacts and zips) trigger the check on every download, although
the user trusts the site. DS's built-in "do not check" list holds only app stores. (3P Matrix 4.3.3 put claude.ai
on its built-in whitelist, which the download check now skips.)
- **(R)** Leave it to the user's trusted domains (DS keeps its "app stores only" rule) — now that blob: files count (item 26).
- Add claude.ai to the built-in list, as 3P Matrix did.

### 26. No tests for page-made (blob:) downloads
DS handles trusted `blob:` hosts correctly (`UrlUtils.getHostname`), but nothing tests it; 3P Matrix's port broke
exactly this (fixed 4.3.3). Item 22's false "hidden extension" also had no test.
- **(R)** Port 3P Matrix's e2e cases: a blob: executable warns without the "hidden" line; a blob: file from a trusted
  domain is not checked. Note: Playwright saves downloads under a random name — use an executable MIME type.
- Unit-test `isTrustedDomain` with a `blob:` URL only.

### 27. The trusted-domains whitelist only looks at the file's own address
`isTrustedDomain` reads the host from the download URL — `blob:https://claude.ai/…` works (verified), but
`data:` files and sandboxed `blob:null/…` files have no host, and a trusted site that serves its files from a
CDN/storage host (another domain) is not matched either. The page the download came from is never consulted.
- **(R)** Match the trusted list against the file host AND the page (`DownloadItem.referrer`, blob/data → page).
- Add a fallback to the referrer only when the file has no host (`data:`, `blob:null`).
- Keep file-host only (documented: add the CDN host to the list yourself).

### 28. A changed DNS choice is lost unless "Save All Settings" is clicked
User report: Cloudflare chosen as first DNS check, later back to Quad9 (DS's default). In DS the dropdowns only
save via the "Save All Settings" button at the bottom — leaving the page without it silently drops the choice.
(Not reproducible in 3P Matrix, which saves each change at once and shows "Saved.".)
- **(R)** Save each setting on change with a status line, as 3P Matrix's Options page does (keep Save All for the rest).
- Warn on leaving the page with unsaved changes (`beforeunload`).
- Keep; move the Save button next to each section.

---

## Summary — recommended order
0. Decided first (DS 3.3.0): items 1, 12 and the domain-age part of 19.
1. Items 1–4, 6–9, 22, 26–28 (small, user-visible or safety, each a few lines; 26 guards 22).
2. Items 12, 16, 17 (cleaner module boundary for 3P Matrix's copy; less dead code).
3. Items 5, 10, 11, 13–15 (UI and principles pass).
4. Items 18–21 (data/tools process, shared with 3P Matrix).
5. Items 23–25 (features and look taken over from 3P Matrix 4.3.1–4.3.3 — your choice per item).
