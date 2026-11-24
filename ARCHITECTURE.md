# 3P Matrix — content firewall

(Docs zip since 5.0.7 — it describes the extension folder; paths below are relative to that folder. The
extension zip ships runtime code and licence files only: tools/package-release.mjs.)

Chrome MV3 extension combining 3P-Matrix-lite (UI, levels, lock level, startup level),
uBlock Stripped Dynamic (privacy & security protections, allow list) and DownloadSentinel 3.5.2
(domain heuristics; since 4.3.0 also its download protection — warnRiskyDownloads). Spec: project doc `claude/SPEC_levels_and_protections.md`.

Load unpacked: `chrome://extensions` → Developer mode → Load unpacked → the extension folder.

## Levels (cumulative)
| L | Third-party content | Protections |
|---|---|---|
| 1 | everything allowed | none |
| 2 | 3P scripts + frames from 445 abused TLDs blocked (blockAbusedTlds) | the "On every site" group (e.g. blockAbusedTlds, blockExfilMessagingBots, blockConsentFix, warnSuspiciousSites, warnRiskyDownloads, warnPasswordForms, warnDeviceCodePages, warnPaymentSkimmer, blockFakeSignInWindow) |
| 3 | 3P scripts + frames blocked except safer regions + built-in whitelist | + the "Outside safer regions" group (blockWasmDubious applies on every site; blockRiskyDownloads off by default) |
| 4 | 3P scripts + frames blocked; built-in whitelist + "cdn" hosts allowed | every group on every site, incl. the "Level 4–5 only" group (3P WebSocket / WebTransport / WebAssembly) |
| 5 | 3P scripts + frames blocked, no exceptions (no whitelist, cdn or Show Matrix allows) | every group on every site |
Tabs (5.1.3): Firewall protection (tab value `browsing`; the only tab with a tick per protection), Download protection,
Scam protection (one switch, enableScamProtection: the bundled scam scripts), Tamper Protection and the Allow list.
Tamper Protection (5.1.0, internally "Tamper Guard") is one switch, watchTamperSensitive ("Enable tamper detection",
from level 2), with four trigger ticks (5.1.3: banking/payment pages, a password/card field hidden as a trick,
checkout words, locked pages) and the same slider: 3 also pages with a tampering sign, 4–5 every page (TAMPER_LEVEL); level 1 /
"All:" on the allow list: off. warnPasswordForms, warnPaymentSkimmer, blockFakeSignInWindow and (5.1.3)
blockObfuscatedEval run under that switch (switchable: false). 5.1.3: a page gets a RISK RATING from the points of its
findings (× 1.5 on banking/payment pages): Critical/High warn in one window per page, Suspicious by level and safer
regions (else only "?" on the toolbar badge), Low never. The password-form, skimmer and fake sign-in warnings keep
their own warning and are also 100-point findings (rules with `ownWarning`): they count in the rating, the popup's
"This page" box and any open tamper window, but never open a tamper window themselves (warnRating leaves them out).
Toolbar badge (5.1.3, owner 2026-11-24): the highest problem wins, one symbol — "!" dangerous site or High/Critical
tamper rating, "?" suspicious site or Suspicious tamper rating — else Chrome's own count of the requests our rules
blocked (displayActionCountAsBadgeText: allow rules not counted, other extensions not counted, no listener, no extra
permission). Per-tab text overrules the count; null hands it back. Chrome clears per-tab badge values on navigation:
Badge.resetPage forgets what was shown and redraws. The popup's "This page" box shows the site risk, the tamper rating (Details reopens the
window) and "Firewall blocked N requests on this page" from declarativeNetRequest.getMatchedRules (activeTab).
Since 4.2.0 no level ever blocks third-party images, video, fonts or stylesheets.
Default startup level: 2. The safer-regions TLD list only has an effect at level 3
(data/constants.js `SAFER_REGIONS_LEVELS`); the popup shows its editor only there. Its country codes are
added with the fixed Continent scope, as in uBlock Stripped Dynamic (`SAFER_REGIONS_AUTO_MODE`; no slider).

## Hard constraints
- **HARD CONSTRAINT (C25, 5.0.7) — name a protection by its key, never by its display number.** In code,
  comments, tests and this README write `blockRiskyDownloads`, not its number in the settings list. Display
  numbers follow the position in the settings list and change whenever a protection is added, removed or moved;
  every renumbering from 4.2 to 5.0.6 left typed numbers behind that described the wrong protection. Numbers the
  user sees are derived at render time (`ui/derived-text.js`, C39a). Proven mechanisms: the registry's `key`
  (storage contract, never renamed) and `PROTECTIONS_IN_DISPLAY_ORDER` (the one display order, which `num` must
  match). Guarded by `tools/check-protection-refs.mjs` and `tools/check-protection-keys.mjs`. Only
  `data/protections.js` (the registry and its renumbering history) and the changelogs keep numbers.
- **HARD CONSTRAINT (C47, 5.0.7) — page scripts listen on `window`, capture phase, registered at
  `document_start`; never on `document`, never later.** A page's own window-capture listener runs before a
  document listener and can stop the event (5.0.6 shipped the ClickFix and skimmer bridges on `document`; a page
  could silence both warnings). Guarded by `tools/test-message-gate.mjs` (classified allowlist) and the
  page-scam cases in `tools/e2e-page-protections.mjs`.
- **The extension zip ships runtime code and licence files only** — declared and guarded in
  `tools/package-release.mjs` (5.0.7).

## Threat model (C49, 5.0.7)
What 3P Matrix protects: the user's sign-ins, payment data and device against hostile pages and downloads, and
its own settings against tampering. It keeps no browsing history and sends nothing anywhere except the optional
VirusTotal and DNS lookups the user turned on.

| Attacker | Can reach | Main risk | Stopped by |
|---|---|---|---|
| A hostile web page | the DOM, events, its own scripts and frames; it runs next to our page scripts | silencing or faking a warning; calling extension handlers through a content script | message gate (C46): page scripts may send 4 message types only; page scripts listen on `window`, capture, at `document_start` (C47); warnings open on the extension's own page, never drawn into the site (C47); `isTrusted` on every in-page decision |
| A compromised third-party script on a good site | same as a hostile page, on a trusted site | skimming, exfiltration | network rules (DNR) before the request leaves; the skimmer and exfiltration checks |
| A downloaded file | the user, once opened | malware | download check and block (warnRiskyDownloads, blockRiskyDownloads), VirusTotal |
| A filter rule, another extension or a page script that replaces built-ins (5.1.0) | the page's JavaScript realm, before or after our document_start script | data quietly edited (json-edit), passwords or card numbers sent elsewhere, forms redirected | Tamper Guard: original descriptors saved at document_start, outer wrappers on armed pages; the page script only REPORTS (bounded, names and hosts only), the service worker decides (C46); the warning is an extension window (C47). Gap: a script that ran before ours is part of the baseline |
| A card skimmer on a checkout (5.1.2 additions) | the shop's page | card number sent in an image/script/frame/link address, a fake card form beside the provider's frame, a script from a look-alike host | address setters + setAttribute checked like requests; card numbers also by value (Luhn); tgSecondCardForm and tgSuspiciousScript derived/scored in the service worker (local site check + provider imitation, no network). Gaps: elements inserted as HTML text, CSS url(), encrypted sends |
| A page faking Tamper Guard reports (5.1.0) | its own report events | a warning about itself, or flooding | reports validated against data/tamper-rules.js; at most 40 per page; dynamic reports only on armed pages; 5.1.3: one window per page (findings only raise its rating — a page faking them only rates itself higher) |
| A settings or allow-list file the user imports | the options page and service worker | stall the extension; prototype or type confusion | size checked before reading (C50); `fromSettingsFile` + `normalizeState` (fuzzed, C51) |
| A tampered list source at build time | shipped data | wrong blocks or trusts | `data-sources.json` provenance, list-freshness and whitelist checks; list rules that DNR cannot express fail the build |
| Another extension | nothing: no `externally_connectable`, no web-accessible resources | — | manifest (C19) |
| The release pipeline | the store package | a malicious or broken release | release declaration and guard (`tools/package-release.mjs`), recorded hashes, permission comparison with the last release (C36) |

**Fail-safe direction.** A check that cannot run fails OPEN only where the user would otherwise lose a normal
action (the password-form check sends the form when the service worker does not answer). Therefore no limit may
be placed where a refusal would make such a check fail open; a page could then bypass the warning by making
its message large (C50).

## Platform
Manifest minimum: Chrome 120. The real-browser tests are pinned to Chromium 129 (Playwright 1.47.2); 5.0.7 was
also verified on Chromium 153. Nothing below Chrome 129 is tested automatically — features that need a newer
Chrome are named where they are used (e.g. `.wasm` matched by address because content-type matching needs 128).

## Layout
```
manifest.json
background.js            lifecycle, event listeners, thin message router (input checks + delegation only)
data/
  constants.js           EVERY switch, ID, priority, score, threshold, colour, timeout, storage key
  protections.js         registry of the selectable protections, their groups and display order (single source of truth)
  tamper-rules.js        5.1.0 THE Tamper Guard rules table: layer, points (5.1.3), texts, watched built-ins (single source;
                         the page script's copy is checked by tools/test-tamper-guard.mjs)
  exfil-channels.js      4.6.0: where phishing pages send stolen data (Telegram bots, Discord/Slack webhooks; form-mail,
                         Power Automate) — the one table behind blockExfilMessagingBots and blockExfilWebServices
  allow-categories.js    5.1.3: the allow-list categories (All, Download, Firewall, Scam, Tamper) and the tab each covers
  state-storage.js       state schema, normalizeState() validation, storage, withStateLock() guard
  message-types.js       runtime message names
  builtin-domains.js     built-in whitelist: 12 categories, one [host, type, reason] row per entry (4.5.6 review;
                         removed hosts kept in BUILTIN_REMOVED); also exempts the outside-safer-regions group (blockRiskyDownloads: the page, at level 3).
                         Checked by tools/check-whitelist.mjs, exported as JSON by tools/export-whitelist.mjs
                         on a first-party visit, at levels 3–4 only; its payment hosts
                         (BUILTIN_PAYMENT) are also exempt from blockPaymentHandlers there
  spam-tlds.js           GENERATED — HaGeZi abused TLDs (tools/build-spam-tlds.mjs)
  suspicious-hosting.js  DDNS / free-hosting domains (blockSuspicious3p)
  network-data.js        high-risk sites, local-network patterns
  tld-constants.js, country-data.js   safer-regions (TLD whitelist) tables from 3P-Matrix-lite
core/
  policy.js              pure: effective level, active protections, rule groups
  rule-builder.js        pure: state → dynamic DNR rules
  script-builder.js      pure: state → content-script registrations
  apply-manager.js       the only module that writes rules/scripts to Chrome (serialized, regex-validated)
  site-scorer.js         stage 1: local heuristics (DownloadSentinel modules)
  online-checks.js       stage 2: RDAP domain age + two DoH threat-intel resolvers, two of five (timeouts, cache)
  site-locks.js          lock / unlock / allow list (pure; 5.1.3: "Category: domain" lines — All = locked at level 1,
                         Download = trusted download hosts, Firewall/Scam/Tamper = state.allowCategories)
  matrix-overrides.js    Show Matrix overrides — set / clear, always global (pure)
  matrix-windows.js      Show Matrix panel windows — open, focus, close with tab/timeout
  view-models.js         the data each page receives (popup, Show Matrix, options)
  navigation-guard.js    warnSuspiciousSites: top-level navigation check → warning dialog; "continue once"
  exfil-guard.js         blockExfilMessagingBots/blockExfilWebServices (4.6.0): a blocked exfiltration request opens the warning dialog with its channel
  tamper-guard.js        5.1.0 Tamper Guard decisions: per-tab state machine (standby/enhanced/cooldown), banking/payment
                         recognition, trigger ticks, report validation, destination checks, 5.1.3 risk score/rating
                         and warn decision (collect delay, quiet mark sink)
  tamper-warnings.js     5.1.0 its warning windows (ui/tamper-warning.html; 5.1.3: one per page, updated in place)
  leave-site.js          4.6.0: "Go back" that leaves the site (steps back until another website; keeps no history)
  password-form.js       warnPasswordForms (4.6.0): pure decision — does this password form send to another site?
  download-guard.js      warnRiskyDownloads: finished-download check (DownloadSentinel background logic) → warning window;
                         blockRiskyDownloads: risky download held (paused) → notice (OK deletes / Download anyway continues → check);
                         level 3 exempts built-in-whitelist pages and trusted download hosts, levels 4–5 nothing
  download-gesture.js    5.1.3: "started without a click" — asks the download's referrer tab once (scripting); asked at
                         EVERY download start the download protection applies to, kept with the download (download-guard
                         _clicks, released with it) so late entries get it too
  download-settings.js   warnRiskyDownloads policy (pure): active per site, trusted download hosts, settings view, edits
  badge.js               per-tab symbol (worst of site risk and tamper rating) + colour, level icon; otherwise Chrome's own
                         block count (displayActionCountAsBadgeText — no listener of ours)
  rule-matcher.js        replays DNR matching on our own rules → the exfiltration warning only fires for 3P Matrix's blocks
  connection-matrix.js   Show Matrix: per-tab observation of third-party connections
  matrix-disposition.js  Show Matrix: per-row policy decision (script/frame, level mode, whitelist)
  tab-sites.js           per-tab top-level host — stand-in for opaque ("null") initiators
  safer-regions.js, tld-engine.js   safer-regions computation (3P-Matrix-lite engine)
security/                content scripts (MAIN world) — uBlock Stripped Dynamic 10.2.1; 5.1.3: scam-guard-page.js (MAIN)
                         + scam-guard-bridge.js (ISOLATED) bundle Scam protection, sec-no-eval-strict.js (level 5); 4.6.0:
                         sec-browser-locker.js (3), sec-form-submit-hook.js + password-form-guard.js (14, the
                         guard runs in the ISOLATED world), sec-notification-prompts.js (18); 5.1.0:
                         tamper-guard-page.js (MAIN: baseline + outer wrappers) + tamper-guard-bridge.js (ISOLATED:
                         hello, payment signals, report forwarding, one bounded MutationObserver on armed pages)
lib/downloadsentinel/    DownloadSentinel 3.5.2 protection/ + util/ modules (4.5.4: the util/ list wrappers + their
                         *.default.js lists are 3P Matrix's — precompiled JSON strings parsed on first lookup,
                         util/LazyJson.js; every list rebuilt by a tool below; otherwise no 3P Matrix patch;
                         its Settings/Storage/MessageTypes are not vendored — settings are passed in from
                         state.downloads). util/DomainAge.js = the domain-age skip rule for site AND download
                         checks; its lists PlatformSuffixes / RdapCctlds are rebuilt by tools/update-domain-age-lists.mjs
ui/                      popup, warning dialog, options page, download warning page, VirusTotal-key prompt
  derived-text.js        every level / protection number / count / threshold a page shows, derived from
                         constants + registry (C39a; HTML uses data-derived placeholders)
util/domain.js           hostname helpers (one registered-domain function, PSL-based)
ui/status-line.js        the one way pages show an action's outcome ("Saved." / "Not saved: …")
LICENSE.txt, THIRD_PARTY_LICENSES.md   GPLv3 + third-party notices (4.3.0)

Tools (separate 3P-Matrix-tools folder, next to this one; npm install there first):
  npm run check            the full check suite (complete-check.mjs) — run before every release
  build-spam-tlds.mjs      regenerates data/spam-tlds.js from spam-tlds-ublock.txt (--check: verify only)
  Every shipped data list has its rebuild tool HERE and a data-sources.json entry (4.5.4 — npm run check
  fails on an unregistered list, a stale minor-release list, or a list whose count drifted). Shared format
  and raw-file cache: list-modules.mjs, lists-raw/ (--fetch re-downloads).
  update-top-sites.mjs     top-sites filter (CrUX top 100,000 + brand websites + GovSuffixes) — per minor release
  update-psl.mjs           Public Suffix List — per minor release; then update-domain-age-lists.mjs (same snapshot)
  update-domain-age-lists.mjs  PlatformSuffixes (PSL private section) + RdapCctlds (IANA) — per minor release
  rebuild-host-list.mjs    HostList (HaGeZi DynDNS + Badware Hoster + Kees1958) — per minor release
  gen-brands-data.mjs      Brands + GovSuffixes (curated tables in the script)
  build-curated-lists.mjs  SuspiciousDomains, SuspiciousTlds, RiskyHostingSites, UrlShorteners (lists-src/*.json)
  package-release-state.mjs  writes package-release-state.json when packaging
```

## Rule groups
Rules are built per *group*, not per site: group 0 = global level (excludes every locked
site), groups 1–5 = all sites locked at that level. Rule id = 10000 × group + local id
(`RULE_LOCAL_ID` in constants). The rule count stays the same however many sites are locked.

## Show Matrix (0.2.0; global overrides since 4.1.0; 3P-Matrix-lite layout and model since 4.2.1)
Popup → Show Matrix opens a panel window for the current tab, reloads the tab and lists every
third-party domain it contacts (a "cdn" subdomain of a non-cdn domain, or a host that is itself a
built-in entry, gets its own row). Columns, as in 3P-Matrix-lite 4.0.2: Internal whitelist ·
Level mode · image · media · stylesheet · SCRIPT · FRAME · fetch/xhr · other · requests.
SCRIPT / FRAME show the policy's real decision (green allow, red block), replayed through the
rules Chrome has (core/matrix-disposition.js + core/rule-matcher.js) — not what was observed.
Level mode = the level's own rules without built-in allows or overrides (grey when something
else decides). Click a SCRIPT/FRAME square: set the opposite as an override; click again: clear.
An override always applies on every site, as in uMatrix / 3P-Matrix-lite (matrixRules key
`MATRIX_SITE_ALL = "*"`). Per-site keys from 0.2.x are merged into the global list on load (4.2.3).
Overrides outrank every level/security rule; only the L5 code block beats them. Stored in
state.matrixRules, DNR ids 900000+ (core/connection-matrix.js, core/matrix-disposition.js,
core/rule-builder.js buildMatrixRules, ui/matrix.*, priority data/constants.js PRIORITY.MATRIX).

## Download protection (warnRiskyDownloads, 4.3.0)
DownloadSentinel 3.5.2 with all its options: a finished executable/script/archive download is checked (URL +
filename heuristics, staging/MIME checks, RDAP, the two DNS checks of Options, optional VirusTotal with FP
reduction) and a maximized warning window shows the result (personalizable colour/title). "Silent when probably
safe", trusted download domains (+ built-in app stores), startup VirusTotal-key nudge. The download's site is the
page it came from: allow-list sites get no download warnings. Settings live in state.downloads (no backup of the
VirusTotal key). Permissions added: downloads, alarms.

## Not in this prototype
- Remote list updates (HaGeZi, DownloadSentinel lists) — DS 3.3.0 removed its FilterDataLoader; bundled lists only.

## Sources & licences
Copyright (C) 2026 Kees1958 and co-authors. Licence: GPLv3 (`LICENSE.txt`); every bundled component and its licence: `THIRD_PARTY_LICENSES.md`.
- 3P-Matrix-lite 4.0.2, uBlock Stripped Dynamic 10.2.1 (GPLv3, based on uBlock Origin Lite),
  DownloadSentinel 3.5.2 — Kees1958 and co-authors.
- HaGeZi DNS blocklists — "Most Abused TLDs" (level-2+ TLD block, `data/spam-tlds.js`) and "DynDNS" + "Badware
  Hoster" (site-visit/download risk score only, via DownloadSentinel's `HostList.default.js`) — see
  github.com/hagezi/dns-blocklists for licence.
- Kees1958 "Suspicious websites" — used twice: a hard block for blockSuspicious3p (`data/suspicious-hosting.js`,
  3P Matrix's own snapshot) and, separately, a risk score merged into the same `HostList.default.js` above
  (DownloadSentinel's snapshot) — see github.com/Kees1958/W3C_annual_most_used_survey_blocklist.
