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

## 5.1.10
Compare at 5.1.9. Changed zips: extension, tools, docs. Ported from Safe Surfing Sentinel 1.0.1→1.0.2.

- **Owner decision 2026-11-26: domain-reputation lists no longer drive hard blocks, only risk scores.**
  A domain-list hit names a shared platform (a DDNS provider, a free host), not something about the
  specific request being made — so it stays a signal for core/site-scorer.js and
  lib/downloadsentinel/util/HostList.js, never an outright DNR block. Two rules removed from
  core/rule-builder.js: ID.SUSP_HOSTING (the blockSuspicious3p hard block on
  data/suspicious-hosting.js's DDNS/free-hosting list) and ID.WASM_DUBIOUS_HOST (the same list's
  narrower WebAssembly-only hard block). ID.SUSP_HOSTING_REGEX (byethost* pattern-match block, not
  list-driven) and ID.WASM_DUBIOUS_TLD / ID.WASM_OUTSIDE_SAFER (TLD/region-driven, not list-driven) are
  structural signals and unaffected. data/suspicious-hosting.js now has zero remaining code consumers in
  this repo — left in place and flagged to the owner rather than deleted, since removing it touches
  tools/data-sources.json, tools/check-magic-numbers.mjs, tools/e2e-worker-blocks.mjs's fixtures, and
  several docs; a bigger cleanup than this redesign asked for.
- **data/constants.js: USUAL_PORTS (renamed from STANDARD_PORTS) is now [443, 8443], not
  [80, 443, 8080, 8443].** NON_STANDARD_PORT_REGEX's hand-built RE2 digit-exclusion trie was still
  excluding 80/8080 from the ":<port>" unusual-port block — stale relative to that rename. Rewritten to
  exclude only 443/8443. core/site-scorer.js's own STANDARD_PORTS references renamed to USUAL_PORTS to
  match (single source of truth, no behavior change there).
- **data/protections.js: BLOCK_SUSPICIOUS_3P and BLOCK_WASM_DUBIOUS labels/descriptions updated** to drop
  "DDNS hosts" / "dubious host" wording now that those hard blocks are gone (BLOCK_WASM_DUBIOUS now says
  "abused TLDs" instead, matching what it actually still blocks by TLD).
- **Consistency fix (found during this port): data/suspicious-hosting.js's own header comment** still
  claimed ID.WASM_DUBIOUS_HOST as "the one remaining consumer" after that rule was removed, contradicting
  core/rule-builder.js's own comment on the same change. Rewritten to state the file has zero remaining
  code consumers, matching reality.

**tools 5.1.10:** tools/e2e-worker-blocks.mjs — removed the HOST.DUBIOUS fixture and its
"blockWasmDubious: 3P WebAssembly from a dubious host" case (asserted the exact behavior just removed;
caught by consumer-inventory sweep before it could cause a false CI failure). complete-check.mjs re-run
(e2e-* skipped, sandbox cannot reach Playwright's browser-download CDN): 33 passed, 0 failed, 5 skipped.

## 5.1.9
Compare at 5.1.8. Changed zips: extension, tools, docs.

- **Dialog loop window (owner, GitHub README editor false alarm 2026-11-25):** security/scam-guard-page.js alert and
  dialog parts counted DIALOG_SPAM_MIN dialogs over the page's whole life (GitHub is a single-page app, so its
  "discard changes?" confirms added up). Now countDialog(): the last DIALOG_SPAM_MIN times (performance.now, bounded
  array, released after the sign), a loop only within DIALOG_LOOP_WINDOW_MS = 1000; sign sent once per page.
  check-shipped-terms keeps DIALOG_LOOP_WINDOW_MS equal in both parts.

**tools 5.1.9:** e2e-page-protections /slow-dialogs (3 confirms 700 ms apart → no warning page; fails on 5.1.8,
passes on 5.1.9); check-shipped-terms + DIALOG_LOOP_WINDOW_MS.

## 5.1.8
Compare at 5.1.7. Extension zip only (owner; not on GitHub yet — GitHub main is 5.1.6).

- **CNN confirmed (owner, 2026-11-25 07:28):** on 5.1.7 the SW console showed no "Tamper debug:" line on cnn.com —
  no payment signal, nothing armed. Cause: Stripe's 1905×1 m-outer frame holds a normal-sized inner frame
  (m.stripe.network, Payment list) that the bridge in m-outer reported; fixed in 5.1.7 (frameSeen gates inner frames).
  The lab /nest case does not reproduce this on 5.1.6 (Chrome's real hidden-frame behaviour differs) — keep it as a
  guard anyway.
- **TAMPER_DEBUG_LOG = false** (kept as a switch for the next diagnosis).

**tools 5.1.8:** no tool changes (version recorded, B4).

## 5.1.7
Compare at 5.1.6. Extension zip only (owner: diagnostic build, not on GitHub).

- **TAMPER_DEBUG_LOG (temporary, data/constants.js):** core/tamper-guard.js debugLog() — payment signals (page, reporting
  frame, frameSeen, frames, payFrames, card, bank), known payment site, and arm() (armedBy, reasons). Hosts only, SW
  console only. To find why cnn.com still arms on 5.1.6 (the top page no longer reports Stripe's 1905×1 hidden frame).
- **Bridge:** a frame that cannot be seen (frameSeen false) reports no frames inside it. e2e /nest case passes, but it
  also passed on 5.1.6 — so not proven to be the CNN cause.

**tools 5.1.7:** e2e-tamper-guard /nest (a normal-sized frame inside the hidden payment frame).

## 5.1.6
Compare at 5.1.5. Changed zips: extension, tools, docs.

- **Hidden payment frames (owner, CNN report 2026-11-25):** CNN armed close watching via REASON.PAYMENT_FRAME — the
  only js.stripe.com frame was Stripe's metrics controller (m-outer, 1 px high, visibility hidden). tamper-guard-bridge.js
  now reports only frames that pass seen() and sends `frameSeen` (this frame's own viewport > INVISIBLE_MAX_PX); core/
  tamper-guard.js counts the reporting frame's own Payment-list host only when frameSeen. Cost: one checkVisibility +
  getBoundingClientRect per frame at the three existing signal moments; fewer pages armed.
- **Scam list order (owner):** data/protections.js SCAM_LIST_ORDER, used by ui/protections.js renderScamRules.
- **Download tab side by side (owner):** ui/protections.js SIDE_BY_SIDE_TABS → .prot-col.prot-row.

**tools 5.1.6:** test-tamper-guard (frameSeen false/true), e2e-tamper-guard (/article-hidden-pay, /article-pay — browser
run passed during development; the release used quick checks only, owner's choice).

## 5.1.5
Compare at 5.1.4. Changed zips: extension, tools, docs. (5.1.4 was zipped and merged to GitHub main.)

- **Password-form guard (user report, Ziggo GO, "Form submission canceled because the form is not connected" at
  security/password-form-guard.js:70):** every password form was held (preventDefault + stopImmediatePropagation)
  until the service worker answered, then re-sent with requestSubmit — a single-page app that re-rendered meanwhile
  had removed the form. Now a form whose destination host = the page's host is never held (sameHost, in the guard and
  in security/sec-form-submit-hook.js for form.submit()); core/password-form.js could not warn there anyway. A held
  form that is no longer connected is not re-sent. e2e-page-protections + an SPA sign-in case (passes on 5.1.3 code too:
  the original race needs a slow, sleeping service worker).
- **Support-scam signs → warning page (owner, 2026-11-24):** security/scam-guard-page.js reports the first sign
  (DIALOG_SPAM_MIN dialogs, keyboard lock, fullscreen re-entry) as LOCKER_SIGN_EVENT; scam-guard-bridge.js sends
  MSG_PAGE_SCAM_BLOCKED kind browserLocker once (data/page-scam-reasons.js BROWSER_LOCKER, leave NEW_TAB). "Leave
  site?" is blocked only after a sign (BeforeUnloadEvent.prototype.preventDefault, returnValue, onbeforeunload) —
  a page's prompt blocks chrome.tabs.update/remove, so it must go first. Typing detector removed.
- **Mac-only Script Editor check:** security/scam-guard-mac.js (ENABLE_SCAM_PROTECTION.macScripts); script-builder
  takes { os }, apply-manager caches chrome.runtime.getPlatformInfo().os.
- **Popup per-tab lines:** core/policy.js protectionCounts; Download = tab protections + DNS slots on + heuristics +
  VirusTotal with a key (DOWNLOAD_CHECK_COUNT, max 6). test-allow-list section P.
- **XSS texts (owner):** tgAddressScript label "Cross-site scripting (XSS)" + plain description; warnXssLinks label
  "Warn about links with hidden code (XSS)", description, and the xssLink warning intro/signal (title kept). XSS stays
  under Scam (owner, after discussion).

**tools 5.1.5:** e2e-page-protections — support-scam warning page, Leave-site only after a sign, SPA sign-in form;
test-allow-list section P (download count, mac-only script); check-shipped-terms + LOCKER_SIGN_EVENT, DIALOG_SPAM_MIN,
CLICKFIX_BLOCKED_EVENT.

## 5.1.4
Compare at 5.1.3. Changed zips: extension, tools, docs. (5.1.3 was zipped and merged to GitHub main, not uploaded to
the Chrome Web Store; owner asked for a bump.)

- **tgSeedSent (owner, 2026-11-24 night):** data/constants.js TAMPER_SEED (word counts 12/15/18/21/24, words of 3–8
  lower-case letters — the BIP-39 shape —, MATCH_WORDS 8, FIELDS_MAX 40); security/tamper-guard-page.js copy (SEED,
  SEED_WORD_RE; test-tamper-guard checks both). seedPhrases(): a field (text input, password input or TEXTAREA — new
  captured getter HTMLTextAreaElement.prototype.value) holding a whole phrase, or a run of ≥ 12 adjacent fields with one
  word each (MetaMask-style boxes). checkOutgoing: letters-only text (as sent and URL-decoded) must contain the first
  MATCH_WORDS words joined → report tgSeedSent (100 points, label "Recovery phrase copied to another site"). A typed
  phrase also starts the outgoing check (holdsSecret / anySecretOnPage). Service worker: only the page's own site is
  exempt (no provider ever needs a seed). Bridge PAGE_RULES copy + tgSeedSent. TAMPER_LABEL_MAX_CHARS 36 → 38 (fits:
  measured to 51). Not browser-tested in this release (owner: quick checks only) — add an e2e case next time.
- **"www-" site names (owner, 2026-11-24 night; URLhaus first page: 98 of 100 blocked or warned, the miss was
  www-featherwallet.com):** lib/downloadsentinel/protection/SketchyUrlCheck.js check 7 — the REGISTERED domain starts
  with "www-" → SCORES.WWW_DASH_DOMAIN 90 (site: −31, suspicious on its own; download: the same SketchyUrl input).
  Subdomains ("www-01.ibm.com") never match; *.translate.goog (Google Translate's proxy) exempt. CrUX top 1M:
  137 hits, 47 of them translate.goog, the other 90 mostly copy-cat download/piracy sites. NOTE: this file is shared
  DownloadSentinel code — DownloadSentinel itself needs the same change (parity).
- **Crypto trigger words (owner, same night):** data/constants.js TAMPER_CRYPTO_WORDS / TAMPER_CRYPTO_ENDINGS under the
  checkout-words tick; core/tamper-guard.js hasAddressWord also matches them in the site's own name (siteNameTokens),
  unlike the checkout words. Left out on purpose: eth, ledger, exodus, phantom, seed, swap, coin.

## 5.1.3
Compare at 5.1.2. Changed zips: extension, tools, docs.

Owner decisions 2026-11-24 (restructure in five steps; nothing released since 5.0.8, so 5.1.x numbering).

- **Tabs (data/protections.js):** PROTECTION_TAB gains SCAM; order BROWSING ("Firewall protection" — the value
  `browsing` kept as contract), DOWNLOAD, SCAM, TAMPER. Only BROWSING is numbered (13 rows; header note maps old →
  new numbers). Scam and Tamper are bundles: members are `switchable: false` + `requires` the switch.
- **Scam protection:** ENABLE_SCAM_PROTECTION owns security/scam-guard-page.js (MAIN: alert/dialog buster,
  browser-locker, ClickFix clipboard, notification prompts — now every site from L2 —, payment and protocol handlers)
  and security/scam-guard-bridge.js (ISOLATED: ClickFix bridge, ConsentFix paste guard, never-share codes). The old
  separate files are deleted. blockRedirectsDialogs keeps L3 outside safer regions. Never-share codes
  (BLOCK_SHARED_CODES): a paste of 4–8 digits or a recovery code into a TEXTAREA/contenteditable → page-scam warning
  kind sharedCode.
- **Obfuscated code under Tamper:** blockObfuscatedEval tab TAMPER, requires the switch; L3 outside safer regions,
  L4 everywhere; `strictScripts` security/sec-no-eval-strict.js from LEVEL.STRICT (every eval blocked; script-builder
  strictRegistrationsFor, id suffix "-strict"). High-risk (adult) eval handling and HDR_HIGH_RISK removed. A block
  dispatches `3pmcf-tg-obfuscated` (detail = entry point); tamper-guard-bridge.js forwards it once per entry point as
  tgObfuscatedCode (40 points; at L3+ a tampering sign that arms).
- **Removed:** BLOCK_HIGH_RISK_EVAL, BLOCK_SENSORS_NFC (motion sensors moved into PP_VALUE.SECURITY), sec-nfc.js,
  sec-no-webtransport.js (WebTransport = DNR only), sec-adult-noeval.js, core/tamper-exceptions.js and the never-warn
  list (state.tamper, MSG_SET_TAMPER_EXCEPTIONS, TAMPER_EXCEPTIONS_CAP).
- **Allow list categories (data/allow-categories.js, core/site-locks.js):** "Category: domain" lines; All →
  level-1 locks; Download → downloads.trustedDomains (host kept); Firewall/Scam/Tamper → state.allowCategories
  (registeredDomain, deduped, ALLOW_CATEGORY_CAP). parseAllowListText returns {entries, errors}; MSG_SET_ALLOW_LIST
  refuses to save with errors named. Firewall = option A: every Firewall DNR rule gets the sites as excluded request
  (main_frame-only rules) or initiator domains (rule-builder withAllowExclusions); SCAM_HEADER_IDS (frame CSP sandbox)
  take the Scam sites. Script registrations get the category's sites in excludeMatches (script-builder
  categoryAllowed). UI: search, match count, "Delete all for this domain".
- **"Always allow" / "Always ignore"** in every warning → addToAllowList with the category of the reason's tab and
  the site per `allow.from` (data/page-scam-reasons.js ALLOW_FROM: target site, sending site, page site; downloads:
  the file host — download-guard allowHostFor). downloads.trustAppStores (default true) replaces the editable list.
- **Tamper risk rating (data/constants.js TAMPER_RATING*, data/tamper-rules.js `points`):** rule `severity`,
  `listLabel`, TAMPER_WARN_MIN, TAMPER_CORRELATION_MIN, TAMPER_SEVERITY(_LABEL/_GROUP_TITLE) removed. Page score = sum
  of distinct findings' points, × TAMPER_SENSITIVE_FACTOR (1.5) on a sensitive page; ratings at 30/60/100. Warn
  rule (core/tamper-guard.js evaluate): CRITICAL/HIGH always on an armed page; SUSPICIOUS from
  TAMPER_SUSPICIOUS_WARN.ALWAYS_FROM (L4), at L3 only outside safer regions (policy isInSaferRegions), else the quiet
  mark (badge BADGE_TAMPER_SUFFIX "•", Badge.setTamperMark via Tamper.setMarkSink, cleared by resetCount); "Tamper:
  site" → outcome EXCEPTION. Findings are always recorded and counted when the page is armed (pending/quiet lists
  gone). Static sign / many-hooks counting by TAMPER_SIGN_POINTS_MIN (20).
- **One window per page (core/tamper-warnings.js showWarning):** findings within TAMPER_COLLECT_MS (2 s) collected
  (per-page timer, cleared on navigation/release, page sequence guard); CRITICAL opens at once; an open window is
  updated (record replaced, MSG_TAMPER_WARNING_CHANGED {id} → the window refetches; never restarts its countdown;
  stops it when the rating became critical); a closed window reopens only for a higher rating (rec.shownRating).
  Window: fixed title, rating chip, summary with score, the signal list (description + points as tooltip).
- **Trigger ticks:** TAMPER_ON_SENSITIVE, TAMPER_ON_HIDDEN_FIELD, TAMPER_ON_CHECKOUT_WORDS, TAMPER_ON_LOCKED_PAGES
  (MECH.TAMPER, require the switch, default on). Hidden field: the bridge's signal check (DOMContentLoaded, load,
  +3 s; at most HIDDEN_FIELDS_MAX measured) sends `hidden` → finding tgHiddenCredential + ARMED_BY.HIDDEN_FIELD; no
  observer on unarmed pages. Locked: lockedLevelOf > ALLOW_ALL → ARMED_BY.LOCKED. Master renamed "Enable tamper
  detection"; group title "Choose how tamper detection heuristics works".
- **tgIbanSent (60):** security/tamper-guard-page.js checkOutgoing also collects IBANs (fields named iban, or typed
  values passing ISO 13616 MOD-97, compacted lower case) and looks for them in the compacted address/body as sent
  and URL-decoded; destination rules as for card numbers (payment providers exempt). Constants TAMPER_IBAN.
- **blockRedirectsDialogs frames only (owner, option 1):** the top-page sandbox rule HDR_CSP_MAIN (102) is retired and
  HDR_HIGH_RISK_CSP_SANDBOX is limited to sub_frame. A sandbox without allow-modals on the TOP page made Chrome drop
  its beforeunload prompt, print() and alert/confirm/prompt, and its popups inherited the sandbox (no
  allow-popups-to-escape-sandbox). Frame redirects stay blocked by the frame rule; top-page dialog spam is Scam
  protection's dialog part (L2+). e2e-page-protections: the leave-prompt cases run at level 3 again.
- **Download "Download started without a click on the page" (core/download-gesture.js):** at onCreated the tab whose URL
  equals the referrer is asked once via scripting.executeScript for navigator.userActivation.isActive (no content
  script stays; ≤ DOWNLOAD_GESTURE.TIMEOUT_MS, ≤ TABS_MAX tabs). No click → withNoClickSignal adds
  SCORE.DOWNLOAD_NO_CLICK (−15) to both host verdicts (headline rebuilt; hard-rule verdicts keep their score); kept on
  the completion re-check. (Issue 6 below: now asked at every download start and kept for late entries.)

- **Bug (user report, screenshot from Brave):** "Uncaught (in promise) TypeError: Failed to fetch" on a site, listed
  under 3P Matrix at security/sec-no-wasm.js:117 (`reflectApply(_nativeFetch, this, args)`). 5.0.7's fix (return the
  browser's own promise, tag on a side branch) was incomplete: the browser files an error under the script of the
  JavaScript frame that CALLED the native function that created it, and any fetch wrapper is that frame. So
  blockWebAssembly no longer wraps fetch or XMLHttpRequest.open: Response.prototype.arrayBuffer() tags by the
  response's own native `url` (after redirects; empty = page-made = same-origin), the XHR `response` getter by the
  native `responseURL`. Same behaviour, fewer wrappers. Remaining frame of ours: a failing BODY read (rare).
  `wrappedBy` in the tamper rules table shrinks to the XHR response getter.
- **Warning countdown 20 s** (owner requests: first 10, then 20): TAMPER_COUNTDOWN_S 5 → 20 — a non-critical tamper
  warning now stays 20 seconds before closing itself (critical ones still never do). The window's text reads the
  constant.
- **Same class, not changed yet (owner to decide):** Tamper Protection's outgoing-data check wraps fetch on armed
  pages (payment pages; every page at levels 4–5), so a failing site fetch there is filed under tamper-guard-page.js.
- **Tests:** test-wasm-wrappers.mjs rewritten (fetch and XHR open untouched; arrayBuffer native promise, ordering,
  cross-origin/same-origin/page-made buffers, XHR responseURL, no own unhandled rejection); test-tamper-guard.mjs's
  wrappedBy case follows the new target.

### 5.1.3 issue round (owner decisions 2026-11-24 afternoon)
1. **Badge symbols only, no background counting (core/badge.js, background.js, ui/popup.js, core/view-models.js):**
   the all-URL webRequest.onErrorOccurred listener and the per-tab count are gone; a listener filtered to
   EXFIL_URL_PATTERNS keeps the exfiltration warning (its type-filter try/catch kept: one Chrome rejects a type).
   webNavigation.onBeforeNavigate removed: ONE webRequest.onBeforeRequest main_frame listener does tab band, then the
   XSS-link check first and the site check only when it did not warn (issue 7: one warning per navigation). Badge:
   "?"/"!" by severity + "•" tamper mark. Popup "This page" box: site risk + reasons, tamper rating + Details
   (MSG_SHOW_TAMPER_DETAILS → Tamper.showDetails), "Continue once" note, "Firewall blocked N requests on this page" from
   declarativeNetRequest.getMatchedRules({tabId}) — new permission activeTab (no install warning; approved in
   check-permission-additions); block rules only counted (POPUP_MATCHED_RULES_MAX). e2e-embedded-frames runs a temp
   copy with declarativeNetRequestFeedback for the count (a test cannot click the toolbar icon).
2. **Lazy outgoing check (security/tamper-guard-page.js):** the fetch/XHR/beacon/WebSocket/address-setter wrappers
   start only after a password, card or IBAN is typed or filled on an armed page (the 5.1.3 "same class" note above
   is settled this way: an untyped page's fetch failures can no longer be filed under the page script).
   8c: a PerformanceObserver ("resource") compares every loaded address with the typed secrets — card data in HTML
   text (an <img> via innerHTML) and CSS url(). 8a (a script that runs before ours) and 8b (Blob/ArrayBuffer bodies):
   documented gaps, deferred.
3. **Own-warning protections as findings (data/tamper-rules.js, core/tamper-guard.js, background.js,
   core/page-scam-guard.js):** three rules tgPasswordForm / tgPaymentSkimmer / tgFakeSignIn with `ownWarning` = the
   protection key and points TAMPER_OWN_WARNING_POINTS (100); TAMPER_RULE_OF_OWN_WARNING maps key → rule; they are in
   TAMPER_DERIVED_RULES (a page can never report one). Tamper.recordOwnWarning(state, key, sender, items) records the
   finding from the service worker's own decision (password form: on warn, dest host; fake sign-in: the imitated host;
   skimmer: on MSG_PAGE_SCAM_BLOCKED before the warning page opens — also after "Continue once", when no warning
   opens), armed or not, when the switch and that protection are active at the top page's level. evaluate() keeps the
   shown score/rating over every finding but decides opening/reopening on rec.warnRating (scoreOf without own-warning
   findings): no extra window; an open window is updated with them. The Tamper list is the rules table only (the
   separate PROTECTIONS rows and TAMPER_LIST_KIND are gone); rows carry `warnsAtOnce`, sorted first among equal points;
   the list shows "warns at once" after their name.
4. **Hidden-field trigger narrowed (security/tamper-guard-bridge.js isTrickHidden):** a. type=hidden named like a
   password (HIDDEN_PASSWORD_SELECTOR) or card field (CARD_SELECTOR), minus token names (HIDDEN_NAME_EXCLUDE_RE:
   token|csrf|nonce — "reset_password_token" is page plumbing); b. a password/card field itself invisible (own
   display/visibility/opacity, ≤ INVISIBLE_MAX_PX) or entirely off the page, while its PARENT is visible
   (checkVisibility with opacity/visibility + size). A field hidden with its surroundings (closed menu, dialog,
   sign-in step) never counts. Used by both the trigger signal and the armed observer's tgHiddenCredential.
5. **Tamper list heading** (ui/protections.js TAMPER_LIST_HEAD): "Signs of tampering — points add up to the page's
   risk rating"; names stay plain.
6. **Click flag at every download start (core/download-guard.js askClick/clickFlag/releaseClick, _clicks):** asked at
   onCreated before the block decision, for every download the warning or the block could apply to (not only
   monitored types known at that moment); kept per download id ({ askedAt, answer promise }), released in release(),
   releaseWithoutWarning(), releaseAll(), the "not ours" completion and erase; swept with the other maps
   (ENTRY_MAX_AGE_MS), capped at DOWNLOAD_GESTURE.ENTRIES_MAX (oldest dropped → unknown, never a false "no click").
   startCheck and lateEntryRecord read it (late entries now get the signal; "Download anyway" on a held download that
   already finished is such a late entry). Lost on a service-worker restart → unknown.
- **Found while doing issue 5 (ui/protections.html):** the Scam tab's "How scam protection works" card held the tamper
  rating bullets (and "toolbar count"), the Tamper tab the pre-rating text. The rating bullets moved to the Tamper card
  ("toolbar icon"); the Scam card got its own (one switch from `scam-level-from`, no rating, frames from
  `scam-frames-level-from` outside safer regions, "Scam: site"). Derived key `tamper-level-sensitive-from` (only used by
  the old Tamper text) removed.
- **Only the four ticks arm a page (owner, 2026-11-24 evening, "need to protect", least overhead):** prompted by
  Speedometer 3.1 getting a "?" at level 3 (a framework replaced Function.prototype.toString → a 20-point sign armed the
  page). Removed: TAMPER_LEVEL (AFTER_SIGN level 3, ALWAYS level 4–5), ARMED_BY.SIGN/ALWAYS/ADDRESS_SCRIPT; a
  tgAddressScript or tgObfuscatedCode report no longer arms; core/tamper-guard.js onReport ignores every report from an
  unarmed page; recordOwnWarning records on armed pages only; the popup's tamper line needs an armed page. Page side:
  security/tamper-guard-page.js compares the static targets only when armed (on arm, then DOMContentLoaded / load /
  +3 s) and holds earlier reports (address sinks, an early JSON replacement) in `pending` (≤ MAX_PENDING_REPORTS = 20,
  released on arm); security/tamper-guard-bridge.js holds blocked obfuscated-code entry points until arm. The baseline
  snapshot at document_start stays (it must precede page scripts). Unwatched pages now send no reports at all.
  UI: "How tamper protection works" first bullet rewritten; derived keys tamper-level-after-sign(-from), tamper-level-always
  removed. Tests: unit cases use a checkout-word page (WATCHED) where a watched page is needed; e2e: level 4 ordinary page
  → no window, DOM-XSS page without a tick → no window, with a checkout word → warning.
- **blockObfuscatedEval back to Firewall (owner, same evening):** "it blocks, it does not watch" — num 10 in the
  "Outside safer regions" group (level 3 outside safer regions, 4–5 every site), own tick, no `requires`, no
  `switchable: false`; old 10–13 → 11–14 (ticks by key carry over). The level-5 strict eval (security/sec-no-eval-strict.js,
  strictScripts/strictFromLevel, script-builder strictRegistrationsFor, SCRIPT_ID_SUFFIX.STRICT) removed. Its tamper sign
  tgObfuscatedCode stays (watched pages only). Tamper tab: 8 registry rows (switch, three own-warning members, four ticks).
- **Badge: the highest problem wins (owner, 2026-11-24; core/badge.js, data/constants.js, core/tamper-guard.js):**
  BADGE_TEXT.TAMPER ("•") removed. The entry's `tamper` is now a SEVERITY from TAMPER_BADGE_SEVERITY (Suspicious →
  SUSPECT, High/Critical → PHISHING); badgeOf takes the worst of site and tamper (SEVERITY_ORDER) → "!" / "?" or text
  null = Chrome's own count. Badge.init() (every SW start): setExtensionActionOptions({ displayActionCountAsBadgeText:
  BADGE_SHOWS_BLOCK_COUNT }) and the GLOBAL badge colour NORMAL (grey). Verified in Chrome with a test extension: only
  block rules are counted (allow rules not), per-tab text overrules the count, text null hands it back, no permission
  beyond declarativeNetRequest; Chrome cannot report the number (getBadgeText gives a placeholder), so a literal "#"
  would need declarativeNetRequestFeedback (C36: re-approval for every user) — owner chose the number.
  Tamper guard: the sink now gets the page's FULL rating (own-warning signs included) whenever evaluate runs, on an
  armed page outside "Tamper: site", else LOW (Badge.setTamperRating replaces setTamperMark/getTamperMark).
  Bug found (confirmed in Chrome): Chrome clears a tab's own badge text on navigation, but _shown still held "?", so
  a same-site navigation left the badge empty; Badge.resetPage now drops _shown and redraws. Session entries with the
  old boolean `tamper` read as NONE (severityOf guard). UI text: the Tamper card's derived `tamper-mark` is "?".
- **Tamper tab layout (owner, UI only — core/policy.js already deactivates every dependent protection, verified for all
  nine Tamper-tab keys at level 5):** ui/protections.js SWITCH_CARD_TITLE puts the tab's switch (the row the others
  name as `masterLabel`) in its own card above its tick group, stacked in one column; TAB_OFF_CLASS on the panel while
  it is off dims the explanation and the signs list. Every `masterOff` checkbox (all tabs: also blockRiskyDownloads
  under warnRiskyDownloads) is now shown unticked and disabled; the stored tick is untouched.
- **Documented Chrome limit:** a shared worker's WebSocket is invisible to extensions, so blockAbusedTlds' WebSocket
  part (#4) cannot reach it (INFO in tools/e2e-worker-blocks.mjs); blockWebsockets (#11) does (CSP on the worker
  script + DNR).
- **Consumer inventory (issues 3, 4, 6):** own-warning decisions — background.js MSG_CHECK_PASSWORD_FORM,
  MSG_CHECK_FAKE_WINDOW, MSG_PAGE_SCAM_BLOCKED (the only three callers of passwordFormDecision / fakeWindowDecision /
  the skimmer kind); the Protections list (tamperView) and the warning window read the same rules table. Hidden-field
  test — the bridge's signal check and its MutationObserver, both via isTrickHidden (the page script has none). Click
  flag — startCheck (incl. "Download anyway" while running), lateEntryRecord (incl. "Download anyway" after finishing),
  the completion re-check (record.noClick). Not swept here: DownloadSentinel itself has no click signal (it is a
  3P Matrix addition to the ported code).

**tools 5.1.4:** test-tamper-guard + seed copies and destination; test-site-scorer + "www-" cases.

**tools 5.1.3:** test-wasm-wrappers.mjs rewritten; new test-allow-list.mjs (wired into complete-check);
test-tamper-guard.mjs rewritten for the rating (ratings, factor, Suspicious by level/safer regions and the mark, one
window updated, collect delay, reopen only higher, trigger ticks, IBAN, obfuscated code, page-script copies);
test-download-active-threat.mjs + no-click signal; e2e-tamper-guard: one rated window, quiet mark, IBAN, packed eval
at level 4; e2e-flows/page-protections/embedded-frames/worker-blocks follow the Scam switch and the allow-list format.
Issue round: test-tamper-guard.mjs + own-warning findings (rule map, never page-reported, Critical without a window,
armed page without a window, counted and updating an open window, switch/level 1 off) and the list (one source,
warnsAtOnce first, heading); e2e-tamper-guard + six hidden-field pages (three tricks arm, closed menu / closed dialog /
reset token do not); e2e-flows + "Started without a click" for a download the page starts itself vs a real click,
and for a late entry (blocked tiny file, finished, Download anyway) both ways; e2e-embedded-frames + the popup count.

## 5.1.2
Compare at 5.1.1. Changed zips: extension, tools, docs.

- **Why:** after the Browser Guard review (its "skimmer protection" is only a DevTools decoy), four gaps in our own
  skimmer detection were ranked by value/cost and chosen by the owner: (1) the address channel, (2) a fake card form
  beside a payment provider's frame, (3) card numbers recognised by value, (4) script hosts that imitate brands or
  script providers. Not built: card data written to storage, reversed/hex encodings, WebRTC data channels.
- **(1) Address channel** (security/tamper-guard-page.js `armAddresses`): on armed pages the `src` setter of
  HTMLImageElement / HTMLScriptElement / HTMLIFrameElement and the `href` setter of HTMLLinkElement, plus
  `Element.prototype.setAttribute` for `src`/`href`, go through `checkOutgoing` like a request (getter kept; the
  original setter always runs, C53). `checkOutgoing` now resolves the destination FIRST and returns for the page's
  own host, so the common case (own images) reads no fields. Gap: elements inserted as HTML text (innerHTML,
  insertAdjacentHTML, document.write) and CSS url().
- **(3) Card number by value** (page script `cardValues`, bridge `hasTypedCardNumber`): any text/tel/number field
  (≤ TAMPER_CARD_VALUE_FIELDS_MAX) whose value is only digits/spaces/dashes, 13–19 digits and Luhn-valid. The bridge
  also re-sends its signals on a field's `change` event (window, capture) when the value is a card number, so a page
  with oddly named fields still becomes a payment page.
- **(2) tgSecondCardForm** (derived, HIGH): the bridge's new `cardNumber` signal (card-NUMBER field, gift cards
  excluded, or a typed card number) from the top page or a same-site frame, while the page embeds a Payment-list
  frame. Never from inside the provider's frame, never on a known payment site. Detail = the provider's frame hosts.
  Derived rules are now one list (`TAMPER_DERIVED_RULES`); a page can never report them. HIGH, not CRITICAL: a shop
  may briefly show its own form and a 3-D Secure frame together.
- **(4) tgSuspiciousScript** (MEDIUM): on armed pages the bridge reports other sites' script hosts (present at arm and
  added later, ≤ TAMPER_SCRIPT_HOSTS_MAX, batched). The service worker keeps those that core/site-scorer.js
  `scoreLocal` rates suspect or worse (look-alike brand/site, abused TLD, free hosting, misused platform) or that
  imitate a script provider (`TAMPER_SCRIPT_PROVIDERS`: the name starts the registered-domain name or one of its
  dash parts — "jquerycdn", "cdn-stripe", not "pinstripe" — or is within 2 edits for names ≥ 8 letters). Built-in
  whitelist and the page's own site are never scored; verdicts cached (cap TAMPER_SCRIPT_VERDICTS_CAP). Domain age
  (RDAP) is NOT used: it would be a network lookup per script host. Measured on 40 hosts: the common CDNs and tag
  managers all rate "none".
- **Warning window:** optional per-rule `detailHead` in the rules table ("Scripts loaded from:", "The payment
  provider's secure frame on this page:").
- **Tests:** test-tamper-guard.mjs — copies of the new limits, derived rules unreportable, the second card form
  (alone / with a frame / inside the frame), imitation matching (6 imitations, 10 real or ordinary hosts), the script
  finding on a payment page vs. only noted on an ordinary page. e2e-tamper-guard.mjs — real Chrome: card number in
  an oddly named field sent in an image address; own card field beside a payment frame; a payment page loading a
  script from jquery-cdn.net.

- **XSS, reflected half — warnXssLinks** (Browsing, level 2, core/xss-link-guard.js): the device-code pattern —
  webRequest.onBeforeRequest (main_frame, observing, never holding the request), `initiator` from ANOTHER site (or
  opaque), the address (path + query; "+" as space, decoded up to XSS_DECODE_ROUNDS) matching XSS_MARKUP_PATTERNS
  (script tag, event handler inside a tag, javascript:) → amber page-scam warning (reason xssLink, LEAVE.NEW_TAB,
  no Trust, Continue once per tab + site). A cheap pre-check (`mayBeXssLink`: initiator present, "<" plain/encoded
  or "javascript" in the address) runs before the state is loaded. The sending site's level decides. No new
  permission (webRequest + <all_urls> were already held). Limits: the # part never reaches the network layer; form
  POSTs; other encodings (HTML entities, base64).
- **XSS, DOM half — tgAddressScript** (Tamper, HIGH): the page script decodes its own query and hash values at
  document_start; only when one carries script markup does it wrap the HTML/code sinks (rules table `sinks`:
  innerHTML/outerHTML/insertAdjacentHTML/setHTMLUnsafe, ShadowRoot innerHTML, document.write/writeln,
  createContextualFragment, iframe srcdoc, setAttribute). A value containing such a piece reports the sink NAME. The
  report arms the page itself (ARMED_BY.ADDRESS_SCRIPT) — the dynamic layer otherwise only takes reports from armed
  pages. eval/Function/string timers are not wrapped (wrapping eval turns direct eval indirect; the obfuscation
  blocks cover them).
- **Fix found by the new e2e case:** `location`'s properties live on the location object ([LegacyUnforgeable]), not
  on Location.prototype — the page script read `href` from the prototype since 5.1.0 and got null (harmless there: a
  relative address simply was not checked). `locationGetter()` now reads the object first.
- **Browsing list reordered** (user decision, after a ChatGPT proposal with one change: ClickFix and ConsentFix side
  by side): see data/protections.js header for old → new numbers (29 numbered now).

- **Obfuscation protections merged** (user decision): blockObfuscatedFunction / -SetTimeout / -SetInterval folded
  into blockObfuscatedEval ("Block obfuscated code execution (eval, Function, timers)"; key kept — contract), one
  scriptlet `security/sec-no-obfuscated-code.js` replacing sec-noeval/-nofunction/-nosettimeout/-nosetinterval.js:
  one detector copy, one injection per frame instead of four, the four per-binding install flags kept (eval's is
  shared with uBD). New guard: a timer binding that is absent is skipped instead of throwing. Old unticks of the three
  dropped keys are dropped by normalizeState (only known keys survive). Browsing list now 26 numbered.
- **Tamper Protection list names** (`listLabel`, owner request): "Warn when …" / "Warn about …", and "Note when …" for
  LOW rules (they never warn); the warning window keeps `label` as its title.
- **Versions** (owner decision, end of the session): 6.0.0 / 6.0.1 / 6.0.2 renamed back to 5.1.0 / 5.1.1 / 5.1.2 —
  none was published. The last full suite ran on the build before the merge and the rename (37/37); after them only
  the non-browser checks ran (32/32, owner: "no need to check").

**tools 5.1.2:** test-tamper-guard.mjs and e2e-tamper-guard.mjs gain the cases above (also: the XSS link decision,
the page script's XSS copies and sink names, the address-script report arming an ordinary page; real Chrome: the
link warning page and the innerHTML case, plus a harmless address that opens nothing).

## 5.1.1
Compare at 5.1.0. Changed zips: extension, tools, docs.

- **Why:** reviewing Malwarebytes Browser Guard 3.3.10 (it injects a "DevTools is open" decoy on addresses matching
  checkout words) showed that our 5.1.0 address-word signal did nothing: it was 25 points against a threshold of 60,
  and every other signal is worth 60+ on its own, so it could never tip a page. It also only matched whole path
  segments in five languages.
- **What:** an address word is no longer points. In `onHello` it arms the page (`ARMED_BY.ADDRESS`) when nothing else
  did — the address is known before the page's scripts run, so the closer watching starts before a later skimmer
  can hook anything. The page is NOT made sensitive by it (B11: page signals may only raise scrutiny): MEDIUM
  findings there are kept in `rec.quiet` (one per rule) and decided again with the banking/payment threshold when a
  real signal (card/IBAN field, payment frame, known payment site) arrives (`updateSensitive`). This also closes an
  earlier gap: a page armed by level 3 (sign) or 4–5 (always) that became sensitive later never re-decided its
  MEDIUM findings.
- **Words:** `TAMPER_ADDRESS_WORDS` per language (EU + EEA + Bulgarian/Greek in both scripts),
  `TAMPER_ADDRESS_ENDINGS` for compound/platform forms (`onepagecheckout`, `onlinebanking`, `anzahlung`),
  `TAMPER_ADDRESS_LETTER_FOLD` for letters NFD does not split (ł ø æ ß đ þ ð œ). Matching: decoded path + subdomain
  labels (never the site's own name), lower case, accents removed, whole tokens; capped at `TAMPER_ADDRESS_TOKENS_MAX`.
- **Known limits:** single-page shops that move to `/checkout` with `history.pushState` are not re-checked (hello runs
  once per document); short words (`kasa`, `cos`, `caja`) can arm an unrelated page — harmless, it only watches.
- **Tests:** test-tamper-guard.mjs — 25 addresses that must match across the languages, 8 near misses, the token
  cap, and the arm-early / confirm-later flow.

**tools 5.1.1:** `test-tamper-guard.mjs` gains the address-word cases; its pending-finding case now uses an address
without a word (`/product/42`).

## 5.1.0

**Working from:** 3P Matrix 5.0.9 (GitHub repo, commit 7ee2354), full suite green before the first change (35/35, real
Chromium 153 for the e2e steps).
**Version:** 5.1.0 — worked on as 5.1.0, renamed 6.0.0 during the work, and back to 5.1.0 by the owner before the first
release (5.1.0–5.1.2 were never published separately).
**Result:** complete-check 37/37 on 5.1.0 (real Chrome 153 for the e2e steps).
**Zips changed:** all three — extension (Tamper Guard, registry tabs, refreshed lists), tools (two new tests, suite
wiring, message-gate allowlist), docs (this entry, CHANGELOG.md, ARCHITECTURE.md).
**Decisions (user, 2026-11-23):** one extension, not a second one (splitting would have cut through the one fact
"how much do I trust this site" — level, safer regions, Trust this site — which two extensions cannot share without
messaging); Tamper Guard follows the level slider: 2 = banking/payment pages, 3 = + after a tampering sign, 4–5 =
always; level 1 / Trust this site = not watched; warn-only; warning with Ignore, a 5-second countdown and "never warn
again"; a Tamper Guard tab; the download protections back on the Download tab; blockRiskyDownloads requires
warnRiskyDownloads; signals the page controls may only RAISE watching, never lower protection.

**tools 5.1.0:** new `test-tamper-guard.mjs` (step tamper-guard) and `e2e-tamper-guard.mjs` (step e2e-tamper-guard);
`test-message-gate.mjs` allowlists the one MutationObserver (tamper-guard-bridge.js, with its limits); lists rebuilt
for 5.1 (update-psl --fetch, update-domain-age-lists from the cache, update-top-sites, rebuild-host-list --fetch,
build-spam-tlds with HaGeZi 2026.1123.0244.34). **Not refreshed:** the IANA RDAP file — data.iana.org is not
reachable from the build machine (`update-domain-age-lists.mjs --fetch` failed); RdapCctlds was rebuilt from the
cached 2026-10-22 file. Run `update-domain-age-lists.mjs --fetch` once more where IANA is reachable.

### Tamper Guard (data/tamper-rules.js, core/tamper-guard.js, core/tamper-warnings.js, core/tamper-exceptions.js,
### security/tamper-guard-page.js, security/tamper-guard-bridge.js, ui/tamper-warning.*)
- **Static layer (MAIN world, every page where watchTamperSensitive runs):** the property descriptors of 32 built-ins
  (JSON, Response, fetch/XHR/sendBeacon/WebSocket, addEventListener, Function.prototype, Crypto/SubtleCrypto,
  HTMLInputElement value, cookie/Storage) and the own names of Object.prototype / Array.prototype are saved at
  document_start and compared at DOMContentLoaded, load and load + 3 s. Holders are resolved through the saved
  descriptors (a page-defined getter on the way counts as a change); comparison is by identity, because a Proxy's
  `toString()` still says `[native code]`. One report per target per page.
- **Dynamic layer (armed pages only):** when JSON.parse / Response.prototype.json is no longer the original, an
  OUTER wrapper returns the replaced function's result unchanged and parses the same text with the saved original to
  compare (field names only, ≤ 512 KiB, ≤ 5000 nodes, depth 12; never with a reviver, which would run twice). This is
  what makes a json-edit rule visible. A page armed BEFORE its scripts replace JSON.parse (the usual case — the arm
  reply arrives at document start; found by e2e-tamper-guard at level 4, where it failed 4 runs out of 4) still has
  the original there: the property then becomes an accessor that reports and wraps an ASSIGNED replacement at once
  (guardData); a replacement by Object.defineProperty is seen by the next static comparison and wrapped then. Our
  wrappers are kept in a WeakSet so they are never wrapped or reported again. Cost of the accessor: a page that reads
  JSON.parse's descriptor on an armed page sees get/set instead of a value. Outer wrappers on fetch, XHR open/send, sendBeacon and WebSocket send check,
  before handing the call on, whether the address or body contains a current password-field or card-field value
  (raw, URL-encoded, base64; card digits also after URL-decoding — "%20" between digit groups adds digits of its own,
  found by the e2e skimmer case). Only the destination HOST leaves the page script. The ISOLATED half runs one bounded
  MutationObserver (action/formaction/integrity + added elements; 200 records / 100 elements per callback;
  disconnected on pagehide, restarted on a back/forward-cache restore).
- **Own wrappers are never a finding:** wrapOuter() moves the target's baseline to our wrapper (arm() compares first,
  so an earlier replacement was already reported). 3P Matrix's OTHER page scripts replace built-ins on purpose
  (blockWebAssembly: fetch, XHR open, XHR response) — `wrappedBy` in the rules table makes the service worker ignore
  those targets where that protection runs (isProtectionActiveOrHighRisk). Known gap: a real replacement of such a
  target is not seen there.
- **Decisions in the service worker only (C46/C47):** reports carry no authority; core/tamper-guard.js validates rule,
  detail kind, sizes and host names, takes page and tab from the sender (C28), applies the level, the destination
  checks (own site, BUILTIN_SIGN_IN for passwords/forms, BUILTIN_PAYMENT for card numbers, BUILTIN_ALL for invisible
  frames) and the exceptions. Severity: LOW findings (common in frameworks such as Zone.js, monitoring scripts and
  cookie-consent tools) are only noted — they never warn, never arm, never count for correlation. Warning threshold:
  MEDIUM on banking/payment pages, HIGH elsewhere. Two other MEDIUM+ findings on the page raise the next one a step.
- **Per-tab state machine (B3a):** STANDBY → ENHANCED → COOLDOWN (same-site navigation; the next page is armed at its
  hello within 60 s) → STANDBY; transitions only through transition(). A finding that arrives before the page is
  armed is decided again when it is armed (pending) — the static report often comes before the payment signals.
- **Banking/payment recognition:** points per signal (built-in Payment list 70, payment-provider frame 60, card
  field 60, IBAN field 60, payment word in the path 25), threshold 60 — a word alone is never enough. Only top frames
  say hello; signals are sent only when a card/bank field or a frame exists, so an ordinary page costs no extra
  service-worker message beyond the hello.
- **Warning window, not in-page UI (C47):** core/tamper-warnings.js opens ui/tamper-warning.html in a popup window
  (one per tab; later findings while it is open are noted). The page cannot remove it. Countdown TAMPER_COUNTDOWN_S
  for non-critical findings, stopped by any pointer/key/wheel input; critical: no countdown. Buttons act on trusted
  clicks only; "Never warn anywhere" asks for confirmation.
- **No history (threat model):** a page's findings live in memory for that page only (one per rule), released on
  navigation and when the tab closes; nothing is shown except the warning itself (UI rule: only what is actionable —
  the "This session — open tabs" list built first was removed on review); only the exceptions the user chooses are stored (state.tamper.exceptions, new key, no schema change, in the
  settings file as `tamperGuard`).
- **Not built, with the reason** (data/tamper-rules.js header): storage/cookie READS and clipboard reads (normal on
  every site; clipboard reads already blocked by blockScpPrivacy), fingerprinting (uBD's Fingerprint inspector),
  eval/Function (the obfuscation blocks), workers, permission prompts, and "another extension was installed or
  widened" — that needs the `management` permission, and C36: an added permission disables the extension for every
  user until they re-approve it. Not attributable: WHICH extension replaced a built-in (a document_start script that
  ran before ours is part of the baseline, and Chrome gives no attribution) — so exceptions are per site or every
  site, not per extension.

### Same release, second decision (user, 2026-11-23 evening): ONE switch, "Tamper Protection"
- User-facing name **Tamper Protection** (code keeps the internal name Tamper Guard: core/tamper-guard.js,
  data/tamper-rules.js). Tabs renamed: Browsing Protection · Download protection · Tamper Protection · Allow (white) list.
- watchTamperSensitive is shown as **"Enable tamper protection"**; watchTamperAfterSign / watchTamperAlways are no
  longer protections (keys removed — a stored untick of them is dropped by normalizeState as an unknown key). The
  slider widens the watching at `TAMPER_LEVEL.AFTER_SIGN` / `TAMPER_LEVEL.ALWAYS` (data/constants.js), same levels.
- warnPasswordForms, warnPaymentSkimmer, blockFakeSignInWindow: new registry field `switchable: false` + `requires` the
  switch — no checkbox, no number, listed first (Critical) in the Tamper Protection list (tamperView
  `TAMPER_LIST_KIND.PROTECTION`). isProtectionEnabled ignores their own tick; normalizeState drops a stored untick (a user
  who had one switched off gets it back — named in CHANGELOG.md).
- Numbering: only switchable rows of numbered tabs (`PROTECTION_TAB_NUMBERED`, `isNumbered()`) — first Browsing and
  Download (1–30), after the review below Browsing only (1–28).
  tools/check-protection-keys.mjs checks: unnumbered rows carry no num, `requires` one level deep and never from a
  higher level, `switchable: false` needs a master, every row in some group.

### Registry: tabs and `requires` (data/protections.js, core/policy.js, core/view-models.js, ui/protections.*, ui/popup.js)
- `tab` field + PROTECTION_TAB; PROTECTION_GROUPS rows per tab; display order = tab, group, registry → renumbered
  (keys unchanged; mapping in the protections.js header). check-protection-keys reads PROTECTIONS_IN_DISPLAY_ORDER,
  so it follows without change.
- `requires` (one level deep): isProtectionEnabled() is false when the master is unticked — the ONE gate every reader
  goes through. isProtectionTicked() is the checkbox only (the page dims a dependent and says why).
- popup level-3 bullet: was "the level-3 GROUP", which also held blockWasmDubious (every site); groups are per tab
  now, so protectionCounts() counts scope OUTSIDE_SAFER_REGIONS directly (`counts.outside`).

### Consumer inventory (Ground Rule, checked before calling this done)
- **Protection enabled/active** — every reader: core/script-builder.js (both registration paths), core/rule-builder.js
  (`on()`, exfil, header bands), core/download-settings.js (warn, block, high-risk path), core/policy.js
  (isProtectionActive, isProtectionActiveOrHighRisk, protectionCounts), core/page-scam-guard.js, core/password-form.js,
  core/navigation-guard.js, core/device-code-guard.js, core/tamper-guard.js — all through isProtectionEnabled /
  isProtectionActive, so `requires` reaches all of them. data/settings-io.js summarize() counts ticks only (data must not
  import core); "N of M protections on" can therefore count a dependent whose master is off — accepted, it is a summary.
- **Protection groups / display order** — core/view-models.js (popup + Protections page), ui/protections.js, ui/popup.js
  (switched to counts.outside), tools/check-protection-keys.mjs; no other reader.
- **Stored state** — normalizeState (validation), defaultState, settings-io export/import/summary, reset (defaultState),
  import (normalizeState) — all carry `tamper`.
- **Messages** — 3 content-script messages in CONTENT_SCRIPT_MESSAGES (test-message-gate checks both directions), 4
  extension-page messages, 1 SW→content message; copies in the bridge checked by check-shipped-terms.
- **Lifecycle (C41 CRUD):** tab watch records created on first message, reset on commit, released on tab close and by
  the cap; warning windows released on window close, tab close and every action; exceptions created by the warning
  window, read by decide(), edited as text on the Tamper Protection tab (Save replaces the list; Import/Export like
  the allow list), reset/imported with the settings.
- **Same logic elsewhere:** the password-to-another-site decision also exists in core/password-form.js (form submit);
  Tamper Guard's tgPasswordSent covers fetch/XHR/beacon/WebSocket, which that check never saw — the two do not
  overlap. The payment-host trust (BUILTIN_PAYMENT) is the same list blockPaymentHandlers and the download checks use (C21).

### Review of the Protections page (owner, same day) — layout and lists
- Only the Browsing list is numbered (PROTECTION_TAB_NUMBERED); the two download protections lost their numbers too.
  The download-blocked notice and the "does nothing while … is off" note now name the protection instead.
- Tamper Protection tab: two columns of the same height — switch, explanation and never-warn list (left, the list's
  text box fills the column); protections grouped by severity like the Browsing level groups, explanation on hover
  (right). Rows without a checkbox get no checkbox row height and no empty number column.
- Never-warn list: text, one "site — finding" per line (label or id; `*` = every site; sites folded to their
  registered domain), Import / Export / Revert / Save like the allow list (MSG_SET_TAMPER_EXCEPTIONS replaces the
  per-entry remove). In "Save settings" as `tamperGuard`; the summary counts switches only.
- The session list ("This session — open tabs") removed with its service-worker log; pageFindings(tabId) keeps the
  current page's findings for the decision (correlation, once per rule) and the tests.
- UI lessons recorded in the principles doc as A10.
- privacy.md rewritten from the code (decided by the owner): what runs on the device, the three online checks, what is
  stored, per permission; Tamper Protection's in-page comparison of field values stated plainly.

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
