// ── data/protections.js ───────────────────────────────────────────────────────
// THE protections registry — single source of truth for the selectable
// protections (32 since 5.0.2; the count is always PROTECTIONS.length). The popup list, the counts, the DNR rule builder and the
// content-script builder all read this table; none of them keeps its own list.
//
// A protection is ACTIVE for a site when:
//     effectiveLevel(site) >= fromLevel   AND   not unticked by the user
//
// Removed in 0.2.3 (user keeps them in uBlock Stripped Dynamic): "Clear history at browser
// start" (deleteHistoryOnStart) and "Block tracking pings" (blockPings). Their keys are
// dropped from saved state by normalizeState(), which keeps only keys listed here.
//
// Added in 0.2.4: "Warn when opening suspicious sites" (4.2.3: was "before"; warnSuspiciousSites, num 10) — the
// navigation-guard warning dialog, until then always on from level 2, is now a selectable
// protection. Old saved states have no entry for it, so it starts ticked (= previous behaviour).
// Level-3 protections renumbered 10–14 → 11–15 (keys unchanged).
//
// Added in 4.2: "Block 3P scripts and frames from abused TLDs" (blockAbusedTlds, num 11) — the
// HaGeZi abused-TLD block, until then an unconditional part of the level-2+ policy, is now a
// selectable protection. Old saved states have no entry for it, so it starts ticked (= previous
// behaviour). 4.2 renumbers so each group is consecutive: level-2 group 1–11 (abused TLDs = 11),
// level-3 group 11–15 → 12–16 (keys unchanged, so saved ticks carry over). `num` is display only.
// 4.2: protection 1 gains trustedExempt — the built-in whitelist's payment hosts may register a
// real payment handler on their own site, at BUILTIN_EXEMPT_LEVELS (3–4) only.
//
// Added in 4.3.0: "Warn when a downloaded file looks risky" (warnRiskyDownloads, num 12) —
// DownloadSentinel 3.2.0's download protection (core/download-guard.js). Old saved states have no
// entry for it, so it starts ticked. Same 4.2 rule, each group consecutive: level-2 group 1–12,
// level-3 group 12–16 → 13–17 (keys unchanged, so saved ticks carry over). `num` is display only.
// Its "site" is the page the download came from (DownloadItem.referrer), else the download host:
// an allow-list site (locked at level 1) gets no download warnings, like every other protection.
//
// 4.3.2 (user request): display numbers 10 ⇄ 11 swapped — the two warnings now sit together at 11 and 12
// (abused-TLD block = 10, suspicious-site warning = 11, risky-download warning = 12); keys unchanged.
// Protection 17's label shortened to fit one popup line.
// Added in 4.3.2: "Block risky downloads (programs, scripts, archives)" (blockRiskyDownloads, num 18) —
// OFF by default (defaultOff). From level 3: outside safer regions at level 3 (the page the download
// came from decides), on every site at levels 4–5. A blocked file never reaches protection 12's check;
// 4.5.5: the blocked download is held (paused) until the user chooses — "Download anyway" continues the same
// download and then protection 12 always checks it (core/download-guard.js). Saved states from before 4.3.2 get it unticked by the schema-3 migration.
//
// Added in 4.4.3 (user request): three siblings of the obfuscated-eval() detector, one per API —
// "Block obfuscated Function() code generation" (blockObfuscatedFunction, num 18), "...setTimeout()
// string execution" (blockObfuscatedSetTimeout, num 19), "...setInterval() string execution"
// (blockObfuscatedSetInterval, num 20). Same scope/level as the eval() detector (outside safer
// regions, from Medium), same shape-only detection (util/ObfuscationShape.js) — not a blanket
// string-handler block like protection 9's fixed-host-list sec-adult-noeval.js. Old saved states
// have no entry for any of the three, so they start ticked.
// User request (same change): display numbers 16 ⇄ 17 swapped so the four obfuscation-style
// protections sit together (redirects/dialogs = 16, eval() = 17, Function() = 18, setTimeout() =
// 19, setInterval() = 20), and the risky-downloads block moves to the end (18 → 21). Keys unchanged
// (contract); every "protection 16/17/18" reference in code comments, docs and test labels that
// meant the OLD number was swept to the new one in the same change (constants.js, message-types.js,
// download-guard.js, download-settings.js, ui/download-blocked.js, README.md, e2e-flows.mjs test
// labels) — a past CHANGELOG_HISTORY.md entry describing an older release keeps ITS OLD numbers,
// since that is what was true when it was written.
// 4.6.0 (user decisions 2026-11-06): four new protections — 11 "Block exfiltrating (phishing) data to messaging
// bots" (blockExfilMessagingBots), 14 "Warn when a password form sends to another site" (warnPasswordForms),
// 18 "Block notification prompts that appear without a click" (blockNotificationPrompts), 24 "Block exfiltrating
// (phishing) data to web services" (blockExfilWebServices) — and protection 3 widened to "Block browser-locker
// scams (popups, keyboard lock)" (key blockDialogSpam kept). Renumbered: 11→12, 12→13, 13–15→15–17, 16→19,
// 17–20→20–23, 21→25. As in 4.4.3, every "protection N" reference in code comments, README and test labels was swept
// to the new numbers BY MEANING (several were already stale, e.g. "protection 18" for the risky-download block);
// user-facing text derives the number from this table (C39a).
//
// 4.7.0 (user decisions 2026-11-06): two new protections in the "every site" group — 15 "Block pasting a sign-in
// address into a website" (blockConsentFix) and 16 "Warn when a site sends you to enter a sign-in code"
// (warnDeviceCodePages); protection 8 (ClickFix) gains a visible warning, macOS/Linux patterns and two levels, and
// a NEW, independent protection 28 a fake sign-in window check (Browser-in-the-Browser). Renumbered: 15–25 → 17–27
// (keys unchanged, references swept by meaning as in 4.6.0).
//
// 4.7.0 (user decisions 2026-11-06, high-risk tier): a new "Level 4–5 only" group — 29 "Block WebSocket
// connections" (blockWebsockets), 30 "Block WebTransport connections" (blockWebtransport), 31 "Block WebAssembly"
// (blockWebAssembly). (A fourth, 32 "Block inline scripts" (blockInlineScripts), shipped in 4.7.0 and was removed
// in 4.7.6 — see that version's note below: its CSP had no nonce/hash matching, so it blocked a site's own
// legitimate inline scripts along with injected ones, breaking most sites it ran on rather than protecting them.)
// And a new field, `alsoHighRisk` (below): EVERY protection in the "outside safer regions" group, including
// blockRiskyDownloads, plus all three remaining new 29–31 protections, now also applies on a HIGH-RISK site
// regardless of the level slider —
// "high-risk" = the site is in data/network-data.js HIGH_RISK_HOSTNAMES (fixed list, always known) OR this tab's
// site-scorer has flagged it SEVERITY.PHISHING this session (core/badge.js, set by core/online-checks.js) — an
// allow-listed site (locked at LEVEL.ALLOW_ALL, "Trust this site") is exempt either way: explicit trust wins.
// core/policy.js isHighRiskSite() is the single decision point. The static half (fixed host list) reaches a
// SCRIPT-mechanism protection via an extra, level-independent chrome.scripting registration
// (core/script-builder.js highRiskRegistrationsFor, id suffix SCRIPT_ID_SUFFIX.HIGH_RISK) and a HEADER/DNR-
// mechanism protection via an extra, level-independent DNR rule (core/rule-builder.js highRiskHeaderRules /
// highRiskDnrRules). The dynamic half (this session's own PHISHING verdict) can only reach HEADER/DNR/NAVIGATION/
// DOWNLOAD-mechanism protections — they decide per request/download, when the verdict is already known — via a
// SECOND, independent tab band (core/policy.js highRiskTabGroups, data/constants.js HIGH_RISK_GROUP_INDEX/
// HIGH_RISK_TAB_BASE): a document_start SCRIPT-mechanism protection cannot be retroactively applied to a page
// whose scoring finishes only after the page already started running — that half of the coverage is deliberately
// left to the (always-on) static host list and to the OTHER protections' own request-time checks.
// "Continue once" on protection 13 only closes that ONE dialog — it does not touch disabledProtections or the
// scorer's verdict, so it never suppresses these.
//
// 4.7.1 (user request): blockConsentFix moved to the end of the "on every site" BLOCK-type protections (1–11),
// ahead of the WARN-type ones that follow — was 15, now 12. Renumbered: 12→13 (warnSuspiciousSites), 13→14
// (warnRiskyDownloads), 14→15 (warnPasswordForms); 16 (warnDeviceCodePages) unchanged. Keys unchanged (contract);
// every "protection N" reference meaning the OLD number swept to the new one in the same change, as in 4.6.0/4.7.0.
//
// 5.0.2: ported from the sibling uBlock-Stripped-Dynamic project, which it was originally (mistakenly) built for —
// "Warn about a fake payment-pixel overlay (skimmer scams)" (warnPaymentSkimmer, num 17) — a "SuperPixel"/Magecart
// payment-skimmer detector. On by default (ticked), warn-only. Added to the end of the "on every site" WARN-type
// group (after warnDeviceCodePages), the same slot pattern 4.7.1 established for that group. Renumbered: 17–31 →
// 18–32 (keys unchanged); every "protection N" reference meaning the OLD number swept to the new one in the same
// change, as in 4.6.0/4.7.0/4.7.1 — a past CHANGELOG_HISTORY.md/CHANGELOG.md entry or the audit doc describing an
// older release keeps ITS OLD numbers.
//
// 5.0.6 (user request): "Warn about a fake sign-in window drawn on a page" (blockFakeSignInWindow) moved from 30 to
// 18 so the "on every site" level-2 group (1–18) runs without a gap; the level-3 group 18–29 → 19–30. Keys unchanged
// (contract), so saved ticks carry over; every "protection N" reference meaning the OLD number swept to the new one
// BY MEANING in the same change, as in 4.6.0–5.0.2.
//
// 5.0.7 (audit of 5.0.6): the display order is defined once (protectionsInGroup / PROTECTIONS_IN_DISPLAY_ORDER,
// below) and tools/check-protection-keys.mjs requires `num` = position in it — before, the check only verified
// "unique, 1…N, no gaps", which is how 4.7.0's blockFakeSignInWindow sat at 30 in a list reading 1–17, 30. And from
// 5.0.7 on, code, tests and README name a protection by its KEY — this header is the only place outside the
// changelogs where display numbers are written (tools/check-protection-refs.mjs, C25).
//
// Fields
//   key        storage key in state.disabledProtections (never rename — it is a contract)
//   num        display number (1 … PROTECTIONS.length) = position in PROTECTIONS_IN_DISPLAY_ORDER (5.0.7)
//   label      popup text — a short, plain-language phrase; may wrap to two lines (0.2.4)
//   fromLevel  first level at which it applies (LEVEL.MILD or LEVEL.SMART)
//   scope      SCOPE.EVERY_SITE | SCOPE.OUTSIDE_SAFER_REGIONS (the latter only differs at
//              level 3 — levels 4–5 apply it on every site, see SAFER_REGIONS_LEVELS)
//   mechanism  MECH.* — which builder implements it (several may apply)
//   scripts    content-script files (MAIN world, all frames, document_start)
//   (4.7.0) a protection may have only `isolatedScripts` (no MAIN-world half), e.g. the ConsentFix paste guard
//   isolatedScripts optional content-script files for the ISOLATED world (4.6.0) — same scope as `scripts`,
//              for code that must talk to the service worker (MAIN-world code cannot)
//   matchHosts optional fixed host list the scripts are limited to
//   extraExcludes optional extra excludeMatches patterns
//   defaultOff optional true = unticked on install, on reset and for states that predate it (4.3.2)
//   trustedExempt optional host list exempt from this protection on a first-party visit, at
//              BUILTIN_EXEMPT_LEVELS only (scope OUTSIDE_SAFER_REGIONS protections always use the
//              whole built-in whitelist for this; this field is for EVERY_SITE protections)
//   alsoHighRisk (4.7.0) optional true = also applies on a high-risk site regardless of level/safer
//              regions (see the 4.7.0 comment above) — only meaningful for a protection whose
//              mechanism can act on a specific site/request (HEADER, DNR, SCRIPT, DOWNLOAD); never
//              set on a NAVIGATION-mechanism protection (warnSuspiciousSites, warnDeviceCodePages — they are their own gate already)
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, NOEVAL_EXTRA_EXCLUDES } from "./constants.js";
import { HIGH_RISK_HOSTNAMES } from "./network-data.js";
import { BUILTIN_PAYMENT } from "./builtin-domains.js";

export const SCOPE = Object.freeze({ EVERY_SITE: "every", OUTSIDE_SAFER_REGIONS: "outside" });
export const MECH  = Object.freeze({
  SCRIPT:  "script",    // content script(s)
  DNR:     "dnr",       // dynamic block/allow rules
  HEADER:  "header",    // dynamic modifyHeaders rules
  NAVIGATION: "navigation", // top-level navigation check (core/navigation-guard.js) — no rules/scripts
  DOWNLOAD:   "download"    // finished-download check (core/download-guard.js) — no rules/scripts
});

// Every protection key, once (4.2.3, audit finding 8). Code refers to a protection ONLY through this
// enum — a typo is then a ReferenceError-like `undefined` that tools/check-protection-keys.mjs and
// isProtectionActive()'s guard both catch, never a silently disabled protection.
// Values are storage keys in state.disabledProtections — never rename a value (contract).
export const PROTECTION_KEY = Object.freeze({
  BLOCK_PAYMENT_HANDLERS:  "blockPaymentHandlers",
  BLOCK_WEB_BUNDLES:       "blockWebBundles",
  BLOCK_DIALOG_SPAM:       "blockDialogSpam",
  BLOCK_LOCAL_NETWORK:     "blockLocalNetwork",
  BLOCK_PROTOCOL_HANDLERS: "blockProtocolHandlers",
  BLOCK_SUSPICIOUS_3P:     "blockSuspicious3p",
  BLOCK_3P_HTTP:           "block3pHttp",
  BLOCK_CLICK_FIX:         "blockClickFix",
  BLOCK_HIGH_RISK_EVAL:    "blockHighRiskEval",
  WARN_SUSPICIOUS_SITES:   "warnSuspiciousSites",
  BLOCK_ABUSED_TLDS:       "blockAbusedTlds",
  WARN_RISKY_DOWNLOADS:    "warnRiskyDownloads",
  BLOCK_SCP_PRIVACY:       "blockScpPrivacy",
  BLOCK_SCP_SECURITY:      "blockScpSecurity",
  BLOCK_SENSORS_NFC:       "blockSensorsNfc",
  BLOCK_OBFUSCATED_EVAL:   "blockObfuscatedEval",
  BLOCK_REDIRECTS_DIALOGS: "blockRedirectsDialogs",
  BLOCK_RISKY_DOWNLOADS:   "blockRiskyDownloads",
  BLOCK_OBFUSCATED_FUNCTION:    "blockObfuscatedFunction",
  BLOCK_OBFUSCATED_SETTIMEOUT:  "blockObfuscatedSetTimeout",
  BLOCK_OBFUSCATED_SETINTERVAL: "blockObfuscatedSetInterval",
  // 4.6.0
  BLOCK_EXFIL_MESSAGING_BOTS:   "blockExfilMessagingBots",
  WARN_PASSWORD_FORMS:          "warnPasswordForms",
  BLOCK_NOTIFICATION_PROMPTS:   "blockNotificationPrompts",
  BLOCK_EXFIL_WEB_SERVICES:     "blockExfilWebServices",
  // 4.7.0
  BLOCK_CONSENT_FIX:            "blockConsentFix",
  WARN_DEVICE_CODE_PAGES:       "warnDeviceCodePages",
  BLOCK_FAKE_SIGNIN_WINDOW:     "blockFakeSignInWindow",
  // 5.0.2
  WARN_PAYMENT_SKIMMER:         "warnPaymentSkimmer",
  // 4.7.0 — "Level 4–5 only" group
  BLOCK_WEBSOCKETS:             "blockWebsockets",
  BLOCK_WEBTRANSPORT:           "blockWebtransport",
  BLOCK_WEBASSEMBLY:            "blockWebAssembly",
  BLOCK_WASM_DUBIOUS:           "blockWasmDubious"     // 5.0.5
  // BLOCK_INLINE_SCRIPTS ("blockInlineScripts") removed in 4.7.6 — see the 4.7.0/4.7.6 comment above.
});

export const PROTECTION_GROUPS = Object.freeze([
  Object.freeze({ title: "On every site",          fromLevel: LEVEL.MILD }),
  // titleNoSaferRegions: shown at levels where the safer-regions list has no effect (4–5)
  Object.freeze({ title: "Outside safer regions",  titleNoSaferRegions: "Extra — outside safer regions", fromLevel: LEVEL.SMART }),
  // 4.7.0: these four never had a "safer regions" phase (fromLevel is already past it) — one fixed title.
  Object.freeze({ title: "Level 4–5 only — extra web-platform blocks", fromLevel: LEVEL.HIGH })
]);

export const PROTECTIONS = Object.freeze([
  { key: PROTECTION_KEY.BLOCK_PAYMENT_HANDLERS,  num: 1,  label: "Block sites from registering a fake payment handler", description: "Stops a page from secretly registering as a payment handler that could intercept or alter your payments.",   fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], scripts: ["security/sec-payment-handlers.js"], trustedExempt: BUILTIN_PAYMENT },
  { key: PROTECTION_KEY.BLOCK_WEB_BUNDLES,       num: 2,  label: "Block Web Bundles (bundled resources that hide code)", description: "Blocks Web Bundle (.wbn) files — a packaging format that can hide malicious code from inspection.",  fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  // 4.6.0: + sec-browser-locker.js (keyboard lock, fullscreen re-entry, "Leave site?" trap, history trap). Key kept (contract).
  { key: PROTECTION_KEY.BLOCK_DIALOG_SPAM,       num: 3,  label: "Block browser-locker scams (popups, keyboard lock)", description: "Blocks browser-locker scams: endless popups, keyboard-lock tricks and fake full-screen support traps.",    fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], scripts: ["security/sec-alertbuster.js", "security/sec-dialogbuster.js", "security/sec-browser-locker.js"] },
  { key: PROTECTION_KEY.BLOCK_LOCAL_NETWORK,     num: 4,  label: "Block pages from reaching your local network", description: "Stops web pages from probing or connecting to devices on your local network.",          fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_PROTOCOL_HANDLERS, num: 5,  label: "Block sites from registering custom protocol handlers", description: "Stops sites from registering themselves as the handler for links like mailto: or crypto-wallet URIs.", fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], scripts: ["security/sec-protocol-handlers.js"] },
  { key: PROTECTION_KEY.BLOCK_SUSPICIOUS_3P,     num: 6,  label: "Block 3P requests to raw IPs, odd ports or DDNS hosts", description: "Blocks third-party requests to raw IPs, odd ports or dynamic-DNS hosts — rare for legitimate services.", fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_3P_HTTP,           num: 7,  label: "Block 3P requests sent over plain, unencrypted HTTP", description: "Blocks third-party requests sent over plain, unencrypted HTTP instead of HTTPS.",   fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_CLICK_FIX,         num: 8,  label: "Block ClickFix-style clipboard hijacking scams", description: "Blocks ClickFix scams that trick you into pasting malicious clipboard commands into Run or a terminal.",        fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], scripts: ["security/sec-clickfix-clipboard.js"], isolatedScripts: ["security/clickfix-bridge.js"] },   // 4.7.0: + bridge → warning
  { key: PROTECTION_KEY.BLOCK_HIGH_RISK_EVAL,     num: 9,  label: "Block eval() on known high-risk (adult) sites", description: "Blocks eval() specifically on sites known for risky (adult) content.",         fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT, MECH.HEADER], scripts: ["security/sec-adult-noeval.js"], matchHosts: HIGH_RISK_HOSTNAMES },
  { key: PROTECTION_KEY.BLOCK_ABUSED_TLDS, num: 10, label: "Block 3P scripts and frames from abused TLDs", description: "Blocks third-party scripts and frames from top-level domains disproportionately used for abuse — at levels 2–3 also their WebSocket and WebTransport connections.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.DNR] },
  // 4.6.0: block + site warning (core/exfil-guard.js); channels in data/exfil-channels.js.
  { key: PROTECTION_KEY.BLOCK_EXFIL_MESSAGING_BOTS, num: 11, label: "Block exfiltrating (phishing) data to messaging bots", description: "Blocks a page sending your data to Telegram, Discord or similar bot endpoints — a common phishing channel.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.DNR] },
  // 4.7.1 (user request): moved here, to the end of the "on every site" BLOCK-type protections, ahead of
  // the WARN-type ones (warnSuspiciousSites … blockFakeSignInWindow) that follow. ISOLATED world only (security/consentfix-paste-guard.js);
  // the warning itself goes through core/page-scam-guard.js.
  { key: PROTECTION_KEY.BLOCK_CONSENT_FIX,       num: 12, label: "Block pasting a sign-in address into a website", description: "Blocks ConsentFix scams that trick you into pasting your own sign-in address into a fake consent box.",      fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], isolatedScripts: ["security/consentfix-paste-guard.js"] },
  { key: PROTECTION_KEY.WARN_SUSPICIOUS_SITES, num: 13, label: "Warn when opening a site that looks suspicious", description: "Warns before you continue onto a site that scores as suspicious: a lookalike domain or brand impersonation.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.NAVIGATION] },
  { key: PROTECTION_KEY.WARN_RISKY_DOWNLOADS,    num: 14, label: "Warn when a downloaded file looks risky", description: "Shows a warning page before an unfamiliar, risky-looking downloaded file (executable, script, archive) opens.",               fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DOWNLOAD] },
  // 4.6.0: MAIN-world hook catches form.submit() (no submit event); the ISOLATED script asks the service worker
  // (core/password-form.js) and shows the in-page warning.
  { key: PROTECTION_KEY.WARN_PASSWORD_FORMS,     num: 15, label: "Warn when a password form sends to another site", description: "Warns when a password field you're submitting will send its data to a different site than the one you're on.",       fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], scripts: ["security/sec-form-submit-hook.js"], isolatedScripts: ["security/password-form-guard.js"] },
  // 4.7.0: the site that SENT the user decides the level (core/device-code-guard.js); amber warning page.
  { key: PROTECTION_KEY.WARN_DEVICE_CODE_PAGES,  num: 16, label: "Warn when a site sends you to enter a sign-in code", description: "Warns before you enter a device sign-in code — a technique abused for account-hijacking phishing.",   fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.NAVIGATION] },
  // 5.0.2: "SuperPixel"/Magecart payment-skimmer check — MAIN-world detection (security/sec-skimmer-warn.js: a
  // fake Facebook-Pixel-loader domain mismatch, or a non-same-origin iframe overlapping a payment field), bridged
  // to the service worker exactly as ClickFix/ConsentFix are (isolatedScripts bridge → core/page-scam-guard.js).
  // Warn-only (never blocks) by design — the detector itself does not stop the page.
  { key: PROTECTION_KEY.WARN_PAYMENT_SKIMMER,    num: 17, label: "Warn about a fake payment-pixel overlay (skimmer scams)", description: "Warns when a page loads a fake tracking-pixel script or draws a payment overlay that doesn't belong to the site — a Magecart-style card-skimming scam.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], scripts: ["security/sec-skimmer-warn.js"], isolatedScripts: ["security/skimmer-bridge.js"] },
  // 4.7.0: own file (security/fake-window-guard.js) — NOT shared with warnPasswordForms, see that file's header for why.
  { key: PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW, num: 18, label: "Warn about a fake sign-in window drawn on a page", description: "Warns when a page draws a fake browser or OS sign-in window with HTML/CSS — a common phishing trick.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], isolatedScripts: ["security/fake-window-guard.js"] },
  { key: PROTECTION_KEY.BLOCK_SCP_PRIVACY,       num: 19, label: "Block camera, mic, screen-share and clipboard reads", description: "Blocks pages from reading your camera, microphone, screen contents or clipboard without asking you.",   fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_SCP_SECURITY,      num: 20, label: "Block Bluetooth, Serial, HID and USB device access", description: "Blocks pages from accessing Bluetooth, Serial, HID and USB devices connected to your computer.",    fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_SENSORS_NFC,       num: 21, label: "Block motion-sensor and NFC access", description: "Blocks pages from reading motion sensors or using NFC, which can fingerprint or track your device.",                    fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER, MECH.SCRIPT], scripts: ["security/sec-nfc.js"], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_NOTIFICATION_PROMPTS, num: 22, label: "Block notification prompts that appear without a click", description: "Blocks a notification-permission prompt from popping up the moment a page loads, before you've clicked anything.", fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT], scripts: ["security/sec-notification-prompts.js"], alsoHighRisk: true },   // 4.6.0
  { key: PROTECTION_KEY.BLOCK_REDIRECTS_DIALOGS, num: 23, label: "Block redirects and dialogs from frames", description: "Blocks embedded frames from redirecting the top page or opening dialogs without your interaction.",              fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_OBFUSCATED_EVAL,   num: 24, label: "Block obfuscated or disguised eval() calls", description: "Blocks eval() calls that use obfuscation to hide what code they're actually running.",            fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT], scripts: ["security/sec-noeval.js"], extraExcludes: NOEVAL_EXTRA_EXCLUDES, alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_OBFUSCATED_FUNCTION,    num: 25, label: "Block obfuscated Function() code generation", description: "Blocks the Function() constructor when used to run code from obfuscated, disguised strings.",        fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT], scripts: ["security/sec-nofunction.js"], extraExcludes: NOEVAL_EXTRA_EXCLUDES, alsoHighRisk: true },   // 4.4.3
  { key: PROTECTION_KEY.BLOCK_OBFUSCATED_SETTIMEOUT,  num: 26, label: "Block obfuscated setTimeout() string execution", description: "Blocks setTimeout() when used to execute a string of obfuscated code instead of a real function.",     fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT], scripts: ["security/sec-nosettimeout.js"], extraExcludes: NOEVAL_EXTRA_EXCLUDES, alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_OBFUSCATED_SETINTERVAL, num: 27, label: "Block obfuscated setInterval() string execution", description: "Blocks setInterval() when used to execute a string of obfuscated code instead of a real function.",    fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT], scripts: ["security/sec-nosetinterval.js"], extraExcludes: NOEVAL_EXTRA_EXCLUDES, alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_EXFIL_WEB_SERVICES, num: 28, label: "Block exfiltrating (phishing) data to web services", description: "Blocks a page sending your data to known phishing-exfiltration web services, and warns about the site.",   fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.DNR], alsoHighRisk: true },   // 4.6.0: block + site warning
  // 5.0.5 (user decision 2026-11-10): third-party WebAssembly from a DUBIOUS host (suspicious-hosting list, abused TLD)
  // on any TLD, or from a host OUTSIDE the safer regions — as a network rule, so it also holds inside workers (page
  // scripts cannot reach them; NoScript's shared-worker work prompted the check). Source-based, so it applies on
  // every page. Matches addresses ending in .wasm (Chrome 120-safe; the content-type label would need Chrome 128).
  { key: PROTECTION_KEY.BLOCK_WASM_DUBIOUS,      num: 29, label: "Block 3P WebAssembly from dubious or non-safer-region hosts", description: "Blocks WebAssembly (.wasm) that a page or its background workers load from a dubious host or from outside your safer regions.", fromLevel: LEVEL.SMART, scope: SCOPE.EVERY_SITE, mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_RISKY_DOWNLOADS,   num: 30, label: "Block risky downloads (programs, scripts, archives)", description: "Blocks risky downloads outright (not just a warning) — programs, scripts, archives. Off by default.",   fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.DOWNLOAD], defaultOff: true, alsoHighRisk: true },   // 4.7.0 (user correction): alsoHighRisk despite defaultOff — a high-risk site re-enables it for that site/visit only, the default stays off everywhere else
  // 4.7.0 — "Level 4–5 only" group (fromLevel: LEVEL.HIGH skips these groups' safer-regions phase entirely).
  // CSP-based (declarativeNetRequest modifyHeaders): core/rule-builder.js headerRules().
  { key: PROTECTION_KEY.BLOCK_WEBSOCKETS,        num: 31, label: "Block third-party WebSocket connections", description: "Blocks WebSocket connections to other origins (the page's own WebSockets still work) — sometimes used to exfiltrate data.",                          fromLevel: LEVEL.HIGH,   scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER, MECH.DNR], alsoHighRisk: true },
  // Attribute-stripping (MAIN-world script deletes window.WebTransport before page code runs) — CSP's connect-src
  // cannot separate WebTransport from ordinary fetch (both use the "https" scheme), see CSP_NO_WS_VALUE's comment.
  { key: PROTECTION_KEY.BLOCK_WEBTRANSPORT,      num: 32, label: "Block third-party WebTransport connections", description: "Blocks WebTransport connections to other origins (the page's own WebTransport still works).",                       fromLevel: LEVEL.HIGH,   scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT, MECH.DNR], scripts: ["security/sec-no-webtransport.js"], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_WEBASSEMBLY,       num: 33, label: "Block third-party WebAssembly", description: "Blocks WebAssembly fetched from other origins; WebAssembly the page loads itself keeps working.",                                    fromLevel: LEVEL.HIGH,   scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT, MECH.DNR], scripts: ["security/sec-no-wasm.js"], alsoHighRisk: true }
  // 4.7.6: "Block inline scripts (strict content policy)" (blockInlineScripts) removed here —
  // its CSP (script-src with no 'unsafe-inline', no nonce/hash) blocked a site's own legitimate inline
  // <script> tags the same as an injected one, so it broke most sites it ran on instead of protecting them.
].map((p) => Object.freeze(p)));

export const PROTECTION_KEYS = Object.freeze(PROTECTIONS.map((p) => p.key));
// Protections that start unticked (install, reset, and states that predate them — STATE_MIGRATIONS).
export const DEFAULT_OFF_KEYS = Object.freeze(PROTECTIONS.filter((p) => p.defaultOff).map((p) => p.key));
export const PROTECTION_BY_KEY = Object.freeze(Object.fromEntries(PROTECTIONS.map((p) => [p.key, p])));
// 5.0.7 — the ONE definition of which protections a group shows and in what order (C21: the settings page,
// the popup and tools/check-protection-keys.mjs all read this; nobody re-derives it). A group shows the rows
// whose fromLevel is the group's, in registry order; groups follow PROTECTION_GROUPS' order. `num` must equal
// a protection's position in PROTECTIONS_IN_DISPLAY_ORDER (checked by tools/check-protection-keys.mjs).
export function protectionsInGroup(group) {
  return PROTECTIONS.filter((p) => p.fromLevel === group.fromLevel);
}
export const PROTECTIONS_IN_DISPLAY_ORDER = Object.freeze(PROTECTION_GROUPS.flatMap(protectionsInGroup));
