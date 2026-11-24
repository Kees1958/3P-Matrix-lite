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
// string-handler block like protection 9's fixed-host-list sec-adult-noeval.js (gone since 5.1.3). Old saved states
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
// 5.1.0 (user decisions 2026-11-23): Tamper Guard, and one rule for the Protections page — a feature with its own tab
// owns its protections and its settings; the Browsing tab holds everything else. New field `tab` (PROTECTION_TAB);
// groups are now per tab (PROTECTION_GROUPS rows carry their tab) and the display order is tab order, then group
// order, then registry order. warnRiskyDownloads and blockRiskyDownloads moved to the Download tab (undoing the
// 4.7.0 move to the Browsing list, by decision); warnPasswordForms, warnPaymentSkimmer and blockFakeSignInWindow moved
// to the new Tamper Guard tab, which also holds the three new Tamper Guard protections: "Watch banking and payment
// pages for tampering" (watchTamperSensitive, level 2), "Also watch pages after a tampering sign"
// (watchTamperAfterSign, level 3) and "Always watch pages for tampering" (watchTamperAlways, level 4). New field
// `requires` (a master protection): blockRiskyDownloads now requires warnRiskyDownloads, and the two wider Tamper
// Guard options require watchTamperSensitive (it owns the page scripts). Renumbered by display order — keys unchanged
// (contract), so saved ticks carry over: 1–13 unchanged, 16→14, 19–29→15–25, 31–33→26–28 (Browsing); 14→29, 30 stays
// (Download).
// 5.1.0 (user decision 2026-11-23, same release): Tamper Protection is ONE switch. watchTamperSensitive is shown as
// "Enable tamper protection"; the two wider options (watchTamperAfterSign, watchTamperAlways) are gone as protections —
// the level slider widens the watching at TAMPER_LEVEL.AFTER_SIGN and TAMPER_LEVEL.ALWAYS (data/constants.js).
// warnPasswordForms, warnPaymentSkimmer and blockFakeSignInWindow can no longer be switched off one by one
// (`switchable: false`, `requires` the master): they run whenever tamper protection is on and are listed as Critical
// findings on the Tamper Protection tab. Only the Browsing tab is numbered (PROTECTION_TAB_NUMBERED; the Download tab too until the owner dropped it in 5.1.0);
// the Tamper Protection tab has no numbers. An old untick of one of those three is dropped (normalizeState).
// 5.1.2 (user decision 2026-11-23): the Browsing list reordered within each level group — network → risky web
// technology → scams (the two "paste this" scams together) → data theft → warnings. New "Warn when another site sends
// you a link with script code in it" (warnXssLinks, level 2, last of that group). Renumbered by display order — keys
// unchanged (contract), so saved ticks carry over: level 2 (old→new) 4→1, 6→2, 7→3, 10→4, 2→5, 1→6, 5→7, 9→8, 3→9,
// 8→10, 12→11, 11→12, 13 and 14 unchanged, new 15; level 3 25→16, 15–17→17–19, 20–23 → ONE protection 20
// (blockObfuscatedFunction / -SetTimeout / -SetInterval merged into blockObfuscatedEval, one scriptlet
// security/sec-no-obfuscated-code.js; an old untick of the three dropped keys is dropped by normalizeState), 18→21,
// 19→22, 24→23; level 4–5 26–28→24–26. 26 numbered. Nothing between 5.1.0 and 5.1.2 was released.
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
//   tab        (5.1.0) optional PROTECTION_TAB.* — the Protections-page tab that lists it; absent = BROWSING (tabOf())
//   requires   (5.1.0) optional PROTECTION_KEY.* of a master protection: unticking the master switches this one
//              off too (core/policy.js isProtectionEnabled). The master's fromLevel is never above this one's
//              (tools/check-protection-keys.mjs), so "requires" is about the tick only, never about levels.
//   switchable (5.1.0) optional false = no checkbox of its own: on exactly when its master (`requires`) is on; not
//              numbered, not listed as a checkbox; its stored untick is dropped (data/state-storage.js).
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, NOEVAL_EXTRA_EXCLUDES } from "./constants.js";
import { BUILTIN_PAYMENT } from "./builtin-domains.js";

export const SCOPE = Object.freeze({ EVERY_SITE: "every", OUTSIDE_SAFER_REGIONS: "outside" });
export const MECH  = Object.freeze({
  SCRIPT:  "script",    // content script(s)
  DNR:     "dnr",       // dynamic block/allow rules
  HEADER:  "header",    // dynamic modifyHeaders rules
  NAVIGATION: "navigation", // top-level navigation check (core/navigation-guard.js) — no rules/scripts
  DOWNLOAD:   "download",   // finished-download check (core/download-guard.js) — no rules/scripts
  TAMPER:     "tamper"      // 5.1.0: decided by core/tamper-guard.js from the page reports — no rules/scripts of its own
});

// 5.1.0 — the Protections-page tabs that list protections, in display order (ui/protections.js renders one list per tab).
// 5.1.3: + SCAM (Scam protection — one switch, one bundle); BROWSING is shown as "Firewall protection" (value kept).
export const PROTECTION_TAB = Object.freeze({ BROWSING: "browsing", DOWNLOAD: "download", SCAM: "scam", TAMPER: "tamper" });
export const PROTECTION_TAB_ORDER = Object.freeze([PROTECTION_TAB.BROWSING, PROTECTION_TAB.DOWNLOAD, PROTECTION_TAB.SCAM, PROTECTION_TAB.TAMPER]);
// Tabs whose protections carry a display number (the Tamper Protection tab has one switch, no numbers).
export const PROTECTION_TAB_NUMBERED = Object.freeze([PROTECTION_TAB.BROWSING]);   // 5.1.0: Download tab unnumbered too (owner)

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
  WARN_SUSPICIOUS_SITES:   "warnSuspiciousSites",
  BLOCK_ABUSED_TLDS:       "blockAbusedTlds",
  WARN_RISKY_DOWNLOADS:    "warnRiskyDownloads",
  BLOCK_SCP_PRIVACY:       "blockScpPrivacy",
  BLOCK_SCP_SECURITY:      "blockScpSecurity",
  BLOCK_OBFUSCATED_EVAL:   "blockObfuscatedEval",
  BLOCK_REDIRECTS_DIALOGS: "blockRedirectsDialogs",
  BLOCK_RISKY_DOWNLOADS:   "blockRiskyDownloads",
  // 4.6.0
  BLOCK_EXFIL_MESSAGING_BOTS:   "blockExfilMessagingBots",
  WARN_PASSWORD_FORMS:          "warnPasswordForms",
  BLOCK_NOTIFICATION_PROMPTS:   "blockNotificationPrompts",
  BLOCK_EXFIL_WEB_SERVICES:     "blockExfilWebServices",
  // 4.7.0
  BLOCK_CONSENT_FIX:            "blockConsentFix",
  WARN_DEVICE_CODE_PAGES:       "warnDeviceCodePages",
  WARN_XSS_LINKS:               "warnXssLinks",          // 5.1.2
  ENABLE_SCAM_PROTECTION:       "enableScamProtection",  // 5.1.3 — the Scam protection tab's switch (owns its bundles)
  BLOCK_SHARED_CODES:           "blockSharedCodes",      // 5.1.3 — never-share codes
  BLOCK_FAKE_SIGNIN_WINDOW:     "blockFakeSignInWindow",
  // 5.0.2
  WARN_PAYMENT_SKIMMER:         "warnPaymentSkimmer",
  // 4.7.0 — "Level 4–5 only" group
  BLOCK_WEBSOCKETS:             "blockWebsockets",
  BLOCK_WEBTRANSPORT:           "blockWebtransport",
  BLOCK_WEBASSEMBLY:            "blockWebAssembly",
  BLOCK_WASM_DUBIOUS:           "blockWasmDubious",    // 5.0.5
  // BLOCK_INLINE_SCRIPTS ("blockInlineScripts") removed in 4.7.6 — see the 4.7.0/4.7.6 comment above.
  // 5.1.0 — Tamper Guard (core/tamper-guard.js)
  WATCH_TAMPER_SENSITIVE:       "watchTamperSensitive",  // shown as "Enable tamper detection" (5.1.3)
  // 5.1.3 — the triggers of the closer watching (core/tamper-guard.js), each a tick under the tamper switch
  TAMPER_ON_SENSITIVE:          "tamperOnSensitive",
  TAMPER_ON_HIDDEN_FIELD:       "tamperOnHiddenField",
  TAMPER_ON_CHECKOUT_WORDS:     "tamperOnCheckoutWords",
  TAMPER_ON_LOCKED_PAGES:       "tamperOnLockedPages"
});

// 5.1.0: groups are per tab — a group shows the rows of its tab whose fromLevel is the group's (protectionsInGroup).
// The order of this list IS the display order (tab order, then level).
export const PROTECTION_GROUPS = Object.freeze([
  Object.freeze({ tab: PROTECTION_TAB.BROWSING, title: "On every site",          fromLevel: LEVEL.MILD }),
  // titleNoSaferRegions: shown at levels where the safer-regions list has no effect (4–5)
  Object.freeze({ tab: PROTECTION_TAB.BROWSING, title: "Outside safer regions",  titleNoSaferRegions: "Extra — outside safer regions", fromLevel: LEVEL.SMART }),
  // 4.7.0: these four never had a "safer regions" phase (fromLevel is already past it) — one fixed title.
  Object.freeze({ tab: PROTECTION_TAB.BROWSING, title: "Level 4–5 only — extra web-platform blocks", fromLevel: LEVEL.HIGH }),
  Object.freeze({ tab: PROTECTION_TAB.DOWNLOAD, title: "On every site",          fromLevel: LEVEL.MILD }),
  Object.freeze({ tab: PROTECTION_TAB.DOWNLOAD, title: "Outside safer regions",  titleNoSaferRegions: "Extra — outside safer regions", fromLevel: LEVEL.SMART }),
  Object.freeze({ tab: PROTECTION_TAB.SCAM,     title: "Scam protection",        fromLevel: LEVEL.MILD }),   // 5.1.3
  Object.freeze({ tab: PROTECTION_TAB.SCAM,     title: "Scam protection — level 3 and up", fromLevel: LEVEL.SMART }),
  // 5.1.3 (owner): the switch and its four triggers under one heading
  Object.freeze({ tab: PROTECTION_TAB.TAMPER,   title: "Choose how tamper detection heuristics works", fromLevel: LEVEL.MILD }),
  // 5.1.3: blockObfuscatedEval moved here (level 3 and up, outside safer regions — its scope is unchanged)
  Object.freeze({ tab: PROTECTION_TAB.TAMPER,   title: "Tamper protection — level 3 and up", fromLevel: LEVEL.SMART })
]);

export const PROTECTIONS = Object.freeze([
  { key: PROTECTION_KEY.BLOCK_LOCAL_NETWORK,     num: 1,  label: "Block pages from reaching your local network", description: "Stops web pages from probing or connecting to devices on your local network.",          fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_SUSPICIOUS_3P,     num: 2,  label: "Block 3P requests to raw IPs, odd ports or DDNS hosts", description: "Blocks third-party requests to raw IPs, odd ports or dynamic-DNS hosts — rare for legitimate services.", fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_3P_HTTP,           num: 3,  label: "Block 3P requests sent over plain, unencrypted HTTP", description: "Blocks third-party requests sent over plain, unencrypted HTTP instead of HTTPS.",   fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_ABUSED_TLDS, num: 4, label: "Block 3P scripts and frames from abused TLDs", description: "Blocks third-party scripts and frames from top-level domains disproportionately used for abuse — at levels 2–3 also their WebSocket and WebTransport connections.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_WEB_BUNDLES,       num: 5,  label: "Block Web Bundles (bundled resources that hide code)", description: "Blocks Web Bundle (.wbn) files — a packaging format that can hide malicious code from inspection.",  fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_PAYMENT_HANDLERS,  label: "Block sites from registering a fake payment handler", description: "Stops a page from secretly registering as a payment handler that could intercept or alter your payments.",   fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  { key: PROTECTION_KEY.BLOCK_PROTOCOL_HANDLERS, label: "Block sites from registering custom protocol handlers", description: "Stops sites from registering themselves as the handler for links like mailto: or crypto-wallet URIs.", fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  // 4.6.0: + sec-browser-locker.js (keyboard lock, fullscreen re-entry, "Leave site?" trap, history trap). Key kept (contract).
  { key: PROTECTION_KEY.BLOCK_DIALOG_SPAM,       label: "Block browser-locker scams (popups, keyboard lock)", description: "Blocks browser-locker scams: endless popups, keyboard-lock tricks and fake full-screen support traps.",    fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  { key: PROTECTION_KEY.BLOCK_CLICK_FIX,         label: "Block ClickFix-style clipboard hijacking scams", description: "Blocks ClickFix scams that trick you into pasting malicious clipboard commands into Run or a terminal.",        fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },   // 4.7.0: + bridge → warning
  // 4.7.1: ISOLATED world only (security/consentfix-paste-guard.js); the warning goes through core/page-scam-guard.js.
  // 5.1.2 (user decision): next to blockClickFix — both are "paste this" scams.
  { key: PROTECTION_KEY.BLOCK_CONSENT_FIX,       label: "Block pasting a sign-in address into a website", description: "Blocks ConsentFix scams that trick you into pasting your own sign-in address into a fake consent box.",      fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  // 4.6.0: block + site warning (core/exfil-guard.js); channels in data/exfil-channels.js.
  { key: PROTECTION_KEY.BLOCK_EXFIL_MESSAGING_BOTS, num: 6, label: "Block exfiltrating (phishing) data to messaging bots", description: "Blocks a page sending your data to Telegram, Discord or similar bot endpoints — a common phishing channel.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.WARN_SUSPICIOUS_SITES, label: "Warn when opening a site that looks suspicious", description: "Warns before you continue onto a site that scores as suspicious: a lookalike domain or brand impersonation.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.NAVIGATION], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  // 4.7.0: the site that SENT the user decides the level (core/device-code-guard.js); amber warning page.
  { key: PROTECTION_KEY.WARN_DEVICE_CODE_PAGES,  label: "Warn when a site sends you to enter a sign-in code", description: "Warns before you enter a device sign-in code — a technique abused for account-hijacking phishing.",   fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.NAVIGATION], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  // 5.1.2 (user decision): reflected XSS from a link — another website (the request's `initiator`, as warnDeviceCodePages)
  // opens a page whose address carries script markup (data/constants.js XSS_MARKUP_PATTERNS). Amber warning page,
  // "Continue once" (core/xss-link-guard.js). The DOM-XSS half is a Tamper Protection finding (tgAddressScript).
  { key: PROTECTION_KEY.WARN_XSS_LINKS,          label: "Warn when another site sends you a link with script code in it", description: "Warns before a page opens from another site's link whose address carries script code — the trick behind cross-site scripting (XSS) attacks on sites you are signed in to.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.NAVIGATION], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  { key: PROTECTION_KEY.WARN_RISKY_DOWNLOADS,    label: "Warn when a downloaded file looks risky", description: "Shows a warning page before an unfamiliar, risky-looking downloaded file (executable, script, archive) opens.",               fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.DOWNLOAD], tab: PROTECTION_TAB.DOWNLOAD },
  // 4.6.0: MAIN-world hook catches form.submit() (no submit event); the ISOLATED script asks the service worker
  // (core/password-form.js) and shows the in-page warning.
  { key: PROTECTION_KEY.WARN_PASSWORD_FORMS,     label: "Warn when a password form sends to another site", description: "Warns when a password field you're submitting will send its data to a different site than the one you're on.",       fromLevel: LEVEL.MILD,   scope: SCOPE.EVERY_SITE,        mechanism: [MECH.SCRIPT], scripts: ["security/sec-form-submit-hook.js"], isolatedScripts: ["security/password-form-guard.js"], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE, switchable: false },
  // 5.0.2: "SuperPixel"/Magecart payment-skimmer check — MAIN-world detection (security/sec-skimmer-warn.js: a
  // fake Facebook-Pixel-loader domain mismatch, or a non-same-origin iframe overlapping a payment field), bridged
  // to the service worker exactly as ClickFix/ConsentFix are (isolatedScripts bridge → core/page-scam-guard.js).
  // Warn-only (never blocks) by design — the detector itself does not stop the page.
  { key: PROTECTION_KEY.WARN_PAYMENT_SKIMMER,    label: "Warn about a fake payment-pixel overlay (skimmer scams)", description: "Warns when a page loads a fake tracking-pixel script or draws a payment overlay that doesn't belong to the site — a Magecart-style card-skimming scam.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], scripts: ["security/sec-skimmer-warn.js"], isolatedScripts: ["security/skimmer-bridge.js"], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE, switchable: false },
  // 4.7.0: own file (security/fake-window-guard.js) — NOT shared with warnPasswordForms, see that file's header for why.
  { key: PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW, label: "Warn about a fake sign-in window drawn on a page", description: "Warns when a page draws a fake browser or OS sign-in window with HTML/CSS — a common phishing trick.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], isolatedScripts: ["security/fake-window-guard.js"], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE, switchable: false },
  // 5.0.5 (user decision 2026-11-10): third-party WebAssembly from a DUBIOUS host (suspicious-hosting list, abused TLD)
  // on any TLD, or from a host OUTSIDE the safer regions — as a network rule, so it also holds inside workers (page
  // scripts cannot reach them; NoScript's shared-worker work prompted the check). Source-based, so it applies on
  // every page. Matches addresses ending in .wasm (Chrome 120-safe; the content-type label would need Chrome 128).
  { key: PROTECTION_KEY.BLOCK_WASM_DUBIOUS,      num: 7, label: "Block 3P WebAssembly from dubious or non-safer-region hosts", description: "Blocks WebAssembly (.wasm) that a page or its background workers load from a dubious host or from outside your safer regions.", fromLevel: LEVEL.SMART, scope: SCOPE.EVERY_SITE, mechanism: [MECH.DNR] },
  { key: PROTECTION_KEY.BLOCK_SCP_PRIVACY,       num: 8, label: "Block camera, mic, screen-share and clipboard reads", description: "Blocks pages from reading your camera, microphone, screen contents or clipboard without asking you.",   fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_SCP_SECURITY,      num: 9, label: "Block Bluetooth, Serial, HID, USB and motion-sensor access", description: "Blocks pages from accessing Bluetooth, Serial, HID and USB devices connected to your computer, and from reading motion sensors (a way to fingerprint your device).",    fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER], alsoHighRisk: true },
  // 5.1.2 (user decision): the former four obfuscation protections (eval, Function, setTimeout, setInterval) are ONE
  // protection with one scriptlet; the eval key is kept (contract), so its tick carries over.
  // 5.1.3 (user decisions 2026-11-24): moved to the Tamper Protection tab (on with "Enable tamper detection", same scope
  // as before). blockHighRiskEval (every eval on known high-risk sites) is gone, and so is this protection's
  // high-risk-site escalation; instead plain eval() — not Function, not timers — is blocked on every site at level 5
  // (strictScripts / strictFromLevel, core/script-builder.js). Planned: a tamper signal when it blocks (step 4).
  { key: PROTECTION_KEY.BLOCK_OBFUSCATED_EVAL,   label: "Block obfuscated code execution (eval, Function, timers)", description: "Blocks eval(), Function() and string setTimeout()/setInterval() calls that run obfuscated, disguised code; ordinary code is never touched. At level 5 every eval() is blocked.", fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT], scripts: ["security/sec-no-obfuscated-code.js"], extraExcludes: NOEVAL_EXTRA_EXCLUDES, strictScripts: ["security/sec-no-eval-strict.js"], strictFromLevel: LEVEL.STRICT, tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE, switchable: false },
  { key: PROTECTION_KEY.BLOCK_NOTIFICATION_PROMPTS, label: "Block notification prompts that appear without a click", description: "Blocks a notification-permission prompt from popping up the moment a page loads, before you've clicked anything.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },   // 4.6.0
  { key: PROTECTION_KEY.BLOCK_REDIRECTS_DIALOGS, label: "Block redirects and dialogs from frames", description: "Blocks embedded frames from redirecting the top page or opening dialogs without your interaction.",              fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER], alsoHighRisk: true, tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  { key: PROTECTION_KEY.BLOCK_EXFIL_WEB_SERVICES, num: 10, label: "Block exfiltrating (phishing) data to web services", description: "Blocks a page sending your data to known phishing-exfiltration web services, and warns about the site.",   fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.DNR], alsoHighRisk: true },   // 4.6.0: block + site warning
  { key: PROTECTION_KEY.BLOCK_RISKY_DOWNLOADS,   label: "Block risky downloads (programs, scripts, archives)", description: "Blocks risky downloads outright (not just a warning) — programs, scripts, archives. Off by default.",   fromLevel: LEVEL.SMART, scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.DOWNLOAD], defaultOff: true, alsoHighRisk: true, tab: PROTECTION_TAB.DOWNLOAD, requires: PROTECTION_KEY.WARN_RISKY_DOWNLOADS },   // 4.7.0 (user correction): alsoHighRisk despite defaultOff — a high-risk site re-enables it for that site/visit only, the default stays off everywhere else
  // 4.7.0 — "Level 4–5 only" group (fromLevel: LEVEL.HIGH skips these groups' safer-regions phase entirely).
  // CSP-based (declarativeNetRequest modifyHeaders): core/rule-builder.js headerRules().
  { key: PROTECTION_KEY.BLOCK_WEBSOCKETS,        num: 11, label: "Block third-party WebSocket connections", description: "Blocks WebSocket connections to other origins (the page's own WebSockets still work) — sometimes used to exfiltrate data.",                          fromLevel: LEVEL.HIGH,   scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.HEADER, MECH.DNR], alsoHighRisk: true },
  // Attribute-stripping (MAIN-world script deletes window.WebTransport before page code runs) — CSP's connect-src
  // cannot separate WebTransport from ordinary fetch (both use the "https" scheme), see CSP_NO_WS_VALUE's comment.
  { key: PROTECTION_KEY.BLOCK_WEBTRANSPORT,      num: 12, label: "Block third-party WebTransport connections", description: "Blocks WebTransport connections to other origins (the page's own WebTransport still works).",                       fromLevel: LEVEL.HIGH,   scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.DNR], alsoHighRisk: true },
  { key: PROTECTION_KEY.BLOCK_WEBASSEMBLY,       num: 13, label: "Block third-party WebAssembly", description: "Blocks WebAssembly fetched from other origins; WebAssembly the page loads itself keeps working.",                                    fromLevel: LEVEL.HIGH,   scope: SCOPE.OUTSIDE_SAFER_REGIONS, mechanism: [MECH.SCRIPT, MECH.DNR], scripts: ["security/sec-no-wasm.js"], alsoHighRisk: true },
  // 5.1.0 — Tamper Protection (core/tamper-guard.js, data/tamper-rules.js), ONE switch. It owns the two page scripts:
  // the MAIN-world half saves the original built-ins at document_start and reports what changed; the ISOLATED half
  // reports the page's banking/payment signals and arms the closer watching; the level slider widens where it is armed.
  // Warn-only: never blocks. No trustedExempt — a recognised bank is exactly the page to watch.
  // 5.1.3 (user decisions 2026-11-24): Scam protection — ONE switch that owns two bundles (one injection per world
  // instead of 6–8): security/scam-guard-page.js (MAIN: browser-locker, ClickFix, notification prompts, payment and
  // protocol handlers) and security/scam-guard-bridge.js (ISOLATED: ClickFix bridge, ConsentFix, never-share codes).
  // The rows under it are not switchable; the navigation warnings and the frames header follow the switch too.
  // trustedExempt BUILTIN_PAYMENT: the payment hosts' first-party exemption of the former blockPaymentHandlers (levels
  // 3–4) now applies to the whole bundle there.
  { key: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, label: "Enable scam protection", description: "Stops tricks aimed at you: dangerous links, fake browser lock-ups, paste-this-command scams and requests for your one-time codes.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], scripts: ["security/scam-guard-page.js"], isolatedScripts: ["security/scam-guard-bridge.js"], trustedExempt: BUILTIN_PAYMENT, tab: PROTECTION_TAB.SCAM },
  { key: PROTECTION_KEY.BLOCK_SHARED_CODES, label: "Block pasting a one-time or recovery code into a message", description: "Stops you pasting a one-time sign-in code, 2FA code or recovery code into a chat, mail or other message box — the \u201csomeone on the phone asks for your code\u201d scam.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT], tab: PROTECTION_TAB.SCAM, requires: PROTECTION_KEY.ENABLE_SCAM_PROTECTION, switchable: false },
  { key: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE,  label: "Enable tamper detection", description: "Warns, with a risk rating, when something changes how a page works or sends your password, card number or IBAN elsewhere. The ticks below choose which pages are watched closely; levels 3–5 add more pages. Also covers the password-form, payment-skimmer and fake sign-in-window warnings.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.SCRIPT, MECH.TAMPER], scripts: ["security/tamper-guard-page.js"], isolatedScripts: ["security/tamper-guard-bridge.js"], tab: PROTECTION_TAB.TAMPER },
  // 5.1.3 — when tamper detection watches a page closely (core/tamper-guard.js ARMED_BY). Each its own tick, all
  // requiring the switch; decided in the service worker from the page's signals — no scripts of their own.
  { key: PROTECTION_KEY.TAMPER_ON_SENSITIVE,       label: "Enable on banking and payment pages", description: "Watches a page closely when it is a known bank or payment site, embeds a payment provider, or has a card or IBAN field.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.TAMPER], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE },
  { key: PROTECTION_KEY.TAMPER_ON_HIDDEN_FIELD,    label: "Enable when a hidden password or card field is added", description: "Watches a page closely when it holds a password or card field hidden as a trick — a hidden field named like one, or a field made invisible while the form around it is visible. Fields in closed menus, dialogs or sign-in steps do not count. A way to collect what your browser fills in.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.TAMPER], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE },
  { key: PROTECTION_KEY.TAMPER_ON_CHECKOUT_WORDS,  label: "Enable on pages with checkout and payment keywords", description: "Watches a page closely from the start when its address has a checkout, cart or payment word (EU languages), before a skimmer loaded later can act.", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.TAMPER], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE },
  { key: PROTECTION_KEY.TAMPER_ON_LOCKED_PAGES,    label: "Enable on locked pages", description: "Watches pages of sites you locked to a level closely (a site locked at level 1, trusted, is never watched).", fromLevel: LEVEL.MILD, scope: SCOPE.EVERY_SITE, mechanism: [MECH.TAMPER], tab: PROTECTION_TAB.TAMPER, requires: PROTECTION_KEY.WATCH_TAMPER_SENSITIVE },
  // 4.7.6: "Block inline scripts (strict content policy)" (blockInlineScripts) removed here —
  // its CSP (script-src with no 'unsafe-inline', no nonce/hash) blocked a site's own legitimate inline
  // <script> tags the same as an injected one, so it broke most sites it ran on instead of protecting them.
].map((p) => Object.freeze(p)));

export const PROTECTION_KEYS = Object.freeze(PROTECTIONS.map((p) => p.key));
// Protections that start unticked (install, reset, and states that predate them — STATE_MIGRATIONS).
export const DEFAULT_OFF_KEYS = Object.freeze(PROTECTIONS.filter((p) => p.defaultOff).map((p) => p.key));
export const PROTECTION_BY_KEY = Object.freeze(Object.fromEntries(PROTECTIONS.map((p) => [p.key, p])));
// 5.1.0 — the tab a protection is listed on (absent field = the Browsing tab).
export function tabOf(p) {
  return p.tab || PROTECTION_TAB.BROWSING;
}
// 5.0.7 — the ONE definition of which protections a group shows and in what order (C21: the settings page,
// the popup and tools/check-protection-keys.mjs all read this; nobody re-derives it). A group shows the rows
// of its tab (5.1.0) whose fromLevel is the group's, in registry order; groups follow PROTECTION_GROUPS' order.
// `num` must equal a protection's position in PROTECTIONS_IN_DISPLAY_ORDER (checked by tools/check-protection-keys.mjs).
export function protectionsInGroup(group) {
  return PROTECTIONS.filter((p) => tabOf(p) === group.tab && p.fromLevel === group.fromLevel);
}
// 5.1.0: only switchable rows of numbered tabs are numbered and listed here; num = position in this list.
export function isNumbered(p) {
  return p.switchable !== false && PROTECTION_TAB_NUMBERED.includes(tabOf(p));
}
export const PROTECTIONS_IN_DISPLAY_ORDER = Object.freeze(PROTECTION_GROUPS.flatMap(protectionsInGroup).filter(isNumbered));
