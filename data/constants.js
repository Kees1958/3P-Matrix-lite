// ── data/constants.js ─────────────────────────────────────────────────────────
// 3P Matrix — content firewall
// THE single place for every switch, magic number, ID, priority, threshold,
// score, colour, storage key and timeout used by the extension. Pure data —
// never mutated at runtime (everything is frozen).
//
// Nothing else in the codebase may declare its own copy of a value that lives
// here; import it instead.
// ─────────────────────────────────────────────────────────────────────────────

import { AUTO_TLD_MODE } from "./tld-constants.js";
// DownloadSentinel's own constants (vendored, lib/downloadsentinel — 3.5.2 since 3P Matrix 4.4.0; 3.3.1 in 4.3.7–4.3.x). Where 3P Matrix and DS share a
// value (DNS providers, download defaults) it is taken FROM there, never re-typed (4.3.0, B2).
import { APP as DS_APP } from "../lib/downloadsentinel/util/AppConstants.js";
import { SCORING_CONFIG as DS_SCORING } from "../lib/downloadsentinel/protection/ScoringEngineV2.js";   // 4.4.0: single source for shared weights

// ── Identity ─────────────────────────────────────────────────────────────────
export const LOG_PREFIX = "[3PMCF]";

// ── Levels (enum + per-level presentation) ───────────────────────────────────
export const LEVEL = Object.freeze({
  ALLOW_ALL: 1,   // every protection off
  MILD:      2,   // the "on every site" group (e.g. blockAbusedTlds, blockExfilMessagingBots, blockConsentFix, warnSuspiciousSites, warnRiskyDownloads, warnPasswordForms, warnDeviceCodePages)
  SMART:     3,   // + the outside-safer-regions group, block 3P scripts/frames outside safer regions
  HIGH:      4,   // + block 3P scripts/frames everywhere; CDN + built-in allowed; + the level 4–5 group (blockWebsockets/blockWebtransport/blockWebAssembly — 4.7.0; a 4th, inline-script blocking, shipped and was removed in 4.7.6 — see data/protections.js)
  STRICT:    5    // block 3P scripts/frames, no exceptions (4.2: never images/video/fonts/CSS)
});
export const LEVEL_MIN = LEVEL.ALLOW_ALL;
export const LEVEL_MAX = LEVEL.STRICT;
export const DEFAULT_STARTUP_LEVEL = LEVEL.MILD;     // spec 2026-10-16: startup level 2 by default
// Levels at which the safer-regions TLD list has any effect (spec 2026-10-16: level 3 only).
// There it allows 3P scripts/frames from those TLDs and exempts their sites from
// the outside-safer-regions group. Levels 4–5 apply that group on every site and ignore the list; levels 1–2
// never used it. The popup shows the safer-regions panel and site label only at these levels.
export const SAFER_REGIONS_LEVELS = Object.freeze([LEVEL.SMART]);
// Levels at which the built-in whitelist (data/builtin-domains.js) is trusted: its 3P scripts/
// frames are allowed AND a first-party visit to one of its hosts is exempt from blockHighRiskEval
// and the outside-safer-regions group (and, for its payment hosts, from blockPaymentHandlers). Never level 2 or 5. Single switch
// read by core/rule-builder.js and core/script-builder.js (4.2: was two private copies).
export const BUILTIN_EXEMPT_LEVELS = Object.freeze([LEVEL.SMART, LEVEL.HIGH]);

// Index = level - 1. Colours are 3P-Matrix-lite's; icons are its brick-wall set.
// 5.0.4 (user decision): names Off / Mild / Smart / High / Strict. `name` = the title next to the big number (popup,
// Show Matrix, toolbar tooltip); `short` = the one word under each number on the popup slider (shown upper-case).
export const LEVEL_INFO = Object.freeze([
  Object.freeze({ level: 1, name: "Off (allow all)",   short: "Off",    color: "#16A34A", icon: "icon_0" }),
  Object.freeze({ level: 2, name: "Mild protection",   short: "Mild",   color: "#93C5FD", icon: "icon_1" }),
  Object.freeze({ level: 3, name: "Smart protection",  short: "Smart",  color: "#FACC15", icon: "icon_2" }),
  Object.freeze({ level: 4, name: "High protection",   short: "High",   color: "#FB923C", icon: "icon_3" }),
  Object.freeze({ level: 5, name: "Strict protection", short: "Strict", color: "#C0392B", icon: "icon_4" })
]);
export const ICON_SIZES = Object.freeze([16, 32, 48, 128]);
export const ICON_DIR   = "icons";
export const ICON_UI_SIZE = 32;                      // icon size shown inside the popup and the warning dialog (one of ICON_SIZES)

// ── Storage ──────────────────────────────────────────────────────────────────
export const STORAGE_KEY_STATE   = "tldm_state";     // chrome.storage.local — whole persistent state
export const STORAGE_AREA_LOCAL  = "local";          // chrome.storage.onChanged area name of STORAGE_KEY_STATE (4.5.4 snapshot)
export const SESSION_KEY = Object.freeze({           // chrome.storage.session — per-id state that survives a SW restart (core/session-map.js)
  BADGE:        "tldm_badge",                        // core/badge.js: tabId → { count, site, severity }
  ALLOWED_ONCE: "tldm_allowed_once",                 // core/navigation-guard.js: tabId → sites allowed once
  BLOCKED_DOWNLOADS: "tldm_blocked_downloads"        // core/download-guard.js (4.5.5): downloadId → blockRiskyDownloads lane entry
});
export const STATE_SCHEMA_VERSION = 5;               // 5 (4.5.8): untouched old DNS default → Control D + DNS4EU; 4 (4.4.5): locks on a shared-hosting suffix dropped; 3 (4.3.2): default-off protections unticked for older states; 2 (4.2.3): matrixRules global-only
export const SITE_LOCKS_CAP       = 500;             // max locked sites incl. allow list (FIFO eviction of the oldest); 4.2.3: was 400
export const MANUAL_TLDS_CAP      = 100;             // max hand-added safer-region TLDs
export const ALLOW_LIST_LINE_MAX  = 253;             // max DNS name length — longer lines are ignored

// ── Shared (multi-tenant) hosting suffixes (4.4.5) ───────────────────────────
// Hosts below these names belong to DIFFERENT organisations (hogeschooltio-my.sharepoint.com vs
// other-my.sharepoint.com) but are not on the Public Suffix List, so registeredDomain() used to
// return "sharepoint.com" and one lock covered every tenant on earth (phishing pages included).
// util/domain.js treats each name here as a public suffix: the registered domain is the tenant's
// own label + suffix. Add an entry here — nowhere else. (A suffix on the PSL itself needs no entry.)
export const SHARED_HOSTING_SUFFIXES = Object.freeze(["sharepoint.com"]);

// ── Safer regions (TLD whitelist) ────────────────────────────────────────────────
// Which country codes are added automatically — FIXED, no user control (0.2.4: the popup's
// 4-position "Auto-add country codes" slider is removed). Same default as uBlock Stripped Dynamic
// (since its 0.0.3): CONTINENT = the countries named by the browser's languages + every country on
// the user's continent that speaks one of them (or a readable relative). (4.2.3: the enum lives in
// data/tld-constants.js, so this is the enum value itself — no duplicated number, no runtime check.)
export const SAFER_REGIONS_AUTO_MODE = AUTO_TLD_MODE.CONTINENT;
// Never ADD a TLD from the HaGeZi abused-TLD list (data/spam-tlds.js) automatically — the base set
// already leaves biz/shop/store/site/online out; this extends the same rule to auto-added country
// codes (e.g. cf, cm, ga, gq, ml, ng, pw). A TLD the user adds by hand is always kept (their choice).
export const SAFER_REGIONS_SKIP_ABUSED_TLDS = true;
export const SAFE_ZONE_TLDS_CAP = 300;               // guard for DNR condition size

// ── DNR rule IDs ─────────────────────────────────────────────────────────────
// Every dynamic rule = GROUP_ID_STRIDE * groupIndex + local id.
//   groupIndex 0     = global rules (all sites not locked)
//   groupIndex 1..5  = sites locked at that level (one rule group per level, not per site)
export const GROUP_ID_STRIDE = 10000;
export const RULE_LOCAL_ID = Object.freeze({
  WEBBUNDLE:            10,  // blockWebBundles
  LOCALNET_NAMES:       11,  // blockLocalNetwork — *.local / *.lan / *.internal / *.home.arpa
  LOCALNET_IPV4:        12,  // blockLocalNetwork — private IPv4 literals
  LOCALNET_IPV6:        13,  // blockLocalNetwork — private IPv6 literals
  SUSP_IP:              20,  // blockSuspicious3p — bare IP literal host
  SUSP_PORT_BLOCK:      22,  // blockSuspicious3p — explicit non-standard port (one regex, no allow twin)
  SUSP_HOSTING:         23,  // blockSuspicious3p — DDNS / free-hosting domains
  SUSP_HOSTING_REGEX:   24,  // blockSuspicious3p — byethost* regex
  HTTP_3P:              30,  // block3pHttp — third-party plain HTTP
  SPAM_TLD_BLOCK:       40,  // blockAbusedTlds (L2+) — 3P scripts/frames from abused TLDs
  L3_BLOCK_CODE:        50,  // L3 — block 3P scripts + frames
  SAFEZONE_ALLOW:       51,  // L3 — allow 3P code from safer-region TLDs
  L4_BLOCK_CODE:        60,  // L4 — block 3P scripts + frames (4.2: was "all except passive")
  CDN_ALLOW:            61,  // L4 — allow 3P code with "cdn" in host
  L5_BLOCK_CODE:        70,  // L5 — block 3P scripts + frames, no exceptions (4.2: was every type)
  BUILTIN_ALLOW_SCRIPT: 80,  // L3/L4 — built-in whitelist, script-only domains
  BUILTIN_ALLOW_FRAME:  81,  // L3/L4 — built-in whitelist, frame-only domains
  BUILTIN_ALLOW_BOTH:   82,  // L3/L4 — built-in whitelist, script + frame domains
  HDR_PP_MAIN:          100, // blockScpPrivacy/blockScpSecurity/blockSensorsNfc — Permissions-Policy on top-level pages
  HDR_PP_SUB:           101, // blockScpPrivacy/blockScpSecurity/blockSensorsNfc — Permissions-Policy on frames
  HDR_CSP_MAIN:         102, // retired 5.1.3 — the sandbox is on FRAMES only (it suppressed the top page's own "Leave
                             // site?" prompt, print() and dialogs, and leaked into its popups) — id kept unused
  HDR_CSP_SUB:          103, // blockRedirectsDialogs — sandbox CSP on frames
  HDR_HIGH_RISK:        110, // retired 5.1.3 (blockHighRiskEval merged into blockObfuscatedEval) — id kept unused
  ALLOW_ALL_REQUESTS:   120, // 4.4.5: level-1 lock — allowAllRequests for the whole frame tree of the site
  TAB_RESET:            130, // 4.4.5: tab band — cancels the session-level rules inside the locked tab
  // 4.6.0: data exfiltration (phishing kits) — one rule per channel, data/exfil-channels.js. A blocked request on
  // one of these ids also opens the site warning (core/exfil-guard.js), so the ids identify the channel.
  EXFIL_TELEGRAM_BOT:   140, // blockExfilMessagingBots — Telegram bot API
  EXFIL_DISCORD_HOOK:   141, // blockExfilMessagingBots — Discord webhooks
  EXFIL_SLACK_HOOK:     142, // blockExfilMessagingBots — Slack incoming webhooks
  EXFIL_FORM_MAIL:      150, // blockExfilWebServices — form-to-email services
  EXFIL_AUTOMATION:     151, // blockExfilWebServices — Power Automate / Logic Apps workflow triggers
  // 4.7.0 — levels 4–5 only, outside safer regions: new web-platform blocks (blockWebsockets/blockWebtransport/blockWebAssembly)
  HDR_CSP_WS_MAIN:      160, // blockWebsockets — WebSocket-blocking CSP on top-level pages
  HDR_CSP_WS_SUB:       161, // blockWebsockets — WebSocket-blocking CSP on frames
  // 162/163 (HDR_CSP_STRICT_MAIN/SUB, blockInlineScripts) retired in 4.7.6 — not reused, so a
  // stale rule from a not-yet-reloaded background page can't collide with a new id here.
  // 4.7.0 — alsoHighRisk: the STATIC half (HIGH_RISK_HOSTNAMES), unconditional on level, same shape as the
  // pre-existing HDR_HIGH_RISK (blockHighRiskEval) but for the protections that opted into alsoHighRisk (data/protections.js)
  HDR_HIGH_RISK_PP:         170, // blockScpPrivacy/blockScpSecurity/blockSensorsNfc (alsoHighRisk) — combined Permissions-Policy
  HDR_HIGH_RISK_CSP_SANDBOX: 171, // blockRedirectsDialogs (alsoHighRisk) — sandbox CSP on the high-risk sites' frames (5.1.3: frames only)
  HDR_HIGH_RISK_CSP_WS:      172, // blockWebsockets (alsoHighRisk) — WebSocket-blocking CSP
  // 173 (HDR_HIGH_RISK_CSP_STRICT, blockInlineScripts alsoHighRisk) retired in 4.7.6 along with 162/163 above.
  EXFIL_FORM_MAIL_HR:        180, // blockExfilWebServices (alsoHighRisk) — form-to-email, static high-risk hosts as the PAGE
  EXFIL_AUTOMATION_HR:       181, // blockExfilWebServices (alsoHighRisk) — workflow triggers, static high-risk hosts as the PAGE
  // 5.0.5 — blockWebsockets/blockWebtransport/blockWebAssembly also as a network block (when enabled): they then hold inside workers too, which a page
  // header (31) or a page script (32/33) cannot reach. Same scope as their page mechanism; HR = static high-risk hosts.
  NET_WS:                    164, // blockWebsockets — block 3P WebSocket requests
  NET_WT:                    165, // blockWebtransport — block 3P WebTransport requests
  NET_WASM:                  166, // blockWebAssembly — block 3P .wasm requests
  HDR_CSP_WS_SCRIPT:         167, // blockWebsockets — the same CSP on script responses: a worker started from one (incl. a
                                  // shared worker, whose WebSocket Chrome does not show to extensions) inherits the block
  HDR_HIGH_RISK_CSP_WS_SCRIPT: 177, // blockWebsockets (alsoHighRisk) — same, static high-risk hosts as the page
  NET_HIGH_RISK_WS:          174, // blockWebsockets (alsoHighRisk)
  NET_HIGH_RISK_WT:          175, // blockWebtransport (alsoHighRisk)
  NET_HIGH_RISK_WASM:        176, // blockWebAssembly (alsoHighRisk)
  // 5.0.5 — blockWasmDubious: 3P WebAssembly from a dubious host (any TLD) or from outside the safer regions
  WASM_DUBIOUS_HOST:         190, // suspicious-hosting list
  WASM_DUBIOUS_TLD:          191, // abused TLDs (their exceptions excluded)
  WASM_OUTSIDE_SAFER:        192  // any host NOT on a safer-region TLD (built-in whitelist exempt at its levels)
});
export const MATRIX_RULE_ID_BASE = 900000;            // Show Matrix overrides: 900000 … 900000 + MATRIX_RULES_MAX - 1

// ── DNR priorities (higher wins) ─────────────────────────────────────────────
export const PRIORITY = Object.freeze({
  LEVEL_BLOCK:       100,    // L3 / L4 3P scripts + frames block
  BUILTIN_ALLOW:     300,    // built-in whitelist
  CDN_ALLOW:         300,    // L4 cdn-host allow
  SPAM_TLD_BLOCK:    350,    // beats built-in/CDN allows
  SAFEZONE_ALLOW:    360,    // L3: safer regions override the abused-TLD block (spec)
  SECURITY_BLOCK:    1000,   // blockWebBundles, blockSuspicious3p, block3pHttp — beat every allow above
  LOCALNET_BLOCK:    1002,   // explicit port cannot bypass it
  // Show Matrix overrides are always global (4.2.3: the legacy per-site tier is gone — old per-site
  // entries are migrated to global by normalizeState). Script and Frame cover disjoint resource
  // types, so they never compete and share one priority.
  MATRIX:             400000, // Show Matrix Script/Frame (beats every level/security rule)
  STRICT_BLOCK:      500000, // L5 beats everything, matrix allows included
  ALLOW_ALL_REQUESTS: 600000, // 4.4.5: level-1 lock — beats every rule of the global/locked groups (incl. L5)
  HEADERS:           1       // modifyHeaders rules never compete with block/allow
});

// ── Tab band (4.4.5) ─────────────────────────────────────────────────────────
// A site lock at level 2–5 is also applied to EVERYTHING loaded in the tab that shows the site
// (nested frames included) with session rules scoped by tabId — a request from an embedded frame
// (e.g. Word Online's officeapps.live.com inside SharePoint) has the FRAME's site as initiator, so
// the initiator-scoped locked group alone never saw it. Band rule priority = TAB_BAND_BASE + the
// ordinary priority; the reset allow sits at TAB_BAND_BASE itself, above every global rule
// (highest: ALLOW_ALL_REQUESTS 600000) and below every band rule (lowest: HEADERS = base + 1).
export const TAB_BAND_BASE        = 1000000;  // priority offset of every tab-band rule
export const TAB_BAND_TABS_MAX    = 200;      // guard: tabs per band (one band per level 2–5)
export const TAB_BAND_RULES_MAX   = 4000;     // guard: session rules we ever ask Chrome for (its limit is 5000)
export const TAB_BAND_LEVELS      = Object.freeze([LEVEL.MILD, LEVEL.SMART, LEVEL.HIGH, LEVEL.STRICT]);  // levels that get a band; level 1 uses allowAllRequests
export const NO_TAB_ID            = -1;       // webRequest: request not tied to a tab

// ── High-risk tab override (4.7.0) ───────────────────────────────────────────
// A second, independent tab band: tabs whose site has been SCORED phishing this browser session
// (core/badge.js severity, set by core/online-checks.js) get every alsoHighRisk protection
// (data/protections.js) regardless of the slider — same session-rules mechanism as the level-lock
// tab band above (core/rule-builder.js buildSessionRules), one reserved group index/priority band so
// it never collides with a level-lock band on the SAME tab (both may be active at once).
export const HIGH_RISK_GROUP_INDEX = 6;       // one group only; TAB_BAND_LEVELS/locked groups never use index 6
export const HIGH_RISK_TAB_BASE    = 2000000; // priority offset — above TAB_BAND_BASE, so headers from both never need ordering between them (modifyHeaders rules all apply regardless of priority)

// ── Resource types ───────────────────────────────────────────────────────────
export const RT = Object.freeze({
  CODE:     Object.freeze(["script", "sub_frame"]),
  PASSIVE:  Object.freeze(["image", "media", "font", "stylesheet"]),   // never targeted by any level (4.2)
  // Everything a page can load besides the top-level document (Chrome's ResourceType enum).
  ALL_SUB:  Object.freeze(["sub_frame", "stylesheet", "script", "image", "font", "object",
                           "xmlhttprequest", "ping", "csp_report", "media", "websocket",
                           "webtransport", "webbundle", "other"]),
  // Live connections (5.0.5: also blocked from abused TLDs at levels 2–3, and by blockWebsockets/blockWebtransport as a network rule).
  LIVE:     Object.freeze(["websocket", "webtransport"]),
  // Code + live connections from a dubious host: blockSuspicious3p (suspicious hosting) and, at levels 2–3, blockAbusedTlds.
  CODE_AND_LIVE: Object.freeze(["sub_frame", "script", "websocket", "webtransport"]),
  // How WebAssembly bytes arrive (fetch()/XHR from a page or a worker) — blockWasmDubious and blockWebAssembly (5.0.5).
  WASM_FETCH: Object.freeze(["xmlhttprequest", "other"])
});
// 5.0.5 — a WebAssembly address: path ending in .wasm (query/fragment allowed). The content-type label
// (application/wasm) would need DNR responseHeaders = Chrome 128; the manifest minimum is 120.
export const WASM_URL_REGEX = "^[^?#]*\\.wasm([?#]|$)";

// ── Third-party heuristics for DNR ───────────────────────────────────────────
export const STANDARD_PORTS = Object.freeze([80, 443, 8080, 8443]);
export const CDN_HOST_MARKER = "cdn";                                          // L4 cdn allow: substring of the HOST name
export const CDN_URL_FILTER_FALLBACK = "*" + CDN_HOST_MARKER + "*";               // L4 cdn allow when CDN_HOST_REGEX is unsupported (looser: whole URL)
export const HTTP_URL_FILTER = "|http://";                                     // block3pHttp: plain-HTTP request URLs
export const CDN_HOST_REGEX = "^[a-z][a-z0-9+.-]*://[^/]*cdn[^/]*(/|$)";        // "cdn" in host only
export const IP_LITERAL_REGEX = "^[a-z]+://(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}([:/]|$)|\\[[0-9a-fA-F:]+\\])";
// Any explicit port EXCEPT 80, 443, 8080, 8443 — one RE2 regex (no look-ahead available), so no
// high-priority "allow standard ports" twin rule is needed (that twin would also have overridden
// the TLD and level blocks for URLs written with an explicit :443).
export const NON_STANDARD_PORT_REGEX = "^[a-z]+://[^/:]+:(?:" + [
  "[0-9]",                                                            // 1 digit
  "[0-79][0-9]|8[1-9]",                                               // 2 digits, not 80
  "[0-35-9][0-9]{2}|4[0-35-9][0-9]|44[0-24-9]",                       // 3 digits, not 443
  "[0-79][0-9]{3}|8[1-35-9][0-9]{2}|80[0-79][0-9]|808[1-9]|84[0-35-9][0-9]|844[0-24-9]", // 4 digits, not 8080/8443
  "[0-9]{5}"                                                          // 5 digits
].join("|") + ")(?:[/?#]|$)";
export const BYETHOST_REGEX   = "^[a-z]+://([a-z0-9-]+\\.)*byethost[a-z0-9-]*\\.com([/:]|$)";

// ── Header values ────────────────────────────────────────────────────────────
export const PP_VALUE = Object.freeze({
  PRIVACY:  "camera=(), microphone=(), display-capture=(), clipboard-read=()",       // blockScpPrivacy
  // blockScpSecurity — 5.1.3: + the motion sensors of the former blockSensorsNfc (its NFC script was dropped: Web NFC
  // exists only in Chrome on Android, where extensions do not run).
  SECURITY: "bluetooth=(), serial=(), hid=(), usb=(), local-network-access=(), accelerometer=(), gyroscope=(), magnetometer=()"
});
export const SANDBOX_CSP_VALUE = "sandbox allow-downloads allow-forms allow-orientation-lock allow-pointer-lock " +
  "allow-popups allow-presentation allow-same-origin allow-scripts allow-storage-access-by-user-activation"; // blockRedirectsDialogs
// 4.7.0 — blockWebsockets: connect-src without the ws:/wss: schemes. Chrome checks a WebSocket
// connection against connect-src same as fetch/XHR, so allowing every OTHER scheme it would otherwise need
// (https/http for fetch, data:/blob: for workers/object URLs) but omitting ws/wss blocks WebSocket specifically
// without breaking ordinary network requests. WebTransport is NOT covered here (see blockWebtransport, a SCRIPT
// protection) — Chrome checks it against connect-src too, but its own scheme is "https", so excluding it would
// also block every ordinary fetch; CSP alone cannot separate the two.
// 4.7.1 (user request): added 'self'. CSP's source-matching gives the 'self' keyword (and a bare host-source
// without an explicit scheme) a ws:／wss: ⇄ http:／https: scheme-equivalence that a plain scheme-only token
// like "https:" does NOT get — so 'self' here allows a WebSocket connection back to the PAGE'S OWN origin
// (first-party use) while every other origin still has no ws:/wss: source to match against and stays blocked
// (third-party use, the actual target of this protection). https:/http:/data:/blob:/filesystem: keep covering
// ordinary fetch/XHR/worker/object-URL traffic to any origin, unaffected by this.
export const CSP_NO_WS_VALUE = "connect-src 'self' https: http: data: blob: filesystem:";
// CSP_STRICT_SCRIPT_VALUE (blockInlineScripts) removed in 4.7.6: a strict script-src with no
// nonce/hash has no way to tell the page's OWN inline <script> tags apart from an injected one — both got
// blocked, so this broke most sites it ran on instead of protecting them. See data/protections.js for the
// full note.

// ── Content-script registration ──────────────────────────────────────────────
export const SCRIPT_ID_PREFIX = "tldm-";             // + protection key (storage contract name; kept)
export const SCRIPT_ID_GROUP_JOIN = "+";            // 4.5.4: id of a merged registration = prefix + member keys joined by this
export const SCRIPT_ID_SUFFIX = Object.freeze({
  SAFER_LOCKED:   "-locked",                         // rescue registration: locked sites inside safer regions
  BUILTIN_LOCKED: "-builtin-locked",                 // rescue registration: built-in-whitelist sites locked at 5
  ISOLATED:       "-isolated",                        // 4.6.0: the ISOLATED-world twin of a registration (isolatedScripts)
  HIGH_RISK:      "-highrisk"                          // 4.7.0: alsoHighRisk's extra registration, fixed to HIGH_RISK_HOSTNAMES, level-independent
});
// 5.1.5 — chrome.runtime.getPlatformInfo().os value of macOS (data/protections.js macScripts).
export const PLATFORM_OS_MAC = "mac";
export const NOEVAL_EXTRA_EXCLUDES = Object.freeze(["*://*/*login*", "*://*/*Login*", "*://*/*LOGIN*", "*://*/*.aspx*"]);

// ── Suspicious-site detection (stage 1 local / stage 2 online) ───────────────
export const SCORE = Object.freeze({
  SUSPECT_AT:           -30,   // ≤ this → orange badge + warning dialog (warnSuspiciousSites)
  PHISHING_BELOW:       -60,   // < this → red badge "!" + phishing dialog
  // 4.4.0: the weights shared with downloads come from DownloadSentinel's SCORING_CONFIG (single source) —
  // they were typed copies here and had drifted (LOOKALIKE_SITE stayed −45 after DS 3.5.0 made it −35).
  IP_HOST:              DS_SCORING.IP_HOST_PENALTY,          // first-party host is a bare public IP address
  NON_STANDARD_PORT:    -15,   // first-party URL uses a port outside STANDARD_PORTS
  PLAIN_HTTP:           -15,   // first-party page over plain HTTP
  SPAM_TLD_RISK:         60,   // 0-100 risk fed into the TLD family for HaGeZi-listed TLDs (→ −30)
  TLD_BASE:             DS_SCORING.HOST_TLD_BASE_SCORE,
  DOMAIN_LIST_BASE:     DS_SCORING.HOST_DOMAIN_BASE_SCORE,
  HOST_LIST_BASE:       DS_SCORING.HOST_LIST_BASE_SCORE,
  SKETCHY_URL_BASE:     DS_SCORING.HOST_SKETCHY_URL_BASE,
  LOOKALIKE_BRAND:      DS_SCORING.LOOKALIKE_BRAND_SCORE,
  LOOKALIKE_SITE:       DS_SCORING.LOOKALIKE_SITE_SCORE,     // −35 since DS 3.5.0 (was −45 here)
  // 4.4.0: a platform hit that is the ONLY real signal counts 1/PLATFORM_SOLO_DIVISOR (DS rule "RiskyHosting
  // solo mitigation", now also for the site check) — see core/site-scorer.js combine().
  PLATFORM_SOLO_DIVISOR: DS_SCORING.RISKY_HOSTING_SOLO_DIVISOR,
  RDAP_YOUNG:           DS_APP.RDAP_YOUNG_SCORE,    // registered < RDAP_YOUNG_DAYS ago (4.4.1: from DS, single source)
  RDAP_RECENT:          DS_APP.RDAP_RECENT_SCORE,   // registered < RDAP_RECENT_DAYS ago
  RDAP_NO_DATE:         DS_APP.RDAP_NO_DATE_SCORE,  // 4.3.4: a real RDAP answer WITHOUT a registration date (DownloadSentinel 3.3.0 rule);
                               // a failed/unreachable lookup or no RDAP service at all stays 0
  DNS_BLOCKED:          -100,  // a threat-intel resolver blocks the domain (hard rule)
  // 4.4.9: data/active-threat-hosts.js — a floor applied directly in core/site-scorer.js,
  // only when BOTH the host matches AND the path looks like that campaign's delivery
  // vehicle (RISKY_DELIVERY_EXT_RE — an archive/executable, not a source/content file);
  // not run through the shared CombinationScoring family system; see that file's header
  // for why. 4.5.8: −40 → −30 (user decision 2026-11-06) — the list is a dated snapshot, not a
  // live feed. Exactly SUSPECT_AT: orange badge; crosses SITE_DIALOG_FROM at SMART/HIGH/STRICT,
  // not MILD. Downloads: "Probably Inconclusive" alone (THRESHOLD_QUESTIONABLE). A floor, not an
  // addend: other signals change the verdict only when they already score below it on their own.
  ACTIVE_THREAT_HOST:   -30,
  // 5.1.3 — a download that started without a click on the page that started it (core/download-gesture.js) — an
  // addend to the download's host score, like the other small signals.
  DOWNLOAD_NO_CLICK:    -15,
  FLOOR:                -100
});
// 4.4.1 — the open-platform tables (DEV_HOSTING_PLATFORMS, ORG_PAGE_PLATFORMS of 4.4.0) moved into the shared
// library: lib/downloadsentinel/util/DeliveryPatterns.js OPEN_PLATFORMS / ORG_PAGE_PLATFORMS (single source for the
// site AND download checks).
// 4.4.1 — site dialog (warnSuspiciousSites) staged by the site's protection level: the dialog opens when the local score
// is at or below this value, or when a site exception applies (lib protection/WarnPolicy.js: known bad,
// impersonation). Below the line but still SUSPECT (≤ SCORE.SUSPECT_AT) → orange badge only, no dialog.
// Level 1 (allow all) never reaches the check (warnSuspiciousSites starts at level 2).
export const SITE_DIALOG_FROM = Object.freeze({
  [LEVEL.MILD]:   -45,
  [LEVEL.SMART]: -30,    // = SCORE.SUSPECT_AT, the pre-4.4.1 line for every level
  [LEVEL.HIGH]:   -20,
  [LEVEL.STRICT]: -15
});
export const SEVERITY = Object.freeze({ NONE: "none", SUSPECT: "suspect", PHISHING: "phishing" });
export const RDAP_YOUNG_DAYS  = DS_APP.RDAP_YOUNG_DAYS;    // 4.4.1: from DS (single source)
export const RDAP_RECENT_DAYS = DS_APP.RDAP_RECENT_DAYS;
export const RDAP_URL         = "https://rdap.org/domain/";
export const RDAP_TIMEOUT_MS  = 3000;            // 4.3.4: was 4000 — same as DNS_TIMEOUT_MS (DS item 21)
export const DNS_TIMEOUT_MS   = 3000;
export const SCORE_CACHE_CAP     = 500;              // registered domains kept in memory
export const SCORE_CACHE_TTL_MS  = 6 * 60 * 60 * 1000; // 6 h

// How a threat-intel resolver says "blocked" (DNS_PROVIDER.*.blockStyle). 4.3.7: taken FROM DownloadSentinel's
// APP.DNS_BLOCK_STYLE (DS 3.3.1) instead of a typed copy (B2):
//   NXDOMAIN_NO_AUTHORITY — NXDOMAIN with an empty authority section (Quad9)
//   ZERO_IP               — answers 0.0.0.0 / :: (Cloudflare 1.1.1.2, Control D)
//   BLOCKPAGE_IP          — answers the provider's block-page IP, provider.blockPageIps (DNS4EU)
//   RPZ_SOA               — no answer + authority SOA whose MNAME ends in provider.rpzSoaMnameSuffix (CleanBrowsing)
export const DNS_BLOCK_STYLE = DS_APP.DNS_BLOCK_STYLE;
// Threat-intel DNS resolvers the user may pick as FIRST / SECOND check — ONE table for the site checks
// (core/online-checks.js) and the download checks (DS DnsThreatProtection): DownloadSentinel's
// APP.DNS_PROVIDERS (4.3.0: was a second, identical copy here). Entries: { id, label, host, url, blockStyle,
// + blockPageIps / rpzSoaMnameSuffix / optionalPermission where DS sets them }. 4.3.7: + DNS4EU, CleanBrowsing.
// optionalPermission is a DownloadSentinel concern only — 3P Matrix holds <all_urls>, so it never asks.
export const DNS_PROVIDER = Object.freeze({
  QUAD9:         DS_APP.DNS_PROVIDERS.quad9,
  CLOUDFLARE:    DS_APP.DNS_PROVIDERS.cloudflare,
  CONTROLD:      DS_APP.DNS_PROVIDERS.controld,
  DNS4EU:        DS_APP.DNS_PROVIDERS.dns4eu,
  CLEANBROWSING: DS_APP.DNS_PROVIDERS.cleanbrowsing
});
export const DNS_NONE = DS_APP.DNS_NONE;              // "none" — a DNS check slot that is switched off
// 5.1.5 (owner): the popup's "Download protection: N" counts the checks a download gets (core/policy.js
// protectionCounts): its Download-tab protections (1–2) + each DNS slot that is not DNS_NONE (0–2) + the URL/filename
// heuristics (always 1) + VirusTotal once a key is entered (0–1) — at most 6.
export const DOWNLOAD_CHECK_COUNT = Object.freeze({ PER_DNS_SLOT: 1, HEURISTICS: 1, VIRUSTOTAL: 1 });
// First-install defaults (3P Matrix's own pair — differs from DS's Quad9 + Control D). 4.5.8: Control D +
// DNS4EU Protective (they block more malware than Quad9 + Cloudflare), the same pair in every region: DS's
// region rule (France → Control D + Cloudflare) only exists to avoid Quad9, which this pair does not use.
// DNS4EU's optionalPermission does not matter here — 3P Matrix holds <all_urls>, so no prompt is ever needed.
export const DEFAULT_DNS_FIRST  = DNS_PROVIDER.CONTROLD.id;
export const DEFAULT_DNS_SECOND = DNS_PROVIDER.DNS4EU.id;
// The pair 4.3.7–4.5.7 gave a first install outside a DS region rule. Read ONLY by the schema-5 migration
// (data/state-storage.js): a stored pair still equal to the old default for the user's region moves to the
// new default; any other stored pair is the user's own choice and is kept.
export const LEGACY_DNS_DEFAULT = Object.freeze({ first: DNS_PROVIDER.QUAD9.id, second: DNS_PROVIDER.CLOUDFLARE.id });

// Hosts never scored as a first-party site (private / local network, loopback).
export const PRIVATE_HOST_SUFFIXES = Object.freeze([".local", ".lan", ".internal", ".home.arpa", ".localhost"]);

// ── Badge ────────────────────────────────────────────────────────────────────
// 5.1.3 (owner, 2026-11-24): the highest problem always wins, one symbol per tab — "!" (red) dangerous: a dangerous
// site OR a High/Critical tamper rating; "?" (orange) suspicious: a suspicious site OR a Suspicious tamper rating;
// otherwise the NUMBER of requests the firewall blocked on the page, counted by Chrome itself
// (declarativeNetRequest.setExtensionActionOptions displayActionCountAsBadgeText — only 3P Matrix's own block rules,
// allow rules not counted, no listener of ours, no extra permission; verified in Chrome). A symbol is per-tab badge
// text, which overrules Chrome's number; text null hands the badge back to the number. NORMAL is the GLOBAL badge
// colour (Chrome resets per-tab colours on navigation), so the number is always grey.
export const BADGE_COLOR = Object.freeze({
  NORMAL:   "#666666",
  SUSPECT:  "#C2410C",
  PHISHING: "#B91C1C"
});
export const BADGE_TEXT = Object.freeze({
  SUSPECT:  "?",                                   // suspicious (orange)
  PHISHING: "!"                                    // dangerous (red)
});
export const BADGE_SHOWS_BLOCK_COUNT = true;       // owner: Chrome's own block count when there is no symbol
// The badge severities from least to most serious ("the highest problem wins").
export const SEVERITY_ORDER = Object.freeze([SEVERITY.NONE, SEVERITY.SUSPECT, SEVERITY.PHISHING]);
// 5.1.3 — the popup's "This page" box and firewall count (core/view-models.js, ui/popup.js).
export const POPUP_RISK_REASONS_MAX = 2;           // site-check reasons shown under "Suspicious site" / "Dangerous site"
export const POPUP_MATCHED_RULES_MAX = 20000;      // guard: matched-rule ids the popup passes on for the firewall count
export const BADGE_RENDER_DELAY_MS = 250;          // 4.5.4: badge redraw (and session save) coalesced per tab

// ── Show Matrix (Script / Frame overrides) ────────────────────────────────────────────────────
// 4.2: the combined 3P-code / 3P-all pair is replaced by two independent columns, Script and
// Frame, each cycling none → BLOCK → ALLOW on its own. Saved data in the old shape
// ({ code, all }) is converted once by data/state-storage.js normalizeState(): code (or, if
// unset, all) → both script and frame. An old 3P-all rule thus keeps its script/frame effect
// but no longer touches images/video/fonts/CSS — in line with the levels, which never do.
// Overrides are GLOBAL, as in uMatrix / 3P-Matrix-lite: a blocked/allowed third party stays
// blocked/allowed on every first-party site. Stored shape: { [MATRIX_SITE_ALL]: { [domain]:
// { script?, frame? } } } — the "*" key is kept so the storage key and backup files stay
// compatible. 4.2.3: per-site keys (0.2.x uBD-style data) are no longer supported; normalizeState
// merges them into "*" once (per scope, the per-site value wins — it used to outrank global).
export const MATRIX_SITE_ALL = "*";                                       // single declared sentinel
export const MATRIX_SCOPE = Object.freeze({ SCRIPT: "script", FRAME: "frame" });
// DNR resource type per scope (one type each — the columns never overlap).
export const MATRIX_SCOPE_RESOURCE_TYPE = Object.freeze({ [MATRIX_SCOPE.SCRIPT]: "script", [MATRIX_SCOPE.FRAME]: "sub_frame" });
// Column header / aria label per scope.
export const MATRIX_SCOPE_LABEL = Object.freeze({ [MATRIX_SCOPE.SCRIPT]: "Script", [MATRIX_SCOPE.FRAME]: "Frame" });
// Pre-4.2 saved keys, read only by normalizeState() for the one-time conversion. Order = precedence.
export const MATRIX_ACTION = Object.freeze({ BLOCK: "block", ALLOW: "allow" });
export const MATRIX_OVERRIDES_CAP   = 1000;          // (site, domain) pairs kept — new pairs refused above this
export const MATRIX_RULES_MAX       = 2000;          // DNR rules in the matrix band (2 per pair at most: Script + Frame)
export const MATRIX_DOMAINS_PER_TAB = 150;           // observed third-party rows per tab (oldest dropped first)
export const TAB_SITES_CAP          = 500;           // core/tab-sites.js: tabs whose top-level host is remembered
export const MATRIX_DURATION_MS     = 5 * 60 * 1000; // observation stops after 5 minutes
export const MATRIX_POLL_MS         = 800;           // panel refresh interval
export const MATRIX_TIMER_WARN_MS   = 60 * 1000;     // panel timer turns yellow in the last minute (3P-Matrix-lite)
export const MATRIX_CLOSE_GRACE_MS  = 5 * 1000;      // panel's own fallback: close itself this long after
                                                     // MATRIX_DURATION_MS if the service worker never did
export const MATRIX_WINDOW = Object.freeze({ width: 980, height: 720 });
// Observed resource types → fixed panel column (same 7 columns as uBlock Stripped Dynamic's panel).
export const MATRIX_TYPE_LABEL = Object.freeze({
  image: "image", media: "media", stylesheet: "css", script: "script", sub_frame: "frame",
  xmlhttprequest: "xhr",
  font: "other", websocket: "other", object: "other", ping: "other", csp_report: "other",
  webbundle: "other", other: "other"            // webtransport: not a webRequest filter type
});

// ── UI ───────────────────────────────────────────────────────────────────────
export const STATUS_CLEAR_MS = 8000;                 // ui/status-line.js: a status line clears itself after this (summaries are long)
// Chrome-defined values (not ours to choose — named so no module types them).
export const CHROME_BLOCKED_BY_CLIENT_ERROR = "net::ERR_BLOCKED_BY_CLIENT"; // webRequest error for any extension's block
export const CHROME_NEW_TAB_URL = "chrome://newtab/";            // "Go back" with no history
export const CHROME_DOWNLOAD_COMPLETE = "complete";              // chrome.downloads DownloadItem.state when finished
export const CHROME_DOWNLOAD_INTERRUPTED = "interrupted";        // chrome.downloads DownloadItem.state when cancelled / failed
export const WARNING_PAGE = "ui/warning.html";
export const WARNING_TARGET_PARAM = "u";             // warning page query parameter carrying the site URL
export const WARNING_REASON_PARAM = "x";             // 4.6.0: warning page parameter carrying an exfiltration channel id
                                                     // 4.7.0: or a page-scam reason id (data/page-scam-reasons.js)
export const WARNING_REFERRER_PARAM = "r";           // 4.7.0: device-code warning — the site that sent the user (display only)


// ── 4.7.0 — Chrome out-of-date check (core/browser-update.js) ────────────────────────────────────────────
// Google's public VersionHistory API: the stable releases serving NOW for one platform. Only the platform id
// is sent — nothing about the user or their browsing.
export const BROWSER_UPDATE = Object.freeze({
  API_URL_TEMPLATE: "https://versionhistory.googleapis.com/v1/chrome/platforms/{platform}/channels/stable/versions/all/releases?filter=endtime=none",
  PLATFORM_TOKEN:   "{platform}",
  ALARM_NAME:       "3pmcf-browser-update",
  PERIOD_MINUTES:   1440,                            // one check a day
  FETCH_TIMEOUT_MS: 10000,                           // a check that takes longer is abandoned (no band change)
  MAX_RESPONSE_BYTES: 262144,                        // guard: a larger answer is not parsed (normal: a few KB)
  STORAGE_KEY:      "tldm_browser_update",           // chrome.storage.local — the last successful check
  // A release counts once Chrome would really offer it: rolled out to at least half of users for a day, or
  // out for a week whatever its rollout (Google rolls updates out gradually — no false "update waiting").
  MIN_ROLLOUT_FRACTION: 0.5,
  MIN_ROLLOUT_AGE_MS:   86400000,                    // 1 day
  ANY_ROLLOUT_AGE_MS:   604800000,                   // 7 days
  // Browsers built on Chromium but not Google Chrome (Brave, Edge, Opera, Vivaldi, distro Chromium) follow
  // their own patch numbers: only the major version is compared, and only this far behind counts.
  OTHER_BROWSER_MAJORS_BEHIND: 2,
  CHROME_BRAND:     "Google Chrome",
  CHROMIUM_BRAND:   "Chromium"
});
// chrome.runtime.getPlatformInfo() → { os, arch } → VersionHistory platform id. ChromeOS (cros) updates with the OS
// and is not checked; an unknown os → no check.
export const BROWSER_UPDATE_PLATFORM = Object.freeze({
  win:   Object.freeze({ x86_64: "win64", "x86-32": "win", arm64: "win_arm64", default: "win64" }),
  mac:   Object.freeze({ arm64: "mac_arm64", default: "mac" }),
  linux: Object.freeze({ default: "linux" })
});
// 4.6.0 — "Go back" that leaves the site (exfiltration and password-form warnings): step back one history entry at a
// time until the tab shows another website; nothing is recorded (no history kept). Guards for a stuck or endless loop:
export const GO_BACK_MAX_STEPS       = 25;           // history entries tried before falling back to a new-tab page
export const GO_BACK_STEP_TIMEOUT_MS = 3000;         // one step that does not commit within this time ends the walk
export const MATRIX_PAGE  = "ui/matrix.html";
export const MATRIX_TAB_PARAM = "tabId";             // Show Matrix panel query parameter: the observed tab
// 5.0.7 (C50) — size limit for files the user imports (settings backup, allow list). A file is read only after
// its size is checked, so a wrong or hostile file cannot stall the options page or the service worker. Generous on
// purpose: a real backup is a few KB, a large allow list a few hundred KB; the limit must never refuse a real one
// a year from now. Read by ui/protections.js readImportFile() — the one place both import paths pass through.
export const IMPORT_FILE_MAX_BYTES = 8 * 1024 * 1024;
export const BYTES_PER_MEBIBYTE = 1024 * 1024;   // for the "too large" message only
export const DECIMAL_RADIX = 10;                     // Number.parseInt of user/URL input

// ── Download protection (warnRiskyDownloads — DownloadSentinel 3.5.2, core/download-guard.js) ─────────
// Scores, thresholds, time budgets and engine filters stay in DownloadSentinel's own constants
// (lib/downloadsentinel: APP in util/AppConstants.js, SCORING_CONFIG in protection/ScoringEngineV2.js).
// This block holds what 3P Matrix itself decides: pages, storage defaults, input limits.
export const DOWNLOAD_WARNING_PAGE   = "ui/download-warning.html";
export const DOWNLOAD_ID_PARAM       = "downloadId";     // download warning page query parameter (Chrome download id)
export const VT_KEY_PROMPT_PAGE      = "ui/vt-key-prompt.html";
export const DOWNLOAD_BLOCKED_PAGE   = "ui/download-blocked.html";   // blockRiskyDownloads notice (4.3.2)
export const DOWNLOAD_BLOCKED_WINDOW = Object.freeze({ width: 520, height: 400 });
export const DOWNLOAD_BLOCK_REASON   = Object.freeze({ LEVEL: "level", OUTSIDE_SAFER: "outside-safer", HIGH_RISK: "high-risk" }); // blockRiskyDownloads: why (4.7.0: HIGH_RISK — alsoHighRisk, the referrer is a known high-risk host, independent of the level slider)
// 4.5.5 — blockRiskyDownloads lane (core/download-guard.js): a blocked download is HELD (paused, or finished but
// unopened) while its notice is open — never cancelled before the user chose. OK / closing the notice / the
// sweep discard it; "Download anyway" moves it to ALLOWED: resumed, and always checked by warnRiskyDownloads.
export const DOWNLOAD_BLOCK_PHASE    = Object.freeze({ HELD: "held", ALLOWED: "allowed" });
// Levels at which blockRiskyDownloads respects the built-in whitelist (page) and the trusted download domains (file
// host or the page it came from). Level 3 only (user, 2026-10-20) — at levels 4–5 every risky download is
// blocked; only the allow list (a site locked at level 1) is outside its reach.
export const DOWNLOAD_BLOCK_EXEMPT_LEVELS = Object.freeze([LEVEL.SMART]);
// 4.5.5 (user decision): levels at which a trusted PAGE also covers files it serves from another host (SharePoint/
// OneDrive zips from *.svc.ms). Levels 4–5 never widen trust: there only the file's own host counts (and, for a
// file with no host of its own — data:, sandboxed blob:null/… — the page, DownloadSentinel's item-27 fallback).
export const DOWNLOAD_PAGE_TRUST_LEVELS = Object.freeze([LEVEL.ALLOW_ALL, LEVEL.MILD, LEVEL.SMART]);
export const VT_KEY_PROMPT_WINDOW    = Object.freeze({ width: DS_APP.VT_KEY_PROMPT_WINDOW_WIDTH, height: DS_APP.VT_KEY_PROMPT_WINDOW_HEIGHT });
export const VT_JOIN_URL             = DS_APP.VT_JOIN_URL;
export const VT_GUI_URL_PREFIX       = "https://www.virustotal.com/gui/url/";   // + VT url id + VT_GUI_URL_SUFFIX
export const VT_GUI_URL_SUFFIX       = "/detection";
export const VT_GUI_HOME_URL         = "https://www.virustotal.com/gui/home/url";
export const HYBRID_ANALYSIS_URL     = "https://hybrid-analysis.com/";          // when VirusTotal does not know the URL
export const VT_API_KEY_RE           = /^[0-9a-fA-F]{64}$/;                     // a VirusTotal API key: 64 hex characters
// False-positive reduction for VirusTotal results (DS util/FpReductionEngines.js tiers). Order = Options slider.
export const FP_LEVEL = Object.freeze({ HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", NONE: "NONE" });
export const FP_LEVEL_ORDER = Object.freeze([FP_LEVEL.HIGH, FP_LEVEL.MEDIUM, FP_LEVEL.LOW, FP_LEVEL.NONE]);
export const FP_LEVEL_HINT = Object.freeze({
  [FP_LEVEL.HIGH]:   "Use only antivirus engines known for very low false positive rates.",
  [FP_LEVEL.MEDIUM]: "Use antivirus engines known for low false positive rates and early detection.",
  [FP_LEVEL.LOW]:    "Use well-known antivirus engines from the B2B and consumer market.",
  [FP_LEVEL.NONE]:   "Use all engines listed at VirusTotal — unfiltered."
});
export const AUTO_ALLOW_THRESHOLD_MIN = DS_APP.AUTO_ALLOW_THRESHOLD_MIN;   // "Silent when probably safe" input range
export const AUTO_ALLOW_THRESHOLD_MAX = DS_APP.AUTO_ALLOW_THRESHOLD_MAX;
// 5.1.3: the allow list's "Download" lines (they are the former own trusted download hosts) — no longer the 12 boxes.
export const TRUSTED_DOWNLOAD_DOMAINS_MAX = 500;
// 5.1.3: at most this many domains per allow-list category (Firewall, Scam, Tamper); "All" keeps SITE_LOCKS_CAP.
export const ALLOW_CATEGORY_CAP = 500;
export const BUILTIN_TRUSTED_DOWNLOAD_DOMAINS = Object.freeze(DS_APP.BUILTIN_DO_NOT_CHECK_DOMAINS.slice()); // app stores — never checked
export const DOWNLOAD_WARNING_TITLE_DEFAULT = DS_APP.WARNING_TITLE_DEFAULT;
export const DOWNLOAD_WARNING_TITLE_MAX = 80;                              // characters (DS options input maxlength)
export const RGB_CHANNEL_MAX = 255;                                       // warning page colour: 0 … 255 per channel
// Defaults of state.downloads (data/state-storage.js). DownloadSentinel's own defaults (its util/Settings.js, not vendored).
export const DOWNLOAD_DEFAULTS = Object.freeze({
  vtApiKey:             "",                              // "" = no VirusTotal key
  vtEnabled:            true,                            // VirusTotal check on (needs a key)
  // 4.4.4 (user request): splits the FP-reduction staged threshold (WarnPolicy, 4.4.1) out from
  // "Silent when probably safe" below — OFF by default (user decision): every monitored download
  // that is not auto-allowed above and has no exception gets a warning window, whatever its score
  // (pre-4.4.1 behaviour), until the user explicitly ticks this on.
  silentWhenInconclusive: false,                         // "Silent when inconclusive"
  autoAllow:            false,                           // "Silent when probably safe"
  autoAllowThreshold:   DS_APP.AUTO_ALLOW_THRESHOLD_DEFAULT,
  fpReductionLevel:     FP_LEVEL.MEDIUM,
  trustedDomains:       Object.freeze(["sharepoint.com"]), // DS starter entry (org-controlled hosting) — the allow list's "Download" lines
  trustAppStores:       true,                              // 5.1.3: "Trust app stores" (BUILTIN_TRUSTED_DOWNLOAD_DOMAINS), a tickbox
  warningColor:         Object.freeze({ r: DS_APP.WARNING_COLOR_DEFAULT_R, g: DS_APP.WARNING_COLOR_DEFAULT_G, b: DS_APP.WARNING_COLOR_DEFAULT_B }),
  warningTitle:         "",                              // "" = DOWNLOAD_WARNING_TITLE_DEFAULT
  vtKeyPromptDismissed: false                            // "don't show the VirusTotal key nudge again"
});

// ── XSS (5.1.2 — core/xss-link-guard.js warnXssLinks; security/tamper-guard-page.js tgAddressScript) ────────────────
// Script markup in an address: a regex SOURCE per pattern (case-insensitive), so the page script's copy can be checked
// against this one (tools/test-tamper-guard.mjs). Deliberately few and specific — each needs markup that only makes
// sense as code: a script tag, an event handler inside a tag, or a javascript: address.
export const XSS_MARKUP_PATTERNS = Object.freeze([
  "<\\s*script\\b",                         // <script
  "<[a-z][^>]*[\\s/]on[a-z]+\\s*=",          // <img src=x onerror=…, <svg/onload=…
  "javascript\\s*:"                           // javascript:alert(1)
]);
export const XSS_MARKUP_FLAGS = "i";
// An address is decoded this many times at most (double-encoded payloads: %253Cscript).
export const XSS_DECODE_ROUNDS = 2;
// Guard (B6): at most this many characters of an address are looked at.
export const XSS_ADDRESS_CHARS_MAX = 8192;
// tgAddressScript: an address piece (a query or hash value) shorter than this is never looked for in the page's HTML.
export const XSS_PIECE_MIN_CHARS = 8;
// Guard (B6): at most this many address pieces are kept per page (security/tamper-guard-page.js copy).
export const XSS_PIECES_MAX = 16;

// ── Tamper Guard (5.1.0 — core/tamper-guard.js, data/tamper-rules.js, security/tamper-guard-*.js) ──────────────────
// Owner decision 2026-11-24 ("need to protect", least overhead): ONLY the four trigger ticks under "Enable tamper
// detection" start the close watching — the level slider no longer widens it (TAMPER_LEVEL AFTER_SIGN / ALWAYS removed).
// 5.1.3 — Tamper risk rating (user decision 2026-11-24). Every finding (data/tamper-rules.js) carries POINTS; a page's
// score is the sum of its DIFFERENT findings' points, × TAMPER_SENSITIVE_FACTOR on a banking/payment page. The score
// gives the page's rating (ordered: a higher number is more serious). Replaces 5.1.0–5.1.2's per-finding severity,
// warning thresholds and correlation step.
export const TAMPER_RATING = Object.freeze({ LOW: 1, SUSPICIOUS: 2, HIGH: 3, CRITICAL: 4 });
// The lowest score of each rating (below SUSPICIOUS: LOW, which never warns).
export const TAMPER_RATING_MIN_POINTS = Object.freeze({
  [TAMPER_RATING.SUSPICIOUS]: 30,
  [TAMPER_RATING.HIGH]:       60,
  [TAMPER_RATING.CRITICAL]:   100
});
export const TAMPER_SENSITIVE_FACTOR = 1.5;    // banking/payment pages count heavier
// Where a SUSPICIOUS page warns (HIGH and CRITICAL always warn on a closely watched page): from ALWAYS_FROM on every
// page; from OUTSIDE_SAFER_FROM only when the page's own site is outside the safer regions; below: only the toolbar
// symbol (core/badge.js setTamperRating: "?").
export const TAMPER_SUSPICIOUS_WARN = Object.freeze({ ALWAYS_FROM: LEVEL.HIGH, OUTSIDE_SAFER_FROM: LEVEL.SMART });
// Which badge severity a tamper rating gives (core/badge.js setTamperRating; the page's full rating, own-warning signs
// included, on a closely watched page outside "Tamper: site").
export const TAMPER_BADGE_SEVERITY = Object.freeze({
  [TAMPER_RATING.SUSPICIOUS]: SEVERITY.SUSPECT,
  [TAMPER_RATING.HIGH]:       SEVERITY.PHISHING,
  [TAMPER_RATING.CRITICAL]:   SEVERITY.PHISHING
});
// One window per page: findings arriving within this time are collected before the window opens (a CRITICAL rating
// opens it at once). Later findings update the open window.
export const TAMPER_COLLECT_MS = 2000;
// A replaced built-in of a rule worth at least this many points counts toward tgManyHooks.
export const TAMPER_SIGN_POINTS_MIN = 20;
// The protections under the tamper switch that have their own warning (password form elsewhere, payment skimmer,
// fake sign-in window) — shown with these points on the Tamper Protection tab: they always warn at once.
export const TAMPER_OWN_WARNING_POINTS = 100;
// 5.1.3 — tgIbanSent (security/tamper-guard-page.js copy): an IBAN is 15–34 letters/digits; ISO 13616 MOD-97 check.
export const TAMPER_IBAN = Object.freeze({ MIN_CHARS: 15, MAX_CHARS: 34, DIVISOR: 97, VALID: 1 });
// 5.1.3 — "Download started without a click" (core/download-gesture.js): the page that started the download (its tab
// address equals the download's referrer) is asked whether it has a recent user click or key press
// (navigator.userActivation.isActive — Chrome keeps it about five seconds). Guards: at most TABS_MAX tabs looked at,
// the answer waited for at most TIMEOUT_MS (else: unknown, no signal). Issue 6: asked at EVERY download start the
// download protection could apply to and kept until the download is released — at most ENTRIES_MAX downloads at
// once (oldest dropped: its signal becomes unknown, never a false "no click").
export const DOWNLOAD_GESTURE = Object.freeze({ TABS_MAX: 200, TIMEOUT_MS: 1000, ENTRIES_MAX: 200 });
export const DOWNLOAD_NO_CLICK_LABEL = "Download started without a click on the page";
// Recognising a banking/payment page (core/tamper-guard.js sensitivePoints). Points per signal; the page counts as
// sensitive at TAMPER_SENSITIVE_THRESHOLD. Every signal here is strong enough on its own. Words in the address are NOT
// points (5.1.1): they only start the closer watching early (TAMPER_ADDRESS_WORDS below) — never make a page sensitive.
export const TAMPER_SENSITIVE_POINTS = Object.freeze({
  KNOWN_PAYMENT_SITE: 70,      // the page's own site is on the built-in whitelist's Payment list (banks, card networks, PSPs)
  PAYMENT_FRAME:      60,      // the page embeds a frame from a Payment-list host (a shop's card form, 3-D Secure)
  CARD_FIELD:         60,      // a card-number / card-code / expiry field (autocomplete cc-*, card field names)
  BANK_FIELD:         60,      // an IBAN / bank-account field
});
export const TAMPER_SENSITIVE_THRESHOLD = 60;
// 5.1.7 TEMPORARY diagnostics (owner, CNN false alarm): log to the service-worker console why a page became a banking
// or payment page and what started close watching (hosts only, nothing leaves the browser). Set false when solved.
export const TAMPER_DEBUG_LOG = false;
// 5.1.1 — Checkout / cart / payment words in the address (EU+ languages). The address is known before the page's own
// scripts run, so a word starts the closer watching AT PAGE START (core/tamper-guard.js ARMED_BY.ADDRESS) — before a
// skimmer loaded later can hook anything. It only raises scrutiny (principle B11): the page does not become a
// banking/payment page by it, so MEDIUM findings there still warn only once a real signal (card/IBAN field, payment
// frame, known payment site) confirms it. Matching (core/tamper-guard.js addressTokens): the decoded path and the
// subdomain labels, lower case, accents removed, split on everything that is not a letter or digit; a word must be a
// WHOLE token ("/kassa" yes, "/kassabon-tips" no). Write words lower case; accents are removed on load anyway.
export const TAMPER_ADDRESS_WORDS = Object.freeze({
  en: ["checkout", "checkouts", "cart", "basket", "payment", "payments", "billing", "banking", "3dsecure"],
  nl: ["afrekenen", "betalen", "betaling", "winkelwagen", "winkelmand", "kassa", "bestellen"],
  de: ["kasse", "warenkorb", "bezahlen", "bezahlung", "zahlung", "bestellung"],
  fr: ["paiement", "panier", "commande", "caisse"],
  es: ["pago", "pagar", "carrito", "caja", "cesta"],
  it: ["pagamento", "carrello", "cassa", "ordine"],
  pt: ["pagamento", "carrinho"],
  pl: ["platnosc", "platnosci", "koszyk", "kasa", "zamowienie"],
  da: ["kasse", "kurv", "indkobskurv", "betaling", "bestilling"],
  no: ["kasse", "handlekurv", "betaling", "bestilling"],
  sv: ["kassa", "varukorg", "kundvagn", "betalning"],
  fi: ["kassa", "ostoskori", "maksu", "tilaus"],
  is: ["karfa", "greidsla"],
  cs: ["pokladna", "kosik", "platba", "objednavka"],
  sk: ["pokladna", "kosik", "platba", "objednavka"],
  hu: ["penztar", "kosar", "fizetes", "rendeles"],
  ro: ["cos", "plata", "comanda", "finalizare"],
  hr: ["blagajna", "kosarica", "placanje"],
  sl: ["blagajna", "kosarica", "placilo"],
  bg: ["plashtane", "kolichka", "kasa", "плащане", "количка", "каса"],
  el: ["pliromi", "kalathi", "tameio", "πληρωμη", "καλαθι", "ταμειο"],
  et: ["kassa", "ostukorv", "makse"],
  lv: ["kase", "grozs", "maksajums"],
  lt: ["kasa", "krepselis", "mokejimas"]
});
// Endings that also count INSIDE a longer token — platform and compound-word forms such as "onepagecheckout",
// "firecheckout", "onlinebanking", "anzahlung". Only words that are not the ending of an ordinary word.
export const TAMPER_ADDRESS_ENDINGS = Object.freeze(["checkout", "payment", "banking", "warenkorb", "zahlung",
  "betaling", "betalning", "handlekurv", "winkelwagen"]);
// 5.1.3 (owner, 2026-11-24) — crypto-currency words, under the same tick ("checkout and payment keywords"). Unlike the
// words above they are ALSO matched in the site's own name (core/tamper-guard.js hasAddressWord): for crypto the name
// is where fake wallet sites put the signal (URLhaus: www-featherwallet.com). Whole tokens; plus the endings below
// inside a longer token ("featherwallet", "ledgerwallet"). Deliberately left out: words that are ordinary words or
// short codes elsewhere ("eth", "ledger", "exodus", "phantom", "seed", "swap", "coin").
export const TAMPER_CRYPTO_WORDS = Object.freeze(["wallet", "wallets", "crypto", "cryptocurrency", "bitcoin", "btc",
  "ethereum", "usdt", "tether", "solana", "monero", "litecoin", "dogecoin", "metamask", "trezor", "coinbase", "binance",
  "walletconnect", "seedphrase", "mnemonic", "airdrop", "staking", "defi", "web3"]);
export const TAMPER_CRYPTO_ENDINGS = Object.freeze(["wallet", "crypto", "bitcoin"]);
// 5.1.4 (owner, 2026-11-24) — tgSeedSent: a crypto wallet's recovery ("seed") phrase sent to another site
// (security/tamper-guard-page.js carries a copy, checked by tools/test-tamper-guard.mjs). A phrase is WORD_COUNTS words
// of WORD_MIN–WORD_MAX lower-case letters (the BIP-39 word shape), typed in ONE field (text field or text area) or one
// word per field in at least the smallest WORD_COUNTS fields next to each other. It is found in outgoing data when
// MATCH_WORDS of its words appear in order with only non-letters between them (any separator, JSON, URL encoding).
export const TAMPER_SEED = Object.freeze({ WORD_COUNTS: [12, 15, 18, 21, 24], WORD_MIN: 3, WORD_MAX: 8, MATCH_WORDS: 8,
                                           FIELDS_MAX: 40 });
// Letters that keep their mark after Unicode decomposition (NFD), folded by hand: Polish ł, Nordic ø/æ, German ß,
// Croatian đ, Icelandic þ/ð, French œ.
export const TAMPER_ADDRESS_LETTER_FOLD = Object.freeze({ "ł": "l", "ø": "o", "æ": "ae", "ß": "ss", "đ": "d", "þ": "th",
  "ð": "d", "œ": "oe" });
// Guard (B6): at most this many address tokens are looked at (very long addresses are cut, never scanned whole).
export const TAMPER_ADDRESS_TOKENS_MAX = 64;
// 5.1.2 — A card number recognised by its VALUE (security/tamper-guard-page.js and security/tamper-guard-bridge.js
// carry copies, checked by tools/test-tamper-guard.mjs): only digits, spaces and dashes, this many digits, and a valid
// Luhn checksum. Finds card fields whatever the page named them; the checksum keeps order and phone numbers out.
export const TAMPER_CARD_VALUE_DIGITS = Object.freeze({ MIN: 13, MAX: 19 });
// Inputs read per check when looking for a card number by value (guard, B6).
export const TAMPER_CARD_VALUE_FIELDS_MAX = 50;
// 5.1.2 — Other sites' script hosts on closely watched pages (tgSuspiciousScript): at most this many hosts reported per
// page (security/tamper-guard-bridge.js copy), and this many host verdicts kept in memory (core/tamper-guard.js; oldest
// dropped). A verdict is the local site check only (core/site-scorer.js), so it does not go stale within a session.
export const TAMPER_SCRIPT_HOSTS_MAX = 24;
export const TAMPER_SCRIPT_VERDICTS_CAP = 500;
// 5.1.2 — Script providers that card skimmers imitate (jquery-cdn.net, googletagmanagr.com, cdn-stripe.xyz): name →
// the provider's real registered domains. A script host whose registered-domain name, or one of its dash-separated
// parts, STARTS with a name ("jquerycdn", "cdn-stripe" — not "pinstripe"), or for names of at least TAMPER_SCRIPT_TYPO.MIN_CHARS differs from it by at most TAMPER_SCRIPT_TYPO.MAX_EDITS
// letters, and is not one of the real domains, imitates that provider (core/tamper-guard.js imitatesProvider).
export const TAMPER_SCRIPT_PROVIDERS = Object.freeze({
  jquery:           ["jquery.com", "jqueryui.com", "jquerymobile.com"],
  googletagmanager: ["googletagmanager.com"],
  googleanalytics:  ["google-analytics.com"],
  googleapis:       ["googleapis.com"],
  gstatic:          ["gstatic.com"],
  stripe:           ["stripe.com", "stripe.network"],
  paypal:           ["paypal.com", "paypalobjects.com"],
  adyen:            ["adyen.com", "adyenpayments.com"],
  braintree:        ["braintreegateway.com", "braintree-api.com", "braintreepayments.com"],
  klarna:           ["klarna.com", "klarnaservices.com", "klarnacdn.net"],
  mollie:           ["mollie.com"],
  facebook:         ["facebook.com", "facebook.net"],
  cloudflare:       ["cloudflare.com", "cloudflareinsights.com"],
  jsdelivr:         ["jsdelivr.net"],
  bootstrapcdn:     ["bootstrapcdn.com"],
  magento:          ["magento.com"],
  shopify:          ["shopify.com", "shopifycdn.com", "shopifysvc.com"],
  hotjar:           ["hotjar.com"]
});
export const TAMPER_SCRIPT_TYPO = Object.freeze({ MIN_CHARS: 8, MAX_EDITS: 2 });
// After a closely watched page is left for another page of the SAME site, keep watching closely this long (bank and
// checkout flows hop between pages and redirects).
export const TAMPER_COOLDOWN_MS = 60 * 1000;
// Guards (B6): tabs tracked, stored never-warn entries, items and characters per reported detail, frame hosts per signal report.
export const TAMPER_TABS_CAP = 500;
export const TAMPER_DETAIL_ITEMS_MAX = 12;
export const TAMPER_DETAIL_TEXT_MAX = 120;
export const TAMPER_FRAME_HOSTS_MAX = 20;
// The warning window (an extension page — a page cannot remove or hide it, C47).
export const TAMPER_WARNING_PAGE = "ui/tamper-warning.html";
export const TAMPER_WARNING_ID_PARAM = "w";          // its query parameter: the warning id (C28: read from the sender's URL)
export const TAMPER_WARNING_WINDOW = Object.freeze({ width: 680, height: 620 });   // the dialog (max 608 px) + three buttons in one row
export const TAMPER_COUNTDOWN_S = 20;                // a non-critical warning closes itself after this (seconds); critical ones never (5.1.3: was 5, owner)
export const TAMPER_COUNTDOWN_TICK_MS = 1000;        // countdown display step
