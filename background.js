// ── background.js — 3P Matrix service worker (lifecycle + thin router) ───────
// No business logic here: every branch validates its input and delegates to a core/ or data/
// module (4.2.3, audit finding 6: lock/allow-list → core/site-locks.js, safer-regions edit →
// core/safer-regions.js, Show Matrix overrides → core/matrix-overrides.js, panel windows →
// core/matrix-windows.js, page models → core/view-models.js).
//
// Lifecycle
//   install          → default state, compute safer regions, apply
//   update / reload  → load state, level = startupLevel, recompute safer regions, apply
//   browser startup  → level = startupLevel, apply; VirusTotal-key nudge (warnRiskyDownloads) when due
//   every SW start   → download guard init (sweep alarm, DownloadSentinel list refresh) — idempotent;
//                      tab band rebuilt from the open tabs (the in-memory assignment is lost on a restart)
//
// Events
//   webNavigation.onBeforeNavigate (top frame) → stage 1 site check → warning dialog (warnSuspiciousSites);
//                                                tab band: the tab joins/leaves its site lock's band (4.4.5)
//   webNavigation.onCommitted (top frame)      → reset badge count, per-tab icon, tab band (after redirects)
//   webRequest.onErrorOccurred                 → count OUR blocks per tab (rule-matcher attribution)
//   tabs.onRemoved / windows.onRemoved         → release per-tab state, matrix panels and download
//                                                warning windows (guards)
//   downloads.onCreated / onChanged / onErased → warnRiskyDownloads + blockRiskyDownloads (core/download-guard.js)
//   alarms.onAlarm                             → stale download-check sweep
//
// All state mutations go through mutate(): load → change → save → apply, run
// under withStateLock() so two messages can never interleave.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, LEVEL_INFO, LOG_PREFIX, SEVERITY, MATRIX_SCOPE, MATRIX_ACTION, WARNING_PAGE, WARNING_TARGET_PARAM, WARNING_REASON_PARAM,
         CHROME_BLOCKED_BY_CLIENT_ERROR, CHROME_NEW_TAB_URL, DOWNLOAD_WARNING_PAGE, DOWNLOAD_BLOCKED_PAGE, DOWNLOAD_ID_PARAM,
         DECIMAL_RADIX, RT } from "./data/constants.js";
import * as M from "./data/message-types.js";
import { defaultState, loadState, saveState, normalizeState, withStateLock, isValidHost, parseLevel } from "./data/state-storage.js";
import { PROTECTION_BY_KEY, PROTECTION_KEY } from "./data/protections.js";
import { PAGE_SCAM_REASON_BY_ID, PAGE_SCAM_KIND, LEAVE } from "./data/page-scam-reasons.js";
import { DEVICE_CODE_URL_PATTERNS } from "./data/device-code-pages.js";
import { effectiveLevel } from "./core/policy.js";
import { applyState, applySessionRules, getCompiledRules } from "./core/apply-manager.js";
import { matchOutcome } from "./core/rule-matcher.js";
import { computeSaferRegions, editSaferRegions } from "./core/safer-regions.js";
import { scoreLocal } from "./core/site-scorer.js";
import { evaluateSite, clearScoreCache } from "./core/online-checks.js";
import { popupModel, matrixModel, optionsModel } from "./core/view-models.js";
import { lockSite, toggleLock, parseAllowListText, replaceAllowList } from "./core/site-locks.js";
import { setMatrixOverride } from "./core/matrix-overrides.js";
import { openMatrixPanel, closeMatrixPanel, onWindowRemoved } from "./core/matrix-windows.js";
import * as Badge from "./core/badge.js";
import * as Guard from "./core/navigation-guard.js";
import * as DeviceCode from "./core/device-code-guard.js";          // 4.7.0 — warnDeviceCodePages
import { senderKind, isMessageAllowed, senderLabel } from "./core/message-gate.js";   // 5.0.6 — C46 sender kinds
import * as PageScam from "./core/page-scam-guard.js";               // 4.7.0 — ClickFix / ConsentFix → warning
import * as BrowserUpdate from "./core/browser-update.js";           // 4.7.0 — Chrome out-of-date band
import * as Matrix from "./core/connection-matrix.js";
import * as TabSites from "./core/tab-sites.js";
import * as TabLocks from "./core/tab-locks.js";
import * as Downloads from "./core/download-guard.js";
import * as Exfil from "./core/exfil-guard.js";                 // 4.6.0 — exfiltration block → site warning
import { leaveSite } from "./core/leave-site.js";               // 4.6.0 — "Go back" that leaves the site
import { passwordFormDecision, fakeWindowDecision } from "./core/password-form.js"; // 4.6.0 warnPasswordForms; 4.7.0 blockFakeSignInWindow
import { applyDownloadSettings, setVtKey, dismissVtKeyPrompt } from "./core/download-settings.js";
import { toSettingsFile, fromSettingsFile, summarize } from "./data/settings-io.js";
import { parseHttpUrl, registeredDomain } from "./util/domain.js";

// ── Core helpers ─────────────────────────────────────────────────────────────
async function commit(state) {
  const saved = await saveState(state);
  await TabLocks.rebuild(saved);                        // locks/level may have changed: re-assign every open tab first
  await applyState(saved);
  Badge.setLevelIcon(saved.level);
  await refreshActiveTabIcon(saved);
  return saved;
}

function mutate(change) {
  return withStateLock(async () => {
    const state = await loadState();
    const result = await change(state);
    const saved = await commit(state);
    return { state: saved, result };
  });
}

async function refreshActiveTabIcon(state) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const p = tab && parseHttpUrl(tab.url || "");
    if (tab && p) Badge.setLevelIcon(effectiveLevel(state, p.host), tab.id);
  } catch { /* no window yet at browser start — global icon is enough */ }
}

// ── Lifecycle ────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener((details) => {
  withStateLock(async () => {
    const state = details.reason === "install" ? defaultState() : await loadState();
    state.level = state.startupLevel;
    state.prevLevel = state.startupLevel;
    // Every reason (install, update, reload): the list depends on code (base TLDs, auto-add
    // scope, country data) — 0.2.4 moves users of the removed slider to the fixed Continent scope.
    state.safeZone.tlds = await computeSaferRegions(state.safeZone);
    await commit(state);
  }).catch((e) => console.error(LOG_PREFIX, "onInstalled:", e));
});

chrome.runtime.onStartup.addListener(() => {
  withStateLock(async () => {
    const state = await loadState();
    state.level = state.startupLevel;
    state.prevLevel = state.startupLevel;
    return commit(state);
  }).then((state) => Downloads.offerVtKey(state))      // real browser start only — a SW restart never re-nudges
    .catch((e) => console.error(LOG_PREFIX, "onStartup:", e));
});

Downloads.init();                                       // every SW start (no event fires on a plain restart)
BrowserUpdate.init();                                    // 4.7.0 — daily alarm (idempotent)

// Tab band (4.4.5): a tab joined, left or closed its site lock's band → re-apply only the session rules.
function syncTabBand(tabId, url) {
  loadState().then((state) => (TabLocks.assign(state, tabId, url) ? applySessionRules(state) : null))
    .catch((e) => console.error(LOG_PREFIX, "tab band:", e));
}

// Every SW start: the session rules Chrome kept are still there, the in-memory assignment is not.
loadState().then(async (state) => { await TabLocks.rebuild(state); await applySessionRules(state); })
  .catch((e) => console.error(LOG_PREFIX, "tab band init:", e));

// ── Navigation / request events (registered synchronously at top level) ─────
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  syncTabBand(details.tabId, details.url);              // before the page creates its frames
  loadState().then((state) => Guard.checkNavigation(details, state))
    .catch((e) => console.error(LOG_PREFIX, "navigation check:", e));
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  syncTabBand(details.tabId, details.url);              // final URL, after redirects
  Badge.resetCount(details.tabId);
  const p = parseHttpUrl(details.url);
  TabSites.setTopHost(details.tabId, p ? p.host : "");
  Matrix.clearOnNavigation(details.tabId, p ? p.host : "");
  if (!p) return;
  Badge.clearRiskIfOtherSite(details.tabId, registeredDomain(p.host));
  loadState().then((state) => Badge.setLevelIcon(effectiveLevel(state, p.host), details.tabId))
    .catch((e) => console.error(LOG_PREFIX, "tab icon:", e));
});

function onRequestError(details) {
  if (details.error !== CHROME_BLOCKED_BY_CLIENT_ERROR || details.type === "main_frame" || details.tabId < 0) return;
  // Chrome reports ERR_BLOCKED_BY_CLIENT for blocks by ANY extension — the badge counts only
  // the requests our own rules block (core/rule-matcher.js replays DNR matching; an opaque
  // "null" initiator is matched as the tab's own site, as Chrome does).
  Promise.all([getCompiledRules(), TabSites.topHostOf(details.tabId)]).then(([compiled, topHost]) => {
    const outcome = matchOutcome(compiled, details, topHost);
    if (outcome.action !== "block") return;
    Badge.noteBlocked(details.tabId);
    return Exfil.onBlockedRequest(details.tabId, outcome.ruleId);   // 4.6.0: an exfiltration block also opens the warning
  }).catch((e) => console.warn(LOG_PREFIX, "block attribution failed:", e));
}
// 4.5.4 (perf P6): the `types` filter makes Chrome drop main-frame errors before they cross to the
// service worker (fewer wake-ups and events). Guard: a Chrome that does not know one of the types throws
// here — then listen without it (the main_frame check above still applies), never without a listener.
try {
  chrome.webRequest.onErrorOccurred.addListener(onRequestError, { urls: ["<all_urls>"], types: [...RT.ALL_SUB] });
} catch (e) {
  console.warn(LOG_PREFIX, "webRequest type filter rejected — listening unfiltered:", e);
  chrome.webRequest.onErrorOccurred.addListener(onRequestError, { urls: ["<all_urls>"] });
}

// ── Device-code warning (warnDeviceCodePages, 4.7.0) — filtered to the known device sign-in pages, so the service
// worker wakes ONLY for them. `initiator` (who started the navigation — a page cannot fake or hide it, unlike the
// Referer header) exists on webRequest events, not on webNavigation, hence this separate listener. Non-blocking:
// the real page is not held (as warnSuspiciousSites), the tab races to the warning instead.
chrome.webRequest.onBeforeRequest.addListener((details) => {
  loadState().then((state) => DeviceCode.onDeviceCodeRequest(details, state))
    .catch((e) => console.error(LOG_PREFIX, "device-code check:", e));
}, { urls: [...DEVICE_CODE_URL_PATTERNS], types: ["main_frame"] });

// ── Downloads (warnRiskyDownloads) — the guard decides per download whether it is active ────────────────
chrome.downloads.onCreated.addListener((item) => {
  loadState().then((state) => Downloads.onCreated(item, state))
    .catch((e) => console.error(LOG_PREFIX, "download created:", e));
});

chrome.downloads.onChanged.addListener((delta) => {
  loadState().then((state) => Downloads.onChanged(delta, state))
    .catch((e) => console.error(LOG_PREFIX, "download changed:", e));
});

chrome.downloads.onErased.addListener(Downloads.onErased);
chrome.alarms.onAlarm.addListener((alarm) => {
  Downloads.onAlarm(alarm).catch((e) => console.error(LOG_PREFIX, "download sweep:", e));
  BrowserUpdate.onAlarm(alarm).catch((e) => console.error(LOG_PREFIX, "browser-update check:", e));   // 4.7.0
});

// A tab swapped for another one (prerender, instant navigation): the old id is gone, the new one is re-read.
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
  releaseBand(removedTabId);
  chrome.tabs.get(addedTabId).then((tab) => syncTabBand(addedTabId, tab.url || tab.pendingUrl))
    .catch(() => { /* gone already */ });
});

function releaseBand(tabId) {
  if (TabLocks.release(tabId)) loadState().then(applySessionRules).catch((e) => console.error(LOG_PREFIX, "tab band release:", e));
}

chrome.tabs.onRemoved.addListener((tabId) => {
  releaseBand(tabId);
  Badge.releaseTab(tabId);
  Guard.releaseTab(tabId);
  TabSites.releaseTab(tabId);
  closeMatrixPanel(tabId);
});

chrome.windows.onRemoved.addListener((windowId) => {
  onWindowRemoved(windowId);                            // Show Matrix panels
  Downloads.onWindowRemoved(windowId)                   // download warning windows + blocked-download notices
    .catch((e) => console.error(LOG_PREFIX, "download window closed:", e));
});

// ── Input guards (audit finding 11 — C6 / C28) ───────────────────────────────
function requireTabId(msg) {
  if (!Number.isInteger(msg.tabId) || msg.tabId < 0) throw new Error("bad tab");
  return msg.tabId;
}

// This extension's own origin ("chrome-extension://<id>/") — an extension-page sender's URL starts with it (C46).
const EXTENSION_ORIGIN = chrome.runtime.getURL("");

// The site a warning-page message is about: taken from the sender's own URL (?u=) when the
// message comes from our warning page (C28 — never trust a message field when the sender says
// it), else from msg.url (pages that act on another tab's URL, e.g. tests and the popup).
function warningTarget(msg, sender) {
  const warningPage = chrome.runtime.getURL(WARNING_PAGE);
  if (sender.url && sender.url.startsWith(warningPage)) {
    const u = new URL(sender.url).searchParams.get(WARNING_TARGET_PARAM);
    if (u) return u;
  }
  return msg.url || "";
}

// 4.6.0: the exfiltration channel the warning is about — ONLY from the warning page's own URL (C28).
function warningReason(sender) {
  const warningPage = chrome.runtime.getURL(WARNING_PAGE);
  return sender.url && sender.url.startsWith(warningPage) ? new URL(sender.url).searchParams.get(WARNING_REASON_PARAM) : null;
}

// 4.6.0: pages a content-script message comes from — ONLY from the sender, which Chrome vouches for (C28).
// The FRAME holding the form decides "same site or not" (a login frame posting to its own site is fine);
// leaving goes by the TAB's top page, the site the user sees.
function senderFrameUrl(sender) { return sender.url || (sender.tab && sender.tab.url) || ""; }
function senderTabUrl(sender)   { return (sender.tab && sender.tab.url) || ""; }

// The download a download page's message is about: ONLY from the sender's own URL (C28) — and only
// from the page that belongs to that message (warning page or blocked notice).
function downloadTarget(sender, pagePath = DOWNLOAD_WARNING_PAGE) {
  const page = chrome.runtime.getURL(pagePath);
  if (!sender.url || !sender.url.startsWith(page)) throw new Error(`not ${pagePath}`);
  const id = Number.parseInt(new URL(sender.url).searchParams.get(DOWNLOAD_ID_PARAM), DECIMAL_RADIX);
  if (!Number.isInteger(id) || id < 0) throw new Error("bad download id");
  return id;
}

// ── Message router ───────────────────────────────────────────────────────────
const HANDLERS = {
  [M.MSG_GET_POPUP_STATE]: async (msg) => popupModel(await loadState(), msg.tabId, msg.url),

  [M.MSG_SET_LEVEL]: async (msg) => {
    const level = parseLevel(msg.level);
    if (level === null) throw new Error("bad level");
    const { state } = await mutate((s) => { if (s.level !== level) { s.prevLevel = s.level; s.level = level; } });
    return popupModel(state, msg.tabId, msg.url);
  },

  [M.MSG_SET_STARTUP_LEVEL]: async (msg) => {
    const level = parseLevel(msg.level);
    if (level === null) throw new Error("bad level");
    const { state } = await mutate((s) => { s.startupLevel = level; });
    return popupModel(state, msg.tabId, msg.url);
  },

  // Lock: pin the CURRENT session level to the site, then restore the session
  // level the user had before moving the slider (3P-Matrix-lite behaviour).
  [M.MSG_TOGGLE_LOCK]: async (msg) => {
    const p = parseHttpUrl(msg.url || "");
    if (!p) throw new Error("not a lockable page");
    const site = registeredDomain(p.host);
    const { state } = await mutate((s) => toggleLock(s, site));
    return popupModel(state, msg.tabId, msg.url);
  },

  [M.MSG_SET_PROTECTION]: async (msg) => {
    if (!PROTECTION_BY_KEY[msg.key]) throw new Error("unknown protection");
    const { state } = await mutate((s) => {
      if (msg.enabled) delete s.disabledProtections[msg.key]; else s.disabledProtections[msg.key] = true;
    });
    return popupModel(state, msg.tabId, msg.url);
  },

  [M.MSG_SET_SAFE_ZONE]: async (msg) => {
    const { state } = await mutate((s) => editSaferRegions(s.safeZone, msg));
    return popupModel(state, msg.tabId, msg.url);
  },

  // ── Show Matrix ──
  [M.MSG_OPEN_MATRIX]: async (msg) => {
    const p = parseHttpUrl(msg.url || "");
    if (!p || !Number.isInteger(msg.tabId)) throw new Error("Show Matrix works on web pages only");
    await openMatrixPanel(msg.tabId, p.host);
    return true;
  },

  [M.MSG_STOP_MATRIX]: async (msg) => { Matrix.stopMatrix(requireTabId(msg)); return true; },

  [M.MSG_GET_MATRIX_DATA]: async (msg) => matrixModel(await loadState(), msg.tabId),

  [M.MSG_SET_MATRIX_RULE]: async (msg) => {
    const activeSite = Matrix.getMatrixData(msg.tabId).site;    // guard: Show Matrix must be tracking this tab
    const domain = String(msg.domain || "").toLowerCase();
    if (!activeSite || !isValidHost(domain) || !Object.values(MATRIX_SCOPE).includes(msg.scope)) throw new Error("bad matrix rule");
    const action = Object.values(MATRIX_ACTION).includes(msg.action) ? msg.action : null;
    const { state } = await mutate((s) => setMatrixOverride(s, domain, msg.scope, action));
    return matrixModel(state, msg.tabId);
  },

  [M.MSG_RELOAD_TAB]: async (msg) => { await chrome.tabs.reload(requireTabId(msg)); return true; },

  [M.MSG_EVALUATE_SITE]: async (msg, sender) => {
    const state = await loadState();
    const local = scoreLocal(warningTarget(msg, sender));
    if (!local) return null;
    const full = await evaluateSite(local, state.dns);
    if (sender.tab) {
      Badge.setRisk(sender.tab.id, full.site, full.severity);
      // 4.7.0: a PHISHING verdict (or a cleared one) changes the alsoHighRisk tab band — re-apply.
      applySessionRules(state).catch((e) => console.error(LOG_PREFIX, "high-risk band (evaluate site):", e));
    }
    return { ...full, levelInfo: LEVEL_INFO };
  },

  [M.MSG_WARNING_ACTION]: async (msg, sender) => {
    const tabId = sender.tab ? sender.tab.id : msg.tabId;
    const p = parseHttpUrl(warningTarget(msg, sender));
    if (!p || tabId === undefined) throw new Error("bad warning action");
    const site = registeredDomain(p.host);
    const reason = warningReason(sender);
    // 4.7.0: a page-scam reason (data/page-scam-reasons.js) may ask for LEAVE.NEW_TAB instead of walking the site's
    // own history back (deviceCode: going back one step would return to the site that SENT the user here).
    const scam = reason ? PAGE_SCAM_REASON_BY_ID[reason] : null;
    if (msg.action === M.WARNING_ACTION.GO_BACK) {
      if (scam && scam.leave === LEAVE.NEW_TAB) { await chrome.tabs.update(tabId, { url: CHROME_NEW_TAB_URL }); return true; }
      if (reason) { await leaveSite(tabId, site); return true; }   // exfiltration or a site-leaving page scam
      try { await chrome.tabs.goBack(tabId); }
      catch { await chrome.tabs.update(tabId, { url: CHROME_NEW_TAB_URL }); }   // no history: open a new-tab page
      return true;
    }
    if (msg.action === M.WARNING_ACTION.TRUST) {
      if (scam && scam.canTrust === false) throw new Error("this warning has no Trust action");
      await mutate((s) => lockSite(s, site, LEVEL.ALLOW_ALL));
      Badge.setRisk(tabId, site, SEVERITY.NONE);
      // 4.7.0: trusting the site also drops it from the alsoHighRisk tab band — re-apply.
      loadState().then(applySessionRules).catch((e) => console.error(LOG_PREFIX, "high-risk band (trust):", e));
    } else if (msg.action === M.WARNING_ACTION.CONTINUE_ONCE) {
      await Guard.allowOnce(tabId, site);                   // stored before the tab reloads (4.5.4)
    } else {
      throw new Error("unknown warning action");
    }
    await chrome.tabs.update(tabId, { url: p.url });
    return true;
  },

  // ── Password-field warnings (page from the sender only, C28) ──
  [M.MSG_CHECK_PASSWORD_FORM]: async (msg, sender) => passwordFormDecision(await loadState(), senderFrameUrl(sender), String(msg.actionUrl || "")),

  // 4.7.0 — blockFakeSignInWindow (Browser-in-the-Browser). 5.0.6: on a hit the service worker opens
  // the red warning page itself (C47 — an in-page dialog could be removed by the page); the reply only says so.
  [M.MSG_CHECK_FAKE_WINDOW]: async (msg, sender) => {
    const state = await loadState();
    const decision = fakeWindowDecision(state, senderFrameUrl(sender), String(msg.shownText || ""));
    if (!decision.warn) return { warned: false };
    const warned = await PageScam.openPageScamWarning(state, PAGE_SCAM_KIND.FAKE_SIGN_IN_WINDOW, PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW, sender);
    return { warned };
  },

  [M.MSG_PASSWORD_FORM_LEAVE]: async (msg, sender) => {
    const p = parseHttpUrl(senderTabUrl(sender));
    if (!p || !sender.tab) throw new Error("bad password-form action");
    await leaveSite(sender.tab.id, registeredDomain(p.host));
    return true;
  },

  // 4.7.0 — ClickFix / ConsentFix: a content script BLOCKED the page scam itself; this opens the matching warning
  // (core/page-scam-guard.js — tab and page from the sender only, C28).
  [M.MSG_PAGE_SCAM_BLOCKED]: async (msg, sender) => PageScam.onPageScamBlocked(await loadState(), String(msg.kind || ""), sender),

  // 4.7.0 — Chrome out-of-date band (popup)
  [M.MSG_GET_BROWSER_UPDATE]: async () => BrowserUpdate.popupBand(),

  // ── Download protection (warnRiskyDownloads) ──
  [M.MSG_GET_DOWNLOAD_CHECK]: async (msg, sender) => Downloads.pageModel(downloadTarget(sender), await loadState()),

  [M.MSG_DISMISS_DOWNLOAD]: async (msg, sender) => { Downloads.dismiss(downloadTarget(sender)); return true; },

  // blockRiskyDownloads notice
  [M.MSG_GET_BLOCKED_DOWNLOAD]: async (msg, sender) => Downloads.blockedModel(downloadTarget(sender, DOWNLOAD_BLOCKED_PAGE)),

  [M.MSG_BLOCKED_DOWNLOAD_ACTION]: async (msg, sender) => {
    await Downloads.blockedAction(downloadTarget(sender, DOWNLOAD_BLOCKED_PAGE), msg.action, await loadState());
    return true;
  },

  [M.MSG_VT_KEY_PROMPT_DONE]: async (msg) => {
    if (msg.dontShowAgain === true) await mutate((s) => dismissVtKeyPrompt(s));
    return true;
  },

  [M.MSG_SET_DOWNLOAD_SETTINGS]: async (msg) => {
    const { state } = await mutate((s) => applyDownloadSettings(s, msg.settings));
    return optionsModel(state);
  },

  [M.MSG_SET_VT_KEY]: async (msg) => {
    const { state } = await mutate((s) => setVtKey(s, msg.key));
    return optionsModel(state);
  },

  [M.MSG_GET_OPTIONS]: async () => optionsModel(await loadState()),

  [M.MSG_SET_DNS]: async (msg) => {
    const { state } = await mutate((s) => { s.dns = { first: msg.first, second: msg.second }; });
    clearScoreCache();                                      // results depend on the chosen resolvers
    return optionsModel(state);
  },

  // The allow-list text is the authoritative list of LEVEL-1 locks only;
  // sites locked at other levels are never shown or touched here.
  [M.MSG_SET_ALLOW_LIST]: async (msg) => {
    const wanted = parseAllowListText(msg.text);
    const { state } = await mutate((s) => replaceAllowList(s, wanted));
    return optionsModel(state);
  },

  [M.MSG_EXPORT_SETTINGS]: async () => {
    const state = await loadState();
    return { file: toSettingsFile(state, chrome.runtime.getManifest().version), summary: summarize(state) };
  },

  [M.MSG_IMPORT_SETTINGS]: async (msg) => {
    const incoming = fromSettingsFile(msg.settings);                 // throws on a foreign file
    const { state } = await mutate(async (s) => {
      const keepVtKey = s.downloads.vtApiKey;                        // 4.4.1: only used when the file has none
      Object.assign(s, normalizeState(incoming));
      // The file carries the key since 4.4.1 (normalizeState drops an invalid one). An older file — or one
      // saved before a key was set — must not clear the key this browser already has.
      if (!s.downloads.vtApiKey) s.downloads.vtApiKey = keepVtKey;
      s.safeZone.tlds = await computeSaferRegions(s.safeZone);       // recomputed for this browser's languages
    });
    clearScoreCache();
    return { ...optionsModel(state), summary: summarize(state) };
  },

  [M.MSG_RESET_SETTINGS]: async () => {
    const { state } = await mutate(async (s) => {
      Object.assign(s, defaultState());
      s.safeZone.tlds = await computeSaferRegions(s.safeZone);
    });
    clearScoreCache();
    return optionsModel(state);
  }
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Guard 1: only this extension (no externally_connectable — checked anyway, C28).
  if (!sender || sender.id !== chrome.runtime.id) { sendResponse({ ok: false, error: "foreign sender" }); return false; }
  const handler = msg && HANDLERS[msg.type];
  if (!handler) { sendResponse({ ok: false, error: "unknown message" }); return false; }
  // Guard 2 (5.0.6, C46): content scripts carry this extension's id too — each message type is allowed only for
  // its sender kind (an extension page, or a content script inside a web page; data/message-types.js).
  if (!isMessageAllowed(msg.type, senderKind(sender, EXTENSION_ORIGIN))) {
    console.warn(LOG_PREFIX, "refused", msg.type, "from", senderLabel(sender));   // origin only (C52)
    sendResponse({ ok: false, error: "not allowed for this sender" });
    return false;
  }
  handler(msg, sender)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((e) => { console.warn(LOG_PREFIX, msg.type, e); sendResponse({ ok: false, error: String(e && e.message || e) }); });
  return true;                                              // async response
});
