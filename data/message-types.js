// ── data/message-types.js ─────────────────────────────────────────────────────
// Named constants for every chrome.runtime message. A typo becomes a
// ReferenceError instead of a silently unhandled message.
// ─────────────────────────────────────────────────────────────────────────────

// popup → SW
export const MSG_GET_POPUP_STATE   = "GET_POPUP_STATE";    // { tabId } → view model for the popup
export const MSG_SET_LEVEL         = "SET_LEVEL";          // { level, tabId } — global session level
export const MSG_SET_STARTUP_LEVEL = "SET_STARTUP_LEVEL";  // { level }
export const MSG_TOGGLE_LOCK       = "TOGGLE_LOCK";        // { site, level, tabId } — lock/unlock a site
export const MSG_SET_PROTECTION    = "SET_PROTECTION";     // { key, enabled }
export const MSG_SET_SAFE_ZONE     = "SET_SAFE_ZONE";      // { addTld?, removeTld?, restoreDefault? }

// popup / matrix panel → SW (Show Matrix)
export const MSG_OPEN_MATRIX       = "OPEN_MATRIX";        // { tabId, url } — start observing, open the panel window, reload the tab
export const MSG_STOP_MATRIX       = "STOP_MATRIX";        // { tabId }
export const MSG_GET_MATRIX_DATA   = "GET_MATRIX_DATA";    // { tabId } → rows + overrides + level
export const MSG_SET_MATRIX_RULE   = "SET_MATRIX_RULE";    // { tabId, domain, scope, action|null }
export const MSG_RELOAD_TAB        = "RELOAD_TAB";         // { tabId }

// warning page → SW
export const MSG_EVALUATE_SITE     = "EVALUATE_SITE";      // { url } → full (stage 1 + 2) result
export const MSG_WARNING_ACTION    = "WARNING_ACTION";     // { action, url, tabId }

// password-form guard (ISOLATED content script) → SW (4.6.0, warnPasswordForms). These two string values are also
// declared in security/password-form-guard.js (content scripts cannot import); tools/check-shipped-terms.mjs keeps
// every MSG_* copy there equal to this file.
export const MSG_CHECK_PASSWORD_FORM  = "CHECK_PASSWORD_FORM";   // { actionUrl } → { warn, destHost } (page = sender, C28)
export const MSG_PASSWORD_FORM_LEAVE  = "PASSWORD_FORM_LEAVE";   // {} — "Go back": leave the sender's site (core/leave-site.js)
// 4.7.0 — same rules (copies in security/*.js kept equal by tools/check-shipped-terms.mjs):
export const MSG_CHECK_FAKE_WINDOW    = "CHECK_FAKE_WINDOW";     // { shownText } → { warned } — Browser-in-the-Browser; 5.0.6: the SW opens the warning page itself
export const MSG_PAGE_SCAM_BLOCKED    = "PAGE_SCAM_BLOCKED";     // { kind: PAGE_SCAM_KIND.* } — a page scam was blocked: open
                                                                 // the warning (page = sender tab, C28)

// popup → SW (4.7.0)
export const MSG_GET_BROWSER_UPDATE   = "GET_BROWSER_UPDATE";    // {} → band model or null (core/browser-update.js)

// download warning page / VirusTotal key prompt → SW (warnRiskyDownloads, 4.3.0)
export const MSG_GET_DOWNLOAD_CHECK  = "GET_DOWNLOAD_CHECK";  // {} → { record, look } for the sender's ?downloadId= (C28)
export const MSG_DISMISS_DOWNLOAD    = "DISMISS_DOWNLOAD";    // {} — the user is done: release the check
export const MSG_VT_KEY_PROMPT_DONE  = "VT_KEY_PROMPT_DONE";  // { dontShowAgain } — nudge closed
// SW → download warning page (4.3.4, DS 3.3.0 item 16): a late VirusTotal verdict for an open page
export const MSG_DOWNLOAD_VT_UPDATE  = "DOWNLOAD_VT_UPDATE";  // { downloadId, record }
// download-blocked notice → SW (blockRiskyDownloads, 4.3.2) — the download id comes from the sender's URL (C28)
export const MSG_GET_BLOCKED_DOWNLOAD    = "GET_BLOCKED_DOWNLOAD";    // {} → notice model or null
export const MSG_BLOCKED_DOWNLOAD_ACTION = "BLOCKED_DOWNLOAD_ACTION"; // { action: BLOCKED_DOWNLOAD_ACTION.* }

// options page → SW
export const MSG_GET_OPTIONS       = "GET_OPTIONS";
export const MSG_SET_DNS           = "SET_DNS";            // { first, second }
export const MSG_SET_ALLOW_LIST    = "SET_ALLOW_LIST";     // { text }
export const MSG_SET_DOWNLOAD_SETTINGS = "SET_DOWNLOAD_SETTINGS"; // { settings: partial state.downloads, never vtApiKey }
export const MSG_SET_VT_KEY        = "SET_VT_KEY";         // { key } — "" clears the VirusTotal API key
export const MSG_EXPORT_SETTINGS   = "EXPORT_SETTINGS";
export const MSG_IMPORT_SETTINGS   = "IMPORT_SETTINGS";    // { settings }
export const MSG_RESET_SETTINGS    = "RESET_SETTINGS";

// Warning-dialog actions (MSG_WARNING_ACTION.action)
export const WARNING_ACTION = Object.freeze({
  GO_BACK:       "goBack",
  TRUST:         "trust",
  CONTINUE_ONCE: "continueOnce"
});

// Download-blocked notice actions (MSG_BLOCKED_DOWNLOAD_ACTION.action)
export const BLOCKED_DOWNLOAD_ACTION = Object.freeze({
  OK:               "ok",                // keep it blocked, close the notice
  DOWNLOAD_ANYWAY:  "downloadAnyway"     // continue the held download (4.5.5); warnRiskyDownloads then checks it
});

// ── Sender kinds (5.0.6, C46) ────────────────────────────────────────────────
// `sender.id === chrome.runtime.id` is also true for every content script this extension injects, so it does not
// tell an extension page from a content script running inside a web page. The router (background.js, via
// core/message-gate.js) refuses a message whose type is not listed for the sender's kind.
export const SENDER_KIND = Object.freeze({
  EXTENSION_PAGE: "extensionPage",   // popup, options, warning pages, notices, Show Matrix (sender.url = this extension)
  CONTENT_SCRIPT: "contentScript"    // security/*.js running inside a web page (sender.tab set, sender.url = the page)
});

// The ONLY messages a content script may send — exactly the ones security/*.js sends (tools/test-message-gate.mjs
// checks both directions). Every other message type is extension-page only.
export const CONTENT_SCRIPT_MESSAGES = Object.freeze(new Set([
  MSG_CHECK_PASSWORD_FORM,   // security/password-form-guard.js
  MSG_PASSWORD_FORM_LEAVE,   // security/password-form-guard.js
  MSG_CHECK_FAKE_WINDOW,     // security/fake-window-guard.js
  MSG_PAGE_SCAM_BLOCKED      // security/clickfix-bridge.js, consentfix-paste-guard.js, skimmer-bridge.js
]));
