// ── ui/download-blocked.js — blockRiskyDownloads notice controller (4.3.2) ──────────────
// Shows which risky download was blocked (held — paused, 4.5.5) and why; OK cancels and deletes it, "Download
// anyway" continues the same download (warnRiskyDownloads then checks it). The download id is read by the service worker from this page's
// URL (C28) — the page never sends it. Texts go in via textContent; failures show in the status line.
// State: busy (one action at a time), released with the page.
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { LOG_PREFIX, DOWNLOAD_BLOCK_REASON as BLOCK_REASON } from "../data/constants.js";
import { fillDerivedText } from "./derived-text.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Settings (one place) ─────────────────────────────────────────────────────
const BUTTON_IDS = Object.freeze(["btnOk", "btnAnyway"]);
const GONE_TEXT = "This blocked download is no longer active — you can close this window.";

let busy = false;

function $(id) { return document.getElementById(id); }
function setButtons(disabled) { for (const id of BUTTON_IDS) $(id).disabled = disabled; }
function baseName(path) { return String(path || "").split(/[\\/]/).pop(); }

function reasonText(m) {
  if (m.reason.kind === BLOCK_REASON.HIGH_RISK) {
    return "This site is known for risky downloads, so this file is blocked regardless of your protection level.";
  }
  if (m.reason.kind === BLOCK_REASON.OUTSIDE_SAFER) {
    return `At level ${m.reason.level} risky downloads from sites outside your safer regions are blocked` +
           (m.reason.tld ? ` (.${m.reason.tld} is not one of them).` : ".");
  }
  return `At level ${m.reason.level} every risky download (program, script, archive) is blocked.`;
}

function render(m) {
  $("dbFile").textContent = baseName(m.filename) || baseName(new URL(m.url).pathname) || m.url;
  $("dbFrom").textContent = `From ${m.site || new URL(m.url).host}`;
  $("dbReason").textContent = reasonText(m);
}

async function act(action) {
  if (busy) return;
  busy = true;
  setButtons(true);
  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_BLOCKED_DOWNLOAD_ACTION, action });
    if (!res || !res.ok) throw new Error(res && res.error || "no response");
    window.close();
  } catch (e) {
    showError($("dbStatus"), e, "That did not work");
    busy = false;                                            // release so the user can try again
    setButtons(false);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  fillDerivedText(document);
  $("btnOk").addEventListener("click", () => act(M.BLOCKED_DOWNLOAD_ACTION.OK));
  $("btnAnyway").addEventListener("click", () => act(M.BLOCKED_DOWNLOAD_ACTION.DOWNLOAD_ANYWAY));
  $("btnOk").focus();
  try {
    const res = await chrome.runtime.sendMessage({ type: M.MSG_GET_BLOCKED_DOWNLOAD });
    if (!res || !res.ok) throw new Error(res && res.error || "no response");
    if (!res.data) { $("dbFile").textContent = GONE_TEXT; setButtons(true); return; }
    render(res.data);
  } catch (e) {
    showError($("dbStatus"), e, "Could not load the blocked download");
    console.warn(LOG_PREFIX, "download blocked:", e);
  }
});

window.addEventListener("pagehide", releaseStatus);
