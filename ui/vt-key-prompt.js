// ── ui/vt-key-prompt.js — VirusTotal key nudge controller ─────────────────────────
// Port of DownloadSentinel 3.2.0 pages/vtkeyprompt/VtKeyPrompt.js (C21), same behaviour:
//   Request → opens VirusTotal's sign-up page in a new tab; Ignore → nothing more.
//   Either way: when "don't show this again" is ticked, the service worker stores that
//   (state.downloads.vtKeyPromptDismissed); then the window closes itself.
// Guard: both buttons are disabled on the first click (no double action); a failed save is shown in
// the status line and the buttons are released, instead of closing as if it had worked.
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { VT_JOIN_URL, LOG_PREFIX } from "../data/constants.js";
import { showError, releaseStatus } from "./status-line.js";

const BUTTON_IDS = Object.freeze(["ignoreBtn", "requestBtn"]);

function $(id) { return document.getElementById(id); }
function setButtons(disabled) { for (const id of BUTTON_IDS) $(id).disabled = disabled; }

async function finish(openSignup) {
  setButtons(true);
  try {
    if (openSignup) chrome.tabs.create({ url: VT_JOIN_URL }).catch((e) => console.warn(LOG_PREFIX, "VirusTotal sign-up tab:", e));
    const res = await chrome.runtime.sendMessage({ type: M.MSG_VT_KEY_PROMPT_DONE, dontShowAgain: $("dontShowAgain").checked });
    if (!res || !res.ok) throw new Error(res && res.error || "no response");
    window.close();
  } catch (e) {
    showError($("vkStatus"), e);
    setButtons(false);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("ignoreBtn").addEventListener("click", () => finish(false));
  $("requestBtn").addEventListener("click", () => finish(true));
});

window.addEventListener("pagehide", releaseStatus);
