// ── core/message-gate.js ──────────────────────────────────────────────────────
// 5.0.6 (C46) — which kind of sender may send which message. Pure: no chrome.* call, no state.
//
// Public interface:
//   senderKind(sender, extensionOrigin)     → SENDER_KIND.* or null (unknown/foreign sender)
//   isMessageAllowed(type, kind)            → true when `kind` may send message `type`
//   senderLabel(sender)                     → the sender's origin only, for logs (5.0.7, C52: never a full address)
//
// Why: background.js used to accept any message whose sender carried this extension's id — which every content
// script does. A content script (code that runs next to hostile pages, C35/C47) could then reach settings import,
// reset or "Trust this site". Now a content script may only send CONTENT_SCRIPT_MESSAGES; everything else is for
// the extension's own pages. Same idea as uBlock-Stripped-Dynamic's route table (SENDER_KINDS).
//
// Dependencies: data/message-types.js (SENDER_KIND, CONTENT_SCRIPT_MESSAGES).
// State owned: none.
// ─────────────────────────────────────────────────────────────────────────────

import { SENDER_KIND, CONTENT_SCRIPT_MESSAGES } from "../data/message-types.js";

// `extensionOrigin` = chrome.runtime.getURL("") (ends with "/"), passed in so this module stays pure and testable.
export function senderKind(sender, extensionOrigin) {
  if (!sender || typeof sender.url !== "string" || typeof extensionOrigin !== "string" || extensionOrigin === "") return null;
  if (sender.url.startsWith(extensionOrigin)) return SENDER_KIND.EXTENSION_PAGE;
  if (sender.tab && Number.isInteger(sender.tab.id)) return SENDER_KIND.CONTENT_SCRIPT;
  return null;
}

export function isMessageAllowed(type, kind) {
  if (kind === SENDER_KIND.EXTENSION_PAGE) return !CONTENT_SCRIPT_MESSAGES.has(type);
  if (kind === SENDER_KIND.CONTENT_SCRIPT) return CONTENT_SCRIPT_MESSAGES.has(type);
  return false;
}

// 5.0.7 (C52): logs name the sender by origin only — a full address can carry a path, query or token.
export function senderLabel(sender) {
  if (!sender || typeof sender.url !== "string") return "an unknown sender";
  try { return new URL(sender.url).origin; } catch { return "an unparseable sender"; }
}
