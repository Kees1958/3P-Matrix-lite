// ── data/exfil-channels.js ────────────────────────────────────────────────────
// 4.6.0 — where phishing pages send stolen data straight from the victim's browser: the ONE table behind
// protections "Block exfiltrating (phishing) data to messaging bots" (blockExfilMessagingBots, every site from
// level 2) and "… to web services" (blockExfilWebServices, outside safer regions from level 3).
//
// Per channel: one DNR block rule (core/rule-builder.js) on every sub-resource request to the channel, except
// when the page itself belongs to the channel's own service (ownDomains — e.g. Discord's web app calling its API).
// A request blocked by one of these rules also opens the site warning with the channel's label
// (core/exfil-guard.js) — the block stops the theft, the warning says why the page is dangerous.
//
//   messaging bots — almost never called from a web page legitimately: a bot token or webhook URL in page code is
//                    readable by anyone, so real integrations call them from a server.
//   web services   — real data channels that some ordinary sites also use from the page (static-site contact
//                    forms, business workflows); hence only outside safer regions. IP-lookup services were left
//                    out on purpose (user decision 2026-11-06): they show WHO visits, they do not carry data away,
//                    and ordinary sites use them for currency/language.
//   Microsoft Teams: the old incoming-webhook host (webhook.office.com) was switched off 18–22 May 2026; its
//                    successor is a Power Automate workflow trigger, listed under web services.
//
// Fields: id (warning-page parameter value), group, ruleLocalId (data/constants.js RULE_LOCAL_ID), label (warning
// text: "This page tried to send data to <label>"), requestDomains (host or any subdomain), urlFilter (optional,
// DNR syntax — plain substring and * only, the subset core/rule-matcher.js replays), ownDomains (pages exempt).
// ─────────────────────────────────────────────────────────────────────────────

import { RULE_LOCAL_ID as ID } from "./constants.js";

export const EXFIL_GROUP = Object.freeze({ MESSAGING_BOTS: "messagingBots", WEB_SERVICES: "webServices" });

export const EXFIL_CHANNELS = Object.freeze([
  { id: "telegramBot",   group: EXFIL_GROUP.MESSAGING_BOTS, ruleLocalId: ID.EXFIL_TELEGRAM_BOT, label: "a Telegram bot",
    requestDomains: ["api.telegram.org"], urlFilter: "api.telegram.org/bot", ownDomains: ["telegram.org", "t.me"] },
  { id: "discordWebhook", group: EXFIL_GROUP.MESSAGING_BOTS, ruleLocalId: ID.EXFIL_DISCORD_HOOK, label: "a Discord webhook",
    requestDomains: ["discord.com", "discordapp.com"], urlFilter: "/api/*webhooks/", ownDomains: ["discord.com", "discordapp.com"] },
  { id: "slackWebhook",  group: EXFIL_GROUP.MESSAGING_BOTS, ruleLocalId: ID.EXFIL_SLACK_HOOK, label: "a Slack webhook",
    requestDomains: ["hooks.slack.com"], urlFilter: "hooks.slack.com/services/", ownDomains: ["slack.com"] },
  { id: "formMail",      group: EXFIL_GROUP.WEB_SERVICES, ruleLocalId: ID.EXFIL_FORM_MAIL, label: "a form-to-email service",
    requestDomains: ["formsubmit.co", "formspree.io", "getform.io", "api.emailjs.com", "api.web3forms.com"],
    ownDomains: ["formsubmit.co", "formspree.io", "getform.io", "emailjs.com", "web3forms.com"] },
  { id: "powerAutomate", group: EXFIL_GROUP.WEB_SERVICES, ruleLocalId: ID.EXFIL_AUTOMATION, label: "a Power Automate workflow",
    requestDomains: ["logic.azure.com", "powerplatform.com"], urlFilter: "/workflows/",
    ownDomains: ["microsoft.com", "office.com", "powerautomate.com", "powerplatform.com", "azure.com", "sharepoint.com", "live.com"] }
].map((c) => Object.freeze({ ...c, requestDomains: Object.freeze(c.requestDomains), ownDomains: Object.freeze(c.ownDomains) })));

export const EXFIL_CHANNEL_BY_ID = Object.freeze(Object.fromEntries(EXFIL_CHANNELS.map((c) => [c.id, c])));
const BY_LOCAL_ID = new Map(EXFIL_CHANNELS.map((c) => [c.ruleLocalId, c]));

// The channel behind a dynamic/session rule id (any group: id = stride × group index + local id), or null.
export function exfilChannelForRule(ruleId, groupIdStride) {
  return Number.isInteger(ruleId) ? BY_LOCAL_ID.get(ruleId % groupIdStride) || null : null;
}
