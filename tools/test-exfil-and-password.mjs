#!/usr/bin/env node
// ── tools/test-exfil-and-password.mjs ────────────────────────────────────────────
// Unit test (4.6.0) for the pure parts of three new protections:
//   • blockExfilMessagingBots / blockExfilWebServices — the DNR rules core/rule-builder.js builds from
//     data/exfil-channels.js, replayed through core/rule-matcher.js (the same replay that decides whether a block
//     opens the warning, core/exfil-guard.js): which levels, which pages are exempt, which channel a rule id is;
//   • warnPasswordForms — core/password-form.js passwordFormDecision();
//   • script registrations: the ISOLATED-world twin of the password-form scripts (core/script-builder.js).
// Every value comes from the extension's own constants and tables — no level, id or host list is typed here
// except the example page/attacker hosts of the scenarios.
//
// Usage:  node test-exfil-and-password.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-exfil-and-password: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const load = (rel) => import(pathToFileURL(resolve(ext, rel)).href);
globalThis.chrome = { runtime: { getURL: (p) => p, getManifest: () => ({ version: "0" }) } };

let C, S, P, RB, RM, X, PF, SB, BD;
try {
  C  = await load("data/constants.js");
  S  = await load("data/state-storage.js");
  P  = await load("data/protections.js");
  RB = await load("core/rule-builder.js");
  RM = await load("core/rule-matcher.js");
  X  = await load("data/exfil-channels.js");
  PF = await load("core/password-form.js");
  SB = await load("core/script-builder.js");
  BD = await load("data/builtin-domains.js");
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }

let failed = 0;
function ok(name, cond, detail = "") { console.log(`${cond ? "      PASS" : "      FAIL"} ${name}${cond ? "" : "  " + detail}`); if (!cond) failed++; }

// ── Scenario hosts (examples, not data) ──
const PHISH_PAGE = "https://login-secure.example";          // a phishing page outside every exemption
const OTHER_SITE = "https://collector.example";
const EXAMPLE_PATH = "/x";
const K = P.PROTECTION_KEY;
const BOTS = X.EXFIL_CHANNELS.filter((c) => c.group === X.EXFIL_GROUP.MESSAGING_BOTS);
const WEB  = X.EXFIL_CHANNELS.filter((c) => c.group === X.EXFIL_GROUP.WEB_SERVICES);

function stateAt(level, edit = (s) => s) {
  const s = S.defaultState();
  s.level = level;
  return S.normalizeState(edit(s));
}
// A request to channel c as a phishing kit sends it (path inside the channel's urlFilter, if any).
function exfilUrl(c) {
  const host = c.requestDomains[0];
  const path = c.urlFilter ? c.urlFilter.replace(host, "").replace("*", "v10/") : EXAMPLE_PATH;
  return `https://${host}${path.startsWith("/") ? path : "/" + path}token`;
}
function replay(state, url, initiator, type = "xmlhttprequest") {
  const compiled = RM.compileRules(RB.buildDynamicRules(state, {}));
  return RM.matchOutcome(compiled, { url, type, initiator });
}

console.log("Exfiltration rules (blockExfilMessagingBots / blockExfilWebServices)");
ok("channels: one rule-id per channel, every id distinct", new Set(X.EXFIL_CHANNELS.map((c) => c.ruleLocalId)).size === X.EXFIL_CHANNELS.length);
ok("both groups have channels", BOTS.length > 0 && WEB.length > 0);
const fromMild = P.PROTECTION_BY_KEY[K.BLOCK_EXFIL_MESSAGING_BOTS].fromLevel;
const fromWeb  = P.PROTECTION_BY_KEY[K.BLOCK_EXFIL_WEB_SERVICES].fromLevel;
for (const c of BOTS) {
  const out = replay(stateAt(fromMild), exfilUrl(c), PHISH_PAGE);
  ok(`messaging bot ${c.id}: blocked from level ${fromMild}`, out.action === "block" && X.exfilChannelForRule(out.ruleId, C.GROUP_ID_STRIDE)?.id === c.id, JSON.stringify(out));
  ok(`messaging bot ${c.id}: not below level ${fromMild}`, replay(stateAt(fromMild - 1), exfilUrl(c), PHISH_PAGE).action !== "block");
  ok(`messaging bot ${c.id}: the service's own page is exempt`, X.exfilChannelForRule(replay(stateAt(fromMild), exfilUrl(c), `https://${c.ownDomains[0]}`).ruleId, C.GROUP_ID_STRIDE) === null);
  const off = stateAt(fromMild, (s) => { s.disabledProtections[K.BLOCK_EXFIL_MESSAGING_BOTS] = true; return s; });
  ok(`messaging bot ${c.id}: unticked → no rule`, X.exfilChannelForRule(replay(off, exfilUrl(c), PHISH_PAGE).ruleId, C.GROUP_ID_STRIDE) === null);
}
ok("a non-channel request on a channel host is not an exfiltration block (Discord page asset)",
   X.exfilChannelForRule(replay(stateAt(fromMild), "https://discord.com/assets/app.js", PHISH_PAGE, "script").ruleId, C.GROUP_ID_STRIDE) === null);
for (const c of WEB) {
  const out = replay(stateAt(fromWeb), exfilUrl(c), PHISH_PAGE);
  ok(`web service ${c.id}: blocked from level ${fromWeb}`, X.exfilChannelForRule(out.ruleId, C.GROUP_ID_STRIDE)?.id === c.id, JSON.stringify(out));
  ok(`web service ${c.id}: not below level ${fromWeb}`, X.exfilChannelForRule(replay(stateAt(fromWeb - 1), exfilUrl(c), PHISH_PAGE).ruleId, C.GROUP_ID_STRIDE) === null);
}
{
  const c = WEB[0];
  const state = stateAt(fromWeb);
  const [saferTld] = state.safeZone.tlds;
  ok(`web services: a page in safer regions (.${saferTld}) is exempt at level ${fromWeb}`,
     X.exfilChannelForRule(replay(state, exfilUrl(c), `https://shop.${saferTld}`).ruleId, C.GROUP_ID_STRIDE) === null);
  const [builtinHost] = BD.BUILTIN_ALL;
  ok("web services: a built-in-whitelist page is exempt", X.exfilChannelForRule(replay(state, exfilUrl(c), `https://${builtinHost}`).ruleId, C.GROUP_ID_STRIDE) === null);
  const [mbot] = BOTS;
  ok(`messaging bots: NOT exempt in safer regions (every site)`,
     X.exfilChannelForRule(replay(state, exfilUrl(mbot), `https://shop.${saferTld}`).ruleId, C.GROUP_ID_STRIDE)?.id === mbot.id);
}

console.log("Password-form decision (warnPasswordForms)");
const PF_STATE = stateAt(P.PROTECTION_BY_KEY[K.WARN_PASSWORD_FORMS].fromLevel);
const decide = (page, action, state = PF_STATE) => PF.passwordFormDecision(state, page, action);
ok("to another site → warn, names the destination", decide(PHISH_PAGE + "/login", OTHER_SITE + "/collect").warn && decide(PHISH_PAGE, OTHER_SITE + EXAMPLE_PATH).destHost === new URL(OTHER_SITE).host);
ok("same site (other subdomain) → no warning", !decide("https://www.shop.example/login", "https://auth.shop.example/session").warn);
ok("to a built-in sign-in service → no warning", !decide(PHISH_PAGE, `https://${BD.BUILTIN_SIGN_IN[0]}/login`).warn);
ok("to a built-in payment service → no warning", !decide(PHISH_PAGE, `https://${BD.BUILTIN_PAYMENT[0]}/pay`).warn);
ok("to a site the user trusts (allow list) → no warning",
   !decide(PHISH_PAGE, OTHER_SITE, stateAt(PF_STATE.level, (s) => { s.siteLocks["collector.example"] = C.LEVEL.ALLOW_ALL; s.siteLocksOrder.push("collector.example"); return s; })).warn);
ok("page trusted (level 1) → no warning",
   !decide(PHISH_PAGE, OTHER_SITE, stateAt(PF_STATE.level, (s) => { s.siteLocks["login-secure.example"] = C.LEVEL.ALLOW_ALL; s.siteLocksOrder.push("login-secure.example"); return s; })).warn);
ok("unticked → no warning", !decide(PHISH_PAGE, OTHER_SITE, stateAt(PF_STATE.level, (s) => { s.disabledProtections[K.WARN_PASSWORD_FORMS] = true; return s; })).warn);
ok("javascript:/mailto: destination → no warning", !decide(PHISH_PAGE, "javascript:void(0)").warn && !decide(PHISH_PAGE, "mailto:a@b.example").warn);
ok("non-http page → no warning", !decide("chrome-extension://x/page.html", OTHER_SITE).warn);

console.log("Script registrations (ISOLATED twin)");
{
  const regs = SB.buildScriptRegistrations(PF_STATE);
  const p = P.PROTECTION_BY_KEY[K.WARN_PASSWORD_FORMS];
  const iso = regs.filter((r) => r.world === "ISOLATED");
  const main = regs.filter((r) => r.world !== "ISOLATED" && p.scripts.every((f) => r.js.includes(f)));
  ok("password-form guard registered in the ISOLATED world", iso.length > 0 && iso.every((r) => p.isolatedScripts.every((f) => r.js.includes(f))), JSON.stringify(iso));
  ok("its MAIN-world hook registered too", main.length > 0);
  ok("ISOLATED and MAIN registrations never merge", regs.every((r) => !(r.world === "ISOLATED" && p.scripts.some((f) => r.js.includes(f)))));
  ok("ISOLATED twin has the MAIN scope (same matches)", iso.some((r) => main.some((m) => JSON.stringify([...m.matches].sort()) === JSON.stringify([...r.matches].sort()))));
}

console.log(failed ? `test-exfil-and-password: ${failed} FAILED` : "test-exfil-and-password: all passed");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
