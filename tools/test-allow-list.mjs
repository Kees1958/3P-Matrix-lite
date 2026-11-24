#!/usr/bin/env node
// ── tools/test-allow-list.mjs ─────────────────────────────────────────────────
// 5.1.3 — the ONE allow list with categories (data/allow-categories.js, core/site-locks.js, core/policy.js):
//   A. text format: "Category: domain", bare domain = All, case-insensitive category, errors named, "All" wins.
//   B. storage: All = level-1 locks, Download = downloads.trustedDomains, Firewall/Scam/Tamper = allowCategories;
//      normalize; settings-file round trip; sorted text out.
//   C. "Always allow / ignore": addToAllowList; "All" already covering the site is a no-op.
//   D. effects: script registrations exclude a category's sites (Scam / Tamper bundles); scam warnings and tamper
//      findings skip them; "Trust app stores" switches the built-in app stores.
// Usage:  node test-allow-list.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
function didNotRun(msg) { console.error(`test-allow-list: DID NOT RUN — ${msg}`); process.exit(EXIT.DID_NOT_RUN); }

const ext = arg("extension");
if (!ext || !existsSync(join(ext, "manifest.json"))) didNotRun("missing or invalid --extension <folder>");
const EXT = resolve(ext);
const load = (rel) => import(pathToFileURL(join(EXT, rel)).href);

let failures = 0;
function ok(label, pass, detail) {
  console.log(`${pass ? "PASS" : "FAIL"} ${label}${pass ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!pass) failures += 1;
}

let S, L, A, POL, B, IO, X, C, DL;
try {
  S = await load("data/state-storage.js");
  L = await load("core/site-locks.js");
  A = await load("data/allow-categories.js");
  POL = await load("core/policy.js");
  B = await load("core/script-builder.js");
  IO = await load("data/settings-io.js");
  X = await load("core/xss-link-guard.js");
  C = await load("data/constants.js");
  DL = await load("core/download-settings.js");
} catch (e) { didNotRun(`cannot import extension modules: ${e.message}`); }
const CAT = A.ALLOW_CATEGORY;

// ── A. text format ──
{
  const r = L.parseAllowListText("example.com\nSCAM: www.tool.example\ntamper : bank.example\nDownload: files.example\n" +
    "firewall: portal.example\nscam: example.com\nbogus: x.example\nAll: not a host\n# comment\n\nhttps://www.addr.example/path");
  ok("A. bare domain = All; category word case-insensitive; an address is cut to its site",
     r.entries.all.join() === "example.com,addr.example" && r.entries.scam.join() === "tool.example" &&
     r.entries.tamper.join() === "bank.example" && r.entries.download.join() === "files.example" && r.entries.firewall.join() === "portal.example", r.entries);
  ok("A. unknown category and invalid domain are named, never dropped silently", r.errors.join("|") === "bogus: x.example|All: not a host", r.errors);
  ok("A. All for a domain removes its other lines", !r.entries.scam.includes("example.com"));
  const dl = L.parseAllowListText("Download: cdn.files.example");
  ok("A. Download lines keep the host (matched with its subdomains, as the former trusted domains)", dl.entries.download.join() === "cdn.files.example");
}

// ── B. storage, text out, backup file ──
{
  const s = S.defaultState();
  L.replaceAllowList(s, L.parseAllowListText("Tamper: b.example\nAll: a.example\nScam: c.example\nDownload: d.example\nFirewall: e.example").entries);
  ok("B. All = a level-1 lock", s.siteLocks["a.example"] === C.LEVEL.ALLOW_ALL);
  ok("B. Download = downloads.trustedDomains (replaces the starter entry)", s.downloads.trustedDomains.join() === "d.example");
  ok("B. Firewall / Scam / Tamper = allowCategories", s.allowCategories.firewall.join() === "e.example" &&
     s.allowCategories.scam.join() === "c.example" && s.allowCategories.tamper.join() === "b.example", s.allowCategories);
  ok("B. text out: sorted by category, then domain", L.allowListText(s) ===
     "All: a.example\nDownload: d.example\nFirewall: e.example\nScam: c.example\nTamper: b.example", L.allowListText(s));
  const back = S.normalizeState(IO.fromSettingsFile(JSON.parse(JSON.stringify(IO.toSettingsFile(s, "test")))));
  ok("B. settings file round trip keeps every category", L.allowListText(back) === L.allowListText(s), L.allowListText(back));
  const n = S.normalizeState({ allowCategories: { scam: ["WWW.X.example", "not a host", "x.example"], nope: ["y.example"] } });
  ok("B. normalize: folded to the site, invalid and duplicate dropped, unknown category ignored",
     n.allowCategories.scam.join() === "x.example" && !("nope" in n.allowCategories), n.allowCategories);
  ok("B. a new install: no category lines, the app stores trusted", Object.values(S.defaultState().allowCategories).every((l) => !l.length) &&
     S.defaultState().downloads.trustAppStores === true);
}

// ── C. "Always allow / ignore" ──
{
  const s = S.defaultState();
  L.addToAllowList(s, CAT.TAMPER, "www.shop.example");
  L.addToAllowList(s, CAT.TAMPER, "shop.example");
  ok("C. adds the site once under its category", s.allowCategories.tamper.join() === "shop.example");
  L.addToAllowList(s, CAT.ALL, "shop.example");
  ok("C. adding All drops the site's other lines", s.siteLocks["shop.example"] === C.LEVEL.ALLOW_ALL && !s.allowCategories.tamper.length);
  L.addToAllowList(s, CAT.SCAM, "shop.example");
  ok("C. a site already under All is not added again", !s.allowCategories.scam.length);
  let threw = false;
  try { L.addToAllowList(s, "nope", "a.example"); } catch { threw = true; }
  ok("C. an unknown category is refused", threw);
}

// ── D. effects ──
{
  const s = S.defaultState();
  s.level = C.LEVEL.SMART;
  s.allowCategories.scam = ["tool.example"];
  s.allowCategories.tamper = ["bank.example"];
  const regs = B.buildScriptRegistrations(s, { grouped: false });
  const ex = (frag) => regs.filter((r) => r.id.includes(frag)).every((r) => (r.excludeMatches || []).some((p) => p.includes(frag === "enableScamProtection" ? "tool.example" : "bank.example")));
  ok("D. the Scam bundles skip a Scam site", ex("enableScamProtection"));
  ok("D. the Tamper scripts skip a Tamper site", ex("watchTamperSensitive"));
  ok("D. … and never the other category's site", !regs.filter((r) => r.id.includes("enableScamProtection"))
     .some((r) => (r.excludeMatches || []).some((p) => p.includes("bank.example"))));
  const link = "https://victim.example/search?q=<script>alert(1)</script>";
  ok("D. XSS link warning: shown when another site sends the link", X.xssLinkDecision(s, link, "https://sender.example").warn);
  s.allowCategories.scam.push("sender.example");
  ok("D. … ignored when the SENDING site is on the list under Scam", !X.xssLinkDecision(s, link, "https://sender.example").warn);
  ok("D. isAllowedFor matches subdomains of a listed site", POL.isAllowedFor(s, CAT.SCAM, "www.tool.example") && !POL.isAllowedFor(s, CAT.TAMPER, "tool.example"));
  const stores = C.BUILTIN_TRUSTED_DOWNLOAD_DOMAINS;
  ok("D. Trust app stores ticked: the app stores are trusted", stores.every((h) => DL.trustedDownloadDomains(s).includes(h)));
  s.downloads.trustAppStores = false;
  ok("D. … unticked: they are not", !stores.some((h) => DL.trustedDownloadDomains(s).includes(h)));
}

// ── P. 5.1.5: the popup's per-tab counts and the mac-only scam script ──
{
  const s = S.defaultState();
  const lvl = C.LEVEL.SMART;
  const VT_KEY = "a".repeat(64);                              // the VirusTotal key shape: 64 hex characters
  const dl = (st) => POL.protectionCounts(st, lvl).download.active;
  s.dns.first = C.DNS_NONE; s.dns.second = C.DNS_NONE; s.downloads.vtApiKey = "";
  const base = dl(s);
  s.dns.first = C.DEFAULT_DNS_FIRST;  ok("P. a DNS check that is on adds one to Download protection", dl(s) === base + 1, `${base} → ${dl(s)}`);
  s.dns.second = C.DEFAULT_DNS_SECOND; ok("P. …the second DNS check another one", dl(s) === base + 2);
  s.downloads.vtApiKey = VT_KEY;      ok("P. …and a VirusTotal key one more", dl(s) === base + 3);
  ok("P. at most 6 download checks", dl(s) <= 6, String(dl(s)));
  const macJs = (os) => B.buildScriptRegistrations(S.defaultState(), { os }).flatMap((r) => r.js || []);
  ok("P. the Script Editor link check is registered on a Mac", macJs(C.PLATFORM_OS_MAC).includes("security/scam-guard-mac.js"));
  ok("P. …and not on Windows", !macJs("win").includes("security/scam-guard-mac.js"));
}

console.log(failures ? `test-allow-list: FAIL — ${failures} case(s)` : "test-allow-list: ALL PASS");
process.exit(failures ? EXIT.FAILED : EXIT.OK);
