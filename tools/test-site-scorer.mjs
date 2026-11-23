#!/usr/bin/env node
// ── test-site-scorer.mjs ─────────────────────────────────────────────────────
// Unit test (4.4.0) for the SITE check's local scoring (core/site-scorer.js) — first test of this module.
//   1. Shared weights come from DownloadSentinel's SCORING_CONFIG (single source; they had drifted).
//   2. Platform rule: a developer-hosting platform hit that is the only real signal counts half (no warning
//      for an ordinary vercel.app / github.io site); with any other signal it counts in full.
//   3. Brand name on a platform (paypal-login.vercel.app) is a signal of its own; an org page whose label IS
//      the brand (microsoft.github.io) is not. Dynamic-DNS hosts are not softened.
//   4. (4.4.1) Dialog staged by protection level (SITE_DIALOG_FROM) with WarnPolicy site exceptions:
//      expected dialog yes/no per level, plus "badge only" (suspect severity, no dialog) at Mild.
//   5. (4.5.0, C42) data/active-threat-hosts.js's matchActiveThreatDelivery(): host AND
//      delivery-extension AND, for github.com/gitlab.com, a path-shape gate too; and the
//      "Download ZIP" shape's false-positive disclaimer, shown only when ActiveThreatHost
//      is the SOLE alarming signal on the site.
// Expected severities only — scores are derived from the constants, never typed here.
//
// Usage:  node test-site-scorer.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { defaultRoots } from "./repo-layout.mjs";
const HERE_DIR = dirname(fileURLToPath(import.meta.url));

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });
const CASES = Object.freeze([
  // [url, expected severity key]  (SEVERITY.NONE / SUSPECT / PHISHING)
  ["https://global-privacy-control.vercel.app/", "NONE"],       // the 2026-10-25 report
  ["https://my-blog.github.io/",                 "NONE"],
  ["https://microsoft.github.io/",               "NONE"],       // the org's own GitHub page
  ["https://paypal-login.vercel.app/",           "PHISHING"],   // brand on a platform
  ["https://microsoft-365-verify.netlify.app/",  "PHISHING"],
  ["https://microsoft-support.github.io/",       "PHISHING"],   // not the org page: label ≠ keyword
  ["https://login.duckdns.org/",                 "PHISHING"],   // dynamic DNS: not softened
  // 4.5.6 (user decision): a site on DownloadSentinel's "misused for malware delivery" list is no risk to VISIT —
  // only a host someone created on it (login.duckdns.org above). Downloads from these stay fully scored.
  ["https://discord.com/channels/1/2",           "NONE"],
  ["https://www.discord.com/",                   "NONE"],
  ["https://t.me/somechannel",                   "NONE"],
  ["https://bit.ly/abc",                         "NONE"],
  ["https://drive.google.com/file/d/x/view",     "NONE"],
  ["https://duckdns.org/",                       "NONE"],
  ["https://paypa1.com/",                        "PHISHING"],   // look-alike, unchanged
  ["https://www.paypal.com/",                    "NONE"],

  // 4.5.0 (C42) — data/active-threat-hosts.js's matchActiveThreatDelivery(): host AND
  // delivery-extension AND, for github.com/gitlab.com, a path-shape gate too. Every
  // negative case confirms the gate, not just the host, is what's being tested — this
  // is the real test that was missing (see C42's worked example: a prior session shipped
  // this feature verified only by ad-hoc chat scripts, while the suite's own PASS was for
  // unrelated cases that never touched this code). The archive/refs/heads "Download ZIP"
  // case's disclaimer wording is checked separately below (section 5), since it depends
  // on whether another signal is also present, not just on severity.
  ["https://raw.githubusercontent.com/user/repo/main/payload.zip",        "SUSPECT"],  // CDN host, any path
  ["https://raw.githubusercontent.com/user/repo/main/README.md",         "NONE"],     // same host, ordinary file read
  ["https://github.com/user/repo/releases/download/v1.0/tool.exe",       "SUSPECT"],  // releases/download + ext
  ["https://github.com/user/repo/raw/main/dropper.rar",                  "SUSPECT"],  // /raw/ + ext
  ["https://github.com/user/repo/raw/main/install.sh",                   "NONE"],     // /raw/ but not a delivery ext
  ["https://github.com/user/repo/releases/download/v1.0/notes.txt",      "NONE"],     // releases/download but not a delivery ext
  ["https://github.com/user/repo/archive/refs/heads/main.zip",           "SUSPECT"],  // "Download ZIP" — included, with a false-positive disclaimer (see below)
  ["https://github.com/user/repo/issues/42",                            "NONE"],     // ordinary browsing, bare github.com
  ["https://gitlab.com/user/repo/-/raw/main/payload.zip",                "SUSPECT"],  // GitLab raw + ext
  ["https://gitlab.com/user/repo/-/blob/main/README.md",                 "NONE"],     // GitLab, ordinary page, no raw path
]);

// [url, dialog per level Mild/Medium/High/Strict ("D" = dialog, "-" = none), exception expected?]
const LEVEL_CASES = Object.freeze([
  ["https://global-privacy-control.vercel.app/", "--DD", false],   // platform alone: strict levels only
  ["http://example.org/",                        "---D", false],   // plain HTTP alone: Strict only
  ["https://cheap-shoes.top/",                   "-DDD", false],   // abused TLD: badge only at Mild
  ["https://203.0.113.9/",                       "-DDD", false],   // bare IP
  ["https://paypa1.com/",                        "DDDD", true],    // impersonation: every level
  ["https://paypal-login.vercel.app/",           "DDDD", true],
  ["https://login.duckdns.org/",                 "DDDD", false],   // score alone is enough
  ["https://www.paypal.com/",                    "----", false],
]);
const DIALOG_MARK = "D";

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
const ext = resolve(arg("extension") || defaultRoots(HERE_DIR).extension);   // 5.0.9: repo-layout.mjs
if (!existsSync(join(ext, "manifest.json"))) {
  console.error(`test-site-scorer: DID NOT RUN — not an extension folder: ${ext}`);
  process.exit(EXIT.DID_NOT_RUN);
}
const load = (rel) => import(pathToFileURL(join(ext, rel)).href);
const { scoreLocal, combine, dialogDecision } = await load("core/site-scorer.js");
const { SCORE, SEVERITY, LEVEL, SITE_DIALOG_FROM } = await load("data/constants.js");
const { SCORING_CONFIG } = await load("lib/downloadsentinel/protection/ScoringEngineV2.js");

let failed = 0;
function ok(name, cond, detail) {
  if (cond) console.log(`  PASS ${name}`);
  else { failed++; console.log(`  FAIL ${name}  ${detail ?? ""}`); }
}

// 1. single source
const SHARED = Object.freeze({
  IP_HOST: "IP_HOST_PENALTY", TLD_BASE: "HOST_TLD_BASE_SCORE", DOMAIN_LIST_BASE: "HOST_DOMAIN_BASE_SCORE",
  HOST_LIST_BASE: "HOST_LIST_BASE_SCORE", SKETCHY_URL_BASE: "HOST_SKETCHY_URL_BASE",
  LOOKALIKE_BRAND: "LOOKALIKE_BRAND_SCORE", LOOKALIKE_SITE: "LOOKALIKE_SITE_SCORE",
  PLATFORM_SOLO_DIVISOR: "RISKY_HOSTING_SOLO_DIVISOR",
});
for (const [mine, ds] of Object.entries(SHARED)) {
  ok(`SCORE.${mine} === DS SCORING_CONFIG.${ds}`, SCORE[mine] === SCORING_CONFIG[ds], `${SCORE[mine]} vs ${SCORING_CONFIG[ds]}`);
}

// 2 + 3. severities. Uses local.severity — scoreLocal()'s OWN final answer — not a fresh
// combine(local.entries) here: raw.githubusercontent.com and gitlab.com are themselves on
// DownloadSentinel's RiskyHostingSites list, so a bare combine() call on their entries hits
// the exact CombinationScoring family-drop bug the 4.4.9 floor exists to prevent (caught by
// this test's own fault-verification run — see C42 — when this loop still called combine()
// directly and two ActiveThreatHost cases failed for the wrong reason).
for (const [url, expect] of CASES) {
  const local = scoreLocal(url);
  ok(`${url} → ${expect}`, local.severity === SEVERITY[expect], `got ${local.severity} (${local.score}): ${local.entries.map((e) => `${e.source} ${e.score}`).join(", ")}`);
}

// 2. a later (online) signal sees the FULL platform score — the rule runs inside combine()
const plain = scoreLocal("https://new-site.vercel.app/");
const alone = combine(plain.entries).score;
const withAge = combine([...plain.entries, { score: SCORE.RDAP_YOUNG, label: "young", source: "RDAP" }]).score;
ok("platform hit alone is halved; with a young-domain signal it counts in full",
   withAge < alone && withAge <= SCORE.SUSPECT_AT, `alone ${alone}, with age ${withAge}`);
ok("combine() never mutates its input", plain.entries.every((e) => e.score < 0 && Number.isInteger(e.score)) &&
   combine(plain.entries).score === alone);

// 4. dialog per level
const LEVELS = Object.freeze([LEVEL.MILD, LEVEL.SMART, LEVEL.HIGH, LEVEL.STRICT]);
ok("every warning level has a dialog threshold", LEVELS.every((l) => typeof SITE_DIALOG_FROM[l] === "number"));
ok("level 1 (allow all) never opens the dialog", dialogDecision(scoreLocal("https://paypa1.com/"), LEVEL.ALLOW_ALL).warn === false);
for (const [url, expect, exception] of LEVEL_CASES) {
  const local = scoreLocal(url);
  const got = LEVELS.map((l) => (dialogDecision(local, l).warn ? DIALOG_MARK : "-")).join("");
  const exc = dialogDecision(local, LEVEL.MILD).exceptions.length > 0;
  ok(`${url} dialog per level ${expect}${exception ? " (exception)" : ""}`, got === expect && exc === exception,
     `got ${got}, exception ${exc}, score ${local.score}`);
}
const shoes = scoreLocal("https://cheap-shoes.top/");
ok("badge only at Mild: suspect severity, no dialog",
   shoes.severity === SEVERITY.SUSPECT && dialogDecision(shoes, LEVEL.MILD).warn === false);

// 5. "Download ZIP" disclaimer — shown only when ActiveThreatHost is the SOLE alarming
// signal (a real person can trigger this exact shape themselves); suppressed the moment
// anything else on the site is also alarming, since corroboration is what the note itself
// says to watch for. Fault-verified by hand against this test file before it was trusted:
// commenting out the "no other alarms" guard in core/site-scorer.js made the "corroborated"
// case below fail (the note appeared even with a second signal present) — confirms this
// case actually exercises the guard, not just the note's existence.
const zipAlone = scoreLocal("https://github.com/user/repo/archive/refs/heads/main.zip");
const zipNote = "Download ZIP";
ok("Download ZIP disclaimer present when it's the only signal",
   zipAlone.signals.some((s) => s.includes(zipNote)), zipAlone.signals.join(" | "));
const zipCorroborated = scoreLocal("http://github.com/user/repo/archive/refs/heads/main.zip");   // + plain-HTTP signal
ok("Download ZIP disclaimer suppressed once a second signal corroborates it",
   zipCorroborated.severity === SEVERITY.SUSPECT && !zipCorroborated.signals.some((s) => s.includes(zipNote)),
   zipCorroborated.signals.join(" | "));

console.log(failed ? `test-site-scorer: ${failed} FAILED` : "test-site-scorer: all passed");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
