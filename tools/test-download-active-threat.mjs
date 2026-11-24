#!/usr/bin/env node
// ── test-download-active-threat.mjs ─────────────────────────────────────────
// Unit test (4.5.1, C42) for core/download-guard.js's applyActiveThreatFloor() — the download-path
// sibling of test-site-scorer.mjs's active-threat cases, added after a real incident: the 4.5.0
// GitHub/GitLab campaign-host feature was wired into the SITE warning (core/site-scorer.js) and
// shipped, without ever checking whether the DOWNLOAD warning (core/download-guard.js) — the only
// other place in this codebase that scores a URL's host (C39a consumer inventory) — also needed it.
// It did: a direct download of a real malware link went completely unwarned.
//
// This test exercises ONLY applyActiveThreatFloor(), the pure function added for this — it is not a
// test of core/download-guard.js as a whole (chrome.downloads/alarms/windows are not mocked here;
// that module has no test coverage beyond this one function, before or after this change, and this
// file does not claim otherwise).
//
// Usage:  node test-download-active-threat.mjs --extension ../3P-Matrix
// Exit:   0 = all pass · 1 = a case failed · 2 = did not run (C38)
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { defaultRoots } from "./repo-layout.mjs";
const HERE_DIR = dirname(fileURLToPath(import.meta.url));

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FAILED: 1, DID_NOT_RUN: 2 });

function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : process.argv[i + 1]; }
const ext = resolve(arg("extension") || defaultRoots(HERE_DIR).extension);   // 5.0.9: repo-layout.mjs
if (!existsSync(join(ext, "manifest.json"))) {
  console.error(`test-download-active-threat: DID NOT RUN — not an extension folder: ${ext}`);
  process.exit(EXIT.DID_NOT_RUN);
}
const load = (rel) => import(pathToFileURL(join(ext, rel)).href);
const { applyActiveThreatFloor, withNoClickSignal, NO_CLICK_SIGNAL_SOURCE } = await load("core/download-guard.js");
const { SCORE, DOWNLOAD_NO_CLICK_LABEL } = await load("data/constants.js");

let failed = 0;
function ok(name, cond, detail) {
  if (cond) console.log(`  PASS ${name}`);
  else { failed++; console.log(`  FAIL ${name}  ${detail ?? ""}`); }
}

// A stand-in for what BrowserProtection.checkHostReputation() would have returned before this
// function runs — only the fields applyActiveThreatFloor() actually reads/returns are given real
// values; the rest mirror the real shape loosely enough to catch a shape mismatch.
function dsResult(score, breakdown = []) {
  return { score, breakdown, classification: "unknown", label: "", hardRuleApplied: null };
}

// 1. A download not on the campaign list: DS's own result passes through completely unchanged.
{
  const input = dsResult(-5, [{ score: -5, label: "Hosted on a platform where anyone can publish", source: "RiskyHosting" }]);
  const out = applyActiveThreatFloor(input, "https://example.com/setup.exe");
  ok("non-campaign download: result object is untouched", out === input, JSON.stringify(out));
}

// 2. CDN host (no path-shape gate), delivery extension: floored to SCORE.ACTIVE_THREAT_HOST, entry added.
{
  const input = dsResult(-5, [{ score: -5, label: "platform", source: "RiskyHosting" }]);
  const out = applyActiveThreatFloor(input, "https://raw.githubusercontent.com/user/repo/main/payload.zip");
  ok("raw.githubusercontent.com .zip: score floored", out.score === SCORE.ACTIVE_THREAT_HOST, `got ${out.score}`);
  ok("raw.githubusercontent.com .zip: breakdown carries the ActiveThreatHost entry",
     out.breakdown.some((e) => e.source === "ActiveThreatHost"), JSON.stringify(out.breakdown));
}

// 3. CDN host, non-delivery extension: no match, result unchanged.
{
  const input = dsResult(-5, [{ score: -5, label: "platform", source: "RiskyHosting" }]);
  const out = applyActiveThreatFloor(input, "https://raw.githubusercontent.com/user/repo/main/README.md");
  ok("raw.githubusercontent.com README: untouched", out === input, JSON.stringify(out));
}

// 4. github.com /releases/download/ + ext: floored, same as the site-visit case.
{
  const input = dsResult(-5, [{ score: -5, label: "platform", source: "RiskyHosting" }]);
  const out = applyActiveThreatFloor(input, "https://github.com/user/repo/releases/download/v1/tool.exe");
  ok("github.com releases/download .exe: score floored", out.score === SCORE.ACTIVE_THREAT_HOST, `got ${out.score}`);
}

// 5. github.com /archive/refs/heads/ ("Download ZIP"), SOLE signal: disclaimer present, explained:true
//    (required by ui/download-warning.js's own rendering rule — a score-0 row with no `explained`
//    flag is silently dropped there, unlike ui/warning.js which shows every row regardless of score).
{
  const input = dsResult(0, []);
  const out = applyActiveThreatFloor(input, "https://github.com/user/repo/archive/refs/heads/main.zip");
  const note = out.breakdown.find((e) => e.source === "ActiveThreatHostNote");
  ok("Download ZIP, sole signal: disclaimer entry present and explained:true",
     !!note && note.explained === true && note.score === 0, JSON.stringify(out.breakdown));
}

// 6. Same shape, but DS already found another negative signal about the FILE: disclaimer suppressed, exactly
//    like the site-visit case. (4.5.8: the platform row no longer counts — it is left out with an active-threat hit.)
{
  const input = dsResult(-10, [{ score: -10, label: "Link opened from a webmail or chat page", source: "MessageOrigin" }]);
  const out = applyActiveThreatFloor(input, "https://github.com/user/repo/archive/refs/heads/main.zip");
  ok("Download ZIP, corroborated by another signal: disclaimer suppressed",
     out.score === SCORE.ACTIVE_THREAT_HOST && !out.breakdown.some((e) => e.source === "ActiveThreatHostNote"),
     JSON.stringify(out.breakdown));
}

// 7. gitlab.com -/raw/ + ext: floored.
{
  const input = dsResult(-15, [{ score: -15, label: "platform", source: "RiskyHosting" }]);
  const out = applyActiveThreatFloor(input, "https://gitlab.com/user/repo/-/raw/main/payload.exe");
  ok("gitlab.com -/raw/ .exe: score floored", out.score === SCORE.ACTIVE_THREAT_HOST, `got ${out.score}`);
}

// 8. The floor never RAISES a worse (more negative) DS score — e.g. a VT-confirmed-malicious host
//    result that was already below SCORE.ACTIVE_THREAT_HOST stays at its own, worse score.
{
  const worse = SCORE.ACTIVE_THREAT_HOST - 20;
  const input = dsResult(worse, [{ score: worse, label: "already worse", source: "RiskyHosting" }]);
  const out = applyActiveThreatFloor(input, "https://github.com/user/repo/releases/download/v1/tool.exe");
  ok("floor never raises an already-worse score", out.score === worse, `got ${out.score}`);
}

// 9. 4.5.8 — the real engine + this floor (the reported case: a .zip on raw.githubusercontent.com, no VT result).
//    One fact, one signal: the platform row (DownloadSentinel halves it as "no other corroborating signal") is left
//    out, and the verdict follows the floored score — never "probably safe" above the malware line.
{
  const { ScoringEngineV2 } = await load("lib/downloadsentinel/protection/ScoringEngineV2.js");
  const { RiskyHostingSites } = await load("lib/downloadsentinel/util/RiskyHostingSites.js");
  const { PLATFORM_SIGNAL_SOURCE, ACTIVE_THREAT_SIGNAL_SOURCE } = await load("data/active-threat-hosts.js");
  const engine = (url) => ScoringEngineV2.evaluateHostReputation({
    rdap: { status: "UNKNOWN", score: 0 }, domainHit: null, tldHit: null, sketchyUrl: { score: 0, signals: [] },
    mimeResult: { neutral: true, score: 0 }, sizeResult: { exceeds: false, score: 0 },
    riskyHosting: RiskyHostingSites.lookup(new URL(url).hostname), url, fileType: "archive" });
  const rawUrl = "https://raw.githubusercontent.com/user/repo/refs/heads/main/tool.zip";
  const ds = engine(rawUrl);
  ok("engine alone: platform row present (precondition)", ds.breakdown.some((e) => e.source === PLATFORM_SIGNAL_SOURCE), JSON.stringify(ds.breakdown));
  let out = applyActiveThreatFloor(ds, rawUrl);
  ok("with the active-threat line: no platform row", !out.breakdown.some((e) => e.source === PLATFORM_SIGNAL_SOURCE), JSON.stringify(out.breakdown));
  ok("verdict follows the floored score", out.classification === ScoringEngineV2.classifyByScore(SCORE.ACTIVE_THREAT_HOST)
     && out.label === ScoringEngineV2.heuristicLabel(1, out.classification), `${out.classification} / ${out.label}`);
  const relUrl = "https://github.com/user/repo/releases/download/v1/setup.exe";   // engine alone says "probably safe"
  const dsSafe = engine(relUrl);
  out = applyActiveThreatFloor(dsSafe, relUrl);
  ok("github.com release: engine's 'safe' verdict replaced by the floored one",
     dsSafe.classification !== out.classification && out.classification === ScoringEngineV2.classifyByScore(SCORE.ACTIVE_THREAT_HOST)
     && out.breakdown.some((e) => e.source === ACTIVE_THREAT_SIGNAL_SOURCE), `${dsSafe.classification} → ${out.classification}`);
}

// 10. 4.5.9 — original link (ported from DownloadSentinel 3.5.4): a GitHub release link redirects to an address
//     WITHOUT an extension; the original link decides. Final address first, original second, first match wins.
{
  const finalUrl = "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sig=x";
  const original = "https://github.com/user/repo/releases/download/v1/tool.exe";
  const input = dsResult(-5, [{ score: -5, label: "platform", source: "RiskyHosting" }]);
  ok("redirect case: final address alone does not match (the gap)", applyActiveThreatFloor(input, [finalUrl]) === input);
  const out = applyActiveThreatFloor(input, [finalUrl, original]);
  ok("redirect case: original link decides → floored", out.score === SCORE.ACTIVE_THREAT_HOST, `got ${out.score}`);
  ok("redirect case: label names the original link's host and extension",
     out.breakdown.some((e) => e.source === "ActiveThreatHost" && e.label.includes("github.com") && e.label.includes(".exe")), JSON.stringify(out.breakdown));
  const both = applyActiveThreatFloor(dsResult(0, []), ["https://raw.githubusercontent.com/u/r/main/a.zip", original]);
  ok("both match: the final address decides (first candidate)", both.breakdown.some((e) => e.label.includes("raw.githubusercontent.com")), JSON.stringify(both.breakdown));
  ok("guards: null / garbage candidates are skipped", applyActiveThreatFloor(input, [null, "not a url", undefined]) === input);
}

// 11. 4.5.9 — an `explained` row (shown, never counted — DeliveryContext) does not suppress the "Download ZIP" note
//     and is not counted in the headline (same rule as DownloadSentinel's isCountedNegative).
{
  const explained = { score: -10, label: "normal for GitHub downloads", source: "MessageOrigin", explained: true };
  const out = applyActiveThreatFloor(dsResult(0, [explained]), "https://github.com/user/repo/archive/refs/heads/main.zip");
  ok("explained row: Download ZIP note still shown", out.breakdown.some((e) => e.source === "ActiveThreatHostNote"), JSON.stringify(out.breakdown));
  ok("explained row: not counted in the headline", /^1 heuristic risk signal /.test(out.label), out.label);
}

// 12. 5.1.3 — "Download started without a click on the page" (core/download-gesture.js): an addend, in both host verdicts,
//     headline rebuilt; a hard-rule verdict keeps its score.
{
  const out = withNoClickSignal(dsResult(-10, []));
  ok("no click: the score drops by SCORE.DOWNLOAD_NO_CLICK", out.score === -10 + SCORE.DOWNLOAD_NO_CLICK, out.score);
  ok("no click: its line is in the breakdown", out.breakdown.some((e) => e.source === NO_CLICK_SIGNAL_SOURCE && e.label === DOWNLOAD_NO_CLICK_LABEL));
  const both = withNoClickSignal({ ...dsResult(0, []), heuristicsOnly: dsResult(-5, []) });
  ok("no click: both host verdicts get it", both.heuristicsOnly.score === -5 + SCORE.DOWNLOAD_NO_CLICK && both.score === SCORE.DOWNLOAD_NO_CLICK);
  const hard = withNoClickSignal({ ...dsResult(SCORE.DNS_BLOCKED, []), hardRuleApplied: true });
  ok("no click: a hard-rule verdict keeps its score", hard.score === SCORE.DNS_BLOCKED && hard.breakdown.length === 1);
  ok("no click: never below SCORE.FLOOR", withNoClickSignal(dsResult(SCORE.FLOOR, [])).score === SCORE.FLOOR);
}

console.log(failed ? `test-download-active-threat: ${failed} FAILED` : "test-download-active-threat: all passed");
process.exit(failed ? EXIT.FAILED : EXIT.OK);
