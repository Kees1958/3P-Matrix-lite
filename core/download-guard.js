// ── core/download-guard.js ────────────────────────────────────────────────────
// warnRiskyDownloads "Warn when a downloaded file looks risky" (4.3.0) — DownloadSentinel's (3.3.1 since 4.3.7; 3.3.0 in 4.3.4–4.3.6) download
// protection, ported from its background.js (C21: same two-listener model, same time budget, same
// re-check rules; only settings, logging and the "is it active here" gate are 3P Matrix's).
//
// Model (DownloadSentinel V2.0+): an information/warning tool, never a blocker — the download always
// completes; nothing is paused, resumed or cancelled.
//   onCreated  → 5.1.3 (issue 6): FIRST, for every download the warning or the block could apply to, asks the page
//                that started it whether there was a click (core/download-gesture.js) — the page's click flag is only
//                fresh now; the answer is kept in _clicks until the download is released, so a LATE ENTRY (file name
//                only known at completion) gets the signal too. Then: monitored file type? start host reputation
//                (DNS threat-intel + RDAP + lists + URL / filename heuristics) and, with a key, the VirusTotal URL
//                check; record startedAt
//   onChanged  → download complete: wait what is left of DS_APP.VT_WAIT_BUDGET_MS, re-check with the
//                confirmed filename/size, combine the scores, then stay silent ("Silent when probably
//                safe") or open the warning window (ui/download-warning.html)
//
// Public interface (called by background.js only):
//   init()                          — idempotent: sweep alarm (4.3.4: no remote list refresh — DS item 18)
//   onCreated(item, state)          — chrome.downloads.onCreated body
//   onChanged(delta, state)         — chrome.downloads.onChanged body
//   onErased(downloadId)            — chrome.downloads.onErased body (release)
//   onAlarm(alarm)                  — chrome.alarms.onAlarm body (stale-entry sweep)
//   onWindowRemoved(windowId)       — a warning window was closed without a button (release)
//   pageModel(downloadId, state)    — what the warning page renders: { record, look } or null
//   dismiss(downloadId)             — the user is done with the warning (release)
//   offerVtKey(state)               — browser start: open the VirusTotal-key nudge when DS would
//   blockedModel(downloadId)        — Promise: what the "download blocked" notice renders, or null (blockRiskyDownloads)
//   blockedAction(downloadId, act, state) — notice button: OK (discard) or DOWNLOAD_ANYWAY (continue the held
//                                     download; warnRiskyDownloads then always checks it)
//
// Also exported, but NOT part of the above (background.js never calls it) — test-only access to a
// pure function, per C42: withNoClickSignal(result) (5.1.3) and applyActiveThreatFloor(result, urls) — urls = [final address, original link] (4.5.9). See tools/test-download-active-threat.mjs.
//
// blockRiskyDownloads "Block risky downloads" (4.3.2, off by default): a monitored file type (the same
// classifyDownload() gate as warnRiskyDownloads) from a page outside safer regions (level 3) or from any page
// (levels 4–5) is HELD — before warnRiskyDownloads's check — and a small notice window explains it.
// 4.5.5 (real report, SharePoint): the download used to be cancelled and deleted at once, and "Download
// anyway" requested its URL again from this service worker. That cannot work for a file that only exists
// as the answer to a POST (SharePoint/OneDrive folder and multi-file zips: a POST to a regional *.svc.ms
// host), a one-time token, or a page's blob: — the file was simply gone. Now the download is PAUSED (a file
// that already finished stays, unopened) until the user chooses: OK, closing the notice or the sweep
// cancel and delete it; "Download anyway" resumes the SAME download, which warnRiskyDownloads then ALWAYS checks
// (even when 12 is unticked or its level is lower), as the user asked for the check. Nothing is re-fetched,
// so a blob: export can be blocked like any other file again (the 4.5.3 warn-only exception is gone).
// Exception: an extensionless generic binary (R1) is never blocked — a false positive on a legitimate Linux
// release binary — it is warn-only.
//
// blockRiskyDownloads lane — one entry per blocked download in a session map (core/session-map.js,
// SESSION_KEY.BLOCKED_DOWNLOADS), so it survives the idle service-worker stop (4.5.4 and older kept it in
// memory: after ~30 s on the notice its buttons answered "no longer active"):
//   { phase, downloadId, url, filename, ext, site, reason, blockedAt, windowId }
//   [HELD] ──OK / notice closed / sweep──► discardHeld(): cancel + delete file, entry removed
//     │
//     └──"Download anyway"──► [ALLOWED] resumed; warnRiskyDownloads always checks it ──release()──► removed
//   Every reader awaits _blocked.ready() first; an ALLOWED entry is also removed by erase and the sweep.
//
// State owned — in memory (lost on a service-worker restart, as in DownloadSentinel: a lost record means the
// late-entry path re-checks at completion, never a silent pass):
//   _pending  Map<downloadId, record>  — bounded: swept every DS_APP.SWEEP_ALARM_PERIOD_MINUTES,
//                                        max age DS_APP.ENTRY_MAX_AGE_MS; released on dismiss/erase
//   _sweepArmed boolean               — 4.5.4 (perf P1): the sweep alarm exists ONLY while the swept maps
//                                        (_pending, _checked, _blocked) hold something: armed by armSweep()
//                                        where an entry enters, cleared by onAlarm() once they are all empty
//   _checked  Set<downloadId>          — onChanged fires several times per download: dedup guard
//   _windows  Map<windowId, downloadId> — open warning windows; released when closed
//   _clicks   Map<downloadId, { askedAt, answer: Promise<true|false|null> }> — 5.1.3 (issue 6): the page's click flag
//                                        asked at the download's start; released with the download (releaseClick in
//                                        every release path, the "not ours" completion, erase), swept like _pending
//                                        (max age DS_APP.ENTRY_MAX_AGE_MS) and capped at DOWNLOAD_GESTURE.ENTRIES_MAX
// — in chrome.storage.session (survives the idle stop):
//   _blocked  session map downloadId → blockRiskyDownloads lane entry (above)
// Every release path goes through release(): record, dedup entry, lane entry, window link and in-flight
// VirusTotal request (BrowserProtection.abandonPendingRequests) together — no partial cleanup.
// ─────────────────────────────────────────────────────────────────────────────

import { UrlUtils } from "../lib/downloadsentinel/util/UrlUtils.js";
import { LOG_PREFIX, DOWNLOAD_WARNING_PAGE, DOWNLOAD_ID_PARAM, DOWNLOAD_WARNING_TITLE_DEFAULT,
         DOWNLOAD_BLOCKED_PAGE, DOWNLOAD_BLOCKED_WINDOW, DOWNLOAD_BLOCK_PHASE as PHASE, SESSION_KEY,
         VT_KEY_PROMPT_PAGE, VT_KEY_PROMPT_WINDOW, CHROME_DOWNLOAD_COMPLETE, CHROME_DOWNLOAD_INTERRUPTED } from "../data/constants.js";
import { APP as DS_APP } from "../lib/downloadsentinel/util/AppConstants.js";
import { ScoringEngineV2 } from "../lib/downloadsentinel/protection/ScoringEngineV2.js";
import { BrowserProtection } from "../lib/downloadsentinel/protection/BrowserProtection.js";
import { FilenameAnalysis } from "../lib/downloadsentinel/util/FilenameAnalysis.js";
import { DownloadShape } from "../lib/downloadsentinel/util/DownloadShape.js";
import { WarnPolicy } from "../lib/downloadsentinel/protection/WarnPolicy.js";   // 4.4.1: staged window decision   // 4.4.0: DS 3.5.0 R1/R4 + delivery context
import { dsSettingsView, vtKeyIsSet, isDownloadCheckActive, isTrustedDownload, shouldOfferVtKey,
         downloadBlockReason, downloadSiteHost, isPageMadeDownload } from "./download-settings.js";
import { BLOCKED_DOWNLOAD_ACTION, MSG_DOWNLOAD_VT_UPDATE } from "../data/message-types.js";
import { SCORE, DOWNLOAD_NO_CLICK_LABEL, DOWNLOAD_GESTURE } from "../data/constants.js";
import { startedWithoutClick } from "./download-gesture.js";   // 5.1.3
import { parseHttpUrl } from "../util/domain.js";
import { matchActiveThreatDelivery, activeThreatLabel, ACTIVE_THREAT_SIGNAL_SOURCE, ACTIVE_THREAT_NOTE_SIGNAL_SOURCE, PLATFORM_SIGNAL_SOURCE } from "../data/active-threat-hosts.js";   // 4.5.1 — see applyActiveThreatFloor() below
import { createSessionMap } from "./session-map.js";

// ── Settings (one place) ─────────────────────────────────────────────────────
const COMBINED_MIN = -100, COMBINED_MAX = 100;   // DownloadSentinel's combined (VT + host) score range
const WINDOW_TYPE_POPUP = "popup";
const WINDOW_STATE_MAXIMIZED = "maximized";      // DownloadSentinel opens its warning maximized
const DOWNLOAD_EXT_DESKTOP = "desktop";          // DS-H001 Linux launcher (FilenameAnalysis.classifyDownload)

// ── State (see header) ───────────────────────────────────────────────────────
const _pending = new Map();
const _checked = new Set();
const _windows = new Map();
const _clicks = new Map();    // 5.1.3 (issue 6): downloadId → { askedAt, answer } (see the header)
const _blocked = createSessionMap(SESSION_KEY.BLOCKED_DOWNLOADS);
let _initialized = false;
let _sweepArmed = false;      // in memory: false after a SW restart, so the next entry (re)creates the alarm

// ── Sweep alarm lifecycle (4.5.4, perf P1) ───────────────────────────────────
// The maps the sweep cleans; the alarm is only needed while one of them holds an entry.
function holdsSweptEntries() {
  return _pending.size > 0 || _checked.size > 0 || _blocked.map.size > 0 || _clicks.size > 0;
}

// Called where an entry enters a swept map. create() with the same name replaces an alarm left over from
// before a SW restart, so there is never a second one.
function armSweep() {
  if (_sweepArmed) return;
  _sweepArmed = true;
  chrome.alarms.create(DS_APP.SWEEP_ALARM_NAME, { periodInMinutes: DS_APP.SWEEP_ALARM_PERIOD_MINUTES })
    .catch((e) => { _sweepArmed = false; console.error(LOG_PREFIX, "download sweep alarm:", e); });
}

// Called after a sweep: nothing left to sweep → release the alarm (no further periodic wake-ups).
function disarmSweepIfIdle() {
  if (holdsSweptEntries()) return;
  _sweepArmed = false;
  chrome.alarms.clear(DS_APP.SWEEP_ALARM_NAME).catch((e) => console.error(LOG_PREFIX, "download sweep alarm clear:", e));
}

// DownloadSentinel 3.3.0 releaseDownload() (item 16): a silent VirusTotal retry still in flight is never
// aborted because the window closed — the record stays (flagged windowClosed) until handleLateVtResult()
// settles it or the retry gives up (it releases its own request); the sweep is the last-resort release.
function release(downloadId, reason) {
  if (BrowserProtection.isVtPending(downloadId) && _pending.has(downloadId)) {
    _pending.get(downloadId).windowClosed = true;
  } else {
    _pending.delete(downloadId);
    BrowserProtection.abandonPendingRequests(downloadId, reason);
  }
  _checked.delete(downloadId);
  releaseClick(downloadId);
  dropLaneEntry(downloadId);
  for (const [windowId, id] of _windows) if (id === downloadId) _windows.delete(windowId);
}

// 4.4.0 (DS 3.5.0 R1): a download that turned out NOT to need a warning after all (an extensionless binary
// that got an ordinary file name at completion). _checked is kept so onChanged keeps ignoring the id; the
// sweep / onErased clean it as before. Any VirusTotal request in flight is aborted.
function releaseWithoutWarning(downloadId, reason) {
  _pending.delete(downloadId);
  releaseClick(downloadId);
  BrowserProtection.abandonPendingRequests(downloadId, reason);
}

// Force-release (sweep, erase): the record goes even with a retry in flight, and the request is aborted.
function releaseAll(downloadId, reason) {
  _pending.delete(downloadId);
  BrowserProtection.abandonPendingRequests(downloadId, reason);
  release(downloadId, reason);
}

// ── 5.1.3 (issue 6): the page's click flag, asked at EVERY download start ───────
// Asked once per download, at onCreated (the page's activation is only fresh then), when the warning or the block
// could apply to it; kept until the download is released. A record (onCreated or late entry) reads it with clickFlag.
function askClick(item, state) {
  if (!item || !item.referrer || _clicks.has(item.id)) return;
  if (!isDownloadCheckActive(state, item) && !downloadBlockReason(state, item)) return;   // nothing would use it
  _clicks.set(item.id, { askedAt: Date.now(), answer: startedWithoutClick(item.referrer) });
  while (_clicks.size > DOWNLOAD_GESTURE.ENTRIES_MAX) _clicks.delete(_clicks.keys().next().value);   // guard: oldest first
  armSweep();
}
// true = started without a click, false = clicked, null = unknown (not asked, no referrer, no answer in time).
function clickFlag(downloadId) {
  const entry = _clicks.get(downloadId);
  return entry ? entry.answer : Promise.resolve(null);
}
function releaseClick(downloadId) { _clicks.delete(downloadId); }

// ── Lifecycle ────────────────────────────────────────────────────────────────
export function init() {
  if (_initialized) return;
  _initialized = true;
  // 4.5.4 (perf P1): no alarm is created here any more — armSweep() creates it when the first entry
  // arrives; an alarm left over from before a SW restart fires once more and onAlarm() clears it.
  // 4.3.4: DownloadSentinel 3.3.0 removed its remote list refresh (FilterDataLoader, item 18) — the bundled
  // lists are the only source; nothing polls a URL any more.
}

export async function onAlarm(alarm) {
  if (!alarm || alarm.name !== DS_APP.SWEEP_ALARM_NAME) return;
  await _blocked.ready();
  const cutoff = Date.now() - DS_APP.ENTRY_MAX_AGE_MS;
  for (const [id, r] of _pending) if ((r.startedAt || 0) < cutoff) releaseAll(id, "stale entry swept");
  for (const id of _checked) if (!_pending.has(id)) _checked.delete(id);   // orphaned by a SW restart
  for (const [id, c] of _clicks) if (c.askedAt < cutoff && !_pending.has(id)) _clicks.delete(id);   // 5.1.3: never completed
  for (const [id, b] of [..._blocked.map]) {
    if (b.blockedAt >= cutoff) continue;
    if (b.phase === PHASE.HELD) await discardHeld(id, "stale notice swept");   // never decided: the safe choice
    else dropLaneEntry(id);
  }
  disarmSweepIfIdle();
}

export function onErased(downloadId) { releaseAll(downloadId, "download erased"); }

// A warning window (warnRiskyDownloads) → release. A blocked-download notice closed without a button → the safe
// choice, as OK: the held download is discarded (found by its window id in the lane — survives a restart).
export async function onWindowRemoved(windowId) {
  const id = _windows.get(windowId);
  if (id !== undefined) { release(id, "warning window closed"); return; }
  await _blocked.ready();
  for (const [downloadId, b] of _blocked.map) {
    if (b.windowId === windowId && b.phase === PHASE.HELD) await discardHeld(downloadId, "notice closed");
  }
}

export function dismiss(downloadId) { release(downloadId, "user dismissed"); }

// ── Record helpers (DownloadSentinel background.js, unchanged logic) ─────────
// The settings a record freezes at download start (DS buildSettingsSnapshot): later setting changes do
// not alter a check already running.
function settingsSnapshot(state) {
  const s = dsSettingsView(state);
  return {
    fpLevel:            s.fpReductionLevel,
    silentWhenInconclusive: s.silentWhenInconclusive,
    autoAllow:          s.autoAllow,
    autoAllowThreshold: s.autoAllowThreshold,
    vtApiKeySet:        vtKeyIsSet(state),
    dnsFirst:           s.dnsFirst,
    dnsSecond:          s.dnsSecond
  };
}

function emptyVt() {
  return { vtDone: false, vtScore: null, vtConfidence: null, vtBreakdown: null, vtHardRule: null,
           vtRawStats: null, vtFilteredStats: null, vtFpLevel: null };
}

// 4.5.1 (C21 — ported, not reinvented): the exact same active-threat floor core/site-scorer.js
// applies for the SITE-visit warning, applied here too for the DOWNLOAD warning — the only other
// place in this codebase that scores a URL's host (C39a consumer inventory: confirmed no third
// place does). Applied AFTER DownloadSentinel's own evaluateHostReputation() result comes back,
// never fed into its internal CombinationScoring call, for the identical reason site-scorer.js's
// comment gives: an unregistered family degrades to NEUTRAL and is silently dropped the moment any
// other family-grouped signal (riskyHosting, present for nearly every one of these hosts already)
// is also there — traced in ScoringEngineV2.evaluateHostReputation() before writing this, not
// assumed from site-scorer.js's case alone.
// Exported (only) so a unit test can exercise this pure function directly, without mocking the
// rest of this module's chrome.downloads plumbing — see tools/test-download-active-threat.mjs.
// 4.5.9 (C21 — ported from DownloadSentinel 3.5.4 util/ActiveThreatHosts.js firstHit/isCountedNegative):
// `urls` = candidates in order — the final address first, then the original link; the first match decides.
// A GitHub release link (github.com/…/releases/download/v1/tool.exe) redirects to a
// release-assets.githubusercontent.com path WITHOUT an extension, so the final address alone missed it.
function firstActiveThreatHit(urls) {
  for (const candidate of Array.isArray(urls) ? urls : [urls]) {
    const p = parseHttpUrl(candidate);
    const hit = p && matchActiveThreatDelivery(p.host, p.pathname);
    if (hit) return { p, hit };
  }
  return null;
}
// A row that counts as an alarming signal: negative and not `explained` (shown, never counted — DeliveryContext).
function isCountedNegative(e) { return !!e && e.score < 0 && !e.explained; }

// 5.1.3 — "Download started without a click on the page" (core/download-gesture.js): an addend to the host score, in both
// host verdicts; classification and headline rebuilt like the floor below. A hard-rule verdict keeps its own.
export const NO_CLICK_SIGNAL_SOURCE = "DownloadNoClick";
export function withNoClickSignal(result) {
  if (!result) return result;
  if (result.heuristicsOnly) {
    const { heuristicsOnly, ...vtKnown } = result;
    return { ...withNoClickSignal(vtKnown), heuristicsOnly: withNoClickSignal(heuristicsOnly) };
  }
  const entries = [...(Array.isArray(result.breakdown) ? result.breakdown : []),
                   { score: SCORE.DOWNLOAD_NO_CLICK, label: DOWNLOAD_NO_CLICK_LABEL, source: NO_CLICK_SIGNAL_SOURCE }];
  const score = Math.max(SCORE.FLOOR, (result.score ?? 0) + SCORE.DOWNLOAD_NO_CLICK);
  if (result.hardRuleApplied) return { ...result, breakdown: entries };
  const classification = ScoringEngineV2.classifyByScore(score);
  const signalCount = entries.filter(isCountedNegative).length;
  return { ...result, score, classification, label: ScoringEngineV2.heuristicLabel(signalCount, classification), breakdown: entries };
}

export function applyActiveThreatFloor(result, urls) {
  const found = firstActiveThreatHit(urls);
  if (!found) return result;
  // 5.0.4 (DS 3.5.6) — both host verdicts (ScoringEngineV2.hostVerdict) get the same floor.
  if (result?.heuristicsOnly) {
    const { heuristicsOnly, ...vtKnown } = result;
    return { ...applyActiveThreatFloor(vtKnown, urls), heuristicsOnly: applyActiveThreatFloor(heuristicsOnly, urls) };
  }
  const { p, hit } = found;
  // 4.5.8: one fact, one signal — the platform row (halved or not) is left out, as in core/site-scorer.js: both
  // describe this host, and this line is the stronger, more specific statement.
  const breakdown = (Array.isArray(result?.breakdown) ? result.breakdown : []).filter((e) => e?.source !== PLATFORM_SIGNAL_SOURCE);
  const entries = [...breakdown, { score: SCORE.ACTIVE_THREAT_HOST, label: activeThreatLabel(p.host, p.pathname), source: ACTIVE_THREAT_SIGNAL_SOURCE }];
  // Same sole-signal guard as site-scorer.js: the disclaimer only applies when nothing else about
  // this download is also alarming (a real person can trigger the "Download ZIP" shape themselves).
  // `explained: true` — NOT copied from site-scorer.js's shape, because ui/download-warning.js is a
  // DIFFERENT renderer with its own rule: it only shows a score-0 row when explained is set (checked
  // first, before score > 0/< 0), otherwise drops it silently. DeliveryContext.js already establishes
  // `explained` as "shown, but doesn't count as a negative signal" in this codebase — the same meaning
  // this note needs, not a repurposing of it.
  if (hit.note && !breakdown.some(isCountedNegative)) {
    entries.push({ score: 0, label: hit.note, source: ACTIVE_THREAT_NOTE_SIGNAL_SOURCE, explained: true });
  }
  // 4.5.8: the verdict follows the floored score — classification and headline are rebuilt with DownloadSentinel's own
  // classifyByScore()/heuristicLabel(), so the warning never says "probably safe" above this line. A hard-rule
  // verdict (DNS block) keeps its own headline: it is already the worst class.
  const score = Math.min(result?.score ?? 0, SCORE.ACTIVE_THREAT_HOST);
  if (result?.hardRuleApplied) return { ...result, score, breakdown: entries };
  const classification = ScoringEngineV2.classifyByScore(score);
  const signalCount = entries.filter(isCountedNegative).length;
  return { ...result, score, classification, label: ScoringEngineV2.heuristicLabel(signalCount, classification), breakdown: entries };
}

// 4.4.0: last argument = DS 3.5.0 downloadContext { visibleExt, isUnknownBinary, fpLevel } from the record.
function hostReputation(r, ext, totalBytes, obfuscation, filename, sizeKnown, isLinuxLauncher) {
  return BrowserProtection.checkHostReputation(
    r.url, r.fileType, ext, r.mime, totalBytes, r.originalUrl, r.isScript, obfuscation,
    FilenameAnalysis.getDoubleExtension(filename), isLinuxLauncher, filename, sizeKnown, r.referrer,
    { first: r.dnsFirst, second: r.dnsSecond }, DownloadShape.contextOf(r))
    .then((result) => applyActiveThreatFloor(result, [r.url, r.originalUrl]));   // 4.5.9: original link too
}

function applyVtResult(r, result) {
  r.vtDone          = true;
  r.vtScore         = result?.score           ?? null;
  r.vtConfidence    = result?.confidence      ?? null;
  r.vtBreakdown     = result?.breakdown       ?? null;
  r.vtHardRule      = result?.hardRuleApplied ?? null;
  r.vtRawStats      = result?.rawStats        ?? null;
  r.vtFilteredStats = result?.filteredStats   ?? null;
  r.vtFpLevel       = result?.fpLevel         ?? null;
}

function originalUrlOf(item, url) { return (item.url && item.url !== url) ? item.url : url; }

async function searchItem(downloadId) {
  try { return (await chrome.downloads.search({ id: downloadId }))[0] || null; }
  catch (e) { console.warn(LOG_PREFIX, "downloads.search:", e); return null; }
}

// ── onCreated — start the checks, record the start time ──────────────────────
export async function onCreated(item, state) {
  if (!item) return;
  await _blocked.ready();                                          // the blockRiskyDownloads lane is read below
  // Guard: a tiny download can complete before this handler's state load resolved — onChanged then
  // already built a late-entry record (or blocked it); a second pass would double checks and windows.
  if (_checked.has(item.id) || _pending.has(item.id) || _blocked.map.has(item.id)) return;
  askClick(item, state);                                           // 5.1.3 (issue 6): first — every download start
  if (blockIfNeeded(item, state)) return;                          // blockRiskyDownloads
  startCheck(item, state);
}

// warnRiskyDownloads' check from the start of a download: monitored type? → record + host reputation + VirusTotal.
// Also the continuation of "Download anyway" for a download that is still running (blockedAction).
function startCheck(item, state) {
  if (!isForced(item.id) && !isDownloadCheckActive(state, item)) return;
  const url = item.finalUrl || item.url || "";
  if (!url || isTrustedDownload(state, item)) return;
  const c = FilenameAnalysis.classifyDownload(url, item.url || "", item.filename || "", item.mime);
  if (!c) return;                                                   // not a monitored file type

  const record = {
    id: item.id, startedAt: Date.now(),                            // before the calls: budget covers setup
    url, originalUrl: originalUrlOf(item, url),
    ext: c.ext, fileType: c.fileType, isScript: c.isScript,
    visibleExt: c.visibleExt, isUnknownBinary: c.isUnknownBinary,   // 4.4.0: R4 input / R1 (re-checked in onChanged)
    filename: item.filename || "", mime: item.mime || "", totalBytes: item.totalBytes || 0,
    referrer: item.referrer || null,
    sizeKnown: (item.totalBytes || 0) > 0,                          // Chrome often reports 0 at creation
    ...emptyVt(),
    hostDone: false, hostResult: null,
    noClick: null,                                                  // 5.1.3: true = started without a click (unknown: null)
    ...settingsSnapshot(state)
  };
  _pending.set(item.id, record);
  armSweep();

  // 5.1.3: the click flag asked at the download's start (askClick; waits ≤ DOWNLOAD_GESTURE.TIMEOUT_MS), with the host check.
  Promise.all([hostReputation(record, c.ext, record.totalBytes, null, record.filename, record.sizeKnown, c.isLinuxLauncher),
               clickFlag(item.id)])
    .then(([hostResult, noClick]) => {
      const r = _pending.get(item.id);
      if (!r) return;
      r.noClick = noClick;
      r.hostDone = true;
      r.hostResult = noClick === true ? withNoClickSignal(hostResult) : hostResult;
    })
    .catch((e) => console.warn(LOG_PREFIX, "download host reputation:", e));

  const s = dsSettingsView(state);
  if (!record.vtApiKeySet || !s.virusTotalEnabled) { record.vtDone = true; return; }   // no key / VT off: done
  // DS 3.3.0: settings passed in (item 12); a first-attempt timeout gets one silent retry (item 16).
  BrowserProtection.checkIfUrlIsMalicious(item.id, url, (result) => {
    const r = _pending.get(item.id);
    if (r) applyVtResult(r, result);
  }, record.originalUrl, s, (result) => handleLateVtResult(item.id, result));
}

// ── DS 3.3.0 item 16: a VirusTotal verdict that arrives after the first timeout already said "unknown" ──
// Window still open → push it live into the page (MSG_DOWNLOAD_VT_UPDATE). Window already closed → reopen
// only when the verdict is WORSE than what the user saw; otherwise release silently.
// 4.4.1 — WarnPolicy's download decision for a record and a combined score (one place for both callers).
function warnDecision(record, combined) {
  return WarnPolicy.downloadDecision({ combinedScore: combined, fpLevel: record.fpLevel,
    entries: (record.hostVerdict ?? record.hostResult)?.breakdown, vtMalicious: record.vtRawStats?.malicious });   // 5.0.4: the verdict used
}

function handleLateVtResult(downloadId, result) {
  const record = _pending.get(downloadId);
  if (!record) return;                                             // released for good (sweep / erase)
  applyVtResult(record, result);
  const previous = record.combinedScore;                          // undefined while the page has not opened yet
  const { combined, scaledHostScore, fpMultiplier, vtUnknown, hostVerdict } = computeCombinedScore(record);
  record.hostVerdict = hostVerdict;   // 5.0.4 (DS 3.5.6): VirusTotal's answer picks the host verdict — before any reader
  if (previous === undefined) return;                              // onChanged has not decided yet: it will use this
  Object.assign(record, { combinedScore: combined, scaledHostScore, fpMultiplier, vtUnknown });
  if (!record.windowClosed) {
    chrome.runtime.sendMessage({ type: MSG_DOWNLOAD_VT_UPDATE, downloadId, record: JSON.parse(JSON.stringify(record)) })
      .catch(() => { /* the page closed in between — its window-close release handles the record */ });
    return;
  }
  // Escalation only. 4.4.1: a download that was quiet (record.quiet) opens only when the new verdict now warrants a
  // window (warnDecision); a dismissed window reopens when the verdict got worse, as before.
  const escalate = record.quiet ? warnDecision(record, combined).warn : combined < previous;
  if (escalate) { record.windowClosed = false; record.quiet = false; openWarningWindow(downloadId); }
  else releaseAll(downloadId, "late VirusTotal result — no escalation");
}

// DownloadSentinel computeCombinedScore(): VirusTotal unknown → negative heuristic signals scaled by the FP
// level; combined = VT + (scaled) host, clamped to the score range. 4.4.0: the scaling itself is DS 3.5.0's
// shared ScoringEngineV2.scaleHostScoreForUnknownVt() (same function DS and its fp-sweep use).
// 5.0.4 (DS 3.5.6) — the host verdict that applies is chosen here (ScoringEngineV2.hostVerdict): VirusTotal unknown →
// heuristics only, small signals add up on a dubious source; VirusTotal known → unchanged.
function computeCombinedScore(record) {
  const vtUnknown = record.vtDone && record.vtScore === null;
  const hostVerdict = ScoringEngineV2.hostVerdict(record.hostResult, vtUnknown);
  const hostScore = hostVerdict?.score ?? 0;
  const { scaled: scaledHostScore, multiplier: fpMultiplier } =
    ScoringEngineV2.scaleHostScoreForUnknownVt(hostScore, record.fpLevel, vtUnknown);
  const combined = Math.max(COMBINED_MIN, Math.min(COMBINED_MAX, (record.vtScore ?? 0) + scaledHostScore));
  return { combined, scaledHostScore, fpMultiplier, vtUnknown, hostVerdict };
}

// ── Late entry: the filename was unknown at onCreated (redirect chains, e.g. Google Drive) ──────────
async function lateEntryRecord(item, state) {
  if (!item || (!isForced(item.id) && !isDownloadCheckActive(state, item))) return null;
  const downloadId = item.id;
  const url = item.finalUrl || item.url || "";
  if (!url || isTrustedDownload(state, item)) return null;
  const filename = item.filename || "";
  const c = FilenameAnalysis.classifyDownload(url, item.url || "", filename, item.mime);
  if (!c) return null;
  // What did the ORIGINAL url suggest? (unfiltered extension — DS-H007 category change)
  const suggestedExt = FilenameAnalysis.getRawExt(FilenameAnalysis.extractFilenameFromUrl(item.url || ""));
  const obfuscation = isPageMadeDownload(item.url) ? null : FilenameAnalysis.getObfuscationSignal(suggestedExt, c.ext);
  const record = {
    id: downloadId, startedAt: Date.now(), url, originalUrl: originalUrlOf(item, url),
    ext: c.ext, confirmedExt: c.ext, confirmedFilename: filename, fileType: c.fileType, isScript: c.isScript,
    visibleExt: c.visibleExt, isUnknownBinary: c.isUnknownBinary,   // 4.4.0: filename already confirmed here
    filename, mime: item.mime || "", totalBytes: item.fileSize || 0, referrer: item.referrer || null,
    sizeKnown: true,                                               // complete: fileSize is final
    ...emptyVt(), vtDone: true, vtUnknown: true,                   // no budget left for VirusTotal
    hostDone: false, hostResult: null, noClick: null,
    ...settingsSnapshot(state),
    state: CHROME_DOWNLOAD_COMPLETE, lateEntry: true, obfuscation
  };
  const [hostResult, noClick] = await Promise.all([
    hostReputation(record, c.ext, record.totalBytes, obfuscation, filename, true, c.isLinuxLauncher), clickFlag(downloadId)]);
  record.noClick = noClick;                                        // 5.1.3 (issue 6): asked at the start (askClick)
  record.hostResult = noClick === true ? withNoClickSignal(hostResult) : hostResult;
  record.hostDone = true;
  _pending.set(downloadId, record);
  armSweep();
  return record;
}

// ── onChanged — download complete: wait the rest of the budget, then act ─────
export async function onChanged(delta, state) {
  if (!delta.state || delta.state.current !== CHROME_DOWNLOAD_COMPLETE) return;
  if (_checked.has(delta.id)) return;                             // dedup guard
  _checked.add(delta.id);

  await _blocked.ready();
  if (isHeld(delta.id)) return;                                    // blockRiskyDownloads holds it: the notice decides
  let record = _pending.get(delta.id);
  if (!record) {
    const item = await searchItem(delta.id);
    if (item && !isForced(item.id) && blockIfNeeded(item, state)) return;   // completed before onCreated ran
    record = await lateEntryRecord(item, state);
  }
  if (!record) { _checked.delete(delta.id); releaseClick(delta.id); return; }   // not ours: release the guard entries

  const waitLeft = Math.max(0, DS_APP.VT_WAIT_BUDGET_MS - (Date.now() - record.startedAt));
  if (waitLeft > 0) await new Promise((r) => setTimeout(r, waitLeft));
  if (!_pending.has(delta.id)) return;                            // erased/swept while waiting

  // Confirmed filename + size, now that the download is complete.
  const item = await searchItem(delta.id);
  const confirmedFilename   = (item && item.filename) || record.filename;
  const confirmedTotalBytes = (item && item.fileSize) ?? record.totalBytes;

  // 4.4.0 (DS 3.5.0 R1): an extensionless generic binary may have got a real name now — DS's shared
  // decision: ordinary file → no warning; a monitored type → R1 no longer applies, re-score below.
  const shape = DownloadShape.reevaluate(record, confirmedFilename);
  if (shape.outcome === DownloadShape.OUTCOME.RELEASE) {
    releaseWithoutWarning(delta.id, "extensionless binary got an ordinary file name");
    return;
  }
  const shapeChanged = shape.outcome === DownloadShape.OUTCOME.BECAME_KNOWN;
  if (shapeChanged) {
    Object.assign(record, { fileType: shape.classified.fileType, isScript: shape.classified.isScript,
                            visibleExt: shape.classified.visibleExt, isUnknownBinary: false });
  }

  const confirmedExt = FilenameAnalysis.getBlockedExtension(record.url, confirmedFilename) || record.ext;

  // Obfuscation (extension hidden or changed category) and size-newly-known (DS v2.8.0) re-check.
  const obfuscation = record.lateEntry || isPageMadeDownload(record.originalUrl) ? null
    : FilenameAnalysis.getObfuscationSignal(record.ext, confirmedExt);
  const sizeNewlyKnown = !record.lateEntry && !record.sizeKnown && confirmedTotalBytes > 0;
  if ((obfuscation || sizeNewlyKnown || shapeChanged) && record.hostDone) {
    const recheck = await hostReputation(record, confirmedExt, confirmedTotalBytes, obfuscation,
                                         confirmedFilename, true, confirmedExt === DOWNLOAD_EXT_DESKTOP);
    record.hostResult = record.noClick === true ? withNoClickSignal(recheck) : recheck;   // 5.1.3: keep the signal
    record.totalBytes = confirmedTotalBytes;
    record.sizeKnown = true;
  }

  const { combined, scaledHostScore, fpMultiplier, vtUnknown, hostVerdict } = computeCombinedScore(record);
  record.hostVerdict = hostVerdict;   // 5.0.4 (DS 3.5.6): VirusTotal's answer picks the host verdict — before any reader

  // Stored before the auto-allow decision too: a late VirusTotal verdict (item 16) compares against it, so
  // a silently allowed file still gets a window when VirusTotal later says it is worse.
  Object.assign(record, { confirmedExt, confirmedFilename, scaledHostScore, combinedScore: combined,
                          fpMultiplier, vtUnknown, state: CHROME_DOWNLOAD_COMPLETE });
  // 4.4.0: an extensionless generic binary (R1) always gets the window (DS APP.EXTENSIONLESS_BINARY_ALWAYS_WARN).
  const mustWarn = DownloadShape.mustAlwaysWarn(record);
  if (!mustWarn && record.autoAllow && combined >= record.autoAllowThreshold) { release(delta.id, "auto-allowed"); return; }
  // 4.4.1 (DS 3.5.2 WarnPolicy): staged by the FP reduction level — the window opens when the combined score is at or
  // below the level's threshold, or when a download exception applies (known bad, impersonation, the file itself,
  // chat/webmail link, very new domain). Otherwise quiet: release() — which keeps the record while a silent
  // VirusTotal retry is still running, so a late verdict that now crosses the line still opens the window
  // (handleLateVtResult, record.quiet).
  // 4.4.4 (user request, "Silent when inconclusive"): this whole staged-quiet behaviour is now its own
  // toggle, separate from "Silent when probably safe" above — off means every download that reaches this
  // point (not auto-allowed, no exception) always gets the window, whatever its score.
  if (!mustWarn && record.silentWhenInconclusive && !warnDecision(record, combined).warn) {
    record.quiet = true;
    release(delta.id, "quiet: below the warning threshold, no exception");
    return;
  }

  await openWarningWindow(delta.id);
}

function openWarningWindow(downloadId) { return openWindow(DOWNLOAD_WARNING_PAGE, downloadId, null); }

// size null = maximized (DownloadSentinel's warning page); else { width, height }.
// Returns the window id, or null when it did not open. track = a warnRiskyDownloads warning window (tracked in
// _windows, released here on failure); the blockRiskyDownloads notice is tracked by its lane entry instead
// (4.5.5 — survives a service-worker restart) and its caller decides what a failed open means.
async function openWindow(page, downloadId, size, track = true) {
  const url = `${chrome.runtime.getURL(page)}?${DOWNLOAD_ID_PARAM}=${encodeURIComponent(downloadId)}`;
  const shape = size ? { width: size.width, height: size.height } : { state: WINDOW_STATE_MAXIMIZED };
  try {
    const win = await chrome.windows.create({ url, type: WINDOW_TYPE_POPUP, ...shape });
    if (!win || win.id === undefined) throw new Error("no window");
    if (track) _windows.set(win.id, downloadId);
    return win.id;
  } catch (e) {
    // The user cannot act on a window that did not open: say so and release everything.
    console.error(LOG_PREFIX, "download window failed:", e);
    if (track) release(downloadId, "warning page open failed");
    return null;
  }
}

// ── Warning page model ───────────────────────────────────────────────────────
// The record (plain data, C31) plus the page look the user chose in Options. Never the API key.
export function pageModel(downloadId, state) {
  const record = _pending.get(downloadId);
  if (!record) return null;
  const d = state.downloads;
  return {
    record: JSON.parse(JSON.stringify(record)),
    look: { color: { ...d.warningColor }, title: d.warningTitle || DOWNLOAD_WARNING_TITLE_DEFAULT }
  };
}

// ── VirusTotal key nudge (browser start) ─────────────────────────────────────
export async function offerVtKey(state) {
  if (!shouldOfferVtKey(state)) return;
  try {
    await chrome.windows.create({ url: chrome.runtime.getURL(VT_KEY_PROMPT_PAGE), type: WINDOW_TYPE_POPUP,
                                  width: VT_KEY_PROMPT_WINDOW.width, height: VT_KEY_PROMPT_WINDOW.height });
  } catch (e) { console.error(LOG_PREFIX, "VirusTotal key prompt failed:", e); }
}

// ── blockRiskyDownloads — block risky downloads (4.3.2; held, not cancelled, since 4.5.5 — see header) ─────
function isHeld(downloadId) { const b = _blocked.map.get(downloadId); return !!b && b.phase === PHASE.HELD; }
function isForced(downloadId) { const b = _blocked.map.get(downloadId); return !!b && b.phase === PHASE.ALLOWED; }

// Lane entry removed (any phase) — safe to call before the restore finished.
function dropLaneEntry(downloadId) {
  _blocked.ready().then(() => { if (_blocked.map.delete(downloadId)) _blocked.save(); });
}

// Pause a running download. A download that already finished (a tiny file) or failed cannot be paused —
// it stays as it is; discardHeld() still deletes a finished file if the user does not continue.
async function holdDownload(downloadId) {
  try { await chrome.downloads.pause(downloadId); }
  catch (e) { console.info(LOG_PREFIX, "blocked download not paused (already finished or stopped):", e && e.message); }
}

// Holds a monitored download when blockRiskyDownloads applies; true = held (the caller stops there).
// Needs _blocked.ready() — every caller awaited it.
function blockIfNeeded(item, state) {
  const reason = downloadBlockReason(state, item);
  if (!reason) return false;
  const url = item.finalUrl || item.url || "";
  const c = url && FilenameAnalysis.classifyDownload(url, item.url || "", item.filename || "", item.mime);
  if (!c) return false;                                             // not a risky file type: never blocked
  // 4.4.0: an extensionless generic binary (DS 3.5.0 R1) is warn-only by decision — legit Linux release
  // binaries look exactly like this — so blockRiskyDownloads never blocks it; the warning window still opens.
  if (c.isUnknownBinary) return false;
  const entry = { phase: PHASE.HELD, downloadId: item.id, url: item.url || url, filename: item.filename || "", ext: c.ext,
                  site: downloadSiteHost(item), reason, blockedAt: Date.now(), windowId: null };
  _blocked.map.set(item.id, entry);
  _blocked.save();
  armSweep();
  holdDownload(item.id);
  openWindow(DOWNLOAD_BLOCKED_PAGE, item.id, DOWNLOAD_BLOCKED_WINDOW, false).then((windowId) => {
    if (windowId === null) { discardHeld(item.id, "notice could not open"); return; }   // nobody can choose: safe choice
    const b = _blocked.map.get(item.id);
    if (b) { b.windowId = windowId; _blocked.save(); }
  });
  return true;
}

// Cancel removes the partial file; a download that already finished (tiny file) is deleted from disk.
async function stopDownload(downloadId) {
  await chrome.downloads.cancel(downloadId);
  const item = await searchItem(downloadId);
  if (item && item.state === CHROME_DOWNLOAD_COMPLETE && item.exists !== false) await chrome.downloads.removeFile(downloadId);
}

// OK / notice closed / sweep: the held download is cancelled and its file deleted; the lane entry goes.
async function discardHeld(downloadId, reason) {
  try { await stopDownload(downloadId); }
  catch (e) { console.warn(LOG_PREFIX, "held download could not be discarded (already gone?):", e && e.message); }
  release(downloadId, `blocked — ${reason}`);
}

export async function blockedModel(downloadId) {
  await _blocked.ready();
  const b = _blocked.map.get(downloadId);
  return b && b.phase === PHASE.HELD ? JSON.parse(JSON.stringify(b)) : null;
}

// 5.1.3 — the host an "Always allow" / "Always ignore" puts on the allow list ("Download: host"): the file's own web
// host, else the page it came from (a page-made blob:/data: file). From the record the page belongs to (C28), or "".
export function allowHostFor(downloadId) {
  const r = _pending.get(downloadId) || _blocked.map.get(downloadId);
  if (!r) return "";
  return (r.url && UrlUtils.getHostname(r.url)) || r.site || "";
}

// "Download anyway": the SAME download continues (nothing is fetched again) and warnRiskyDownloads checks it.
export async function blockedAction(downloadId, action, state) {
  await _blocked.ready();
  if (!isHeld(downloadId)) throw new Error("this blocked download is no longer active");
  if (action === BLOCKED_DOWNLOAD_ACTION.OK) { await discardHeld(downloadId, "OK"); return; }
  if (action !== BLOCKED_DOWNLOAD_ACTION.DOWNLOAD_ANYWAY) throw new Error("unknown action");
  const item = await searchItem(downloadId);
  if (!item || item.state === CHROME_DOWNLOAD_INTERRUPTED) {
    release(downloadId, "blocked — gone before Download anyway");
    throw new Error("Chrome no longer has this download — download the file again from the page");
  }
  const b = _blocked.map.get(downloadId);
  b.phase = PHASE.ALLOWED;                                          // before resuming: the next events see it
  await _blocked.save();
  if (item.state === CHROME_DOWNLOAD_COMPLETE) {                    // finished while held: check it now
    _checked.delete(downloadId);
    await onChanged({ id: downloadId, state: { current: CHROME_DOWNLOAD_COMPLETE } }, state);
    return;
  }
  if (item.paused) await chrome.downloads.resume(downloadId);       // throws when Chrome cannot resume: shown
  startCheck(item, state);                                          // completion → onChanged → warning window
}
