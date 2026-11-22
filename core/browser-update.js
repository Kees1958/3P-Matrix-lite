// ── core/browser-update.js ────────────────────────────────────────────────────
// 4.7.0 — "Chrome has a security update waiting" band (not a selectable protection: always on, like the badge
// icon — a browser six zero-days behind protects nobody). Checks Google's public VersionHistory API once a day
// for the current stable release of the user's OWN platform, and compares it with the running browser.
//
// Public interface:
//   init()          — idempotent: creates the daily alarm if missing (every SW start, as core/download-guard.js)
//   onAlarm(alarm)  — chrome.alarms.onAlarm body; runs the check when it is BROWSER_UPDATE.ALARM_NAME
//   popupBand()     — Promise<{ show, message } | null> for the popup; also runs the check once if none has ever
//                     completed (first install, so the band is not empty for a day)
//
// Request: the platform id only (chrome.runtime.getPlatformInfo() → BROWSER_UPDATE_PLATFORM) — nothing about the
// user or their browsing. A Chromium-based browser that is not Google Chrome (Brave, Edge, Opera, Vivaldi, distro
// Chromium — chrome.runtime.getBrowserInfo() when available, else UA brand data) follows its OWN patch numbers:
// only the MAJOR version is compared, and only OTHER_BROWSER_MAJORS_BEHIND majors counts as "behind" — Chrome's
// point-release cadence does not apply to them, and comparing minors would be a constant false alarm.
// A release counts as "waiting" once Chrome would really offer it (MIN_ROLLOUT_FRACTION for MIN_ROLLOUT_AGE_MS, or
// out ANY_ROLLOUT_AGE_MS regardless of fraction) — Google rolls updates out gradually, so a brand-new release is
// not yet an update most users are missing.
// Fail-soft: network error, timeout, an unreadable/oversized response, or an unknown platform/os → no band change
// (the last successful check is kept); ChromeOS is never checked (updates with the OS).
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX, BROWSER_UPDATE as BU, BROWSER_UPDATE_PLATFORM as PLATFORM_IDS } from "../data/constants.js";

const CHROMEOS_PLATFORM = "cros";
const VERSION_SEGMENT_RE = /^\d+$/;
const MAJOR_SEGMENT_INDEX = 0;
const VERSION_SEGMENTS = 4;                   // major.minor.build.patch — Chrome's own version shape

function platformIdFor(platformInfo) {
  const table = PLATFORM_IDS[platformInfo.os];
  if (!table) return null;                                           // unknown os: never checked
  return table[platformInfo.arch] || table.default;
}

// "152.0.7977.82" → [152,0,7977,82], or null for anything that is not four numeric segments.
function parseVersion(v) {
  const parts = String(v || "").split(".");
  if (parts.length !== VERSION_SEGMENTS || !parts.every((p) => VERSION_SEGMENT_RE.test(p))) return null;
  return parts.map(Number);
}

function compareVersions(a, b) {
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}

// The newest release that is really "waiting" (rolled out enough, long enough) for this platform, or null.
function currentServingRelease(releases) {
  const now = Date.now();
  let best = null;
  for (const r of releases) {
    const version = parseVersion(r.version);
    const servingStart = Date.parse(r.servingStartTime || r.timestamp || "");
    if (!version || Number.isNaN(servingStart)) continue;
    const age = now - servingStart;
    const fraction = Number(r.fraction) || 0;
    const rolledOutEnough = (fraction >= BU.MIN_ROLLOUT_FRACTION && age >= BU.MIN_ROLLOUT_AGE_MS) || age >= BU.ANY_ROLLOUT_AGE_MS;
    if (!rolledOutEnough) continue;
    if (!best || compareVersions(version, best) > 0) best = version;
  }
  return best;
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), BU.FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const len = Number(res.headers.get("content-length") || 0);
    if (len > BU.MAX_RESPONSE_BYTES) throw new Error("response too large");
    const text = await res.text();
    if (text.length > BU.MAX_RESPONSE_BYTES) throw new Error("response too large");
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

// Running browser's own version + brand, from the most specific source available.
async function runningBrowser() {
  let brand = BU.CHROME_BRAND;
  if (typeof chrome.runtime.getBrowserInfo === "function") {
    try { brand = (await chrome.runtime.getBrowserInfo()).name || brand; } catch { /* keep default */ }
  }
  const uaBrands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  const uaFull = navigator.userAgentData && typeof navigator.userAgentData.getHighEntropyValues === "function"
    ? await navigator.userAgentData.getHighEntropyValues(["fullVersionList"]).catch(() => null)
    : null;
  const fullList = (uaFull && uaFull.fullVersionList) || uaBrands;
  const isChrome = brand === BU.CHROME_BRAND || uaBrands.some((b) => b.brand === BU.CHROME_BRAND) && !uaBrands.some((b) => b.brand !== BU.CHROME_BRAND && b.brand !== BU.CHROMIUM_BRAND && !/not.a.brand/i.test(b.brand));
  const entry = fullList.find((b) => b.brand === BU.CHROME_BRAND) || fullList.find((b) => b.brand === BU.CHROMIUM_BRAND) || fullList[0];
  const version = parseVersion(entry && entry.version && entry.version.split(".").length === VERSION_SEGMENTS ? entry.version : `${entry ? entry.version : "0"}.0.0.0`);
  return { brand, isChrome: !!isChrome, version };
}

async function runCheck() {
  const platformInfo = await chrome.runtime.getPlatformInfo();
  if (platformInfo.os === CHROMEOS_PLATFORM) return null;             // updates with the OS
  const platformId = platformIdFor(platformInfo);
  if (!platformId) return null;
  const url = BU.API_URL_TEMPLATE.replace(BU.PLATFORM_TOKEN, platformId);
  const data = await fetchJson(url);
  const releases = Array.isArray(data.releases) ? data.releases : [];
  const serving = currentServingRelease(releases);
  if (!serving) return null;
  const running = await runningBrowser();
  if (!running.version) return null;
  const behind = running.isChrome
    ? compareVersions(serving, running.version) > 0
    : serving[MAJOR_SEGMENT_INDEX] - running.version[MAJOR_SEGMENT_INDEX] >= BU.OTHER_BROWSER_MAJORS_BEHIND;
  const record = { checkedAt: Date.now(), servingVersion: serving.join("."), runningVersion: running.version.join("."), isChrome: running.isChrome, behind, os: platformInfo.os };
  await chrome.storage.local.set({ [BU.STORAGE_KEY]: record });
  return record;
}

export async function init() {
  chrome.alarms.create(BU.ALARM_NAME, { periodInMinutes: BU.PERIOD_MINUTES })
    .catch((e) => console.error(LOG_PREFIX, "browser-update alarm:", e));
}

export async function onAlarm(alarm) {
  if (alarm.name !== BU.ALARM_NAME) return;
  try { await runCheck(); }
  catch (e) { console.warn(LOG_PREFIX, "browser-update check failed (kept the last result):", e); }   // fail-soft
}

function bandFor(record, os) {
  if (!record || !record.behind) return null;
  const message = os === "linux"
    ? "Chrome has a security update waiting — update it through your software updater."
    : "Chrome has a security update waiting — restart Chrome to finish it.";
  return { show: true, message };
}

export async function popupBand() {
  const stored = await chrome.storage.local.get(BU.STORAGE_KEY);
  let record = stored[BU.STORAGE_KEY] || null;
  if (!record) {
    try { record = await runCheck(); }                                // first install: do not show an empty band for a day
    catch (e) { console.warn(LOG_PREFIX, "browser-update first check failed:", e); return null; }
  }
  return bandFor(record, record && record.os);
}
