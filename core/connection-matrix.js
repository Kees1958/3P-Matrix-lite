// ── core/connection-matrix.js ─────────────────────────────────────────────────
// Show Matrix — per-tab observer of every THIRD-PARTY connection, blocked or
// not. Ported from 3P-Matrix-lite 4.0.2 core/connection-matrix.js; rows are
// grouped by registered domain (PSL-based, util/domain.js). 4.2.1: rows only record what was
// SEEN (types, count, one sample URL); whether a type is allowed or blocked is the policy's
// decision, computed from the active rules by core/matrix-disposition.js (3P-Matrix-lite model).
//
// Row key (3P-Matrix-lite 4.0.2 _groupingKeyFor): normally the registered domain, EXCEPT a
// subdomain gets its own row when
//   1. its host name contains "cdn" and its registered domain does not (level 4's cdn allow
//      then treats it differently from its parent; lite also split when both contain "cdn",
//      which only added rows that are always decided the same way)
//   2. it is itself an entry of the built-in whitelist (e.g. js.stripe.com vs stripe.com)
//
// Public interface:
//   startMatrix(tabId, host, onExpire) — begin (or restart) observing a tab; onExpire(tabId)
//                              runs once when MATRIX_DURATION_MS elapses (used to close the panel)
//   stopMatrix(tabId)          — stop observing a tab, release its memory
//   getMatrixData(tabId)       — snapshot { host, site, entries[], remaining, requestCount }
//   clearOnNavigation(tabId)   — top frame committed: start a fresh table
//   isObserving(tabId)
//
// Guards / bounded state (all in memory; a service-worker restart simply ends
// observation — the panel then closes itself, ui/matrix.js):
//   _tabs  Map<tabId, Bucket>   — one bucket per observed tab, released on stop,
//                                 tab close, or MATRIX_DURATION_MS timeout
//   entries per bucket capped at MATRIX_DOMAINS_PER_TAB (oldest dropped); observation ends after MATRIX_DURATION_MS
//   the shared webRequest listener exists only while at least one tab is observed
// ─────────────────────────────────────────────────────────────────────────────

import { MATRIX_DOMAINS_PER_TAB, MATRIX_DURATION_MS, MATRIX_TYPE_LABEL, CDN_HOST_MARKER } from "../data/constants.js";
import { registeredDomain } from "../util/domain.js";
import { BUILTIN_ALL } from "../data/builtin-domains.js";

const BUILTIN_EXACT = new Set(BUILTIN_ALL);   // exact built-in entries (row split rule 2)

const OBSERVED_TYPES = Object.keys(MATRIX_TYPE_LABEL);
const _tabs = new Map();
let _listenerActive = false;

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

// Row key for a request host, or null when first party (see header for the split rules).
function rowKeyFor(bucket, host) {
  const domain = registeredDomain(host);
  if (!domain || domain === bucket.site) return null;          // first party — not shown
  if (host === domain) return domain;
  const cdnSplit = host.includes(CDN_HOST_MARKER) && !domain.includes(CDN_HOST_MARKER);
  if (cdnSplit || BUILTIN_EXACT.has(host)) return host;
  return domain;
}

function entryFor(bucket, url) {
  const host = hostOf(url);
  if (!host) return null;
  const key = rowKeyFor(bucket, host);
  if (!key) return null;
  let entry = bucket.entries.get(key);
  if (!entry) {
    if (bucket.entries.size >= MATRIX_DOMAINS_PER_TAB) bucket.entries.delete(bucket.entries.keys().next().value);
    entry = { domain: key, types: new Set(), sampleUrls: {}, count: 0 };
    bucket.entries.set(key, entry);
  }
  return entry;
}

function onRequest(details) {
  const bucket = _tabs.get(details.tabId);
  if (!bucket) return;
  const label = MATRIX_TYPE_LABEL[details.type];
  const entry = label && entryFor(bucket, details.url);
  if (!entry) return;
  entry.types.add(label);
  if (!entry.sampleUrls[label]) entry.sampleUrls[label] = details.url;   // first seen per type wins
  entry.count++;
  bucket.requestCount++;
}

function ensureListener() {
  if (_listenerActive) return;
  chrome.webRequest.onBeforeRequest.addListener(onRequest, { urls: ["<all_urls>"], types: OBSERVED_TYPES });
  _listenerActive = true;
}

function releaseListenerIfIdle() {
  if (!_listenerActive || _tabs.size > 0) return;
  try { chrome.webRequest.onBeforeRequest.removeListener(onRequest); } catch { /* already gone */ }
  _listenerActive = false;
}

export function startMatrix(tabId, host, onExpire) {
  stopMatrix(tabId);                                            // guard: release any previous bucket first
  const bucket = {
    host, site: registeredDomain(host), entries: new Map(), requestCount: 0,
    startTime: Date.now(),
    timer: setTimeout(() => {
      stopMatrix(tabId);                                        // release data + listener first
      if (typeof onExpire === "function") { try { onExpire(tabId); } catch { /* panel already gone */ } }
    }, MATRIX_DURATION_MS)
  };
  _tabs.set(tabId, bucket);
  ensureListener();
}

export function stopMatrix(tabId) {
  const bucket = _tabs.get(tabId);
  if (!bucket) return;
  clearTimeout(bucket.timer);
  _tabs.delete(tabId);
  releaseListenerIfIdle();
}

export function isObserving(tabId) { return _tabs.has(tabId); }

export function clearOnNavigation(tabId, newHost) {
  const bucket = _tabs.get(tabId);
  if (!bucket) return;
  bucket.entries.clear();
  bucket.requestCount = 0;
  if (newHost) { bucket.host = newHost; bucket.site = registeredDomain(newHost); }
}

export function getMatrixData(tabId) {
  const bucket = _tabs.get(tabId);
  if (!bucket) return { observing: false, host: "", site: "", entries: [], remaining: 0, requestCount: 0 };
  return {
    observing: true,
    host: bucket.host,
    site: bucket.site,
    requestCount: bucket.requestCount,
    remaining: Math.max(0, MATRIX_DURATION_MS - (Date.now() - bucket.startTime)),
    entries: [...bucket.entries.values()].map((e) => ({
      domain: e.domain, types: [...e.types], sampleUrls: { ...e.sampleUrls }, count: e.count
    }))
  };
}
