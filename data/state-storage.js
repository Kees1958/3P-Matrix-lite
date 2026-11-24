// ── data/state-storage.js ─────────────────────────────────────────────────────
// State schema, defaults, validation and chrome.storage.local access.
// THE only module that reads/writes the persistent state key.
//
// Public interface:
//   defaultState()           — a fresh, fully independent default state object
//   normalizeState(raw)      — returns a NEW validated state (never mutates raw)
//   loadState()              — Promise<state>  (always normalized; a private copy the caller may change)
//   saveState(state)         — Promise<void>   (normalizes before writing)
//   isValidHost(h)           — lower-case DNS host name check
//   isValidTld(t)            — lower-case TLD (or xn-- punycode) check
//   parseLevel(v)            — level 1..5 from any input, or null
//   STATE_MIGRATIONS         — the ordered schema migration list (read-only; for tests)
//   withStateLock(fn)        — serializes read-modify-write cycles (guard against
//                              two messages interleaving and losing an update)
//
// State shape:
//   schema               number   STATE_SCHEMA_VERSION
//   level                1..5     current global (session) level
//   prevLevel            1..5     level before the last slider move (lock restores it)
//   startupLevel         1..5     level applied at every browser start
//   siteLocks            { [registeredDomain]: level }   — allow list = sites locked at 1
//   siteLocksOrder       string[] insertion order for FIFO eviction (in sync with siteLocks)
//   disabledProtections  { [protectionKey]: true }       — unticked protections
//   safeZone             { manualTlds[], excludedTlds[], tlds[] } — the "safer regions"
//                        (auto-add scope is fixed, constants SAFER_REGIONS_AUTO_MODE; a stored
//                        autoTldMode from ≤ 0.2.3 is dropped here)
//                        (key name kept: storage keys are contracts)
//   dns                  { first, second }                — provider ids or DNS_NONE
//   matrixRules          { [MATRIX_SITE_ALL]: { [domain]: { script, frame } } } — Show Matrix
//                        overrides, always global (each scope "block" | "allow" | absent);
//                        capped at MATRIX_OVERRIDES_CAP domains.
//   downloads            warnRiskyDownloads (4.3.0, DownloadSentinel settings) — defaults DOWNLOAD_DEFAULTS:
//                        { vtApiKey, vtEnabled, silentWhenInconclusive, autoAllow, autoAllowThreshold, fpReductionLevel,
//                          trustedDomains[], warningColor{r,g,b}, warningTitle, vtKeyPromptDismissed,
//                          (4.3.4's trustAiDownloads dropped in 4.3.6: not copied, so it disappears on load) }
//                        A new key, not a changed shape: older states simply get the defaults (no
//                        migration step, schema unchanged). The DNS choice is the shared state.dns.
//   allowCategories      5.1.3 { firewall, scam, tamper: registered domains[] } — the allow list's category lines
//   (gone: tamper        5.1.0–5.1.2 never-warn list, never released) { exceptions: [{ rule, site }] } — "never warn again" choices; rule =
//                        data/tamper-rules.js TAMPER_RULE value, site = a registered domain or TAMPER_EXCEPTION_ALL_SITES
//                        ("*" = every site); capped at TAMPER_EXCEPTIONS_CAP, duplicates dropped. A new key (no
//                        migration, schema unchanged), like `downloads`. Nothing about visited pages is stored here.
//
// Schema versions and migrations (C32, audit finding 9) — ONE ordered list, run from ONE place:
//   normalizeState(raw) → migrateRaw(raw) applies every MIGRATIONS step whose `to` is above the
//   data's own `schema` (data without one — stored before 4.2.3, or any backup file — counts as 1),
//   then validates. Every step is idempotent, so running it on already-converted data is harmless.
//   Adding a shape change = bump STATE_SCHEMA_VERSION + append one step here; nothing else converts.
//   schema 1  ≤ 4.2.2 — matrixRules may hold per-site keys and pre-4.2 { code, all } entries
//   schema 2  4.2.3   — matrixRules is { "*": { [domain]: { script?, frame? } } } only
//   schema 3  4.3.2   — every DEFAULT_OFF_KEYS protection (blockRiskyDownloads) is in disabledProtections:
//                       a state without the key would otherwise read as "ticked" (the registry's default
//                       is "on" unless unticked). Not COMPAT-REMOVE: a new default-off protection appends
//                       the same kind of step.
//   schema 4  4.4.5   — a lock whose key is a SHARED_HOSTING_SUFFIX itself ("sharepoint.com") is dropped: since
//                       4.4.5 locks are per tenant ("acme-my.sharepoint.com"), so that key would never match
//                       again — and, kept, it would only have been a dead entry in the allow list. (4.4.5–4.5.x
//                       first carried such a lock over to the tenant hosts open in tabs on update — removed in
//                       4.6.0 as scheduled); this step drops it.
//   schema 5  4.5.8   — the DNS default became Control D + DNS4EU. A stored pair still EQUAL to the old default
//                       for the user's region (legacyDefaultDns(): Quad9 + Cloudflare, France Control D +
//                       Cloudflare) counts as never changed and moves to the new pair; any other pair is kept.
//                       (A user who deliberately picked exactly the old default cannot be told apart — moved too.)
//
// Backward-compatibility conversions — removal schedule (grep: COMPAT-REMOVE)
//   Code that exists only to read data written by an older version carries the tag
//   "COMPAT-REMOVE ≥x.y"; from version x.y on it is deleted. tools/check-compat-remove.mjs (complete-check
//   step compat-remove, 4.5.4) FAILS the suite when a tagged block outlives its version.
//   Removed in 4.5.4 (tag ≥4.5): the schema-2 Show Matrix conversion + MATRIX_LEGACY_SCOPES, and the v1
//   backup format in settings-io.js. Removed in 4.6.0 (tag ≥4.6): core/legacy-suffix-locks.js (4.4.5 upgrade).
// ─────────────────────────────────────────────────────────────────────────────

import {
  STORAGE_KEY_STATE, STORAGE_AREA_LOCAL, STATE_SCHEMA_VERSION, SHARED_HOSTING_SUFFIXES, LEVEL_MIN, LEVEL_MAX, DEFAULT_STARTUP_LEVEL,
  SITE_LOCKS_CAP, MANUAL_TLDS_CAP, SAFE_ZONE_TLDS_CAP,
  DOWNLOAD_DEFAULTS, FP_LEVEL, VT_API_KEY_RE, AUTO_ALLOW_THRESHOLD_MIN, AUTO_ALLOW_THRESHOLD_MAX,
  TRUSTED_DOWNLOAD_DOMAINS_MAX, DOWNLOAD_WARNING_TITLE_MAX, RGB_CHANNEL_MAX,
  DNS_PROVIDER, DNS_NONE, DEFAULT_DNS_FIRST, DEFAULT_DNS_SECOND, LEGACY_DNS_DEFAULT, LOG_PREFIX, DECIMAL_RADIX,
  MATRIX_SCOPE, MATRIX_ACTION, MATRIX_OVERRIDES_CAP, MATRIX_SITE_ALL, ALLOW_CATEGORY_CAP
} from "./constants.js";
import { ALLOW_CATEGORIES_STORED } from "./allow-categories.js";
import { PROTECTION_KEY, PROTECTION_KEYS, PROTECTION_BY_KEY, DEFAULT_OFF_KEYS } from "./protections.js";
import { BASE_TLDS } from "./tld-constants.js";
import { registeredDomain } from "../util/domain.js";
// DownloadSentinel's region-aware DNS defaults. 4.5.8: read only by the schema-5 migration (legacyDefaultDns) —
// a first install no longer uses a region rule.
import { DnsDefaults } from "../lib/downloadsentinel/util/DnsDefaults.js";

const DNS_IDS = new Set([...Object.values(DNS_PROVIDER).map((p) => p.id), DNS_NONE]);
const TLD_RE  = /^[a-z0-9-]{2,63}$|^xn--[a-z0-9-]{1,59}$/;
const HOST_RE = /^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

export function defaultState() {
  return {
    schema:              STATE_SCHEMA_VERSION,
    level:               DEFAULT_STARTUP_LEVEL,
    prevLevel:           DEFAULT_STARTUP_LEVEL,
    startupLevel:        DEFAULT_STARTUP_LEVEL,
    siteLocks:           {},
    siteLocksOrder:      [],
    disabledProtections: Object.fromEntries(DEFAULT_OFF_KEYS.map((k) => [k, true])),   // default-off protections
    safeZone: {
      manualTlds:   [],
      excludedTlds: [],
      tlds:         BASE_TLDS.slice()       // replaced by the computed list on first boot
    },
    dns: defaultDns(),
    matrixRules: {},
    downloads: defaultDownloads(),
    allowCategories: defaultAllowCategories()      // 5.1.3: the allow list's Firewall / Scam / Tamper lines
  };
}

// First-install DNS pair (4.5.8: one pair for every region — see DEFAULT_DNS_FIRST in constants.js). A stored
// choice is never replaced here — normalizeState() only falls back to this for a missing/invalid stored value.
function defaultDns() {
  return { first: DEFAULT_DNS_FIRST, second: DEFAULT_DNS_SECOND };
}

// The pair 4.3.7–4.5.7 gave a first install in THIS browser's region: a DownloadSentinel region rule
// (DnsDefaults: France → Control D + Cloudflare) or else LEGACY_DNS_DEFAULT. For the schema-5 migration only.
// DnsDefaults never throws and never returns an unknown id; re-checked against DNS_IDS anyway (data, not trusted).
function legacyDefaultDns() {
  const region = DnsDefaults.get();
  const useRegion = region.region !== DnsDefaults.GLOBAL_REGION && DNS_IDS.has(region.first) && DNS_IDS.has(region.second);
  return useRegion ? { first: region.first, second: region.second } : { ...LEGACY_DNS_DEFAULT };
}

function defaultAllowCategories() {
  return Object.fromEntries(ALLOW_CATEGORIES_STORED.map((c) => [c, []]));
}
// 5.1.3 — each stored category: valid hosts → registered domains, no duplicates, at most ALLOW_CATEGORY_CAP.
function normalizeAllowCategories(raw) {
  const out = defaultAllowCategories();
  if (!raw || typeof raw !== "object") return out;
  for (const c of ALLOW_CATEGORIES_STORED) {
    if (!Array.isArray(raw[c])) continue;
    for (const h of raw[c]) {
      const host = String(h).trim().toLowerCase();
      if (!isValidHost(host)) continue;
      const site = registeredDomain(host);
      if (!out[c].includes(site)) out[c].push(site);
      if (out[c].length >= ALLOW_CATEGORY_CAP) break;
    }
  }
  return out;
}

// A fresh, independent copy of the download-protection defaults (arrays/objects never shared).
function defaultDownloads() {
  return {
    ...DOWNLOAD_DEFAULTS,
    trustedDomains: DOWNLOAD_DEFAULTS.trustedDomains.slice(),
    warningColor: { ...DOWNLOAD_DEFAULTS.warningColor }
  };
}

// ── Validation helpers (pure) ────────────────────────────────────────────────
function clampLevel(v, fallback) {
  const n = Number.parseInt(v, DECIMAL_RADIX);
  return Number.isInteger(n) && n >= LEVEL_MIN && n <= LEVEL_MAX ? n : fallback;
}
function cleanTldList(list, cap) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const t of list) {
    const s = String(t).trim().replace(/^\.+/, "").toLowerCase();
    if (TLD_RE.test(s) && !out.includes(s)) out.push(s);
    if (out.length >= cap) break;
  }
  return out;
}
export function isValidHost(h) { return typeof h === "string" && HOST_RE.test(h); }
export function isValidTld(t) { return typeof t === "string" && TLD_RE.test(t); }
// A level from any input (message field, select value) → LEVEL_MIN … LEVEL_MAX, or null when invalid.
export function parseLevel(v) { return clampLevel(v, null); }

// Returns a NEW, fully validated state object built from `raw` (any shape).
export function normalizeState(raw) {
  const d = defaultState();
  const r = migrateRaw(raw);                 // older shapes converted first, in schema order
  const s = defaultState();

  s.level        = clampLevel(r.level, d.level);
  s.prevLevel    = clampLevel(r.prevLevel, s.level);
  s.startupLevel = clampLevel(r.startupLevel, d.startupLevel);

  // siteLocks + order — rebuilt together so they can never drift apart.
  const locks = (r.siteLocks && typeof r.siteLocks === "object") ? r.siteLocks : {};
  const order = Array.isArray(r.siteLocksOrder) ? r.siteLocksOrder : Object.keys(locks);
  for (const host of order) {
    if (!isValidHost(host) || Object.prototype.hasOwnProperty.call(s.siteLocks, host)) continue;
    const lvl = clampLevel(locks[host], null);
    if (lvl === null) continue;
    s.siteLocks[host] = lvl;
    s.siteLocksOrder.push(host);
  }
  while (s.siteLocksOrder.length > SITE_LOCKS_CAP) delete s.siteLocks[s.siteLocksOrder.shift()];

  // disabledProtections — only known keys survive.
  const dis = (r.disabledProtections && typeof r.disabledProtections === "object") ? r.disabledProtections : {};
  // Built from the data only (not on top of defaultState's default-off entries — that would undo a tick):
  // data without the newest default-off keys gets them from STATE_MIGRATIONS, a fresh install from defaultState().
  s.disabledProtections = {};
  // 5.1.0: a protection without a checkbox of its own (switchable: false) keeps no untick — it follows its master.
  for (const key of PROTECTION_KEYS) if (dis[key] === true && PROTECTION_BY_KEY[key].switchable !== false) s.disabledProtections[key] = true;

  // safeZone
  const z = (r.safeZone && typeof r.safeZone === "object") ? r.safeZone : {};
  s.safeZone.manualTlds   = cleanTldList(z.manualTlds, MANUAL_TLDS_CAP);
  s.safeZone.excludedTlds = cleanTldList(z.excludedTlds, SAFE_ZONE_TLDS_CAP);
  s.safeZone.tlds         = Array.isArray(z.tlds) ? cleanTldList(z.tlds, SAFE_ZONE_TLDS_CAP) : d.safeZone.tlds;

  // dns
  const dns = (r.dns && typeof r.dns === "object") ? r.dns : {};
  s.dns.first  = DNS_IDS.has(dns.first)  ? dns.first  : d.dns.first;
  s.dns.second = DNS_IDS.has(dns.second) ? dns.second : d.dns.second;
  if (s.dns.second !== DNS_NONE && s.dns.second === s.dns.first) s.dns.second = DNS_NONE; // never ask the same resolver twice

  s.matrixRules = normalizeMatrixRules(r.matrixRules);
  s.downloads = normalizeDownloads(r.downloads);
  s.allowCategories = normalizeAllowCategories(r.allowCategories);   // 5.1.3 (the 5.1.0–5.1.2 never-warn list was never released: dropped)

  return s;
}

// ── Download protection settings (pure, 4.3.0) ───────────────────────────────
const FP_LEVELS = new Set(Object.values(FP_LEVEL));
const RGB_CHANNELS = Object.freeze(["r", "g", "b"]);

function bool(v, fallback) { return typeof v === "boolean" ? v : fallback; }
function clampInt(v, min, max, fallback) {
  const n = Number.parseInt(v, DECIMAL_RADIX);
  return Number.isInteger(n) ? Math.min(max, Math.max(min, n)) : fallback;
}
export function isValidVtKey(k) { return typeof k === "string" && VT_API_KEY_RE.test(k); }

// Every field validated on its own — a bad value falls back to its default, never to "off".
function normalizeDownloads(raw) {
  const d = defaultDownloads();
  if (!raw || typeof raw !== "object") return d;
  const out = defaultDownloads();
  out.vtApiKey             = isValidVtKey(raw.vtApiKey) ? raw.vtApiKey : d.vtApiKey;
  out.vtEnabled            = bool(raw.vtEnabled, d.vtEnabled);
  out.silentWhenInconclusive = bool(raw.silentWhenInconclusive, d.silentWhenInconclusive);
  out.autoAllow            = bool(raw.autoAllow, d.autoAllow);
  out.autoAllowThreshold   = clampInt(raw.autoAllowThreshold, AUTO_ALLOW_THRESHOLD_MIN, AUTO_ALLOW_THRESHOLD_MAX, d.autoAllowThreshold);
  out.fpReductionLevel     = FP_LEVELS.has(raw.fpReductionLevel) ? raw.fpReductionLevel : d.fpReductionLevel;
  if (Array.isArray(raw.trustedDomains)) {
    const list = [];
    for (const h of raw.trustedDomains) {
      const host = String(h).trim().toLowerCase();
      if (isValidHost(host) && !list.includes(host)) list.push(host);
      if (list.length >= TRUSTED_DOWNLOAD_DOMAINS_MAX) break;
    }
    out.trustedDomains = list;                             // an emptied list stays empty (user's choice)
  }
  const c = (raw.warningColor && typeof raw.warningColor === "object") ? raw.warningColor : {};
  for (const ch of RGB_CHANNELS) out.warningColor[ch] = clampInt(c[ch], 0, RGB_CHANNEL_MAX, d.warningColor[ch]);
  out.warningTitle         = typeof raw.warningTitle === "string" ? raw.warningTitle.trim().slice(0, DOWNLOAD_WARNING_TITLE_MAX) : d.warningTitle;
  out.vtKeyPromptDismissed = bool(raw.vtKeyPromptDismissed, d.vtKeyPromptDismissed);
  out.trustAppStores       = bool(raw.trustAppStores, d.trustAppStores);   // 5.1.3
  return out;
}

// ── Show Matrix overrides (pure) ─────────────────────────────────────────────
const MATRIX_SCOPES  = Object.freeze(Object.values(MATRIX_SCOPE));
const MATRIX_ACTIONS = new Set(Object.values(MATRIX_ACTION));

// One stored entry → { script?, frame? } with known actions only ({} when nothing valid).
function normalizeMatrixEntry(src) {
  const entry = {};
  if (!src || typeof src !== "object") return entry;
  for (const sc of MATRIX_SCOPES) if (MATRIX_ACTIONS.has(src[sc])) entry[sc] = src[sc];
  return entry;
}

// Returns { [MATRIX_SITE_ALL]: { [domain]: entry } } (or {} when empty). Overrides are global only:
// any other key is dropped (older shapes were converted by the schema-2 migration).
// Valid hosts, known scopes/actions only, empty entries dropped, capped at MATRIX_OVERRIDES_CAP.
function normalizeMatrixRules(raw) {
  const domains = (raw && typeof raw === "object" && raw[MATRIX_SITE_ALL] && typeof raw[MATRIX_SITE_ALL] === "object") ? raw[MATRIX_SITE_ALL] : {};
  const out = {};
  let count = 0;
  for (const domain of Object.keys(domains)) {
    if (count >= MATRIX_OVERRIDES_CAP) break;
    if (!isValidHost(domain)) continue;
    const entry = normalizeMatrixEntry(domains[domain]);
    if (!Object.keys(entry).length) continue;
    out[domain] = entry;
    count++;
  }
  return count ? { [MATRIX_SITE_ALL]: out } : {};
}

// ── Schema migrations (C32) ──────────────────────────────────────────────────
const SCHEMA_BEFORE_VERSIONING = 1;          // data without a `schema` field (≤ 4.2.2, backup files)

// schema 1 → 2 (4.2.3): Show Matrix overrides became global-only with Script/Frame scopes. The conversion
// (per-site keys merged into "*", { code, all } → { script, frame }) was removed in 4.5.4 as scheduled
// (its removal was scheduled for 4.5): every user has run 4.2.3+ since. The step stays in the list (schema numbering);
// on older data normalizeState() simply drops the shapes it no longer recognises.
function schema2NoLongerConverted() { /* removed in 4.5.4 — see above */ }

// schema 2 → 3 (4.3.2): the default-off protections that did not exist yet start unticked. Idempotent.
// (Keys listed explicitly — a LATER default-off protection gets its own step, so a user's tick on this
// one is never undone by a future migration.)
const SCHEMA_3_DEFAULT_OFF = Object.freeze([PROTECTION_KEY.BLOCK_RISKY_DOWNLOADS]);
function untickNewDefaultOffV3(r) {
  const dis = (r.disabledProtections && typeof r.disabledProtections === "object") ? { ...r.disabledProtections } : {};
  for (const key of SCHEMA_3_DEFAULT_OFF) dis[key] = true;
  r.disabledProtections = dis;
}

// schema 3 → 4 (4.4.5): locks on a bare shared-hosting suffix can no longer match (registeredDomain()
// now returns the tenant's own domain), so they are removed — the user re-locks the tenant. Idempotent.
function dropSharedSuffixLocksV4(r) {
  const locks = (r.siteLocks && typeof r.siteLocks === "object") ? { ...r.siteLocks } : {};
  for (const suffix of SHARED_HOSTING_SUFFIXES) delete locks[suffix];
  r.siteLocks = locks;
  if (Array.isArray(r.siteLocksOrder)) r.siteLocksOrder = r.siteLocksOrder.filter((h) => !SHARED_HOSTING_SUFFIXES.includes(h));
}

// schema 4 → 5 (4.5.8): a DNS pair the user never changed (still the old default for this region) follows the new
// default; any other pair — including a missing/invalid one, which normalizeState() handles — is left as stored.
// Writes a fresh dns object (the raw copy is shallow). Idempotent: the new pair never equals an old default.
function moveUntouchedDnsDefaultV5(r) {
  const dns = (r.dns && typeof r.dns === "object") ? r.dns : null;
  if (!dns) return;
  const old = legacyDefaultDns();
  if (dns.first === old.first && dns.second === old.second) r.dns = { ...dns, ...defaultDns() };
}

// THE ordered migration list: { to: schema reached, since: extension version, run(rawCopy) }.
export const STATE_MIGRATIONS = Object.freeze([
  Object.freeze({ to: 2, since: "4.2.3", run: schema2NoLongerConverted }),
  Object.freeze({ to: 3, since: "4.3.2", run: untickNewDefaultOffV3 }),
  Object.freeze({ to: 4, since: "4.4.5", run: dropSharedSuffixLocksV4 }),
  Object.freeze({ to: 5, since: "4.5.8", run: moveUntouchedDnsDefaultV5 })
]);

// Returns a converted shallow copy of `raw` (never mutates the caller's object).
function migrateRaw(raw) {
  const r = (raw && typeof raw === "object") ? { ...raw } : {};
  const from = Number.isInteger(r.schema) ? r.schema : SCHEMA_BEFORE_VERSIONING;
  for (const m of STATE_MIGRATIONS) if (m.to > from) m.run(r);
  return r;
}

// ── In-memory snapshot (4.5.4, perf P3) ──────────────────────────────────────
// Every event used to read and normalize the whole state from chrome.storage (4× per navigation). One
// normalized snapshot is kept instead:
//   filled    by the first loadState() after a service-worker start (storage read + normalize, once)
//   replaced  by saveState() — the snapshot then equals what was just stored
//   dropped   by chrome.storage.onChanged for STORAGE_KEY_STATE (any writer: another context, DevTools,
//             tests) — the next loadState() reads storage again. The listener only DROPS, never applies newValue:
//             its events arrive late, and applying them could put an OLDER own write back between two quick
//             saves (a lost update). (4.6.0: no longer exported — its only outside caller, the 4.4.5 lock
//             conversion, was removed.)
//   released  with the service worker; nothing else to clean up
// Guards: callers always get their OWN copy (structuredClone) — mutate() changes it in place, the snapshot
// must never follow; a storage read that finishes after a newer save/drop never overwrites it (_snapshotGen).
let _snapshot = null;        // normalized state, or null = not loaded yet / dropped
let _snapshotGen = 0;        // bumped by every replacement or drop
let _listening = false;      // the onChanged listener is attached once, on the first storage access

function setSnapshot(clean) {
  _snapshotGen++;
  _snapshot = structuredClone(clean);
}

function dropSnapshot() {
  _snapshotGen++;
  _snapshot = null;
}

function onStorageChanged(changes, area) {
  if (area === STORAGE_AREA_LOCAL && changes[STORAGE_KEY_STATE]) dropSnapshot();
}

// Not at import: pure users (the tools' unit tests) import this module without chrome.storage.
function listenForChanges() {
  if (_listening) return;
  _listening = true;
  chrome.storage.onChanged.addListener(onStorageChanged);
}

// ── Storage access ───────────────────────────────────────────────────────────
export async function loadState() {
  listenForChanges();
  if (_snapshot) return structuredClone(_snapshot);
  const gen = _snapshotGen;
  try {
    const stored = await chrome.storage.local.get(STORAGE_KEY_STATE);
    const clean = normalizeState(stored[STORAGE_KEY_STATE]);
    if (gen === _snapshotGen) setSnapshot(clean);            // no newer write arrived meanwhile
    return clean;
  } catch (e) {
    console.error(LOG_PREFIX, "loadState failed — using defaults:", e);
    return defaultState();                                   // never cached: the next call retries storage
  }
}

export async function saveState(state) {
  listenForChanges();
  const clean = normalizeState(state);
  await chrome.storage.local.set({ [STORAGE_KEY_STATE]: clean });
  setSnapshot(clean);
  return clean;
}

// ── Guard: serialize read-modify-write cycles ────────────────────────────────
// Each caller's fn(state) runs only after the previous one has finished
// (resolved OR rejected), so two quick popup clicks can never both read the
// same old state and overwrite each other. The chain is released after every
// step — a failure never blocks later callers.
let _chain = Promise.resolve();
export function withStateLock(fn) {
  const run = _chain.then(() => fn());
  _chain = run.then(() => undefined, () => undefined);
  return run;
}
