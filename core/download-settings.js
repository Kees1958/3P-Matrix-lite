// ── core/download-settings.js ─────────────────────────────────────────────────
// Pure policy for warnRiskyDownloads "Warn when a downloaded file looks risky" (4.3.0): which downloads
// are checked, and the settings view DownloadSentinel's vendored modules expect. No Chrome calls.
//
// Public interface:
//   dsSettingsView(state)               — state → DownloadSentinel's settings object shape (the one
//                                         its util/Settings.js reads from storage; passed to BrowserProtection as its settings). Read-only.
//   vtKeyIsSet(state)                   — a valid VirusTotal API key is stored
//   downloadSiteHost(item)              — the "site" a download belongs to: the page it came from
//                                         (DownloadItem.referrer), else the download host ("" if none)
//   isDownloadCheckActive(state, item)  — warnRiskyDownloads active at that site's effective level, and the
//                                         site not on the built-in whitelist (4.3.3)
//   isPageMadeDownload(url)             — blob:/data: download (no "hidden extension" signal for those)
//   isTrustedDownload(state, item)      — DS DownloadTrust.isTrustedDomain over trustedDownloadDomains():
//                                         the file's host, OR (levels DOWNLOAD_PAGE_TRUST_LEVELS, 4.5.5) the page it
//                                         came from
//   trustedDownloadDomains(state)       — app stores + the user's domains
//   shouldOfferVtKey(state)             — the startup VirusTotal-key nudge should open
//   downloadBlockReason(state, item)    — blockRiskyDownloads (4.3.2): null, or why this download's site blocks
//                                         risky downloads: { kind: DOWNLOAD_BLOCK_REASON.*, level, tld }
//                                         (the caller still checks the file type)
//   applyDownloadSettings(state, patch) — Options "Save": set the editable fields (mutates state;
//                                         throws on a field that is not editable or invalid input)
//   setVtKey(state, key)                — Options VirusTotal key: "" clears it (and VT off), a valid key
//                                         sets it (and VT on) — DownloadSentinel's own rule; else throws
//   dismissVtKeyPrompt(state)           — "don't show this again"
//
// Two independent "trusted" ideas, kept apart on purpose:
//   - the 3P Matrix allow list (sites locked at level 1) is about the PAGE: no protection there, so no
//     download warning for anything that page offers;
//   - DownloadSentinel's trusted download domains are about the FILE HOST (app stores, the user's
//     SharePoint …), checked on every page.
// ─────────────────────────────────────────────────────────────────────────────

import { BUILTIN_TRUSTED_DOWNLOAD_DOMAINS, DOWNLOAD_BLOCK_REASON, DOWNLOAD_BLOCK_EXEMPT_LEVELS, DOWNLOAD_PAGE_TRUST_LEVELS } from "../data/constants.js";
import { BUILTIN_ALL } from "../data/builtin-domains.js";
import { PROTECTION_KEY } from "../data/protections.js";
import { isValidVtKey } from "../data/state-storage.js";
import { effectiveLevel, isProtectionActive, isProtectionEnabled, saferRegionsApply, isHighRiskSite } from "./policy.js";
import { isInDomainList, tldOf } from "../util/domain.js";
import { VtKeyPromptPolicy } from "../lib/downloadsentinel/util/VtKeyPromptPolicy.js";
// 4.3.4: DownloadSentinel 3.3.0's own trust helpers (C21) — host of blob: URLs, referrer fallback (item 27),
// page-made files (item 22). Replaces 3P Matrix's 4.3.3 copies of the same logic.
import { DownloadTrust } from "../lib/downloadsentinel/util/DownloadTrust.js";
import { UrlUtils } from "../lib/downloadsentinel/util/UrlUtils.js";

const DOWNLOAD_KEY = PROTECTION_KEY.WARN_RISKY_DOWNLOADS;
const BLOCK_KEY = PROTECTION_KEY.BLOCK_RISKY_DOWNLOADS;
const BLOCK_REASON = DOWNLOAD_BLOCK_REASON;

export function vtKeyIsSet(state) { return isValidVtKey(state.downloads.vtApiKey); }

export function dsSettingsView(state) {
  const d = state.downloads;
  return {
    extensionEnabled:     isProtectionEnabled(state, DOWNLOAD_KEY),   // per-download level gate: isDownloadCheckActive
    virusTotalEnabled:    d.vtEnabled,
    vtApiKey:             d.vtApiKey,
    isVtApiKeySet:        vtKeyIsSet(state),
    silentWhenInconclusive: d.silentWhenInconclusive,
    autoAllow:            d.autoAllow,
    autoAllowThreshold:   d.autoAllowThreshold,
    fpReductionLevel:     d.fpReductionLevel,
    customDomains:        d.trustedDomains.slice(),
    warningColorR:        d.warningColor.r,
    warningColorG:        d.warningColor.g,
    warningColorB:        d.warningColor.b,
    warningTitle:         d.warningTitle,
    dnsFirst:             state.dns.first,                            // one DNS choice for sites and downloads
    dnsSecond:            state.dns.second,
    vtKeyPromptDismissed: d.vtKeyPromptDismissed
  };
}

// The page a download came from: referrer, else the file's own host (blob:https://x/… → x, via DS UrlUtils).
export function downloadSiteHost(item) {
  if (!item) return "";
  for (const u of [item.referrer, item.finalUrl, item.url]) {      // first one with a web host wins
    const host = u ? UrlUtils.getHostname(u) : null;
    if (host) return host;
  }
  return "";
}

// A file the page generated itself (blob:/data:) — no "extension hidden" signal (DS item 22).
export function isPageMadeDownload(url) { return DownloadTrust.isPageMadeDownload(url); }

// 4.3.3 (user decision): a page on the built-in whitelist is skipped, as by the site warning (11).
export function isDownloadCheckActive(state, item) {
  const host = downloadSiteHost(item);
  if (host && isInDomainList(host, BUILTIN_ALL)) return false;
  const level = host ? effectiveLevel(state, host) : state.level;
  return isProtectionActive(state, DOWNLOAD_KEY, level);
}

// Same "site" as warnRiskyDownloads (the page the download came from). Level 3: only outside safer regions;
// levels 4–5: every site (SAFER_REGIONS_LEVELS decides where the list counts, as for the outside-safer-regions group).
// Exemptions (user decision 2026-10-20) only at DOWNLOAD_BLOCK_EXEMPT_LEVELS (level 3): a page on the built-in
// whitelist, or a file host on the trusted download domains (built-in app stores + the user's list).
// Levels 4–5: no exception at all — only the allow list (a site locked at level 1) is outside its reach.
export function downloadBlockReason(state, item) {
  const host = downloadSiteHost(item);
  const level = host ? effectiveLevel(state, host) : state.level;
  const active = isProtectionActive(state, BLOCK_KEY, level);
  // 4.7.0 — alsoHighRisk: a known high-risk referrer (data/network-data.js HIGH_RISK_HOSTNAMES; a
  // download has no reliable tabId, so only the STATIC half applies here, not a session PHISHING
  // verdict — see data/protections.js' 4.7.0 alsoHighRisk comment) blocks regardless of level,
  // UNLESS the user has unticked the protection entirely (isHighRiskSite has no "enabled" opinion).
  const highRisk = !active && isProtectionEnabled(state, BLOCK_KEY) && isHighRiskSite(state, host);
  if (!active && !highRisk) return null;
  if (DOWNLOAD_BLOCK_EXEMPT_LEVELS.includes(level) &&
      ((host && isInDomainList(host, BUILTIN_ALL)) || isTrustedDownload(state, item))) return null;
  const tld = host ? tldOf(host) : "";
  if (highRisk) return { kind: BLOCK_REASON.HIGH_RISK, level, tld };
  if (!saferRegionsApply(level)) return { kind: BLOCK_REASON.LEVEL, level, tld };
  return state.safeZone.tlds.includes(tld) ? null : { kind: BLOCK_REASON.OUTSIDE_SAFER, level, tld };
}

// The effective trusted-download list: built-in app stores (always) and the user's own domains. DownloadSentinel's
// "Trust AI downloads" category is not offered (4.3.6, user decision) — add an AI site to your own domains instead.
// 5.1.3: the app stores only while "Trust app stores" is ticked; the user's domains are the allow list's Download lines.
export function trustedDownloadDomains(state) {
  const d = state.downloads;
  return [...(d.trustAppStores ? BUILTIN_TRUSTED_DOWNLOAD_DOMAINS : []), ...d.trustedDomains];
}

// Trusted when the file's own host is on the list (DS 3.3.0 rule, item 27: the page only when the file has no
// host — data:, sandboxed blob:null/…). 4.5.5 (real report, SharePoint): at DOWNLOAD_PAGE_TRUST_LEVELS (1–3) the
// page it came from (DownloadItem.referrer) counts too, as Options says — SharePoint and OneDrive serve folder /
// multi-file zips from a regional *.svc.ms host, so a trusted hogeschooltio.sharepoint.com did not cover its own
// downloads. Levels 4–5 never widen trust (user decision). The level is the page's effective level, the same
// "site" warnRiskyDownloads and blockRiskyDownloads use. The DS function is reused for both hosts (C21).
// Consumers: warnRiskyDownloads (download-guard startCheck / lateEntryRecord), blockRiskyDownloads (downloadBlockReason).
export function isTrustedDownload(state, item) {
  if (!item) return false;
  const list = trustedDownloadDomains(state);
  const referrer = item.referrer || null;
  if (DownloadTrust.isTrustedDomain(item.finalUrl || item.url || "", list, referrer)) return true;
  const host = downloadSiteHost(item);
  const level = host ? effectiveLevel(state, host) : state.level;
  return !!referrer && DOWNLOAD_PAGE_TRUST_LEVELS.includes(level) && DownloadTrust.isTrustedDomain(referrer, list);
}

// DownloadSentinel's own rule (VtKeyPromptPolicy — reused, C21), with its master switch read as
// "warnRiskyDownloads runs at browser start" (the session level is the startup level then).
export function shouldOfferVtKey(state) {
  const view = { ...dsSettingsView(state), extensionEnabled: isProtectionActive(state, DOWNLOAD_KEY, state.startupLevel) };
  return VtKeyPromptPolicy.shouldShowVtKeyPrompt(view);
}

// ── Mutations (pure — background.js runs them inside mutate(), normalizeState() validates again) ────
// Fields Options may change. vtApiKey is NOT here: it has its own message (setVtKey), so a key can never
// be overwritten by a settings form that does not show it.
const EDITABLE = Object.freeze(["vtEnabled", "silentWhenInconclusive", "autoAllow", "autoAllowThreshold", "fpReductionLevel",
                                "trustAppStores", "warningColor", "warningTitle"]);   // 5.1.3: trusted domains → the allow list

export function applyDownloadSettings(state, patch) {
  if (!patch || typeof patch !== "object") throw new Error("bad download settings");
  const unknown = Object.keys(patch).filter((k) => !EDITABLE.includes(k));
  if (unknown.length) throw new Error(`not editable: ${unknown.join(", ")}`);
  if (patch.trustAppStores !== undefined && typeof patch.trustAppStores !== "boolean") throw new Error("bad app-store choice");
  Object.assign(state.downloads, patch);
}

export function setVtKey(state, key) {
  const k = String(key || "").trim();
  if (!k) { state.downloads.vtApiKey = ""; state.downloads.vtEnabled = false; return; }
  if (!isValidVtKey(k)) throw new Error("invalid key — expected 64 hex characters");
  state.downloads.vtApiKey = k;
  state.downloads.vtEnabled = true;
}

export function dismissVtKeyPrompt(state) { state.downloads.vtKeyPromptDismissed = true; }
