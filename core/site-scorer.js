// ── core/site-scorer.js ───────────────────────────────────────────────────────
// Stage 1 — LOCAL first-party site scoring (no network). Reuses
// DownloadSentinel's heuristics modules unchanged (3.3.1 since 4.3.7, 3.3.0 since 4.3.4; gov suffixes exempt from look-alike) (4.3.0: the two former 3P Matrix patches —
// SketchyUrlCheck subdomain count, CombinationScoring port family — are upstream in DS 3.2.0, and
// the three imitation checks are one: LookalikeDomainCheck, project doc DESIGN_lookalike_check.md).
//
// Public interface:
//   scoreLocal(url)          — { site, host, score, severity, signals[], entries[] } or null
//                              (null = not scorable: non-http(s), private/local host)
//   combine(entries)         — { score, severity } via DownloadSentinel CombinationScoring
//   severityOf(score)        — SEVERITY.*
//
// entries[] = DownloadSentinel-style { score, label, source } items (fed to
// CombinationScoring); signals[] = the same labels, worst first, for the UI.
// Measured cost: ~0.4 ms per domain (brand Levenshtein dominates).
// Look-alike hit kinds (LookalikeDomainCheck.check().type) → score; brand beats site (DS SCORING_CONFIG).
// 4.5.6 (user decision): DownloadSentinel's SuspiciousDomains list ("misused for malware delivery": discord.com,
// t.me, bit.ly, drive.google.com, duckdns.org …) scores a page visit ONLY for a host someone created on such a
// platform (login.duckdns.org, microsoft-support.github.io). The listed site itself (or its www.) is no risk to
// visit — downloading from it is, and that stays fully scored by the download check (warnRiskyDownloads).
// ─────────────────────────────────────────────────────────────────────────────

import { SCORE, SEVERITY, STANDARD_PORTS, SITE_DIALOG_FROM } from "../data/constants.js";
import { SPAM_TLDS, SPAM_TLD_EXCEPTIONS } from "../data/spam-tlds.js";
import { matchActiveThreatDelivery, activeThreatLabel, ACTIVE_THREAT_SIGNAL_SOURCE, ACTIVE_THREAT_NOTE_SIGNAL_SOURCE, PLATFORM_SIGNAL_SOURCE } from "../data/active-threat-hosts.js";
import { parseHttpUrl, registeredDomain, tldOf, isIpHost, isPrivateHost, isInDomainList } from "../util/domain.js";
import { SketchyUrlCheck } from "../lib/downloadsentinel/protection/SketchyUrlCheck.js";
import { LookalikeDomainCheck } from "../lib/downloadsentinel/protection/LookalikeDomainCheck.js";
import { CombinationScoring } from "../lib/downloadsentinel/protection/CombinationScoring.js";
import { HostList } from "../lib/downloadsentinel/util/HostList.js";
import { SuspiciousTlds } from "../lib/downloadsentinel/util/SuspiciousTlds.js";
import { SuspiciousDomains } from "../lib/downloadsentinel/util/SuspiciousDomains.js";
import { RiskyHostingSites } from "../lib/downloadsentinel/util/RiskyHostingSites.js";
import { DeliveryPatterns } from "../lib/downloadsentinel/util/DeliveryPatterns.js";   // 4.4.1: open platforms + brand on platform
import { WarnPolicy } from "../lib/downloadsentinel/protection/WarnPolicy.js";          // 4.4.1: dialog yes/no (thresholds + exceptions)

const WWW_PREFIX = "www.";            // 4.5.6: "www.discord.com" is the listed site itself, not a user-made host

const SPAM_TLD_SET = new Set(SPAM_TLDS);
const SPAM_EXCEPTION_SET = new Set(SPAM_TLD_EXCEPTIONS);
const SIGNAL_SUFFIX_RE = /\s*\(\+\d+\).*$/;          // strips DownloadSentinel's "(+15)" score suffix

const RISK_SCALE_MAX = 100;                          // DownloadSentinel risk scores run 0 … 100
const LOOKALIKE_KIND = Object.freeze({ BRAND: "brand", SITE: "site" });   // LookalikeDomainCheck result types

// A 0–100 DownloadSentinel risk mapped onto a negative base score, never below SCORE.FLOOR.
function scaled(risk, base) {
  return Math.max(SCORE.FLOOR, Math.round((risk / RISK_SCALE_MAX) * base));
}

export function severityOf(score) {
  if (score < SCORE.PHISHING_BELOW) return SEVERITY.PHISHING;
  if (score <= SCORE.SUSPECT_AT) return SEVERITY.SUSPECT;
  return SEVERITY.NONE;
}

// 4.4.0 — a platform hit (RiskyHosting, or a DomainList hit on a developer-hosting platform: entry.platform)
// that is the only real signal counts half — "anyone can publish here" says little about THIS site on its own.
// Same test as DownloadSentinel's RiskyHosting solo rule: no other entry at or below the stacking floor.
// Runs here because combine() is the one funnel for both stages (local and online-checks.js), so a later
// signal (young domain, DNS block) always sees the full platform score. Entries are copied, never mutated.
function withPlatformSoloRule(entries) {
  const platform = entries.filter((e) => e.platform && e.score < 0);
  if (platform.length === 0) return entries;
  const corroborated = entries.some((e) => !e.platform && e.score <= CombinationScoring.CONFIG.STACK_MIN_SIGNAL);
  if (corroborated) return entries;
  return entries.map((e) => (e.platform && e.score < 0 ? { ...e, score: Math.round(e.score / SCORE.PLATFORM_SOLO_DIVISOR) } : e));
}

// 5.0.4 (DS 3.5.6) — a site visit has no VirusTotal answer: heuristics are the only indicator, so small signals add
// up on a dubious source (CombinationScoring.smallSignalsStack) — kept in sync with the download check.
const SITE_HEURISTICS_ONLY = Object.freeze({ heuristicsOnly: true });
export function combine(entries) {
  const res = CombinationScoring.combineHostResults(withPlatformSoloRule(entries), SITE_HEURISTICS_ONLY);
  const score = Math.max(SCORE.FLOOR, res.score || 0);
  return { score, severity: severityOf(score) };
}

function tldEntry(host, site, tld) {
  if (SPAM_EXCEPTION_SET.has(site) || isInDomainList(host, SPAM_TLD_EXCEPTIONS)) return null;
  const dsHit = SuspiciousTlds.lookup(tld);
  const risk = Math.max(dsHit ? dsHit.score : 0, SPAM_TLD_SET.has(tld) ? SCORE.SPAM_TLD_RISK : 0);
  if (!risk) return null;
  return { score: scaled(risk, SCORE.TLD_BASE), label: `TLD .${tld} is on the abused-TLD list`, source: "TldList" };
}

// 4.4.0 — a brand name in the subdomain of an open platform (paypal-login.vercel.app): the platform rule above
// would otherwise halve the only signal and let it through. 4.4.1: the rule itself is the shared library's
// DeliveryPatterns.brandOnPlatform() (downloads use it too); source "PlatformBrand" (URL_SHAPE family — it
// stacks with the platform hit) is an IMPERSONATION exception in WarnPolicy.
function platformBrandEntry(host, platformDomain) {
  const hit = DeliveryPatterns.brandOnPlatform(host, platformDomain);
  if (!hit) return null;
  return { score: SCORE.LOOKALIKE_SITE, source: "PlatformBrand",
           label: `Uses the brand name "${hit.keyword}" on a platform where anyone can publish (${platformDomain})` };
}

// 4.4.1 — does this local result open the dialog at the site's protection level? (SITE_DIALOG_FROM + WarnPolicy
// site exceptions). A level without a threshold (level 1) never opens it.
export function dialogDecision(local, level) {
  const threshold = SITE_DIALOG_FROM[level];
  if (!local || threshold === undefined) return { warn: false, threshold: null, exceptions: [] };
  return WarnPolicy.siteDecision({ score: local.score, threshold, entries: local.entries });
}

export function scoreLocal(url) {
  const p = parseHttpUrl(url);
  if (!p || isPrivateHost(p.host)) return null;
  const host = p.host;
  const ip = isIpHost(host);
  const site = registeredDomain(host);
  let entries = [];
  let activeThreat = false;        // 4.4.9: see the score floor applied below, after combine()
  let activeThreatHit = null;      // 4.5.0: set inside the else-branch below, read again after the loop

  if (ip) {
    entries.push({ score: SCORE.IP_HOST, label: "Site is a bare IP address, not a domain name", source: "IpAddressCheck" });
  } else {
    // Name-based checks (meaningless for an IP literal).
    const sketchy = SketchyUrlCheck.check(`${p.protocol}//${host}/`);   // host only — no path checks for pages
    if (sketchy.score > 0) {
      const top = (sketchy.signals[0] || "Suspicious name pattern").replace(SIGNAL_SUFFIX_RE, "").trim();
      entries.push({ score: scaled(sketchy.score, SCORE.SKETCHY_URL_BASE), label: top, source: "SketchyUrl" });
      for (const sig of sketchy.signals.slice(1)) {
        entries.push({ score: 0, label: sig.replace(SIGNAL_SUFFIX_RE, "").trim(), source: "SketchyUrl" });
      }
    }
    const hostHit = HostList.lookup(host);
    if (hostHit) entries.push({ score: scaled(hostHit.score, SCORE.HOST_LIST_BASE), label: `Free-hosting / dynamic-DNS domain (${hostHit.matchedDomain})`, source: "HostList" });
    const domHit = SuspiciousDomains.lookup(host);
    const domHitIsSiteItself = !!domHit && (host === domHit.matchedDomain || host === WWW_PREFIX + domHit.matchedDomain);
    if (domHit && !domHitIsSiteItself) {
      const platform = DeliveryPatterns.isOpenPlatform(domHit.matchedDomain);
      entries.push({ score: scaled(domHit.score, SCORE.DOMAIN_LIST_BASE), platform, source: "DomainList",
                     label: platform ? `Hosted on a platform where anyone can publish, sometimes misused (${domHit.matchedDomain})`
                                     : `Domain has been misused in the past (${domHit.matchedDomain})` });
    }
    const risky = RiskyHostingSites.lookup(host);
    // 4.5.0: data/active-threat-hosts.js — a host under active, observed abuse right now,
    // AND the URL looks like that campaign's actual delivery (archive/executable path,
    // plus a path-shape gate for github.com/gitlab.com, which also serve their entire
    // normal browsing UI from the same host). Scored here for the signals list; the
    // actual floor on the final score is applied below (after combine()), not through
    // CombinationScoring's family system — see that file's header for why.
    activeThreatHit = matchActiveThreatDelivery(host, p.pathname);
    activeThreat = !!activeThreatHit;
    // 4.5.8: one fact, one signal — with an active-threat hit the platform row is left out (both describe this host;
    // see PLATFORM_SIGNAL_SOURCE). `risky` still feeds the brand-on-platform check below.
    if (risky && !activeThreat) entries.push({ score: risky.score, platform: true, label: `Hosted on a platform where anyone can publish (${risky.host})`, source: PLATFORM_SIGNAL_SOURCE });
    if (activeThreatHit) {
      entries.push({ score: SCORE.ACTIVE_THREAT_HOST, label: activeThreatLabel(host, p.pathname), source: ACTIVE_THREAT_SIGNAL_SOURCE });
    }
    const platformDomain = (domHit && DeliveryPatterns.isOpenPlatform(domHit.matchedDomain)) ? domHit.matchedDomain : (risky ? risky.host : null);
    const brandOnPlatform = platformDomain ? platformBrandEntry(host, platformDomain) : null;
    if (brandOnPlatform) entries.push(brandOnPlatform);
    const tld = tldEntry(host, site, tldOf(host));
    if (tld) entries.push(tld);
    const lookalike = LookalikeDomainCheck.check(host);
    if (lookalike) {
      const brand = lookalike.type === LOOKALIKE_KIND.BRAND;
      entries.push({
        score: brand ? SCORE.LOOKALIKE_BRAND : SCORE.LOOKALIKE_SITE,
        label: brand ? `Looks like the brand site ${lookalike.resembles}` : `Looks like the popular site ${lookalike.resembles}`,
        source: "LookalikeDomain"
      });
    }
  }

  if (p.port && !STANDARD_PORTS.includes(Number(p.port))) {
    entries.push({ score: SCORE.NON_STANDARD_PORT, label: `Unusual port :${p.port}`, source: "NonStandardPort" });
  }
  if (p.protocol === "http:") {
    entries.push({ score: SCORE.PLAIN_HTTP, label: "Not encrypted (plain HTTP)", source: "ProtocolCheck" });
  }

  // 4.5.0: a shape's disclaimer (activeThreatHit.note — see data/active-threat-hosts.js,
  // currently only the "Download ZIP" shape) is added as its OWN signal line — a score-0
  // entry, which sorts after every real (negative-score) signal below — only when the
  // ActiveThreatHost entry is the SOLE negative signal on this site. The note exists
  // precisely because a real person can trigger that one shape themselves; if something
  // else here also looks wrong, that corroboration is exactly what the note says to watch
  // for, so this stays off the list at that point instead of undercutting a real warning.
  if (activeThreatHit?.note && !entries.some((e) => e.source !== ACTIVE_THREAT_SIGNAL_SOURCE && e.score < 0)) {
    entries = [...entries, { score: 0, label: activeThreatHit.note, source: ACTIVE_THREAT_NOTE_SIGNAL_SOURCE }];
  }

  const scoring = entries.filter((e) => e.score < 0);
  const combined = combine(scoring);
  // 4.4.9: floor, not a CombinationScoring family entry (see the ActiveThreatHost push
  // above) — guarantees this signal governs the final score on its own, independent of
  // whatever else combine() did or didn't do with it.
  const score = activeThreat ? Math.min(combined.score, SCORE.ACTIVE_THREAT_HOST) : combined.score;
  const severity = severityOf(score);
  const signals = [...entries].sort((a, b) => a.score - b.score).map((e) => e.label);
  return { site, host, score, severity, signals, entries: scoring };
}
