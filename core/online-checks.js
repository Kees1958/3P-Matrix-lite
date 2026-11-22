// ── core/online-checks.js ─────────────────────────────────────────────────────
// Stage 2 — ONLINE checks, run only for sites stage 1 already found suspicious.
// Only the registered domain / hostname leaves the machine.
//
// Public interface:
//   evaluateSite(local, dnsSettings) — Promise<full result>
//       local       = core/site-scorer.js scoreLocal() result (must be non-null)
//       dnsSettings = state.dns { first, second }
//     → { site, host, score, severity, signals[], checks: { rdap, dns: [] } }
//   clearScoreCache()                — release the in-memory cache
//
// Guards:
//   - every network call has a hard timeout (AbortController) and can only fail
//     to "unavailable" — an unreachable check is NEVER reported as safe
//   - results are cached per registered domain (cap SCORE_CACHE_CAP, TTL
//     SCORE_CACHE_TTL_MS, oldest evicted first)
// ─────────────────────────────────────────────────────────────────────────────

import {
  SCORE, RDAP_URL, RDAP_TIMEOUT_MS, RDAP_YOUNG_DAYS, RDAP_RECENT_DAYS, DNS_TIMEOUT_MS,
  DNS_PROVIDER, DNS_NONE, DNS_BLOCK_STYLE, SCORE_CACHE_CAP, SCORE_CACHE_TTL_MS, LOG_PREFIX
} from "../data/constants.js";
import { combine, severityOf } from "./site-scorer.js";
import { ACTIVE_THREAT_SIGNAL_SOURCE } from "../data/active-threat-hosts.js";
import { isIpHost } from "../util/domain.js";
// Domain-age skip rule (platform subdomain / ccTLD without RDAP): DownloadSentinel's own module since 4.3.4
// (DS 3.3.0 util/DomainAge.js — ported from 3P Matrix 4.3.0; one rule for sites and downloads).
import { domainAgeNotApplicable } from "../lib/downloadsentinel/util/DomainAge.js";

// NOT_APPLICABLE (4.3.0): the domain age cannot exist for this site (DomainAge.js) — skipped, no score.
// NO_DATE (4.3.4): RDAP answered but publishes no registration date — scored SCORE.RDAP_NO_DATE (−10).
export const CHECK_STATUS = Object.freeze({ BLOCKED: "blocked", ALLOWED: "allowed", UNAVAILABLE: "unavailable", SKIPPED: "skipped", NOT_APPLICABLE: "not-applicable", NO_DATE: "no-date" });
const DAY_MS = 86400000;

// ── Fetch with a hard timeout ────────────────────────────────────────────────
async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal, credentials: "omit", cache: "no-store" });
  } finally {
    clearTimeout(timer);                                // release the timer on every path
  }
}

// ── RDAP domain age ──────────────────────────────────────────────────────────
async function checkRdap(site) {
  if (!site || isIpHost(site)) return { status: CHECK_STATUS.SKIPPED };
  const na = domainAgeNotApplicable(site);                 // platform subdomain / ccTLD without RDAP: no call
  if (na) return { status: CHECK_STATUS.NOT_APPLICABLE, reason: na.text };
  try {
    const res = await fetchWithTimeout(RDAP_URL + encodeURIComponent(site), { headers: { Accept: "application/rdap+json" } }, RDAP_TIMEOUT_MS);
    if (!res.ok) return { status: CHECK_STATUS.UNAVAILABLE, reason: `HTTP ${res.status}` };
    const data = await res.json();
    const ev = Array.isArray(data.events) && data.events.find((e) => e.eventAction === "registration" || e.eventAction === "registered");
    const t = ev && Date.parse(ev.eventDate);
    if (!t) return { status: CHECK_STATUS.NO_DATE, reason: "no registration date published" };
    return { status: CHECK_STATUS.ALLOWED, ageDays: Math.max(0, Math.floor((Date.now() - t) / DAY_MS)) };
  } catch (e) {
    return { status: CHECK_STATUS.UNAVAILABLE, reason: e && e.name === "AbortError" ? "timeout" : "network error" };
  }
}

// ── DNS-over-HTTPS (RFC 8484 wire format) ────────────────────────────────────
// RFC 1035 wire-format layout (every offset/length the parser uses, in one place).
const DNS = Object.freeze({
  TYPE_A: 1, TYPE_CNAME: 5, TYPE_SOA: 6, TYPE_AAAA: 28, CLASS_IN: 1, RCODE_NXDOMAIN: 3,
  HEADER: 12,                 // header length
  FLAGS_OFFSET: 2, RCODE_MASK: 0x0f,
  QDCOUNT_OFFSET: 4, ANCOUNT_OFFSET: 6, NSCOUNT_OFFSET: 8,
  QTYPE_QCLASS_LEN: 4,        // after a question name
  RR_FIXED_LEN: 10,           // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) after an answer name
  RR_RDLENGTH_OFFSET: 8,      // within the fixed part
  PTR_LEN: 2,                 // compression pointer length
  A_LEN: 4, AAAA_LEN: 16,     // address RDATA lengths
  MAX_LABEL: 63, MAX_NAME: 255, PTR_FLAG: 0xC0, PTR_OFFSET_MASK: 0x3F, BITS_PER_BYTE: 8, MAX_HOPS: 20
});
const LABEL_SEPARATOR = ".";      // between labels of a decoded name
const IPV4_SEPARATOR = ".";
const ZERO_IPV4 = "0.0.0.0";      // "blocked" answer of zero-ip resolvers
const ZERO_IPV6 = "::";
const NONZERO_IPV6 = "ipv6";      // any non-zero IPv6 answer (only "is it ::" matters here)

function encodeQuery(host) {
  const bytes = [0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];   // id 0, RD, 1 question
  for (const label of host.split(".").filter(Boolean)) {
    const b = new TextEncoder().encode(label);
    if (!b.length || b.length > DNS.MAX_LABEL) return null;
    bytes.push(b.length, ...b);
  }
  bytes.push(0, 0, DNS.TYPE_A, 0, DNS.CLASS_IN);
  if (bytes.length - DNS.HEADER - DNS.QTYPE_QCLASS_LEN > DNS.MAX_NAME) return null;
  let bin = "";
  for (const x of bytes) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Skips a (possibly compressed) name; returns the offset after it, or -1.
function skipName(view, off) {
  for (let hops = 0; hops < DNS.MAX_HOPS && off < view.byteLength; hops++) {
    const len = view.getUint8(off);
    if (len === 0) return off + 1;
    if ((len & DNS.PTR_FLAG) === DNS.PTR_FLAG) return off + DNS.PTR_LEN;
    off += 1 + len;
  }
  return -1;
}

// 4.3.7 — decodes a (possibly compressed) name to lower case, no trailing dot; null on any malformed
// input (pointer loop, label too long, runs past the end). Needed for the authority SOA's MNAME (RPZ_SOA).
function readName(view, start) {
  const labels = [];
  let off = start;
  for (let hops = 0; hops <= DNS.MAX_HOPS; ) {
    if (off >= view.byteLength) return null;
    const len = view.getUint8(off);
    if ((len & DNS.PTR_FLAG) === DNS.PTR_FLAG) {
      if (off + 1 >= view.byteLength) return null;
      off = ((len & DNS.PTR_OFFSET_MASK) << DNS.BITS_PER_BYTE) | view.getUint8(off + 1);
      hops++;
      continue;
    }
    if (len === 0) return labels.join(LABEL_SEPARATOR).toLowerCase();
    if (len > DNS.MAX_LABEL || off + 1 + len > view.byteLength) return null;
    labels.push(new TextDecoder().decode(new Uint8Array(view.buffer, view.byteOffset + off + 1, len)));
    off += 1 + len;
  }
  return null;
}

// 4.3.7 — authority section: MNAMEs of its SOA records. Supplementary data: a malformed section ends the scan
// and keeps what was read (never discards the answers; an unreadable section can never mean "blocked").
function readAuthoritySoaMnames(view, start, count) {
  const mnames = [];
  let off = start;
  for (let i = 0; i < count && off < view.byteLength; i++) {
    off = skipName(view, off); if (off < 0 || off + DNS.RR_FIXED_LEN > view.byteLength) break;
    const type = view.getUint16(off), rdlen = view.getUint16(off + DNS.RR_RDLENGTH_OFFSET);
    off += DNS.RR_FIXED_LEN;
    if (off + rdlen > view.byteLength) break;
    if (type === DNS.TYPE_SOA) { const m = readName(view, off); if (m) mnames.push(m); }
    off += rdlen;
  }
  return mnames;
}

function parseResponse(buf) {
  const view = new DataView(buf);
  if (view.byteLength < DNS.HEADER) return null;
  const rcode = view.getUint16(DNS.FLAGS_OFFSET) & DNS.RCODE_MASK;
  const qd = view.getUint16(DNS.QDCOUNT_OFFSET), an = view.getUint16(DNS.ANCOUNT_OFFSET), ns = view.getUint16(DNS.NSCOUNT_OFFSET);
  let off = DNS.HEADER;
  for (let i = 0; i < qd; i++) { off = skipName(view, off); if (off < 0) return null; off += DNS.QTYPE_QCLASS_LEN; }
  const addrs = [];
  let cnames = 0;
  for (let i = 0; i < an && off < view.byteLength; i++) {
    off = skipName(view, off); if (off < 0 || off + DNS.RR_FIXED_LEN > view.byteLength) return null;
    const type = view.getUint16(off), rdlen = view.getUint16(off + DNS.RR_RDLENGTH_OFFSET);
    off += DNS.RR_FIXED_LEN;
    if (off + rdlen > view.byteLength) return null;
    if (type === DNS.TYPE_A && rdlen === DNS.A_LEN) {
      const octets = [];
      for (let k = 0; k < DNS.A_LEN; k++) octets.push(view.getUint8(off + k));
      addrs.push(octets.join(IPV4_SEPARATOR));
    }
    if (type === DNS.TYPE_CNAME) cnames++;               // 4.3.4: an alias counts as an answer (DS DnsThreatProtection)
    if (type === DNS.TYPE_AAAA && rdlen === DNS.AAAA_LEN) {
      let zero = true; for (let k = 0; k < DNS.AAAA_LEN; k++) if (view.getUint8(off + k)) zero = false;
      addrs.push(zero ? ZERO_IPV6 : NONZERO_IPV6);
    }
    off += rdlen;
  }
  return { rcode, an, ns, addrs, cnames, soaMnames: readAuthoritySoaMnames(view, off, ns) };
}

// Guards: a provider without the list/suffix (config slip) can never report "blocked" — fail open to the
// ordinary answer handling, never a false "malicious".
function isBlockPageAnswer(provider, addr) {
  const ips = Array.isArray(provider.blockPageIps) ? provider.blockPageIps : [];
  return addr === ZERO_IPV4 || addr === ZERO_IPV6 || ips.includes(addr);
}
function hasRpzSoa(provider, mnames) {
  const suffix = typeof provider.rpzSoaMnameSuffix === "string" ? provider.rpzSoaMnameSuffix.toLowerCase() : "";
  if (!suffix) return false;
  return mnames.some((m) => m === suffix || m.endsWith(LABEL_SEPARATOR + suffix));
}

async function checkDns(providerId, host) {
  const provider = Object.values(DNS_PROVIDER).find((p) => p.id === providerId);
  if (!provider || providerId === DNS_NONE) return { status: CHECK_STATUS.SKIPPED };
  const base = { provider: provider.id, label: provider.label };
  if (isIpHost(host)) return { ...base, status: CHECK_STATUS.SKIPPED };
  const q = encodeQuery(host);
  if (!q) return { ...base, status: CHECK_STATUS.UNAVAILABLE, reason: "invalid name" };
  try {
    const res = await fetchWithTimeout(`${provider.url}?dns=${q}`, { headers: { Accept: "application/dns-message" } }, DNS_TIMEOUT_MS);
    if (!res.ok) return { ...base, status: CHECK_STATUS.UNAVAILABLE, reason: `HTTP ${res.status}` };
    const msg = parseResponse(await res.arrayBuffer());
    if (!msg) return { ...base, status: CHECK_STATUS.UNAVAILABLE, reason: "unreadable answer" };
    if (provider.blockStyle === DNS_BLOCK_STYLE.NXDOMAIN_NO_AUTHORITY && msg.rcode === DNS.RCODE_NXDOMAIN) {
      return { ...base, status: msg.ns === 0 ? CHECK_STATUS.BLOCKED : CHECK_STATUS.UNAVAILABLE, reason: msg.ns === 0 ? "" : "domain does not exist" };
    }
    if (provider.blockStyle === DNS_BLOCK_STYLE.ZERO_IP && msg.addrs.some((a) => a === ZERO_IPV4 || a === ZERO_IPV6)) {
      return { ...base, status: CHECK_STATUS.BLOCKED };
    }
    // 4.3.7 — DNS4EU: its block-page address (DS provider.blockPageIps), or 0.0.0.0 / ::.
    if (provider.blockStyle === DNS_BLOCK_STYLE.BLOCKPAGE_IP && msg.addrs.some((a) => isBlockPageAnswer(provider, a))) {
      return { ...base, status: CHECK_STATUS.BLOCKED };
    }
    // 4.3.7 — CleanBrowsing: no answer + a policy-zone SOA (MNAME ends in provider.rpzSoaMnameSuffix).
    // A real non-existent name carries the registry's SOA instead → "domain does not exist" below.
    if (provider.blockStyle === DNS_BLOCK_STYLE.RPZ_SOA && !msg.addrs.length && !msg.cnames && hasRpzSoa(provider, msg.soaMnames)) {
      return { ...base, status: CHECK_STATUS.BLOCKED };
    }
    if (msg.rcode === DNS.RCODE_NXDOMAIN && !msg.addrs.length && !msg.cnames) {
      return { ...base, status: CHECK_STATUS.UNAVAILABLE, reason: "domain does not exist" };
    }
    // 4.3.4 (DownloadSentinel parity, item 21): no A/AAAA/CNAME record at all is "no answer", never "clean".
    if (!msg.addrs.length && !msg.cnames) return { ...base, status: CHECK_STATUS.UNAVAILABLE, reason: msg.an ? "no A/AAAA/CNAME records" : "no DNS records returned" };
    return { ...base, status: CHECK_STATUS.ALLOWED };
  } catch (e) {
    return { ...base, status: CHECK_STATUS.UNAVAILABLE, reason: e && e.name === "AbortError" ? "timeout" : "network error — your own DNS may block it" };
  }
}

// ── Cache (guarded: capped, TTL, oldest evicted) ─────────────────────────────
const _cache = new Map();   // site → { at, result }
function cacheGet(site) {
  const hit = _cache.get(site);
  if (!hit) return null;
  if (Date.now() - hit.at > SCORE_CACHE_TTL_MS) { _cache.delete(site); return null; }
  return hit.result;
}
function cachePut(site, result) {
  _cache.delete(site);
  _cache.set(site, { at: Date.now(), result });
  while (_cache.size > SCORE_CACHE_CAP) _cache.delete(_cache.keys().next().value);
}
export function clearScoreCache() { _cache.clear(); }

// ── Public ───────────────────────────────────────────────────────────────────
export async function evaluateSite(local, dnsSettings) {
  const key = `${local.host}|${dnsSettings.first}|${dnsSettings.second}`;
  const cached = cacheGet(key);
  if (cached) return cached;

  const [rdap, dns1, dns2] = await Promise.all([
    checkRdap(local.site),
    checkDns(dnsSettings.first, local.host),
    checkDns(dnsSettings.second, local.host)
  ]);

  const entries = local.entries.slice();
  const signals = [];
  if (rdap.status === CHECK_STATUS.ALLOWED) {
    const age = rdap.ageDays;
    const ageScore = age < RDAP_YOUNG_DAYS ? SCORE.RDAP_YOUNG : age < RDAP_RECENT_DAYS ? SCORE.RDAP_RECENT : 0;
    if (ageScore < 0) entries.push({ score: ageScore, label: `Domain registered ${age} days ago (RDAP)`, source: "RDAP" });
    signals.push(`Domain registered ${age} days ago (RDAP)`);
  } else if (rdap.status === CHECK_STATUS.UNAVAILABLE) {
    signals.push(`Domain age unavailable (${rdap.reason})`);
  } else if (rdap.status === CHECK_STATUS.NO_DATE) {
    entries.push({ score: SCORE.RDAP_NO_DATE, label: "Domain age not published by the registry (RDAP)", source: "RDAP" });
    signals.push("Domain age not published by the registry — treated as recent (RDAP)");
  } else if (rdap.status === CHECK_STATUS.NOT_APPLICABLE) {
    signals.push(`Domain age ${rdap.reason}`);
  }

  let { score } = combine(entries);
  [[dns1, "first"], [dns2, "second"]].forEach(([r, which]) => {
    if (r.status === CHECK_STATUS.BLOCKED) { score = SCORE.DNS_BLOCKED; signals.push(`Blocked by ${r.label} — ${which} DNS check`); }
    else if (r.status === CHECK_STATUS.ALLOWED) signals.push(`Clean on ${r.label} — ${which} DNS check`);
    else if (r.status === CHECK_STATUS.UNAVAILABLE) signals.push(`${r.label} check unavailable (${r.reason})`);
  });
  // 4.4.9: same floor as core/site-scorer.js scoreLocal() — re-applied here because this
  // function recombines from local.entries via combine() itself, which would otherwise
  // let CombinationScoring's family system (ActiveThreatHost has no family registered
  // there on purpose — see data/active-threat-hosts.js) drop the signal again.
  if (local.entries.some((e) => e.source === ACTIVE_THREAT_SIGNAL_SOURCE)) {
    score = Math.min(score, SCORE.ACTIVE_THREAT_HOST);
  }

  const result = {
    site: local.site, host: local.host, score, severity: severityOf(score),
    signals: [...local.signals, ...signals],
    checks: { rdap, dns: [dns1, dns2] }
  };
  cachePut(key, result);
  if (score !== local.score) console.info(LOG_PREFIX, `online checks moved ${local.host} from ${local.score} to ${score}`);
  return result;
}
