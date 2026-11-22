// ── util/domain.js ────────────────────────────────────────────────────────────
// Pure hostname helpers. ONE registered-domain function for the whole
// extension (locks, scoring, safer regions), backed by DownloadSentinel's Public
// Suffix List module — no second, hand-rolled suffix table.
//
// Public interface:
//   parseHttpUrl(url)          — { url, host, protocol, port, pathname } or null for non-http(s)
//   registeredDomain(host)     — "www.bbc.co.uk" → "bbc.co.uk" (host itself if unknown); 4.4.5: a
//                                shared-hosting suffix (data/constants.js SHARED_HOSTING_SUFFIXES) counts as a
//                                public suffix — "acme-my.sharepoint.com" → "acme-my.sharepoint.com"
//   chromeSite(host)           — the PSL-only registered domain: what Chrome's own "third party" test uses
//                                (so rule replay matches DNR; registeredDomain() is for OUR locks/scoring)
//   tldOf(host)                — last label
//   isIpHost(host)             — IPv4 dotted quad or bracketed/plain IPv6
//   isPrivateHost(host)        — loopback / private / link-local / *.local etc.
//   isInDomainList(host, list) — host equals or is a subdomain of an entry
//   hostMatchPattern(host)     — "*://*.example.com/*" content-script pattern
//   tldMatchPattern(tld)       — "*://*.nl/*"
// ─────────────────────────────────────────────────────────────────────────────

import { UrlUtils } from "../lib/downloadsentinel/util/UrlUtils.js";
import { PRIVATE_HOST_SUFFIXES, SHARED_HOSTING_SUFFIXES } from "../data/constants.js";
import { PRIVATE_IPV4_BLOCKS } from "../data/network-data.js";

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function parseHttpUrl(url) {
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return null;
  return { url: u.href, host, protocol: u.protocol, port: u.port, pathname: u.pathname };
}

export function isIpHost(host) {
  if (!host) return false;
  if (IPV4_RE.test(host)) return true;
  return host.includes(":");            // IPv6 (brackets already stripped)
}

export function chromeSite(host) {
  if (!host) return "";
  if (isIpHost(host)) return host;
  return UrlUtils.getRegisteredDomain(host) || host;
}

// The tenant's own label + the shared suffix ("a.b.sharepoint.com" → "b.sharepoint.com"), or null.
function sharedHostingDomain(host) {
  for (const suffix of SHARED_HOSTING_SUFFIXES) {
    if (host === suffix) return suffix;
    if (!host.endsWith("." + suffix)) continue;
    const labels = host.slice(0, host.length - suffix.length - 1).split(".");
    return labels[labels.length - 1] + "." + suffix;
  }
  return null;
}

export function registeredDomain(host) {
  if (!host) return "";
  if (isIpHost(host)) return host;
  return sharedHostingDomain(host) || chromeSite(host);
}

export function tldOf(host) {
  if (!host || isIpHost(host)) return "";
  const i = host.lastIndexOf(".");
  return i === -1 ? host : host.slice(i + 1);
}

export function isPrivateHost(host) {
  if (!host) return true;
  if (host === "localhost" || host === "::1") return true;
  if (PRIVATE_HOST_SUFFIXES.some((s) => host.endsWith(s))) return true;
  const m = IPV4_RE.exec(host);
  if (m) {
    const [, firstText, secondText] = m;                       // first two octets
    const first = Number(firstText), second = Number(secondText);
    return PRIVATE_IPV4_BLOCKS.some((b) => b.first === first &&
      (b.secondMin === undefined || (second >= b.secondMin && second <= b.secondMax)));
  }
  if (host.includes(":")) return /^(f[cd]|fe[89ab])/i.test(host);
  return false;
}

export function isInDomainList(host, list) {
  if (!host || !list) return false;
  for (const d of list) {
    if (host === d || host.endsWith("." + d)) return true;
  }
  return false;
}

export function hostMatchPattern(host) { return `*://*.${host}/*`; }
export function tldMatchPattern(tld)   { return `*://*.${tld}/*`; }
