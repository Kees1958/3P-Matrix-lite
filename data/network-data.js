// ── data/network-data.js ──────────────────────────────────────────────────────
// Static host data for the DNR protections. Pure data + pure regex builders.
//
//   HIGH_RISK_HOSTNAMES        — blockHighRiskEval site list (uBlock Stripped Dynamic 10.2.1
//                                js/data/high-risk-sites.js) + HIGH_RISK_HOSTNAMES_ADDED
//                                − HIGH_RISK_HOSTNAMES_DROPPED
//   LOCAL_NETWORK_NAME_DOMAINS — blockLocalNetwork host-name suffixes
//   LOCAL_NETWORK_INITIATOR_EXEMPT — pages on the local network itself are never blocked
//   buildLocalNetworkIpv4Regex() / buildLocalNetworkIpv6Regex() — blockLocalNetwork
//                                (ported from uBD js/data/local-network-hosts.js; three
//                                rules, because one regex exceeds Chrome's RE2 memory limit)
// Loopback (127/8, ::1, localhost) is deliberately NOT blocked, so local helper
// apps (password-manager bridges, dev servers) keep working.
// ─────────────────────────────────────────────────────────────────────────────

// 4.2: additions BEYOND the ported uBlock Stripped Dynamic list (user request) — kept apart so
// the ported list stays verbatim and can be re-synced.
const HIGH_RISK_HOSTNAMES_ADDED = Object.freeze([
  "fullvideosporn.com"
]);

const HIGH_RISK_HOSTNAMES_PORTED = Object.freeze([
  "pornhub.com", "xhamster.com", "xvideos.com", "xnxx.com", "eporner.com",
  "redtube.com", "tube8.com", "xgroovy.com", "xgroovy.tv", "youporn.com",
  "spankbang.com", "porntrex.com", "onlyfans.com", "theporndude.com",
  "xvideos.es", "xhamsterlive.com", "fpo.xxx", "qorno.com", "pornpics.com",
  "f95zone.to", "xhamster19.com", "beeg.com", "tnaflix.com",
  "coveryourtracks.eff.org"
]);

// 5.0.6 (user request): entries of the ported list that do NOT belong here — kept apart, like the additions above,
// so the ported list stays verbatim and can be re-synced.
//   coveryourtracks.eff.org — the EFF's browser-fingerprinting test page, not a risky (adult) site. Being on this
//   list also made it a "high-risk site" for every alsoHighRisk protection, not only blockHighRiskEval.
const HIGH_RISK_HOSTNAMES_DROPPED = Object.freeze(new Set([
  "coveryourtracks.eff.org"
]));

export const HIGH_RISK_HOSTNAMES = Object.freeze([...new Set([...HIGH_RISK_HOSTNAMES_PORTED, ...HIGH_RISK_HOSTNAMES_ADDED])]
  .filter((h) => !HIGH_RISK_HOSTNAMES_DROPPED.has(h)));

export const LOCAL_NETWORK_NAME_DOMAINS = Object.freeze(["local", "lan", "internal", "home.arpa"]);
export const LOCAL_NETWORK_INITIATOR_EXEMPT = Object.freeze([...LOCAL_NETWORK_NAME_DOMAINS, "localhost", "127.0.0.1"]);

// First-party IPv4 hosts that are never scored as suspicious sites (util/domain.js isPrivateHost):
// a block matches when the first octet equals `first` and, if given, the second octet lies in
// [secondMin, secondMax]. (4.2.3: moved here from inline numbers — audit finding 13.)
export const PRIVATE_IPV4_BLOCKS = Object.freeze([
  Object.freeze({ first: 0 }),                                   // 0.0.0.0/8 "this network"
  Object.freeze({ first: 10 }),                                  // 10.0.0.0/8
  Object.freeze({ first: 127 }),                                 // 127.0.0.0/8 loopback
  Object.freeze({ first: 169, secondMin: 254, secondMax: 254 }), // 169.254.0.0/16 link-local
  Object.freeze({ first: 172, secondMin: 16,  secondMax: 31 }),  // 172.16.0.0/12
  Object.freeze({ first: 192, secondMin: 168, secondMax: 168 }), // 192.168.0.0/16
  Object.freeze({ first: 100, secondMin: 64,  secondMax: 127 })  // 100.64.0.0/10 carrier-grade NAT
]);

const OCTET = "(?:\\.[0-9]+)";
const LOCAL_IPV4_RANGES = Object.freeze([
  { restOctets: 3, prefixes: ["10"] },                                    // 10.0.0.0/8
  { restOctets: 2, prefixes: [
    "192\\.168",                                                          // 192.168.0.0/16
    "172\\.(?:1[6-9]|2[0-9]|3[01])",                                      // 172.16.0.0/12
    "169\\.254",                                                          // link-local
    "100\\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])"                      // carrier-grade NAT
  ] }
]);
const IPV4_MAPPED_PRIVATE_HEX_GROUPS = Object.freeze(["a[0-9a-f][0-9a-f]", "c0a8", "ac1[0-9a-f]", "a9fe", "64[4-7][0-9a-f]"]);
const LOCAL_IPV6_FRAGMENTS = Object.freeze([
  "f[cd][0-9a-f:]*",                                                      // fc00::/7 unique local
  "fe[89ab][0-9a-f:]*",                                                   // fe80::/10 link-local
  `::ffff:(?:${IPV4_MAPPED_PRIVATE_HEX_GROUPS.join("|")}):[0-9a-f]+`      // IPv4-mapped private ranges
]);
const URL_HEAD = "^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?";
const URL_TAIL = "(?::[0-9]+)?(?:[/?#]|$)";

export function buildLocalNetworkIpv4Regex() {
  const parts = LOCAL_IPV4_RANGES.map((r) => `(?:${r.prefixes.join("|")})${OCTET}{${r.restOctets}}`);
  return `${URL_HEAD}(?:${parts.join("|")})${URL_TAIL}`;
}

export function buildLocalNetworkIpv6Regex() {
  return `${URL_HEAD}\\[(?:${LOCAL_IPV6_FRAGMENTS.join("|")})\\]${URL_TAIL}`;
}
