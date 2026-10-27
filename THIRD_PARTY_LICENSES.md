# Third-party components — 3P Matrix — content firewall

Copyright (C) 2026 Kees1958 and co-authors.

3P Matrix is distributed under the **GNU General Public License v3** (`LICENSE.txt`, the unmodified licence text). It contains, or is
derived from, the components below. Each keeps its own licence; the notices here satisfy their attribution
requirements.

| Component | Where in this extension | Licence |
|---|---|---|
| **uBlock Origin Lite** (Raymond Hill and contributors), via **uBlock Stripped Dynamic 10.2.1** | `security/*.js` (protection scripts), protection rules in `core/rule-builder.js`, `data/suspicious-hosting.js`, `data/network-data.js` | GPLv3 — https://github.com/uBlockOrigin/uBOL-home |
| **3P-Matrix-lite 4.0.2** | UI layout, levels, lock/startup level, Show Matrix model, `core/tld-engine.js`, `data/country-data.js`, `data/tld-constants.js`, `data/builtin-domains.js` (its built-in whitelist, with uBlock Stripped Dynamic 10.2.0's corrections), icons | same authors as this extension (Kees1958 and co-authors) |
| **DownloadSentinel 3.5.2** | `lib/downloadsentinel/` (domain and download heuristics, lists), `ui/download-warning.*`, `ui/vt-key-prompt.*` (ported pages) | same authors as this extension (Kees1958 and co-authors) |
| **HaGeZi DNS blocklists** — "The World's Most Abused TLDs", Dynamic-DNS / free-hoster lists | `data/spam-tlds.js` (generated), `data/suspicious-hosting.js` (HaGeZi DynDNS part; the rest is Kees1958's "Suspicious websites" list via uBlock Stripped Dynamic), `lib/downloadsentinel/util/HostList.default.js` | GPLv3 — https://github.com/hagezi/dns-blocklists |
| **Public Suffix List** (Mozilla Foundation and contributors) | `lib/downloadsentinel/util/PublicSuffixList.default.js` (generated) | MPL 2.0 — https://publicsuffix.org/ — full text: https://mozilla.org/MPL/2.0/ |
| **Chrome UX Report (CrUX)** top origins by Google — used for the lookalike check, compiled into a Bloom filter (3P-Matrix-tools/update-top-sites.mjs, once per minor release) | `lib/downloadsentinel/util/TopSitesFilter.default.js` (generated) | CC BY 4.0 — "CrUX datasets by Google are licensed under a Creative Commons Attribution 4.0 International License" — https://developer.chrome.com/docs/crux/methodology |
| **AdGuard corelibs** `prevent-eval-if` (converted to a self-contained script) | `security/sec-noeval.js`; its siblings `security/sec-nofunction.js`, `sec-nosettimeout.js`, `sec-nosetinterval.js` (4.4.3) reuse that script's structure and its obfuscation-shape test | GPLv3 — https://github.com/AdguardTeam/Scriptlets |

Generated data files name their source in their own header. When a list is regenerated, its source and
licence stay as listed here; a new source gets a new row in the same release (C39a — every consumer).
