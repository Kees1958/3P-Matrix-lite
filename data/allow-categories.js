// ── data/allow-categories.js ──────────────────────────────────────────────────
// 5.1.3 (owner decisions 2026-11-24) — the ONE allow (white) list, with categories. A site under a category is
// exempt from everything of that category: warnings are ignored, blocks are allowed. "All" = the former allow list
// (a site locked at level 1 — no protection at all). Written one per line as "Category: domain"; a bare domain is
// read as "All: domain" (core/site-locks.js parseAllowListText). On save "All" for a domain removes its other lines.
//
// Where each category is stored (single source each):
//   ALL      — state.siteLocks at LEVEL.ALLOW_ALL (unchanged)
//   DOWNLOAD — state.downloads.trustedDomains (unchanged storage: the former "own trusted domains", released in 5.0.9;
//              a host, matched with its subdomains, as before)
//   FIREWALL, SCAM, TAMPER — state.allowCategories[category]: registered domains
//
// Which category a protection belongs to follows its Protections-page tab (ALLOW_CATEGORY_OF_TAB).
// ─────────────────────────────────────────────────────────────────────────────

import { PROTECTION_TAB } from "./protections.js";

export const ALLOW_CATEGORY = Object.freeze({ ALL: "all", DOWNLOAD: "download", FIREWALL: "firewall", SCAM: "scam", TAMPER: "tamper" });
// Display order of the list (and of a save's sorting) and the word written in front of the domain.
export const ALLOW_CATEGORY_ORDER = Object.freeze([ALLOW_CATEGORY.ALL, ALLOW_CATEGORY.DOWNLOAD, ALLOW_CATEGORY.FIREWALL,
                                                   ALLOW_CATEGORY.SCAM, ALLOW_CATEGORY.TAMPER]);
export const ALLOW_CATEGORY_LABEL = Object.freeze({ [ALLOW_CATEGORY.ALL]: "All", [ALLOW_CATEGORY.DOWNLOAD]: "Download",
  [ALLOW_CATEGORY.FIREWALL]: "Firewall", [ALLOW_CATEGORY.SCAM]: "Scam", [ALLOW_CATEGORY.TAMPER]: "Tamper" });
// The categories kept in state.allowCategories (the other two have their own storage, see above).
export const ALLOW_CATEGORIES_STORED = Object.freeze([ALLOW_CATEGORY.FIREWALL, ALLOW_CATEGORY.SCAM, ALLOW_CATEGORY.TAMPER]);
// A protection's category = its tab's.
export const ALLOW_CATEGORY_OF_TAB = Object.freeze({
  [PROTECTION_TAB.BROWSING]: ALLOW_CATEGORY.FIREWALL,
  [PROTECTION_TAB.DOWNLOAD]: ALLOW_CATEGORY.DOWNLOAD,
  [PROTECTION_TAB.SCAM]:     ALLOW_CATEGORY.SCAM,
  [PROTECTION_TAB.TAMPER]:   ALLOW_CATEGORY.TAMPER
});
