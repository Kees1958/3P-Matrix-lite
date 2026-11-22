"use strict";

/**
 * 3P Matrix (4.5.4): this list ships as a precompiled JSON string in RdapCctlds.default.js, rebuilt by
 * 3P-Matrix-tools/update-domain-age-lists.mjs (registered in its data-sources.json; source: https://data.iana.org/rdap/dns.json).
 * EXTENSION/data/… paths below describe DownloadSentinel's own repository layout.
 *
 * RdapCctlds.js — Two-letter country-code TLDs that actually run an RDAP
 * service (IANA RDAP bootstrap, dns.json). A ccTLD NOT in this list
 * publishes no registration date at all — there is nothing to ask, so the
 * lookup is skipped rather than always coming back empty. v3.3.0 (3P Matrix
 * alignment item 1). Every gTLD (more than two letters) always has RDAP
 * under its ICANN contract, so this list only ever matters for two-letter
 * ccTLDs.
 *
 * Single source of truth: EXTENSION/data/RdapCctlds.json. Rebuilt by
 * tools/update-domain-age-lists.mjs once per minor release (see
 * data-sources.json's updateOn: "minor" for this list).
 */
import { RdapCctldsDefaultJson } from "./RdapCctlds.default.js";
import { createListSetModule } from "./ListSetModule.js";

export const RdapCctlds = createListSetModule(RdapCctldsDefaultJson);
