"use strict";

/**
 * 3P Matrix (4.5.4): this list ships as a precompiled JSON string in PlatformSuffixes.default.js, rebuilt by
 * tools/update-domain-age-lists.mjs (registered in its data-sources.json; source: https://publicsuffix.org/list/public_suffix_list.dat).
 * data/… paths below are DownloadSentinel's own (its repo's data/ folder), not 3P Matrix's data/.
 *
 * PlatformSuffixes.js — Hosting-platform suffixes where a "registered
 * domain" is really a shared platform (github.io, blogspot.com, …): anyone
 * can get a subdomain there, so that platform's RDAP registration age says
 * nothing about the specific site being downloaded from. v3.3.0 (3P Matrix
 * alignment item 1).
 *
 * Public Suffix List private section (count: data/PlatformSuffixes.json), some as PSL wildcard
 * rules ("*.platform.tld"). Consumed by util/DomainAge.js's
 * domainAgeNotApplicable() — never looked up directly elsewhere.
 *
 * Single source of truth: data/PlatformSuffixes.json. Rebuilt by
 * tools/update-domain-age-lists.mjs once per minor release (see
 * data-sources.json's updateOn: "minor" for this list).
 */
import { PlatformSuffixesDefaultJson } from "./PlatformSuffixes.default.js";
import { createListSetModule } from "./ListSetModule.js";

export const PlatformSuffixes = createListSetModule(PlatformSuffixesDefaultJson);
