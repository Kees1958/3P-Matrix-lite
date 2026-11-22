"use strict";

/**
 * 3P Matrix (4.5.4): this list ships as a precompiled JSON string in SuspiciousTlds.default.js, rebuilt by
 * 3P-Matrix-tools/build-curated-lists.mjs (registered in its data-sources.json; source: curated (tools/lists-src/SuspiciousTlds.json)).
 * EXTENSION/data/… paths below describe DownloadSentinel's own repository layout.
 *
 * SuspiciousTlds.js
 * Risk scores (0–100) for TLDs frequently abused in phishing, spam, and
 * malware delivery. Higher score = stronger indicator of risk.
 *
 * DOCS/ARCHITECTURE.md, "Filter-data remote-update mechanism" — the raw
 * TABLE data now lives in EXTENSION/data/SuspiciousTlds.json (single source
 * of truth); this module only holds the lookup LOGIC. See
 * SuspiciousDomains.js's header for the full rationale — this module follows
 * the identical pattern.
 */
import { SuspiciousTldsDefaultJson } from "./SuspiciousTlds.default.js";
import { lazyJson } from "./LazyJson.js";

export const SuspiciousTlds = (function () {

    // 3P Matrix 4.5.4 (perf P4): parsed on first lookup, not at service-worker start (util/LazyJson.js).
    const defaultData = lazyJson(SuspiciousTldsDefaultJson);
    let TABLE = null;       // null = use the default (parsed on first use); setData() replaces it
    function data() { return TABLE === null ? (TABLE = defaultData()) : TABLE; }

    /**
     * Look up a TLD in the table.
     * @param {string} tld - Just the last label, e.g. "xyz"
     * @returns {{ score: number, tld: string } | null}
     */
    function lookup(tld) {
        if (!tld) return null;
        const t = tld.toLowerCase();
        if (data()[t] !== undefined) {
            return { score: data()[t], tld: t };
        }
        return null;
    }

    function setData(newTable) {
        TABLE = newTable;
    }

    function resetToDefault() {
        TABLE = null;           // released: the next lookup goes back to the default
    }

    return { lookup, setData, resetToDefault };
})();
