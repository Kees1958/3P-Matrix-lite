// ── core/session-map.js ───────────────────────────────────────────────────────
// Runtime state keyed by a Chrome integer id (tabId, downloadId) that must survive a service-worker
// restart (4.5.4): Chrome stops an idle service worker after ~30 s, which used to wipe the badge count, the
// risk colour, "Continue once" and (4.5.5) the blocked downloads waiting for the user's choice.
// chrome.storage.session keeps them for the browser session only — cleared when the browser closes, never
// written to disk — which is exactly their intended lifetime.
//
// Users: core/badge.js (tabs), core/navigation-guard.js (tabs), core/download-guard.js (downloads).
//
// Public interface:
//   createSessionMap(key) → store
//     store.ready()     — Promise: the map is restored (first call starts the restore; later calls share it)
//     store.map         — Map<id, value> (JSON-able values); change it only after ready() resolved
//     store.save()      — writes the whole map (small: bounded by open tabs / pending downloads); best
//                         effort, never throws
//
// Lifecycle / guards:
//   init     lazily, on the first ready() — not at import, so pure users (unit tests) need no chrome.storage
//   restore  entries from storage are loaded once; a restore failure leaves an empty map (state starts
//            fresh, exactly the pre-4.5.4 behaviour) and is logged
//   release  callers delete an entry when its tab / download ends and save(); the whole store is released
//            by Chrome at browser close
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX, DECIMAL_RADIX } from "../data/constants.js";

export function createSessionMap(key) {
  const map = new Map();
  let restoring = null;                       // Promise of the one restore, or null = not started

  function ready() {
    if (!restoring) {
      restoring = chrome.storage.session.get(key)
        .then((stored) => {
          for (const [rawId, value] of Object.entries(stored[key] || {})) {
            const id = Number.parseInt(rawId, DECIMAL_RADIX);
            if (Number.isInteger(id) && !map.has(id)) map.set(id, value);
          }
        })
        .catch((e) => console.warn(LOG_PREFIX, `session restore failed (${key}) — starting empty:`, e));
    }
    return restoring;
  }

  function save() {
    return chrome.storage.session.set({ [key]: Object.fromEntries(map) })
      .catch((e) => console.warn(LOG_PREFIX, `session save failed (${key}):`, e));
  }

  return { ready, map, save };
}
