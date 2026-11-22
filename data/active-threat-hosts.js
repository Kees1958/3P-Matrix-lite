// ── data/active-threat-hosts.js ───────────────────────────────────────────────
// Hosts seen RIGHT NOW (live threat-intel, not a generic "open platform" rule)
// serving malware — but ONLY when the URL also looks like the actual delivery
// pattern of that campaign, not for ordinary use of the same host.
//
// Two kinds of entry below:
//   - host alone (RISKY_DELIVERY_EXT_RE is the only gate) — the GitHub
//     content-delivery CDN hosts. They have no other legitimate shape to
//     narrow against: any path on raw.githubusercontent.com ending in .zip
//     IS a file being fetched for download, full stop.
//   - host + shapes[] — the *redirect-origin* hosts (github.com, gitlab.com
//     themselves), which also serve their entire normal browsing UI, so the
//     extension alone isn't enough. Each shape is one URL pattern real
//     campaigns use; a shape may carry its own `note` — extra wording shown
//     to the user when THAT specific shape is the reason this fired, for a
//     shape where a real person doing something normal can produce the same
//     URL on their own (see the archive/refs/heads entry below).
//
// 2026-10-28/29: GitHub's and GitLab's raw-content/release hosts — and the
// bare github.com/gitlab.com redirect origins that resolve to them — are
// being used to distribute malware inside archive/executable files hosted in
// throwaway/disposable repos. These same hosts are also the everyday way
// countless legitimate pages load a raw .js/.css/.json/.md file, or the way a
// maintainer shares a release binary they actually published — a host-only
// match would warn on that ordinary traffic too, so every entry below
// requires the URL to ALSO look like an actual delivery (RISKY_DELIVERY_EXT_RE),
// and the two redirect-origin hosts require a matching path shape on top.
//
// Verified against URLhaus's live feed (2026-10-29, malware-filter.gitlab.io/
// malware-filter/urlhaus-filter.txt, 125,522 entries total):
//   raw.githubusercontent.com (any path)          — 56,454 hits (45%)
//   github.com + /releases/download/<tag>/<file>  — 40,414 hits (32%)
//   github.com + /raw/<branch>/<file>             —  7,673 hits (6%)
//   gitlab.com + /-/raw/<branch>/<file>           —    781 hits (0.6%)
//   github.com + /archive/refs/heads/<branch>.zip —     87 hits (0.07%)
//   release-assets/objects/media.githubusercontent.com, codeload.github.com
//                                                  —     36 hits (0.03%)
// — together ~84% of the feed, up from ~45% before github.com/gitlab.com
// were added.
//
// github.com + /archive/refs/heads/<branch>.zip is included despite its low
// hit-share ABOVE, by deliberate decision, because it's also the one shape a
// real person generates on their own: it's the exact link behind GitHub's
// "Download ZIP" button on every public repository, with no owner action
// required — unlike a release or a raw-file link, which both need someone to
// have deliberately published that specific artifact. Its `shapes` entry
// below carries a `note` saying so, so the warning dialog itself tells a user
// who just clicked that button that this may well be them, not an attacker —
// rather than silently leaving the shape out and missing the 87 real hits
// (this list's other entries also need their own note whenever a future
// addition has the same "a normal user action also produces this exact URL"
// property; see C42 for why a disclaimer is not a substitute for a real test
// of the shape it's attached to).
//
// Deliberately kept OUT of the shared lib/downloadsentinel/ library
// (RiskyHostingSites, CombinationScoring's FAMILY_MAP, …): those files are
// reused unchanged from DownloadSentinel (see core/site-scorer.js's header).
// This list is a short-lived, 3P-Matrix-only addition for hosts/patterns
// currently seeing real abuse — review and prune periodically, it is not a
// permanent blocklist. An entry whose campaign has died down should be
// removed, extension/shape requirement and all.
//
// githubassets.com (the GitHub UI's own static-asset CDN) is NOT included —
// unrelated host, already built-in trusted (script only, 4.4.7).
// ─────────────────────────────────────────────────────────────────────────────

// Hosts currently part of an active campaign (exact match, lowercase).
// `shapes`, when present, is an ADDITIONAL requirement on top of
// RISKY_DELIVERY_EXT_RE — needed only for the two hosts that also serve
// their entire normal browsing UI (github.com, gitlab.com); the CDN-only
// hosts have no other legitimate shape to narrow against, so they have none.
export const ACTIVE_THREAT_HOSTS = Object.freeze([
  { host: "raw.githubusercontent.com" },
  { host: "release-assets.githubusercontent.com" },
  { host: "codeload.github.com" },
  { host: "objects.githubusercontent.com" },
  { host: "media.githubusercontent.com" },
  {
    host: "github.com",
    shapes: [
      { pattern: /\/releases\/download\// },
      { pattern: /\/raw\// },
      {
        pattern: /\/archive\/refs\/heads\//,
        // Shown appended to this hit's signal label, as its own last line — see
        // the header comment above for why this one shape needs it and the
        // others don't. core/site-scorer.js only appends it when this is the
        // SOLE alarming signal on the site, so the wording never needs to say
        // so itself.
        note: "When you pressed the “Download ZIP” button on GitHub, it might be a false alarm."
      }
    ]
  },
  { host: "gitlab.com", shapes: [{ pattern: /\/-\/raw\// }] }
]);

// Archive/executable extensions — the actual delivery vehicle for a payload,
// as opposed to a source/content file (.js, .css, .json, .md, .png, …) the
// same hosts serve constantly and harmlessly. Case-insensitive, end of path.
export const RISKY_DELIVERY_EXT_RE = /\.(zip|rar|7z|tar|tgz|gz|exe|msi|bat|cmd|scr|jar|apk|dmg|pkg|iso|ps1|vbs|dll|sys)$/i;

// Signal names and label shared by the site check (core/site-scorer.js, core/online-checks.js) and the download check
// (core/download-guard.js) — 4.5.8: declared once (were typed in each). PLATFORM_SIGNAL_SOURCE is the name both checks
// (and DownloadSentinel) give the "file-sharing platform" row; when an active-threat hit is present that row is left
// out: both say "this host", and the active-threat line is the stronger, more specific statement (one fact, one signal).
export const ACTIVE_THREAT_SIGNAL_SOURCE      = "ActiveThreatHost";
export const ACTIVE_THREAT_NOTE_SIGNAL_SOURCE = "ActiveThreatHostNote";
export const PLATFORM_SIGNAL_SOURCE           = "RiskyHosting";
export function activeThreatLabel(host, pathname) {
  return `Currently used to deliver malware as a .${String(pathname).split(".").pop()} file (${host})`;
}

const ACTIVE_THREAT_HOST_MAP = new Map(ACTIVE_THREAT_HOSTS.map((e) => [e.host, e]));

// The one function both core/site-scorer.js and core/online-checks.js call —
// centralized so the host list, the extension gate and the per-host shape
// gate can't drift apart between the two scoring stages (the exact failure
// C22 names: one rule, enforced identically everywhere it applies).
//
// Returns null when this isn't an active-threat delivery, or
// { note } (note is null unless the matched shape carries one) when it is.
export function matchActiveThreatDelivery(host, pathname) {
  const entry = ACTIVE_THREAT_HOST_MAP.get(host);
  if (!entry) return null;
  const path = pathname || "";
  if (!RISKY_DELIVERY_EXT_RE.test(path)) return null;
  if (!entry.shapes) return { note: null };                       // CDN-only host: extension alone is the gate
  const shape = entry.shapes.find((s) => s.pattern.test(path));
  return shape ? { note: shape.note || null } : null;
}
