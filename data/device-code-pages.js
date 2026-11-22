// ── data/device-code-pages.js ─────────────────────────────────────────────────
// 4.7.0 — warnDeviceCodePages "Warn when a site sends you to enter a sign-in code": the ONE table of
// device sign-in pages. On these pages a code signs a DEVICE into the account; scammers send people there with the
// attacker's code ("device-code phishing"). The pages themselves are real.
//
// Per page: `host` (exact host or any subdomain), `path` (match-pattern path: * = anything; the webRequest filter is
// built from it, so the service worker wakes ONLY for these addresses), `ownDomains` (registered domains of the
// provider: a link from the provider's own pages is not a warning case).
// The final hosts after the provider's own redirects are listed too (microsoft.com/devicelogin →
// login.microsoftonline.com/…/deviceauth): a server redirect keeps the original initiator, so either address
// gives the same verdict.
// ─────────────────────────────────────────────────────────────────────────────

const MICROSOFT = Object.freeze(["microsoft.com", "microsoftonline.com", "live.com", "office.com", "aka.ms", "windows.net", "azure.com", "microsoft365.com"]);
const GOOGLE    = Object.freeze(["google.com"]);
const GITHUB    = Object.freeze(["github.com"]);

export const DEVICE_CODE_PAGES = Object.freeze([
  { host: "microsoft.com",             path: "/devicelogin*",         ownDomains: MICROSOFT },
  { host: "microsoft.com",             path: "/link*",                ownDomains: MICROSOFT },
  { host: "login.microsoftonline.com", path: "/*/oauth2/deviceauth*", ownDomains: MICROSOFT },
  { host: "login.microsoft.com",       path: "/device*",              ownDomains: MICROSOFT },
  { host: "login.live.com",            path: "/oauth20_remoteconnect.srf*", ownDomains: MICROSOFT },
  { host: "google.com",                path: "/device*",              ownDomains: GOOGLE },
  { host: "accounts.google.com",       path: "/o/oauth2/device*",     ownDomains: GOOGLE },
  { host: "github.com",                path: "/login/device*",        ownDomains: GITHUB }
].map((p) => Object.freeze(p)));

// webRequest URL filter: each page on its host and on any subdomain (www.).
export const DEVICE_CODE_URL_PATTERNS = Object.freeze(DEVICE_CODE_PAGES.flatMap((p) => [`*://${p.host}${p.path}`, `*://*.${p.host}${p.path}`]));
