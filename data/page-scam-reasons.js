// ── data/page-scam-reasons.js ─────────────────────────────────────────────────
// 4.7.0 — the ONE table of warning-page reasons that are not an exfiltration channel: what a page tried to make
// the user do, how the warning looks, and what its buttons do. Read by the service worker (which reasons exist,
// how "Go back" behaves — core/page-scam-guard.js, background.js) and by ui/warning.js (text and look).
//
//   clickFix    — blockClickFix: the page put a command on the clipboard for the user to run (ClickFix, FileFix, the
//                 macOS Script Editor link). Red. The command was not copied.
//   consentFix  — blockConsentFix: the user pasted a sign-in address (http://localhost/?code=… or a Microsoft
//                 sign-in return address) into a website — that address is a key to the account. Red. Not pasted.
//   deviceCode  — warnDeviceCodePages: another website sent the user to a device sign-in page (microsoft.com/devicelogin
//                 …), where a code the attacker gives signs the ATTACKER's device into the user's account. Amber:
//                 the page itself is real; only the user knows whether they started the sign-in.
//   paymentSkimmer — warnPaymentSkimmer (5.0.2): the page loaded a fake tracking-pixel script (claims to be Facebook's
//                 loader but is served from the wrong domain) or drew a payment-field overlay that is not
//                 same-origin with the page — the two "SuperPixel"/Magecart card-skimmer signals. Red: the page
//                 is actively trying to steal card data, not merely suspicious.
//   fakeSignInWindow — blockFakeSignInWindow (5.0.6; was an in-page dialog since 4.7.0): a box around a password field draws
//                 its own title bar and address of ANOTHER site's sign-in (Browser-in-the-Browser). Red. Moved to
//                 this warning page because the page itself could remove an in-page dialog (C47) — and a phishing
//                 page is exactly the page that wants to.
//
// Fields
//   id          warning-page parameter value (WARNING_REASON_PARAM); never equal to an exfiltration channel id
//   look        LOOK.PHISHING (red) | LOOK.ATTENTION (amber, the "suspicious" look)
//   leave       LEAVE.SITE (walk back until another website — core/leave-site.js) | LEAVE.NEW_TAB (straight to a
//               new-tab page: going back would land on the site that sent the user)
//   scoreSite   true = the warning also shows the site's own risk score (stage 1 + 2), as other warnings do
//   canTrust    false = no "Trust this site" button (trusting microsoft.com would be meaningless here)
//   title/intro/signal  the text; {place} (clickFix) = where the OS runs a pasted command (RUN_PLACE_BY_OS),
//               {referrer} (deviceCode) = the site that sent the user
//   back/cont   button labels (null = the warning page's own default label)
//   note        replaces the warning page's small print (null = keep it)
// ─────────────────────────────────────────────────────────────────────────────

export const LOOK  = Object.freeze({ PHISHING: "phishing", ATTENTION: "attention" });
export const LEAVE = Object.freeze({ SITE: "site", NEW_TAB: "newTab" });

export const PAGE_SCAM_KIND = Object.freeze({
  CLICK_FIX:       "clickFix",
  CONSENT_FIX:     "consentFix",
  DEVICE_CODE:     "deviceCode",
  PAYMENT_SKIMMER: "paymentSkimmer",   // 5.0.2
  FAKE_SIGN_IN_WINDOW: "fakeSignInWindow"   // 5.0.6
});

// Where a pasted command would run, per chrome.runtime.getPlatformInfo().os (user decision 2026-11-06: Linux
// names Ctrl+Alt+T). Unknown os → DEFAULT.
export const RUN_PLACE_BY_OS = Object.freeze({
  win:     "the Run window (Win+R), PowerShell or the File Explorer address bar",
  mac:     "Terminal, Spotlight or Script Editor",
  linux:   "a terminal (Ctrl+Alt+T) or the Alt+F2 run window",
  cros:    "a terminal",
  default: "a terminal or a run window"
});

export const PAGE_SCAM_REASONS = Object.freeze([
  { id: PAGE_SCAM_KIND.CLICK_FIX, look: LOOK.PHISHING, leave: LEAVE.SITE, scoreSite: true, canTrust: true,
    title: "This page tried to make you run a command on your computer",
    intro: "No real CAPTCHA, update or error message ever asks you to paste something into {place}. The command was not copied. Close this page.",
    signal: "This page put a hidden command on the clipboard — typical of a ClickFix scam",
    back: null, cont: null, note: null },
  { id: PAGE_SCAM_KIND.CONSENT_FIX, look: LOOK.PHISHING, leave: LEAVE.SITE, scoreSite: true, canTrust: true,
    title: "This page asked you to paste a sign-in address",
    intro: "Never copy an address that starts with http://localhost — or any sign-in return address — into a website. It gives that site access to your account. 3P Matrix did not paste it.",
    signal: "This page asked for a sign-in return address — typical of a ConsentFix account takeover",
    back: null, cont: null, note: null },
  { id: PAGE_SCAM_KIND.DEVICE_CODE, look: LOOK.ATTENTION, leave: LEAVE.NEW_TAB, scoreSite: false, canTrust: false,
    title: "Did you start this sign-in yourself?",
    intro: "{referrer} sent you here to enter a code. Scammers use this page to take over accounts: the code signs THEIR device into YOUR account. Only continue if you started the sign-in yourself, on your own TV, app or computer.",
    signal: "Opened from another website, not typed or from a bookmark",
    back: "No, leave", cont: "Yes, I started it",
    note: "“Yes, I started it” opens the page for this tab only. Typing the address yourself never shows this question." },
  { id: PAGE_SCAM_KIND.PAYMENT_SKIMMER, look: LOOK.PHISHING, leave: LEAVE.SITE, scoreSite: true, canTrust: true,
    title: "This page shows signs of a payment-skimming scam",
    intro: "A script on this page pretended to be a well-known tracking pixel, or a payment box was drawn that does not actually belong to this site — both are used to quietly copy card details as you type them. Close this page rather than enter any payment information here.",
    signal: "A fake tracking-pixel loader or an unrelated payment overlay was found on this page — typical of a Magecart card-skimming scam",
    back: null, cont: null, note: null },
  { id: PAGE_SCAM_KIND.FAKE_SIGN_IN_WINDOW, look: LOOK.PHISHING, leave: LEAVE.SITE, scoreSite: true, canTrust: true,
    title: "This page drew a fake sign-in window",
    intro: "A box on this page draws its own title bar and address bar around a password field, pretending to be the sign-in window of another site such as Google or Microsoft. A real sign-in window is a separate browser window with the browser's own address bar. Do not enter your password here.",
    signal: "A drawn \u201cwindow\u201d around a password field shows the address of a sign-in provider that is not this site — typical of a Browser-in-the-Browser phishing page",
    back: null, cont: null, note: null }
].map((r) => Object.freeze(r)));

export const PAGE_SCAM_REASON_BY_ID = Object.freeze(Object.fromEntries(PAGE_SCAM_REASONS.map((r) => [r.id, r])));
export const UNKNOWN_REFERRER_TEXT = "Another website";   // deviceCode {referrer} when the sending site is not known
