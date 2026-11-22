// ── data/builtin-domains.js ───────────────────────────────────────────────────
// Built-in whitelist: third-party scripts/frames from these hosts are allowed at levels 3 and 4 (never at
// level 5). Also: a first-party visit to one of them is exempt from blockHighRiskEval and the outside-safer-regions group (levels 3–4),
// from warnSuspiciousSites, from warnRiskyDownloads when it is the page a download came
// from, and payment hosts may register a payment handler (blockPaymentHandlers). Consumers: core/rule-builder.js,
// core/script-builder.js, core/navigation-guard.js, core/download-settings.js, core/connection-matrix.js,
// core/matrix-disposition.js (Show Matrix "Internal whitelist" tooltip), data/protections.js, ui/popup.js.
//
// RULES for an entry (all must hold — tools/check-whitelist.mjs enforces what is mechanical):
//   - narrow and owner-controlled: nobody but the vendor publishes there (no user uploads, no self-service
//     marketplaces, no community CDN mirrors — jsdelivr/unpkg/esm.sh/npm, cdn.bootcss.com stay out)
//   - a genuine embeddable script/frame, in the category it is filed under
//   - never a host on the download risk lists (DownloadSentinel RiskyHostingSites / SuspiciousDomains /
//     HostList, data/active-threat-hosts.js) — the check fails on any overlap
//   - one line per entry: [host, type, reason]; the reason says what it is and why it is trusted
//
// History: 3P-Matrix-lite 4.0.2 BUILTIN_DOMAINS + uBlock Stripped Dynamic 10.2.0 corrections; 0.2.4
// streaming/meeting/gaming embeds (hand-curated); 4.4.7 review of the user's trusted.json.
// 4.5.6 (real report: a Discord attachment downloaded unchecked) — full category review, every entry got
// its reason; the catch-all group "Sign-in, CAPTCHA, video or JS library" was split into real categories;
// 9 entries removed (BUILTIN_REMOVED below, with the reason — never re-add one without a new decision).
// 4.5.7: 35 entries added from uBlock Stripped Dynamic's list (meeting, sign-in, payment), 46 candidates
// rejected — each with its reason in BUILTIN_REMOVED.
// Machine-readable copy for DownloadSentinel / uBlock Stripped Dynamic: 3P-Matrix-tools/export-whitelist.mjs.
// ─────────────────────────────────────────────────────────────────────────────

// Which resource types an entry allows (DNR rules in core/rule-builder.js).
const TYPE = Object.freeze({ BOTH: "both", SCRIPT: "script", FRAME: "frame" });

// Categories: label (Show Matrix tooltip, JSON export), summary (popup "Trusted: …" line; "" = not named there).
export const BUILTIN_GROUP = Object.freeze({
  PAYMENT: Object.freeze({ label: "Payment", summary: "payment" }),
  SIGN_IN: Object.freeze({ label: "Sign-in", summary: "sign-in" }),
  CAPTCHA: Object.freeze({ label: "CAPTCHA or bot protection", summary: "" }),
  FRAUD: Object.freeze({ label: "Fraud prevention", summary: "" }),
  VIDEO: Object.freeze({ label: "Video or audio player", summary: "video" }),
  STREAMING: Object.freeze({ label: "Streaming embed", summary: "streaming" }),
  MEETING: Object.freeze({ label: "Meeting embed", summary: "meetings" }),
  GAMING: Object.freeze({ label: "Gaming embed", summary: "games" }),
  SOCIAL: Object.freeze({ label: "Social post embed", summary: "" }),
  WIDGET: Object.freeze({ label: "Map or translation widget", summary: "" }),
  LIBRARY: Object.freeze({ label: "JS / CSS / font library", summary: "" }),
  PLATFORM: Object.freeze({ label: "Platform vendor assets", summary: "" })
});

// ── Payment — Payment providers, card networks, 3-D Secure, buy-now-pay-later and billing. Card-network and bank main domains are kept for 3-D Secure (user decision 2026-11-04).
const PAYMENT = Object.freeze([
  ["2checkout.com", TYPE.BOTH, "2Checkout / Verifone billing"],
  ["adyen.com", TYPE.BOTH, "Adyen payment platform"],
  ["aexp-static.com", TYPE.BOTH, "American Express checkout / 3-D Secure assets"],
  ["affirm.com", TYPE.BOTH, "Affirm buy-now-pay-later"],
  ["airwallex.com", TYPE.BOTH, "Airwallex payments"],
  ["amazonpay.com", TYPE.BOTH, "Amazon Pay"],
  ["americanexpress.com", TYPE.BOTH, "American Express card network / 3-D Secure (kept: user decision 2026-11-04)"],
  ["apple-pay-gateway-nc-pod.apple.com", TYPE.BOTH, "Apple Pay merchant gateway"],
  ["apple-pay-gateway.apple.com", TYPE.BOTH, "Apple Pay merchant gateway"],
  ["assets.braintreegateway.com", TYPE.BOTH, "Braintree (PayPal) checkout assets"],
  ["authorize.net", TYPE.BOTH, "Authorize.Net payment gateway (Visa)"],
  ["avangate.com", TYPE.BOTH, "Avangate (2Checkout) billing"],
  ["avangate.net", TYPE.BOTH, "Avangate (2Checkout) billing assets"],
  ["axepta.it", TYPE.BOTH, "Axepta (BNL / Worldline) payments (IT)"],
  ["axerve.com", TYPE.BOTH, "Axerve payment gateway (IT)"],
  ["bac-assets.com", TYPE.BOTH, "Bank of America 3-D Secure / checkout assets (kept: banks, user decision 2026-11-04)"],
  ["bambora.com", TYPE.BOTH, "Bambora / Worldline payment gateway"],
  ["bancontact.com", TYPE.BOTH, "Bancontact (Belgian bank-payment scheme)"],
  ["banked.com", TYPE.BOTH, "Banked pay-by-bank"],
  ["bb.com.br", TYPE.BOTH, "Banco do Brasil 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["beanstream.com", TYPE.BOTH, "Beanstream / Bambora gateway (Canada)"],
  ["billink.nl", TYPE.BOTH, "Billink pay-later (NL)"],
  ["bizum.es", TYPE.BOTH, "Bizum mobile payments (ES)"],
  ["bluesnap.com", TYPE.BOTH, "BlueSnap payments"],
  ["bluesnap.net", TYPE.BOTH, "BlueSnap payment assets"],
  ["bnlpositivity.it", TYPE.BOTH, "BNL bank 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["bradesco.com.br", TYPE.BOTH, "Bradesco 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["braintree-api.com", TYPE.BOTH, "Braintree API"],
  ["braintreegateway.com", TYPE.BOTH, "Braintree gateway"],
  ["buckaroo.nl", TYPE.BOTH, "Buckaroo payment service provider (NL)"],
  ["cardinalcommerce.com", TYPE.BOTH, "Cardinal Commerce 3-D Secure (Visa)"],
  ["cardinaltrusted.com", TYPE.BOTH, "Cardinal Commerce 3-D Secure (Visa)"],
  ["ccv.eu", TYPE.BOTH, "CCV payment terminals and online payments (NL)"],
  ["cdn.checkout.com", TYPE.BOTH, "Checkout.com hosted fields assets"],
  ["chargebee.com", TYPE.BOTH, "Chargebee subscription billing"],
  ["chargebeestatic.com", TYPE.BOTH, "Chargebee checkout assets"],
  ["chargebeestaticv2.com", TYPE.BOTH, "Chargebee checkout assets"],
  ["chasecdn.com", TYPE.BOTH, "Chase 3-D Secure / checkout assets (kept: banks, user decision 2026-11-04)"],
  ["chasepaymentech.com", TYPE.BOTH, "Chase Paymentech acquiring"],
  ["checkout.com", TYPE.BOTH, "Checkout.com payment platform"],
  ["checkout.stripe.com", TYPE.BOTH, "Stripe hosted checkout"],
  ["checkoutshopper-live.adyen.com", TYPE.BOTH, "Adyen hosted checkout components"],
  ["cielo.com.br", TYPE.BOTH, "Cielo card acquirer (BR)"],
  ["cleverbridge.com", TYPE.BOTH, "Cleverbridge billing"],
  ["clover.com", TYPE.BOTH, "Clover (Fiserv) point-of-sale and online payments"],
  ["cm.com", TYPE.BOTH, "CM.com payments (also messaging; payment pages run here)"],
  ["comgate.cz", TYPE.BOTH, "Comgate payment gateway (CZ)"],
  ["computop.com", TYPE.BOTH, "Computop payment platform (DE)"],
  ["convergepay.com", TYPE.BOTH, "Elavon Converge gateway"],
  ["cybersource.com", TYPE.BOTH, "Cybersource gateway / 3-D Secure (Visa)"],
  ["dalenys.com", TYPE.BOTH, "Dalenys payments (FR)"],
  ["discover.com", TYPE.BOTH, "Discover card network / 3-D Secure (kept: user decision 2026-11-04)"],
  ["elavon.com", TYPE.BOTH, "Elavon card acquiring"],
  ["eps-ueberweisung.at", TYPE.BOTH, "EPS bank transfer scheme (AT)"],
  ["euplatesc.ro", TYPE.BOTH, "EuPlătesc payment gateway (RO)"],
  ["every-pay.com", TYPE.BOTH, "EveryPay payment gateway (Baltics)"],
  ["fastspringresources.com", TYPE.BOTH, "FastSpring checkout assets"],
  ["firstdata.com", TYPE.BOTH, "First Data (Fiserv) processing"],
  ["fiserv.com", TYPE.BOTH, "Fiserv payment processing"],
  ["fisglobal.com", TYPE.BOTH, "FIS / Worldpay payment processing"],
  ["gestpay.it", TYPE.BOTH, "Gestpay / Axerve gateway (IT)"],
  ["gestpay.net", TYPE.BOTH, "Gestpay / Axerve gateway (IT)"],
  ["getnet.com.br", TYPE.BOTH, "GetNet (Santander) card acquirer (BR)"],
  ["getswish.se", TYPE.BOTH, "Swish mobile payments (SE)"],
  ["globalpay.com", TYPE.BOTH, "Global Payments gateway"],
  ["globalpaymentsinc.com", TYPE.BOTH, "Global Payments"],
  ["gocardless.com", TYPE.BOTH, "GoCardless direct debit"],
  ["googlepay.com", TYPE.BOTH, "Google Pay"],
  ["gopay.com", TYPE.BOTH, "GoPay payment gateway (CZ)"],
  ["gpwebpay.com", TYPE.BOTH, "GP webpay gateway (CZ)"],
  ["heidelpay.com", TYPE.BOTH, "Heidelpay / Unzer (DE)"],
  ["helcim.com", TYPE.BOTH, "Helcim payment processing"],
  ["hipay-tpp.com", TYPE.BOTH, "HiPay payments"],
  ["hooks.stripe.com", TYPE.BOTH, "Stripe 3-D Secure redirect / webhooks endpoint"],
  ["ideal-checkout.nl", TYPE.BOTH, "iDEAL checkout plug-in (NL)"],
  ["ideal.nl", TYPE.BOTH, "iDEAL — Dutch bank-payment scheme"],
  ["ingenico.com", TYPE.BOTH, "Ingenico / Worldline payments"],
  ["itau.com.br", TYPE.BOTH, "Itaú Unibanco 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["js.braintreegateway.com", TYPE.SCRIPT, "Braintree drop-in script"],
  ["js.mollie.com", TYPE.BOTH, "Mollie components script"],
  ["js.squareup.com", TYPE.SCRIPT, "Square web payments script"],
  ["js.stripe.com", TYPE.SCRIPT, "Stripe.js"],
  ["js.stripe.network", TYPE.SCRIPT, "Stripe.js network helper"],
  ["klarna.com", TYPE.BOTH, "Klarna buy-now-pay-later and checkout"],
  ["klarnacdn.net", TYPE.BOTH, "Klarna checkout assets"],
  ["klarnaservices.com", TYPE.BOTH, "Klarna checkout services"],
  ["lyra.com", TYPE.BOTH, "Lyra payment platform (FR)"],
  ["m.stripe.network", TYPE.BOTH, "Stripe fraud-signal frame (Stripe.js)"],
  ["makecommerce.net", TYPE.BOTH, "MakeCommerce payment gateway (Baltics)"],
  ["mastercard.com", TYPE.BOTH, "Mastercard network / 3-D Secure (kept: user decision 2026-11-04)"],
  ["memberful.com", TYPE.BOTH, "Memberful membership billing"],
  ["mercadopago.cl", TYPE.BOTH, "Mercado Pago checkout (CL)"],
  ["mercadopago.com.ar", TYPE.BOTH, "Mercado Pago checkout (AR)"],
  ["mercadopago.com.br", TYPE.BOTH, "Mercado Pago checkout (BR)"],
  ["mercadopago.com.co", TYPE.BOTH, "Mercado Pago checkout (CO)"],
  ["mercadopago.com.mx", TYPE.BOTH, "Mercado Pago checkout (MX)"],
  ["mercurypayments.it", TYPE.BOTH, "Mercury Payments (Nexi) (IT)"],
  ["mobilepay.dk", TYPE.BOTH, "MobilePay (DK/FI)"],
  ["mollie.com", TYPE.BOTH, "Mollie payment service provider (NL)"],
  ["moneris.com", TYPE.BOTH, "Moneris payment processing (CA)"],
  ["monetaonline.it", TYPE.BOTH, "Moneta Online (Nexi) gateway (IT)"],
  ["multi-safepay.com", TYPE.BOTH, "MultiSafepay payment service provider (NL)"],
  ["netopia-payments.com", TYPE.BOTH, "Netopia payment gateway (RO)"],
  ["nexi.it", TYPE.BOTH, "Nexi payments (IT)"],
  ["nexigroup.com", TYPE.BOTH, "Nexi Group payments"],
  ["noda.live", TYPE.BOTH, "Noda open-banking payments"],
  ["nordpayments.com", TYPE.BOTH, "Nord Payments (DK)"],
  ["nubank.com.br", TYPE.BOTH, "Nubank 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["nuvei.com", TYPE.BOTH, "Nuvei payments"],
  ["ogone.com", TYPE.BOTH, "Ogone (Ingenico / Worldline) gateway"],
  ["onfastspring.com", TYPE.BOTH, "FastSpring checkout"],
  ["onlinepaymentplatform.nl", TYPE.BOTH, "Online Payment Platform (NL)"],
  ["opayo.co.uk", TYPE.BOTH, "Opayo (Elavon, formerly Sage Pay) gateway (UK)"],
  ["orbitalpaymentech.com", TYPE.BOTH, "Chase Orbital gateway"],
  ["paddle.com", TYPE.BOTH, "Paddle billing / merchant of record"],
  ["paddle.net", TYPE.BOTH, "Paddle checkout assets"],
  ["pagbank.com.br", TYPE.BOTH, "PagBank payments / 3-D Secure (BR) (kept: banks, user decision 2026-11-04)"],
  ["pagseguro.com.br", TYPE.BOTH, "PagSeguro payments (BR)"],
  ["pay.google.com", TYPE.BOTH, "Google Pay sheet"],
  ["pay.nl", TYPE.BOTH, "Pay.nl payment service provider (NL)"],
  ["paybox.com", TYPE.BOTH, "Paybox / Verifone gateway (FR)"],
  ["payments-amazon.com", TYPE.BOTH, "Amazon Pay checkout"],
  ["payone.com", TYPE.BOTH, "Payone payment provider (DE)"],
  ["paypal.com", TYPE.BOTH, "PayPal checkout"],
  ["paypalobjects.com", TYPE.BOTH, "PayPal checkout assets"],
  ["payplug.com", TYPE.BOTH, "PayPlug payment gateway (FR)"],
  ["payu.com", TYPE.BOTH, "PayU payment gateway"],
  ["payu.pl", TYPE.BOTH, "PayU payment gateway (PL)"],
  ["plaid.com", TYPE.BOTH, "Plaid bank-account linking for payments"],
  ["plugandpay.io", TYPE.BOTH, "Plug&Pay checkout (NL)"],
  ["postepay.it", TYPE.BOTH, "Postepay (Poste Italiane) payments"],
  ["pronamicpay.com", TYPE.BOTH, "Pronamic Pay checkout plug-in (NL)"],
  ["przelewy24.pl", TYPE.BOTH, "Przelewy24 bank transfers (PL)"],
  ["pse.com.co", TYPE.BOTH, "PSE bank-transfer scheme (CO)"],
  ["ratepay.com", TYPE.BOTH, "Ratepay buy-now-pay-later (DE)"],
  ["recurly.com", TYPE.BOTH, "Recurly subscription billing"],
  ["redsys.es", TYPE.BOTH, "Redsys card gateway / 3-D Secure (ES)"],
  ["revolut.com", TYPE.BOTH, "Revolut Pay / 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["riverty.com", TYPE.BOTH, "Riverty (Afterpay) pay-later (NL/DE)"],
  ["safecharge.com", TYPE.BOTH, "SafeCharge (Nuvei) gateway"],
  ["sagepay.com", TYPE.BOTH, "Sage Pay / Opayo gateway (UK)"],
  ["satispay.com", TYPE.BOTH, "Satispay mobile payments (IT)"],
  ["scalapay.com", TYPE.BOTH, "Scalapay buy-now-pay-later (IT)"],
  ["sella.it", TYPE.BOTH, "Banca Sella payments / 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["sia.eu", TYPE.BOTH, "SIA (Nexi) payment infrastructure"],
  ["siirto.fi", TYPE.BOTH, "Siirto mobile payments (FI)"],
  ["sisow.nl", TYPE.BOTH, "Sisow / Buckaroo payments (NL)"],
  ["squarecdn.com", TYPE.BOTH, "Square checkout assets"],
  ["squareup.com", TYPE.BOTH, "Square payments"],
  ["stripe.com", TYPE.BOTH, "Stripe payments"],
  ["stripe.network", TYPE.BOTH, "Stripe network helper"],
  ["stripecdn.com", TYPE.BOTH, "Stripe assets"],
  ["swish.nu", TYPE.BOTH, "Swish mobile payments (SE)"],
  ["tikkie.nl", TYPE.BOTH, "Tikkie payment requests (ABN AMRO, NL)"],
  ["tink.com", TYPE.BOTH, "Tink open-banking payments (Visa)"],
  ["tpay.com", TYPE.BOTH, "Tpay payment gateway (PL)"],
  ["transbank.cl", TYPE.BOTH, "Transbank card payments (CL)"],
  ["truelayer.com", TYPE.BOTH, "TrueLayer open-banking payments"],
  ["trustly.com", TYPE.BOTH, "Trustly pay-by-bank"],
  ["tsys.com", TYPE.BOTH, "TSYS (Global Payments) processing"],
  ["twint.ch", TYPE.BOTH, "TWINT mobile payments (CH)"],
  ["unicredit.it", TYPE.BOTH, "UniCredit 3-D Secure (kept: banks, user decision 2026-11-04)"],
  ["unzer.com", TYPE.BOTH, "Unzer payment platform (DE)"],
  ["verifone.cloud", TYPE.BOTH, "Verifone online checkout"],
  ["verifone.com", TYPE.BOTH, "Verifone payments"],
  ["vipps.no", TYPE.BOTH, "Vipps mobile payments (NO)"],
  ["vippsmobilepay.com", TYPE.BOTH, "Vipps MobilePay checkout"],
  ["visa.com", TYPE.BOTH, "Visa network / 3-D Secure (kept: user decision 2026-11-04)"],
  ["vyne.co.uk", TYPE.BOTH, "Vyne pay-by-bank (UK)"],
  ["walleypay.com", TYPE.BOTH, "Walley pay-later (Nordics)"],
  ["wero-wallet.eu", TYPE.BOTH, "Wero (European Payments Initiative) wallet"],
  ["wf.com", TYPE.BOTH, "Wells Fargo 3-D Secure / merchant services (kept: banks, user decision 2026-11-04)"],
  ["wfinterface.com", TYPE.BOTH, "Wells Fargo merchant interface (kept: banks, user decision 2026-11-04)"],
  ["worldline.com", TYPE.BOTH, "Worldline payment platform"],
  ["worldpay.com", TYPE.BOTH, "Worldpay payment gateway"],
  ["worldpaypayments.com", TYPE.BOTH, "Worldpay checkout"],
  ["x.klarnacdn.net", TYPE.BOTH, "Klarna checkout assets"]
]);

// ── Sign-in — Sign-in / single-sign-on hosts (frames and their assets).
const SIGN_IN = Object.freeze([
  ["account.microsoft.com", TYPE.FRAME, "Microsoft account frame"],
  ["accounts.google.com", TYPE.BOTH, "Google account sign-in"],
  ["appleid.apple.com", TYPE.FRAME, "Sign in with Apple"],
  ["auth0.com", TYPE.BOTH, "Auth0 (Okta) hosted sign-in"],
  ["bankid.com", TYPE.BOTH, "BankID — Nordic bank-grade digital identity"],
  ["clerk.com", TYPE.BOTH, "Clerk hosted sign-in"],
  ["cloudflareaccess.com", TYPE.BOTH, "Cloudflare Access sign-in"],
  ["descope.com", TYPE.BOTH, "Descope hosted sign-in"],
  ["descopecdn.com", TYPE.BOTH, "Descope sign-in assets"],
  ["digid.nl", TYPE.BOTH, "DigiD — Dutch government digital identity"],
  ["duosecurity.com", TYPE.BOTH, "Duo Security (Cisco) two-factor frame"],
  ["eherkenning.nl", TYPE.BOTH, "eHerkenning — Dutch business digital identity"],
  ["idmsa.apple.com", TYPE.FRAME, "Apple ID sign-in service"],
  ["itsme-id.com", TYPE.BOTH, "itsme — Belgian digital identity app"],
  ["login.live.com", TYPE.FRAME, "Microsoft account sign-in"],
  ["login.microsoftonline.com", TYPE.FRAME, "Microsoft Entra ID sign-in"],
  ["login.windows.net", TYPE.FRAME, "Microsoft Entra ID sign-in (legacy host)"],
  ["mitid.dk", TYPE.BOTH, "MitID — Danish government digital identity"],
  ["msauth.net", TYPE.BOTH, "Microsoft sign-in assets"],
  ["msftauth.net", TYPE.BOTH, "Microsoft sign-in assets"],
  ["okta.com", TYPE.BOTH, "Okta single sign-on"],
  ["onelogin.com", TYPE.BOTH, "OneLogin single sign-on"],
  ["passport.com", TYPE.BOTH, "Microsoft account (legacy Passport host)"],
  ["pingone.com", TYPE.BOTH, "PingOne (Ping Identity) hosted sign-in"],
  ["stytch.com", TYPE.BOTH, "Stytch hosted sign-in"],
  ["workos.com", TYPE.BOTH, "WorkOS enterprise sign-in"]
]);

// ── CAPTCHA or bot protection — CAPTCHA, challenge and bot-protection services.
const CAPTCHA = Object.freeze([
  ["altcha.org", TYPE.BOTH, "ALTCHA proof-of-work CAPTCHA"],
  ["arkoselabs.com", TYPE.BOTH, "Arkose Labs challenge"],
  ["awswaf.com", TYPE.BOTH, "AWS WAF CAPTCHA / challenge"],
  ["captcha-delivery.com", TYPE.BOTH, "DataDome challenge pages"],
  ["captcha-open-b.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud CAPTCHA"],
  ["captcha-open-southeast-b.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud CAPTCHA (SE Asia)"],
  ["captcha-open-southeast.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud CAPTCHA (SE Asia)"],
  ["captcha-open.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud CAPTCHA"],
  ["captcha.eu", TYPE.BOTH, "captcha.eu (EU-hosted CAPTCHA)"],
  ["captchafox.com", TYPE.BOTH, "CaptchaFox"],
  ["cdn.privatecaptcha.com", TYPE.BOTH, "Private Captcha"],
  ["challenges.cloudflare.com", TYPE.BOTH, "Cloudflare challenge pages"],
  ["client-api.arkoselabs.com", TYPE.BOTH, "Arkose Labs challenge API"],
  ["datadome.co", TYPE.BOTH, "DataDome bot protection"],
  ["frcapi.com", TYPE.BOTH, "Friendly Captcha API"],
  ["friendlycaptcha.com", TYPE.BOTH, "Friendly Captcha"],
  ["geetest.com", TYPE.BOTH, "GeeTest CAPTCHA"],
  ["hcaptcha.com", TYPE.FRAME, "hCaptcha challenge frame"],
  ["js.hcaptcha.com", TYPE.SCRIPT, "hCaptcha script"],
  ["moderate.cleantalk.org", TYPE.BOTH, "CleanTalk form anti-spam"],
  ["protechts.net", TYPE.BOTH, "HUMAN (PerimeterX) bot defence"],
  ["px-cdn.net", TYPE.BOTH, "HUMAN (PerimeterX) bot defence assets"],
  ["px-cloud.net", TYPE.BOTH, "HUMAN (PerimeterX) bot defence"],
  ["recaptcha.net", TYPE.BOTH, "Google reCAPTCHA"],
  ["static-captcha-sgp.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud CAPTCHA assets (Singapore)"],
  ["static-captcha.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud CAPTCHA assets"],
  ["static.geetest.com", TYPE.BOTH, "GeeTest CAPTCHA assets"],
  ["turnstile.cloudflare.com", TYPE.BOTH, "Cloudflare Turnstile"]
]);

// ── Fraud prevention — Checkout fraud prevention and identity verification (device fingerprinting libraries are NOT trusted — fpjscdn.net removed 4.5.6).
const FRAUD = Object.freeze([
  ["cloudauth-device-dualstack.cn-shanghai.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud device risk check"],
  ["cloudauth-device.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud device risk check"],
  ["cloudauth-device.ap-southeast-1.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud device risk check (SE Asia)"],
  ["device.saf.aliyuncs.com", TYPE.BOTH, "Alibaba Cloud fraud detection"],
  ["forter.com", TYPE.BOTH, "Forter checkout fraud prevention"],
  ["incognia.com", TYPE.BOTH, "Incognia fraud prevention"],
  ["iovation.com", TYPE.BOTH, "iovation (TransUnion) fraud prevention"],
  ["riskified.com", TYPE.BOTH, "Riskified checkout fraud prevention"],
  ["seon.io", TYPE.BOTH, "SEON fraud prevention"],
  ["sift.com", TYPE.BOTH, "Sift fraud prevention"],
  ["signifyd.com", TYPE.BOTH, "Signifyd checkout fraud prevention"],
  ["withpersona.com", TYPE.BOTH, "Persona identity verification"]
]);

// ── Video or audio player — Video / audio players and video platforms with an embeddable player.
const VIDEO = Object.freeze([
  ["bcove.video", TYPE.BOTH, "Brightcove player"],
  ["brightcove.com", TYPE.BOTH, "Brightcove video platform"],
  ["cdn.fluidplayer.com", TYPE.BOTH, "Fluid Player (open-source HTML5 player)"],
  ["cdn.jwplayer.com", TYPE.BOTH, "JW Player"],
  ["cdn.jwpltx.com", TYPE.BOTH, "JW Player analytics-free assets"],
  ["cdn.plyr.io", TYPE.BOTH, "Plyr (open-source HTML5 player)"],
  ["cloudflarestream.com", TYPE.BOTH, "Cloudflare Stream player"],
  ["content.jwplatform.com", TYPE.BOTH, "JW Player content"],
  ["dailymotion.com", TYPE.BOTH, "Dailymotion embeds"],
  ["dmcdn.net", TYPE.BOTH, "Dailymotion assets"],
  ["dmxleo.dailymotion.com", TYPE.BOTH, "Dailymotion player"],
  ["embed.mychannels.video", TYPE.BOTH, "MyChannels video embeds (NL publishers)"],
  ["ext-twitch.tv", TYPE.BOTH, "Twitch extensions"],
  ["f.vimeocdn.com", TYPE.BOTH, "Vimeo player assets"],
  ["fast.wistia.com", TYPE.BOTH, "Wistia player"],
  ["geo.dailymotion.com", TYPE.BOTH, "Dailymotion player"],
  ["googlevideo.com", TYPE.BOTH, "YouTube video streams"],
  ["i.vimeocdn.com", TYPE.BOTH, "Vimeo thumbnails"],
  ["jtvnw.net", TYPE.BOTH, "Twitch video assets"],
  ["jwpcdn.com", TYPE.BOTH, "JW Player assets"],
  ["jwplatform.com", TYPE.BOTH, "JW Player platform"],
  ["jwplayer.com", TYPE.BOTH, "JW Player"],
  ["kaltura.com", TYPE.BOTH, "Kaltura video platform"],
  ["loom.com", TYPE.BOTH, "Loom video embeds"],
  ["loomcdn.com", TYPE.BOTH, "Loom assets"],
  ["mux.com", TYPE.BOTH, "Mux video player"],
  ["panopto.com", TYPE.BOTH, "Panopto lecture video"],
  ["play.vidyard.com", TYPE.FRAME, "Vidyard player"],
  ["player.captivate.fm", TYPE.BOTH, "Captivate podcast player"],
  ["player.twitch.tv", TYPE.FRAME, "Twitch embedded player"],
  ["player.vimeo.com", TYPE.FRAME, "Vimeo embedded player"],
  ["players.brightcove.net", TYPE.BOTH, "Brightcove player"],
  ["releases.flowplayer.org", TYPE.BOTH, "Flowplayer"],
  ["rumble.com", TYPE.BOTH, "Rumble video embeds"],
  ["sproutvideo.com", TYPE.BOTH, "SproutVideo player"],
  ["ted.com", TYPE.BOTH, "TED talk embeds"],
  ["twitchcdn.net", TYPE.BOTH, "Twitch assets"],
  ["videodelivery.net", TYPE.BOTH, "Cloudflare Stream delivery"],
  ["vimeocdn.com", TYPE.BOTH, "Vimeo assets"],
  ["vjs.zencdn.net", TYPE.BOTH, "Video.js"],
  ["wistia.com", TYPE.BOTH, "Wistia video"],
  ["wistia.net", TYPE.BOTH, "Wistia assets"],
  ["youtu.be", TYPE.BOTH, "YouTube short links"],
  ["youtube-nocookie.com", TYPE.BOTH, "YouTube privacy-enhanced embeds"],
  ["youtube.com", TYPE.BOTH, "YouTube embeds"],
  ["ytimg.com", TYPE.BOTH, "YouTube thumbnails / player assets"]
]);

// ── Streaming embed — Music / podcast services with a genuine embed widget.
const STREAMING = Object.freeze([
  ["deezer.com", TYPE.FRAME, "Deezer embed widget"],
  ["mixcloud.com", TYPE.FRAME, "Mixcloud embed widget"],
  ["music.apple.com", TYPE.FRAME, "Apple Music embed widget"],
  ["scdn.co", TYPE.BOTH, "Spotify embed assets"],
  ["soundcloud.com", TYPE.BOTH, "SoundCloud embed widget"],
  ["spotify.com", TYPE.BOTH, "Spotify embed widget (open.spotify.com)"],
  ["spotifycdn.com", TYPE.BOTH, "Spotify embed assets (moved from the player group, 4.5.6)"]
]);

// ── Meeting embed — Meeting apps with a genuine embeddable meeting (chat platforms such as Discord are NOT meeting apps).
const MEETING = Object.freeze([
  ["8x8.vc", TYPE.BOTH, "8x8 Jitsi-based meeting embed"],
  ["daily.co", TYPE.BOTH, "Daily video-call embed (built for third-party embedding)"],
  ["goto.com", TYPE.BOTH, "GoTo (LogMeIn) meeting platform"],
  ["gotomeeting.com", TYPE.BOTH, "GoTo Meeting"],
  ["jitsi.org", TYPE.BOTH, "Jitsi Meet (open-source meeting platform)"],
  ["livestorm.co", TYPE.BOTH, "Livestorm webinar / meeting embed"],
  ["meet.google.com", TYPE.BOTH, "Google Meet"],
  ["meet.jit.si", TYPE.BOTH, "Jitsi Meet hosted instance (iframe API)"],
  ["teams.live.com", TYPE.BOTH, "Microsoft Teams (consumer) meeting embed"],
  ["teams.microsoft.com", TYPE.BOTH, "Microsoft Teams meeting embed"],
  ["webex.com", TYPE.BOTH, "Webex meeting embed"],
  ["whereby.com", TYPE.BOTH, "Whereby meeting embed"],
  ["zoom.com", TYPE.BOTH, "Zoom (secondary domain of zoom.us)"],
  ["zoom.us", TYPE.BOTH, "Zoom Web SDK meeting embed"],
  ["zoomgov.com", TYPE.BOTH, "Zoom for Government meeting embed"]
]);

// ── Gaming embed — Official game-store widgets only — no self-service marketplaces (itch.io) and no user-generated community sites (steamcommunity.com).
const GAMING = Object.freeze([
  ["steampowered.com", TYPE.BOTH, "Steam store widget (store.steampowered.com/widget) — official Valve store"]
]);

// ── Social post embed — Embedded posts from a social platform's own embed host (never the platform's main domain).
const SOCIAL = Object.freeze([
  ["embed.reddit.com", TYPE.BOTH, "Reddit post embeds (moved from the player group, 4.5.6)"]
]);

// ── Map or translation widget — Narrow widget hosts (maps, translation).
const WIDGET = Object.freeze([
  ["maps.googleapis.com", TYPE.BOTH, "Google Maps embeds"],
  ["translate.googleapis.com", TYPE.BOTH, "Google Translate website widget"]
]);

// ── JS / CSS / font library — Curated, maintainer-controlled libraries and fonts. jsdelivr / unpkg / esm.sh / npm stay out: anyone can publish there.
const LIBRARY = Object.freeze([
  ["ajax.googleapis.com", TYPE.BOTH, "Google Hosted Libraries"],
  ["ajax.microsoft.com", TYPE.SCRIPT, "Microsoft Ajax CDN"],
  ["aspnetcdn.com", TYPE.SCRIPT, "Microsoft Ajax CDN (moved from platform assets, 4.5.6)"],
  ["bootstrapcdn.com", TYPE.SCRIPT, "Bootstrap CDN"],
  ["cdn.datatables.net", TYPE.SCRIPT, "DataTables"],
  ["cdn.materialdesignicons.com", TYPE.SCRIPT, "Material Design Icons"],
  ["cdn.plot.ly", TYPE.SCRIPT, "Plotly"],
  ["cdn.tailwindcss.com", TYPE.SCRIPT, "Tailwind CSS play CDN"],
  ["cdnjs.cloudflare.com", TYPE.SCRIPT, "cdnjs (curated: every library reviewed before publishing)"],
  ["code.jquery.com", TYPE.SCRIPT, "jQuery CDN"],
  ["d3js.org", TYPE.SCRIPT, "D3.js"],
  ["fontawesome.com", TYPE.SCRIPT, "Font Awesome"],
  ["fonts.googleapis.com", TYPE.BOTH, "Google Fonts"],
  ["threejs.org", TYPE.SCRIPT, "three.js"],
  ["use.typekit.net", TYPE.SCRIPT, "Adobe Fonts"]
]);

// ── Platform vendor assets — Narrow static-asset hosts of a platform vendor — never its main domain and never a user-content host.
const PLATFORM = Object.freeze([
  ["awsstatic.com", TYPE.SCRIPT, "Amazon Web Services static assets"],
  ["cdn-apple.com", TYPE.SCRIPT, "Apple static assets"],
  ["dropboxstatic.com", TYPE.SCRIPT, "Dropbox static assets (never user files — dropboxusercontent.com is not listed)"],
  ["gfx.ms", TYPE.SCRIPT, "Microsoft sign-in / Office static assets"],
  ["githubassets.com", TYPE.SCRIPT, "GitHub static assets (never user files)"],
  ["gstatic.com", TYPE.BOTH, "Google static assets (reCAPTCHA, fonts, sign-in)"],
  ["office.net", TYPE.SCRIPT, "Microsoft Office CDN"]
]);

// Removed (4.5.6 review) or rejected as candidates (4.5.7: uBD's whitelist diff) — host → why. Kept so a
// decision is never silently undone (check-whitelist.mjs fails when one of these is listed) and so
// DownloadSentinel / uBlock Stripped Dynamic can apply the same review.
export const BUILTIN_REMOVED = Object.freeze({
  "discord.com": "Chat / community platform, not a meeting app; its attachment hosts deliver malware unchecked (real report 2026-11-04)",
  "discordapp.com": "Discord attachment CDN (cdn.discordapp.com) — user-uploaded files; on the download risk list",
  "discordapp.net": "Discord media CDN (media.discordapp.net) — user-uploaded files; on the download risk list",
  "itch.io": "Self-service marketplace: anyone uploads games (executables) — breaks the no-self-publish rule",
  "openai.com": "AI assistant, not sign-in/CAPTCHA/video/library; the AI category was removed in 4.3.6",
  "allianzdirect.com": "Insurer, not a payment provider",
  "profitwell.com": "Subscription analytics (Paddle), not payment",
  "fpjscdn.net": "FingerprintJS device fingerprinting — not trusted in a privacy firewall (user decision 2026-11-04)",
  "steamcommunity.com": "User-generated community pages, most-phished gaming domain (user decision 2026-11-04)",
  "slack.com": "Chat platform with user file uploads (files.slack.com) — the same hole as Discord",
  "bluejeans.com": "Service shut down (BlueJeans, 2024)",
  "skype.com": "Service shut down (Skype, May 2025)",
  "chime.aws": "Service shut down (Amazon Chime, February 2026)",
  "epicgames.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "battle.net": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "blizzard.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "xbox.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "xboxlive.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "playstation.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "playstation.net": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "nintendo.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "ea.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "ubisoft.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "riotgames.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "rockstargames.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "gog.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "minecraft.net": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "mojang.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "square-enix.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "capcom.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "konami.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "sega.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "bandainamcoent.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "nexon.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "ncsoft.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "netmarble.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "krafton.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "pubg.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "pearlabyss.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "smilegate.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "hoyoverse.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "mihoyo.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "garena.com": "Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "roblox.com": "User-generated games and a common malware / scam lure — Whole publisher / store site, not an embeddable widget — the Gaming category holds official store widgets only (4.5.6)",
  "accounts.youtube.com": "Already covered by youtube.com (Video or audio player)",
  "pingidentity.com": "Ping Identity's company site; its sign-in runs on pingone.com (added instead)",
  "gov.br": "Covers thousands of Brazilian government sites; tax/ID lookups run on the merchant's server, not in the browser",
  "sii.cl": "Tax authority; RUT lookups run on the merchant's server, not in the browser",
  "afip.gob.ar": "Tax authority; CUIT lookups run on the merchant's server, not in the browser",
  "sat.gob.mx": "Tax authority; RFC lookups run on the merchant's server, not in the browser",
  "whatsapp.com": "Consumer messaging app, no embed; click-to-chat buttons are plain links that need no whitelist",
  "whatsapp.net": "WhatsApp media host — user-uploaded files",
  "telegram.org": "On DownloadSentinel's malware-delivery list (check-whitelist.mjs refuses it); click-to-chat is a plain link",
  "signal.org": "Consumer messaging app, no embed; click-to-chat buttons are plain links",
  "viber.com": "Consumer messaging app, no embed; click-to-chat buttons are plain links"
});

// ── Compose (derived — never edit below) ────────────────────────────────────
const TABLES = Object.freeze([
  [BUILTIN_GROUP.PAYMENT, PAYMENT],
  [BUILTIN_GROUP.SIGN_IN, SIGN_IN],
  [BUILTIN_GROUP.CAPTCHA, CAPTCHA],
  [BUILTIN_GROUP.FRAUD, FRAUD],
  [BUILTIN_GROUP.VIDEO, VIDEO],
  [BUILTIN_GROUP.STREAMING, STREAMING],
  [BUILTIN_GROUP.MEETING, MEETING],
  [BUILTIN_GROUP.GAMING, GAMING],
  [BUILTIN_GROUP.SOCIAL, SOCIAL],
  [BUILTIN_GROUP.WIDGET, WIDGET],
  [BUILTIN_GROUP.LIBRARY, LIBRARY],
  [BUILTIN_GROUP.PLATFORM, PLATFORM]
]);

// Every entry as plain data: { host, type, category, reason } — for the check and the JSON export.
export const BUILTIN_ENTRIES = Object.freeze(TABLES.flatMap(([group, rows]) =>
  rows.map(([host, type, reason]) => Object.freeze({ host, type, category: group.label, reason }))));

function hostsOf(type) { return Object.freeze(BUILTIN_ENTRIES.filter((e) => e.type === type).map((e) => e.host).sort()); }

export const BUILTIN_BOTH = hostsOf(TYPE.BOTH);                 // script AND frame allowed
export const BUILTIN_SCRIPT_ONLY = hostsOf(TYPE.SCRIPT);
export const BUILTIN_FRAME_ONLY = hostsOf(TYPE.FRAME);
// 4.2: payment hosts only (any type) — blockPaymentHandlers's trustedExempt list.
export const BUILTIN_PAYMENT = Object.freeze(PAYMENT.map(([host]) => host).sort());
// 4.6.0: sign-in services — a password form on another site may legitimately send to them (warnPasswordForms).
export const BUILTIN_SIGN_IN = Object.freeze(SIGN_IN.map(([host]) => host).sort());
// Every built-in host (any type) — used to skip first-party scoring.
export const BUILTIN_ALL = Object.freeze([...BUILTIN_BOTH, ...BUILTIN_SCRIPT_ONLY, ...BUILTIN_FRAME_ONLY]);
// 4.2.1: category label per host — Show Matrix "Internal whitelist" tooltip (as in 3P-Matrix-lite).
export const BUILTIN_CATEGORY = Object.freeze(Object.fromEntries(BUILTIN_ENTRIES.map((e) => [e.host, e.category])));
// The popup's one-line summary of what is trusted (4.5.6: derived — it used to be a typed copy).
export const BUILTIN_SUMMARY = Object.freeze(Object.values(BUILTIN_GROUP).map((g) => g.summary).filter(Boolean));
