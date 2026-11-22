# 3P Matrix — new look-alike (phishing imitation) check · design in progress

Status: **design discussion, not implemented.** Decided with the user on 2026-10-19, step by step.
Shipped release at the time: 4.2.3. Part of protection 10 ("Warn when opening a site that looks suspicious").
Scope: replaces today's three overlapping imitation checks (generic digit-for-letter, 22-brand look-alike,
top-site look-alike). All other suspicious-site signals (abused TLD, IP host, free hosting/DDNS, odd port,
plain HTTP, punycode, brand typo by edit distance, …) stay as they are.

## Decided

### Test 1 — the site itself is popular → stop
The site's registered domain is looked up in the top-sites list (CrUX top 1M, Bloom filter). A hit means it is an
original, not an imitation (e.g. 1688.com, cloudflare.com, cornell.edu) → no look-alike check. Local, microseconds.
Known limit: ~1 % Bloom false positives → ~1 in 100 unknown look-alikes skipped.

### Test 2 — no imitation characters → stop (this check only)
Continue only when the name contains an imitation:
- **clear**: digits 1→l, 0→o, 5→s, 8→b *next to a letter* (digit runs like 365, 500px, 1688 are not imitations);
  **non-Latin letters that look Latin** (e.g. Cyrillic а for a);
- **questionable**: rn→m, vv→w, cl→d.
About 12 % of real top sites contain one. "Stop" ends only the look-alike check, never the other signals.

### Test 3 — convert and compare locally (multi-step, user design)
Variants, each checked in order, first hit wins (duplicates skipped):
1. all clear imitations converted (skipped when there is none — that is the original, handled by test 1);
2. all clear + the 1st questionable occurrence (left to right);
3. all clear + the 2nd questionable occurrence (when present);
4. all clear + all questionable occurrences.
With 3+ questionable occurrences, combinations like "1st + 3rd" are not tried (accepted).
Each variant is compared two ways:
- **whole name** against the top-sites list — only when the converted name has **≥ 5 letters** (measured: below 5
  letters accidental hits dominate, e.g. rnz→mz, tcl→td; from 5 letters 0.0–0.4 %);
- **separate words** (split on - and .) against the brand list — catches "microsoft-login", "paypa1-l0gin".
No clear/questionable distinction in matching: measured coincidence rates are equal per kind; length is what matters.

### Brand list — one list for every check
- Today: 113 brands (typo check) and 22 brands (look-alike) grew separately; 7 of the 22 are not in the 113.
  → **one merged list** (113 + 7 = 120) plus the regional extension below, each brand with its real website(s).
- Brands whose name is an **ordinary word or very short** (plus, target, free, orange, dirk, bell, post, lotto,
  metro, iceland, coop, spar, dia, ica, …) count **only when the whole site name is imitated**, never as a word
  inside another name. Names under 5 letters: exact match only (existing typo-check rule).
- Shared government suffixes (gov.uk, gov.br, gob.mx, gouv.fr …) are recognised as real sites; agency names
  (impots, ameli, elster, irs, sat …) are the brand words.
- brandtree.org: **dropped** (user, 2026-10-19) — brand names without websites; the curated ~600 list replaces it.

### Regions (user decision)
Five Eyes (US, UK, CA, AU, NZ), Europe (excluding Russia and Belarus), Middle America (Mexico + Central America),
South America, Korea, Japan. Phishing themes: parcel delivery, free groceries (supermarkets), lottery prizes.

### Warning and online checks
- A local match (imitation + look-alike of something known + not itself popular) **warns immediately** — no waiting
  for the network.
- Domain age (RDAP) and the two threat-intel DNS services run **inside the warning dialog** (as today) to set the
  severity and wording: young or blocked → red "possible phishing"; old and clean → orange, gentler wording.
  Measured accidental-hit rate ~1 in 1,000 converted names; those are usually old, clean domains.
- DNS lookups are ~10–300 ms (3 s is only the timeout); both services in parallel; answers cached 6 h.

### Top-sites list (revised 2026-10-19)
**Top 100,000 CrUX sites + every brand website** (518 of the 594 brand websites are in the top 100k; the other 76 —
smaller banks/post services such as snsbank.nl, knab.nl, triodos.nl, posta.sk — are added explicitly), ≈ 80k
domains, ≈ 125 KB instead of ≈ 1.2 MB. Still a data file **fetched lazily** when a site reaches test 3.
Refreshed once per minor release (update-top-sites.mjs + list-freshness suite step; the tool gets a rank cut-off
and adds the brand websites).

## Still open (next steps of the discussion)
- Exact severity rules in the dialog: domain-age thresholds (30 / 90 days). **Decided: no published age = treat as
  younger than 90 days** (RDAP does not always publish one, e.g. some ccTLD registries).
- ~~Wording of the warning reason~~ — **decided: "looks like paypal.com"**.
- ~~Refresh rule for the other lists~~ — **decided: HaGeZi abused TLDs, Public Suffix List and free-hosting/DDNS
  also refresh once per minor release** (port DownloadSentinel's proven list tools rather than rewrite them).
- Hyphen-count signal: measure on the top 1M first (DownloadSentinel dropped it as noisy).

## Regional brand list (verified)
Verified against the Chrome UX Report top-1M list (release 202609) on 2026-10-19 — every website below is in it.
Total new websites: **479** (plus the 113 + 7 existing brands).

| Group | # | Real websites |
|---|---|---|
| Netherlands + first EU set | 44 | ing.nl, rabobank.nl, abnamro.nl, snsbank.nl, asnbank.nl, regiobank.nl, knab.nl, bunq.com, triodos.nl, digid.nl, belastingdienst.nl, overheid.nl, uwv.nl, svb.nl, duo.nl, rdw.nl, cjib.nl, toeslagen.nl, postnl.nl, bol.com, coolblue.nl, marktplaats.nl, thuisbezorgd.nl, ah.nl, kpn.com, ziggo.nl, odido.nl, tikkie.me, ideal.nl, ns.nl, eneco.nl, vattenfall.nl, essent.nl, zalando.com, vinted.com, klarna.com, wise.com, n26.com, kbc.be, belfius.be, bpost.be, itsme-id.com, sparkasse.de, deutschepost.de |
| Germany | 14 | deutsche-bank.de, commerzbank.de, dkb.de, ing.de, postbank.de, comdirect.de, vr.de, elster.de, otto.de, telekom.de, vodafone.de, o2online.de, hermesworld.com, dpd.de |
| France | 20 | credit-agricole.fr, labanquepostale.fr, societegenerale.fr, boursobank.com, lcl.fr, caisse-epargne.fr, bnpparibas, ameli.fr, impots.gouv.fr, franceconnect.gouv.fr, ants.gouv.fr, laposte.fr, chronopost.fr, orange.fr, sfr.fr, free.fr, bouyguestelecom.fr, leboncoin.fr, fnac.com, cdiscount.com |
| Belgium | 4 | bnpparibasfortis.be, ing.be, argenta.be, proximus.be |
| Luxembourg | 3 | post.lu, spuerkeess.lu, bil.com |
| Spain | 10 | bancosantander.es, bbva.es, caixabank.es, bankinter.com, bancsabadell.com, agenciatributaria.gob.es, seg-social.es, correos.es, movistar.es, elcorteingles.es |
| Italy | 10 | intesasanpaolo.com, unicredit.it, poste.it, bancobpm.it, agenziaentrate.gov.it, inps.it, tim.it, vodafone.it, satispay.com, finecobank.com |
| Portugal | 6 | cgd.pt, millenniumbcp.pt, novobanco.pt, portaldasfinancas.gov.pt, ctt.pt, mbway.pt |
| Austria | 6 | sparkasse.at, raiffeisen.at, bawag.at, post.at, oesterreich.gv.at, bmf.gv.at |
| Ireland | 5 | aib.ie, bankofireland.com, revenue.ie, anpost.com, ptsb.ie |
| Poland | 9 | pkobp.pl, mbank.pl, pekao.com.pl, erste.pl, ing.pl, inpost.pl, allegro.pl, poczta-polska.pl, gov.pl |
| Sweden | 7 | swedbank.se, seb.se, handelsbanken.se, nordea.se, bankid.com, skatteverket.se, postnord.se |
| Denmark | 6 | danskebank.dk, mitid.dk, borger.dk, skat.dk, postnord.dk, mobilepay.dk |
| Finland | 5 | nordea.fi, op.fi, posti.fi, vero.fi, suomi.fi |
| Czechia | 4 | csas.cz, csob.cz, kb.cz, ceskaposta.cz |
| Romania | 5 | bancatransilvania.ro, bcr.ro, anaf.ro, posta-romana.ro, emag.ro |
| Greece | 6 | nbg.gr, eurobank.gr, alpha.gr, piraeusbank.gr, elta.gr, gov.gr |
| Hungary | 2 | otpbank.hu, posta.hu |
| United Kingdom | 12 | barclays.co.uk, lloydsbank.com, natwest.com, santander.co.uk, halifax.co.uk, nationwide.co.uk, monzo.com, gov.uk, royalmail.com, evri.com, bt.com, ee.co.uk |
| Switzerland | 5 | ubs.com, postfinance.ch, raiffeisen.ch, post.ch, twint.ch |
| Norway | 4 | dnb.no, vipps.no, posten.no, skatteetaten.no |
| United States | 18 | irs.gov, ssa.gov, usps.com, capitalone.com, discover.com, usbank.com, pnc.com, truist.com, venmo.com, zellepay.com, cash.app, att.com, verizon.com, t-mobile.com, walmart.com, target.com, bestbuy.com, xfinity.com |
| Canada | 11 | rbc.com, td.com, scotiabank.com, bmo.com, cibc.com, canadapost-postescanada.ca, canada.ca, interac.ca, desjardins.com, rogers.com, bell.ca |
| Mexico | 8 | bbva.mx, banorte.com, banamex.com, santander.com.mx, sat.gob.mx, gob.mx, mercadolibre.com.mx, telcel.com |
| Brazil | 12 | itau.com.br, bradesco.com.br, bb.com.br, caixa.gov.br, nubank.com.br, santander.com.br, gov.br, correios.com.br, mercadolivre.com.br, magazineluiza.com.br, picpay.com, bancointer.com.br |
| Argentina | 6 | bancogalicia.com.ar, bna.com.ar, mercadopago.com.ar, arca.gob.ar, santander.com.ar, bbva.com.ar |
| Chile | 4 | bancoestado.cl, santander.cl, bancochile.cl, sii.cl |
| Colombia | 4 | bancolombia.com, davivienda.com, dian.gov.co, nequi.com.co |
| Peru | 4 | viabcp.com, bbva.pe, interbank.pe, sunat.gob.pe |
| Australia | 16 | commbank.com.au, westpac.com.au, anz.com, nab.com.au, my.gov.au, ato.gov.au, servicesaustralia.gov.au, auspost.com.au, telstra.com.au, optus.com.au, woolworths.com.au, coles.com.au, aldi.com.au, thelott.com, linkt.com.au, afterpay.com |
| New Zealand | 14 | anz.co.nz, asb.co.nz, bnz.co.nz, westpac.co.nz, kiwibank.co.nz, ird.govt.nz, nzta.govt.nz, nzpost.co.nz, spark.co.nz, one.nz, woolworths.co.nz, paknsave.co.nz, newworld.co.nz, mylotto.co.nz |
| Japan | 19 | bk.mufg.jp, smbc.co.jp, mizuhobank.co.jp, japanpost.jp, jp-bank.japanpost.jp, rakuten.co.jp, rakuten-card.co.jp, nta.go.jp, docomo.ne.jp, au.com, softbank.jp, kuronekoyamato.co.jp, sagawa-exp.co.jp, aeon.co.jp, etc-meisai.jp, mercari.com, paypay.ne.jp, saisoncard.co.jp, jcb.co.jp |
| South Korea | 20 | kbstar.com, shinhan.com, wooribank.com, hanabank.com, nonghyup.com, kakaobank.com, toss.im, gov.kr, hometax.go.kr, epost.go.kr, cjlogistics.com, coupang.com, naver.com, kakao.com, kt.com, tworld.co.kr, lguplus.com, ssg.com, lotteon.com, dhlottery.co.kr |
| Rest of Europe (SK SI HR BG EE LV LT UA RS IS MT CY) | 31 | slsp.sk, tatrabanka.sk, posta.sk, nlb.si, posta.si, pbz.hr, zaba.hr, posta.hr, dskbank.bg, econt.com, speedy.bg, lhv.ee, swedbank.ee, eesti.ee, omniva.ee, swedbank.lv, latvija.gov.lv, swedbank.lt, seb.lt, privatbank.ua, monobank.ua, diia.gov.ua, novaposhta.ua, ukrposhta.ua, posta.rs, islandsbanki.is, arionbanki.is, island.is, bov.com, maltapost.com, bankofcyprus.com |
| Rest of South America (UY PY EC VE + supermarkets CL CO PE) | 8 | brou.com.uy, itau.com.py, pichincha.com, bancodevenezuela.com, jumbo.cl, lider.cl, exito.com, plazavea.com.pe |
| Central America (GT CR PA SV HN DO) | 11 | banrural.com.gt, bi.com.gt, bancobcr.com, bncr.fi.cr, correos.go.cr, banistmo.com, bgeneral.com, bancoagricola.com, ficohsa.com, banreservas.com, popularenlinea.com |
| Parcel delivery | 9 | dhl.com, dhl.de, ups.com, fedex.com, dpd.com, gls-group.com, gls-info.nl, myhermes.de, budbee.com |
| Supermarkets (free-groceries lures) | 28 | jumbo.com, lidl.nl, lidl.de, lidl.com, aldi.nl, aldi.com, aldi-nord.de, aldi-sued.de, plus.nl, dirk.nl, picnic.app, carrefour.fr, carrefour.com, leclerc, delhaize.be, colruyt.be, rewe.de, edeka.de, kaufland.de, tesco.com, sainsburys.co.uk, asda.com, morrisons.com, kroger.com, costco.com, mercadona.es, esselunga.it, conad.it |
| Lotteries (prize lures) | 14 | nederlandseloterij.nl, postcodeloterij.nl, vriendenloterij.nl, lotto.de, euro-millions.com, national-lottery.co.uk, fdj.fr, loteriasyapuestas.es, selae.es, lottomatica.it, powerball.com, megamillions.com, calottery.com, loterias.caixa.gov.br |
| United States | 11 | albertsons.com, safeway.com, publix.com, heb.com, wholefoodsmarket.com, aldi.us, traderjoes.com, wegmans.com, meijer.com, instacart.com, foodlion.com |
| United Kingdom | 6 | aldi.co.uk, lidl.co.uk, waitrose.com, coop.co.uk, iceland.co.uk, ocado.com |
| Canada | 8 | loblaws.ca, sobeys.com, metro.ca, walmart.ca, costco.ca, realcanadiansuperstore.ca, nofrills.ca, pcoptimum.ca |
| Mexico | 4 | walmart.com.mx, soriana.com, chedraui.com.mx, oxxo.com |
| Brazil | 4 | paodeacucar.com, assai.com.br, atacadao.com.br, carrefour.com.br |
| Argentina | 2 | coto.com.ar, diaonline.supermercadosdia.com.ar |
| Spain | 2 | carrefour.es, dia.es |
| Italy | 2 | coop.it, carrefour.it |
| Poland | 2 | biedronka.pl, zabka.pl |
| Sweden | 1 | ica.se |
| Denmark | 2 | netto.dk, salling.dk |
| Finland | 2 | k-ruoka.fi, s-kaupat.fi |
| Portugal | 2 | continente.pt, pingodoce.pt |
| Austria | 2 | billa.at, spar.at |
| Ireland | 2 | dunnesstores.com, supervalu.ie |
| Switzerland | 2 | migros.ch, coop.ch |
| Norway | 1 | rema.no |
