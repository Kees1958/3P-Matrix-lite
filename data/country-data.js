// ── data/country-data.js ──────────────────────────────────────────────────────
// Country → continent → spoken-language reference data. Pure data, no logic.
// Consumed by core/tld-engine.js, which turns it into the lookups behind the
// TLD whitelist's CONTINENT and WORLDWIDE auto-detection modes.
//
// Source: "Countries per continent with languages.docx" (196 sovereign
// countries). Antarctica is deliberately omitted — no permanent population,
// and its only entry (.aq, en) would just add noise to every English speaker's
// WORLDWIDE list.
//
// Data conventions:
//   - Entries are keyed by the country's ccTLD (lowercase, no dot), grouped
//     under a CONTINENTS value.
//   - The array lists the BASE language codes spoken there (the "nl" of
//     "nl-BE"). The region half of the source document's tags is dropped: it
//     always equals the TLD, with one exception — the UK, whose region code is
//     "gb" but whose TLD is "uk" (see REGION_TLD_EXCEPTIONS).
//   - Codes are stored exactly as the source document has them. Alias
//     normalisation (nb → no, etc.) happens at lookup time, in
//     core/tld-engine.js, via LANG_ALIASES below — so this data stays a
//     faithful copy of its source.
//   - Continent assignment follows the source document: Cyprus and Russia are
//     Europe, Türkiye/Georgia/Armenia/Azerbaijan/Kazakhstan are Asia, Central
//     America and the Caribbean are North America.
// ─────────────────────────────────────────────────────────────────────────────

// Continent identifiers — the only valid keys of COUNTRY_DATA/TERRITORY_DATA and
// the only values continent-resolution ever returns. Compare against these,
// never against bare strings.
export const CONTINENTS = Object.freeze({
  AFRICA:        "africa",
  NORTH_AMERICA: "north-america",
  SOUTH_AMERICA: "south-america",
  EUROPE:        "europe",
  ASIA:          "asia",
  OCEANIA:       "oceania"
});

// Sovereign countries, from the source document.
export const COUNTRY_DATA = {
  [CONTINENTS.AFRICA]: {
    dz: ["ar", "ber"],                          // Algeria
    ao: ["pt"],                                 // Angola
    bj: ["fr"],                                 // Benin
    bw: ["en", "tn"],                           // Botswana
    bf: ["fr", "mos"],                          // Burkina Faso
    bi: ["fr", "rn", "sw"],                     // Burundi
    cv: ["pt", "kea"],                          // Cabo Verde
    cm: ["fr", "en"],                           // Cameroon
    cf: ["fr", "sg"],                           // Central African Republic
    td: ["fr", "ar"],                           // Chad
    km: ["ar", "fr", "swb"],                    // Comoros
    cd: ["fr", "sw", "ln"],                     // Democratic Republic of the Congo
    dj: ["fr", "ar", "so", "aa"],               // Djibouti
    eg: ["ar"],                                 // Egypt
    gq: ["es", "fr", "pt"],                     // Equatorial Guinea
    er: ["ti", "ar", "en"],                     // Eritrea
    sz: ["en", "ss"],                           // Eswatini
    et: ["am", "om", "ti"],                     // Ethiopia
    ga: ["fr"],                                 // Gabon
    gm: ["en", "wo", "mnk"],                    // Gambia
    gh: ["en", "ak", "ee"],                     // Ghana
    gn: ["fr", "sus"],                          // Guinea
    gw: ["pt", "pov"],                          // Guinea-Bissau
    ci: ["fr"],                                 // Côte d’Ivoire
    ke: ["en", "sw"],                           // Kenya
    ls: ["en", "st"],                           // Lesotho
    lr: ["en"],                                 // Liberia
    ly: ["ar"],                                 // Libya
    mg: ["mg", "fr"],                           // Madagascar
    mw: ["en", "ny"],                           // Malawi
    ml: ["fr", "bm"],                           // Mali
    mr: ["ar", "fr"],                           // Mauritania
    mu: ["en", "fr", "mfe"],                    // Mauritius
    ma: ["ar", "ber", "fr"],                    // Morocco
    mz: ["pt"],                                 // Mozambique
    na: ["en", "af", "de", "na"],               // Namibia
    ne: ["fr", "ha", "dje"],                    // Niger
    ng: ["en", "ha", "yo", "ig"],               // Nigeria
    cg: ["fr", "ln"],                           // Republic of the Congo
    rw: ["rw", "en", "fr", "sw"],               // Rwanda
    st: ["pt"],                                 // São Tomé and Príncipe
    sn: ["fr", "wo"],                           // Senegal
    sc: ["en", "fr", "crs"],                    // Seychelles
    sl: ["en", "kri"],                          // Sierra Leone
    so: ["so", "ar"],                           // Somalia
    za: ["en", "af", "zu", "xh", "st", "tn", "ts", "ss", "ve", "nr", "nso"], // South Africa
    ss: ["en", "ar"],                           // South Sudan
    sd: ["ar", "en"],                           // Sudan
    tz: ["sw", "en"],                           // Tanzania
    tg: ["fr", "ee"],                           // Togo
    tn: ["ar", "fr"],                           // Tunisia
    ug: ["en", "sw", "lg"],                     // Uganda
    zm: ["en", "bem", "nya"],                   // Zambia
    zw: ["en", "sn", "nd"],                     // Zimbabwe
  },
  [CONTINENTS.NORTH_AMERICA]: {
    ag: ["en"],                                 // Antigua and Barbuda
    bs: ["en"],                                 // Bahamas
    bb: ["en"],                                 // Barbados
    bz: ["en", "es"],                           // Belize
    ca: ["en", "fr"],                           // Canada
    cr: ["es"],                                 // Costa Rica
    cu: ["es"],                                 // Cuba
    dm: ["en", "fr"],                           // Dominica
    do: ["es"],                                 // Dominican Republic
    sv: ["es"],                                 // El Salvador
    gd: ["en"],                                 // Grenada
    gt: ["es", "quc"],                          // Guatemala
    ht: ["fr", "ht"],                           // Haiti
    hn: ["es"],                                 // Honduras
    jm: ["en"],                                 // Jamaica
    mx: ["es"],                                 // Mexico
    ni: ["es"],                                 // Nicaragua
    pa: ["es"],                                 // Panama
    kn: ["en"],                                 // Saint Kitts and Nevis
    lc: ["en"],                                 // Saint Lucia
    vc: ["en"],                                 // Saint Vincent and the Grenadines
    tt: ["en"],                                 // Trinidad and Tobago
    us: ["en", "es"],                           // United States
  },
  [CONTINENTS.SOUTH_AMERICA]: {
    ar: ["es"],                                 // Argentina
    bo: ["es", "qu", "ay"],                     // Bolivia
    br: ["pt"],                                 // Brazil
    cl: ["es"],                                 // Chile
    co: ["es"],                                 // Colombia
    ec: ["es", "qu"],                           // Ecuador
    gy: ["en"],                                 // Guyana
    py: ["es", "gn"],                           // Paraguay
    pe: ["es", "qu", "ay"],                     // Peru
    sr: ["nl", "srn"],                          // Suriname
    uy: ["es"],                                 // Uruguay
    ve: ["es"],                                 // Venezuela
  },
  [CONTINENTS.EUROPE]: {
    al: ["sq"],                                 // Albania
    ad: ["ca", "es", "fr"],                     // Andorra
    at: ["de"],                                 // Austria
    by: ["be", "ru"],                           // Belarus
    be: ["nl", "fr", "de"],                     // Belgium
    ba: ["bs", "hr", "sr"],                     // Bosnia and Herzegovina
    bg: ["bg"],                                 // Bulgaria
    hr: ["hr"],                                 // Croatia
    cy: ["el", "tr"],                           // Cyprus
    cz: ["cs"],                                 // Czechia
    dk: ["da"],                                 // Denmark
    ee: ["et", "ru"],                           // Estonia
    fi: ["fi", "sv"],                           // Finland
    fr: ["fr"],                                 // France
    de: ["de"],                                 // Germany
    gr: ["el"],                                 // Greece
    hu: ["hu"],                                 // Hungary
    is: ["is"],                                 // Iceland
    ie: ["en", "ga"],                           // Ireland
    it: ["it"],                                 // Italy
    lv: ["lv", "ru"],                           // Latvia
    li: ["de"],                                 // Liechtenstein
    lt: ["lt", "ru"],                           // Lithuania
    lu: ["lb", "fr", "de"],                     // Luxembourg
    mt: ["mt", "en"],                           // Malta
    md: ["ro", "ru"],                           // Moldova
    mc: ["fr"],                                 // Monaco
    me: ["sr", "bs", "sq"],                     // Montenegro
    nl: ["nl", "fy"],                           // Netherlands
    mk: ["mk", "sq"],                           // North Macedonia
    no: ["nb", "nn", "se"],                     // Norway
    pl: ["pl"],                                 // Poland
    pt: ["pt"],                                 // Portugal
    ro: ["ro"],                                 // Romania
    ru: ["ru"],                                 // Russia
    sm: ["it"],                                 // San Marino
    rs: ["sr", "hu"],                           // Serbia
    sk: ["sk"],                                 // Slovakia
    si: ["sl"],                                 // Slovenia
    es: ["es", "ca", "eu", "gl"],               // Spain
    se: ["sv"],                                 // Sweden
    ch: ["de", "fr", "it", "rm"],               // Switzerland
    ua: ["uk"],                                 // Ukraine
    uk: ["en", "cy", "gd"],                     // United Kingdom
    va: ["it", "la"],                           // Vatican City
  },
  [CONTINENTS.ASIA]: {
    af: ["ps", "fa"],                           // Afghanistan
    am: ["hy"],                                 // Armenia
    az: ["az"],                                 // Azerbaijan
    bh: ["ar", "en"],                           // Bahrain
    bd: ["bn"],                                 // Bangladesh
    bt: ["dz", "en"],                           // Bhutan
    bn: ["ms", "en"],                           // Brunei
    kh: ["km"],                                 // Cambodia
    cn: ["zh"],                                 // China
    ge: ["ka"],                                 // Georgia
    in: ["hi", "en", "bn", "te", "mr", "ta", "gu", "ur", "kn", "ml", "pa"], // India
    id: ["id", "jv", "su"],                     // Indonesia
    ir: ["fa"],                                 // Iran
    iq: ["ar", "ku"],                           // Iraq
    il: ["he", "ar"],                           // Israel
    jp: ["ja"],                                 // Japan
    jo: ["ar"],                                 // Jordan
    kz: ["kk", "ru"],                           // Kazakhstan
    kw: ["ar", "en"],                           // Kuwait
    kg: ["ky", "ru"],                           // Kyrgyzstan
    la: ["lo"],                                 // Laos
    lb: ["ar", "fr", "en"],                     // Lebanon
    my: ["ms", "en", "zh", "ta"],               // Malaysia
    mv: ["dv"],                                 // Maldives
    mn: ["mn"],                                 // Mongolia
    mm: ["my", "en"],                           // Myanmar
    np: ["ne"],                                 // Nepal
    kp: ["ko"],                                 // North Korea
    om: ["ar", "en"],                           // Oman
    pk: ["ur", "en", "pa", "sd"],               // Pakistan
    ps: ["ar"],                                 // Palestine
    ph: ["fil", "en"],                          // Philippines
    qa: ["ar", "en"],                           // Qatar
    sa: ["ar"],                                 // Saudi Arabia
    sg: ["en", "zh", "ms", "ta"],               // Singapore
    kr: ["ko"],                                 // South Korea
    lk: ["si", "ta"],                           // Sri Lanka
    sy: ["ar"],                                 // Syria
    tw: ["zh"],                                 // Taiwan
    tj: ["tg", "ru"],                           // Tajikistan
    th: ["th"],                                 // Thailand
    tl: ["pt", "tet"],                          // Timor-Leste
    tr: ["tr"],                                 // Türkiye
    tm: ["tk"],                                 // Turkmenistan
    ae: ["ar", "en"],                           // United Arab Emirates
    uz: ["uz", "ru"],                           // Uzbekistan
    vn: ["vi"],                                 // Vietnam
    ye: ["ar"],                                 // Yemen
  },
  [CONTINENTS.OCEANIA]: {
    au: ["en"],                                 // Australia
    fj: ["en", "fj", "hi"],                     // Fiji
    ki: ["en", "gil"],                          // Kiribati
    mh: ["en", "mh"],                           // Marshall Islands
    fm: ["en"],                                 // Micronesia
    nr: ["en", "na"],                           // Nauru
    nz: ["en", "mi"],                           // New Zealand
    pw: ["en", "pau"],                          // Palau
    pg: ["en", "tpi", "ho"],                    // Papua New Guinea
    ws: ["sm", "en"],                           // Samoa
    sb: ["en"],                                 // Solomon Islands
    to: ["to", "en"],                           // Tonga
    tv: ["tvl", "en"],                          // Tuvalu
    vu: ["bi", "en", "fr"],                     // Vanuatu
  },
};

// Supplement: territories the source document (sovereign countries only) leaves
// out, but that carry their own ccTLD and that the previous hand-picked tables
// already used. Same shape as COUNTRY_DATA. Add a line here to teach the engine
// about another territory — no code change needed. Continents are geographic:
// Greenland is North America, the Faroe Islands and the Isle of Man are Europe.
export const TERRITORY_DATA = {
  [CONTINENTS.NORTH_AMERICA]: {
    aw: ["nl", "pap"],                          // Aruba
    cw: ["nl", "pap"],                          // Curaçao
    gl: ["kl", "da"],                           // Greenland
  },
  [CONTINENTS.EUROPE]: {
    fo: ["fo", "da"],                           // Faroe Islands
    im: ["en", "gv"],                           // Isle of Man
  },
  [CONTINENTS.ASIA]: {
    hk: ["zh", "en"],                           // Hong Kong
    mo: ["zh", "pt"],                           // Macao
  },
};

// Region subtags whose ccTLD differs from the region code itself. Every other
// region subtag in a browser language tag (nl-BE → "be") already equals its ccTLD.
export const REGION_TLD_EXCEPTIONS = Object.freeze({
  gb: "uk"   // en-GB → .uk (".gb" exists but is effectively unused)
});

// Language-code aliases, applied to BOTH the browser's tags and this file's
// codes before comparing, so e.g. a browser reporting "nb" (Norwegian Bokmål)
// matches a country listed as "nn"/"no". Left side → canonical right side.
export const LANG_ALIASES = Object.freeze({
  nb: "no",    // Norwegian Bokmål
  nn: "no",    // Norwegian Nynorsk
  tl: "fil",   // Tagalog → Filipino
  iw: "he",    // legacy Hebrew code
  in: "id"     // legacy Indonesian code
});

// Groups of languages that are readily understood in writing by speakers of the
// others (reading intelligibility). Used by CONTINENT and WORLDWIDE: a browser
// language counts as ALSO speaking every other language in its group, so e.g.
// a Danish speaker also gets the Norwegian and Swedish countries (on their
// continent for CONTINENT, anywhere for WORLDWIDE), and an Indonesian speaker in
// Asia also gets the Malay-speaking ones. Relations are symmetric within a group.
// Codes are canonical (see LANG_ALIASES): "no" covers nb/nn. "cnr" (Montenegrin)
// is rarely sent by browsers but is listed so a browser that does gets the group.
// Add a line to add a group — no code change needed.
export const MUTUALLY_INTELLIGIBLE_LANGS = Object.freeze([
  ["cs", "sk"],                 // Czech – Slovak
  ["sr", "hr", "bs", "cnr"],    // Serbian – Croatian – Bosnian – Montenegrin
  ["id", "ms"],                 // Indonesian – Malay
  ["da", "no", "sv"]            // Danish – Norwegian – Swedish
]);

// One-way relations: [language of the reader, language that reader can also read].
// For pairs where comprehension is clearly lopsided, so only the reader's side
// gains. Same mechanism and scope as MUTUALLY_INTELLIGIBLE_LANGS, one direction.
//   pt → es: Portuguese speakers cope with Spanish well, Spanish speakers with
//   Portuguese less so — mostly a listening effect (Portuguese has far more vowel
//   sounds and heavier reduction), smaller in writing, but treated as one-way here
//   by explicit choice. So a Portuguese speaker also gets the Spanish-speaking
//   countries; a Spanish speaker does NOT get the Portuguese-speaking ones.
export const ONE_WAY_INTELLIGIBLE_LANGS = Object.freeze([
  ["pt", "es"],   // Portuguese reader → Spanish
  ["sl", "hr"]    // Slovenian reader → Croatian — reading scores are clearly asymmetric
                  // (Slovenian→Croatian ~94% vs Croatian→Slovenian ~64%, Golubović & Gooskens)
]);

// ccTLDs that language-based expansion (CONTINENT/WORLDWIDE) never ADDS, carried
// over unchanged from the previous hand-picked table's decision ("excluded for
// geopolitical reasons"). This only stops them being added because someone
// speaks Russian or a related language: a browser whose own region tag IS
// ru/by still gets it from the BROWSER level, and a user can still add either
// by hand.
export const EXPANSION_EXCLUDED_TLDS = Object.freeze(["ru", "by"]);

// ── Browser time zone → continent ────────────────────────────────────────────
// Fallback for when no browser language tag names a usable region ("en" on its
// own, es-419, …). Matched in this order: exact zone name, then a name prefix,
// then the first path segment ("Europe/Amsterdam" → "Europe"). A guess, not a
// fact: it only ever picks a continent, never a country.
export const TIMEZONE_AREA_DEFAULT = Object.freeze({
  Europe:    CONTINENTS.EUROPE,
  Africa:    CONTINENTS.AFRICA,
  Asia:      CONTINENTS.ASIA,
  Australia: CONTINENTS.OCEANIA,
  Pacific:   CONTINENTS.OCEANIA,
  America:   CONTINENTS.NORTH_AMERICA,   // South America carved out below
  Atlantic:  CONTINENTS.EUROPE,          // exceptions below
  Indian:    CONTINENTS.AFRICA,          // exceptions below
  Arctic:    CONTINENTS.EUROPE           // Svalbard
  // Antarctica/*, Etc/*, UTC, GMT deliberately absent → no guess
});

export const TIMEZONE_PREFIX_EXCEPTIONS = Object.freeze({
  "America/Argentina/": CONTINENTS.SOUTH_AMERICA
});

export const TIMEZONE_EXCEPTIONS = Object.freeze({
  // South America (the rest of "America/*" is North America)
  "America/Araguaina": CONTINENTS.SOUTH_AMERICA, "America/Asuncion": CONTINENTS.SOUTH_AMERICA,
  "America/Bahia": CONTINENTS.SOUTH_AMERICA, "America/Belem": CONTINENTS.SOUTH_AMERICA,
  "America/Boa_Vista": CONTINENTS.SOUTH_AMERICA, "America/Bogota": CONTINENTS.SOUTH_AMERICA,
  "America/Buenos_Aires": CONTINENTS.SOUTH_AMERICA, "America/Campo_Grande": CONTINENTS.SOUTH_AMERICA,
  "America/Caracas": CONTINENTS.SOUTH_AMERICA, "America/Catamarca": CONTINENTS.SOUTH_AMERICA,
  "America/Cayenne": CONTINENTS.SOUTH_AMERICA, "America/Cordoba": CONTINENTS.SOUTH_AMERICA,
  "America/Cuiaba": CONTINENTS.SOUTH_AMERICA, "America/Eirunepe": CONTINENTS.SOUTH_AMERICA,
  "America/Fortaleza": CONTINENTS.SOUTH_AMERICA, "America/Guayaquil": CONTINENTS.SOUTH_AMERICA,
  "America/Guyana": CONTINENTS.SOUTH_AMERICA, "America/Jujuy": CONTINENTS.SOUTH_AMERICA,
  "America/La_Paz": CONTINENTS.SOUTH_AMERICA, "America/Lima": CONTINENTS.SOUTH_AMERICA,
  "America/Maceio": CONTINENTS.SOUTH_AMERICA, "America/Manaus": CONTINENTS.SOUTH_AMERICA,
  "America/Mendoza": CONTINENTS.SOUTH_AMERICA, "America/Montevideo": CONTINENTS.SOUTH_AMERICA,
  "America/Noronha": CONTINENTS.SOUTH_AMERICA, "America/Paramaribo": CONTINENTS.SOUTH_AMERICA,
  "America/Porto_Acre": CONTINENTS.SOUTH_AMERICA, "America/Porto_Velho": CONTINENTS.SOUTH_AMERICA,
  "America/Punta_Arenas": CONTINENTS.SOUTH_AMERICA, "America/Recife": CONTINENTS.SOUTH_AMERICA,
  "America/Rio_Branco": CONTINENTS.SOUTH_AMERICA, "America/Rosario": CONTINENTS.SOUTH_AMERICA,
  "America/Santarem": CONTINENTS.SOUTH_AMERICA, "America/Santiago": CONTINENTS.SOUTH_AMERICA,
  "America/Sao_Paulo": CONTINENTS.SOUTH_AMERICA,
  "Atlantic/Stanley": CONTINENTS.SOUTH_AMERICA, "Atlantic/South_Georgia": CONTINENTS.SOUTH_AMERICA,
  "Pacific/Galapagos": CONTINENTS.SOUTH_AMERICA, "Pacific/Easter": CONTINENTS.SOUTH_AMERICA,
  // North America (politically/geographically, despite the area name)
  "Atlantic/Bermuda": CONTINENTS.NORTH_AMERICA, "Pacific/Honolulu": CONTINENTS.NORTH_AMERICA,
  // Africa
  "Atlantic/Cape_Verde": CONTINENTS.AFRICA, "Atlantic/St_Helena": CONTINENTS.AFRICA,
  // Asia / Oceania inside the "Indian" area
  "Indian/Maldives": CONTINENTS.ASIA, "Indian/Chagos": CONTINENTS.ASIA,
  "Indian/Christmas": CONTINENTS.OCEANIA, "Indian/Cocos": CONTINENTS.OCEANIA
});
