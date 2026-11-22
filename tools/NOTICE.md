# Notice — 3P Matrix — content firewall (tools)

Copyright (C) 2026 Kees1958 and co-authors. Distributed under the GNU General Public License v3 — the licence
text is `LICENSE.txt` in the extension package (3P-Matrix-<version>-extension.zip); third-party components and their
licences are listed in `THIRD_PARTY_LICENSES.md` there.

This package is never shipped inside the extension. Its scripts need the development dependencies in
`package.json` (acorn, eslint, espree, eslint-scope: MIT; playwright: Apache-2.0), which are installed with
`npm ci` and not included in this package.

`lists-raw/` holds cached copies of the upstream data files the list tools read (HaGeZi, Kees1958, Public
Suffix List, IANA RDAP bootstrap); each stays under its own licence, recorded per list in `data-sources.json`
("licence"). The Chrome UX Report top-sites list is not included: `update-top-sites.mjs` downloads it on
demand (CC BY 4.0, Google). `lists-src/` holds the curated lists of this project (GPLv3).
