'use strict';
//
// panel/portal/shell.js — the portal's HTML page, and the assets it may have.
//
// ── The page carries no sentence of its own ──────────────────────────────────
//
// Every visible string is a catalog key the client script resolves, and the
// catalog for the negotiated locale is INLINED, so the first paint is already
// in the viewer's language rather than a flash of key names. Vietnamese is the
// default and this is the surface most users see; a page that rendered in
// English for a moment would be rendering wrongly for the majority.
//
// ── The asset list is a list, not a directory ────────────────────────────────
//
// The admin panel serves panel/public as a static directory. The portal does
// not: it names the four shared files it needs, one route each, and serves its
// own two from panel/portal/public. That is three lines longer and it means
// app.js and actions.js — the admin UI's code — are not reachable from the
// socket the internet can see. Neither is a secret and neither would be a
// vulnerability; they are simply not this audience's, and a static mount would
// have handed them over by default rather than by decision.

const fs = require('node:fs');
const path = require('node:path');

const PANEL_PUBLIC = path.join(__dirname, '..', 'public');
const PORTAL_PUBLIC = path.join(__dirname, 'public');

/**
 * The shared files, by the exact URL each is served at.
 *
 * All four are generic: a theme switcher, a catalog resolver, an Intl wrapper
 * and the vendored theme tokens. None of them knows anything about the admin
 * panel, and none is duplicated here — a second copy of format.js would be a
 * second place for the "null is not zero" rule to be got wrong.
 *
 * panel.css is deliberately NOT in this list. It is the admin layer, sized for
 * a wide operations console. portal.css carries the Vietnamese `--font`
 * overrides itself for exactly that reason: the portal must not be one
 * stylesheet away from the mid-word fallback that override exists to fix.
 */
const SHARED_ASSETS = Object.freeze({
  '/assets/css/vendor/office-tools.css': path.join(PANEL_PUBLIC, 'css', 'vendor', 'office-tools.css'),
  '/assets/js/theme.js': path.join(PANEL_PUBLIC, 'js', 'theme.js'),
  '/assets/js/i18n.js': path.join(PANEL_PUBLIC, 'js', 'i18n.js'),
  '/assets/js/format.js': path.join(PANEL_PUBLIC, 'js', 'format.js'),
});

const OWN_ASSETS = Object.freeze({
  '/assets/css/portal.css': path.join(PORTAL_PUBLIC, 'css', 'portal.css'),
  '/assets/js/qr.js': path.join(PORTAL_PUBLIC, 'js', 'qr.js'),
  '/assets/js/portal.js': path.join(PORTAL_PUBLIC, 'js', 'portal.js'),
});

const ASSETS = Object.freeze({ ...SHARED_ASSETS, ...OWN_ASSETS });

const CONTENT_TYPES = { '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

/** Register one route per asset. No directory is exposed. */
function mountAssets(app) {
  for (const [url, file] of Object.entries(ASSETS)) {
    const type = CONTENT_TYPES[path.extname(file)] || 'application/octet-stream';
    app.get(url, (req, res) => {
      res.type(type);
      res.set('Cache-Control', 'no-store');
      res.sendFile(file, (err) => {
        if (!err) return;
        // A missing asset is a broken deployment, not a client error, and it is
        // worth being loud about: the page still renders and simply does not
        // work, which is the hardest kind of failure to report from a phone.
        if (!res.headersSent) res.status(404).type('text/plain').send('not found');
      });
    });
  }
  return Object.keys(ASSETS);
}

/** Are all of them actually there? Answered at startup, not at first request. */
function missingAssets() {
  const missing = [];
  for (const [url, file] of Object.entries(ASSETS)) {
    if (!fs.existsSync(file)) missing.push(`${url} -> ${file}`);
  }
  return missing;
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

/**
 * The shell page.
 *
 * `noindex, nofollow` and a referrer policy of `no-referrer` matter more here
 * than on the admin panel: this one is meant to be reachable, and a portal URL
 * turning up in a search index — or leaking to whatever a user clicks next — is
 * a list of somewhere worth probing.
 */
function render({ locale, cfg, catalogs }) {
  const boot = {
    locale,
    locales: cfg.locales,
    defaultLocale: cfg.default_locale,
    // The same cookie the admin panel uses for a display preference. It is not
    // a credential, it is per browser, and somebody who is both an operator and
    // a user should not have to choose their language twice.
    cookieName: 'vpn55_locale',
    strings: catalogs.catalog(locale),
  };
  // `</script>` inside JSON would close the tag early. The escape is the
  // standard one and is why this is not a bare JSON.stringify.
  const json = JSON.stringify(boot).replace(/</g, '\\u003c');

  return `<!doctype html>
<html lang="${esc(locale)}" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title data-i18n="portal.title"></title>
<link rel="stylesheet" href="/assets/css/vendor/office-tools.css">
<link rel="stylesheet" href="/assets/css/portal.css">
</head>
<body>
<script id="boot" type="application/json">${json}</script>
<script src="/assets/js/theme.js"></script>
<script src="/assets/js/i18n.js"></script>
<script src="/assets/js/format.js"></script>
<script src="/assets/js/qr.js"></script>
<script src="/assets/js/portal.js"></script>
</body>
</html>
`;
}

module.exports = { render, mountAssets, missingAssets, ASSETS, SHARED_ASSETS, OWN_ASSETS, esc };
