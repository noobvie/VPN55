/* ============================================================
   VENDORED — the Office Tools four-theme system. PINNED COPY.
   ============================================================

   Source : Office_Tools/js/common.js, the "Theme" block
   Commit : f0897cb105bdea4cdd27961e7f368802e780f188 (2026-07-23)
   Vendored: 2026-08-29, Phase 5. Licence: MIT.

   Pinned for the same reason as the stylesheet beside it: the admin UI must not
   change the day the tools site is restyled. The four themes and the
   `data-theme` attribute they set are carried over exactly — `light`, `dark`,
   `matrix`, `anime` — because those are the names the vendored stylesheet's
   selectors are written against, and renaming one here would silently unstyle it.

   TWO DELIBERATE DELTAS FROM UPSTREAM, both documented rather than quiet:

   1. STORAGE KEY is `vpn55-theme`, not `ot-theme`. Different origin, different
      product; a shared key name would only ever confuse someone debugging.

   2. DEFAULT is `dark`, not `matrix`. Upstream is a public tools site where the
      green terminal look is part of the pitch. This is an operations console
      read while something is wrong, and a saturated monochrome theme is a poor
      default for reading a table of numbers. Anyone who wants it is one click
      away and the choice sticks.

   THE LABELS ARE NOT HERE. Upstream carries an English label per theme inline;
   this file carries none, because every string this panel shows comes from a
   locale catalog. This exposes the theme LIST and the current name; app.js
   renders the label with t('theme.<name>').
   ============================================================ */
'use strict';

var VPN55_THEMES = ['light', 'dark', 'matrix', 'anime'];
var VPN55_THEME_DEFAULT = 'dark';
var VPN55_THEME_KEY = 'vpn55-theme';

/* Applied before first paint — this script is loaded ahead of the app so the
   page never renders in one theme and then jumps to another. */
(function () {
  var saved = null;
  try {
    saved = localStorage.getItem(VPN55_THEME_KEY);
  } catch (e) {
    /* Private windows and blocked site data both throw here rather than
       returning null. Neither is a reason to fail to render. */
  }
  var valid = VPN55_THEMES.indexOf(saved) >= 0 ? saved : VPN55_THEME_DEFAULT;
  document.documentElement.setAttribute('data-theme', valid);
})();

function vpn55CurrentTheme() {
  var current = document.documentElement.getAttribute('data-theme');
  return VPN55_THEMES.indexOf(current) >= 0 ? current : VPN55_THEME_DEFAULT;
}

function vpn55NextTheme() {
  var idx = VPN55_THEMES.indexOf(vpn55CurrentTheme());
  return VPN55_THEMES[(idx + 1) % VPN55_THEMES.length];
}

function vpn55SetTheme(name) {
  if (VPN55_THEMES.indexOf(name) < 0) return vpn55CurrentTheme();
  document.documentElement.setAttribute('data-theme', name);
  try {
    localStorage.setItem(VPN55_THEME_KEY, name);
  } catch (e) {
    /* The theme still applies for this page view; it just will not persist. */
  }
  return name;
}
