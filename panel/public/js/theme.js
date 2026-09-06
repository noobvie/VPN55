/* ============================================================
   VENDORED — the Office Tools four-theme system. PINNED COPY.
   ============================================================

   Source : Office_Tools/js/common.js, the "Theme" block
   Commit : f0897cb105bdea4cdd27961e7f368802e780f188 (2026-07-23)
   Vendored: 2026-08-29, Phase 5. Licence: MIT.

   Pinned for the same reason as the stylesheet beside it: the admin UI must not
   change the day the tools site is restyled. The `data-theme` attribute and the
   NAMES it takes are carried over exactly, because those names are what the
   vendored stylesheet's selectors are written against and renaming one here
   would silently unstyle it.

   THREE DELIBERATE DELTAS FROM UPSTREAM, all documented rather than quiet:

   1. STORAGE KEY is `vpn55-theme`, not `ot-theme`. Different origin, different
      product; a shared key name would only ever confuse someone debugging.

   2. DEFAULT is `dark`, not `matrix`. Upstream is a public tools site where the
      green terminal look is part of the pitch. This is an operations console
      read while something is wrong, and a saturated monochrome theme is a poor
      default for reading a table of numbers. Anyone who wants it is one click
      away and the choice sticks.

   3. THE LIST IS SHORTER, AND ONE NAME IN IT IS NOT UPSTREAM'S. Upstream offers
      light, dark, matrix and anime. This panel offers light, dark and `mina`.

      Removing a name from this list is the whole removal — the vendored
      stylesheet still carries its [data-theme="matrix"] and [data-theme="anime"]
      rules, and they simply never match, because nothing ever sets the
      attribute to those values again. That is on purpose: the pinned file stays
      byte-identical to upstream so a re-vendor is still a diff, and this list
      stays the one place that decides what a reader can actually reach.

      The two that went were the two that could not be read. The vendored anime
      palette put a warning badge at 1.93:1 and a quota bar at 1.80:1 against its
      own track, and its decoration sat at z-index 9999 over the top-bar
      controls; matrix was legible but is a saturated monochrome, which is a poor
      surface for a table of numbers. `mina` is defined in panel.css and
      portal.css rather than in the vendored file — see the block there.

      ⚠ A theme name that is no longer in this list may still be sitting in
      somebody's localStorage from before the change. vpn55SetTheme and the
      first-paint block below both validate against VPN55_THEMES and fall back
      to the default, so a stale `matrix` loads as `dark` rather than as an
      unstyled page. Do not remove that validation.

   THE LABELS ARE NOT HERE. Upstream carries an English label per theme inline;
   this file carries none, because every string this panel shows comes from a
   locale catalog. This exposes the theme LIST and the current name; app.js
   renders the label with t('theme.<name>').
   ============================================================ */
'use strict';

var VPN55_THEMES = ['light', 'dark', 'mina'];
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
