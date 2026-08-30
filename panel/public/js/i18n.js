'use strict';
/*
 * panel/public/js/i18n.js — the client half of the i18n layer.
 *
 * Every visible string in this UI resolves through t(). There is no English
 * sentence in the HTML, in app.js, or in an event record — a hardcoded string
 * is a string no translator will ever see.
 *
 * The catalog for the negotiated locale is inlined into the page by the server,
 * so the first paint is already in the viewer's language. Switching locale
 * fetches the other catalog and re-renders; it does not reload, so nothing is
 * lost, and the choice is stored in a cookie the server reads next time.
 *
 * A missing key returns the key itself, VISIBLY, and logs once. A blank would
 * read as a design decision and would never get reported.
 */

var VPN55_I18N = (function () {
  var boot = JSON.parse(document.getElementById('boot').textContent);
  var strings = boot.strings || {};
  var locale = boot.locale;
  var warned = Object.create(null);

  function t(key, vars) {
    var value = Object.prototype.hasOwnProperty.call(strings, key) ? strings[key] : undefined;
    if (value === undefined) {
      if (!warned[key]) {
        warned[key] = true;
        // Visible in the console, and visible on the page as the key itself.
        console.warn('vpn55: missing translation key', key, 'in', locale);
      }
      return key;
    }
    if (!vars) return value;
    return value.replace(/\{(\w+)\}/g, function (whole, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : whole;
    });
  }

  /**
   * A key that may not exist, with a fallback key. Used wherever a value comes
   * from an adapter and could be one this build has never heard of — a new
   * service state, a new filtering level. The unknown case gets its own phrasing
   * rather than an empty cell, because "we do not recognise this" and "there is
   * nothing here" are different answers.
   */
  function tOr(key, fallbackKey, vars) {
    if (Object.prototype.hasOwnProperty.call(strings, key)) return t(key, vars);
    return t(fallbackKey, vars);
  }

  function has(key) {
    return Object.prototype.hasOwnProperty.call(strings, key);
  }

  function current() { return locale; }
  function available() { return boot.locales.slice(); }

  function setCookie(value) {
    /* Lax, no expiry games: this is a display preference, not a session. Lax
     * rather than Strict on purpose — following a link into the panel should
     * arrive in the language the person chose, and a locale is not a credential.
     *
     * Secure matches what the session cookie does: set when the page is HTTPS,
     * dropped on a plain-HTTP loopback deployment, where a Secure cookie would
     * be discarded by the browser and the preference would silently never
     * persist. It is a per-viewer preference and it is stored per BROWSER;
     * nothing about it is inferred from where the viewer is. */
    var secure = window.location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = boot.cookieName + '=' + encodeURIComponent(value) +
      '; Path=/; Max-Age=31536000; SameSite=Lax' + secure;
  }

  function switchTo(next, onReady) {
    if (boot.locales.indexOf(next) < 0) return;
    fetch('/api/i18n/' + encodeURIComponent(next), { headers: { Accept: 'application/json' } })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (payload) {
        strings = payload.strings || {};
        locale = payload.locale;
        warned = Object.create(null);
        setCookie(locale);
        document.documentElement.setAttribute('lang', locale);
        if (onReady) onReady(locale);
      })
      .catch(function (err) {
        console.error('vpn55: could not load locale', next, err);
      });
  }

  /** Fill every [data-i18n] element in a subtree. */
  function apply(root) {
    var nodes = (root || document).querySelectorAll('[data-i18n]');
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].textContent = t(nodes[i].getAttribute('data-i18n'));
    }
    var attrs = (root || document).querySelectorAll('[data-i18n-title]');
    for (var j = 0; j < attrs.length; j++) {
      attrs[j].setAttribute('title', t(attrs[j].getAttribute('data-i18n-title')));
    }
  }

  return {
    t: t, tOr: tOr, has: has,
    current: current, available: available,
    switchTo: switchTo, apply: apply,
    pollSeconds: boot.pollSeconds,
  };
})();
