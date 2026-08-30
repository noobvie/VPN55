'use strict';
/*
 * panel/public/js/format.js — every number and instant that reaches the screen.
 *
 * The server sends raw values on purpose: bytes as integers, instants as Unix
 * epochs, counts as counts. Formatting happens HERE because this is the only
 * place that knows the viewer's locale and time zone. A byte count formatted on
 * the server arrives pre-translated into the wrong language and cannot be
 * un-formatted; a timestamp formatted on the server arrives in the server's time
 * zone, which is a fact about the machine and not about the person reading it.
 *
 * ── The rule that runs through all of it ─────────────────────────────────────
 *
 * `null` means NO READING, and it renders as an em dash. It is never 0, never
 * "never", and never an empty cell that reads as a design choice. Three of the
 * functions below take a value that can legitimately be null and every one of
 * them returns the dash rather than guessing — because the guess is what turns
 * "this daemon could not be asked" into "this user has used nothing", and those
 * two get opposite decisions from whoever is reading.
 */

var VPN55_FMT = (function () {
  var DASH = '—';   // em dash

  function localeTag() {
    // The catalog locale is the right tag for numbers and dates too: someone
    // reading the panel in Vietnamese wants Vietnamese grouping and date order.
    // BCP 47 wants a region for some formats; the bare language tag is valid and
    // Intl resolves it, so no region is invented here.
    return (typeof VPN55_I18N !== 'undefined' && VPN55_I18N.current()) || 'en';
  }

  /* ── Bytes ────────────────────────────────────────────────────────────────
   *
   * Binary units, and labelled as binary units. A tunnel's counters are byte
   * counts from the kernel, and every tool an operator will cross-check against
   * — `ip -s link`, the daemons' own status output — divides by 1024. Showing
   * 1.07 GB where the other window says 1.00 GiB invites the conclusion that one
   * of them is wrong.
   *
   * The unit word is NOT translated. KiB/MiB/GiB are IEC symbols, the same in
   * every locale; "translating" them would be inventing a unit. The NUMBER is
   * localised, which is the part that actually differs — 1.234,5 against 1,234.5.
   */
  var UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

  function bytes(value) {
    if (value === null || value === undefined) return DASH;
    if (typeof value !== 'number' || !isFinite(value)) return DASH;
    if (value === 0) return numeric(0) + ' B';

    var i = 0;
    var n = Math.abs(value);
    while (n >= 1024 && i < UNITS.length - 1) { n = n / 1024; i++; }
    if (value < 0) n = -n;

    // Plain bytes are whole; everything above gets one or two decimals so a
    // column of values stays comparable at a glance without becoming noise.
    var decimals = i === 0 ? 0 : (n < 10 ? 2 : 1);
    return numeric(n, decimals) + ' ' + UNITS[i];
  }

  function numeric(value, decimals) {
    if (value === null || value === undefined) return DASH;
    try {
      return new Intl.NumberFormat(localeTag(), {
        minimumFractionDigits: decimals || 0,
        maximumFractionDigits: decimals || 0,
      }).format(value);
    } catch (e) {
      return String(value);
    }
  }

  function percent(fraction) {
    // null is unlimited, and unlimited has no percentage. Rendering it as 0%
    // would put every unlimited user at the bottom of a "closest to quota" sort.
    if (fraction === null || fraction === undefined) return DASH;
    try {
      return new Intl.NumberFormat(localeTag(), {
        style: 'percent',
        maximumFractionDigits: fraction < 0.1 ? 1 : 0,
      }).format(fraction);
    } catch (e) {
      return Math.round(fraction * 100) + '%';
    }
  }

  /* ── Instants ─────────────────────────────────────────────────────────────
   *
   * Epoch seconds in, the viewer's time zone out. Absolute time in the title
   * attribute of every relative one, always — "3 hours ago" is easy to read and
   * impossible to correlate with a log file, and the moment anyone is actually
   * debugging they need the timestamp.
   */
  function absolute(epochSeconds) {
    if (epochSeconds === null || epochSeconds === undefined) return DASH;
    try {
      return new Intl.DateTimeFormat(localeTag(), {
        dateStyle: 'medium', timeStyle: 'medium',
      }).format(new Date(epochSeconds * 1000));
    } catch (e) {
      return new Date(epochSeconds * 1000).toISOString();
    }
  }

  var RELATIVE_STEPS = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 7],
    ['week', 4.348],
    ['month', 12],
    ['year', Infinity],
  ];

  /*
   * Intl.RelativeTimeFormat does the grammar, in every locale, including the
   * ones where "3 days ago" is not a matter of appending a word. This is exactly
   * the place a hand-rolled `n + ' ' + unit + (n === 1 ? '' : 's')` would be
   * wrong in two of our three languages and unfixable in a translation file.
   */
  function relative(epochSeconds, nowSeconds) {
    if (epochSeconds === null || epochSeconds === undefined) return DASH;
    var now = nowSeconds || Math.floor(Date.now() / 1000);
    var delta = epochSeconds - now;
    var abs = Math.abs(delta);

    try {
      var rtf = new Intl.RelativeTimeFormat(localeTag(), { numeric: 'auto' });
      var unit = 'second';
      var value = delta;
      for (var i = 0; i < RELATIVE_STEPS.length; i++) {
        if (abs < RELATIVE_STEPS[i][1]) { unit = RELATIVE_STEPS[i][0]; break; }
        abs = abs / RELATIVE_STEPS[i][1];
        value = value / RELATIVE_STEPS[i][1];
      }
      return rtf.format(Math.round(value), unit);
    } catch (e) {
      return absolute(epochSeconds);
    }
  }

  /* Duration, for "running since" — a length of time, not a point in one. */
  function duration(seconds) {
    if (seconds === null || seconds === undefined || seconds < 0) return DASH;
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var parts = [];
    // The unit letters here come from the catalog, because d/h/m are words in
    // every language even when they are one letter long.
    var T = (typeof VPN55_I18N !== 'undefined') ? VPN55_I18N.t : function (k) { return k; };
    if (d) parts.push(numeric(d) + T('unit.days.short'));
    if (h || d) parts.push(numeric(h) + T('unit.hours.short'));
    if (!d) parts.push(numeric(m) + T('unit.minutes.short'));
    return parts.join(' ');
  }

  /*
   * A handshake is three states, and it stays three states right to the pixel.
   *   'at'      → when
   *   'never'   → this credential has never connected
   *   'unknown' → the service keeps no history, which is NOT "never"
   * Collapsing the last two tells an operator that a user who connected
   * yesterday never has, and that is the kind of wrong that gets access removed.
   */
  function handshake(h, nowSeconds) {
    var T = VPN55_I18N.t;
    if (!h || h.kind === 'unknown') return { text: T('value.unknown'), title: T('value.unknown.help') };
    if (h.kind === 'never') return { text: T('value.never'), title: T('value.never.help') };
    return { text: relative(h.at, nowSeconds), title: absolute(h.at) };
  }

  /** An ISO date string from the registry (or null for "never expires"). */
  function isoDate(value) {
    if (!value) return DASH;
    var t = Date.parse(value);
    if (isNaN(t)) return String(value);
    try {
      return new Intl.DateTimeFormat(localeTag(), { dateStyle: 'medium' }).format(new Date(t));
    } catch (e) {
      return String(value);
    }
  }

  /** Text straight into a text node — never innerHTML anywhere in this app. */
  function text(value) {
    return (value === null || value === undefined || value === '') ? DASH : String(value);
  }

  return {
    DASH: DASH,
    bytes: bytes,
    numeric: numeric,
    percent: percent,
    absolute: absolute,
    relative: relative,
    duration: duration,
    handshake: handshake,
    isoDate: isoDate,
    text: text,
  };
})();
