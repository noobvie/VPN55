'use strict';
//
// panel/lib/i18n.js — keyed catalogs. Never a phrase map.
//
// `t('service.state.running')` against panel/locales/{vi,en,fr}.json. NOT a map
// keyed on English strings: a phrase map keyed on English word order misses
// every translator who reorders the sentence, and the failure is invisible
// because the two maps look identical. In a sibling project that shipped 27
// unbranded strings, the page title and a currency label among them.
//
// ── The rules this file enforces ─────────────────────────────────────────────
//
//  * VIETNAMESE IS THE DEFAULT LOCALE. English is the fallback and the
//    key-authoring source. vi.json is the file that must never have a missing
//    key — it is what most users see.
//  * A missing key falls back to English AND LOGS. A silent blank is worse than
//    an untranslated string, because nobody ever finds out about it.
//  * A key missing from English too returns the key itself, visibly. A blank
//    would read as a design decision.
//  * Locale is chosen per viewer, from a cookie, else Accept-Language, else the
//    configured default. NEVER from geography — where someone is standing is not
//    what language they read.
//
// Formatting (dates, numbers, byte sizes) is Intl, done in the browser where the
// viewer's own time zone is known. This file ships the catalog and the negotiated
// locale; it does not pre-render a single number.

const fs = require('node:fs');
const path = require('node:path');
const log = require('./log');

const DIR = path.join(__dirname, '..', 'locales');
const FALLBACK = 'en';

class Catalogs {
  constructor(locales, defaultLocale) {
    this.locales = locales;
    this.defaultLocale = defaultLocale;
    this.maps = new Map();
  }

  load() {
    for (const locale of this.locales) {
      const file = path.join(DIR, `${locale}.json`);
      let parsed;
      try {
        parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch (err) {
        throw new Error(`${file}: ${err.message}`);
      }
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error(`${file}: top level must be an object`);
      }
      this.maps.set(locale, flatten(parsed, '', new Map()));
    }

    // The same parity rule CI enforces, applied at startup — because CI checks
    // the repo and this checks what was actually deployed, and those are not
    // always the same tree.
    const union = new Set();
    for (const m of this.maps.values()) for (const k of m.keys()) union.add(k);
    for (const locale of this.locales) {
      const m = this.maps.get(locale);
      const missing = [...union].filter((k) => !m.has(k));
      if (missing.length) {
        const note = locale === this.defaultLocale ? ' (the DEFAULT locale — this is what most users see)' : '';
        log.warn(`${locale}.json is missing ${missing.length} key(s)${note}`, missing.slice(0, 10));
      }
    }
    log.info(`locales loaded — ${union.size} key(s) across ${this.locales.length} catalog(s)`);
    return this;
  }

  has(locale) {
    return this.maps.has(locale);
  }

  /** The whole catalog for a locale, English-filled, for the browser. */
  catalog(locale) {
    const target = this.maps.get(locale) || new Map();
    const fallback = this.maps.get(FALLBACK) || new Map();
    const out = Object.create(null);
    for (const [k, v] of fallback) out[k] = v;
    for (const [k, v] of target) out[k] = v;
    return out;
  }

  t(locale, key, vars) {
    const target = this.maps.get(locale);
    let value = target ? target.get(key) : undefined;
    if (value === undefined) {
      const fallback = this.maps.get(FALLBACK);
      value = fallback ? fallback.get(key) : undefined;
      if (value === undefined) {
        log.warnOnce(`missing-key:${key}`, `missing translation key "${key}" in every catalog`);
        return key;
      }
      log.warnOnce(`missing-key:${locale}:${key}`,
        `missing translation key "${key}" in ${locale}.json — falling back to ${FALLBACK}`);
    }
    return interpolate(value, vars);
  }

  /**
   * Pick a locale for this request. Cookie wins (the viewer said so), then
   * Accept-Language, then the configured default.
   */
  negotiate(cookieLocale, acceptLanguage) {
    if (cookieLocale && this.has(cookieLocale)) return cookieLocale;
    for (const tag of parseAcceptLanguage(acceptLanguage)) {
      if (this.has(tag)) return tag;
      const base = tag.split('-')[0];
      if (this.has(base)) return base;
    }
    return this.defaultLocale;
  }
}

/** { a: { b: "x" } } -> "a.b" */
function flatten(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else if (typeof v === 'string') out.set(key, v);
  }
  return out;
}

/** {name} placeholders. No pluralisation logic here — see the note below. */
function interpolate(template, vars) {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name) =>
    (Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : whole));
}

//
// There is deliberately no `+ 's'` anywhere in this file. Vietnamese has no
// plural inflection at all and French pluralises differently from English, so
// hand-rolled plural logic is wrong in two of the three locales this ships in.
// Where a count needs a word, the catalog carries a phrasing that works for any
// count in that language, and Intl.NumberFormat renders the number itself.
//

function parseAcceptLanguage(header) {
  if (!header) return [];
  return String(header)
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      let q = 1;
      for (const p of params) {
        const m = /^\s*q\s*=\s*([\d.]+)\s*$/.exec(p);
        if (m) q = Number(m[1]) || 0;
      }
      return { tag: tag.trim().toLowerCase(), q };
    })
    .filter((x) => x.tag && x.q > 0)
    .sort((a, b) => b.q - a.q)
    .map((x) => x.tag);
}

module.exports = { Catalogs, parseAcceptLanguage, FALLBACK };
