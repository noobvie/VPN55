#!/usr/bin/env node
//
// Locale key-parity check.
//
// Keyed catalogs, never phrase maps: the three files must carry an identical set
// of keys. English is the key-authoring source; Vietnamese is the default locale
// and the file that must never have a missing key.
//
// Exits non-zero on: unparseable JSON, a non-object catalog, a key present in one
// file and absent from another, or a value that is not a string.
//
// Run locally:  node .github/scripts/check-locales.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIR = join(REPO, 'panel', 'locales');

// English is the source of truth for which keys exist. Vietnamese is the default
// locale shown to users; French is the third catalog.
const SOURCE = 'en';
const LOCALES = ['vi', 'en', 'fr'];

const problems = [];
const rel = (p) => relative(REPO, p).replace(/\\/g, '/');

/** Flatten a nested catalog to dotted keys: { a: { b: "x" } } -> "a.b". */
function flatten(obj, prefix, out, file) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      flatten(v, key, out, file);
    } else if (typeof v === 'string') {
      out.set(key, v);
    } else {
      problems.push(`${file}: key "${key}" is ${Array.isArray(v) ? 'an array' : typeof v}, expected a string`);
    }
  }
  return out;
}

function load(locale) {
  const path = join(DIR, `${locale}.json`);
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    problems.push(`${rel(path)}: cannot read (${err.code || err.message})`);
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    problems.push(`${rel(path)}: invalid JSON — ${err.message}`);
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    problems.push(`${rel(path)}: top level must be an object`);
    return null;
  }
  return flatten(parsed, '', new Map(), rel(path));
}

const catalogs = new Map();
for (const locale of LOCALES) {
  const keys = load(locale);
  if (keys) catalogs.set(locale, keys);
}

if (catalogs.size === LOCALES.length) {
  // Union of every key seen anywhere — so a key invented in vi.json and never
  // authored in en.json is caught too, not just the missing-translation direction.
  const union = new Set();
  for (const keys of catalogs.values()) for (const k of keys.keys()) union.add(k);

  for (const locale of LOCALES) {
    const keys = catalogs.get(locale);
    const missing = [...union].filter((k) => !keys.has(k)).sort();
    if (missing.length) {
      const note = locale === 'vi'
        ? '  (vi is the DEFAULT locale — a missing key here is what most users see)'
        : locale === SOURCE
          ? '  (en is the key-authoring source — a key exists that was never authored here)'
          : '';
      problems.push(
        `panel/locales/${locale}.json: ${missing.length} missing key(s)${note}\n` +
        missing.map((k) => `    - ${k}`).join('\n')
      );
    }
    const blank = [...keys.entries()].filter(([, v]) => v.trim() === '').map(([k]) => k).sort();
    if (blank.length) {
      problems.push(
        `panel/locales/${locale}.json: ${blank.length} key(s) with an empty value — ` +
        'a blank string is worse than an untranslated one\n' +
        blank.map((k) => `    - ${k}`).join('\n')
      );
    }
  }

  const total = union.size;
  if (!problems.length) {
    console.log(
      total === 0
        ? `Locale parity OK — ${LOCALES.length} catalogs, no keys authored yet.`
        : `Locale parity OK — ${total} key(s) present in all ${LOCALES.length} catalogs.`
    );
  }
}

if (problems.length) {
  console.error('Locale check FAILED:\n');
  for (const p of problems) console.error(`  ${p}\n`);
  process.exit(1);
}
