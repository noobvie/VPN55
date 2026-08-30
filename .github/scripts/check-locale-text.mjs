#!/usr/bin/env node
//
// Parity check for the SHELL side's translated text — lib/locales/<tag>/<locale>.txt.
//
// The JSON catalogs under panel/locales are checked by check-locales.mjs. These
// are the other half: the setup instructions and client-config comments that
// lib/proto_*.sh hands to an end user. Same rule, different file format.
//
// Three things are compared, and each of them is a real failure that reads as
// fine:
//
//   1. Every locale exists for every adapter that has any. A missing fr.txt
//      means a French user silently gets the English page.
//   2. The SECTION NAMES match. A section the renderer asks for and the
//      translation does not carry falls back to English mid-document — one
//      paragraph in the wrong language, in the middle of a page that otherwise
//      looks translated.
//   3. The PLACEHOLDER SET inside each section matches. This is the one that
//      costs a user their connection: a translator who drops {endpoint} has
//      removed the server address from a page whose entire purpose is to carry
//      it, and the result reads perfectly well.
//
// The section names and placeholders are the contract; the prose is not. That is
// the whole point of keying on stable identifiers rather than on English text.
//
// Run locally:  node .github/scripts/check-locale-text.mjs

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIR = join(REPO, 'lib', 'locales');

// Kept in step with VPN55_LOCALES / VPN55_DEFAULT_LOCALE in lib/core_i18n.sh.
// Duplicated deliberately: this check must fail when the shell adds a locale
// and the files do not follow, which it cannot do if it reads the list from the
// same place the shell does.
const LOCALES = ['vi', 'en', 'fr'];
const DEFAULT_LOCALE = 'vi';
const FALLBACK_LOCALE = 'en';

const problems = [];

/**
 * The same parse the shell does — `@@ name` opens a section, everything to the
 * next marker is its body. Written once here and once in core_i18n.sh, and the
 * two agreeing is what makes this check mean anything; a checker with its own
 * idea of what a section is would pass files the renderer reads differently.
 */
function parse(path) {
  const sections = new Map();
  let current = null;
  let lineNo = 0;
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    lineNo += 1;
    const m = /^@@\s+([A-Za-z0-9._-]+)\s*$/.exec(line);
    if (m) {
      if (sections.has(m[1])) {
        problems.push(`lib/locales/${path.split(/[\\/]/).slice(-2).join('/')}: ` +
          `section "${m[1]}" appears twice (line ${lineNo}) — the renderer keeps the last one`);
      }
      current = { name: m[1], lines: [], placeholders: new Set() };
      sections.set(m[1], current);
      continue;
    }
    if (current === null) {
      if (line.trim() !== '') {
        problems.push(`${rel(path)}: line ${lineNo} is outside any section — ` +
          'text before the first `@@ name` marker is never rendered');
      }
      continue;
    }
    current.lines.push(line);
    for (const p of line.matchAll(/\{([A-Za-z0-9_]+)\}/g)) current.placeholders.add(p[1]);
  }
  return sections;
}

const rel = (p) => p.slice(REPO.length + 1).replace(/\\/g, '/');

if (!existsSync(DIR)) {
  console.log('No lib/locales/ — nothing to check.');
  process.exit(0);
}

const tags = readdirSync(DIR).filter((d) => statSync(join(DIR, d)).isDirectory()).sort();
let sectionCount = 0;

for (const tag of tags) {
  const parsed = new Map();

  for (const locale of LOCALES) {
    const path = join(DIR, tag, `${locale}.txt`);
    if (!existsSync(path)) {
      const note = locale === DEFAULT_LOCALE
        ? '  (the DEFAULT locale — this is what most users get)'
        : locale === FALLBACK_LOCALE
          ? '  (the FALLBACK locale — every other locale falls back to this one)'
          : '';
      problems.push(`lib/locales/${tag}/${locale}.txt is missing${note}`);
      continue;
    }
    parsed.set(locale, parse(path));
  }
  if (parsed.size !== LOCALES.length) continue;

  // The union, so a section invented in one file and authored nowhere else is
  // caught in both directions rather than only the missing-translation one.
  const union = new Set();
  for (const s of parsed.values()) for (const name of s.keys()) union.add(name);
  sectionCount += union.size;

  for (const locale of LOCALES) {
    const sections = parsed.get(locale);
    const missing = [...union].filter((n) => !sections.has(n)).sort();
    if (missing.length) {
      problems.push(
        `lib/locales/${tag}/${locale}.txt: ${missing.length} missing section(s) — ` +
        'each one falls back to English in the middle of a translated page\n' +
        missing.map((n) => `    - @@ ${n}`).join('\n'),
      );
    }
    for (const [name, s] of sections) {
      if (s.lines.join('').trim() === '') {
        problems.push(`lib/locales/${tag}/${locale}.txt: section "${name}" is empty — ` +
          'the renderer treats that as absent and falls back');
      }
    }
  }

  // Placeholders, per section, against the fallback locale's set. A dropped
  // placeholder removes a fact from the page and leaves the prose intact.
  const source = parsed.get(FALLBACK_LOCALE);
  for (const name of [...union].sort()) {
    const want = source.has(name) ? source.get(name).placeholders : new Set();
    for (const locale of LOCALES) {
      if (locale === FALLBACK_LOCALE) continue;
      const sections = parsed.get(locale);
      if (!sections.has(name)) continue;
      const got = sections.get(name).placeholders;
      const dropped = [...want].filter((p) => !got.has(p)).sort();
      const invented = [...got].filter((p) => !want.has(p)).sort();
      if (dropped.length) {
        problems.push(
          `lib/locales/${tag}/${locale}.txt, section "${name}": ` +
          `${dropped.map((p) => `{${p}}`).join(', ')} present in ${FALLBACK_LOCALE} and missing here.\n` +
          '    The sentence still reads; the fact it was carrying is gone.',
        );
      }
      if (invented.length) {
        problems.push(
          `lib/locales/${tag}/${locale}.txt, section "${name}": ` +
          `${invented.map((p) => `{${p}}`).join(', ')} is not a placeholder the renderer fills.\n` +
          '    It will be printed literally, braces and all.',
        );
      }
    }
  }
}

if (problems.length) {
  console.error('Shell-side locale text check FAILED:\n');
  for (const p of problems) console.error(`  ${p}\n`);
  process.exit(1);
}

console.log(
  tags.length === 0
    ? 'Shell-side locale text OK — no adapters ship translated text yet.'
    : `Shell-side locale text OK — ${sectionCount} section(s) across ${tags.length} ` +
      `adapter(s), identical sections and placeholders in ${LOCALES.join('/')}.`,
);
