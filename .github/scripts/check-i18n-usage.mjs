#!/usr/bin/env node
//
// Every key the panel ASKS FOR must exist in the catalogs.
//
// check-locales.mjs compares the three catalogs with each other. That catches
// drift between translations and cannot catch the other direction: a `t()` call
// naming a key nobody ever authored. All three files agree perfectly, the check
// is green, and the panel renders the literal string `auth.signed_in` on screen.
//
// That is not hypothetical — it is what this check found the first time it ran.
// panel/lib/auth.js audited `auth.signed_in` and `auth.signed_out` while the
// catalogs carried `auth.signedin` and `auth.signout`. Nobody noticed because
// the audit view that renders them has not been built yet, which is exactly the
// kind of gap that ships: the bug is already written and simply not on screen
// this month.
//
// ── Two passes, on purpose ───────────────────────────────────────────────────
//
// STRICT, for the failure. Only `t(...)`, `tOr(...)`, `data-i18n`, and the
// `error:` / `message:` keys that travel to the browser to be resolved there.
// A key named in one of those and absent from the catalog is a build failure,
// because it is a string that will appear, as itself, on somebody's screen.
//
// LOOSE, for the "never looked up" note. Any quoted string that IS a catalog
// key counts as used, wherever it appears — because keys are routinely handed
// to a local helper rather than written inside the lookup:
//
//     row('user.field.quota', 'user.field.quota.help', quota)
//
// The loose pass can only ever mark a key USED, never unknown, so a coincidence
// costs one line of noise in a note and can never fail a build.
//
// ── Dynamic keys ─────────────────────────────────────────────────────────────
//
// The panel builds some keys from a value it got from an adapter:
//
//     tOr('service.state.' + word, 'service.state.other', { state: word })
//
// That is correct — a service state this build has never heard of gets its own
// phrasing rather than an empty cell. It also means the literal key appears
// nowhere in the source. So a concatenation onto a literal ending in a dot
// CLAIMS that prefix, and every catalog key under it counts as used.
//
// Run locally:  node .github/scripts/check-i18n-usage.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SOURCE = join(REPO, 'panel', 'locales', 'en.json');

const rel = (p) => relative(REPO, p).replace(/\\/g, '/');
const problems = [];
const notes = [];

// ── The catalog ──────────────────────────────────────────────────────────────
const catalog = new Set();
(function flatten(obj, prefix) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key);
    else catalog.add(key);
  }
})(JSON.parse(readFileSync(SOURCE, 'utf8')), '');

// ── Every panel source file ──────────────────────────────────────────────────
const files = [];
(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'locales') continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(js|mjs)$/.test(p)) files.push(p);
  }
})(join(REPO, 'panel'));
files.sort();

const Q = String.raw`['"]([A-Za-z0-9_.-]+)['"]`;

// STRICT — a key named here and missing from the catalog is a failure.
const LITERAL = [
  new RegExp(String.raw`\bt\(\s*${Q}`, 'g'),
  new RegExp(String.raw`\btOr\(\s*${Q}\s*,\s*${Q}`, 'g'),
  new RegExp(String.raw`\bT\(\s*${Q}`, 'g'),                 // the alias in format.js
  new RegExp(String.raw`\bhas\(\s*${Q}`, 'g'),
  new RegExp(String.raw`['"]data-i18n(?:-title)?['"]\s*:\s*${Q}`, 'g'),
  new RegExp(String.raw`data-i18n(?:-title)?=["']([A-Za-z0-9_.-]+)["']`, 'g'),
  // auth.js returns { error: 'auth.locked' } and the page renders t(that).
  // A key that travels over the wire is still a key.
  new RegExp(String.raw`\b(?:error|message)\s*:\s*'([a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'`, 'g'),
];

// A prefix claim: a literal ending in a dot, concatenated with something.
const PREFIX = new RegExp(String.raw`\b(?:t|tOr|T|has)\(\s*['"]([A-Za-z0-9_.-]*\.)['"]\s*\+`, 'g');

// A lookup whose key this checker cannot see: the first argument is an
// expression. Declarations are excluded — `function t(key, vars)` and the class
// method `t(locale, key, vars)` are where t is DEFINED, and a definition is not
// a lookup.
const OPAQUE = new RegExp(
  String.raw`(?<!function\s)(?<![A-Za-z0-9_$.])(?:t|tOr)\(\s*([A-Za-z_$][A-Za-z0-9_$.\[\]]*)\s*[,)]`, 'g');
const OPAQUE_SKIP = new Set(['key', 'fallbackKey', 'locale']);

const used = new Map();      // key -> Set(files)
const claimed = new Map();   // prefix -> Set(files)
const opaque = [];
let strictCount = 0;

function note(map, key, file) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(file);
}

for (const file of files) {
  const src = readFileSync(file, 'utf8');
  // Comments are stripped so a key merely MENTIONED in prose is not counted as
  // a call. Newlines inside a block comment are preserved so the line numbers
  // reported below stay true to the file on disk.
  const code = src
    .replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

  for (const re of LITERAL) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      for (let i = 1; i < m.length; i++) {
        if (!m[i]) continue;
        note(used, m[i], rel(file));
        strictCount += 1;
      }
    }
  }

  PREFIX.lastIndex = 0;
  let m;
  while ((m = PREFIX.exec(code)) !== null) note(claimed, m[1], rel(file));

  OPAQUE.lastIndex = 0;
  while ((m = OPAQUE.exec(code)) !== null) {
    if (OPAQUE_SKIP.has(m[1])) continue;
    const line = code.slice(0, m.index).split('\n').length;
    opaque.push(`${rel(file)}:${line}  t(${m[1]})`);
  }

  // LOOSE — see the header. Marks used, never unknown.
  for (const q of code.matchAll(/['"]([A-Za-z0-9_.-]+)['"]/g)) {
    if (catalog.has(q[1])) note(used, q[1], rel(file));
  }
}

// Collect the strict names separately so the failure list cannot be polluted by
// the loose pass, which is allowed to be approximate.
const strict = new Set();
for (const file of files) {
  const code = readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
  for (const re of LITERAL) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      for (let i = 1; i < m.length; i++) if (m[i]) strict.add(m[i]);
    }
  }
}

// ── 1. Asked for, never authored. The failure. ───────────────────────────────
const unknown = [...strict].filter((k) => !catalog.has(k) && !k.endsWith('.')).sort();
if (unknown.length) {
  problems.push(
    `${unknown.length} key(s) are looked up and exist in no catalog. Each renders\n` +
    '  as the literal key text on screen:\n' +
    unknown.map((k) => `    - ${k}   (${[...used.get(k)].join(', ')})`).join('\n'),
  );
}

// ── 2. A lookup this check cannot see ────────────────────────────────────────
// Not a failure — the runtime error-key resolution in actions.js is exactly
// this shape and is right. But it is the blind spot, and a checker that stays
// quiet about what it cannot see is worse than no checker.
if (opaque.length) {
  notes.push(
    `${opaque.length} lookup(s) take a key this check cannot read. Nothing here\n` +
    '  verifies them:\n' +
    opaque.map((l) => `    - ${l}`).join('\n'),
  );
}

// ── 3. Authored, never asked for ─────────────────────────────────────────────
// Also not a failure: keys legitimately land ahead of the screen that will show
// them, and this repo has a whole audit view's worth waiting on a later phase.
// But an unused key is also what a RENAMED key leaves behind, and the two look
// identical from here, so the list is printed rather than swallowed.
const unusedKeys = [...catalog].filter((k) => {
  if (used.has(k)) return false;
  for (const prefix of claimed.keys()) if (k.startsWith(prefix)) return false;
  return true;
}).sort();
if (unusedKeys.length) {
  notes.push(
    `${unusedKeys.length} catalog key(s) are never looked up. Expected while a view\n` +
    '  is still unwritten — and also what a rename leaves behind:\n' +
    unusedKeys.map((k) => `    - ${k}`).join('\n'),
  );
}

for (const n of notes) console.log(`  note: ${n}\n`);

if (problems.length) {
  console.error('Locale usage check FAILED:\n');
  for (const p of problems) console.error(`  ${p}\n`);
  process.exit(1);
}

console.log(
  `Locale usage OK — ${strict.size} key(s) named in a lookup and ${claimed.size} ` +
  `prefix claim(s) across ${files.length} file(s); all resolve in ${rel(SOURCE)}. ` +
  `(${strictCount} lookup sites.)`,
);
