#!/usr/bin/env node
//
// String expansion — lay the panel out against the LONGEST locale, not English.
//
// French runs 15–25% longer than English as a rule of thumb, and Vietnamese runs
// longer still for anything technical, because it spells out words English
// abbreviates ("chứng danh" for "credential", "người dùng" for "user"). A button
// or a column header sized to its English caption is a button that is too small
// in two of the three languages this ships in.
//
// ── What this checks, and what it deliberately does not ─────────────────────
//
// It does NOT check prose. A paragraph that runs 30% longer in French simply
// wraps, and wrapping is fine. What matters is text in a box that will not grow
// or will not wrap:
//
//   *.col.*       table column headers. `.grid th` is `white-space: nowrap`, so
//                 a long header widens the table rather than wrapping. The table
//                 scrolls inside its own box, so this degrades rather than
//                 breaks — but it degrades on every row, for everyone.
//   badges        service state, filtering level, note severity. `.badge` is
//                 `white-space: nowrap` too, and these sit in table cells.
//   buttons/tabs  the caption is the width. These pad rather than measure, so
//                 they grow — into whatever is beside them.
//
// For each of those the LONGEST locale is reported, and a ceiling is enforced so
// nobody lands a forty-character button caption in one language and finds out
// from a screenshot months later.
//
// Prose keys are measured too, but only reported — never failed.
//
// Run locally:  node .github/scripts/check-expansion.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIR = join(REPO, 'panel', 'locales');
const LOCALES = ['vi', 'en', 'fr'];
const BASE = 'en';

// Ceilings in characters, for text that cannot wrap or must not grow much.
// Generous on purpose: the point is to catch something absurd, not to police
// wording. Vietnamese needs the room — "Kết nối gần nhất" is not a translation
// anyone should be asked to shorten.
const CEILING = {
  column: 26,      // *.col.*  — nowrap, and there are up to eleven per table
  badge: 22,       // *.state.*, filtering.level.*, note.severity.* — nowrap, in a cell
  action: 30,      // buttons and tabs
};

function flatten(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else if (typeof v === 'string') out.set(key, v);
  }
  return out;
}

const cat = new Map();
for (const locale of LOCALES) {
  cat.set(locale, flatten(JSON.parse(readFileSync(join(DIR, `${locale}.json`), 'utf8')), '', new Map()));
}

// ── Which keys are laid out, and how that is decided ────────────────────────
//
// By NAME, from an explicit list, and not by a heuristic on the English text.
//
// The heuristic was tried first — "a short string with no sentence punctuation
// is a label" — and it was wrong in the expensive direction. `health.kind.*`,
// `revoke.latency.*` and `custody.who.*` are not badges at all: they render as
// disclosure prose in a paragraph that wraps perfectly well. A check that
// reports twelve non-problems is a check somebody switches off, and then it is
// not there on the day a genuine forty-character column header lands.
//
// So the list is maintained by hand. Adding a label to the UI means adding it
// here — which is a line of work, and is the price of the check meaning
// something. The naming convention does most of it: every table header in this
// catalog is `*.col.*` already.
const LABEL = [
  [/\.col\.[a-z_]+$/, 'column'],                                       // .grid th — nowrap
  [/^service\.state\.(running|stopped|absent|unknown)$/, 'badge'],
  [/^filtering\.level\.(resistant|partial|exposed)$/, 'badge'],
  [/^note\.severity\.(info|warn|crit)$/, 'badge'],
  [/^audit\.result\.(ok|error|denied)$/, 'badge'],
  [/^(user\.(enabled|disabled|expired|expiry\.unparseable)|quota\.(over|unlimited)|expiry\.never)$/, 'badge'],
  [/^service\.(unavailable|boot\.disabled)$/, 'badge'],
  [/^view\.[a-z]+$/, 'action'],                                        // the tab rail
  [/^theme\.(light|dark|matrix|anime)$/, 'action'],
  [/^locale\.name\.[a-z]{2}$/, 'action'],
  [/^auth\.(title|username|password|signin|signout)$/, 'action'],
  [/^action\.(confirm|cancel|working)$/, 'action'],
  [/^user\.(add|remove|enable|disable)$/, 'action'],
  [/^cred\.(issue|revoke)$/, 'action'],
  [/^(service\.restart|audit\.title|enforce\.title|orphans\.title|auth\.off\.title)$/, 'action'],
  [/^user\.field\.(quota|expires|conn_limit|quota_reset)$/, 'action'],  // form labels
  [/^(service\.(listen|since|creds)|filtering\.label|custody\.label|revoke\.label|restart\.label|fromservice\.label)$/, 'action'],

  // The self-serve portal (Phase 8). BUTTON CAPTIONS AND BADGES ONLY. Its
  // headings, its form labels and its help text all sit in block elements that
  // wrap, and listing them here reported three non-problems on the first run —
  // which is exactly the over-classification the note above warns about, since
  // a check that cries wolf is a check somebody switches off before the day a
  // real forty-character caption lands.
  //
  // The portal is one column on a phone, so a button caption that grows pushes
  // whatever is beside it onto the next row. That is a softer failure than a
  // table header widening a grid, but it happens on the screen most users see.
  [/^portal\.(signin|signout|download|rotate|copy|save|close)$/, 'action'],
  [/^portal\.token\.(issue|revoke|copy)$/, 'action'],
  [/^portal\.state\.(active|disabled|expired|expiry_unreadable)$/, 'badge'],
  [/^portal\.(connected|notconnected)$/, 'badge'],
];

/** Which class a key belongs to, or null for prose. */
function classOf(key) {
  if (key.endsWith('.help')) return null;      // tooltips wrap; they are never a box
  for (const [re, cls] of LABEL) if (re.test(key)) return cls;
  return null;
}

// The measured length is what a reader sees, so placeholders are not counted as
// their own braces — `{user}` renders as a name of unknown length, and counting
// six literal characters for it would understate every string that has one.
const visible = (s) => s.replace(/\{[A-Za-z0-9_]+\}/g, '').trim().length;

const problems = [];
const rows = [];

for (const [key, en] of cat.get(BASE)) {
  const cls = classOf(key);
  const lengths = LOCALES.map((l) => [l, visible(cat.get(l).get(key) ?? '')]);
  const [longestLocale, longest] = lengths.reduce((a, b) => (b[1] > a[1] ? b : a));
  const base = visible(en) || 1;

  rows.push({ key, cls, longestLocale, longest, base, ratio: longest / base, lengths });

  if (!cls) continue;
  if (longest > CEILING[cls]) {
    problems.push(
      `${key}  [${cls}]  ceiling ${CEILING[cls]}, longest ${longest} (${longestLocale})\n` +
      lengths.map(([l, n]) => `      ${l}  ${String(n).padStart(3)}  ${JSON.stringify(cat.get(l).get(key))}`).join('\n'),
    );
  }
}

// ── The report ───────────────────────────────────────────────────────────────
// Printed every run, pass or fail. The number that matters is not the average —
// it is which locale is longest, because that is the one the layout has to fit.
const laidOut = rows.filter((r) => r.cls);
const wins = { vi: 0, en: 0, fr: 0 };
for (const r of laidOut) wins[r.longestLocale] += 1;

const totals = {};
for (const l of LOCALES) totals[l] = rows.reduce((n, r) => n + (r.lengths.find((x) => x[0] === l)[1]), 0);

console.log('  String expansion, whole catalog (characters, placeholders excluded):');
for (const l of LOCALES) {
  const pct = Math.round(((totals[l] / totals[BASE]) - 1) * 100);
  console.log(`    ${l}  ${String(totals[l]).padStart(6)}  ${l === BASE ? '(base)' : `${pct >= 0 ? '+' : ''}${pct}% vs ${BASE}`}`);
}
console.log(`\n  Of the ${laidOut.length} key(s) that sit in a box which cannot wrap,`);
console.log('  the longest rendering is:');
for (const l of LOCALES) console.log(`    ${l}  ${String(wins[l]).padStart(4)}`);
console.log('  Lay those out against the winner, never against English.\n');

const worst = laidOut.sort((a, b) => b.longest - a.longest).slice(0, 8);
console.log('  Longest eight, which are what the layout actually has to hold:');
for (const r of worst) {
  console.log(`    ${String(r.longest).padStart(3)}  ${r.longestLocale}  ${r.key}` +
    `  ${JSON.stringify(cat.get(r.longestLocale).get(r.key))}`);
}
console.log('');

if (problems.length) {
  console.error('Expansion budget check FAILED:\n');
  for (const p of problems) console.error(`  ${p}\n`);
  console.error('  These sit in a box that will not wrap. Either shorten the string, or');
  console.error('  change the layout so it can grow — and raise the ceiling here in the');
  console.error('  same commit, so the next person meets the new rule rather than this one.\n');
  process.exit(1);
}

console.log(`Expansion budget OK — ${laidOut.length} laid-out string(s), all within their ceiling.`);
