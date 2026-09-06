#!/usr/bin/env node
//
// Does the panel's font stack actually render Vietnamese?
//
// This is not a typography question. Vietnamese stacks two marks on one vowel —
// ế, ộ, ữ, ậ, ề, ợ — and those live in Latin Extended Additional (U+1EA0–U+1EF9),
// a block plenty of respectable faces simply do not carry. A browser does not
// fail when a glyph is missing: it silently falls back PER CHARACTER, so a word
// renders half in the chosen face and half in whatever the system substitutes.
// The result looks like a rendering bug on the reader's machine rather than a
// bug in the page, which is why it survives review. Vietnamese is the DEFAULT
// locale here, so this is the majority reading experience, not an edge case.
//
// ── Why a table and not a live test ─────────────────────────────────────────
//
// The panel names system fonts. They live on the VIEWER's machine, not in this
// repo, so there is nothing here to measure — CI has no Segoe UI and no
// SF Pro. What CI can do is check the STACKS against a table of which families
// carry the block, and refuse a stack that has no covering family in it.
//
// The table is not folklore. Every Windows row was derived by parsing the cmap
// of the shipped font file with the prober built into this script:
//
//     node .github/scripts/check-fonts.mjs --probe C:/Windows/Fonts
//
// Re-run it on any machine to re-derive a row rather than believe one. The Apple
// and generic rows are marked as reasoned rather than measured, and are treated
// as UNVERIFIED by the check — which is the point: a stack must not depend on
// them.
//
// ── The rule the check enforces ─────────────────────────────────────────────
//
// Every font-family stack must contain at least one family MEASURED to carry the
// repertoire, and no family KNOWN TO LACK it may appear in the stack at all.
//
// Note the second half is "at all", not "before the verified one". Being listed
// after a covering family only protects a reader on a platform where that
// covering family exists — and these stacks are built from platform-specific
// names. A macOS machine reaching `Courier` because it has no Windows
// `Courier New` is precisely the case an ordering rule would wave through.
//
// Families nobody has measured are allowed anywhere: they may well work, they
// are simply not what the stack is relying on.
//
// Run locally:  node .github/scripts/check-fonts.mjs

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
// Both of our layers, and the vendored file they sit on. portal.css is here
// because the portal does NOT load panel.css — it is a separate application on
// a separate socket, laid out for a phone rather than for a console — so it
// carries its own copy of the --font overrides. Vietnamese is the default
// locale and the portal is the surface most users see, which makes it the worst
// possible place for the mid-word fallback these overrides exist to prevent.
//
// site/index.html is here too, and it is the one that got away. It is a single
// self-contained file with its stylesheet inline, it is `lang="vi"` and it is
// the ONLY page in this repo that is entirely Vietnamese — and it shipped
// naming "Helvetica Neue", the exact family this check records as `none`. It
// was invisible because this list was three panel stylesheets, so the rule the
// whole file exists to enforce was enforced everywhere except the page with the
// most Vietnamese on it.
const CSS = [
  join(REPO, 'panel', 'public', 'css', 'panel.css'),
  join(REPO, 'panel', 'portal', 'public', 'css', 'portal.css'),
  join(REPO, 'panel', 'public', 'css', 'vendor', 'office-tools.css'),
  join(REPO, 'site', 'index.html'),
  // The nginx 502/503/504 page. Also inline, also Vietnamese, and served at the
  // exact moment nothing else on this host is — so it is the last page anyone
  // would notice a font hole on, and the last one anybody would think to check.
  join(REPO, 'deploy', 'nginx', 'vpn55-offline.html'),
];

// ── The repertoire ───────────────────────────────────────────────────────────
// The 67 Vietnamese letters that are not plain ASCII, in both cases, plus the
// combining marks a decomposed string needs. 142 code points.
const SAMPLE = 'Tiếng Việt — mật khẩu đã được lưu ở máy chủ; hãy giữ tệp cấu hình cẩn thận.';
const REPERTOIRE = (() => {
  const cps = new Set();
  for (const c of 'àáâãèéêìíòóôõùúýăĂđĐĩĨũŨơƠưƯÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚÝ') cps.add(c.codePointAt(0));
  for (let cp = 0x1EA0; cp <= 0x1EF9; cp++) cps.add(cp);          // Latin Extended Additional
  for (const cp of [0x0300, 0x0301, 0x0302, 0x0303, 0x0309, 0x0323, 0x031B, 0x0306]) cps.add(cp);
  return [...cps];
})();

// ── The table ────────────────────────────────────────────────────────────────
//
//   'full'    measured: the cmap covers the whole repertoire
//   'partial' measured: covers the precomposed letters but not every mark
//   'none'    known not to carry Latin Extended Additional
//   'unknown' nobody has measured it here — allowed, but never relied on
//
const COVERAGE = new Map(Object.entries({
  // Measured on Windows 11 26200 with --probe C:/Windows/Fonts, 2026-08-30.
  'segoe ui':          ['full',    'measured: cmap, Windows 11, 142/142'],
  'arial':             ['full',    'measured: cmap, Windows 11, 142/142'],
  'consolas':          ['full',    'measured: cmap, Windows 11, 142/142'],
  'courier new':       ['full',    'measured: cmap, Windows 11, 142/142 — but see the note below'],
  'tahoma':            ['full',    'measured: cmap, Windows 11, 142/142'],
  'calibri':           ['full',    'measured: cmap, Windows 11, 142/142'],
  'times new roman':   ['full',    'measured: cmap, Windows 11, 142/142'],
  'verdana':           ['partial', 'measured: cmap, Windows 11, 141/142 — no U+031B combining horn'],

  // Not measured here. Reasoned, and deliberately NOT trusted by the check.
  //
  // Helvetica Neue is the one that matters: it is macOS-only, it is named in a
  // theme stack, and its Latin Extended Additional coverage is incomplete. It is
  // recorded as 'none' rather than 'unknown' because the whole reason this file
  // exists is to stop a stack leaning on it.
  'helvetica neue':    ['none',    'macOS system face; Latin Extended Additional is incomplete'],
  'helvetica':         ['none',    'macOS system face; Latin Extended Additional is incomplete'],
  'courier':           ['none',    'the macOS Courier, not Courier New; no Latin Extended Additional'],

  '-apple-system':     ['unknown', 'resolves to SF Pro, which does carry Vietnamese — but it is a keyword, not a file'],
  'blinkmacsystemfont': ['unknown', 'the same face by its Blink spelling'],
  'ui-monospace':      ['unknown', 'resolves to SF Mono / Cascadia Mono depending on platform'],
  'ui-sans-serif':     ['unknown', 'platform UI face'],
  'sfmono-regular':    ['unknown', 'macOS SF Mono'],
  'menlo':             ['unknown', 'macOS; derived from DejaVu Sans Mono, which carries the block'],
  'roboto':            ['unknown', 'Android/ChromeOS; recent versions carry the block'],
  'noto sans':         ['unknown', 'Google Noto; carries the block by design'],
  'dejavu sans':       ['unknown', 'common Linux default; carries the block'],
  'dejavu sans mono':  ['unknown', 'common Linux default; carries the block'],
  'cascadia mono':     ['unknown', 'Windows Terminal face'],
  'liberation sans':   ['unknown', 'common Linux metric-compatible face'],

  // The generics are the browser's last resort and resolve to something
  // different on every platform. A stack that reaches one has stopped choosing.
  'sans-serif':        ['unknown', 'generic — whatever the platform picks'],
  'serif':             ['unknown', 'generic'],
  'monospace':         ['unknown', 'generic'],
  'system-ui':         ['unknown', 'generic platform UI face'],
}));

// ── The prober ───────────────────────────────────────────────────────────────
// Reads a real font file's cmap and reports what it covers. This is how the
// measured rows above were produced; it is not part of the check.
function coverageOf(buf, offset = 0) {
  const u16 = (o) => buf.readUInt16BE(o);
  const u32 = (o) => buf.readUInt32BE(o);
  if (u32(offset) === 0x74746366) return coverageOf(buf, u32(offset + 12));  // 'ttcf'
  let cmapOff = null;
  for (let i = 0; i < u16(offset + 4); i++) {
    const rec = offset + 12 + i * 16;
    if (buf.toString('latin1', rec, rec + 4) === 'cmap') cmapOff = u32(rec + 8);
  }
  if (cmapOff === null) return null;
  let best = null;
  let bestScore = -1;
  for (let i = 0; i < u16(cmapOff + 2); i++) {
    const p = cmapOff + 4 + i * 8;
    const pid = u16(p);
    const eid = u16(p + 2);
    const score = (pid === 3 && eid === 10) ? 3 : (pid === 3 && eid === 1) ? 2 : (pid === 0) ? 1 : 0;
    if (score > bestScore) { bestScore = score; best = cmapOff + u32(p + 4); }
  }
  if (best === null) return null;
  const has = new Set();
  const fmt = u16(best);
  if (fmt === 4) {
    const segX2 = u16(best + 6);
    const endO = best + 14;
    const startO = endO + segX2 + 2;
    const deltaO = startO + segX2;
    const rangeO = deltaO + segX2;
    for (let s = 0; s < segX2 / 2; s++) {
      const end = u16(endO + s * 2);
      const start = u16(startO + s * 2);
      if (start === 0xFFFF) continue;
      const delta = buf.readInt16BE(deltaO + s * 2);
      const ro = u16(rangeO + s * 2);
      for (let c = start; c <= end; c++) {
        let g;
        if (ro === 0) g = (c + delta) & 0xFFFF;
        else {
          const gi = rangeO + s * 2 + ro + (c - start) * 2;
          if (gi + 1 >= buf.length) continue;
          g = u16(gi);
          if (g) g = (g + delta) & 0xFFFF;
        }
        if (g) has.add(c);
      }
    }
  } else if (fmt === 12) {
    for (let i = 0; i < u32(best + 12); i++) {
      const g = best + 16 + i * 12;
      const s = u32(g);
      const e = u32(g + 4);
      for (let c = s; c <= e && c - s < 200000; c++) has.add(c);
    }
  } else return null;
  return has;
}

if (process.argv[2] === '--probe') {
  const dir = process.argv[3];
  if (!dir || !existsSync(dir)) {
    console.error('usage: check-fonts.mjs --probe <directory of font files>');
    process.exit(2);
  }
  console.log(`Vietnamese repertoire: ${REPERTOIRE.length} code points`);
  console.log(`Sample: ${SAMPLE}\n`);
  for (const f of readdirSync(dir).filter((x) => /\.(ttf|ttc|otf)$/i.test(x)).sort()) {
    let has;
    try { has = coverageOf(readFileSync(join(dir, f))); } catch (e) { console.log(`${f}: unreadable (${e.message})`); continue; }
    if (!has) { console.log(`${f}: no cmap this prober understands`); continue; }
    const missing = REPERTOIRE.filter((c) => !has.has(c));
    console.log(
      `${basename(f).padEnd(20)} ${missing.length === 0 ? 'full' : `MISSING ${missing.length}`}` +
      (missing.length ? `  ${missing.slice(0, 12).map((c) => String.fromCodePoint(c)).join(' ')}` : ''),
    );
  }
  process.exit(0);
}

// ── The check ────────────────────────────────────────────────────────────────
//
// vendor/office-tools.css is a PINNED copy of somebody else's stylesheet and is
// never edited — panel.css loads second and wins by cascade. So judging the
// vendored file directly would report a defect nobody may fix, in a line that
// never takes effect. What is checked instead is the OVERRIDE: for every
// selector where the vendored file sets `--font`, panel.css must set it too.
// An un-overridden one is judged on its own merits, because that one does reach
// the screen.
//
// ── Unless the theme is unreachable ─────────────────────────────────────────
//
// A [data-theme="x"] rule only ever renders if something can set that
// attribute to "x", and the one thing that ever does is VPN55_THEMES in
// public/js/theme.js. The vendored file still carries full palettes for themes
// this panel no longer offers — matrix and anime — byte-identical to upstream,
// so that a re-vendor stays a diff rather than an archaeology exercise. Those
// stacks reach nobody.
//
// Grading them anyway would demand an override in panel.css for a theme that
// cannot be selected, which is a rule that exists only to keep a check quiet.
// That is how a check stops being believed. So the reachable set is read from
// theme.js — from the list itself, not from a copy of it here, because a
// second copy is a thing to forget.
const problems = [];
const overridden = [];
const unreachable = [];
let stackCount = 0;

/** The theme names public/js/theme.js actually offers. */
const REACHABLE = (() => {
  const src = readFileSync(join(REPO, 'panel', 'public', 'js', 'theme.js'), 'utf8');
  const m = src.match(/VPN55_THEMES\s*=\s*\[([^\]]*)\]/);
  if (!m) {
    // Not a warning to swallow: if the list cannot be read, every theme has to
    // be treated as reachable, or a real hole hides behind a parse failure.
    problems.push('panel/public/js/theme.js: could not read VPN55_THEMES — every theme will be graded.');
    return null;
  }
  return new Set(m[1].split(',').map((x) => x.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean));
})();

/** '[data-theme="matrix"]' -> false once matrix is no longer in the list. */
function selectorReachable(selector) {
  if (REACHABLE === null) return true;
  const m = String(selector).match(/^\[data-theme="([^"]+)"\]$/);
  if (!m) return true;         // :root, or a compound selector — always live
  return REACHABLE.has(m[1]);
}

/** Split a font-family value into families, respecting quotes. */
function families(value) {
  return value
    .split(',')
    .map((f) => f.trim().replace(/^['"]|['"]$/g, '').toLowerCase())
    .filter(Boolean);
}

/** The selector of the rule a declaration at `index` sits in. */
function selectorAt(src, index) {
  const open = src.lastIndexOf('{', index);
  if (open < 0) return '';
  const before = src.slice(0, open);
  // `*/` is two characters, so its end is index + 2 — off by one here leaves a
  // stray slash glued to the selector and no two selectors ever compare equal.
  const ends = [before.lastIndexOf('}') + 1, before.lastIndexOf('{') + 1, before.lastIndexOf('*/') + 2];
  const start = Math.max(0, ...ends.filter((e) => e > 1));
  return src.slice(start, open)
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Selectors where panel.css defines --font, so the vendored value never lands. */
const panelTokenSelectors = new Set();
{
  const own = join(REPO, 'panel', 'public', 'css', 'panel.css');
  if (existsSync(own)) {
    const src = readFileSync(own, 'utf8');
    const re = /(?:^|[;{\s])--font\s*:\s*([^;}]+)/g;
    let m;
    while ((m = re.exec(src)) !== null) panelTokenSelectors.add(selectorAt(src, m.index));
  }
}

for (const file of CSS) {
  if (!existsSync(file)) continue;
  const src = readFileSync(file, 'utf8');
  const label = file.slice(REPO.length + 1).replace(/\\/g, '/');
  const isVendor = label.includes('/vendor/');

  // `font-family: …`, the `--font: …` token every panel rule resolves through,
  // and `--sans`/`--mono`, which is what site/index.html calls its two. The
  // names are listed rather than guessed at: a heuristic like "any custom
  // property whose value mentions sans-serif" would grade half the palette on
  // the day somebody writes `--card-shadow` badly, and a check that reports
  // non-problems is a check that gets switched off. A new surface that invents
  // a fourth token name adds it here.
  const re = /(?:^|[;{\s])(font-family|--font|--sans|--mono)\s*:\s*([^;}]+)/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const prop = m[1];
    const value = m[2].trim();
    if (value === 'inherit' || value.startsWith('var(')) continue;
    const list = families(value);
    if (!list.length) continue;

    const line = src.slice(0, m.index).split('\n').length;
    const where = `${label}:${line}`;
    const selector = selectorAt(src, m.index);

    if (isVendor && prop === '--font') {
      // A theme nothing can select renders nothing, so its stack is not a
      // stack anyone reads. Recorded rather than silently skipped — the note
      // at the end is what stops this becoming a place to hide a hole.
      if (!selectorReachable(selector)) {
        unreachable.push(`${selector}  (${where})`);
        continue;
      }
      if (panelTokenSelectors.has(selector)) {
        overridden.push(`${selector || ':root'}  (${where})`);
        continue;
      }
      problems.push(
        `${where}\n    ${selector} { --font: ${value} }\n` +
        '    The vendored file sets this token and panel.css does not override it\n' +
        '    for the same selector, so this stack is what readers get. The vendored\n' +
        '    file is pinned and must not be edited — add the override to panel.css.',
      );
      // and fall through, so the stack itself is reported too
    }
    stackCount += 1;

    const firstVerified = list.findIndex((f) => {
      const e = COVERAGE.get(f);
      return e && (e[0] === 'full' || e[0] === 'partial');
    });

    if (firstVerified === -1) {
      problems.push(
        `${where}\n    ${value}\n` +
        '    No family in this stack is verified to carry Vietnamese. Every name\n' +
        '    here is either unmeasured or known to lack the block, so what a\n' +
        '    reader sees is whatever their browser substitutes, per character.',
      );
      continue;
    }

    const bad = list.filter((f) => COVERAGE.get(f)?.[0] === 'none');
    if (bad.length) {
      problems.push(
        `${where}\n    ${value}\n` +
        `    ${bad.map((b) => `"${b}"`).join(', ')} does not carry Vietnamese. Any reader whose\n` +
        '    machine has it and lacks whatever is listed before it lands on it, and\n' +
        `    falls back mid-word: ${SAMPLE.slice(0, 34)}…\n` +
        bad.map((b) => `      ${b} — ${COVERAGE.get(b)[1]}`).join('\n'),
      );
    }
  }
}

if (problems.length) {
  console.error('Vietnamese font-coverage check FAILED:\n');
  for (const p of problems) console.error(`  ${p}\n`);
  console.error('  Vietnamese is the default locale. A stack that falls back mid-word is');
  console.error('  what most users see, and it reads as a fault on their machine.\n');
  process.exit(1);
}

if (unreachable.length) {
  console.log('  Vendored --font tokens for themes theme.js no longer offers, so');
  console.log('  never selected and never rendered:');
  for (const u of unreachable) console.log(`    - ${u}`);
  console.log('');
}

if (overridden.length) {
  console.log('  Vendored --font tokens overridden in panel.css, so never rendered:');
  for (const o of overridden) console.log(`    - ${o}`);
  console.log('');
}

console.log(
  `Font coverage OK — ${stackCount} stack(s) reach the screen; every one names a ` +
  'family measured to carry the Vietnamese repertoire, and none names a family ' +
  'known to lack it.',
);
