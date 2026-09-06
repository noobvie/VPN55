#!/usr/bin/env node
//
// Is every colour pair on the two panel surfaces actually readable, in every
// theme?
//
// ── Why this is a script and not a review ───────────────────────────────────
//
// The two stylesheets each open with the same warning: wherever a rule sets a
// background it must set its colour too, because a quiet element that overrides
// only its background inherits ink chosen for a different surface. That warning
// has been in both files from the start and it did not prevent a warning badge
// shipping at 1.93:1 — an amber word on an amber tint. It could not prevent it,
// because "is this pair readable" is arithmetic and a reviewer reading a
// stylesheet is not doing arithmetic. They are looking at a rule that names two
// tokens and concluding, correctly, that it names two tokens.
//
// Worse, the failure is INVISIBLE on the machine most likely to review it. The
// default theme is dark, most themes were fine for any given pair, and nobody
// switches theme to read a table. The two worst offenders have since been
// dropped, which does not make the check less necessary — it makes it the
// reason anyone knew which two to drop. So it is mechanical, it runs on every
// theme, and it fails the build.
//
// ── What it checks ──────────────────────────────────────────────────────────
//
//  1. PAIRED PROPERTY, mechanically, per rule. Every rule that sets a
//     background must set a colour, and the other way round. Rules that legally
//     cannot be paired — a meter bar with no text in it, a rule whose ink is
//     deliberately set on its own children — are listed in PAIR_EXEMPT with the
//     reason. An exemption is a decision someone wrote down; an omission is not.
//
//  2. CONTRAST, for every pair the stylesheets actually use, resolved PER
//     ELEMENT rather than per rule. A rule that sets only `color` is paired with
//     the background of the element it renders inside — which is why the table
//     below carries a `where`, and why it is maintained by hand: the DOM is
//     built in JavaScript and cannot be read off the CSS.
//
//     Text is held to 4.5:1 (WCAG 1.4.3 AA, and every one of these is small
//     text — the largest is .95rem). Non-text that carries meaning — a control's
//     boundary, a meter fill against its track — is held to 3:1 (1.4.11).
//
//  3. EVERY REFERENCED TOKEN RESOLVES, in every theme. A `var(--typo)` does not
//     error and does not fall back to anything sensible — the declaration is
//     dropped and the property inherits, so a mistyped background inherits its
//     parent's and a mistyped colour inherits ink chosen for another surface.
//     That is the same failure as an unpaired rule arriving by a different
//     route, and it is invisible in whichever theme you happen to be looking at
//     if the token exists there and not in the others.
//
//  4. THE TWO TOKEN BLOCKS AGREE. portal.css duplicates panel.css's ink tokens
//     deliberately, because the portal does not load panel.css and must not
//     depend on it. Duplication that nothing checks is duplication that drifts,
//     so this checks it.
//
// ── What it deliberately does NOT do ────────────────────────────────────────
//
// It does not read the vendored file's own component rules and grade them. That
// file is a pinned copy of a marketing site's stylesheet, most of it for
// components this panel never renders, and failing the build on a rule nobody
// can edit and nobody displays would make this check something people switch
// off. The two vendored components the panel DOES render — .tabs/.tab-btn and
// .card — appear in the pair table by hand, marked VENDORED, and are corrected
// by an override in panel.css.
//
// It also does not grade the vendored blocks for themes nothing can select any
// more. [data-theme="matrix"] and [data-theme="anime"] are still in the pinned
// file, byte-identical to upstream so a re-vendor stays a diff; they are simply
// never matched, because VPN55_THEMES in theme.js no longer offers those names.
//
// Run locally:  node .github/scripts/check-contrast.mjs
//               node .github/scripts/check-contrast.mjs --table   (print it all)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const VENDOR = 'panel/public/css/vendor/office-tools.css';
const PANEL = 'panel/public/css/panel.css';
const PORTAL = 'panel/portal/public/css/portal.css';

// The list theme.js actually offers. `mina` has no block in the vendored file at
// all — its whole palette is defined in our layer — so themeTokens() below finds
// nothing in the middle of the cascade for it and every one of its tokens has to
// be named locally. A token this file grades that mina forgets to define
// resolves to the LIGHT theme's value, on a near-black ground, and that is
// exactly the failure this check exists to report.
const THEMES = ['light', 'dark', 'mina'];
// The light theme is the vendored file's bare :root; the rest are [data-theme=...]
// blocks layered on top of it.
const SELECTOR = (t) => (t === 'light' ? ':root' : `[data-theme="${t}"]`);

const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const strip = (css) => css.replace(/\/\*[\s\S]*?\*\//g, '');

// ── Tokens ──────────────────────────────────────────────────────────────────

/** Every `--token: value` declaration in every block matching `sel`. */
function tokensIn(css, sel) {
  const out = {};
  const body = strip(css);
  let from = 0;
  for (;;) {
    const i = body.indexOf(sel, from);
    if (i < 0) break;
    const open = body.indexOf('{', i);
    const close = body.indexOf('}', open);
    if (open < 0 || close < 0) break;
    // Only an exact selector match, so `[data-theme="dark"] .thing { }` does not
    // contribute tokens to the dark theme's root.
    if (body.slice(i + sel.length, open).trim() === '') {
      for (const decl of body.slice(open + 1, close).split(';')) {
        const m = decl.match(/^\s*(--[\w-]+)\s*:\s*(.+?)\s*$/);
        if (m) out[m[1]] = m[2];
      }
    }
    from = close + 1;
  }
  return out;
}

/**
 * The token table a browser would arrive at for one theme: the vendored :root,
 * then the vendored theme block, then our layer's :root, then our layer's theme
 * block. That is cascade order, and getting it wrong is the difference between
 * grading what ships and grading what used to.
 */
function themeTokens(layerCss, theme) {
  const v = read(VENDOR);
  return {
    ...tokensIn(v, ':root'),
    ...(theme === 'light' ? {} : tokensIn(v, SELECTOR(theme))),
    ...tokensIn(layerCss, ':root'),
    ...(theme === 'light' ? {} : tokensIn(layerCss, SELECTOR(theme))),
  };
}

/** Follow `var(--a)` chains to a literal. Cycles resolve to null, not a hang. */
function resolveToken(table, name, seen = new Set()) {
  if (seen.has(name)) return null;
  seen.add(name);
  const raw = table[name];
  if (!raw) return null;
  const m = raw.match(/^var\(\s*(--[\w-]+)\s*\)$/);
  if (m) return resolveToken(table, m[1], seen);
  return raw.trim();
}

// ── Colour ──────────────────────────────────────────────────────────────────

function rgb(value) {
  if (!value) return null;
  const m = String(value).trim().match(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/);
  if (!m) return null;
  let h = m[1];
  if (h.length === 3) h = h.split('').map((c) => c + c).join('');
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
}

/** WCAG 2.x relative luminance. */
function luminance([r, g, b]) {
  const lin = (c) => {
    const v = c / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// ── 1. The paired-property check ────────────────────────────────────────────

/**
 * Rules allowed to set one half of the pair, and why. The reason is the point:
 * every entry here is a claim someone can go and check, and an entry whose claim
 * stops being true is a bug this check will not catch — so keep them narrow.
 */
const PAIR_EXEMPT = new Map([
  ['.meter', 'the track of a quota bar; it has no text in it, ever'],
  ['.meter__fill', 'the bar itself; no text in it, ever'],
  ['.meter__fill--warn', 'as .meter__fill'],
  ['.meter__fill--crit', 'as .meter__fill'],
  ['.qr', 'a camera target, deliberately outside the theme system — see the note in the file'],
  ['[data-theme="mina"] body::before', 'the ribbon: a CSS drawing on ::before, which cannot contain text'],
  ['.proto', 'a drawn mark, 0.62em square; it holds no text node and never will'],
  ['.proto--1', 'as .proto'],
  ['.proto--2', 'as .proto'],
  ['.proto--3', 'as .proto'],
  ['.proto--more', 'as .proto'],
]);

function ruleset(css) {
  const out = [];
  // One level of @media unwrapping is enough: neither file nests further.
  const flat = strip(css).replace(/@media[^{]+\{([\s\S]*?)\n\}/g, (_, inner) => inner);
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(flat))) {
    const decl = {};
    for (const d of m[2].split(';')) {
      const dm = d.match(/^\s*([\w-]+)\s*:\s*(.+?)\s*$/s);
      if (dm) decl[dm[1]] = dm[2].replace(/\s+/g, ' ');
    }
    out.push({ selector: m[1].trim().replace(/\s+/g, ' '), decl });
  }
  return out;
}

function pairedPropertyProblems(file, css) {
  const problems = [];
  for (const { selector, decl } of ruleset(css)) {
    // A bare :root or [data-theme="x"] block defines tokens and paints nothing.
    // The match has to be EXACT: `[data-theme="mina"] .card` and
    // `[data-theme="mina"] body::before` are painted rules that happen to start
    // with the same characters, and a prefix test waves both of them through —
    // which is how a theme-scoped decoration gets to skip the one check written
    // to catch theme-scoped decorations.
    if (/^(:root|\[data-theme="[^"]+"\])$/.test(selector)) continue;
    const bg = decl.background || decl['background-color'];
    const fg = decl.color;
    if (!bg || fg) continue;
    if (PAIR_EXEMPT.has(selector)) continue;
    problems.push(
      `${file}: \`${selector}\` sets a background (${bg}) and no colour.\n` +
      '      Either name the colour beside it, or add the selector to PAIR_EXEMPT\n' +
      '      in this script with the reason it can never carry text.',
    );
  }
  return problems;
}

// ── 2. The pair table ───────────────────────────────────────────────────────
//
// `on` is the background the element actually renders against, which is a fact
// about the DOM and not about the CSS — app.js and portal.js build these trees,
// so this list is maintained by hand and reviewed when a view changes.
// `min` is 4.5 for text and 3 for a meaningful non-text boundary.
//
// `only` names the stylesheet a pair belongs to, where it is not in both. It
// matters more than it looks: without it, a pair is graded against a file that
// does not define its tokens, and "a token does not resolve" then reads as a
// missing definition rather than as a pair asked of the wrong surface. The
// quota meter exists only in the portal and the tab strip and the protocol
// marker only in the panel.

const TEXT = 4.5;
const NONTEXT = 3;

const PAIRS = [
  // ── shared: the ink ramp on the three surfaces ──
  { ink: '--text', on: '--bg', min: TEXT, where: 'body, .field, .setting__input, .signin, .modal' },
  { ink: '--text', on: '--bg-card', min: TEXT, where: '.grid td, .events, .btn, .signin__form, .modal__box, .flash__item, .setting, portal .card/.banner' },
  { ink: '--text', on: '--bg-secondary', min: TEXT, where: '.disclosure, .note, .banner, .btn:hover, tr:hover td, portal .config__body, portal .btn' },
  { ink: '--text-muted', on: '--bg', min: TEXT, where: '.diag, .footer, topbar .muted, .pbar__who, .pfooter' },
  { ink: '--text-muted', on: '--bg-card', min: TEXT, where: '.from-service in .events, .flash__from, portal .card__sub / .muted / .facts dt' },
  { ink: '--text-muted', on: '--bg-secondary', min: TEXT, where: '.chip, .empty, .grid th, .badge--idle, .disclosure__label, VENDORED .tab-btn' },
  { ink: '--text-light', on: '--bg', min: TEXT, where: '.is-unset outside a card' },
  { ink: '--text-light', on: '--bg-card', min: TEXT, where: '.is-unset in .grid td and .facts dd, .from-service__mark in .events, portal .is-unset' },
  { ink: '--text-light', on: '--bg-secondary', min: TEXT, where: '.badge--unknown, .from-service__mark in .disclosure/.note, .is-unset on a hovered row' },

  // ── the muted note inside a tinted banner (portal) ──
  { ink: '--text-muted', on: '--danger-dim', min: TEXT, only: 'portal.css', where: '.from-service inside .banner--crit' },
  { ink: '--text-muted', on: '--warning-dim', min: TEXT, only: 'portal.css', where: '.from-service inside .banner--warn' },
  { ink: '--text-muted', on: '--primary-dim', min: TEXT, only: 'portal.css', where: '.from-service inside .banner--info' },
  { ink: '--text', on: '--danger-dim', min: TEXT, where: '.banner--crit body text' },
  { ink: '--text', on: '--warning-dim', min: TEXT, where: '.banner--warn body text' },
  { ink: '--text', on: '--primary-dim', min: TEXT, where: '.banner--info body text' },

  // ── status ink on its own tint ──
  { ink: '--ink-ok', on: '--success-dim', min: TEXT, where: '.badge--ok' },
  { ink: '--ink-warn', on: '--warning-dim', min: TEXT, where: '.badge--warn' },
  { ink: '--ink-crit', on: '--danger-dim', min: TEXT, where: '.badge--crit, portal .btn--danger' },
  { ink: '--ink-accent', on: '--primary-dim', min: TEXT, where: '.badge--info' },

  // ── status ink on a plain surface ──
  { ink: '--ink-crit', on: '--bg-card', min: TEXT, where: '.btn--danger, .signin__problem' },
  { ink: '--ink-crit', on: '--bg', min: TEXT, where: 'portal .problem' },
  { ink: '--ink-warn', on: '--bg-secondary', min: TEXT, where: '.disclosure__warn' },
  { ink: '--ink-accent', on: '--bg-card', min: TEXT, only: 'panel.css', where: 'VENDORED .tab-btn.active, corrected in panel.css' },

  // ── ink on a filled control ──
  { ink: '--bg', on: '--ink-accent', min: TEXT, where: '.chip--on, .btn--primary' },
  { ink: '--bg', on: '--ink-crit', min: TEXT, where: '.btn--danger:hover' },

  // ── non-text that carries meaning (1.4.11) ──
  { ink: '--border-control', on: '--bg', min: NONTEXT, where: 'field and button boundary on the page ground' },
  { ink: '--border-control', on: '--bg-card', min: NONTEXT, where: 'field and button boundary on a card' },
  { ink: '--border-control', on: '--bg-secondary', min: NONTEXT, where: 'chip boundary on a tinted strip' },
  { ink: '--ink-accent', on: '--bg-secondary', min: NONTEXT, only: 'portal.css', where: '.meter__fill against its track' },
  { ink: '--ink-warn', on: '--bg-secondary', min: NONTEXT, only: 'portal.css', where: '.meter__fill--warn against its track' },
  { ink: '--ink-crit', on: '--bg-secondary', min: NONTEXT, only: 'portal.css', where: '.meter__fill--crit against its track' },

  // ── the protocol marks. Non-text, so 3:1 against every surface a service
  //    label sits on. Their separation FROM EACH OTHER is not checkable here
  //    and is not the mechanism — the shape is. See the .proto block in
  //    panel.css.
  { ink: '--proto-1', on: '--bg-card', min: NONTEXT, only: 'panel.css', where: 'first service, in a table cell' },
  { ink: '--proto-2', on: '--bg-card', min: NONTEXT, only: 'panel.css', where: 'second service, in a table cell' },
  { ink: '--proto-3', on: '--bg-card', min: NONTEXT, only: 'panel.css', where: 'third service, in a table cell' },
  { ink: '--proto-more', on: '--bg-card', min: NONTEXT, only: 'panel.css', where: 'a fourth service this build has never met' },
  { ink: '--proto-1', on: '--bg-secondary', min: NONTEXT, only: 'panel.css', where: 'first service, on a hovered row' },
  { ink: '--proto-2', on: '--bg-secondary', min: NONTEXT, only: 'panel.css', where: 'second service, on a hovered row' },
  { ink: '--proto-3', on: '--bg-secondary', min: NONTEXT, only: 'panel.css', where: 'third service, on a hovered row' },
  { ink: '--proto-more', on: '--bg-secondary', min: NONTEXT, only: 'panel.css', where: 'fourth, on a hovered row' },
];

// ── Run ─────────────────────────────────────────────────────────────────────

const showTable = process.argv.includes('--table');
const problems = [];
const surfaces = [
  ['panel.css', PANEL, read(PANEL)],
  ['portal.css', PORTAL, read(PORTAL)],
];

for (const [label, , css] of surfaces) problems.push(...pairedPropertyProblems(label, css));

// The two token blocks must agree, or the portal quietly renders a different
// palette from the console it is administered by.
{
  const INK = ['--text-light', '--text-muted', '--ink-ok', '--ink-warn', '--ink-crit',
    '--ink-accent', '--border-control'];
  for (const theme of THEMES) {
    const a = themeTokens(read(PANEL), theme);
    const b = themeTokens(read(PORTAL), theme);
    for (const name of INK) {
      const [ra, rb] = [resolveToken(a, name), resolveToken(b, name)];
      if (ra !== rb) {
        problems.push(
          `${theme}: ${name} is ${ra} in panel.css but ${rb} in portal.css.\n` +
          '      The duplication is deliberate (the portal does not load panel.css);\n' +
          '      the two values drifting apart is not.',
        );
      }
    }
  }
}

// Every var(--x) the stylesheet reaches for, resolved against each theme's real
// table. Cheap, and it is what catches a token added to two theme blocks and
// forgotten in the third — which is the exact shape of the mina palette, every
// token of which has to be written out because the vendored file has no block
// for it to inherit from.
for (const [label, , css] of surfaces) {
  const referenced = new Set(
    [...strip(css).matchAll(/var\(\s*(--[\w-]+)/g)].map((m) => m[1]),
  );
  for (const theme of THEMES) {
    const table = themeTokens(css, theme);
    for (const name of referenced) {
      if (name in table) continue;
      problems.push(
        `${label} / ${theme}: ${name} is used but never defined for this theme.\n` +
        '      The declaration will be dropped and the property will inherit —\n' +
        '      silently, and only in this theme.',
      );
    }
  }
}

let checked = 0;
for (const [label, , css] of surfaces) {
  const rows = [];
  for (const theme of THEMES) {
    const table = themeTokens(css, theme);
    for (const p of PAIRS) {
      if (p.only && p.only !== label) continue;
      const ink = rgb(resolveToken(table, p.ink));
      const on = rgb(resolveToken(table, p.on));
      if (!ink || !on) {
        problems.push(`${label} / ${theme}: ${p.ink} on ${p.on} — a token does not resolve to a colour.`);
        continue;
      }
      const r = contrast(ink, on);
      checked += 1;
      const bad = r < p.min;
      if (showTable || bad) {
        rows.push(`  ${theme.padEnd(7)} ${(p.ink + ' on ' + p.on).padEnd(34)} ` +
                  `${r.toFixed(2).padStart(6)} / ${p.min}  ${bad ? 'FAIL' : 'ok  '}  ${p.where}`);
      }
      if (bad) {
        problems.push(
          `${label} / ${theme}: ${p.ink} on ${p.on} is ${r.toFixed(2)}:1, ` +
          `below ${p.min}:1.\n      ${p.where}`,
        );
      }
    }
  }
  if (showTable && rows.length) {
    console.log(`\n${label}`);
    console.log(rows.join('\n'));
  }
}

if (problems.length) {
  console.error('\nContrast check FAILED:\n');
  for (const p of problems) console.error(`  ${p}\n`);
  console.error('  These are the pairings a reader has to read. A failure here is not a');
  console.error('  matter of taste: it is text somebody cannot see, in a theme somebody');
  console.error('  chose, on a console read while something is wrong.\n');
  process.exit(1);
}

console.log(
  `Contrast OK — ${checked} pairings checked across ${THEMES.length} themes and ` +
  `${surfaces.length} stylesheets; every rule that paints a background names its ` +
  'colour beside it, every token referenced resolves in every theme, and the ' +
  'two ink token blocks agree.',
);
