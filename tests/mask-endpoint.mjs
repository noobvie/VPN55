#!/usr/bin/env node
//
// Does the Connections table's address mask actually mask?
//
// ── Why this has a test when nothing else in format.js does ─────────────────
//
// Every other function in format.js fails LOUDLY. A byte count formatted wrong
// is a wrong byte count on screen and somebody says so. This one fails QUIETLY
// and in the direction that matters: a mask that lets a value through renders
// something that looks masked to whoever is reading, gets photographed for the
// README (docs/launch.md asks for a screenshot of this exact table), and nobody
// finds out because the output has the right SHAPE.
//
// So the cases below are mostly the ones where a lenient parser would say yes:
//
//   10.1.2.3.evil.example   four octets and a suffix. A `startsWith`-shaped
//                           test masks nothing here and reports success.
//   999.1.2.3               syntactically four octets, none of them an octet.
//   2001:db8::1             `::` stands for an unknown number of zero groups,
//                           so reading three groups off the LITERAL text gives
//                           the right answer here by luck and the wrong one for
//                           ::1 — which is why the elision is expanded first.
//   ::ffff:192.0.2.128      an IPv4 tail is two groups, not one. Counting
//                           colons puts the /48 boundary in the wrong place.
//   fe80::1%eth0            a zone index. Not maskable by this code, and it
//                           must come back as UNMASKABLE rather than as a
//                           best-effort prefix — the whole design is fail
//                           closed, and this is the case that tests it.
//
// Run locally:  node tests/mask-endpoint.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'panel/public/js/format.js');

// format.js is a browser script, not a module: it declares one global and has
// no exports. Evaluating it against a stub i18n is how it gets tested without
// adding a build step to a panel that deliberately has none.
globalThis.VPN55_I18N = { t: (k) => `<${k}>`, current: () => 'en' };
(0, eval)(`${fs.readFileSync(SRC, 'utf8')};globalThis.__FMT = VPN55_FMT;`);
const { maskEndpoint } = globalThis.__FMT;

// [input, expected text, expected `masked` flag]
const CASES = [
  // IPv4, with and without the port an adapter usually appends.
  ['203.0.113.47', '203.0.113.0/24', true],
  ['203.0.113.47:51820', '203.0.113.0/24:51820', true],
  ['10.8.0.6', '10.8.0.0/24', true],
  ['198.51.100.255:1194', '198.51.100.0/24:1194', true],

  // IPv6 — the elision is expanded before three groups are taken off the front.
  ['2001:db8:1234:5678::1', '2001:db8:1234::/48', true],
  ['2001:db8::1', '2001:db8::/48', true],
  ['::1', '::/48', true],
  ['::ffff:192.0.2.128', '::/48', true],
  ['[2001:db8:1234:5678::1]:51820', '[2001:db8:1234::/48]:51820', true],
  ['fd00:1111:2222:3333::9', 'fd00:1111:2222::/48', true],

  // Nothing that is not an address may be displayed as though it were masked.
  ['fe80::1%eth0', null, false],
  ['vpn.example.org:1194', null, false],
  ['10.1.2.3.evil.example', null, false],
  ['999.1.2.3', null, false],
  ['203.0.113', null, false],
  ['2001:db8::1::2', null, false],
  ['not an address', null, false],

  // Absent is absent, and that is already the dash. Not a mask failure.
  ['', '—', true],
  [null, '—', true],
  [undefined, '—', true],
];

const failures = [];
for (const [input, wantText, wantMasked] of CASES) {
  const got = maskEndpoint(input);
  if (got.masked !== wantMasked) {
    failures.push(
      `${JSON.stringify(input)}: masked=${got.masked}, expected ${wantMasked}` +
      (got.masked ? ` — it produced "${got.text}", which will be shown as an address` : ''),
    );
    continue;
  }
  if (wantText !== null && got.text !== wantText) {
    failures.push(`${JSON.stringify(input)}: got "${got.text}", expected "${wantText}"`);
  }
}

// A separate assertion, because it is the one that matters: nothing that came
// back as masked may still contain the whole of what went in.
for (const [input] of CASES) {
  if (typeof input !== 'string' || !input) continue;
  const got = maskEndpoint(input);
  const bare = input.replace(/^\[|\](:\d+)?$/g, '').split('%')[0];
  if (got.masked && got.text.includes(bare) && bare.length > 3) {
    failures.push(`${JSON.stringify(input)}: reported masked but the full address survived in "${got.text}"`);
  }
}

if (failures.length) {
  console.error('Address mask check FAILED:\n');
  for (const f of failures) console.error(`  ${f}`);
  console.error('\n  This mask is what stops a remote address the collector deliberately');
  console.error('  never stored being written down by a camera instead.\n');
  process.exit(1);
}

console.log(`Address mask OK — ${CASES.length} cases; every value that reports itself masked is one.`);
