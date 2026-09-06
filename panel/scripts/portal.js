#!/usr/bin/env node
'use strict';
//
// panel/scripts/portal.js — access codes for the self-serve portal.
//
//   node scripts/portal.js list [user]
//   node scripts/portal.js issue  <user> [--label <text>] [--days <n>]
//   node scripts/portal.js revoke <id>
//   node scripts/portal.js revoke-user <user>
//   node scripts/portal.js link   <user> --url https://portal.example/ [...]
//
// Run on the host, as root or as the panel's service user. It exists so an
// operator with a terminal never needs the panel's web UI to get somebody
// online — and so a deployment that has switched sign-in off, or lost its
// administrator password, still has a way to hand out access.
//
// ── This is NOT the same shape as scripts/admin.js ───────────────────────────
//
// admin.js is console-only on purpose: an administrator password is the thing
// every other control depends on, and creating one is deliberately not a button
// behind a session that might have been stolen.
//
// A portal code is the opposite kind of secret. It grants one person a view of
// their own account and their own configuration, which they are entitled to
// anyway, and it has to REACH them — over Telegram, over Zalo, in a message.
// So the same operation exists in the admin panel as well, audited, and this is
// the second way rather than the only way.
//
// ── The code is shown once ───────────────────────────────────────────────────
//
// Only a SHA-256 of it is stored. Nothing on this host can print it again, and
// a lost code is re-issued rather than looked up. That is stated in the output
// rather than left for somebody to discover.

const fs = require('node:fs');
const path = require('node:path');

const { load: loadConfig, ConfigError } = require('../lib/config');
const { PortalTokens } = require('../portal/tokens');

const RE_USER = /^[a-z][a-z0-9_-]{1,31}$/;

function fail(message, extra = []) {
  process.stderr.write(`vpn55-portal: ${message}\n`);
  for (const line of extra) process.stderr.write(`  ${line}\n`);
  process.exit(1);
}

function usage() {
  process.stderr.write(`
vpn55 — self-serve portal access codes

  node scripts/portal.js list [user]
  node scripts/portal.js issue  <user> [--label <text>] [--days <n>]
  node scripts/portal.js revoke <id>
  node scripts/portal.js revoke-user <user>
  node scripts/portal.js link   <user> --url <portal URL> [--label <text>] [--days <n>]

A code is shown ONCE, when it is issued. Only its fingerprint is stored, so it
cannot be printed again — re-issue rather than look it up, and revoke the old
one if it may have gone astray.

\`link\` issues a code and prints a whole URL with it in the FRAGMENT. A fragment
is never sent to a server, so the code stays out of the web server's access log
and out of the Referer header of whatever the person clicks next. Send that link
and they are signed in with one tap; the page removes it from the address bar
once it has been read.

--days is the life of the CODE, not of the account. Leave it out for a code that
does not expire: it is how somebody gets back in on a new phone months from now,
and an expiry that quietly turns that into a support message is a worse default
than an operator revoking it deliberately.
`);
}

/** Options after the sub-command, checked rather than trusted. */
function parseOptions(argv) {
  const out = { label: '', days: null, url: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === '--label') {
      if (next === undefined) fail('--label needs a value');
      out.label = next; i += 1;
    } else if (arg === '--days') {
      if (next === undefined) fail('--days needs a value');
      if (!/^[0-9]+$/.test(next)) fail(`--days must be a whole number, got '${next}'`);
      out.days = Number(next); i += 1;
    } else if (arg === '--url') {
      if (next === undefined) fail('--url needs a value');
      out.url = next; i += 1;
    } else {
      fail(`unknown option '${arg}'`, ['Run with no arguments for the usage text.']);
    }
  }
  return out;
}

/**
 * Does the register know this person?
 *
 * A code for a user who does not exist is a code that redeems into a session
 * with no account behind it — the portal signs it straight back out, which
 * looks to the operator like a broken code rather than like a typo in a name.
 * So the name is checked here, where the mistake was made.
 *
 * It is a WARNING and not a refusal, because this script reads the register
 * directly and a deployment could reasonably have it somewhere else. Refusing
 * on a file this script only assumes the location of would be worse than saying
 * what it found.
 */
function warnIfUnknown(cfg, user) {
  let entries;
  try {
    entries = fs.readdirSync(cfg.user_dir);
  } catch (err) {
    process.stderr.write(
      `note: cannot read the user register at ${cfg.user_dir} ` +
      `(${err.code || err.message}); the name was not checked.\n`);
    return;
  }
  if (entries.includes(`${user}.conf`)) return;
  process.stderr.write(
    `WARNING: the register at ${cfg.user_dir} has no user called '${user}'.\n` +
    '  The code will be issued, and it will sign in and immediately sign out\n' +
    '  again, because there is no account for it to show. Create the user first:\n' +
    `    ${cfg.installer}   →  Users\n`);
}

function printRecord(record) {
  const bits = [
    record.id,
    record.user,
    `created ${record.created}`,
    `expires ${record.expiresAt || 'never'}`,
    `last used ${record.lastUsedAt || 'never'}`,
  ];
  if (record.revokedAt) bits.push(`REVOKED ${record.revokedAt}`);
  if (record.label) bits.push(`"${record.label}"`);
  process.stdout.write(`${bits.join('\t')}\n`);
}

function main() {
  const [, , command, ...rest] = process.argv;

  if (!command || command === '--help' || command === '-h') {
    usage();
    process.exit(command ? 0 : 2);
  }

  let cfg;
  try {
    // forListener:false — this script opens no socket, so the listener
    // arrangement checks (which trust_proxy goes with which bind) must not
    // stop it. They would otherwise lock an operator out of the very tool
    // that fixes a panel refusing to start.
    cfg = loadConfig({ forListener: false });
  } catch (err) {
    if (err instanceof ConfigError) fail('configuration is not usable:', err.problems);
    throw err;
  }

  if (!cfg.portal_enabled) {
    // Not a refusal: issuing a code before turning the portal on is a perfectly
    // reasonable order to do things in. It is said once so that "the code does
    // not work" has an answer before anyone has to go looking for one.
    process.stderr.write(
      `note: portal_enabled=0 in ${cfg.confPath}, so the portal is not listening.\n` +
      '  Codes issued now will work as soon as it is turned on.\n');
  }

  const tokens = new PortalTokens({ file: cfg.portal_tokens_file, warn: (m) => process.stderr.write(`${m}\n`) });
  try {
    tokens.load();
  } catch (err) {
    fail(err.message);
  }

  if (command === 'list') {
    const user = rest[0] || null;
    if (user && !RE_USER.test(user)) fail(`invalid user name '${user}'`);
    const records = tokens.list(user);
    if (!records.length) {
      process.stdout.write(
        user ? `no portal codes for ${user}\n` : `no portal codes in ${tokens.file}\n`);
      return;
    }
    for (const record of records) printRecord(record);
    return;
  }

  if (command === 'revoke') {
    const id = rest[0];
    if (!id) fail('revoke needs the id of a code — run `list` to see them');
    const record = tokens.revoke(id);
    if (!record) fail(`no portal code with id '${id}'`, ['Run `list` to see the ids.']);
    process.stdout.write(`revoked ${record.id} (${record.user})\n`);
    process.stderr.write(
      'A session already open on that code ends at its next request, not at its\n' +
      'expiry — the portal re-checks the code on every request it resolves.\n');
    return;
  }

  if (command === 'revoke-user') {
    const user = rest[0];
    if (!user || !RE_USER.test(user)) fail(`invalid user name '${user || ''}'`);
    const n = tokens.revokeUser(user);
    process.stdout.write(`revoked ${n} code(s) for ${user}\n`);
    return;
  }

  if (command !== 'issue' && command !== 'link') {
    usage();
    process.exit(2);
  }

  const user = rest[0];
  if (!user || !RE_USER.test(user)) {
    fail(`invalid user name '${user || ''}'`, [
      '2–32 characters: a lowercase letter first, then a-z 0-9 _ -',
    ]);
  }
  const opts = parseOptions(rest.slice(1));

  let base = null;
  if (command === 'link') {
    if (!opts.url) fail('link needs --url, the address the portal is served at');
    try {
      base = new URL(opts.url);
    } catch {
      fail(`--url is not a URL: '${opts.url}'`);
    }
    if (base.protocol !== 'https:' && base.hostname !== 'localhost' && base.hostname !== '127.0.0.1') {
      // A code travelling over plain HTTP is a code anyone on the path can read
      // and use. Refused rather than warned about: the whole link exists to be
      // sent to somebody over a network.
      fail(`--url must be https (got ${base.protocol}//)`, [
        'The link carries an access code. Over plain HTTP it is readable by',
        'anything between the two of you, and it grants that account.',
        'localhost and 127.0.0.1 are allowed for a local test.',
      ]);
    }
  }

  warnIfUnknown(cfg, user);

  let issued;
  try {
    issued = tokens.issue(user, { label: opts.label, expiresInDays: opts.days });
  } catch (err) {
    fail(err.message);
  }

  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    // Written as root, read by the panel. Said here rather than left to a
    // permission error at somebody's first sign-in attempt.
    process.stderr.write(
      `note: ${tokens.file} must be readable by the panel's service user.\n` +
      `  chown vpn55-panel:vpn55-panel ${tokens.file}\n`);
  }

  process.stdout.write('\n');
  if (command === 'link') {
    base.hash = `code=${encodeURIComponent(issued.token)}`;
    process.stdout.write(`${base.toString()}\n`);
  } else {
    process.stdout.write(`${issued.token}\n`);
  }
  process.stdout.write('\n');
  process.stderr.write(
    `id ${issued.record.id}   user ${issued.record.user}   ` +
    `expires ${issued.record.expiresAt || 'never'}\n` +
    'This is the only time it can be shown. Only its fingerprint is stored, so\n' +
    'it cannot be printed again — if it goes astray, revoke it and issue another:\n' +
    `  node ${path.relative(process.cwd(), __filename).replace(/\\/g, '/')} revoke ${issued.record.id}\n`);
}

try {
  main();
} catch (err) {
  fail(err && err.message ? err.message : String(err));
}

module.exports = { RE_USER, parseOptions };
