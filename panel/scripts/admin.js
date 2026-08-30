#!/usr/bin/env node
'use strict';
//
// panel/scripts/admin.js — administrator accounts for the panel.
//
//   node scripts/admin.js list
//   node scripts/admin.js add     <name>
//   node scripts/admin.js passwd  <name>
//   node scripts/admin.js remove  <name>
//
// Run as ROOT, on the host, from a terminal. It is not reachable from the panel
// and there is no HTTP route that does any of this — an admin account is the
// thing every other control depends on, so creating one is deliberately an
// action at the console rather than a button behind a session that might have
// been stolen. docs/security-model.md §2 lists the reset path as "via the
// installer, as root"; this is that path.
//
// ── Why the password never appears in argv ───────────────────────────────────
//
// It is read from the terminal with echo off, or from stdin when there is no
// terminal. It is never an argument, because argv is world-readable in
// /proc/<pid>/cmdline for the life of the process — the same reason the wallet
// tooling in a sibling project stopped using `-p`. It is never echoed, never
// logged, and never written anywhere except as an scrypt hash.
//
// ── What it writes ───────────────────────────────────────────────────────────
//
//   { "admins": { "<name>": { "hash": "scrypt$…", "created": "…", "updated": "…" } } }
//
// at cfg.admins_file, mode 0600, owned by the panel's service user — the panel
// reads it on every login. Written through a temp file and renamed, so a failed
// write cannot truncate the file that holds every administrator on the host.

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { load: loadConfig, ConfigError } = require('../lib/config');
const { hashPassword, verifyPassword } = require('../lib/auth');

// The same shape helper/vpnctl and the register enforce for a user name. An
// admin name is a different namespace, but there is no reason for it to be a
// wider one, and a narrow name cannot be mistaken for an option or a path.
const RE_NAME = /^[a-z][a-z0-9_-]{1,31}$/;

const MIN_LENGTH = 12;

function fail(message, extra = []) {
  process.stderr.write(`vpn55-admin: ${message}\n`);
  for (const line of extra) process.stderr.write(`  ${line}\n`);
  process.exit(1);
}

function usage() {
  process.stderr.write(`
vpn55 panel — administrator accounts

  node scripts/admin.js list
  node scripts/admin.js add     <name>
  node scripts/admin.js passwd  <name>
  node scripts/admin.js remove  <name>

Run as root on the host. The password is read from the terminal with echo off,
never from an argument — argv is world-readable while the process runs.

Removing an account does not end a session it already has. Restart the panel to
drop every session on the host:  systemctl restart vpn55-panel
`);
}

function readAdmins(file) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    fail(`cannot read ${file}: ${err.code || err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.admins || typeof parsed.admins !== 'object') {
    fail(`${file} does not look like an admin file`, [
      'Expected {"admins": {"<name>": {"hash": "scrypt$…"}}}.',
      'Move it aside and create the account again rather than editing it by hand.',
    ]);
  }
  return parsed.admins;
}

function writeAdmins(file, admins) {
  const dir = path.dirname(file);
  const tmp = `${file}.tmp`;
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
    fs.writeFileSync(tmp, `${JSON.stringify({ admins }, null, 2)}\n`, { mode: 0o600 });
    // Renamed over rather than written in place: a failed write must never
    // truncate the file listing every administrator on this host.
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* the temp file may not exist */ }
    fail(`cannot write ${file}: ${err.code || err.message}`);
  }
}

/**
 * Read a password with echo off.
 *
 * With no terminal it reads one line from stdin instead, so the account can be
 * created from a provisioning script — still not from argv. The distinction is
 * the point: a pipe is as private as the thing on the other end of it, and argv
 * is private to nobody.
 */
function readSecret(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      let buf = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (c) => { buf += c; });
      process.stdin.on('end', () => resolve(buf.split('\n')[0]));
      process.stdin.on('error', reject);
      return;
    }

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    process.stdout.write(prompt);

    // Suppress the echo of everything typed between now and the newline. The
    // prompt itself is written above so it survives.
    const original = rl._writeToOutput;
    rl._writeToOutput = function muted(text) {
      if (text.includes('\n') || text.includes('\r')) original.call(rl, '\n');
    };

    rl.question('', (answer) => {
      rl._writeToOutput = original;
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Two entries, compared, and a floor on the length.
 *
 * The floor is length only — no character-class rule. A composition rule pushes
 * people towards `Password1!` and away from a passphrase, and this hash is
 * scrypt, so length is the thing that actually costs an attacker anything.
 */
async function newPassword() {
  const first = await readSecret('New password: ');
  if (first.length < MIN_LENGTH) {
    fail(`the password must be at least ${MIN_LENGTH} characters`, [
      'Length is the only rule. A passphrase of four ordinary words beats',
      'anything short with punctuation in it, and this hash is scrypt.',
    ]);
  }
  if (process.stdin.isTTY) {
    const again = await readSecret('Repeat: ');
    if (again !== first) fail('the two entries do not match; nothing was changed');
  }
  return first;
}

async function main() {
  const [, , command, name] = process.argv;

  if (!command || command === '--help' || command === '-h') {
    usage();
    process.exit(command ? 0 : 2);
  }

  let cfg;
  try {
    cfg = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) fail('configuration is not usable:', err.problems);
    throw err;
  }

  const file = cfg.admins_file;
  const admins = readAdmins(file);

  if (command === 'list') {
    const names = Object.keys(admins).sort();
    if (names.length === 0) {
      process.stdout.write(`no administrators in ${file}\n`);
      return;
    }
    for (const n of names) {
      const rec = admins[n] || {};
      process.stdout.write(`${n}\tcreated ${rec.created || '-'}\tupdated ${rec.updated || '-'}\n`);
    }
    return;
  }

  if (!['add', 'passwd', 'remove'].includes(command)) {
    usage();
    process.exit(2);
  }

  // Writing the file is only useful as the user the panel runs as, or as root
  // with the ownership fixed afterwards. Said once, here, rather than left to a
  // permission error at the panel's next login attempt.
  if (typeof process.getuid === 'function' && process.getuid() !== 0) {
    process.stderr.write(
      `note: not running as root. ${file} must end up owned by the panel's service ` +
      'user and mode 0600, or the panel cannot read it.\n');
  }

  if (!name || !RE_NAME.test(name)) {
    fail(`invalid administrator name${name ? ` '${name}'` : ''}`, [
      '2–32 characters: a lowercase letter first, then a-z 0-9 _ -',
    ]);
  }

  const exists = Object.hasOwn(admins, name);

  if (command === 'remove') {
    if (!exists) fail(`no administrator named '${name}'`);
    if (Object.keys(admins).length === 1) {
      fail(`'${name}' is the only administrator`, [
        'Removing it would leave a panel with sign-in on and nobody able to sign in,',
        'which is indistinguishable from a forgotten password. Add the replacement',
        'first, then remove this one.',
      ]);
    }
    delete admins[name];
    writeAdmins(file, admins);
    process.stdout.write(`removed ${name}\n`);
    process.stderr.write(
      'Their current session is still valid until it expires. ' +
      'Restart the panel to end every session now: systemctl restart vpn55-panel\n');
    return;
  }

  if (command === 'add' && exists) {
    fail(`'${name}' already exists`, ['Use `passwd` to change their password.']);
  }
  if (command === 'passwd' && !exists) {
    fail(`no administrator named '${name}'`, ['Use `add` to create them.']);
  }

  const password = await newPassword();

  // A new password that is the current one is a no-op the operator would read as
  // a rotation. Worth one comparison at a cost nobody notices.
  if (command === 'passwd' && verifyPassword(password, admins[name].hash)) {
    fail('that is the current password; nothing was changed');
  }

  const now = new Date().toISOString();
  admins[name] = {
    hash: hashPassword(password),
    created: exists ? (admins[name].created || now) : now,
    updated: now,
  };
  writeAdmins(file, admins);

  process.stdout.write(`${command === 'add' ? 'created' : 'updated'} ${name}\n`);
  process.stdout.write(`${file}  (mode 0600 — it must be readable by the panel's user)\n`);
  if (command === 'passwd') {
    process.stderr.write(
      'Existing sessions for this account are NOT ended by a password change. ' +
      'Restart the panel to end them: systemctl restart vpn55-panel\n');
  }
}

main().catch((err) => {
  fail(err && err.message ? err.message : String(err));
});

module.exports = { RE_NAME, MIN_LENGTH };
