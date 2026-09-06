#!/usr/bin/env node
'use strict';
//
// panel/scripts/admin.js — administrator accounts for the panel.
//
//   node scripts/admin.js list
//   node scripts/admin.js add     <name>
//   node scripts/admin.js passwd  <name>
//   node scripts/admin.js remove  <name>
//   node scripts/admin.js totp    <name>            enrol a second factor
//   node scripts/admin.js totp --clear <name>       remove one (break-glass)
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
// ── The second factor, and why enrolling it is a console action ──────────────
//
// TOTP gates SIGNING IN, not each write (panel/lib/auth.js, decision 6). That
// only holds up if the factor cannot be enrolled, replaced or removed from the
// panel itself: a stolen session that could enrol a factor of its own would have
// turned the second factor into a lock it holds the key to, and one that could
// clear a factor would have turned it off.
//
// So all three live here, behind root on the host, and there are deliberately NO
// remote recovery codes. A stack of single-use secrets that skip the factor,
// stored on the same host as the hashes, is a bypass — and it buys nothing,
// because the person who would use it is the person who can already run
// `totp --clear` at this console. The break-glass path for a lost phone is that
// command, and requiring root for it is what stops it being a way in.
//
// ── What it writes ───────────────────────────────────────────────────────────
//
//   { "admins": { "<name>": {
//        "hash": "scrypt$…", "created": "…", "updated": "…",
//        "totp": { "secret": "<base32>", "enrolledAt": "…" }
//   } } }
//
// at cfg.admins_file, mode 0600, owned by the panel's service user — the panel
// reads it on every login and never writes it. Written through a temp file and
// renamed, so a failed write cannot truncate the file that holds every
// administrator on the host. panel/lib/admins.js is the one reader and the one
// writer of that format.

const readline = require('node:readline');

const { load: loadConfig, ConfigError } = require('../lib/config');
const { hashPassword, verifyPassword } = require('../lib/auth');
const adminFile = require('../lib/admins');
const totp = require('../lib/totp');

// The portal's QR encoder, reused rather than reimplemented. It is a browser
// file that guards its export so it also loads in Node, which is how
// portal-selftest.js already checks its tables against published values — so
// this is the one encoder in the tree and it is the one CI verifies. A second
// copy here would be a second set of those tables, and a mistyped figure in one
// of them produces a plausible square that no phone can read.
const QR = require('../portal/public/js/qr');

const RE_NAME = adminFile.RE_NAME;

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
  node scripts/admin.js totp    <name>          enrol a second factor (TOTP)
  node scripts/admin.js totp --clear <name>     remove it — the break-glass path

Run as root on the host. The password is read from the terminal with echo off,
never from an argument — argv is world-readable while the process runs.

Removing an account does not end a session it already has. Restart the panel to
drop every session on the host:  systemctl restart vpn55-panel
`);
}

function readAdmins(file) {
  try {
    return adminFile.read(file);
  } catch (err) {
    fail(err.message, err.hints || []);
    return Object.create(null);   // not reached; fail() exits
  }
}

function writeAdmins(file, admins) {
  try {
    adminFile.write(file, admins);
  } catch (err) {
    fail(err.message, err.hints || []);
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
 * Read a line WITH echo.
 *
 * Used for the TOTP confirmation code. Hiding it would be security theatre with
 * a cost: the code is six digits that expire in half a minute and are already on
 * a screen in the operator's hand, and a hidden field is a field where a typo is
 * invisible — at the exact moment somebody is checking whether enrolment worked.
 */
function readLine(prompt) {
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
    rl.question(prompt, (answer) => { rl.close(); resolve(answer); });
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

/**
 * A QR code, in the terminal, that a phone camera can actually read.
 *
 * ── Why the colours are explicit and not the terminal's ─────────────────────
 *
 * A scanner needs the dark modules DARK against a light field. Printing solid
 * blocks and letting them inherit the terminal's palette gets that right on a
 * light theme and exactly backwards on a dark one — and the result is not a
 * visible failure, it is a handsome square that no phone will read, which is
 * the worst outcome for something whose only job is to be scanned. So every
 * cell names both its foreground and its background: black modules on white,
 * whatever the operator's theme is.
 *
 * ── Why half blocks ─────────────────────────────────────────────────────────
 *
 * An otpauth URI is around 110 bytes, which is a version-6 or -7 code: 45
 * modules plus a four-module quiet zone on each side. One character per module
 * is 53 columns, which fits an 80-column terminal; two rows per character line
 * is 27 lines, which fits a screen. Two characters per module would be 106
 * columns and would wrap, and a wrapped QR is not a QR.
 *
 * Returns null when there is no terminal or the encoder declines — the key and
 * the URI are printed either way, so this is an addition, never the only path.
 */
function qrLines(text) {
  if (!process.stdout.isTTY) return null;
  let code;
  try {
    code = QR.encode(text);
  } catch {
    return null;
  }
  if (!code || !code.modules) return null;

  const QUIET = 4;
  const size = code.size;
  const width = size + QUIET * 2;
  // 1 = dark. Outside the code is the quiet zone, which must be light.
  const at = (r, c) => {
    const y = r - QUIET;
    const x = c - QUIET;
    if (y < 0 || x < 0 || y >= size || x >= size) return 0;
    return code.modules[y][x];
  };

  const FG = { 0: '97', 1: '30' };   // bright white ink, black ink
  const BG = { 0: '107', 1: '40' };  // bright white field, black field

  const lines = [];
  for (let r = 0; r < width; r += 2) {
    let line = '';
    for (let c = 0; c < width; c += 1) {
      const top = at(r, c);
      // An odd number of rows leaves the last line with no bottom half; it must
      // be LIGHT, not a repeat of the top, or the code gains a row of modules
      // that is not in it.
      const bottom = r + 1 < width ? at(r + 1, c) : 0;
      line += `\x1b[${FG[top]};${BG[bottom]}m▀`;
    }
    lines.push(line + '\x1b[0m');
  }
  return lines;
}

/**
 * Enrol a second factor.
 *
 * ⚠ The secret is only stored once a CURRENT CODE HAS BEEN PROVED. Writing it
 * first and trusting the operator to have scanned it correctly is how somebody
 * ends up locked out of their own panel by a phone whose clock is wrong, an app
 * that ignored the parameters, or a mistyped key — and the symptom is identical
 * in all three cases: a code that is always refused, with nothing to say why.
 * Nothing is written unless this host and that phone have already agreed once.
 */
async function enrolTotp(file, admins, name) {
  const secret = totp.randomSecret();
  const uri = totp.uri({ secret, account: name });

  process.stdout.write(`
Enrol a second factor for '${name}'.
`);

  // The code, when there is a terminal to draw it in. The key and the URI are
  // printed either way: over a connection that mangles the block characters, or
  // into a log, the QR is the part that degrades and the text is the part that
  // still works.
  const qr = qrLines(uri);
  if (qr) {
    process.stdout.write('\nScan this with an authenticator app:\n\n');
    for (const line of qr) process.stdout.write('  ' + line + '\n');
  }

  process.stdout.write(`
${qr ? 'Or type the key in by hand' : 'Add this to an authenticator app'} — the key and the URI
describe the same secret${qr ? ' as the code above' : ''}.

  Key  ${totp.grouped(secret)}
  URI  ${uri}

It is SHA-1, 6 digits, 30 seconds — the shape every authenticator implements.
This key is shown once and is not stored anywhere it can be read back.

`);

  const typed = await readLine('Enter the code your app is showing now: ');
  const check = totp.verify(secret, typed);
  if (!check.ok) {
    fail('that code does not match, so NOTHING was saved', [
      "The account still signs in with its password alone; nothing is broken.",
      '',
      'Two things cause this. Either the key was not entered correctly — start',
      'again and check it character by character — or this host and the phone',
      'disagree about the time by more than 30 seconds. Check the clock here:',
      '',
      '  timedatectl status        # "System clock synchronized: yes"',
    ]);
  }

  admins[name].totp = { secret, enrolledAt: new Date().toISOString() };
  admins[name].updated = new Date().toISOString();
  writeAdmins(file, admins);

  process.stdout.write(`
Enrolled. '${name}' now needs a code as well as a password to sign in.

Sessions that are already open are NOT affected. Restart the panel to end them:
  systemctl restart vpn55-panel

If the phone is ever lost, clear the factor from this console:
  node ${process.argv[1]} totp --clear ${name}
`);
}

/**
 * The break-glass path.
 *
 * It is not a bypass, and the difference is worth being precise about: running
 * it needs root on this host, and root can already read the hashes, rewrite this
 * file, stop the panel and change every credential the panel could. It removes
 * nothing an attacker who could run it did not already have.
 *
 * That is exactly why there is no remote equivalent.
 */
function clearTotp(file, admins, name) {
  if (!adminFile.totpSecret(admins[name])) {
    fail(`'${name}' has no second factor enrolled`, [
      'Nothing was changed. `list` shows which accounts have one.',
    ]);
  }
  delete admins[name].totp;
  admins[name].updated = new Date().toISOString();
  writeAdmins(file, admins);

  process.stdout.write(`Cleared the second factor for ${name}.\n`);
  process.stderr.write(
    "That account now signs in with its password alone. If require_totp=1 in " +
    'panel.conf it cannot sign in at all until a new factor is enrolled, which ' +
    'is the safe direction but is not what somebody standing at a lost phone ' +
    'usually wants — enrol the replacement now:\n' +
    `  node ${process.argv[1]} totp ${name}\n`);
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === '--help' || command === '-h') {
    usage();
    process.exit(command ? 0 : 2);
  }

  // `totp --clear <name>` is the one subcommand with a flag, so the name is not
  // always argv[1]. Parsed explicitly rather than by position: a flag silently
  // read as a name would create an administrator called `--clear`.
  const clearFlag = argv.includes('--clear');
  const name = argv.slice(1).find((a) => !a.startsWith('-'));

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
      // Whether an account holds a second factor is the first thing worth
      // knowing about it, so it is a column rather than something to work out
      // by opening the JSON.
      const factor = adminFile.totpSecret(rec) ? '2fa' : '-';
      process.stdout.write(
        `${n}\t${factor}\tcreated ${rec.created || '-'}\tupdated ${rec.updated || '-'}\n`);
    }
    if (cfg.require_totp) {
      const bare = names.filter((n) => adminFile.isUsable(admins[n]) && !adminFile.totpSecret(admins[n]));
      if (bare.length) {
        process.stderr.write(
          `\nrequire_totp=1 in ${cfg.confPath}, and ${bare.length} account(s) above ` +
          'have no second factor. They cannot sign in until one is enrolled: ' +
          `${bare.join(', ')}\n`);
      }
    }
    return;
  }

  if (!['add', 'passwd', 'remove', 'totp'].includes(command)) {
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

  if (command === 'totp') {
    if (!exists) fail(`no administrator named '${name}'`, ['Use `add` to create them.']);
    if (clearFlag) { clearTotp(file, admins, name); return; }
    if (adminFile.totpSecret(admins[name])) {
      fail(`'${name}' already has a second factor enrolled`, [
        'Clear it first, then enrol the new device:',
        `  node ${process.argv[1]} totp --clear ${name}`,
        '',
        'Two steps rather than one, so replacing a factor is never something',
        'that happens by running the enrol command a second time by mistake.',
      ]);
    }
    await enrolTotp(file, admins, name);
    return;
  }

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
    // Spread FIRST, so an existing record keeps every field this command does
    // not set — the second factor above all. A `passwd` that rebuilt the record
    // from scratch would silently un-enrol somebody's authenticator, and the
    // symptom would be a factor that simply stopped being asked for, which
    // nobody reports as a bug.
    ...(exists ? admins[name] : {}),
    hash: hashPassword(password),
    created: exists ? (admins[name].created || now) : now,
    updated: now,
  };
  writeAdmins(file, admins);

  process.stdout.write(`${command === 'add' ? 'created' : 'updated'} ${name}\n`);
  process.stdout.write(`${file}  (mode 0600 — it must be readable by the panel's user)\n`);
  if (command === 'add') {
    process.stdout.write(
      `Enrol a second factor for them:  node ${process.argv[1]} totp ${name}\n`);
  }
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
