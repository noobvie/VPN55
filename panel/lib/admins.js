'use strict';
//
// panel/lib/admins.js — the administrator file, read and written in one place.
//
//   { "admins": { "<name>": {
//        "hash":    "scrypt$…",
//        "created": "2026-08-31T…",
//        "updated": "2026-08-31T…",
//        "totp":    { "secret": "<base32>", "enrolledAt": "…" }   ← optional
//   } } }
//
// at cfg.admins_file, mode 0600, owned by the panel's service user.
//
// ── Why this is a module and not two copies ──────────────────────────────────
//
// It was two copies: scripts/admin.js read and wrote it, panel/lib/auth.js read
// it, and the two agreed only because nothing had changed the format yet. Adding
// a field is exactly the change that breaks that kind of agreement — one side
// preserves it, the other drops it on the next write, and the symptom is a
// second factor that silently disappears the next time somebody changes their
// password. One reader and one writer, here.
//
// ── The panel process NEVER writes this file ─────────────────────────────────
//
// `write` exists for scripts/admin.js, which runs as root at a console. Nothing
// reachable over HTTP calls it, and that is deliberate rather than incidental:
// enrolling a second factor, clearing one, and changing a password are all
// console actions, so a stolen session cannot enrol a factor of its own or
// remove the one that is there. The panel opens this file read-only, on every
// login, and that is the whole of its relationship with it.
//
// It follows that the second factor's REPLAY GUARD cannot live here — writing a
// counter per login would hand the HTTP process a write path to the file holding
// every hash on the host, to save a failure mode that a restart already bounds.
// It lives in memory in auth.js instead; see the note there.

const fs = require('node:fs');
const path = require('node:path');

// The same shape helper/vpnctl and the register enforce for a user name. An
// administrator is a different namespace, but there is no reason for it to be a
// wider one, and a narrow name cannot be mistaken for an option or a path.
const RE_NAME = /^[a-z][a-z0-9_-]{1,31}$/;

class AdminFileError extends Error {
  constructor(message, hints = []) {
    super(message);
    this.name = 'AdminFileError';
    this.hints = hints;
  }
}

/**
 * Read the file.
 *
 * A missing file is an empty set, not an error — that is a host where nobody has
 * been created yet, and server.js has its own refusal for it. Anything present
 * but not the expected shape THROWS: quietly treating a malformed file as "no
 * administrators" would turn a corrupted file into a panel that refuses to start
 * for a reason that names the wrong thing.
 *
 * Copied onto a null-prototype object: a name of `constructor` or `__proto__`
 * must look up nothing rather than find a function.
 */
function read(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return Object.create(null);
    throw new AdminFileError(`cannot read ${file}: ${err.code || err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new AdminFileError(`${file} is not readable JSON: ${err.message}`, [
      'Move it aside deliberately and create the account again rather than',
      'editing it by hand — it holds every administrator on this host.',
    ]);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.admins || typeof parsed.admins !== 'object') {
    throw new AdminFileError(`${file} does not look like an administrator file`, [
      'Expected {"admins": {"<name>": {"hash": "scrypt$…"}}}.',
    ]);
  }
  return Object.assign(Object.create(null), parsed.admins);
}

/**
 * Replace the file.
 *
 * Written to a temp file and renamed, so a failed write cannot truncate the file
 * that lists every administrator on the host. Mode 0600 on the temp file, before
 * the rename, rather than after: a file that exists for even a moment at the
 * umask default is a file somebody could have opened.
 */
function write(file, admins) {
  const dir = path.dirname(file);
  const tmp = `${file}.tmp`;
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
    fs.writeFileSync(tmp, `${JSON.stringify({ admins }, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* the temp file may not exist */ }
    throw new AdminFileError(`cannot write ${file}: ${err.code || err.message}`);
  }
}

/** A record that could actually authenticate somebody. */
function isUsable(record) {
  return Boolean(record && typeof record.hash === 'string' && record.hash.startsWith('scrypt$'));
}

/**
 * The enrolled second-factor secret, or null.
 *
 * Deliberately strict about the shape: a `totp` key holding anything other than
 * a string secret is treated as NOT enrolled, which means the account signs in
 * with a password alone. That is the safe direction only because enrolment is a
 * console action — a corrupted field cannot be planted over HTTP, and the
 * alternative (refusing every login) locks the operator out of the panel over a
 * malformed field they cannot see.
 *
 * `require_totp` is what closes that gap for an operator who would rather be
 * locked out than let an account through on one factor.
 */
function totpSecret(record) {
  if (!record || !record.totp || typeof record.totp !== 'object') return null;
  const secret = record.totp.secret;
  return typeof secret === 'string' && secret.length >= 16 ? secret : null;
}

module.exports = { read, write, isUsable, totpSecret, AdminFileError, RE_NAME };
