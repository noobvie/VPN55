'use strict';
//
// panel/portal/tokens.js — the portal's access codes.
//
// One person, one or more codes. A code is what an operator hands somebody so
// they can fetch their own configuration, see their own usage and rotate their
// own credential. It is not a password and there is no password anywhere in the
// portal: the people this serves are not the people running the server, and a
// sign-up flow with a password to forget is a flow that generates support work
// in a market where support is a Telegram message at midnight.
//
// ── Why this is not in vpnctl, and does not need to be ───────────────────────
//
// Issuing a code changes nothing on the host. It writes one line into the
// panel's own state directory — which docs/security-model.md §3 already lists
// the panel as owning outright, portal tokens included. It touches no key, no
// server configuration and no register entry, so routing it through a root
// helper would widen the privileged surface to do something unprivileged.
//
// The corollary is worth stating plainly rather than leaving implied: a
// compromised panel can mint itself a portal code for any user. That is not a
// new power. The same compromised panel can already call `cred-add` and issue
// itself a working credential outright, which is strictly more.
//
// ── What is stored is not the code ───────────────────────────────────────────
//
// The file holds SHA-256 of each code, and the code itself is returned exactly
// once, at issue. Nothing on this host can recover it afterwards; a lost code is
// re-issued, not looked up.
//
// SHA-256 rather than scrypt, deliberately, and it is the opposite decision to
// the one auth.js makes about admin passwords. scrypt is slow on purpose
// because a password has perhaps 40 bits of entropy and an offline attacker
// gets unlimited guesses. A code here is 256 bits from crypto.randomBytes:
// there is no dictionary, no reuse from another site and no offline attack
// worth mounting, so the slow hash would buy nothing and would cost ~100ms of
// CPU on every single portal request. Fast is correct here; it would be a
// serious mistake in auth.js.
//
// The map is keyed BY the hash, so verifying is a lookup rather than a scan
// over every record comparing secrets — which is also what keeps the comparison
// free of a timing signal about how many codes exist.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const VERSION = 1;

// A recognisable prefix so a code that turns up somewhere it should not — a
// screenshot, a chat log, a support ticket — is identifiable as a VPN55 portal
// code at a glance, and greppable when somebody needs to find every place one
// leaked to. It is not a secret and it is not part of the entropy.
const PREFIX = 'vpn55_';
const SECRET_BYTES = 32;

// The shape a whole code has to match before it is even hashed. A cheap gate in
// front of the lookup, and it means a request body full of megabytes never gets
// as far as a hash.
const RE_TOKEN = /^vpn55_[A-Za-z0-9_-]{43}$/;

const RE_USER = /^[a-z][a-z0-9_-]{1,31}$/;
const RE_ID = /^[0-9a-f]{16}$/;

/** SHA-256, hex. The key this file is indexed by. */
function fingerprint(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('hex');
}

class PortalTokens {
  constructor({ file, warn = console.warn }) {
    this.file = file;
    this.warn = warn;
    this.state = { version: VERSION, tokens: Object.create(null) };
    this.loaded = false;
  }

  // ── Storage ───────────────────────────────────────────────────────────────

  load() {
    let raw;
    try {
      raw = fs.readFileSync(this.file, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        // No codes yet is the normal state of a fresh install, not a fault. The
        // portal answers 401 to everything until an operator issues one.
        this.loaded = true;
        return this.state;
      }
      throw err;
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      // Refusing beats starting empty. Starting empty would sign every user out
      // of the portal at once and give no sign of why — and the file is still
      // there and still readable by a human, so the recoverable answer is to
      // stop and say so.
      throw new Error(
        `${this.file}: unreadable (${err.message}). Every portal access code ` +
        'lives here and none of them can be recovered from anywhere else, so ' +
        'this is not being replaced automatically. Move it aside deliberately ' +
        'to start again — every user will then need a new code.');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`${this.file}: top level must be an object`);
    }
    if (parsed.version !== VERSION) {
      throw new Error(
        `${this.file}: written by version ${parsed.version}, this build understands ${VERSION}`);
    }

    // Null-prototype: a fingerprint is hex, so it cannot BE `__proto__` — but
    // the file is JSON on disk and a hand-edit could put one there, and a
    // lookup that found Object.prototype.constructor instead of a record is a
    // bug nobody would guess at from the symptom.
    this.state = {
      version: VERSION,
      tokens: Object.assign(Object.create(null), parsed.tokens || {}),
    };
    this.loaded = true;
    return this.state;
  }

  /** Atomic replace, mode 0600. The same discipline store.js uses. */
  save() {
    const dir = path.dirname(this.file);
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.mkdirSync(dir, { recursive: true, mode: 0o750 });
    let fd;
    try {
      fd = fs.openSync(tmp, 'wx', 0o600);
      fs.writeSync(fd, `${JSON.stringify(this.state, null, 2)}\n`);
      fs.fsyncSync(fd);
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
  }

  // ── Issuing ───────────────────────────────────────────────────────────────

  /**
   * Mint a code for one user.
   *
   * Returns { token, record }. `token` is the ONLY time the plaintext exists
   * anywhere; the caller shows it to the operator and then it is gone.
   *
   * `expiresInDays` is the life of the CODE, not of the account. It defaults to
   * never, because the code is how somebody gets back in on a new phone eight
   * months from now, and an expiry that quietly turned that into a support
   * request would be a worse default than an operator revoking it deliberately.
   */
  issue(user, { label = '', expiresInDays = null, now = Date.now() } = {}) {
    if (!RE_USER.test(user)) throw new Error(`invalid user name '${user}'`);
    if (expiresInDays !== null) {
      if (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 3650) {
        throw new Error('expiresInDays must be a whole number of days from 1 to 3650');
      }
    }

    const token = PREFIX + crypto.randomBytes(SECRET_BYTES).toString('base64url');
    const record = {
      // A short public handle for revoking one code without naming the code.
      // Derived from the fingerprint rather than randomly, so it cannot collide
      // with a different record's, and so it reveals nothing a fingerprint
      // already in this file does not.
      id: fingerprint(token).slice(0, 16),
      user,
      label: String(label || '').slice(0, 64),
      created: new Date(now).toISOString(),
      expiresAt: expiresInDays === null
        ? null
        : new Date(now + expiresInDays * 86_400_000).toISOString(),
      lastUsedAt: null,
      revokedAt: null,
    };

    this.state.tokens[fingerprint(token)] = record;
    this.save();
    return { token, record };
  }

  // ── Verifying ─────────────────────────────────────────────────────────────

  /**
   * A live record for this code, or null.
   *
   * null for a code that does not exist, one that was revoked, and one that has
   * expired — the caller must not tell those apart in a response, for the same
   * reason vpnctl gives one answer for three credential cases. Knowing that a
   * code was real but revoked is knowing something.
   *
   * `lastUsedAt` is recorded because "this code has never been used" is what an
   * operator looks at when somebody says they never received it. It is written
   * at most once a minute per code: the portal polls, and a disk write per poll
   * per user is a lot of fsync for a timestamp nobody reads to the second.
   */
  verify(token, { now = Date.now() } = {}) {
    if (typeof token !== 'string' || !RE_TOKEN.test(token)) return null;

    const record = this.state.tokens[fingerprint(token)];
    if (!record) return null;
    if (record.revokedAt) return null;
    if (record.expiresAt) {
      const t = Date.parse(record.expiresAt);
      // An unparseable expiry is treated as EXPIRED rather than as absent. A
      // corrupted date must fail closed: the other reading would turn one bad
      // character into a code that can never be timed out.
      if (Number.isNaN(t) || t <= now) return null;
    }

    const last = record.lastUsedAt ? Date.parse(record.lastUsedAt) : 0;
    if (!(now - last < 60_000)) {
      record.lastUsedAt = new Date(now).toISOString();
      try {
        this.save();
      } catch (err) {
        // Never fatal. A read-only state directory is a serious condition and
        // it is reported — but refusing somebody their own configuration
        // because a usage timestamp could not be written gets the priority
        // backwards, exactly as audit.js says of its own log.
        this.warn(`[portal] cannot record code use in ${this.file}: ${err.code || err.message}`);
      }
    }
    return record;
  }

  // ── Managing ──────────────────────────────────────────────────────────────

  /** Every record, newest first; optionally for one user. Never the codes. */
  list(user = null) {
    const out = [];
    for (const record of Object.values(this.state.tokens)) {
      if (user && record.user !== user) continue;
      out.push({ ...record });
    }
    out.sort((a, b) => String(b.created).localeCompare(String(a.created)));
    return out;
  }

  /**
   * Revoke one code by its public id. Returns the record, or null.
   *
   * Marked, not deleted — the same reasoning the credential register applies to
   * a revoked credential. "This code existed and was withdrawn" is a different
   * fact from "this code never existed", and afterwards is exactly when someone
   * needs to be able to tell them apart.
   */
  revoke(id, { now = Date.now() } = {}) {
    if (!RE_ID.test(String(id))) return null;
    for (const record of Object.values(this.state.tokens)) {
      if (record.id !== id) continue;
      if (record.revokedAt) return { ...record };
      record.revokedAt = new Date(now).toISOString();
      this.save();
      return { ...record };
    }
    return null;
  }

  /** Revoke every live code for one user. Returns how many were withdrawn. */
  revokeUser(user, { now = Date.now() } = {}) {
    let n = 0;
    for (const record of Object.values(this.state.tokens)) {
      if (record.user !== user || record.revokedAt) continue;
      record.revokedAt = new Date(now).toISOString();
      n += 1;
    }
    if (n) this.save();
    return n;
  }

  /** How many live codes exist, in total or for one user. */
  count(user = null) {
    let n = 0;
    for (const record of Object.values(this.state.tokens)) {
      if (user && record.user !== user) continue;
      if (record.revokedAt) continue;
      n += 1;
    }
    return n;
  }
}

module.exports = { PortalTokens, fingerprint, RE_TOKEN, PREFIX, VERSION };
