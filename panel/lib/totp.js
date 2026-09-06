'use strict';
//
// panel/lib/totp.js — RFC 6238 time-based one-time passwords, on node:crypto.
//
// No dependency, and no configurability: HMAC-SHA1, six digits, a thirty-second
// period. Those are not defaults here, they are the whole vocabulary.
//
// ── Why nothing is tunable ───────────────────────────────────────────────────
//
// RFC 6238 allows SHA-256 and SHA-512 and every digit count from six to eight.
// Real authenticator applications do not: several ignore the `algorithm` and
// `digits` parameters in an otpauth:// URI entirely and compute SHA-1/6 anyway.
// An operator who picked SHA-256 would enrol successfully, see a code on their
// phone, and be unable to sign in — with both sides certain they were right. So
// there is one shape, it is the one every app implements, and a stored record
// cannot name a different one.
//
// ── Two properties that make this a second factor rather than a formality ────
//
//  1. A CODE IS ACCEPTED ONCE. The verifier returns the counter it matched and
//     the caller refuses a counter it has already accepted. Without that, a code
//     shoulder-surfed or read out of a phishing page stays usable for the rest
//     of its 30-second step and the skew window either side — which is the whole
//     of the window an attacker relaying a code in real time needs.
//
//  2. THE COMPARE IS CONSTANT TIME, over a fixed length. A six-digit space is
//     small enough that a timing signal on the first digit is worth having, and
//     timingSafeEqual THROWS on a length mismatch, so the length is normalised
//     before the compare rather than checked inside it.
//
// ── The secret is 20 bytes ───────────────────────────────────────────────────
//
// 160 bits, which is what RFC 4226 §4 R6 requires and what every authenticator
// expects. Base32 without padding: `=` is legal in RFC 4648 and is rejected by
// several apps when it appears in an otpauth:// secret parameter.

const crypto = require('node:crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const DIGITS = 6;
const PERIOD = 30;
const SECRET_BYTES = 20;

/** RFC 4648 base32, no padding. */
function encodeBase32(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Base32 to Buffer, or null.
 *
 * Case-insensitive, and spaces and padding are ignored: authenticator apps
 * display a secret in groups of four and people retype what they see. A
 * character outside the alphabet is a null return rather than a silent skip — a
 * secret that decoded to "whatever of that was valid" would enrol a key neither
 * side can reproduce.
 */
function decodeBase32(text) {
  const clean = String(text || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean) return null;
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function randomSecret() {
  return encodeBase32(crypto.randomBytes(SECRET_BYTES));
}

/** Is this a secret we could actually compute with? */
function isSecret(text) {
  const raw = decodeBase32(text);
  return raw !== null && raw.length >= 10;
}

/** The time step a moment falls in. */
function counterFor(nowMs = Date.now()) {
  return Math.floor(nowMs / 1000 / PERIOD);
}

/**
 * The code for one counter, as a zero-padded string.
 *
 * ⚠ The counter is a 64-bit big-endian integer and JavaScript's bitwise
 * operators are 32-bit, so the high word is written with arithmetic rather than
 * a shift. It stays zero until some time in the year 6000; getting it wrong
 * would still be a bug that only ever appears on somebody else's clock.
 */
function codeFor(secret, counter) {
  const key = decodeBase32(secret);
  if (!key) return null;

  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const mac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | ((mac[offset + 1] & 0xff) << 16)
    | ((mac[offset + 2] & 0xff) << 8)
    | (mac[offset + 3] & 0xff);
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Check a code.
 *
 * @param {string} secret            base32, as stored
 * @param {string} token             what the operator typed
 * @param {object} [opts]
 * @param {number} [opts.nowMs]
 * @param {number} [opts.window=1]   steps of clock skew accepted either side
 * @param {number} [opts.notBefore]  the highest counter already spent for this
 *                                   account; a code at or below it is refused
 * @returns {{ok: boolean, counter: number|null, reason: string|null}}
 *
 * `reason` separates "wrong code" from "that code has already been used". The
 * second is either a double-submit or somebody replaying, and the caller audits
 * them differently.
 */
function verify(secret, token, { nowMs = Date.now(), window = 1, notBefore = -1 } = {}) {
  const typed = String(token || '').replace(/\s/g, '');
  if (!/^[0-9]{6}$/.test(typed)) return { ok: false, counter: null, reason: 'malformed' };
  if (!isSecret(secret)) return { ok: false, counter: null, reason: 'no_secret' };

  const current = counterFor(nowMs);
  let matched = null;
  // Every candidate is computed and compared, and the loop does NOT stop at a
  // match: returning early would take a different amount of time for a code one
  // step old than for a current one, which is a small oracle for the receiver's
  // clock offset. Three steps; the cost is nothing.
  for (let step = -window; step <= window; step += 1) {
    const counter = current + step;
    const expect = codeFor(secret, counter);
    if (expect === null) continue;
    const a = Buffer.from(expect, 'utf8');
    const b = Buffer.from(typed, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) matched = counter;
  }

  if (matched === null) return { ok: false, counter: null, reason: 'mismatch' };
  // Replay. See property 1 in the header.
  if (matched <= notBefore) return { ok: false, counter: matched, reason: 'reused' };
  return { ok: true, counter: matched, reason: null };
}

/**
 * The otpauth:// URI an authenticator imports.
 *
 * The issuer appears twice — once in the label path and once as a parameter.
 * That is not redundancy anybody enjoys; it is what the de-facto spec says, and
 * an app given only one of the two files the account under a blank issuer.
 */
function uri({ secret, account, issuer = 'VPN55' }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(PERIOD),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** Four-character groups — for reading off a terminal onto a phone. */
function grouped(secret) {
  return String(secret).replace(/(.{4})/g, '$1 ').trim();
}

module.exports = {
  encodeBase32, decodeBase32, randomSecret, isSecret,
  counterFor, codeFor, verify, uri, grouped,
  DIGITS, PERIOD, SECRET_BYTES,
};
