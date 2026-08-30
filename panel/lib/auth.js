'use strict';

// panel/lib/auth.js — admin session handling.
//
// Session-based, rate-limited on failure, lockout keyed on (username, IP), on
// the makeRateLimiter factory pattern vendored into panel/lib/rate-limit.js.
//
// The self-serve portal (Phase 8) does NOT use this module. It gets its own auth
// model on its own route tree — a role flag on shared admin routes is exactly
// how a user reaches an admin endpoint.
//
// ── Five decisions, each with a failure it is avoiding ────────────────────────
//
//  1. SESSIONS LIVE IN MEMORY, NOT ON DISK. A restart logs everybody out, which
//     is the correct trade for a panel one person uses: a token written to disk
//     is a token that survives a compromise, survives a backup, and outlives the
//     process that could have expired it. (docs/security-model.md §2 said the
//     state directory; Phase 6 moved it into memory and the table says so now.)
//
//  2. AN ABSOLUTE TTL, CAPPED, AS WELL AS AN IDLE TIMEOUT. A bearer token cannot
//     be withdrawn from the client's side, so "still logged in from last month"
//     is a credential with no expiry wearing a session's name. The absolute cap
//     is 24h and config cannot raise it.
//
//  3. IDLE COUNTS INTERACTION, NEVER TRAFFIC. The panel polls status; if a poll
//     refreshed the idle clock, an open tab would keep a session alive forever
//     and the idle timeout would be decorative. Only requests the caller marks
//     as interactive — every write, and an explicit heartbeat the UI sends on
//     real input — touch it. Reads do not.
//
//  4. THE PASSWORD CHECK COSTS THE SAME FOR AN UNKNOWN USER. Without that, the
//     response time answers "does this account exist?" for free, and username
//     enumeration is the first half of every credential-stuffing run. An unknown
//     username is verified against a fixed dummy hash and then fails.
//
//  5. WRITES NEED A HEADER, NOT JUST A COOKIE. SameSite=Strict already stops a
//     cross-site form post, but it is one browser default away from not being
//     enough, and the panel is the one thing on this box that can revoke access.
//     Every write also carries the session's CSRF token in a request header,
//     which a cross-origin page cannot set and cannot read.

const crypto = require('node:crypto');
const fs = require('node:fs');

const { clientIp, makeRateLimiter, makeLockout } = require('./rate-limit');

const COOKIE = 'vpn55_sid';
const CSRF_HEADER = 'x-vpn55-csrf';
const ABSOLUTE_TTL_CAP_MS = 24 * 60 * 60 * 1000;

// scrypt parameters. N=2^15 with r=8 is roughly 32 MB and ~100 ms on a small
// VPS — slow enough that an offline attack on a stolen hash is expensive, fast
// enough that a login is not. maxmem must be raised explicitly: Node's default
// is 32 MB and N=2^15 needs slightly more than that, so leaving it at the
// default makes scryptSync throw rather than run.
const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, keylen: 64, maxmem: 96 * 1024 * 1024 });

/** `scrypt$N$r$p$<salt-b64>$<hash-b64>` */
function hashPassword(password, { salt = crypto.randomBytes(16) } = {}) {
  const key = crypto.scryptSync(Buffer.from(String(password), 'utf8'), salt, SCRYPT.keylen, SCRYPT);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
}

function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  // A stored record names its own cost parameters so an old hash still verifies
  // after the defaults are raised. It does NOT get to name an arbitrary one: a
  // hash file an attacker could write could otherwise set N=2 and make every
  // password cheap to brute-force, or set N enormous and hang the process.
  if (N < 16384 || N > 1048576 || r < 4 || r > 32 || p < 1 || p > 16) return false;

  let salt;
  let expected;
  try {
    salt = Buffer.from(parts[4], 'base64');
    expected = Buffer.from(parts[5], 'base64');
  } catch {
    return false;
  }
  if (salt.length < 8 || expected.length < 16) return false;

  let actual;
  try {
    actual = crypto.scryptSync(Buffer.from(String(password), 'utf8'), salt, expected.length, {
      N, r, p, maxmem: SCRYPT.maxmem,
    });
  } catch {
    return false;
  }
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// The fixed record an unknown username is checked against, so the wrong-username
// path costs the same as the wrong-password path. Computed once at load.
const DUMMY_HASH = hashPassword(crypto.randomBytes(32).toString('base64'));

function parseCookies(header) {
  const out = Object.create(null);
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

class Auth {
  constructor({ config, audit, warn = console.warn }) {
    this.config = config;
    this.audit = audit;
    this.warn = warn;

    this.sessions = new Map();   // sid -> { user, createdAt, lastSeenAt, ip, csrf }

    this.absoluteTtlMs = Math.min(config.session_ttl_ms, ABSOLUTE_TTL_CAP_MS);
    this.idleTtlMs = Math.min(config.session_idle_ms, this.absoluteTtlMs);

    // Two independent controls, because they answer different questions.
    // The lockout stops guessing at ONE account from ONE place; the per-IP
    // limiter stops one place spraying MANY accounts, which the lockout alone
    // would never see, since each pair would only ever accumulate one failure.
    this.lockout = makeLockout({
      maxFailures: config.login_max_failures,
      windowMs: config.login_window_ms,
      lockMs: config.login_lock_ms,
    });
    this.ipLimiter = makeRateLimiter({
      windowMs: config.login_window_ms,
      max: config.login_ip_max,
      message: 'auth.rate_limited',
    });

    const sweep = setInterval(() => this.sweep(), 60_000);
    if (typeof sweep.unref === 'function') sweep.unref();
    this._sweep = sweep;
  }

  ip(req) {
    return clientIp(req, { trustProxy: this.config.trust_proxy });
  }

  // ── Administrator records ─────────────────────────────────────────────────
  // { "admins": { "<name>": { "hash": "scrypt$…", "created": "…" } } }
  //
  // Written by the installer as root, then chowned to the panel user. Read on
  // every login rather than cached, so `vpnctl`-adjacent tooling that resets a
  // password takes effect without restarting the panel — and because a file read
  // is nothing next to an scrypt.
  _loadAdmins() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.config.admins_file, 'utf8'));
      const admins = parsed && typeof parsed === 'object' ? parsed.admins : null;
      if (!admins || typeof admins !== 'object') return Object.create(null);
      // Copied onto a null-prototype object: a username of `constructor` or
      // `__proto__` must look up nothing rather than find a function.
      return Object.assign(Object.create(null), admins);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        this.warn(`[auth] cannot read ${this.config.admins_file}: ${err.code || err.message}`);
      }
      return Object.create(null);
    }
  }

  /**
   * How many administrator accounts exist.
   *
   * server.js refuses to start when sign-in is on and this is zero. A panel that
   * shows a password prompt nobody can ever satisfy is indistinguishable, from
   * the operator's side, from a forgotten password — and the fix for the two is
   * completely different.
   */
  adminCount() {
    const admins = this._loadAdmins();
    let n = 0;
    for (const name of Object.keys(admins)) {
      const rec = admins[name];
      if (rec && typeof rec.hash === 'string' && rec.hash.startsWith('scrypt$')) n += 1;
    }
    return n;
  }

  /**
   * Attempt a login.
   *
   * Returns { ok: true, session } or { ok: false, error, retryAfterMs }. The
   * error is a MESSAGE KEY, never prose: the panel resolves it through the
   * locale catalogs, and VI is what most operators will read.
   *
   * Every outcome is audited, including the refusals. A refused login is the
   * record that matters — a successful one looks the same whoever caused it.
   */
  login(req, { username, password }) {
    const ip = this.ip(req);
    const user = String(username || '');
    const auditBase = { actor: user || null, ip, verb: 'login', target: user || null };

    // Per-IP first, and it does not care whether the username exists — an
    // attacker must not be able to spend this budget only on real accounts.
    if (!this.ipLimiter.allow(ip)) {
      this.audit.write({ ...auditBase, result: 'denied', message: 'auth.rate_limited' });
      return { ok: false, error: 'auth.rate_limited', retryAfterMs: this.ipLimiter.retryAfterMs(ip) };
    }

    // The lockout key. The pair, not either half — see rate-limit.js.
    const key = `${user}\u0000${ip}`;
    const locked = this.lockout.state(key);
    if (locked.locked) {
      this.audit.write({ ...auditBase, result: 'denied', message: 'auth.locked' });
      return { ok: false, error: 'auth.locked', retryAfterMs: locked.remainingMs };
    }

    const admins = this._loadAdmins();
    const record = Object.hasOwn(admins, user) ? admins[user] : null;

    // The unknown-user branch still pays for an scrypt. See decision 4.
    const stored = (record && typeof record.hash === 'string') ? record.hash : DUMMY_HASH;
    const passed = verifyPassword(password, stored) && record !== null;

    if (!passed) {
      const after = this.lockout.fail(key);
      this.audit.write({
        ...auditBase,
        result: 'denied',
        message: after.locked ? 'auth.locked' : 'auth.bad_credentials',
        detail: { failures: after.failures },
      });
      return {
        ok: false,
        error: after.locked ? 'auth.locked' : 'auth.bad_credentials',
        retryAfterMs: after.remainingMs,
      };
    }

    this.lockout.succeed(key);

    const now = Date.now();
    const sid = crypto.randomBytes(32).toString('base64url');
    const session = {
      sid,
      user,
      ip,
      csrf: crypto.randomBytes(32).toString('base64url'),
      createdAt: now,
      lastSeenAt: now,
    };
    this.sessions.set(sid, session);

    this.audit.write({ ...auditBase, result: 'ok', message: 'auth.signed_in' });
    return { ok: true, session };
  }

  /**
   * Resolve a request to a live session, or null.
   *
   * `interactive` is the idle-clock decision and the caller owns it: pass true
   * for a write or a real user gesture, false for a poll. A poller that refreshed
   * the clock would mean no unattended window ever times out — decision 3.
   *
   * The session is NOT bound to the client IP. A mobile operator moving between
   * networks would otherwise be logged out mid-action, and an attacker who has
   * the cookie usually has the network path too, so the check costs real
   * usability for very little. It is recorded on the session and shown in the
   * audit log instead, where a human can notice it changed.
   */
  resolve(req, { interactive = false } = {}) {
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies[COOKIE];
    if (!sid) return null;

    const session = this.sessions.get(sid);
    if (!session) return null;

    const now = Date.now();
    if (now - session.createdAt > this.absoluteTtlMs) {
      this.sessions.delete(sid);
      return null;
    }
    if (now - session.lastSeenAt > this.idleTtlMs) {
      this.sessions.delete(sid);
      return null;
    }
    if (interactive) session.lastSeenAt = now;
    return session;
  }

  /**
   * The CSRF check for write routes. A cross-origin page can cause the cookie to
   * be sent; it cannot read the token or set a custom header, so requiring both
   * is what makes the difference.
   */
  checkCsrf(req, session) {
    const sent = req.headers[CSRF_HEADER];
    if (!session || typeof sent !== 'string' || sent.length !== session.csrf.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(session.csrf));
  }

  logout(req) {
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies[COOKIE];
    if (!sid) return false;
    const session = this.sessions.get(sid);
    this.sessions.delete(sid);
    if (session) {
      this.audit.write({
        actor: session.user, ip: this.ip(req), verb: 'logout',
        target: session.user, result: 'ok', message: 'auth.signed_out',
      });
    }
    return Boolean(session);
  }

  /** Drop every session belonging to one administrator — used after a reset. */
  revokeUser(user) {
    let n = 0;
    for (const [sid, s] of this.sessions) {
      if (s.user === user) { this.sessions.delete(sid); n++; }
    }
    return n;
  }

  sweep() {
    const now = Date.now();
    for (const [sid, s] of this.sessions) {
      if (now - s.createdAt > this.absoluteTtlMs || now - s.lastSeenAt > this.idleTtlMs) {
        this.sessions.delete(sid);
      }
    }
  }

  cookieHeader(session, { secure = true } = {}) {
    const maxAge = Math.floor(this.absoluteTtlMs / 1000);
    const bits = [
      `${COOKIE}=${session.sid}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${maxAge}`,
    ];
    // Secure is dropped only for a plain-HTTP loopback deployment, where the
    // browser would otherwise discard the cookie and the panel would appear to
    // accept a login and then immediately forget it.
    if (secure) bits.push('Secure');
    return bits.join('; ');
  }

  clearCookieHeader({ secure = true } = {}) {
    const bits = [`${COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
    if (secure) bits.push('Secure');
    return bits.join('; ');
  }

  stop() {
    clearInterval(this._sweep);
    this.lockout.stop();
    this.ipLimiter.stop();
  }
}

module.exports = {
  Auth, hashPassword, verifyPassword, parseCookies,
  COOKIE, CSRF_HEADER, ABSOLUTE_TTL_CAP_MS, SCRYPT,
};
