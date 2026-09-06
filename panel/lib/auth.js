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
// ── Six decisions, each with a failure it is avoiding ─────────────────────────
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
//
//  6. THE SECOND FACTOR GATES SIGNING IN, NOT EACH WRITE. Two reasons, and the
//     second is the one that decided it.
//
//     The reads are not innocuous. A session that opened without a second factor
//     but could not write would still hand over every user name, every quota,
//     every endpoint address and every traffic total on the host — which is most
//     of what somebody would want it for. Gating writes protects the actions and
//     leaks the intelligence.
//
//     And a factor demanded per write TEACHES THE WRONG REFLEX. An operator
//     prompted for a code six times an hour stops reading the prompt, and a
//     person who enters a code whenever they are asked is a person a phishing
//     page can ask. A factor that is demanded once, at a moment the operator
//     chose, is a factor they notice being asked for at a moment they did not.
//
//     Enrolment, clearing and password changes are all CONSOLE actions
//     (scripts/admin.js), so a stolen session cannot enrol a factor of its own
//     or remove the one that is there. The break-glass path for a lost device is
//     `admin.js totp --clear <name>` as root on the host — which is not a bypass
//     in any meaningful sense, because anyone who can run it already has root
//     and does not need the panel. Deliberately, there are NO remote recovery
//     codes: a stack of single-use secrets that skip the factor, stored on the
//     same host as the hashes, is the bypass this design was asked to avoid, and
//     it buys nothing the console does not already give.

const crypto = require('node:crypto');

const adminFile = require('./admins');
const totp = require('./totp');
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

/**
 * Cookie header → object.
 *
 * ⚠ decodeURIComponent THROWS on a malformed escape, and `Cookie: x=%` is a
 * malformed escape. Unguarded, that URIError propagates out of resolve() —
 * which every gated route calls — and express turns it into a 500 with a stack
 * trace in the journal. So any caller at all, holding no session and needing no
 * credential, could make every authenticated route on the panel fail by sending
 * one junk byte. A cookie that cannot be decoded is a cookie we do not have:
 * the value is dropped and the request goes on to be treated as signed out,
 * which is what it is.
 *
 * (server.js:readCookie and portal/auth.js:parseCookies both already had this
 * guard. This copy, the one on the authenticated path, did not.)
 */
function parseCookies(header) {
  const out = Object.create(null);
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      // Not a value we can read. Not a reason to fail the request either.
      continue;
    }
  }
  return out;
}

class Auth {
  constructor({ config, audit, warn = console.warn, alerter = null }) {
    this.config = config;
    this.audit = audit;
    this.warn = warn;
    this.alerter = alerter;

    this.sessions = new Map();   // sid -> { user, createdAt, lastSeenAt, ip, csrf }

    // The TOTP replay guard: the highest time step each administrator has
    // already spent. A code is good for one step and the skew window either
    // side, and without this it stays good for all of that after it has been
    // used — which is exactly the window somebody relaying a code in real time
    // is working in.
    //
    // ⚠ IN MEMORY, like the sessions, and for a related reason. Persisting it
    // would mean the HTTP-facing process writing the file that holds every
    // administrator's hash, on every login. That file is read-only from here on
    // purpose (panel/lib/admins.js), and a write path into it is a bigger thing
    // to give away than the failure it would close: a restart forgets the spent
    // counter, so a code could be replayed across one — inside its own 90-second
    // window, by somebody who already had it, at a moment they cannot choose.
    this.totpSpent = new Map();

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
      return adminFile.read(this.config.admins_file);
    } catch (err) {
      // A malformed file is an empty set HERE, with a loud warning, rather than
      // a throw. This runs on the login path, and a throw would be a 500 on
      // every attempt with the reason only in a stack trace; an empty set is a
      // refused login, which is what a panel with no readable administrator
      // file should do. scripts/admin.js treats the same error as fatal,
      // because there the operator is standing in front of it.
      this.warn(`[auth] ${err.message}`);
      return Object.create(null);
    }
  }

  /**
   * Which administrators have no second factor enrolled.
   *
   * server.js prints these at start-up when `require_totp` is on, because
   * otherwise the first anybody hears of it is a refused login with a message
   * about a console they may not be sitting at.
   */
  adminsWithoutTotp() {
    const admins = this._loadAdmins();
    return Object.keys(admins)
      .filter((name) => adminFile.isUsable(admins[name]) && !adminFile.totpSecret(admins[name]))
      .sort();
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
      if (adminFile.isUsable(admins[name])) n += 1;
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
  login(req, { username, password, totp: token = '' }) {
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

    if (!passed) return this._fail(key, auditBase, 'auth.bad_credentials');

    // ── The second factor ────────────────────────────────────────────────────
    //
    // Reached only once the password is right, which is the ordinary two-step
    // shape and gives nothing away: whoever is here has already proven the first
    // factor, so being told a second one is wanted tells them nothing they could
    // not work out by holding a correct password.
    //
    // The lockout is NOT cleared until both factors have passed — clearing it
    // after the password would mean an attacker with a leaked password could
    // reset the failure counter at will and guess codes forever.
    const secret = adminFile.totpSecret(record);

    if (!secret && this.config.require_totp) {
      // Policy says every account carries a factor and this one does not. The
      // fix is at the console, so the message says so rather than offering a
      // field the operator cannot fill in.
      this.audit.write({ ...auditBase, result: 'denied', message: 'auth.totp_enrol_required' });
      return { ok: false, error: 'auth.totp_enrol_required' };
    }

    if (secret) {
      const typed = String(token || '').trim();
      if (!typed) {
        // Not a failure, and deliberately not counted as one: the normal sign-in
        // passes through here exactly once, and counting it would spend a fifth
        // of the operator's own lockout budget every time they signed in. The
        // per-IP limiter has already counted the request.
        this.audit.write({ ...auditBase, result: 'denied', message: 'auth.totp_required' });
        return { ok: false, error: 'auth.totp_required', needsTotp: true };
      }

      const spent = this.totpSpent.has(user) ? this.totpSpent.get(user) : -1;
      const check = totp.verify(secret, typed, { notBefore: spent });
      if (!check.ok) {
        // A reused code is audited as its own thing. It is usually a
        // double-submit, and it is occasionally somebody replaying a code they
        // watched being typed — which is the one login failure worth being able
        // to find in a log afterwards.
        const message = check.reason === 'reused' ? 'auth.totp_reused' : 'auth.totp_invalid';
        return this._fail(key, auditBase, message, { needsTotp: true });
      }
      this.totpSpent.set(user, check.counter);
    }

    this.lockout.succeed(key);

    // The caller's previous session, if they had one, ends here.
    //
    // There is no session fixation to worry about — nothing hands out a session
    // id before authentication and `sid` below is 32 fresh bytes — but without
    // this, signing in again simply ADDS a session and leaves the old cookie
    // live for its full absolute lifetime. Sessions would then accumulate per
    // user with no ceiling, and "sign in again" would not be a way to end a
    // session left open on a machine somebody no longer has.
    const previous = parseCookies(req.headers.cookie)[COOKIE];
    if (previous) this.sessions.delete(previous);

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
   * One refusal: count it, audit it, and tell the operator if a lockout tripped.
   *
   * Shared by the password and the second-factor branches so they cannot drift —
   * a wrong code and a wrong password must cost the same against the same
   * counter, or the factor with the cheaper failure is the one worth attacking.
   */
  _fail(key, auditBase, message, extra = {}) {
    const after = this.lockout.fail(key);
    const finalMessage = after.locked ? 'auth.locked' : message;
    this.audit.write({
      ...auditBase, result: 'denied', message: finalMessage,
      detail: { failures: after.failures, reason: message },
    });

    // The alert carries a COUNT and nothing else — no username, no address. The
    // audit log has both and is one SSH session away; a webhook URL is the least
    // trusted place anything about this host ends up. See lib/alerts.js.
    if (after.locked && this.alerter) {
      try {
        this.alerter.event('auth.locked_out', {});
      } catch {
        // Alerting must never turn a refused login into a 500.
      }
    }

    return { ok: false, error: finalMessage, retryAfterMs: after.remainingMs, ...extra };
  }

  /**
   * Change the session timeouts while the panel is running.
   *
   * The absolute cap still applies and configuration still cannot raise it.
   * Shortening either one takes effect at the next resolve(), including for
   * sessions that are already open — which is the point of shortening it.
   */
  setSessionTimeouts({ ttlMs, idleMs }) {
    if (Number.isFinite(ttlMs)) this.absoluteTtlMs = Math.min(ttlMs, ABSOLUTE_TTL_CAP_MS);
    if (Number.isFinite(idleMs)) this.idleTtlMs = Math.min(idleMs, this.absoluteTtlMs);
    else this.idleTtlMs = Math.min(this.idleTtlMs, this.absoluteTtlMs);
  }

  /**
   * Rebuild the login lockout and the per-IP limiter.
   *
   * ⚠ THIS DISCARDS WHATEVER THEY WERE HOLDING — every accumulated failure and
   * every live lockout. That is not a bypass: those counters only ever restrain
   * somebody who is NOT signed in, and whoever reaches this is signed in. It
   * does mean an operator can clear a lockout by nudging a number, which is
   * better known than discovered.
   *
   * The old timers are stopped first. A replaced limiter whose prune interval is
   * still running is a leak that only shows up as a process that will not exit.
   */
  setLoginLimits({ windowMs, maxFailures, lockMs, ipMax }) {
    this.lockout.stop();
    this.ipLimiter.stop();
    this.lockout = makeLockout({ maxFailures, windowMs, lockMs });
    this.ipLimiter = makeRateLimiter({ windowMs, max: ipMax, message: 'auth.rate_limited' });
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
    if (!session || typeof sent !== 'string') return false;

    // ⚠ Compare BYTE lengths, not character lengths. timingSafeEqual measures
    // bytes and THROWS when they differ, so a header of the right character
    // count carrying multi-byte UTF-8 ("é".repeat(43) against a 43-char token)
    // passed the string-length guard and threw inside the compare. That is a
    // 500 where a 403 belongs — and worse, the audit line for a refused CSRF
    // never gets written, which is exactly the refusal worth having a record of.
    const a = Buffer.from(sent, 'utf8');
    const b = Buffer.from(session.csrf, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
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
