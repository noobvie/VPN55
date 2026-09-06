'use strict';
//
// panel/portal/auth.js — sessions for the self-serve portal.
//
// This module has NOTHING to do with panel/lib/auth.js, and that is the design
// rather than an accident of layout. It does not import it, does not share its
// session map, does not read its cookie and does not know its users exist. The
// build plan's rule for this phase — "never the admin page with a role check: a
// role flag on shared admin routes is exactly how a user reaches an admin
// endpoint" — is met by there being no shared object to put a flag on.
//
// ── Three separations, and what each one is worth ────────────────────────────
//
//  1. A DIFFERENT PROCESS-LEVEL MAP. An admin session id and a portal session
//     id are looked up in different Maps by different classes. Presenting one
//     to the other resolves to null, whatever it says inside.
//
//  2. A DIFFERENT COOKIE NAME. `vpn55_portal` against `vpn55_sid`. This is the
//     weakest of the three on its own — a cookie name is not a security control
//     — but it means a browser holding both keeps them apart, so an operator
//     who is also a user does not sign out of one by using the other.
//
//  3. A DIFFERENT LISTENER. The portal app is a separate express instance on a
//     separate socket, and no admin route is registered on it. That is the one
//     that actually settles it: even a perfect forgery of a portal session
//     cannot reach an admin handler, because on that socket there is no admin
//     handler to reach. Nothing here has to be right for that to hold.
//
// ── What is deliberately NOT copied from the admin side ──────────────────────
//
// THE (username, IP) LOCKOUT. It answers "too many failures for this identity",
// and the portal has no identity to fail against: a code is redeemed or it is
// not, and every wrong attempt is a different string. A lockout keyed on the
// submitted code would allocate one bucket per guess and never trip; keyed on
// the user it would let anyone lock a stranger out of their own portal by
// guessing at codes that were never theirs.
//
// What is left is a plain per-IP limiter, and that is the correct control here
// because guessing is not the threat. A code is 256 bits from randomBytes:
// exhausting it is not a rate to be limited, it is arithmetic that does not
// finish. The limiter exists so an open portal cannot be used to make this host
// hash and read state on demand.

const crypto = require('node:crypto');

const { clientIp, makeRateLimiter } = require('../lib/rate-limit');

const COOKIE = 'vpn55_portal';
const CSRF_HEADER = 'x-vpn55-portal-csrf';

// The same 24h ceiling auth.js applies to an admin session, for the same
// reason: a bearer token cannot be withdrawn from the client's side, so an
// absolute lifetime configuration can raise without limit is a credential with
// no expiry wearing a session's name.
const ABSOLUTE_TTL_CAP_MS = 24 * 60 * 60 * 1000;

// A portal session is not an admin session and says so in its own record. The
// listener split already makes a cross-tree resolve impossible; this is what
// makes it impossible to write the bug in the first place, since a session
// object from the wrong Map fails the check before its fields are read.
const KIND = 'portal';

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
      // A cookie whose value is not valid percent-encoding is not our cookie.
      // Throwing here would make one malformed header from any source break
      // every request, including the ones carrying a perfectly good session.
    }
  }
  return out;
}

class PortalAuth {
  constructor({ config, tokens, audit, warn = console.warn }) {
    this.config = config;
    this.tokens = tokens;
    this.audit = audit;
    this.warn = warn;

    // Portal sessions. A different Map from Auth's, in a different object, in a
    // different module. See separation 1.
    this.sessions = new Map();

    this.absoluteTtlMs = Math.min(config.portal_session_ttl_ms, ABSOLUTE_TTL_CAP_MS);
    this.idleTtlMs = Math.min(config.portal_session_idle_ms, this.absoluteTtlMs);

    this.ipLimiter = makeRateLimiter({
      windowMs: config.portal_window_ms,
      max: config.portal_ip_max,
      message: 'portal.rate_limited',
    });

    // Fetching a configuration, per USER. Every one of these forks a root
    // helper that reads a spool and talks to an adapter, so an authenticated
    // caller in a loop is a caller making this host fork on demand. Nothing
    // else on the portal costs a subprocess, and the page itself only asks when
    // somebody presses a button — so the limit is generous enough that a real
    // person switching between four artifacts on three credentials never meets
    // it, and low enough that a script does.
    this.configLimiter = makeRateLimiter({
      windowMs: config.portal_window_ms,
      max: config.portal_config_max,
      message: 'portal.rate_limited',
    });

    // Rotations, per USER rather than per address. Rotation issues a credential
    // before it revokes the old one, so an unbounded caller could fill the
    // address pool from a phone — and the person doing that is identified, so
    // the limit belongs on them rather than on wherever they happen to be
    // standing. A user on a train changing networks must not get a fresh budget.
    this.rotateLimiter = makeRateLimiter({
      windowMs: config.portal_rotate_window_ms,
      max: config.portal_rotate_max,
      message: 'portal.rotate_limited',
    });

    const sweep = setInterval(() => this.sweep(), 60_000);
    if (typeof sweep.unref === 'function') sweep.unref();
    this._sweep = sweep;
  }

  ip(req) {
    return clientIp(req, { trustProxy: this.config.portal_trust_proxy });
  }

  /**
   * Redeem an access code for a session.
   *
   * Returns { ok: true, session } or { ok: false, error, retryAfterMs }, where
   * `error` is a catalog key rather than prose — the portal is the surface most
   * users actually see, and an API that answered in English would make its
   * errors the one part of the product that never got translated.
   *
   * There is ONE failure message for a code that does not exist, a revoked one,
   * an expired one and one whose user has since been deleted. Telling them
   * apart would confirm that a code was once real, and the whole point of a
   * bearer code is that possession is the only thing worth learning about it.
   */
  redeem(req, token) {
    const ip = this.ip(req);

    if (!this.ipLimiter.allow(ip)) {
      this.audit.write({
        actor: null, ip, verb: 'portal-redeem', target: null,
        result: 'denied', message: 'portal.rate_limited',
      });
      return {
        ok: false,
        error: 'portal.rate_limited',
        retryAfterMs: this.ipLimiter.retryAfterMs(ip),
      };
    }

    const record = this.tokens.verify(token);
    if (!record) {
      this.audit.write({
        actor: null, ip, verb: 'portal-redeem', target: null,
        result: 'denied', message: 'portal.bad_code',
      });
      return { ok: false, error: 'portal.bad_code' };
    }

    const now = Date.now();
    const session = {
      sid: crypto.randomBytes(32).toString('base64url'),
      kind: KIND,
      user: record.user,
      tokenId: record.id,
      ip,
      csrf: crypto.randomBytes(32).toString('base64url'),
      createdAt: now,
      lastSeenAt: now,
    };
    this.sessions.set(session.sid, session);

    this.audit.write({
      actor: record.user, ip, verb: 'portal-redeem', target: record.user,
      result: 'ok', message: 'portal.signed_in', detail: { tokenId: record.id },
    });
    return { ok: true, session };
  }

  /**
   * Resolve a request to a live portal session, or null.
   *
   * `interactive` is the idle-clock decision and the caller owns it, exactly as
   * on the admin side: true for a write or a real gesture, false for a poll. The
   * portal page refreshes its own usage figures, and a refresh that reset the
   * clock would mean a phone left on a table holds a session open until the
   * absolute cap.
   *
   * The session is NOT bound to the client address. This audience is on mobile
   * data in a market where the address changes between one screen and the next,
   * and a check that signs somebody out mid-download costs real usability for a
   * property an attacker holding the cookie usually has anyway. The address is
   * recorded on the session and in the audit log instead.
   */
  resolve(req, { interactive = false } = {}) {
    const sid = parseCookies(req.headers.cookie)[COOKIE];
    if (!sid) return null;

    const session = this.sessions.get(sid);
    // The kind check is redundant three times over — this Map only ever holds
    // portal sessions, and the socket only ever serves portal routes. It is
    // here so that a future refactor which merges a map, or a test that injects
    // one, fails rather than quietly authorising.
    if (!session || session.kind !== KIND) return null;

    const now = Date.now();
    if (now - session.createdAt > this.absoluteTtlMs) {
      this.sessions.delete(sid);
      return null;
    }
    if (now - session.lastSeenAt > this.idleTtlMs) {
      this.sessions.delete(sid);
      return null;
    }

    // A code revoked while somebody is signed in ends the session at the next
    // request rather than at its expiry. Revoking access that stays live for
    // two more hours is the same class of untruth as a revocation reported
    // before it has taken effect — and unlike a tunnel, this one CAN be ended,
    // so it is.
    if (!this.tokens.list(session.user).some(
      (r) => r.id === session.tokenId && !r.revokedAt)) {
      this.sessions.delete(sid);
      return null;
    }

    if (interactive) session.lastSeenAt = now;
    return session;
  }

  /**
   * The CSRF check. A cross-origin page can cause the cookie to be sent; it
   * cannot read a response body or set a custom header, so requiring both is
   * what makes the difference. The portal's rotate route destroys a working
   * credential, which is more than enough to be worth protecting.
   */
  checkCsrf(req, session) {
    const sent = req.headers[CSRF_HEADER];
    if (!session || typeof sent !== 'string') return false;

    // ⚠ BYTE lengths, not character lengths — timingSafeEqual measures bytes and
    // THROWS when they differ, so a header of the right character count carrying
    // multi-byte UTF-8 got past the guard and threw inside the compare. On this
    // socket that matters more than on the admin one: it is a 500 instead of a
    // 403, reachable by anyone who can load the page, and the refused-CSRF audit
    // line never gets written. lib/auth.js carries the same fix.
    const a = Buffer.from(sent, 'utf8');
    const b = Buffer.from(session.csrf, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  /** May this user rotate again right now? Consumes one from the budget. */
  allowRotate(user) {
    return this.rotateLimiter.allow(String(user));
  }

  rotateRetryAfterMs(user) {
    return this.rotateLimiter.retryAfterMs(String(user));
  }

  /** May this user fetch another configuration? Consumes one from the budget. */
  allowConfig(user) {
    return this.configLimiter.allow(String(user));
  }

  configRetryAfterMs(user) {
    return this.configLimiter.retryAfterMs(String(user));
  }

  signOut(req) {
    const sid = parseCookies(req.headers.cookie)[COOKIE];
    if (!sid) return false;
    const session = this.sessions.get(sid);
    this.sessions.delete(sid);
    if (session) {
      this.audit.write({
        actor: session.user, ip: this.ip(req), verb: 'portal-signout',
        target: session.user, result: 'ok', message: 'portal.signed_out',
      });
    }
    return Boolean(session);
  }

  /** Drop every portal session belonging to one user. */
  revokeUser(user) {
    let n = 0;
    for (const [sid, s] of this.sessions) {
      if (s.user === user) { this.sessions.delete(sid); n += 1; }
    }
    return n;
  }

  /**
   * Drop every session opened with ONE code.
   *
   * Narrower than revokeUser on purpose. Withdrawing the code somebody's old
   * phone was signed in with must not also sign out the phone they are holding,
   * which is what an operator would be doing without meaning to if this were
   * keyed on the user.
   *
   * resolve() already re-checks the code on every request, so a session on a
   * withdrawn code dies at its next call regardless. This makes it immediate,
   * which is the difference between "revoked" and "revoked, eventually".
   */
  revokeToken(tokenId) {
    let n = 0;
    for (const [sid, s] of this.sessions) {
      if (s.tokenId === tokenId) { this.sessions.delete(sid); n += 1; }
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
    const bits = [
      `${COOKIE}=${session.sid}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${Math.floor(this.absoluteTtlMs / 1000)}`,
    ];
    // Dropped for a plain-HTTP loopback deployment, where the browser would
    // discard a Secure cookie and the portal would appear to accept a code and
    // then instantly forget it — a failure with nothing in any log to explain it.
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
    this.ipLimiter.stop();
    this.configLimiter.stop();
    this.rotateLimiter.stop();
  }
}

module.exports = { PortalAuth, parseCookies, COOKIE, CSRF_HEADER, KIND, ABSOLUTE_TTL_CAP_MS };
