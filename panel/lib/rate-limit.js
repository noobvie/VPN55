'use strict';

// panel/lib/rate-limit.js — fixed-window rate limiting, and the login lockout
// built on top of it.
//
// The makeRateLimiter factory is vendored from Office Tools
// `backend/lib/rate-limit.js` (same author, MIT, pinned copy — ATTRIBUTIONS.md).
// The fixed-window counter and its shape are unchanged. Three things are
// different, and each is a change this deployment needs rather than a
// preference:
//
//  1. THE CLIENT IP IS NOT TAKEN FROM A HEADER BY DEFAULT, AND WHEN IT IS, IT
//     IS NOT TAKEN FROM THE FIRST HOP.
//     Upstream reads the first X-Forwarded-For hop unconditionally, which is
//     correct there — every request arrives through nginx and Cloudflare, so the
//     header is written by infrastructure and the socket address is a proxy.
//     Here the same code would be a hole rather than a convenience: the login
//     lockout is keyed on the client IP, so an attacker who can set that header
//     freely gets an unlimited supply of distinct "clients" and is never locked
//     out. So the header is consulted only when the operator has said a proxy is
//     the sole way in (`trust_proxy`), and otherwise the socket address wins.
//     A rate limiter keyed on caller-controlled input is not a rate limiter.
//
//     ⚠ Consulting the header is not enough on its own, and the first version of
//     this module got that wrong. `trust_proxy=1` with a first-hop read is the
//     SAME hole wearing a permission slip, because nginx APPENDS to this header
//     rather than replacing it — see clientIp() below for the arithmetic. The
//     gate says whether to believe a header; it cannot say which part of one is
//     true.
//
//  2. THE PRUNE TIMER IS UNREFERENCED.
//     Upstream's setInterval keeps a Node process alive forever, which is
//     invisible in a server that never exits. This module is also loaded by a
//     one-shot script and by tests, where a process that will not exit is a hang
//     with no error message.
//
//  3. THE LOCKOUT IS A SEPARATE PRIMITIVE.
//     Rate limiting and lockout answer different questions — "too many requests"
//     versus "too many FAILURES for this identity" — and conflating them means
//     a successful login is throttled by the attempts of whoever guessed wrong
//     before it. They are composed at the call site instead.

/**
 * The key every limiter and lockout is bucketed by.
 *
 * `trustProxy` must reflect the deployment, not the wish: turning it on when
 * anything can reach the port directly hands every attacker a fresh identity per
 * request. Turning it off behind a proxy collapses every client into one bucket,
 * which is noisy but fails CLOSED — the wrong default is the other one.
 */
function clientIp(req, { trustProxy = false } = {}) {
  if (trustProxy) {
    // X-Real-IP FIRST, because it is the only one of the two a client cannot
    // contribute to. nginx sets it with `proxy_set_header X-Real-IP
    // $remote_addr`, and proxy_set_header OVERWRITES — an inbound X-Real-IP is
    // discarded before it ever reaches this process.
    const real = String(req.headers['x-real-ip'] || '').trim();
    if (real) return real;

    // Fall back to the LAST X-Forwarded-For hop, never the first.
    //
    // ⚠ The first hop is CLIENT-CONTROLLED, which is the opposite of what it
    // looks like. The shipped vhost sets the header with
    // `$proxy_add_x_forwarded_for`, and that APPENDS $remote_addr to whatever
    // the caller already sent — so `X-Forwarded-For: 1.2.3.4` arrives here as
    // "1.2.3.4, <real client>" and reading [0] hands the caller the pen. With
    // the lockout keyed on this value that is two separate holes at once: an
    // endless supply of fresh identities to guess from, and the ability to
    // aim a lockout AT the operator by sending their address with their
    // username. The last hop is the one the proxy itself wrote.
    //
    // Behind two chained proxies the last hop is the inner proxy rather than
    // the client, which collapses everyone into one bucket — noisy, but it
    // fails CLOSED, and that is the right direction for this value.
    const hops = String(req.headers['x-forwarded-for'] || '').split(',');
    const last = hops[hops.length - 1].trim();
    if (last) return last;
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/**
 * Fixed-window counter.
 *
 *   const lim = makeRateLimiter({ windowMs: 60_000, max: 15 });
 *   if (!lim.allow(key)) …
 */
function makeRateLimiter({ windowMs, max, message = 'rate.limited' }) {
  const map = new Map();

  const prune = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of map) if (now > v.resetAt) map.delete(k);
  }, 300_000);
  // See note 2 in the header.
  if (typeof prune.unref === 'function') prune.unref();

  function allow(key) {
    const now = Date.now();
    let e = map.get(key);
    if (!e || now > e.resetAt) e = { count: 0, resetAt: now + windowMs };
    e.count++;
    map.set(key, e);
    return e.count <= max;
  }

  function retryAfterMs(key) {
    const e = map.get(key);
    if (!e) return 0;
    return Math.max(0, e.resetAt - Date.now());
  }

  function reset(key) { map.delete(key); }

  function stop() { clearInterval(prune); }

  return { allow, retryAfterMs, reset, stop, map, message, max, windowMs };
}

/**
 * Failure lockout, keyed on whatever string the caller composes.
 *
 * For admin login that key is `(username, IP)` — the pair, not either alone:
 *
 *   keyed on USERNAME alone, anyone can lock a known administrator out of their
 *   own panel from anywhere, which turns a login control into a denial of
 *   service against the operator;
 *
 *   keyed on IP alone, an attacker spreading guesses across many usernames from
 *   one address is throttled correctly, but a shared NAT locks out innocent
 *   colleagues.
 *
 * The pair is the standard answer and is what docs/security-model.md specifies.
 * It leaves one gap open on purpose — an attacker with many addresses and one
 * target username — which is why the caller ALSO applies a plain per-IP limiter,
 * and why the password hash is scrypt rather than something fast.
 *
 * A successful authentication clears the bucket. A failure while already locked
 * does NOT extend the lock: an extending lock can be held open indefinitely by
 * an attacker who keeps knocking, which locks out the real administrator for as
 * long as the attacker cares to continue.
 */
function makeLockout({ maxFailures, windowMs, lockMs }) {
  const map = new Map();

  const prune = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of map) {
      if (now > v.until && now > v.windowEnds) map.delete(k);
    }
  }, 300_000);
  if (typeof prune.unref === 'function') prune.unref();

  function state(key) {
    const now = Date.now();
    const e = map.get(key);
    if (!e) return { locked: false, failures: 0, remainingMs: 0 };
    if (e.until > now) {
      return { locked: true, failures: e.failures, remainingMs: e.until - now };
    }
    if (now > e.windowEnds) return { locked: false, failures: 0, remainingMs: 0 };
    return { locked: false, failures: e.failures, remainingMs: 0 };
  }

  function fail(key) {
    const now = Date.now();
    let e = map.get(key);

    // Already locked: record nothing. See the note above on extending locks.
    if (e && e.until > now) {
      return { locked: true, failures: e.failures, remainingMs: e.until - now };
    }
    if (!e || now > e.windowEnds) e = { failures: 0, windowEnds: now + windowMs, until: 0 };

    e.failures += 1;
    if (e.failures >= maxFailures) {
      e.until = now + lockMs;
    }
    map.set(key, e);
    return {
      locked: e.until > now,
      failures: e.failures,
      remainingMs: Math.max(0, e.until - now),
    };
  }

  function succeed(key) { map.delete(key); }

  function stop() { clearInterval(prune); }

  return { state, fail, succeed, stop, map, maxFailures, lockMs };
}

module.exports = { clientIp, makeRateLimiter, makeLockout };
