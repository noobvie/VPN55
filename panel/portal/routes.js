'use strict';
//
// panel/portal/routes.js — the self-serve route tree.
//
// Mounted on its OWN express app, on its own listener. Not a sub-path of the
// admin app, not the admin router with a role check. See panel/portal/auth.js
// for why that distinction is the phase's central one and how it is enforced
// three times over.
//
// ── Everything a user may do, in full ────────────────────────────────────────
//
//   POST   /api/portal/session          redeem an access code
//   GET    /api/portal/session          am I signed in?
//   DELETE /api/portal/session          sign out
//   POST   /api/portal/session/touch    the idle heartbeat
//   GET    /api/portal/me               my usage, my expiry, my credentials
//   GET    /api/portal/creds/:id/config my own configuration for one of them
//   POST   /api/portal/creds/:id/rotate replace one of mine
//
// Seven routes, and there is nothing else on this socket except the page, its
// assets and the locale catalogs. No user list, no other person's anything, no
// service control, no register write. A route that is not here cannot be
// reached from here.
//
// ── What is deliberately absent ──────────────────────────────────────────────
//
// ISSUING A FIRST CREDENTIAL. `cred-add` exists and the portal could call it,
// and it does not: the brief for this surface is see, download, show, rotate,
// "and nothing more". A person with no credential needs an operator, which is
// one message rather than a self-service path that allocates addresses.
//
// A HEALTH ENDPOINT. /healthz lives on the admin listener. It answers with no
// authentication at all, which is right for a monitor on a private address and
// wrong for a socket the internet can reach.
//
// ── The ownership check appears twice, on purpose ────────────────────────────
//
// Once here, through logic.js, so the answer is a clean 404 and the page can
// say something useful. Once inside helper/vpnctl, as root, against the
// register, before a byte of a configuration is produced. The second is the
// control. If every line of this file were wrong, a user still could not read
// another user's configuration.

const express = require('express');

const log = require('../lib/log');
const { CSRF_HEADER } = require('./auth');
const { resolveOwnCredential, normaliseArtifact, accountView } = require('./logic');

// Message keys, never prose. The portal is the surface most users see and it is
// Vietnamese-first; an API answering in English would make its errors the one
// part of the product that never got translated — which is exactly the part
// somebody reads when things have gone wrong.
const E_AUTH = 'portal.auth_required';
const E_NOT_FOUND = 'portal.cred_unknown';
const E_FAILED = 'portal.failed';

/**
 * A helper failure, as an HTTP status.
 *
 * Narrower than the admin panel's mapping on purpose. `cred-config` answers
 * "unknown target" (5) for a credential that does not exist, one that belongs to
 * somebody else and one that was revoked — the portal must not widen that back
 * out into three distinguishable statuses on the way to the browser, because
 * the helper collapsed them for a reason.
 */
function statusForHelperCode(code) {
  switch (code) {
    case 2:
    case 3: return 400;   // this panel built a bad call — a bug here, not theirs
    case 4: return 500;   // not root: a deployment fault
    case 5: return 404;   // unknown / not yours / revoked — one answer
    default: return 502;
  }
}

// The token store is deliberately NOT a parameter here. Nothing in this file
// needs it: portalAuth already holds it and is the only thing that should ever
// verify a code. A router that could also read the store would be a second
// place for "is this code still valid" to be answered, and the two would
// eventually disagree.
function build({ cfg, portalAuth, audit, privileged, collector, catalogs }) {
  const router = express.Router();

  // A small body limit. Nothing here takes more than an access code, and a
  // generous limit on an internet-facing socket is memory somebody else decides
  // how to spend.
  router.use(express.json({ limit: '4kb' }));

  // X-Forwarded-Proto is read only when `portal_trust_proxy` says a proxy is the
  // sole way in — the same rule the client address follows, because it is the
  // same class of header. Unconditionally, any caller could assert the
  // connection was https and decide whether this socket's own session cookie
  // carried `Secure`. lib/routes-admin.js carries the same fix.
  const isSecure = (req) => req.secure
    || (cfg.portal_trust_proxy
        && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');

  // ── Guards ────────────────────────────────────────────────────────────────

  /** Signed in. NOT counted as interaction — the page polls. */
  function requireUser(req, res, next) {
    const session = portalAuth.resolve(req, { interactive: false });
    if (!session) return res.status(401).json({ ok: false, error: E_AUTH });
    req.portal = session;
    return next();
  }

  /** Signed in, CSRF-checked, and it DOES count as interaction. */
  function requireAction(req, res, next) {
    const session = portalAuth.resolve(req, { interactive: true });
    if (!session) return res.status(401).json({ ok: false, error: E_AUTH });
    if (!portalAuth.checkCsrf(req, session)) {
      audit.write({
        actor: session.user, ip: portalAuth.ip(req), verb: 'portal-csrf',
        target: req.path, result: 'denied', message: 'portal.csrf_failed',
      });
      return res.status(403).json({ ok: false, error: 'portal.csrf_failed' });
    }
    req.portal = session;
    return next();
  }

  /**
   * The one place a credential id from a URL is turned into a credential.
   *
   * The user comes from the session and never from the request. A wrong id, a
   * revoked one and somebody else's are the same 404 with the same body — see
   * the header, and logic.js.
   */
  function ownCred(req, res) {
    const snapshot = collector.snapshot;
    if (!snapshot) {
      res.status(503).json({ ok: false, error: 'portal.not_ready' });
      return null;
    }
    const owned = resolveOwnCredential(snapshot, req.portal.user, req.params.id);
    if (!owned) {
      res.status(404).json({ ok: false, error: E_NOT_FOUND });
      return null;
    }
    return owned;
  }

  // ── Session ───────────────────────────────────────────────────────────────

  /**
   * Redeem an access code.
   *
   * The code arrives in a POST BODY, never in the URL. A code in a query string
   * is a code in the nginx access log, in the browser history and in the
   * Referer header of the next request — and the link an operator sends carries
   * it in the FRAGMENT for the same reason, which a browser does not transmit
   * at all. panel/portal/public/js/portal.js reads it from there and posts it.
   */
  router.post('/session', (req, res) => {
    const body = req.body || {};
    const outcome = portalAuth.redeem(req, typeof body.code === 'string' ? body.code : '');

    if (!outcome.ok) {
      const status = outcome.error === 'portal.rate_limited' ? 429 : 401;
      const payload = { ok: false, error: outcome.error };
      if (outcome.retryAfterMs) {
        payload.retryAfterSeconds = Math.ceil(outcome.retryAfterMs / 1000);
        res.set('Retry-After', String(payload.retryAfterSeconds));
      }
      return res.status(status).json(payload);
    }

    res.set('Set-Cookie', portalAuth.cookieHeader(outcome.session, { secure: isSecure(req) }));
    return res.json({
      ok: true,
      user: outcome.session.user,
      // In the BODY, never in a cookie. A token the browser sends by itself is
      // a token another site can cause to be sent; one this page has to read
      // and echo into a header cannot be replayed cross-origin.
      csrf: outcome.session.csrf,
      csrfHeader: CSRF_HEADER,
      idleSeconds: Math.floor(portalAuth.idleTtlMs / 1000),
      expiresInSeconds: Math.floor(portalAuth.absoluteTtlMs / 1000),
    });
  });

  router.get('/session', (req, res) => {
    const session = portalAuth.resolve(req, { interactive: false });
    if (!session) return res.status(401).json({ ok: false, error: E_AUTH });
    return res.json({
      ok: true,
      user: session.user,
      csrf: session.csrf,
      csrfHeader: CSRF_HEADER,
      idleSeconds: Math.floor(portalAuth.idleTtlMs / 1000),
      expiresInSeconds: Math.floor(
        Math.max(0, portalAuth.absoluteTtlMs - (Date.now() - session.createdAt)) / 1000),
    });
  });

  router.delete('/session', (req, res) => {
    portalAuth.signOut(req);
    res.set('Set-Cookie', portalAuth.clearCookieHeader({ secure: isSecure(req) }));
    res.json({ ok: true });
  });

  /** The idle heartbeat. Sent on a real gesture, never on a timer. */
  router.post('/session/touch', requireAction, (req, res) => {
    res.json({ ok: true });
  });

  // ── The account ───────────────────────────────────────────────────────────

  /**
   * Everything about the signed-in person, and nothing about anybody else.
   *
   * There is no `/api/portal/users/:name` and there never will be. The user is
   * the session's; the route has no parameter to change.
   */
  router.get('/me', requireUser, (req, res) => {
    const view = accountView({
      snapshot: collector.snapshot,
      collector,
      user: req.portal.user,
      health: collector.health(),
    });

    // The register no longer lists this person — deleted while a code was still
    // live. Ending the session is the honest answer; an empty page would read
    // as "you have nothing", which is a different and much more alarming thing
    // to tell somebody than "you are no longer here".
    if (view === null) {
      portalAuth.signOut(req);
      res.set('Set-Cookie', portalAuth.clearCookieHeader({ secure: isSecure(req) }));
      return res.status(401).json({ ok: false, error: 'portal.no_account' });
    }

    return res.json({ ok: true, ...view });
  });

  // ── One credential's configuration ────────────────────────────────────────

  /**
   * The person's own configuration file, for one of their own credentials.
   *
   * Answers with the artifact LIST as well as the one delivered, so the page can
   * offer the others — an Apple profile, a certificate bundle, the setup
   * instructions — without a second privileged call per credential.
   *
   * The bytes come back base64 and are handed to the browser base64. They are
   * NOT decoded here into a file download with a Content-Disposition, because
   * the page has to be able to show a QR of the same bytes and put the text on
   * screen for someone copying it by hand; doing both from one response is
   * simpler than fetching it twice, and it is one root call rather than two.
   */
  router.get('/creds/:id/config', requireUser, async (req, res) => {
    const owned = ownCred(req, res);
    if (!owned) return undefined;

    const artifact = normaliseArtifact(req.query.artifact);
    if (artifact === false) {
      return res.status(400).json({ ok: false, error: 'portal.artifact_unknown' });
    }

    // The only route on this socket that costs a subprocess. It is behind a
    // session, so this is not about strangers — it is about an authenticated
    // caller in a loop making this host fork on demand, which a session does
    // nothing to prevent. Checked AFTER ownership so that a budget cannot be
    // spent probing ids that were never going to resolve.
    if (!portalAuth.allowConfig(req.portal.user)) {
      const retryAfterSeconds = Math.ceil(portalAuth.configRetryAfterMs(req.portal.user) / 1000);
      res.set('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        ok: false, error: 'portal.rate_limited', retryAfterSeconds,
      });
    }

    // The language the handed-over text is written in. The viewer's, negotiated
    // for this request — the operator who issued this credential and the person
    // downloading it are usually not the same person and often do not read the
    // same language, so the locale is decided here and now rather than having
    // been frozen at issue.
    // catalogs.defaultLocale rather than cfg.default_locale — the settings
    // screen can change the default without a restart, and a handed-over file
    // written in the language the panel was STARTED in would be the one place
    // that change did not reach.
    const locale = catalogs.has(req.locale) ? req.locale : catalogs.defaultLocale;

    const ip = portalAuth.ip(req);
    try {
      const { details, artifacts } = await privileged.credConfig(
        req.portal.user, owned.meta.id, artifact, locale);

      audit.write({
        actor: req.portal.user, ip, verb: 'portal-config', target: owned.meta.id,
        result: 'ok', code: 0,
        detail: { service: owned.service.tag, artifact: details.artifact || null },
      });

      return res.json({
        ok: true,
        cred: owned.meta.id,
        service: owned.service.tag,
        serviceLabel: owned.service.label,
        artifact: details.artifact || null,
        artifacts,
        filename: details.filename || null,
        encoding: details.encoding || 'text',
        // The adapter's own judgement about whether a camera will actually
        // resolve this, not a guess from its length. A QR of eight kilobytes is
        // a picture of nothing, and offering one is worse than offering none
        // because it looks as though it should have worked.
        qr: details.qr === '1',
        // The adapter's own sentence about this file. Rendered verbatim and
        // attributed, exactly like a note — this side cannot translate a
        // sentence it did not write without learning which protocol wrote it.
        note: details.note || null,
        bodyBase64: details.body_b64 || '',
      });
    } catch (err) {
      const code = typeof err.code === 'number' ? err.code : 6;
      audit.write({
        actor: req.portal.user, ip, verb: 'portal-config', target: owned.meta.id,
        result: 'error', code, message: err.message,
      });
      log.warn(`portal config failed for ${req.portal.user}/${owned.meta.id}`, err.message);
      // The helper's message is NOT forwarded on this route. On the admin panel
      // it is, because an operator debugging a host wants the sentence root
      // wrote. Here the audience cannot act on it and the sentence can describe
      // the state of another person's credential, so the log keeps it and the
      // response carries a key.
      return res.status(statusForHelperCode(code)).json({
        ok: false,
        error: code === 5 ? E_NOT_FOUND : E_FAILED,
      });
    }
  });

  // ── Rotation ──────────────────────────────────────────────────────────────

  /**
   * Replace one of my credentials with a new one.
   *
   * ISSUE FIRST, THEN REVOKE, and the order is the whole design. The other way
   * round, a revocation that succeeds followed by an issue that fails leaves
   * somebody with no access at all and no way to get any — from a phone, on a
   * network they just lost. This way the worst case is two working credentials
   * and a message saying so, which an operator can tidy and which nobody is
   * locked out by.
   *
   * It is genuinely two privileged calls rather than one atomic verb, so the
   * failure between them is real and is reported rather than hidden.
   */
  router.post('/creds/:id/rotate', requireAction, async (req, res) => {
    const owned = ownCred(req, res);
    if (!owned) return undefined;

    const user = req.portal.user;
    const ip = portalAuth.ip(req);

    if (!portalAuth.allowRotate(user)) {
      audit.write({
        actor: user, ip, verb: 'portal-rotate', target: owned.meta.id,
        result: 'denied', message: 'portal.rotate_limited',
      });
      const retryAfterSeconds = Math.ceil(portalAuth.rotateRetryAfterMs(user) / 1000);
      res.set('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        ok: false, error: 'portal.rotate_limited', retryAfterSeconds,
      });
    }

    let issued = null;
    try {
      const { details } = await privileged.credAdd(user, owned.service.tag, {}, { actor: user });
      issued = details.cred_id || null;
      audit.write({
        actor: user, ip, verb: 'portal-rotate-add', target: `${user}/${owned.service.tag}`,
        result: 'ok', code: 0, detail: { credId: issued, replacing: owned.meta.id },
      });
    } catch (err) {
      const code = typeof err.code === 'number' ? err.code : 6;
      audit.write({
        actor: user, ip, verb: 'portal-rotate-add', target: `${user}/${owned.service.tag}`,
        result: 'error', code, message: err.message,
      });
      log.warn(`portal rotate could not issue for ${user}`, err.message);
      // Nothing was revoked, so the old credential still works. Saying so is
      // the difference between a user retrying calmly and a user thinking they
      // have just destroyed their own access.
      return res.status(statusForHelperCode(code)).json({
        ok: false, error: 'portal.rotate_failed_kept',
      });
    }

    // The helper refuses to report success without a credential id, so this is
    // an inconsistency rather than a normal outcome — but it must be handled
    // here, because the alternative is the one path in this route that can end
    // with the user holding nothing: revoking the working credential on the
    // strength of a replacement this process cannot name.
    //
    // Reported as "nothing changed, the one you have still works". That is true
    // whichever way the ambiguity resolves, which is what makes it the right
    // thing to say; if a credential WAS created, the audit line and the panel's
    // own list are where an operator finds it.
    if (!issued) {
      audit.write({
        actor: user, ip, verb: 'portal-rotate-revoke', target: owned.meta.id,
        result: 'denied', message: 'no credential id was returned; not revoking',
      });
      log.warn(`portal rotate for ${user}: the helper reported success with no `
        + `credential id, so ${owned.meta.id} was left alone`);
      return res.status(500).json({ ok: false, error: 'portal.rotate_failed_kept' });
    }

    let revoked = false;
    let latency = null;
    try {
      // expectUser is the second ownership check, and on this path it is the
      // one that does not depend on any code in this process being right. The
      // resolver above read a snapshot of the register that is up to a poll
      // interval old; the helper re-derives the holder from the registry as
      // root and refuses if it disagrees.
      const { details } = await privileged.credRevoke(
        owned.meta.id, owned.service.tag, { actor: user, expectUser: user });
      revoked = true;
      // The adapter's own answer about what it achieved, passed through
      // untouched. An adapter that ended the live session says so and is
      // believed — over-warning on the days it is instant is how somebody
      // learns to ignore the warning on the day it is not.
      latency = details.latency || null;
      audit.write({
        actor: user, ip, verb: 'portal-rotate-revoke', target: owned.meta.id,
        result: 'ok', code: 0, detail: { replacedBy: issued, latency },
      });
    } catch (err) {
      const code = typeof err.code === 'number' ? err.code : 6;
      audit.write({
        actor: user, ip, verb: 'portal-rotate-revoke', target: owned.meta.id,
        result: 'error', code, message: err.message,
      });
      log.warn(`portal rotate issued ${issued} but could not revoke ${owned.meta.id}`, err.message);
    }

    // Read the host again before answering, so the page renders a fresh reading
    // rather than an assumption about what the write did. The panel is not the
    // source of truth and a rotation is exactly when that matters.
    await collector.poll().catch(() => { /* the next scheduled poll catches up */ });

    return res.json({
      ok: true,
      cred: issued,
      replaced: owned.meta.id,
      // false means the new credential exists and the old one is still live.
      // Reported rather than smoothed over: two working credentials is a state
      // an operator needs to know about, and the person holding them is the one
      // who can say so.
      revoked,
      latency,
      service: owned.service.tag,
      serviceLabel: owned.service.label,
    });
  });

  // Anything else on this socket is not a route. A JSON 404 rather than
  // express's HTML default, so a client parsing this API never has to guess
  // whether it is holding a page.
  router.use((req, res) => {
    res.status(404).json({ ok: false, error: 'portal.not_found' });
  });

  return router;
}

module.exports = { build, statusForHelperCode, E_AUTH, E_NOT_FOUND, E_FAILED };
