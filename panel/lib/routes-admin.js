'use strict';
//
// panel/lib/routes-admin.js — sign-in, and the write actions.
//
// Everything here that changes anything goes through panel/lib/privileged.js and
// therefore through helper/vpnctl's seven verbs. There is no other write path in
// the panel, and no route below shells out, writes a config file, or touches the
// register directly.
//
// ── The shape of every write route ───────────────────────────────────────────
//
//   authenticated  →  CSRF header  →  validate  →  privileged verb  →  audit
//
// All four, in that order, for all of them. The audit entry is written whatever
// the outcome, including the refusals — a refused revocation is the record that
// matters most, because a successful one looks the same whoever asked for it.
//
// ── Message keys, never prose ────────────────────────────────────────────────
//
// Every `error` in a response is a catalog key. The panel is Vietnamese-first,
// and an API that returned English sentences would make its errors the one part
// of the product that never got translated — which is exactly the part somebody
// reads when things have gone wrong. The one exception is `detail`, which
// carries the HELPER's own message: adapter-authored text, rendered verbatim and
// attributed, the same rule the `note` and `filtering` records already follow.
//
// ── Why the panel does not paraphrase a revocation ───────────────────────────
//
// `cred-revoke` returns the latency the adapter actually achieved. It is passed
// through untouched. An adapter that managed to end the live session says so and
// is believed — over-warning on the days it is instant is how an operator learns
// to ignore the warning on the day it is not.

const express = require('express');

const log = require('./log');
const { CSRF_HEADER } = require('./auth');

// The register's nullable policy fields, and nothing else. `enabled` is absent
// on purpose: it has two verbs of its own, and a field assignment that quietly
// did the same thing would be a second way to reach the same state with a
// different audit record.
const POLICY_FIELDS = Object.freeze(['quota_bytes', 'expires_at', 'conn_limit', 'quota_reset']);

const RE_USER = /^[a-z][a-z0-9_-]{1,31}$/;
const RE_TAG = /^[a-z][a-z0-9_]{0,31}$/;
const RE_CRED = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Turn a HelperError into an HTTP status.
 *
 * The helper's exit codes already separate "you asked wrong" from "it went
 * wrong", and that distinction is worth carrying across: the first is a bug in
 * this panel and belongs in the 4xx range, the second is a condition on the
 * server and belongs in the 5xx range. Collapsing them to 500 would make a
 * mistyped quota look like a broken host.
 */
function statusForHelperCode(code) {
  switch (code) {
    case 2: return 400;   // usage
    case 3: return 400;   // bad argument
    case 4: return 500;   // not root — a deployment fault, not the caller's
    case 5: return 404;   // unknown target
    default: return 502;  // the action was attempted and did not succeed
  }
}

function build({ cfg, auth, audit, privileged, enforcer, collector, portalTokens, portalAuth }) {
  const router = express.Router();
  router.use(express.json({ limit: '32kb' }));

  // ── Guards ────────────────────────────────────────────────────────────────

  /**
   * Authenticated, and NOT counted as user interaction.
   *
   * The idle clock is only touched by writes and by an explicit heartbeat. A
   * poll that refreshed it would mean no unattended browser tab ever times out,
   * and the idle timeout would be decorative — the lesson is borrowed from a
   * sibling project where exactly that shipped.
   */
  function requireSession(req, res, next) {
    if (cfg.allow_unauthenticated) {
      req.session = { user: 'anonymous', csrf: null, ip: auth.ip(req) };
      return next();
    }
    const session = auth.resolve(req, { interactive: false });
    if (!session) return res.status(401).json({ ok: false, error: 'auth.required' });
    req.session = session;
    return next();
  }

  /**
   * A write. Authenticated, CSRF-checked, and it DOES count as interaction.
   *
   * SameSite=Strict already stops a cross-site form post; the header is the
   * second lock, because a cross-origin page can cause the cookie to be sent but
   * cannot read the token or set a custom header. For the one thing on this host
   * that can revoke access, one lock is not enough.
   */
  function requireWrite(req, res, next) {
    if (cfg.allow_unauthenticated) {
      req.session = { user: 'anonymous', csrf: null, ip: auth.ip(req) };
      return next();
    }
    const session = auth.resolve(req, { interactive: true });
    if (!session) return res.status(401).json({ ok: false, error: 'auth.required' });
    if (!auth.checkCsrf(req, session)) {
      audit.write({
        actor: session.user, ip: auth.ip(req), verb: 'csrf', target: req.path,
        result: 'denied', message: 'auth.csrf_failed',
      });
      return res.status(403).json({ ok: false, error: 'auth.csrf_failed' });
    }
    req.session = session;
    return next();
  }

  /** One place that turns a privileged call into a response and an audit line. */
  async function run(req, res, { verb, target, call, detail = null }) {
    const actor = req.session.user;
    const ip = auth.ip(req);
    try {
      const { result, details } = await call();
      audit.write({
        actor, ip, verb, target, result: 'ok', code: 0,
        message: result.message || null,
        detail: { ...(detail || {}), ...details },
      });
      return res.json({ ok: true, message: result.message || null, detail: details });
    } catch (err) {
      const code = typeof err.code === 'number' ? err.code : 6;
      audit.write({
        actor, ip, verb, target, result: 'error', code,
        message: err.message, detail: err.details || null,
      });
      log.warn(`${verb} failed for ${target}`, err.message);
      return res.status(statusForHelperCode(code)).json({
        ok: false,
        error: 'action.failed',
        // The helper's own sentence, rendered verbatim and attributed in the UI.
        detail: err.message,
        code,
      });
    }
  }

  // ── Session ───────────────────────────────────────────────────────────────

  // Whether the cookie is marked Secure follows how the request arrived. Behind
  // the nginx vhost it is https and the flag is right; on a plain-HTTP loopback
  // deployment the browser would DISCARD a Secure cookie, and the panel would
  // appear to accept a login and instantly forget it — a failure with nothing in
  // any log to explain it.
  const isSecure = (req) => req.secure
    || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';

  router.post('/session', async (req, res) => {
    const body = req.body || {};
    const outcome = auth.login(req, {
      username: typeof body.username === 'string' ? body.username : '',
      password: typeof body.password === 'string' ? body.password : '',
    });

    if (!outcome.ok) {
      // 429 for a throttle, 401 for a wrong password: a client that retries on a
      // 401 and backs off on a 429 can only do the right thing if they differ.
      const status = (outcome.error === 'auth.locked' || outcome.error === 'auth.rate_limited')
        ? 429 : 401;
      const payload = { ok: false, error: outcome.error };
      if (outcome.retryAfterMs) {
        payload.retryAfterSeconds = Math.ceil(outcome.retryAfterMs / 1000);
        res.set('Retry-After', String(payload.retryAfterSeconds));
      }
      return res.status(status).json(payload);
    }

    res.set('Set-Cookie', auth.cookieHeader(outcome.session, { secure: isSecure(req) }));
    return res.json({
      ok: true,
      user: outcome.session.user,
      // The CSRF token is returned in the BODY, not in a cookie. A token that
      // travelled in a cookie would be sent by the browser automatically, which
      // is the property that makes cookies forgeable cross-site in the first
      // place; one the page has to read and echo cannot be.
      csrf: outcome.session.csrf,
      csrfHeader: CSRF_HEADER,
      idleSeconds: Math.floor(auth.idleTtlMs / 1000),
      expiresInSeconds: Math.floor(auth.absoluteTtlMs / 1000),
    });
  });

  router.delete('/session', (req, res) => {
    auth.logout(req);
    res.set('Set-Cookie', auth.clearCookieHeader({ secure: isSecure(req) }));
    res.json({ ok: true });
  });

  router.get('/session', (req, res) => {
    if (cfg.allow_unauthenticated) {
      return res.json({ ok: true, authenticated: true, unauthenticatedMode: true, user: null });
    }
    const session = auth.resolve(req, { interactive: false });
    if (!session) return res.status(401).json({ ok: false, error: 'auth.required' });
    return res.json({
      ok: true,
      authenticated: true,
      user: session.user,
      csrf: session.csrf,
      csrfHeader: CSRF_HEADER,
      idleSeconds: Math.floor(auth.idleTtlMs / 1000),
      expiresInSeconds: Math.floor(
        Math.max(0, auth.absoluteTtlMs - (Date.now() - session.createdAt)) / 1000),
    });
  });

  /**
   * The idle heartbeat.
   *
   * Sent by the UI on a real gesture — a key, a pointer move, a click — and
   * never on a timer. It is the only GET that touches the idle clock, and that
   * is the whole point of it existing separately from every other read.
   */
  router.post('/session/touch', requireWrite, (req, res) => {
    res.json({ ok: true });
  });

  // ── Users ─────────────────────────────────────────────────────────────────

  router.post('/users', requireWrite, async (req, res) => {
    const body = req.body || {};
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!RE_USER.test(name)) return res.status(400).json({ ok: false, error: 'user.invalid_name' });

    const fields = {};
    for (const key of POLICY_FIELDS) {
      if (!Object.hasOwn(body, key)) continue;
      const v = body[key];
      // null and '' both mean the register's null — unlimited / never. They are
      // forwarded as an empty value rather than dropped, because dropping is
      // "leave it alone" and the caller asked for "clear it".
      fields[key] = (v === null || v === undefined) ? '' : String(v).trim();
    }

    return run(req, res, {
      verb: 'user-add', target: name, detail: { fields },
      call: () => privileged.userAdd(name, fields, { actor: req.session.user }),
    });
  });

  router.delete('/users/:name', requireWrite, async (req, res) => {
    const name = req.params.name;
    if (!RE_USER.test(name)) return res.status(400).json({ ok: false, error: 'user.invalid_name' });
    // The helper refuses while any credential is still active, and there is no
    // force flag anywhere in this stack — a peer left behind by a deleted user
    // is working access with nobody accountable for it. The UI turns the helper's
    // refusal into "revoke these first", which is the correct order of operations
    // rather than an obstacle to route around.
    return run(req, res, {
      verb: 'user-remove', target: name,
      call: () => privileged.userRemove(name, { actor: req.session.user }),
    });
  });

  router.post('/users/:name/enable', requireWrite, async (req, res) => {
    const name = req.params.name;
    if (!RE_USER.test(name)) return res.status(400).json({ ok: false, error: 'user.invalid_name' });
    return run(req, res, {
      verb: 'user-enable', target: name,
      call: () => privileged.userEnable(name, { actor: req.session.user }),
    });
  });

  /**
   * Disabling is a POLICY FLAG. It stops new credentials being issued; it does
   * NOT end a tunnel that is already up, because none of these services can
   * suspend a credential and later restore it.
   *
   * The helper reports how many credentials are still live, and that detail is
   * returned untouched so the UI can say "disabled, and N devices are still
   * connected" instead of a bare success. A success message that reads as
   * "access cut" when it is not is the same class of lie as a revocation that
   * has not taken effect.
   */
  router.post('/users/:name/disable', requireWrite, async (req, res) => {
    const name = req.params.name;
    if (!RE_USER.test(name)) return res.status(400).json({ ok: false, error: 'user.invalid_name' });
    return run(req, res, {
      verb: 'user-disable', target: name,
      call: () => privileged.userDisable(name, { actor: req.session.user }),
    });
  });

  // ── Credentials ───────────────────────────────────────────────────────────

  /**
   * Issue a credential.
   *
   * `options` are opaque here. This file must not learn what any adapter's
   * options mean — the adapter DECLARES them through its `capability option`
   * records, the UI prompts for whatever comes back, and the adapter refuses one
   * it did not declare. That is the only place the question "is this value
   * sane?" is actually answerable.
   */
  router.post('/creds', requireWrite, async (req, res) => {
    const body = req.body || {};
    const user = typeof body.user === 'string' ? body.user.trim() : '';
    const service = typeof body.service === 'string' ? body.service.trim() : '';
    if (!RE_USER.test(user)) return res.status(400).json({ ok: false, error: 'user.invalid_name' });
    if (!RE_TAG.test(service)) return res.status(400).json({ ok: false, error: 'service.invalid_tag' });

    const options = Object.create(null);
    if (body.options && typeof body.options === 'object' && !Array.isArray(body.options)) {
      for (const [k, v] of Object.entries(body.options)) {
        if (v === null || v === undefined || v === '') continue;
        options[k] = String(v);
      }
    }

    return run(req, res, {
      verb: 'cred-add', target: `${user}/${service}`, detail: { optionKeys: Object.keys(options) },
      call: () => privileged.credAdd(user, service, options, { actor: req.session.user }),
    });
  });

  /**
   * Revoke a credential.
   *
   * The owning service is resolved by the HELPER from the register, so the panel
   * cannot aim a revocation at the wrong one. A service tag may be supplied and
   * is used only as the fallback for a credential the register does not know —
   * which is the orphan case the status view already surfaces.
   */
  router.delete('/creds/:id', requireWrite, async (req, res) => {
    const id = req.params.id;
    if (!RE_CRED.test(id)) return res.status(400).json({ ok: false, error: 'cred.invalid_id' });

    const service = typeof req.query.service === 'string' ? req.query.service.trim() : '';
    if (service && !RE_TAG.test(service)) {
      return res.status(400).json({ ok: false, error: 'service.invalid_tag' });
    }

    return run(req, res, {
      verb: 'cred-revoke', target: id,
      call: () => privileged.credRevoke(id, service || null, { actor: req.session.user }),
    });
  });

  // ── Services ──────────────────────────────────────────────────────────────

  /**
   * Restart one service.
   *
   * `tag` is an adapter tag, and the helper refuses one no adapter registered —
   * which is what stops this from being "restart any unit on this box". The
   * disruption a restart causes is declared in the adapter's `capability restart`
   * record and shown BEFORE the operator confirms, because the disruption is the
   * thing they are deciding about. That ordering is the same lesson the
   * revocation notice already learned.
   */
  router.post('/services/:tag/restart', requireWrite, async (req, res) => {
    const tag = req.params.tag;
    if (!RE_TAG.test(tag)) return res.status(400).json({ ok: false, error: 'service.invalid_tag' });
    return run(req, res, {
      verb: 'service-restart', target: tag,
      call: () => privileged.serviceRestart(tag, { actor: req.session.user }),
    });
  });

  // ── Reads that only exist once there are writes ───────────────────────────

  router.get('/audit', requireSession, (req, res) => {
    const limit = Math.min(1000, Math.max(1, Number.parseInt(req.query.limit, 10) || 200));
    res.json({ ok: true, entries: audit.tail(limit) });
  });

  /**
   * The last enforcement pass.
   *
   * `stillConnected` and `quotaSkipped` are the two numbers worth showing: the
   * first is what flag-only enforcement did not achieve, the second is how many
   * accounts could not be checked at all. A summary of zeroes with no snapshot
   * behind it means "could not look", not "nothing to do", so `snapshotAge` is
   * carried too.
   */
  router.get('/enforcement', requireSession, (req, res) => {
    res.json({
      ok: true,
      enabled: cfg.enforce_enabled,
      intervalSeconds: Math.floor(cfg.enforce_interval_ms / 1000),
      quotaRevoke: cfg.enforce_quota_revoke,
      expiryRevoke: cfg.enforce_expiry_revoke,
      lastRun: enforcer ? enforcer.lastRun : null,
      disabledByJob: enforcer ? { ...enforcer.disabled } : {},
    });
  });

  // ── Portal access codes (Phase 8) ─────────────────────────────────────────
  //
  // These are NOT privileged calls and they do not go through vpnctl. Issuing a
  // code writes one line into the panel's own state directory, which
  // docs/security-model.md §3 already lists the panel as owning outright,
  // portal tokens included. It touches no key, no server configuration and no
  // register entry, so routing it through the root helper would widen the
  // privileged surface in order to do something unprivileged.
  //
  // They live in the ADMIN tree because issuing somebody access is an operator's
  // action. Nothing on the portal's own socket can reach them: that is a
  // different express application, and these routes are not registered on it.
  //
  // The same operations exist at the console in scripts/portal.js, which is the
  // path that still works when sign-in is off or a password has been lost.

  /** Every code, or one user's. Never a code itself — only fingerprint records. */
  router.get('/portal/tokens', requireSession, (req, res) => {
    if (!portalTokens) return res.status(404).json({ ok: false, error: 'portal.disabled' });
    const user = typeof req.query.user === 'string' ? req.query.user.trim() : '';
    if (user && !RE_USER.test(user)) {
      return res.status(400).json({ ok: false, error: 'user.invalid_name' });
    }
    return res.json({ ok: true, enabled: cfg.portal_enabled, tokens: portalTokens.list(user || null) });
  });

  /**
   * Issue a code.
   *
   * The plaintext is in the RESPONSE BODY and nowhere else. It is not in the
   * audit log, not in the panel's own log and not on disk — only its
   * fingerprint is stored, so this response is the one and only time it exists.
   * The audit record says a code was issued, to whom, by whom; a log that also
   * carried the code would turn every audit reader into somebody who can sign
   * in as anybody.
   */
  router.post('/portal/tokens', requireWrite, (req, res) => {
    if (!portalTokens) return res.status(404).json({ ok: false, error: 'portal.disabled' });
    const body = req.body || {};
    const name = typeof body.user === 'string' ? body.user.trim() : '';
    if (!RE_USER.test(name)) return res.status(400).json({ ok: false, error: 'user.invalid_name' });

    let days = null;
    if (body.days !== undefined && body.days !== null && body.days !== '') {
      days = Number.parseInt(String(body.days), 10);
      if (!Number.isInteger(days) || days < 1 || days > 3650) {
        return res.status(400).json({ ok: false, error: 'portal.token.bad_days' });
      }
    }

    let issued;
    try {
      issued = portalTokens.issue(name, {
        label: typeof body.label === 'string' ? body.label : '',
        expiresInDays: days,
      });
    } catch (err) {
      log.warn(`could not issue a portal code for ${name}`, err.message);
      return res.status(500).json({ ok: false, error: 'action.failed' });
    }

    audit.write({
      actor: req.session.user, ip: auth.ip(req), verb: 'portal-token-issue',
      target: name, result: 'ok', code: 0,
      detail: { tokenId: issued.record.id, expiresAt: issued.record.expiresAt },
    });

    return res.json({ ok: true, token: issued.token, record: issued.record });
  });

  /**
   * Withdraw a code.
   *
   * A session already open on it ends at its next request rather than at its
   * expiry — portalAuth re-checks the code on every resolve. Unlike a tunnel,
   * this one CAN be ended immediately, so it is: reporting an access withdrawal
   * that stays live for two more hours is the same class of untruth as a
   * revocation reported before it has taken effect.
   */
  router.delete('/portal/tokens/:id', requireWrite, (req, res) => {
    if (!portalTokens) return res.status(404).json({ ok: false, error: 'portal.disabled' });
    const id = String(req.params.id || '');
    if (!/^[0-9a-f]{16}$/.test(id)) {
      return res.status(400).json({ ok: false, error: 'portal.token.invalid_id' });
    }
    const record = portalTokens.revoke(id);
    if (!record) return res.status(404).json({ ok: false, error: 'portal.token.unknown' });

    const ended = portalAuth ? portalAuth.revokeToken(record.id) : 0;
    audit.write({
      actor: req.session.user, ip: auth.ip(req), verb: 'portal-token-revoke',
      target: record.user, result: 'ok', code: 0,
      detail: { tokenId: record.id, sessionsEnded: ended },
    });
    return res.json({ ok: true, record, sessionsEnded: ended });
  });

  /**
   * Force a status re-read, so the UI is not showing a stale snapshot straight
   * after a write. It is a POST because it costs a subprocess, and it is behind
   * requireWrite for the same reason — an unauthenticated caller must not be
   * able to make this host fork on demand.
   */
  router.post('/refresh', requireWrite, async (req, res) => {
    await collector.poll();
    res.json({ ok: true, health: collector.health() });
  });

  return router;
}

module.exports = { build, statusForHelperCode, POLICY_FIELDS };
