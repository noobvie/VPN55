'use strict';
/*
 * panel/public/js/actions.js — sign-in, and everything that changes something.
 *
 * Loaded BEFORE app.js and exposed as VPN55_ACTIONS. It owns three things the
 * read views deliberately know nothing about: the session, the CSRF token, and
 * the confirm-then-call cycle every write goes through.
 *
 * ── The same three rules app.js is built on ─────────────────────────────────
 *
 *  1. NO STRING IS WRITTEN HERE. Every visible word comes from t().
 *  2. NO innerHTML, ANYWHERE. Every node is created; every string is a text
 *     node. A user name and a credential id are values from the host, and the
 *     host is exactly where an attacker who got that far would put a payload.
 *  3. THE PROTOCOL IS NEVER NAMED. A service is a tag and a label the adapter
 *     declared; this file has no list of them and no branch on which one it is.
 *
 * ── Why the confirmation is a dialog and not window.confirm ─────────────────
 *
 * A browser lets someone tick "prevent this page from creating more dialogs",
 * and from then on window.confirm returns false without asking. On a page whose
 * confirmations guard irreversible actions, a control that can be silently
 * disabled by the person using it is the wrong control — they would click
 * Revoke, see nothing happen, and click it again.
 *
 * ── The CSRF token travels in a header, never in a cookie ───────────────────
 *
 * A cookie is sent by the browser automatically, which is the exact property
 * that makes a cookie forgeable from another site. A token this page had to read
 * out of a response body and put into a custom header cannot be replayed by a
 * page that cannot read that body.
 *
 * ── The idle clock counts gestures, not traffic ─────────────────────────────
 *
 * The panel polls every fifteen seconds. If a poll refreshed the idle timer, an
 * unattended browser tab would hold a session open indefinitely and the timeout
 * would be decorative. So the heartbeat below is sent on a REAL gesture and at
 * most once a minute — and never on a timer, and never by the poll.
 */

var VPN55_ACTIONS = (function () {
  var t = VPN55_I18N.t;
  // Server-supplied keys go through tOr: the panel and the server can be a
  // version apart, and a key this catalog predates must degrade to a sentence
  // rather than render as `action.thing.failed` in front of an operator.
  var tOr = VPN55_I18N.tOr;

  var CSRF_HEADER = 'X-VPN55-CSRF';

  var session = {
    known: false,          // have we asked the server yet?
    authenticated: false,
    unauthenticatedMode: false,   // sign-in switched off in panel.conf
    user: null,
    csrf: null,
  };

  var listeners = [];
  var lastTouch = 0;
  var overlay = null;

  /* ── DOM helpers ──────────────────────────────────────────────────────────
   * A local copy rather than a shared one: this file loads first, and a helper
   * imported across files is a load-order dependency waiting to be reordered. */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined) return;
        if (k === 'text') node.appendChild(document.createTextNode(String(v)));
        else node.setAttribute(k, String(v));
      });
    }
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function onChange(fn) { listeners.push(fn); }
  function fire(what) { listeners.forEach(function (fn) { try { fn(what); } catch (e) { /* a listener must not stop the others */ } }); }

  /* ══════════════════════════════════════════════════════════════════════════
     Requests
     ══════════════════════════════════════════════════════════════════════════ */

  /**
   * Every call to the panel goes through here.
   *
   * Resolves with the parsed body on success and REJECTS with an object carrying
   * `error` (a catalog key) and `detail` (the helper's own sentence, if there is
   * one) on failure. The distinction matters: `error` is ours and is translated;
   * `detail` was written by a program that knows which protocol it is, so it is
   * shown verbatim and attributed rather than reworded into something this side
   * cannot actually vouch for.
   */
  function request(method, path, body) {
    var opts = {
      method: method,
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (session.csrf && method !== 'GET') opts.headers[CSRF_HEADER] = session.csrf;

    return fetch(path, opts).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.ok) return data;

        // A 401 anywhere means the session is gone — expired, idled out, or the
        // panel restarted. Show the sign-in form rather than an error about a
        // request nobody made consciously.
        if (res.status === 401) {
          session.authenticated = false;
          session.user = null;
          session.csrf = null;
          showSignIn();
        }
        var err = {
          status: res.status,
          error: data.error || 'action.failed',
          detail: data.detail || null,
          retryAfterSeconds: data.retryAfterSeconds || null,
        };
        throw err;
      });
    }, function () {
      // The panel process itself did not answer. A different failure from a
      // refusal, and it gets a different message.
      throw { status: 0, error: 'app.unreachable.title', detail: null };
    });
  }

  /* ══════════════════════════════════════════════════════════════════════════
     Session
     ══════════════════════════════════════════════════════════════════════════ */

  function readSession() {
    return request('GET', '/api/admin/session').then(function (data) {
      session.known = true;
      session.authenticated = true;
      session.unauthenticatedMode = data.unauthenticatedMode === true;
      session.user = data.user || null;
      session.csrf = data.csrf || null;
      hideSignIn();
      return session;
    }, function () {
      session.known = true;
      session.authenticated = false;
      return session;
    });
  }

  function signIn(username, password) {
    return request('POST', '/api/admin/session', {
      username: username, password: password,
    }).then(function (data) {
      session.known = true;
      session.authenticated = true;
      session.user = data.user;
      session.csrf = data.csrf;
      hideSignIn();
      fire('signin');
      return session;
    });
  }

  function signOut() {
    return request('DELETE', '/api/admin/session').then(function () {
      session.authenticated = false;
      session.user = null;
      session.csrf = null;
      showSignIn();
      fire('signout');
    });
  }

  /**
   * The idle heartbeat.
   *
   * Bound to real gestures and throttled to once a minute, so an open tab that
   * nobody is touching does time out. Errors are swallowed: a failed heartbeat
   * is not something to interrupt anyone about, and the next request will find
   * the session gone and show the form.
   */
  function touch() {
    if (!session.authenticated || session.unauthenticatedMode) return;
    var now = Date.now();
    if (now - lastTouch < 60000) return;
    lastTouch = now;
    request('POST', '/api/admin/session/touch').catch(function () { /* see above */ });
  }

  /* ══════════════════════════════════════════════════════════════════════════
     The sign-in form
     ══════════════════════════════════════════════════════════════════════════ */

  function showSignIn() {
    if (overlay) return;
    if (session.unauthenticatedMode) return;

    var name = el('input', { type: 'text', id: 'signin-name', autocomplete: 'username', autocapitalize: 'off', spellcheck: 'false' });
    var pass = el('input', { type: 'password', id: 'signin-pass', autocomplete: 'current-password' });
    var problem = el('p', { class: 'signin__problem', role: 'alert' });
    var submit = el('button', { type: 'submit', class: 'btn btn--primary', text: t('auth.signin') });

    var form = el('form', { class: 'signin__form', novalidate: 'novalidate' }, [
      el('h1', { class: 'signin__title', text: t('auth.title') }),
      el('label', { for: 'signin-name', text: t('auth.username') }),
      name,
      el('label', { for: 'signin-pass', text: t('auth.password') }),
      pass,
      problem,
      submit,
    ]);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      problem.textContent = '';
      submit.disabled = true;
      submit.textContent = t('action.working');

      signIn(name.value, pass.value).catch(function (err) {
        // The password field is cleared and the name is not: whoever just
        // mistyped a long passphrase should not also have to retype their name,
        // and leaving the password in the box is how it ends up in a screenshot.
        pass.value = '';
        problem.textContent = tOr(err.error, 'action.failed', {
          minutes: err.retryAfterSeconds
            ? Math.max(1, Math.ceil(err.retryAfterSeconds / 60)) : 0,
        });
      }).then(function () {
        submit.disabled = false;
        submit.textContent = t('auth.signin');
      });
    });

    overlay = el('div', { class: 'signin', role: 'dialog', 'aria-modal': 'true' }, [form]);
    document.body.appendChild(overlay);
    name.focus();
  }

  function hideSignIn() {
    if (!overlay) return;
    overlay.remove();
    overlay = null;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     Confirm, then act
     ══════════════════════════════════════════════════════════════════════════ */

  /**
   * A modal confirmation. Resolves true or false; never throws.
   *
   * `danger` reddens the confirm button and is set for the two actions that
   * cannot be undone — deleting a user and revoking a credential. The wording
   * says what cannot be undone; the colour only makes it hard to miss.
   */
  function confirm(message, opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var box = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' });
      var yes = el('button', {
        type: 'button',
        class: 'btn ' + (opts.danger ? 'btn--danger' : 'btn--primary'),
        text: opts.confirmLabel || t('action.confirm'),
      });
      var no = el('button', { type: 'button', class: 'btn', text: t('action.cancel') });

      function close(answer) {
        document.removeEventListener('keydown', onKey, true);
        box.remove();
        resolve(answer);
      }
      function onKey(ev) {
        if (ev.key === 'Escape') { ev.preventDefault(); close(false); }
      }

      yes.addEventListener('click', function () { close(true); });
      no.addEventListener('click', function () { close(false); });
      document.addEventListener('keydown', onKey, true);

      box.appendChild(el('div', { class: 'modal__box' }, [
        el('p', { class: 'modal__text', text: message }),
        el('div', { class: 'modal__buttons' }, [no, yes]),
      ]));
      document.body.appendChild(box);
      // Cancel takes focus, not the confirm button: the Enter key belongs to the
      // safe answer when the dialog is guarding something irreversible.
      no.focus();
    });
  }

  /* ══════════════════════════════════════════════════════════════════════════
     Feedback
     ══════════════════════════════════════════════════════════════════════════ */

  function flash(kind, message, detail) {
    var host = document.getElementById('vpn55-flash');
    if (!host) {
      host = el('div', { id: 'vpn55-flash', class: 'flash' });
      document.body.appendChild(host);
    }
    var box = el('div', { class: 'flash__item flash__item--' + kind, role: 'status' }, [
      el('p', { text: message }),
      // The helper's own sentence, quoted and attributed. It is the one piece of
      // text on the page that stays in the language the service wrote it in, and
      // saying so is better than leaving a line that looks like a failed
      // translation.
      detail ? el('p', { class: 'flash__from', text: t('action.fromhelper', { detail: detail }) }) : null,
    ]);
    host.appendChild(box);
    setTimeout(function () { box.remove(); }, kind === 'ok' ? 6000 : 12000);
  }

  /**
   * The whole cycle for one write: confirm if asked, call, report, re-poll.
   *
   * `okKey` is the catalog key for the success message and `vars` fills it in.
   * The reload afterwards is not cosmetic — the panel is not the source of truth,
   * so the only honest way to show the result of a write is to read the host
   * again rather than to assume the write did what it said.
   */
  function act(spec) {
    var run = spec.confirm
      ? confirm(spec.confirm, { danger: spec.danger, confirmLabel: spec.confirmLabel })
      : Promise.resolve(true);

    return run.then(function (go) {
      if (!go) return null;
      touch();
      return request(spec.method, spec.path, spec.body).then(function (data) {
        flash('ok', spec.ok ? spec.ok(data) : t('action.failed'), null);
        // Ask the panel to read the host again before the next scheduled poll,
        // so what is on screen is a fresh reading and not an assumption.
        return request('POST', '/api/admin/refresh')
          .catch(function () { /* the next poll will catch up */ })
          .then(function () { fire('changed'); return data; });
      }, function (err) {
        flash('error', tOr(err.error, 'action.failed'), err.detail);
        throw err;
      });
    });
  }

  /** A button wired to `act`. Disables itself while the call is in flight. */
  function button(label, spec, extraClass) {
    var b = el('button', {
      type: 'button',
      class: 'btn btn--row' + (extraClass ? ' ' + extraClass : ''),
      text: label,
    });
    b.addEventListener('click', function () {
      b.disabled = true;
      act(spec).catch(function () { /* already reported by act */ })
        .then(function () { b.disabled = false; });
    });
    return b;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     Start
     ══════════════════════════════════════════════════════════════════════════ */

  function start() {
    ['keydown', 'pointerdown'].forEach(function (evt) {
      document.addEventListener(evt, touch, { passive: true });
    });
    return readSession().then(function (s) {
      if (!s.authenticated && !s.unauthenticatedMode) showSignIn();
      return s;
    });
  }

  return {
    session: session,
    start: start,
    readSession: readSession,
    signIn: signIn,
    signOut: signOut,
    showSignIn: showSignIn,
    request: request,
    confirm: confirm,
    flash: flash,
    act: act,
    button: button,
    onChange: onChange,
    el: el,
    CSRF_HEADER: CSRF_HEADER,
  };
})();
