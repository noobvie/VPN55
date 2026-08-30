'use strict';
/*
 * panel/portal/public/js/portal.js — the self-serve page.
 *
 * ── The three rules the admin UI is built on, and this one too ──────────────
 *
 *  1. NO STRING IS WRITTEN HERE. Every visible word comes from t(). This is the
 *     surface most users see and Vietnamese is the default locale, so an
 *     English sentence hardcoded here is a sentence no translator will ever be
 *     shown and every user will read in the wrong language.
 *
 *  2. NO innerHTML, ANYWHERE. Every node is created and every string is a text
 *     node. The values on this page — a credential id, a service label, the
 *     text of a configuration file — come from services on the host, which is
 *     exactly where an attacker who got that far would put a payload.
 *
 *  3. THE PROTOCOL IS NEVER NAMED. A service is a tag and a label the adapter
 *     declared. There is no list of protocols in this file and no branch on
 *     which one is which; the filtering warning is the adapter's own words.
 *
 * ── What is different from the admin page ───────────────────────────────────
 *
 * It shows exactly one person's own account, because that is all the API will
 * answer with. There is no user list to render, no id to type, and no route
 * with somebody else's name in it — see panel/portal/logic.js.
 *
 * ── The access code arrives in the fragment ─────────────────────────────────
 *
 * An operator sends a link ending `#code=…`. A fragment is never transmitted to
 * the server, so the code stays out of the nginx access log, out of the Referer
 * header of whatever the user clicks next, and out of any proxy in between. The
 * page reads it, posts it in a body, and then rewrites the address bar so a
 * screenshot or a shared link does not carry it either.
 */

(function () {
  var t = VPN55_I18N.t;
  var tOr = VPN55_I18N.tOr;
  var F = VPN55_FMT;

  var CSRF_HEADER = 'X-VPN55-PORTAL-CSRF';
  var POLL_MS = 30000;

  var state = {
    known: false,
    user: null,
    csrf: null,
    account: null,
    /* credId -> the last config response for it, so switching artifacts and
       re-opening a panel does not re-ask the host for something it just sent. */
    configs: Object.create(null),
    open: Object.create(null),
    error: null
  };

  var root = null;
  var timer = null;

  /* ── DOM ───────────────────────────────────────────────────────────────── */

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined) return;
        if (k === 'text') node.appendChild(document.createTextNode(String(v)));
        else if (k === 'on') Object.keys(v).forEach(function (evt) { node.addEventListener(evt, v[evt]); });
        else node.setAttribute(k, String(v));
      });
    }
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  /** A value that may be absent. The em dash is an answer, not an empty cell. */
  function value(text, unset, title) {
    var node = el('dd', { text: text, class: unset ? 'num is-unset' : 'num' });
    if (title) node.setAttribute('title', title);
    return node;
  }

  function fact(dl, labelKey, valueNode) {
    dl.appendChild(el('dt', { text: t(labelKey) }));
    dl.appendChild(valueNode);
  }

  function badge(kind, label, title) {
    return el('span', { class: 'badge badge--' + kind, text: label, title: title || null });
  }

  /**
   * A service's own sentence, quoted and attributed.
   *
   * The label is translated; the sentence is not, and cannot be — it was
   * written by a module that knows which protocol it is, and this side may not
   * learn that. Saying so is better than leaving one line that looks like a
   * failed translation.
   */
  function fromService(message) {
    if (!message) return null;
    return el('p', { class: 'from-service' }, [
      el('span', { class: 'from-service__mark', text: t('fromservice.label') }),
      document.createTextNode(message)
    ]);
  }

  /* ── Requests ──────────────────────────────────────────────────────────── */

  function request(method, path, body) {
    var opts = {
      method: method,
      headers: { Accept: 'application/json' },
      credentials: 'same-origin'
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (state.csrf && method !== 'GET') opts.headers[CSRF_HEADER] = state.csrf;

    return fetch(path, opts).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.ok) return data;
        if (res.status === 401) {
          state.user = null;
          state.csrf = null;
          state.account = null;
        }
        throw {
          status: res.status,
          error: data.error || 'portal.failed',
          retryAfterSeconds: data.retryAfterSeconds || null
        };
      });
    }, function () {
      /* The portal process itself did not answer — a different failure from a
         refusal, and it gets a different message. */
      throw { status: 0, error: 'portal.unreachable' };
    });
  }

  /* ── Feedback ──────────────────────────────────────────────────────────── */

  function flash(kind, message) {
    var host = document.getElementById('portal-flash');
    if (!host) {
      host = el('div', { id: 'portal-flash', class: 'flash' });
      document.body.appendChild(host);
    }
    var box = el('div', { class: 'flash__item flash__item--' + kind, role: 'status' },
      [el('p', { text: message })]);
    host.appendChild(box);
    setTimeout(function () { box.remove(); }, kind === 'ok' ? 6000 : 12000);
  }

  /**
   * A modal confirmation. Never window.confirm: a browser lets somebody tick
   * "prevent this page from creating more dialogs", and from then on it returns
   * false without asking — so the guard in front of the one irreversible action
   * here would silently stop working and the button would appear dead.
   */
  function confirmAction(message, opts) {
    var options = opts || {};
    return new Promise(function (resolve) {
      var yes = el('button', {
        type: 'button',
        class: 'btn ' + (options.danger ? 'btn--danger' : 'btn--primary'),
        text: options.confirmLabel || t('action.confirm')
      });
      var no = el('button', { type: 'button', class: 'btn', text: t('action.cancel') });
      var box = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' });

      function close(answer) {
        document.removeEventListener('keydown', onKey, true);
        box.remove();
        resolve(answer);
      }
      function onKey(ev) { if (ev.key === 'Escape') { ev.preventDefault(); close(false); } }

      yes.addEventListener('click', function () { close(true); });
      no.addEventListener('click', function () { close(false); });
      document.addEventListener('keydown', onKey, true);

      box.appendChild(el('div', { class: 'modal__box' }, [
        el('p', { class: 'modal__text', text: message }),
        el('div', { class: 'modal__buttons' }, [no, yes])
      ]));
      document.body.appendChild(box);
      /* Cancel takes focus. The Enter key belongs to the safe answer when the
         dialog is guarding something that cannot be undone. */
      no.focus();
    });
  }

  /* ── Sign in ───────────────────────────────────────────────────────────── */

  function readCodeFromFragment() {
    var hash = String(window.location.hash || '');
    var m = /(?:^#|&)code=([^&]+)/.exec(hash);
    if (!m) return null;
    try {
      return decodeURIComponent(m[1]);
    } catch (e) {
      return m[1];
    }
  }

  /** Take the code out of the address bar once it has been read. */
  function stripFragment() {
    try {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    } catch (e) {
      /* A browser that refuses this still works; the code simply stays in the
         address bar, which is why it was never in the query string. */
    }
  }

  function signIn(code) {
    return request('POST', '/api/portal/session', { code: code }).then(function (data) {
      state.user = data.user;
      state.csrf = data.csrf;
      return load();
    });
  }

  function renderSignIn() {
    var input = el('input', {
      type: 'text',
      id: 'portal-code',
      class: 'field field--code',
      autocomplete: 'off',
      autocapitalize: 'off',
      autocorrect: 'off',
      spellcheck: 'false'
    });
    var problem = el('p', { class: 'problem', role: 'alert' });
    var submit = el('button', { type: 'submit', class: 'btn btn--primary btn--wide', text: t('portal.signin') });

    var form = el('form', { class: 'card signin', novalidate: 'novalidate' }, [
      el('h1', { class: 'card__title', text: t('portal.signin.title') }),
      el('p', { class: 'card__sub', text: t('portal.signin.help') }),
      el('label', { for: 'portal-code', text: t('portal.code') }),
      input,
      problem,
      submit
    ]);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      problem.textContent = '';
      submit.disabled = true;
      submit.textContent = t('action.working');
      signIn(input.value.trim()).catch(function (err) {
        problem.textContent = tOr(err.error, 'portal.failed', {
          minutes: err.retryAfterSeconds ? Math.max(1, Math.ceil(err.retryAfterSeconds / 60)) : 0
        });
      }).then(function () {
        submit.disabled = false;
        submit.textContent = t('portal.signin');
      });
    });

    var wrap = el('div', {}, [form]);
    setTimeout(function () { input.focus(); }, 0);
    return wrap;
  }

  /* ── The account ───────────────────────────────────────────────────────── */

  function accountCard(account) {
    var u = account.user;
    var card = el('section', { class: 'card' });

    var status;
    if (!u.enabled) status = badge('crit', t('portal.state.disabled'), t('portal.state.disabled.help'));
    else if (u.expired === true) status = badge('crit', t('portal.state.expired'));
    else if (u.expired === null) status = badge('warn', t('portal.state.expiry_unreadable'));
    else status = badge('ok', t('portal.state.active'));

    card.appendChild(el('h2', { class: 'card__title' }, [
      document.createTextNode(t('portal.account')),
      document.createTextNode(' '),
      status
    ]));

    var dl = el('dl', { class: 'facts' });

    fact(dl, 'portal.col.used', value(F.bytes(u.total)));
    fact(dl, 'portal.col.down', value(F.bytes(u.rxTotal)));
    fact(dl, 'portal.col.up', value(F.bytes(u.txTotal)));

    /* A null quota is UNLIMITED, and it is not a zero. Rendering the null as a
       zero would put every unlimited account at 100% of nothing. */
    if (u.quotaBytes === null) {
      fact(dl, 'portal.col.quota', value(t('quota.unlimited'), true, t('quota.unlimited.help')));
    } else {
      fact(dl, 'portal.col.quota', value(F.bytes(u.quotaBytes)));
      fact(dl, 'portal.col.remaining', value(F.bytes(u.quotaRemaining)));
    }

    if (u.expiresAt === null) {
      fact(dl, 'portal.col.expires', value(t('expiry.never'), true, t('expiry.never.help')));
    } else {
      fact(dl, 'portal.col.expires', value(F.isoDate(u.expiresAt)));
    }

    if (u.connLimit !== null) fact(dl, 'portal.col.devices', value(F.numeric(u.connLimit)));

    card.appendChild(dl);

    if (u.quotaUsedFraction !== null) {
      var pct = Math.max(0, Math.min(1, u.quotaUsedFraction));
      var fillClass = 'meter__fill';
      if (pct >= 1) fillClass += ' meter__fill--crit';
      else if (pct >= 0.8) fillClass += ' meter__fill--warn';
      card.appendChild(el('div', { class: 'meter' }, [
        el('div', { class: fillClass, style: 'width:' + (pct * 100).toFixed(1) + '%' })
      ]));
      card.appendChild(el('p', {
        class: 'small muted',
        text: t('portal.quota.used', { percent: F.percent(u.quotaUsedFraction) })
      }));
    }

    /* Disabling is a POLICY FLAG and it does not end a tunnel already up. The
       page says so rather than letting somebody conclude from a red badge that
       their connection has been cut when it has not. */
    if (!u.enabled) {
      card.appendChild(el('p', { class: 'banner banner--crit', text: t('portal.disabled.explain') }));
    }

    return card;
  }

  /* ── One credential ────────────────────────────────────────────────────── */

  function credentialCard(cred) {
    var card = el('section', { class: 'card' });

    card.appendChild(el('h2', { class: 'card__title' }, [
      document.createTextNode(cred.serviceLabel),
      document.createTextNode(' '),
      cred.connected
        ? badge('ok', t('portal.connected'))
        : badge('idle', t('portal.notconnected'), t('portal.notconnected.help'))
    ]));

    var dl = el('dl', { class: 'facts' });
    fact(dl, 'portal.col.issued', value(cred.created ? F.isoDate(cred.created) : F.DASH, !cred.created));
    fact(dl, 'portal.col.address', value(cred.address || F.DASH, !cred.address));

    var seen = F.handshake(cred.lastSeen);
    fact(dl, 'portal.col.lastseen', value(seen.text, false, seen.title));

    var down = cred.rxTotal === null && cred.txTotal === null;
    fact(dl, 'portal.col.used',
      value(F.bytes(cred.rxTotal) + ' / ' + F.bytes(cred.txTotal), down, t('value.noreading.help')));

    /* Who holds the private key, per credential. It is a disclosure, not a
       statistic: on the server-generated path this machine saw the key, and the
       person deciding whether that is acceptable is the one reading this page. */
    if (cred.custody) {
      fact(dl, 'custody.label', el('dd', {
        text: tOr('custody.who.' + cred.custody, 'custody.who.other', { who: cred.custody })
      }));
    }
    card.appendChild(dl);

    /* How this service fares on a filtered network. The LEVEL is a stable word
       this page translates; the sentence is the adapter's own and is shown
       verbatim — a reader cannot translate a sentence it did not write without
       learning which protocol wrote it, which is the one thing it may not do. */
    if (cred.filtering) {
      var lvl = cred.filtering.level;
      var kind = lvl === 'resistant' ? 'ok' : (lvl === 'exposed' ? 'crit' : 'warn');
      card.appendChild(el('p', { class: 'small' }, [
        document.createTextNode(t('filtering.label') + ' '),
        badge(cred.filtering.levelKnown ? kind : 'unknown',
          tOr('filtering.level.' + lvl, 'filtering.level.other', { level: lvl }),
          cred.filtering.levelKnown ? null : t('filtering.level.unrecognised'))
      ]));
      var explain = fromService(cred.filtering.explanation);
      if (explain) card.appendChild(explain);
    }

    var actions = el('div', { class: 'actions' });

    /* configAvailable is three-valued and each value gets a different control.
       false means the key was erased on schedule and there is genuinely nothing
       to download — offering a button that can only fail would be worse than
       saying so. null means the service did not answer, and the button is
       offered, because telling somebody their working credential is beyond
       recovery on the strength of a missing field is the more expensive wrong
       answer. */
    if (cred.configAvailable === false) {
      card.appendChild(el('p', { class: 'banner banner--warn', text: t('portal.config.gone') }));
    } else {
      actions.appendChild(el('button', {
        type: 'button',
        class: 'btn btn--primary',
        text: t('portal.download'),
        on: { click: function () { openConfig(cred.id, null); } }
      }));
    }

    actions.appendChild(el('button', {
      type: 'button',
      class: 'btn btn--danger',
      text: t('portal.rotate'),
      on: { click: function () { rotate(cred); } }
    }));
    card.appendChild(actions);

    if (state.open[cred.id]) card.appendChild(configPanel(cred));
    return card;
  }

  /* ── The configuration panel ───────────────────────────────────────────── */

  function openConfig(credId, artifact) {
    state.open[credId] = true;
    var key = credId + '\u0000' + (artifact || '');
    if (state.configs[key]) { render(); return; }

    state.configs[key] = { loading: true };
    render();

    var url = '/api/portal/creds/' + encodeURIComponent(credId) + '/config'
      + (artifact ? '?artifact=' + encodeURIComponent(artifact) : '');

    request('GET', url).then(function (data) {
      state.configs[key] = data;
      render();
    }, function (err) {
      delete state.configs[key];
      flash('error', tOr(err.error, 'portal.failed'));
      render();
    });
  }

  /** base64 to bytes, and to text. No atob shortcut for the text: a UTF-8
      configuration with Vietnamese in a comment would come back mangled. */
  function decodeBytes(b64) {
    var binary = atob(String(b64 || ''));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function decodeText(b64) {
    var bytes = decodeBytes(b64);
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    try { return decodeURIComponent(escape(s)); } catch (e) { return s; }
  }

  function configPanel(cred) {
    var wrap = el('div', { class: 'config' });
    var current = null;
    var currentKey = null;

    /* Whichever artifact of this credential was loaded last. */
    Object.keys(state.configs).forEach(function (k) {
      if (k.indexOf(cred.id + '\u0000') !== 0) return;
      currentKey = k;
      current = state.configs[k];
    });

    if (!current) return wrap;
    if (current.loading) {
      wrap.appendChild(el('p', { class: 'muted small', text: t('action.working') }));
      return wrap;
    }

    /* Other files this credential has. Rendered as buttons rather than a select
       so the label, which is the adapter's own and may be long in any language,
       is allowed to wrap. */
    if (current.artifacts && current.artifacts.length > 1) {
      var picker = el('div', { class: 'actions' });
      current.artifacts.forEach(function (a) {
        picker.appendChild(el('button', {
          type: 'button',
          class: 'btn' + (a.id === current.artifact ? ' btn--primary' : ''),
          text: a.label,
          on: { click: function () { openConfig(cred.id, a.id); } }
        }));
      });
      wrap.appendChild(picker);
    }

    var note = fromService(current.note);
    if (note) wrap.appendChild(note);

    var isText = current.encoding === 'text';

    if (isText) {
      var text = decodeText(current.bodyBase64);
      wrap.appendChild(el('pre', { class: 'config__body', text: text }));

      /* A QR only where the adapter said a camera will resolve it, and only
         where the encoder agrees it fits. Both gates matter: the first is the
         adapter's judgement about its own file, the second is arithmetic. */
      if (current.qr) {
        var drawn = VPN55_QR.draw(text, { label: t('portal.qr.label') });
        if (drawn) {
          wrap.appendChild(el('div', { class: 'qr' }, [drawn.svg]));
          wrap.appendChild(el('p', { class: 'small muted', text: t('portal.qr.help') }));
        } else {
          wrap.appendChild(el('p', { class: 'small muted', text: t('portal.qr.toobig') }));
        }
      }

      wrap.appendChild(el('div', { class: 'actions' }, [
        el('button', {
          type: 'button', class: 'btn', text: t('portal.copy'),
          on: {
            click: function () {
              if (!navigator.clipboard) { flash('error', t('portal.copy.failed')); return; }
              navigator.clipboard.writeText(text).then(
                function () { flash('ok', t('portal.copy.done')); },
                function () { flash('error', t('portal.copy.failed')); });
            }
          }
        }),
        saveButton(current)
      ]));
    } else {
      /* Not text: there is nothing useful to show on screen and nothing a
         camera could read, so the only honest control is the download. */
      wrap.appendChild(el('p', { class: 'small muted', text: t('portal.binary') }));
      wrap.appendChild(el('div', { class: 'actions' }, [saveButton(current)]));
    }

    if (currentKey) {
      wrap.appendChild(el('button', {
        type: 'button', class: 'btn', text: t('portal.close'),
        on: {
          click: function () {
            delete state.open[cred.id];
            /* The bytes are dropped from memory too, not just hidden. There is
               a private key in some of them and the page may stay open on a
               phone for hours. */
            Object.keys(state.configs).forEach(function (k) {
              if (k.indexOf(cred.id + '\u0000') === 0) delete state.configs[k];
            });
            render();
          }
        }
      }));
    }
    return wrap;
  }

  function saveButton(current) {
    return el('button', {
      type: 'button', class: 'btn btn--primary', text: t('portal.save'),
      on: {
        click: function () {
          var bytes = decodeBytes(current.bodyBase64);
          var blob = new Blob([bytes], { type: 'application/octet-stream' });
          var url = URL.createObjectURL(blob);
          var a = el('a', { href: url, download: current.filename || 'vpn55.conf' });
          document.body.appendChild(a);
          a.click();
          a.remove();
          /* Revoked on a timer rather than immediately: a browser that has not
             finished reading the blob when the URL is revoked saves nothing and
             reports nothing. */
          setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
        }
      }
    });
  }

  /* ── Rotation ──────────────────────────────────────────────────────────── */

  function rotate(cred) {
    confirmAction(t('portal.rotate.confirm', { service: cred.serviceLabel }), { danger: true })
      .then(function (go) {
        if (!go) return null;
        return request('POST', '/api/portal/creds/' + encodeURIComponent(cred.id) + '/rotate')
          .then(function (data) {
            /* Two outcomes, and they are genuinely different. `revoked` false
               means the new credential exists and the OLD ONE STILL WORKS —
               which is a state an operator needs to know about, and reporting
               it as a clean success would be the same class of untruth as a
               revocation reported before it has taken effect. */
            if (data.revoked) flash('ok', t('portal.rotate.done'));
            else flash('error', t('portal.rotate.partial'));
            Object.keys(state.configs).forEach(function (k) { delete state.configs[k]; });
            state.open = Object.create(null);
            return load();
          }, function (err) {
            flash('error', tOr(err.error, 'portal.failed', {
              minutes: err.retryAfterSeconds
                ? Math.max(1, Math.ceil(err.retryAfterSeconds / 60)) : 0
            }));
          });
      });
  }

  /* ── The frame ─────────────────────────────────────────────────────────── */

  function topBar() {
    var bar = el('header', { class: 'pbar' }, [
      el('span', { class: 'pbar__title', text: t('portal.title') })
    ]);
    if (state.user) bar.appendChild(el('span', { class: 'pbar__who', text: state.user }));

    var controls = el('div', { class: 'pbar__controls' });

    VPN55_I18N.available().forEach(function (code) {
      if (code === VPN55_I18N.current()) return;
      controls.appendChild(el('button', {
        type: 'button', class: 'chip', text: t('locale.name.' + code),
        on: { click: function () { VPN55_I18N.switchTo(code, function () { render(); }); } }
      }));
    });

    controls.appendChild(el('button', {
      type: 'button', class: 'chip',
      text: t('theme.next', { name: t('theme.' + vpn55NextTheme()) }),
      on: { click: function () { vpn55SetTheme(vpn55NextTheme()); render(); } }
    }));

    if (state.user) {
      controls.appendChild(el('button', {
        type: 'button', class: 'chip', text: t('portal.signout'),
        on: {
          click: function () {
            request('DELETE', '/api/portal/session').then(function () {
              state.user = null;
              state.csrf = null;
              state.account = null;
              state.configs = Object.create(null);
              render();
            });
          }
        }
      }));
    }

    bar.appendChild(controls);
    return bar;
  }

  function render() {
    if (!root) {
      root = el('div', { class: 'portal' });
      document.body.appendChild(root);
    }
    clear(root);
    document.title = t('portal.title');
    VPN55_I18N.apply(document);

    root.appendChild(topBar());

    if (!state.known) {
      root.appendChild(el('p', { class: 'muted', text: t('app.loading') }));
      return;
    }
    if (!state.user) {
      root.appendChild(renderSignIn());
      return;
    }
    if (!state.account) {
      root.appendChild(el('p', { class: 'muted', text: t('app.loading') }));
      return;
    }

    /* Stale data says so. The figures below come from the last successful read
       of the services; when that read is failing, a page that simply kept
       showing them would be presenting a guess as a fact. */
    var health = state.account.health;
    if (health && health.consecutiveFailures > 0) {
      root.appendChild(el('div', { class: 'banner banner--warn' }, [
        el('strong', { text: t('portal.stale.title') }),
        document.createTextNode(t('portal.stale.body'))
      ]));
    }

    root.appendChild(accountCard(state.account));

    var creds = state.account.credentials;
    if (!creds.length) {
      root.appendChild(el('div', { class: 'card' }, [
        el('h2', { class: 'card__title', text: t('portal.nocreds.title') }),
        el('p', { class: 'muted small', text: t('portal.nocreds.body') })
      ]));
      return;
    }
    creds.forEach(function (c) { root.appendChild(credentialCard(c)); });
  }

  /* ── Loading ───────────────────────────────────────────────────────────── */

  function load() {
    return request('GET', '/api/portal/me').then(function (data) {
      state.account = data;
      state.known = true;
      render();
      return data;
    }, function (err) {
      state.known = true;
      state.account = null;
      if (err.status !== 401) state.error = err.error;
      render();
      throw err;
    });
  }

  /**
   * The idle heartbeat.
   *
   * Bound to real gestures and throttled to once a minute — never on a timer,
   * and never by the poll below. If a poll refreshed the idle clock, a phone
   * left face-up on a table would hold a session open until the absolute cap
   * and the idle timeout would be decorative.
   */
  var lastTouch = 0;
  function touch() {
    if (!state.user || !state.csrf) return;
    var now = Date.now();
    if (now - lastTouch < 60000) return;
    lastTouch = now;
    request('POST', '/api/portal/session/touch').catch(function () { /* the next
      request will find the session gone and show the form */ });
  }

  function start() {
    ['keydown', 'pointerdown'].forEach(function (evt) {
      document.addEventListener(evt, touch, { passive: true });
    });

    render();

    var code = readCodeFromFragment();
    if (code) stripFragment();

    /* Ask whether there is already a session BEFORE spending a code on a new
       one: somebody who reopens their link an hour later should land on their
       page rather than burning a redemption and a rate-limit slot. */
    request('GET', '/api/portal/session').then(function (data) {
      state.user = data.user;
      state.csrf = data.csrf;
      state.known = true;
      return load();
    }, function () {
      state.known = true;
      if (!code) { render(); return null; }
      return signIn(code).catch(function (err) {
        render();
        flash('error', tOr(err.error, 'portal.failed', {
          minutes: err.retryAfterSeconds
            ? Math.max(1, Math.ceil(err.retryAfterSeconds / 60)) : 0
        }));
      });
    }).catch(function () { render(); });

    timer = setInterval(function () {
      if (!state.user) return;
      load().catch(function () { /* rendered already */ });
    }, POLL_MS);
    if (timer && timer.unref) timer.unref();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
}());
