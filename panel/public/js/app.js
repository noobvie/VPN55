'use strict';
/*
 * panel/public/js/app.js — the admin views.
 *
 * Four of them: what each service is doing, who the users are and what they have
 * used, what is connected right now, and what has changed recently.
 *
 * Phase 6 added the controls that change something. They are thin on purpose:
 * every one of them hands a spec to VPN55_ACTIONS, which owns the session, the
 * CSRF token, the confirmation and the reporting. This file decides WHERE a
 * control belongs and what it is called; it does not know how to talk to the
 * host, and it holds no credential of any kind.
 *
 * ── Three rules this file is built around ────────────────────────────────────
 *
 * 1. NO STRING IS WRITTEN HERE. Every visible word comes from t(). The two
 *    deliberate exceptions are text an ADAPTER wrote — a note, and a filtering
 *    explanation — which are rendered as quoted data, attributed to the service,
 *    because this side cannot translate a sentence it did not author without
 *    first learning which protocol wrote it, and that is the one thing it may
 *    not do.
 *
 * 2. NO innerHTML, ANYWHERE. Every node is created and every string goes in as
 *    a text node. A user name, a credential id and an adapter's note are all
 *    values from the host, and the host is exactly where an attacker who got
 *    that far would put a payload. There is a CSP that would stop an injected
 *    <script> from running, but the CSP is the second line, not the first.
 *
 * 3. THE PROTOCOL IS NEVER NAMED. This file renders whatever the adapters
 *    declare — tags, labels, states, filtering levels. There is no list of
 *    services here, no branch on which one it is, and no icon keyed to one. If
 *    a fourth is added, this file does not change.
 *
 * ── Why it re-renders wholesale ──────────────────────────────────────────────
 * Every poll replaces the view's nodes. It is a handful of tables at a human
 * poll interval, so the cost is nothing, and the alternative — patching rows in
 * place — is where a stale cell survives a refresh and shows a number that is no
 * longer true. Scroll position and the open view are preserved explicitly.
 */

(function () {
  var t = VPN55_I18N.t;
  var tOr = VPN55_I18N.tOr;
  var F = VPN55_FMT;
  var A = VPN55_ACTIONS;

  /* Whether to draw the controls that change something.
   *
   * They are hidden, not disabled, when there is no session: a disabled button
   * invites someone to work out why it is disabled, and the answer here is
   * always "you are not signed in", which the sign-in form in front of them
   * already says. */
  function canWrite() {
    return A.session.authenticated || A.session.unauthenticatedMode;
  }

  var VIEWS = ['services', 'users', 'connections', 'events'];
  var state = {
    view: 'services',
    data: null,
    error: null,
    loading: false,
    now: Math.floor(Date.now() / 1000),
  };

  /* ── Tiny DOM helpers ────────────────────────────────────────────────────
   * `el` takes text, never markup. That is the whole point of it. */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === 'class') node.className = v;
        else if (k === 'text') node.appendChild(document.createTextNode(String(v)));
        else node.setAttribute(k, String(v));
      });
    }
    (children || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* A cell whose value may be absent. Absent renders as an em dash with a
   * tooltip saying what absent means here — not as an empty cell, which reads
   * as a value of zero or as a layout bug. */
  function cell(value, title) {
    var td = el('td', { text: value === null ? F.DASH : value });
    if (value === null) {
      td.className = 'is-unset';
      td.setAttribute('title', title || t('value.noreading.help'));
    } else if (title) {
      td.setAttribute('title', title);
    }
    return td;
  }

  function badge(kind, label, title) {
    return el('span', { class: 'badge badge--' + kind, text: label, title: title || null });
  }

  /* ── Service state, filtering level: adapter words, translated if known ────
   * The adapter's own word is the fallback. A state or level this build has
   * never heard of renders as that word rather than as a blank or as "unknown" —
   * a new answer should look like a new answer. */
  function serviceStateLabel(stateWord) {
    return tOr('service.state.' + stateWord, 'service.state.other', { state: stateWord });
  }

  function stateKind(stateWord) {
    if (stateWord === 'running') return 'ok';
    if (stateWord === 'stopped') return 'warn';
    if (stateWord === 'absent') return 'idle';
    return 'unknown';
  }

  function filteringKind(level) {
    if (level === 'resistant') return 'ok';
    if (level === 'partial') return 'warn';
    if (level === 'exposed') return 'crit';
    return 'unknown';
  }

  /* ══════════════════════════════════════════════════════════════════════════
     VIEW 1 — Services
     ══════════════════════════════════════════════════════════════════════════ */
  function renderServices(data) {
    var wrap = el('div', { class: 'stack' });

    if (!data.services.length) {
      wrap.appendChild(emptyNote(t('services.none')));
      return wrap;
    }

    data.services.forEach(function (s) {
      var card = el('section', { class: 'card' });

      card.appendChild(el('header', { class: 'card__head' }, [
        el('h2', { class: 'card__title', text: s.label }),
        badge(stateKind(s.state), serviceStateLabel(s.state)),
        s.available === false
          ? badge('crit', t('service.unavailable'), t('service.unavailable.help'))
          : null,
        s.enabled === false
          ? badge('warn', t('service.boot.disabled'), t('service.boot.disabled.help'))
          : null,
      ]));

      var dl = el('dl', { class: 'facts' });
      fact(dl, t('service.listen'), s.listen === null ? null : s.listen);
      fact(dl, t('service.since'),
        s.since === null ? null : F.duration(data.generatedAt - s.since),
        s.since === null ? null : F.absolute(s.since));
      fact(dl, t('service.creds'), F.numeric(s.credCount));
      card.appendChild(dl);

      /* ── The filtering disclosure ──────────────────────────────────────────
       * The one thing on this page that answers "will this still work on a
       * network that is filtering?". The LEVEL is the adapter's stable word and
       * gets a translated label; the SENTENCE is the adapter's own and is shown
       * as its words, attributed. See docs/circumvention.md §10. */
      if (s.filtering) {
        var f = el('div', { class: 'disclosure disclosure--' + filteringKind(s.filtering.level) });
        f.appendChild(el('span', { class: 'disclosure__label', text: t('filtering.label') }));
        f.appendChild(badge(
          filteringKind(s.filtering.level),
          tOr('filtering.level.' + s.filtering.level, 'filtering.level.other',
              { level: s.filtering.level })));
        if (!s.filtering.levelKnown) {
          f.appendChild(el('p', { class: 'disclosure__warn', text: t('filtering.level.unrecognised') }));
        }
        if (s.filtering.explanation) f.appendChild(fromService(s.filtering.explanation));
        card.appendChild(f);
      }

      if (s.custody) {
        var c = el('div', { class: 'disclosure disclosure--info' });
        c.appendChild(el('span', { class: 'disclosure__label', text: t('custody.label') }));
        c.appendChild(el('span', {
          text: tOr('custody.who.' + s.custody.who, 'custody.who.other', { who: s.custody.who }),
        }));
        if (s.custody.disclosure) c.appendChild(fromService(s.custody.disclosure));
        card.appendChild(c);
      }

      if (s.revoke) {
        var r = el('div', { class: 'disclosure disclosure--info' });
        r.appendChild(el('span', { class: 'disclosure__label', text: t('revoke.label') }));
        r.appendChild(el('span', {
          text: tOr('revoke.latency.' + s.revoke.latency, 'revoke.latency.other',
                    { latency: s.revoke.latency }),
        }));
        // Three cases, and only one of them is a duration:
        //   -1  → no bound at all. Not a duration, and must never be shown as
        //         one; it gets its own sentence.
        //    0  → the withdrawal IS the effect. The latency label above already
        //         says "takes effect at once", so a second line reading "at
        //         worst 0m before it takes effect" adds nothing and reads as
        //         though there were a delay of some kind. Nothing is appended.
        //   >0  → a real bound, shown as a duration.
        var worstCase = null;
        if (s.revoke.unbounded) worstCase = t('revoke.unbounded');
        else if (s.revoke.worstCaseSeconds === null) worstCase = t('value.unknown');
        else if (s.revoke.worstCaseSeconds > 0) {
          worstCase = t('revoke.worstcase', { duration: F.duration(s.revoke.worstCaseSeconds) });
        }
        if (worstCase) r.appendChild(el('span', { class: 'muted', text: worstCase }));
        card.appendChild(r);
      }

      if (s.restart) {
        var rs = el('div', { class: 'disclosure disclosure--info' });
        rs.appendChild(el('span', { class: 'disclosure__label', text: t('restart.label') }));
        rs.appendChild(el('span', {
          text: tOr('restart.effect.' + s.restart.effect, 'restart.effect.other',
                    { effect: s.restart.effect }),
        }));
        if (s.restart.explanation) rs.appendChild(fromService(s.restart.explanation));
        card.appendChild(rs);
      }

      /* ── Restart ───────────────────────────────────────────────────────────
       * The confirmation text is the ADAPTER's own sentence about what a restart
       * costs the people connected right now — the `restart` capability record
       * rendered just above. Shown BEFORE the operator confirms, because the
       * disruption is the thing they are deciding about. That ordering is the
       * lesson the revocation notice already learned the hard way. */
      if (canWrite() && s.state !== 'absent') {
        var restartConfirm = s.restart && s.restart.explanation
          ? s.restart.explanation
          : tOr('restart.effect.' + (s.restart ? s.restart.effect : 'unknown'),
                'restart.effect.other', { effect: s.restart ? s.restart.effect : '' });

        card.appendChild(el('div', { class: 'card__actions' }, [
          A.button(t('service.restart'), {
            method: 'POST',
            path: '/api/admin/services/' + encodeURIComponent(s.tag) + '/restart',
            confirm: restartConfirm,
            confirmLabel: t('service.restart'),
            ok: function () { return t('service.restart.done', { service: s.label }); },
          }),
        ]));
      }

      (s.notes || []).forEach(function (n) {
        var note = el('div', { class: 'note note--' + n.severity });
        note.appendChild(badge(n.severity === 'crit' ? 'crit' : n.severity === 'warn' ? 'warn' : 'idle',
          tOr('note.severity.' + n.severity, 'note.severity.other', { severity: n.severity })));
        if (!n.severityKnown) {
          note.appendChild(el('span', { class: 'muted', text: t('note.severity.unrecognised') }));
        }
        note.appendChild(fromService(n.message));
        card.appendChild(note);
      });

      wrap.appendChild(card);
    });

    return wrap;
  }

  function fact(dl, label, value, title) {
    dl.appendChild(el('dt', { text: label }));
    var dd = el('dd', { text: value === null || value === undefined ? F.DASH : value });
    if (value === null || value === undefined) {
      dd.className = 'is-unset';
      dd.setAttribute('title', t('value.noreading.help'));
    } else if (title) {
      dd.setAttribute('title', title);
    }
    dl.appendChild(dd);
  }

  /*
   * Text an adapter wrote, shown as its words and labelled as such.
   *
   * It is NOT translated and cannot be: translating it would mean this side
   * knowing which protocol produced it. Marking it visually is the honest
   * alternative — the reader can see that this sentence came from the service
   * and is the one thing on the page that will be in English on a Vietnamese
   * install, rather than wondering why one line did not translate.
   */
  function fromService(message) {
    var p = el('p', { class: 'from-service', title: t('fromservice.help') });
    p.appendChild(el('span', { class: 'from-service__mark', text: t('fromservice.label'), 'aria-hidden': 'true' }));
    p.appendChild(document.createTextNode(message));
    return p;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     VIEW 2 — Users
     ══════════════════════════════════════════════════════════════════════════ */
  function renderUsers(data) {
    var wrap = el('div', { class: 'stack' });

    if (!data.users.length) {
      wrap.appendChild(emptyNote(t('users.none')));
    } else {
      var table = el('table', { class: 'grid' });
      var userCols = [
        t('users.col.name'), t('users.col.state'), t('users.col.creds'),
        t('users.col.down'), t('users.col.up'), t('users.col.total'),
        t('users.col.quota'), t('users.col.expires'), t('users.col.lastseen'),
      ];
      if (canWrite()) userCols.push('');
      table.appendChild(headRow(userCols));

      var tbody = el('tbody');
      data.users.forEach(function (u) {
        var tr = el('tr');
        tr.appendChild(el('td', {}, [el('span', { class: 'ident', text: u.name })]));

        var flags = el('td');
        flags.appendChild(u.enabled === false
          ? badge('warn', t('user.disabled'), t('user.disabled.help'))
          : badge('ok', t('user.enabled')));
        if (u.expired === true) flags.appendChild(badge('crit', t('user.expired')));
        if (u.expired === null) flags.appendChild(badge('unknown', t('user.expiry.unparseable')));
        tr.appendChild(flags);

        tr.appendChild(cell(F.numeric(u.credentials) +
          (u.reportedCredentials ? ' (' + F.numeric(u.reportedCredentials) + ')' : ''),
          t('users.col.creds.help')));
        tr.appendChild(cell(F.bytes(u.rxTotal)));
        tr.appendChild(cell(F.bytes(u.txTotal)));
        tr.appendChild(cell(F.bytes(u.total)));

        // Unlimited is not 100% and not 0% — it is the absence of a limit, and
        // it says so.
        if (u.quotaBytes === null) {
          tr.appendChild(cell(t('quota.unlimited'), t('quota.unlimited.help')));
        } else {
          var td = el('td');
          td.appendChild(el('span', { text: F.percent(u.quotaUsedFraction) }));
          td.appendChild(el('span', {
            class: 'muted', text: ' / ' + F.bytes(u.quotaBytes),
          }));
          if (u.quotaUsedFraction !== null && u.quotaUsedFraction >= 1) {
            td.appendChild(badge('crit', t('quota.over')));
          }
          tr.appendChild(td);
        }

        tr.appendChild(cell(u.expiresAt === null ? t('expiry.never') : F.isoDate(u.expiresAt),
          u.expiresAt === null ? t('expiry.never.help') : null));

        var seen = F.handshake(u.lastSeen, data.generatedAt);
        tr.appendChild(cell(seen.text, seen.title));

        if (canWrite()) tr.appendChild(userActions(u, data));

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      wrap.appendChild(table);
    }

    if (canWrite()) wrap.appendChild(addUserCard(data));

    /* ── Orphans ──────────────────────────────────────────────────────────────
     * A credential the services are serving whose user is not in the registry.
     * This is precisely the drift the architecture exists to prevent, so it is
     * shown loudly rather than dropped from a list where nobody would miss it. */
    if (data.orphanCredentials && data.orphanCredentials.length) {
      var card = el('section', { class: 'card card--alert' });
      card.appendChild(el('h2', { class: 'card__title', text: t('orphans.title') }));
      card.appendChild(el('p', { text: t('orphans.explain') }));
      var ot = el('table', { class: 'grid' });
      ot.appendChild(headRow([t('orphans.col.service'), t('orphans.col.cred'), t('orphans.col.user')]));
      var ob = el('tbody');
      data.orphanCredentials.forEach(function (c) {
        ob.appendChild(el('tr', {}, [
          el('td', { text: c.serviceLabel }),
          el('td', {}, [el('span', { class: 'ident', text: c.id })]),
          cell(c.user, c.user === null ? t('orphans.nouser.help') : null),
        ]));
      });
      ot.appendChild(ob);
      card.appendChild(ot);
      wrap.appendChild(card);
    }

    return wrap;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     VIEW 3 — Connections
     ══════════════════════════════════════════════════════════════════════════ */
  function renderConnections(data) {
    var wrap = el('div', { class: 'stack' });

    wrap.appendChild(el('p', { class: 'muted', text: t('connections.explain') }));

    if (!data.connections.length) {
      wrap.appendChild(emptyNote(t('connections.none')));
      return wrap;
    }

    var table = el('table', { class: 'grid' });
    var connCols = [
      t('conn.col.service'), t('conn.col.user'), t('conn.col.cred'),
      t('conn.col.address'), t('conn.col.endpoint'),
      t('conn.col.session'), t('conn.col.total'), t('conn.col.handshake'),
    ];
    if (canWrite()) connCols.push('');
    table.appendChild(headRow(connCols));

    var tbody = el('tbody');
    data.connections.forEach(function (c) {
      var tr = el('tr');
      tr.appendChild(el('td', { text: c.serviceLabel }));
      tr.appendChild(cell(c.user, c.user === null ? t('orphans.nouser.help') : null));
      tr.appendChild(el('td', {}, [el('span', { class: 'ident', text: c.id })]));
      tr.appendChild(cell(c.address));

      // The endpoint is the remote address of a person. It is shown because an
      // operator diagnosing a connection needs it, and it is marked as personal
      // data because it is: see docs/security-model.md on what the panel keeps.
      tr.appendChild(cell(c.endpoint, t('conn.col.endpoint.help')));

      // Session counters versus accumulated totals, side by side and never
      // confused: the left pair resets under you, the right pair does not.
      var session = el('td', { class: 'pair' });
      session.appendChild(el('span', { text: F.bytes(c.rx), class: c.rx === null ? 'is-unset' : null }));
      session.appendChild(el('span', { class: 'muted', text: ' / ' }));
      session.appendChild(el('span', { text: F.bytes(c.tx), class: c.tx === null ? 'is-unset' : null }));
      session.setAttribute('title', t('conn.col.session.help'));
      tr.appendChild(session);

      var total = el('td', { class: 'pair' });
      total.appendChild(el('span', { text: F.bytes(c.rxTotal) }));
      total.appendChild(el('span', { class: 'muted', text: ' / ' }));
      total.appendChild(el('span', { text: F.bytes(c.txTotal) }));
      if (c.resets) {
        total.appendChild(badge('idle', t('conn.resets', { count: F.numeric(c.resets) }),
                                t('conn.resets.help')));
      }
      total.setAttribute('title', t('conn.col.total.help'));
      tr.appendChild(total);

      var hs = F.handshake(c.handshake, data.generatedAt);
      tr.appendChild(cell(hs.text, hs.title));

      if (canWrite()) {
        tr.appendChild(el('td', { class: 'actions' }, [revokeButton(c.id, c.tag)]));
      }

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     VIEW 4 — Events
     ══════════════════════════════════════════════════════════════════════════
     Events are stored as a TYPE plus structured data, never as a rendered
     sentence — so the sentence is built here, in the language the reader chose,
     and an event recorded a month ago in Vietnamese reads in French today. */
  function renderEvents(data) {
    var wrap = el('div', { class: 'stack' });
    if (!data.events || !data.events.length) {
      wrap.appendChild(emptyNote(t('events.none')));
      return wrap;
    }

    var list = el('ol', { class: 'events' });
    data.events.forEach(function (e) {
      var li = el('li', { class: 'event' });
      li.appendChild(el('time', {
        class: 'event__when',
        datetime: new Date(e.at * 1000).toISOString(),
        title: F.absolute(e.at),
        text: F.relative(e.at, data.generatedAt),
      }));
      li.appendChild(el('span', { class: 'event__type', text: eventLabel(e) }));
      var detail = eventDetail(e);
      if (detail) li.appendChild(detail);
      list.appendChild(li);
    });
    wrap.appendChild(list);
    return wrap;
  }

  function eventLabel(e) {
    var d = e.data || {};
    // Every known type has a key; an unknown one falls back to a sentence that
    // says a new kind of event arrived, showing its type verbatim. A build older
    // than the thing writing its events should say so, not draw a blank row.
    return tOr('event.' + e.type, 'event.other', {
      type: e.type,
      user: d.user || F.DASH,
      cred: d.credId || F.DASH,
      service: d.tag || F.DASH,
      from: d.from ? serviceStateLabel(d.from) : F.DASH,
      to: d.to ? serviceStateLabel(d.to) : F.DASH,
      count: d.count === undefined ? F.DASH : F.numeric(d.count),
      kind: d.kind || F.DASH,
      carried: d.carried === undefined ? F.DASH : F.bytes(d.carried),
      failures: d.afterFailures === undefined ? F.DASH : F.numeric(d.afterFailures),
      severity: d.severity || F.DASH,
    });
  }

  function eventDetail(e) {
    // A note's message is adapter-authored text and is the only event content
    // shown verbatim.
    if (e.type === 'note.raised' && e.data && e.data.message) return fromService(e.data.message);
    return null;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     Chrome — header, tabs, staleness banner
     ══════════════════════════════════════════════════════════════════════════ */
  function headRow(labels) {
    var thead = el('thead');
    var tr = el('tr');
    labels.forEach(function (l) { tr.appendChild(el('th', { scope: 'col', text: l })); });
    thead.appendChild(tr);
    return thead;
  }

  function emptyNote(message) {
    return el('p', { class: 'empty', text: message });
  }

  /*
   * The staleness banner. A panel showing old numbers without saying they are
   * old is worse than one showing nothing: every number on the page still looks
   * current, and someone acts on it. So the moment a read fails, the page says
   * when the data is from and why it stopped.
   */
  function renderHealth(data) {
    var h = data.health || {};
    if (!h.consecutiveFailures) return null;

    var box = el('div', { class: 'banner banner--crit', role: 'alert' });
    box.appendChild(el('strong', { text: t('health.stale.title') }));
    box.appendChild(el('p', {
      text: h.lastSuccessAt
        ? t('health.stale.body', {
            when: F.relative(h.lastSuccessAt, data.generatedAt),
            failures: F.numeric(h.consecutiveFailures),
          })
        : t('health.never.body', { failures: F.numeric(h.consecutiveFailures) }),
    }));
    if (h.error) {
      box.appendChild(el('p', {
        class: 'banner__why',
        text: tOr('health.kind.' + h.error.kind, 'health.kind.other', { kind: h.error.kind }),
      }));
      // The underlying message is operator-facing diagnostic text from this
      // process, not a translated string — shown so the reason is not a guess.
      box.appendChild(el('pre', { class: 'diag', text: h.error.message }));
    }
    return box;
  }

  function renderNav() {
    var nav = el('nav', { class: 'tabs', role: 'tablist' });
    VIEWS.forEach(function (name) {
      // Vendored class names: .tabs / .tab-btn / .active are the pinned theme's
      // own, including the treatment each of the four themes gives them. Reusing
      // them is the point of vendoring; re-implementing a tab strip beside one
      // that already exists is how the admin UI stops matching itself.
      var b = el('button', {
        class: 'tab-btn' + (state.view === name ? ' active' : ''),
        type: 'button',
        role: 'tab',
        'aria-selected': state.view === name ? 'true' : 'false',
        text: t('view.' + name),
      });
      b.addEventListener('click', function () {
        state.view = name;
        try { location.hash = name; } catch (err) { /* no history: not fatal */ }
        render();
      });
      nav.appendChild(b);
    });
    return nav;
  }

  function renderTopBar(data) {
    var bar = el('div', { class: 'topbar' });

    bar.appendChild(el('h1', { class: 'topbar__title', text: t('app.title') }));

    var meta = el('div', { class: 'topbar__meta' });
    if (data) {
      meta.appendChild(el('span', {
        class: 'muted',
        title: F.absolute(data.stamp || data.generatedAt),
        text: t('app.updated', { when: F.relative(data.stamp || data.generatedAt, state.now) }),
      }));
      meta.appendChild(el('span', {
        class: 'muted',
        text: t('app.counts', {
          services: F.numeric(data.counts.services),
          users: F.numeric(data.counts.users),
          reported: F.numeric(data.counts.reported),
        }),
      }));
    }
    bar.appendChild(meta);

    var controls = el('div', { class: 'topbar__controls' });

    if (A.session.unauthenticatedMode) {
      // Not a decoration. The panel is running with sign-in switched off, which
      // means every control on this page is available to anyone who can reach
      // the address, and that is worth saying on every screen rather than once
      // in a log nobody is reading.
      controls.appendChild(badge('crit', t('auth.off.title'), t('auth.off.body')));
    } else if (A.session.authenticated) {
      controls.appendChild(el('span', {
        class: 'muted', text: t('auth.signedin', { user: A.session.user }),
      }));
      var out = el('button', { type: 'button', class: 'chip', text: t('auth.signout') });
      out.addEventListener('click', function () {
        A.signOut().then(render, render);
      });
      controls.appendChild(out);
    }

    // Locale switcher. Each language is named in ITSELF — a Vietnamese speaker
    // looking for their language is looking for "Tiếng Việt", not for whatever
    // the current interface language calls it.
    VPN55_I18N.available().forEach(function (code) {
      var b = el('button', {
        type: 'button',
        class: 'chip' + (VPN55_I18N.current() === code ? ' chip--on' : ''),
        lang: code,
        text: t('locale.name.' + code),
        'aria-pressed': VPN55_I18N.current() === code ? 'true' : 'false',
      });
      b.addEventListener('click', function () {
        VPN55_I18N.switchTo(code, function () {
          document.title = t('app.title');
          render();
        });
      });
      controls.appendChild(b);
    });

    var themeBtn = el('button', {
      type: 'button',
      class: 'chip',
      text: t('theme.' + vpn55CurrentTheme()),
      title: t('theme.next', { name: t('theme.' + vpn55NextTheme()) }),
    });
    themeBtn.addEventListener('click', function () {
      vpn55SetTheme(vpn55NextTheme());
      render();
    });
    controls.appendChild(themeBtn);

    bar.appendChild(controls);
    return bar;
  }

  /* Stated once, plainly, at the bottom of every view: the server's own
     configuration is the source of truth, and everything here was read from it.
     Phase 5 also said the build could change nothing; that sentence went when
     that stopped being true, rather than staying on as a reassuring untruth. */
  function renderFooter() {
    var f = el('footer', { class: 'footer' });
    f.appendChild(el('p', { class: 'muted', text: t('app.source') }));
    f.appendChild(el('p', { class: 'muted', text: t('audit.second_log') }));
    return f;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     The write controls
     ══════════════════════════════════════════════════════════════════════════
     Each one builds a spec and hands it to VPN55_ACTIONS. The wording of a
     confirmation is here because it is a UI decision; the confirming, calling
     and reporting are not. */

  function revokeButton(credId, serviceTag) {
    return A.button(t('cred.revoke'), {
      method: 'DELETE',
      path: '/api/admin/creds/' + encodeURIComponent(credId) +
            (serviceTag ? '?service=' + encodeURIComponent(serviceTag) : ''),
      // Irreversible, and the wording says which part is irreversible rather
      // than asking "are you sure?" — which is a question nobody answers no to.
      confirm: t('cred.revoke.confirm', { cred: credId }),
      confirmLabel: t('cred.revoke'),
      danger: true,
      ok: function (data) {
        // The adapter reported what it ACTUALLY achieved. An adapter that ended
        // the live session says so and is believed; over-warning on the days it
        // is instant is how an operator learns to ignore the warning on the day
        // it is not.
        var latency = data && data.detail ? data.detail.latency : null;
        return latency === 'immediate'
          ? t('cred.revoke.done.immediate', { cred: credId })
          : t('cred.revoke.done.delayed', { cred: credId });
      },
    }, 'btn--danger');
  }

  function userActions(u, data) {
    var td = el('td', { class: 'actions' });

    if (u.enabled === false) {
      td.appendChild(A.button(t('user.enable'), {
        method: 'POST',
        path: '/api/admin/users/' + encodeURIComponent(u.name) + '/enable',
        ok: function () { return t('user.enable.done', { name: u.name }); },
      }));
    } else {
      td.appendChild(A.button(t('user.disable'), {
        method: 'POST',
        path: '/api/admin/users/' + encodeURIComponent(u.name) + '/disable',
        ok: function (res) {
          // The helper counted the credentials that are still carrying traffic.
          // Disabling is a policy flag and does not end a tunnel already up, so
          // a plain "disabled" here would read as "access cut" — the same class
          // of untruth as a revocation reported before it has taken effect.
          var still = res && res.detail
            ? parseInt(res.detail.active_credentials, 10) : 0;
          return still > 0
            ? t('user.disable.partial', { name: u.name, count: F.numeric(still) })
            : t('user.disable.done', { name: u.name });
        },
      }));
    }

    td.appendChild(issueButton(u, data));
    td.appendChild(portalCodeButton(u));

    td.appendChild(A.button(t('user.remove'), {
      method: 'DELETE',
      path: '/api/admin/users/' + encodeURIComponent(u.name),
      confirm: t('user.remove.confirm', { name: u.name }),
      confirmLabel: t('user.remove'),
      danger: true,
      ok: function () { return t('user.remove.done', { name: u.name }); },
    }, 'btn--danger'));

    return td;
  }

  /* ── Portal access codes ──────────────────────────────────────────────────
   *
   * The operator's half of Phase 8: hand somebody a code so they can fetch
   * their own configuration without asking for it.
   *
   * This is NOT a privileged call and it does not go through the root helper —
   * it writes one line into the panel's own state directory. It lives here
   * because issuing somebody access is an operator's action; nothing on the
   * portal's own socket can reach these routes, because that is a different
   * express application and they are not registered on it.
   *
   * ⚠ THE CODE IS SHOWN ONCE. Only a SHA-256 of it is stored, so this dialog is
   * the one and only time it exists anywhere — which is why it is a panel the
   * operator closes deliberately rather than a flash that disappears on a timer.
   */
  function portalCodeButton(u) {
    var b = el('button', { type: 'button', class: 'btn btn--row', text: t('portal.token.title') });
    b.addEventListener('click', function () { openPortalCodes(u); });
    return b;
  }

  function openPortalCodes(u) {
    var host = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' });
    var body = el('div', { class: 'modal__box' });
    var list = el('div');
    var problem = el('p', { class: 'signin__problem', role: 'alert' });

    function close() {
      document.removeEventListener('keydown', onKey, true);
      host.remove();
    }
    function onKey(ev) { if (ev.key === 'Escape') { ev.preventDefault(); close(); } }
    document.addEventListener('keydown', onKey, true);

    function refresh() {
      A.request('GET', '/api/admin/portal/tokens?user=' + encodeURIComponent(u.name))
        .then(function (res) {
          clear(list);
          if (!res.tokens || !res.tokens.length) {
            list.appendChild(emptyNote(t('portal.token.none')));
            return;
          }
          var table = el('table', { class: 'grid' });
          table.appendChild(headRow([
            t('portal.token.col.id'), t('portal.token.col.label'),
            t('portal.token.col.created'), t('portal.token.col.expires'),
            t('portal.token.col.lastused'), '',
          ]));
          var tbody = el('tbody');
          res.tokens.forEach(function (rec) {
            var row = el('tr');
            row.appendChild(cell(rec.id));
            row.appendChild(cell(rec.label || F.DASH, rec.label ? null : undefined));
            row.appendChild(cell(F.isoDate(rec.created)));
            row.appendChild(cell(rec.expiresAt ? F.isoDate(rec.expiresAt) : t('expiry.never')));
            row.appendChild(cell(rec.lastUsedAt ? F.relative(Date.parse(rec.lastUsedAt) / 1000)
                                                : t('value.never')));
            var actions = el('td', { class: 'actions' });
            if (rec.revokedAt) {
              actions.appendChild(badge('idle', t('audit.result.denied')));
            } else {
              var revoke = el('button', {
                type: 'button', class: 'btn btn--row btn--danger', text: t('portal.token.revoke'),
              });
              revoke.addEventListener('click', function () {
                A.confirm(t('portal.token.revoke.confirm'), { danger: true })
                  .then(function (go) {
                    if (!go) return null;
                    return A.request('DELETE', '/api/admin/portal/tokens/' + encodeURIComponent(rec.id))
                      .then(refresh, function (err) {
                        problem.textContent = tOr(err.error, 'action.failed');
                      });
                  });
              });
              actions.appendChild(revoke);
            }
            row.appendChild(actions);
            tbody.appendChild(row);
          });
          table.appendChild(tbody);
          list.appendChild(table);
        }, function (err) {
          clear(list);
          problem.textContent = tOr(err.error, 'action.failed');
        });
    }

    var label = el('input', { type: 'text', class: 'field', id: 'ptk-label', autocomplete: 'off' });
    var days = el('input', { type: 'text', class: 'field', id: 'ptk-days', inputmode: 'numeric', autocomplete: 'off' });
    var issue = el('button', { type: 'button', class: 'btn btn--primary', text: t('portal.token.issue') });

    issue.addEventListener('click', function () {
      problem.textContent = '';
      issue.disabled = true;
      A.request('POST', '/api/admin/portal/tokens', {
        user: u.name,
        label: label.value,
        days: days.value.trim(),
      }).then(function (res) {
        label.value = '';
        days.value = '';
        showCode(res.token);
        refresh();
      }, function (err) {
        problem.textContent = tOr(err.error, 'action.failed');
      }).then(function () { issue.disabled = false; });
    });

    /* The code itself. A read-only input rather than a text node, so it can be
       selected and copied on a phone even where the clipboard API is refused —
       and never innerHTML, because this string came from a server response. */
    function showCode(code) {
      var field = el('input', { type: 'text', class: 'field', readonly: 'readonly', value: code });
      var copy = el('button', { type: 'button', class: 'btn', text: t('portal.token.copy') });
      copy.addEventListener('click', function () {
        field.select();
        if (!navigator.clipboard) { A.flash('error', t('portal.copy.failed'), null); return; }
        navigator.clipboard.writeText(code).then(
          function () { A.flash('ok', t('portal.copy.done'), null); },
          function () { A.flash('error', t('portal.copy.failed'), null); });
      });
      body.insertBefore(el('div', { class: 'note note--warn' }, [
        el('p', { text: t('portal.token.once') }),
        field,
        el('div', { class: 'card__actions' }, [copy]),
      ]), problem);
      field.focus();
      field.select();
    }

    var done = el('button', { type: 'button', class: 'btn', text: t('action.cancel') });
    done.addEventListener('click', close);

    body.appendChild(el('h2', { class: 'card__title', text: t('portal.token.title') + ' — ' + u.name }));
    body.appendChild(el('div', { class: 'formrow' }, [
      el('label', { for: 'ptk-label', text: t('portal.token.label') }), label,
    ]));
    body.appendChild(el('div', { class: 'formrow' }, [
      el('label', { for: 'ptk-days', text: t('portal.token.days') }), days,
    ]));
    body.appendChild(el('div', { class: 'card__actions' }, [issue]));
    body.appendChild(problem);
    body.appendChild(list);
    body.appendChild(el('div', { class: 'modal__buttons' }, [done]));

    host.appendChild(body);
    document.body.appendChild(host);
    refresh();
  }

  /* Issuing a credential asks the ADAPTER what it needs.
   *
   * The options come from that service's own `option` capability records: this
   * file prompts for whatever comes back and knows what none of it means. That
   * is the whole reason the record exists — before it, the installer prompted
   * every service for a public key because one of them wanted one. */
  function issueButton(u, data) {
    var b = el('button', { type: 'button', class: 'btn btn--row', text: t('cred.issue') });
    b.addEventListener('click', function () { openIssueForm(u, data); });
    return b;
  }

  function openIssueForm(u, data) {
    var available = (data.services || []).filter(function (s) {
      return s.available !== false && s.state !== 'absent';
    });
    if (!available.length) {
      A.flash('error', t('services.none'), null);
      return;
    }

    var pick = el('select', { class: 'field' });
    available.forEach(function (s) {
      pick.appendChild(el('option', { value: s.tag, text: s.label }));
    });

    var optionHost = el('div', { class: 'stack' });
    var inputs = {};
    var custody = el('p', { class: 'muted' });

    function refreshOptions() {
      clear(optionHost);
      clear(custody);
      inputs = {};
      var s = available.filter(function (x) { return x.tag === pick.value; })[0];
      if (!s) return;

      /* Key custody is a disclosure, not a detail: whether the server has ever
       * held this person's private key is something they are entitled to know,
       * and the moment of issue is when the operator can still choose. The
       * sentence is the adapter's own. */
      if (s.custody && s.custody.disclosure) {
        custody.appendChild(document.createTextNode(s.custody.disclosure));
      }

      (s.options || []).forEach(function (o) {
        var id = 'issue-opt-' + o.key;
        var input = el('input', { type: 'text', id: id, class: 'field' });
        inputs[o.key] = { input: input, required: o.required === true };
        optionHost.appendChild(el('label', { for: id, text: o.prompt }));
        if (o.help) optionHost.appendChild(el('p', { class: 'muted', text: o.help }));
        optionHost.appendChild(input);
      });
    }

    pick.addEventListener('change', refreshOptions);
    refreshOptions();

    var problem = el('p', { class: 'signin__problem', role: 'alert' });
    var go = el('button', { type: 'submit', class: 'btn btn--primary', text: t('cred.issue') });
    var cancel = el('button', { type: 'button', class: 'btn', text: t('action.cancel') });

    var form = el('form', { class: 'signin__form', novalidate: 'novalidate' }, [
      el('h1', { class: 'signin__title', text: t('cred.issue') }),
      el('p', { class: 'muted', text: u.name }),
      pick,
      custody,
      optionHost,
      problem,
      el('div', { class: 'modal__buttons' }, [cancel, go]),
    ]);

    var box = el('div', { class: 'signin', role: 'dialog', 'aria-modal': 'true' }, [form]);
    function close() { box.remove(); }
    cancel.addEventListener('click', close);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      problem.textContent = '';

      var options = {};
      var missing = null;
      Object.keys(inputs).forEach(function (key) {
        var v = inputs[key].input.value.trim();
        if (!v && inputs[key].required) missing = key;
        if (v) options[key] = v;
      });
      if (missing) {
        // The adapter said this one is required, so refusing here saves a round
        // trip. The adapter refuses it too, and that is the check that counts.
        problem.textContent = t('action.failed');
        return;
      }

      go.disabled = true;
      go.textContent = t('action.working');
      A.act({
        method: 'POST',
        path: '/api/admin/creds',
        body: { user: u.name, service: pick.value, options: options },
        ok: function (res) {
          return t('cred.issue.done', {
            cred: (res && res.detail && res.detail.cred_id) || '',
          });
        },
      }).then(function (res) {
        if (res) close();
      }).catch(function () { /* reported by act */ })
        .then(function () {
          go.disabled = false;
          go.textContent = t('cred.issue');
        });
    });

    document.body.appendChild(box);
    pick.focus();
  }

  /* Adding a user. Every policy field is optional and blank means unlimited or
     never — which is why each one says so rather than defaulting to a number
     that would look like a decision somebody made. */
  function addUserCard() {
    var card = el('section', { class: 'card' });
    card.appendChild(el('h2', { class: 'card__title', text: t('user.add') }));

    var name = el('input', { type: 'text', id: 'add-name', class: 'field', autocapitalize: 'off', spellcheck: 'false' });
    var quota = el('input', { type: 'text', id: 'add-quota', class: 'field', inputmode: 'numeric' });
    var expires = el('input', { type: 'text', id: 'add-expires', class: 'field', placeholder: 'YYYY-MM-DD' });
    var conn = el('input', { type: 'text', id: 'add-conn', class: 'field', inputmode: 'numeric' });

    var reset = el('select', { id: 'add-reset', class: 'field' });
    [['', 'user.field.quota_reset.lifetime'],
     ['daily', 'user.field.quota_reset.daily'],
     ['weekly', 'user.field.quota_reset.weekly'],
     ['monthly', 'user.field.quota_reset.monthly']].forEach(function (pair) {
      reset.appendChild(el('option', { value: pair[0], text: t(pair[1]) }));
    });

    function row(labelKey, helpKey, input) {
      var block = el('div', { class: 'formrow' });
      block.appendChild(el('label', { for: input.id, text: t(labelKey) }));
      block.appendChild(input);
      if (helpKey) block.appendChild(el('p', { class: 'muted', text: t(helpKey) }));
      return block;
    }

    var problem = el('p', { class: 'signin__problem', role: 'alert' });
    var go = el('button', { type: 'submit', class: 'btn btn--primary', text: t('user.add') });

    var form = el('form', { class: 'form', novalidate: 'novalidate' }, [
      row('users.col.name', 'user.invalid_name', name),
      row('user.field.quota', 'user.field.quota.help', quota),
      row('user.field.quota_reset', null, reset),
      row('user.field.expires', 'user.field.expires.help', expires),
      row('user.field.conn_limit', 'user.field.conn_limit.help', conn),
      problem,
      go,
    ]);

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      problem.textContent = '';

      if (!/^[a-z][a-z0-9_-]{1,31}$/.test(name.value.trim())) {
        // The helper checks this too, and that is the check that counts. This
        // one exists so a typo is answered here instead of by a round trip.
        problem.textContent = t('user.invalid_name');
        return;
      }

      go.disabled = true;
      go.textContent = t('action.working');
      A.act({
        method: 'POST',
        path: '/api/admin/users',
        body: {
          name: name.value.trim(),
          // '' is the register's null: unlimited, never, no device cap. Sent
          // rather than omitted, because omitting means "leave it alone".
          quota_bytes: quota.value.trim(),
          expires_at: expires.value.trim(),
          conn_limit: conn.value.trim(),
          quota_reset: reset.value,
        },
        ok: function () { return t('user.add.done', { name: name.value.trim() }); },
      }).then(function (res) {
        if (res) { name.value = ''; quota.value = ''; expires.value = ''; conn.value = ''; }
      }).catch(function () { /* reported by act */ })
        .then(function () {
          go.disabled = false;
          go.textContent = t('user.add');
        });
    });

    card.appendChild(form);
    return card;
  }

  /* ══════════════════════════════════════════════════════════════════════════
     Render + poll
     ══════════════════════════════════════════════════════════════════════════ */
  var root = null;

  function render() {
    if (!root) return;
    var scrollY = window.scrollY;
    document.documentElement.setAttribute('lang', VPN55_I18N.current());
    document.title = t('app.title');

    clear(root);
    root.appendChild(renderTopBar(state.data));
    root.appendChild(renderNav());

    var main = el('main', { class: 'main', role: 'tabpanel' });

    if (state.error) {
      var b = el('div', { class: 'banner banner--crit', role: 'alert' });
      b.appendChild(el('strong', { text: t('app.unreachable.title') }));
      b.appendChild(el('p', { text: t('app.unreachable.body') }));
      b.appendChild(el('pre', { class: 'diag', text: state.error }));
      main.appendChild(b);
    }

    if (state.data) {
      var health = renderHealth(state.data);
      if (health) main.appendChild(health);

      if (!state.data.ready) {
        main.appendChild(emptyNote(t('app.waiting')));
      } else if (state.view === 'services') main.appendChild(renderServices(state.data));
      else if (state.view === 'users') main.appendChild(renderUsers(state.data));
      else if (state.view === 'connections') main.appendChild(renderConnections(state.data));
      else main.appendChild(renderEvents(state.data));
    } else if (!state.error) {
      main.appendChild(emptyNote(t('app.loading')));
    }

    root.appendChild(main);
    root.appendChild(renderFooter());
    window.scrollTo(0, scrollY);
  }

  function poll() {
    if (state.loading) return;
    state.loading = true;
    fetch('/api/state', { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then(function (r) {
        // A 401 is not a broken host — it is a session that ended, and it wants
        // the sign-in form rather than a message about an HTTP status. The last
        // data stays on screen behind the form; there is nothing secret in
        // having drawn it, and it is what was true a moment ago.
        if (r.status === 401) {
          A.session.authenticated = false;
          A.showSignIn();
          throw new Error('unauthenticated');
        }
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        state.data = data;
        state.error = null;
        state.now = data.generatedAt;
      })
      .catch(function (err) {
        // The panel process itself is unreachable — a different failure from the
        // host being unreadable, and it gets a different message. The last data
        // stays on screen, labelled as the last data. A session that simply
        // ended is not an error to report: the form is already on screen.
        var message = String(err && err.message ? err.message : err);
        state.error = message === 'unauthenticated' ? null : message;
      })
      .then(function () {
        state.loading = false;
        render();
      });
  }

  function start() {
    root = el('div', { class: 'app' });
    document.body.appendChild(root);

    var hash = String(location.hash || '').replace('#', '');
    if (VIEWS.indexOf(hash) >= 0) state.view = hash;

    render();

    // The session is resolved BEFORE the first poll, so the first paint already
    // knows whether to draw the controls that change something. Drawing them and
    // then removing them a moment later is how a button gets clicked in the gap.
    A.start().then(function () {
      render();
      poll();
    });

    // Any completed write re-reads the host and repaints, so what is on screen
    // after an action is a fresh reading rather than an assumption about what
    // the action did.
    A.onChange(function () { poll(); render(); });

    var period = (VPN55_I18N.pollSeconds || 15) * 1000;
    setInterval(poll, period);

    // Re-poll on return to the tab: a page that has been in the background for
    // an hour would otherwise show hour-old numbers for up to a full interval,
    // at exactly the moment someone has come back to look at them.
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') poll();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
