'use strict';
//
// VPN55 admin panel — entry point. Phase 6: sign-in and write actions.
//
// Its own systemd unit, its own port, its own nginx vhost, its own unprivileged
// service user. It never shares a process with anything public-facing.
//
// ── The write path, and how narrow it is ────────────────────────────────────
//
// Phase 5 refused every method except GET and HEAD, ahead of every route, so a
// write could not be reached even if somebody added one. Phase 6 replaces that
// blanket with a specific one: writes exist, they live under /api/admin, and
// every one of them ends at panel/lib/privileged.js — which invokes
// helper/vpnctl's seven verbs and nothing else. There is no other way for this
// process to change anything on the host. It cannot run a command, write a
// config file, or touch the register directly, and nothing outside
// privileged.js may spawn a privileged process at all.
//
// Two guards stand in front of every write: an admin session, and a CSRF token
// this page has to read and echo in a header. The reads keep the shape they had.
//
// ── The panel is not the source of truth ────────────────────────────────────
//
// On-disk server configuration is. Every view is built from the adapters'
// `_status` output, read fresh each poll. The one thing this process keeps of
// its own is accumulated traffic totals, and only because that is the single
// number no adapter can answer: all three reset their counters.
//
// ── Binding ─────────────────────────────────────────────────────────────────
//
// To the tunnel interface's address, never 0.0.0.0 with an allowlist. An
// allowlist still lets a stranger complete the TLS handshake and reach this
// code; binding to a private interface means the packet never arrives. Paired
// with DNS-01 certbot, nothing inbound needs opening at all. config.js refuses
// a wildcard rather than warning about one.
//
// ── Every string on screen comes from a catalog ─────────────────────────────
//
// Vietnamese default, English fallback, French third. There is no English
// sentence in the HTML, in the client script or in an event record. The two
// exceptions are deliberate and marked as such in the UI: an adapter's own note
// text, and an adapter's own filtering explanation. Both are data written by a
// module that knows which protocol it is; this side cannot translate them
// without learning the same thing, which it may not do.

const express = require('express');
const path = require('node:path');

const log = require('./lib/log');
const { load: loadConfig, ConfigError } = require('./lib/config');
const { Catalogs } = require('./lib/i18n');
const { StatusReader } = require('./lib/status-read');
const { Store } = require('./lib/store');
const { Collector } = require('./lib/collector');
const { buildView } = require('./lib/view');
const { Audit } = require('./lib/audit');
const { Auth } = require('./lib/auth');
const { Privileged } = require('./lib/privileged');
const { Enforcer } = require('./lib/enforcement');
const { Alerter } = require('./lib/alerts');
const { Settings } = require('./lib/settings');
const adminRoutes = require('./lib/routes-admin');
const { PortalTokens } = require('./portal/tokens');
const { PortalAuth } = require('./portal/auth');
const portalRoutes = require('./portal/routes');
const portalShell = require('./portal/shell');

const LOCALE_COOKIE = 'vpn55_locale';

function die(message, detail) {
  log.error(message);
  if (detail) for (const line of [].concat(detail)) log.error(`  ${line}`);
  process.exitCode = 1;
}

function main() {
  let cfg;
  try {
    cfg = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      die('configuration is not usable, so nothing was started:', err.message);
      return;
    }
    throw err;
  }
  log.setLevel(cfg.log_level);

  // ── Sign-in ───────────────────────────────────────────────────────────────
  // Phase 5 had no sign-in and refused to start until the operator acknowledged
  // that, through this same setting. Phase 6 inverts it exactly as that block
  // said it would: authentication now exists, and setting the flag TURNS IT OFF.
  //
  // So the refusal moves to the other side. Running with it on is a thing to do
  // on a laptop; on a host it hands every user name, quota and traffic total —
  // and now every write action — to anyone who can reach the bind address.
  if (cfg.allow_unauthenticated) {
    log.warn('allow_unauthenticated=1 — THERE IS NO SIGN-IN AND NO CSRF CHECK. ' +
             'Every write action on this host is available to anyone who can reach ' +
             `${cfg.bind}:${cfg.port}. Set it to 0 in ${cfg.confPath}.`);
  }

  if (!cfg.bindIsLocal) {
    die(`bind address ${cfg.bind} is not assigned to any interface on this host.`, [
      'listen() would fail with EADDRNOTAVAIL a moment from now; this is the same',
      'failure, said in time to be useful. Bring the tunnel interface up first, or',
      'correct the address.',
    ]);
    return;
  }
  if (!cfg.bindIsPrivate) {
    log.warn(`bind address ${cfg.bind} is not a private address — this panel may be ` +
             'reachable from outside the tunnel. That is the arrangement the ' +
             'security model exists to avoid; see docs/security-model.md §4.');
  }

  // ── Catalogs, before anything can need a string ───────────────────────────
  let catalogs;
  try {
    catalogs = new Catalogs(cfg.locales, cfg.default_locale).load();
  } catch (err) {
    die('locale catalogs could not be loaded:', err.message);
    return;
  }

  // ── The first of the two privileged paths ─────────────────────────────────
  // The READER. It is constructed first because the collector needs it and
  // because a panel that cannot see the host has nothing to show, but it is not
  // the only one: the write helper is built a few lines below and both are
  // preflighted before anything listens. docs/security-model.md §6E.7 is the
  // record that this surface is two programs, not one.
  const reader = new StatusReader({ config: cfg, warn: (m) => log.warn(m) });
  const problems = reader.preflight();
  if (problems.length) {
    die('the status read is not usable, so nothing was started:', problems);
    return;
  }

  const store = new Store(cfg.state_dir);
  try {
    store.ensureDir();
    store.load();
  } catch (err) {
    die('state could not be loaded:', err.message);
    return;
  }

  // ── Alerting ──────────────────────────────────────────────────────────────
  //
  // Built before the collector and the enforcer because both hand it their
  // results, and wired HERE rather than inside either of them. That is the whole
  // arrangement: collector.js keeps knowing only about counters, enforcement.js
  // keeps knowing only about quotas, and the decision about what is worth
  // telling somebody lives in one file with the suppression logic that stops it
  // becoming noise.
  //
  // Inert unless alert_enabled is on AND a URL is set. With neither, every
  // observation below is a few comparisons and a return.
  const alerter = new Alerter({ cfg, catalogs });
  if (alerter.active) {
    log.info(`alerts: ${cfg.alert_webhook_format} webhook, ` +
             `${alerter.confirmations} confirmation(s), ` +
             `${Math.floor(alerter.cooldownMs / 1000)}s cooldown, ` +
             `at most ${alerter.maxPerHour}/hour`);
  }

  const collector = new Collector({
    privileged: reader,
    store,
    cfg,
    // The panel cannot see the host at all while this is true, which makes every
    // other alert unknowable rather than false — so this one is separate from
    // them and is the only one raised from the read path.
    onPoll: (health) => {
      alerter.observe(
        'status.unreadable',
        health.consecutiveFailures >= alerter.statusFailures,
        // `count` rather than `failures`: every alert renders through one
        // template that fills {count}, so a differently named field would come
        // out as a literal `{count}` in the message.
        { count: health.consecutiveFailures },
      );
    },
  });

  // ── The write path ────────────────────────────────────────────────────────
  // Constructed here and passed down, so there is exactly one Privileged in the
  // process and its call queue really does serialise every root call. A second
  // instance would have a second queue, and the serialisation would be a comment
  // rather than a property.
  const audit = new Audit({ file: cfg.audit_file, warn: (m) => log.warn(m) });
  const privileged = new Privileged({ config: cfg, warn: (m) => log.warn(m) });
  const auth = new Auth({ config: cfg, audit, warn: (m) => log.warn(m), alerter });

  // The same question the status reader asks about the installer, asked about
  // the helper: can this process replace the file it is about to ask root to
  // run? A NOPASSWD rule on a writable path is root with a delay, so this is a
  // refusal rather than a warning.
  const helperProblems = privileged.preflight();
  if (helperProblems.length) {
    die('the privileged helper is not usable, so nothing was started:', helperProblems);
    return;
  }

  // Sign-in is on and nobody can sign in: refuse, rather than start a panel with
  // an unusable login form. An operator who meets a password prompt that can
  // never be satisfied has no way to tell it from a forgotten password.
  if (!cfg.allow_unauthenticated && auth.adminCount() === 0) {
    die(`no administrator accounts exist in ${cfg.admins_file}.`, [
      'Sign-in is on and there is nobody who can sign in. Create the first',
      'account as root, on this host:',
      '',
      '  node /usr/local/lib/vpn55/panel/scripts/admin.js add <name>',
      '',
      'It prompts for the password, writes the hash, and never echoes or logs it.',
    ]);
    return;
  }

  // Sign-in is on, `require_totp` is on, and somebody has no second factor: they
  // cannot sign in, and the fix is at this console. Said at start-up rather than
  // left for them to discover as a refused login with a message about a terminal
  // they may not be sitting at.
  if (!cfg.allow_unauthenticated && cfg.require_totp) {
    const bare = auth.adminsWithoutTotp();
    if (bare.length) {
      log.warn(`require_totp=1 and ${bare.length} account(s) have no second factor ` +
               'enrolled. They CANNOT sign in until they do. Enrol each of them here:',
               bare.join(', '));
      log.warn('  node /usr/local/lib/vpn55/panel/scripts/admin.js totp <name>');
    }
  }

  const enforcer = new Enforcer({
    cfg,
    collector,
    store,
    privileged,
    audit,
    onRun: (summary) => {
      // ⚠ A run that could not read the host must not RESOLVE anything. Its
      // counters are all zero, and zero here means "did not look", not "nothing
      // to report" — resolving on it would send an all-clear derived from a
      // reading that was never taken. `looked` is the flag that separates the
      // two; a summary of zeroes cannot.
      if (!summary.looked) return;

      alerter.observe('enforce.still_connected', summary.stillConnected > 0,
                      { count: summary.stillConnected });
      alerter.observe('enforce.quota_skipped', summary.quotaSkipped > 0,
                      { count: summary.quotaSkipped });
      // An EDGE, not a level: a baseline is re-taken by one run and the next run
      // finds nothing to re-take. See the warning at the top of lib/alerts.js.
      if (summary.baselinesReset > 0) {
        alerter.event('enforce.baselines_reset', { count: summary.baselinesReset });
      }
    },
  });

  // ── The settings screen's live values ─────────────────────────────────────
  //
  // Built last of the runtime modules, because it pushes a value into each of
  // them. cfg stays frozen and stays the record of what was LOADED; from here
  // on, what is RUNNING is whatever these modules hold, and this is the only
  // thing that changes them.
  //
  // applyAll() is not optional. config.js has already merged the overlay for its
  // own purposes, so without this the loader and a module that read cfg once at
  // construction would disagree — and the screen would be showing a value that
  // was not the one in use.
  const settings = new Settings({ cfg });
  settings.bind({ collector, auth, enforcer, catalogs, alerter });
  settings.applyAll();
  if (cfg.overridden.length) {
    log.info(`settings screen is overriding ${cfg.overridden.length} key(s) from ` +
             `${cfg.confPath}`, cfg.overridden.join(', '));
  }
  for (const note of cfg.notes) log.warn(note);

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);

  app.use((req, res, next) => {
    // A panel is not a public site and nothing here should ever be framed,
    // sniffed or sent to a third party as a referrer.
    res.set({
      'Content-Security-Policy':
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; " +
        "frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  });

  // ── Locale for this request ───────────────────────────────────────────────
  app.use((req, res, next) => {
    const fromCookie = readCookie(req.headers.cookie, LOCALE_COOKIE);
    req.locale = catalogs.negotiate(fromCookie, req.headers['accept-language']);
    next();
  });

  app.get('/healthz', (req, res) => {
    const h = collector.health();
    res.status(h.lastSuccessAt === null && h.consecutiveFailures > 0 ? 503 : 200)
       .json({ ok: h.lastSuccessAt !== null, ...h });
  });

  app.get('/api/locale', (req, res) => {
    // `catalogs.defaultLocale`, not `cfg.default_locale` — the settings screen
    // can change it without a restart, and cfg is the record of what was loaded.
    res.json({ locale: req.locale, available: cfg.locales, default: catalogs.defaultLocale });
  });

  app.get('/api/i18n/:locale', (req, res) => {
    const wanted = String(req.params.locale || '').toLowerCase();
    if (!catalogs.has(wanted)) {
      res.status(404).json({ error: 'unknown_locale', available: cfg.locales });
      return;
    }
    res.json({ locale: wanted, strings: catalogs.catalog(wanted) });
  });

  // ── The write surface ─────────────────────────────────────────────────────
  // One mount point, one module, and every route under it ends at
  // privileged.js. Mounted BEFORE the read routes so that a path collision
  // would be a visible 404 from this router rather than a read silently
  // shadowing a write.
  // ── The portal's token store and session map ──────────────────────────────
  //
  // Built here, ahead of BOTH applications, because both need them: the admin
  // app so an operator can issue and withdraw a code, the portal app because
  // they are its own. There is exactly one of each in this process — a second
  // token store would be a second opinion about who has access, and a second
  // session map would make "sign this person out" true in one place and false
  // in the other.
  //
  // Null when the portal is switched off, and the admin routes answer a token
  // call with a 404 rather than pretending the feature is there.
  let portalTokens = null;
  let portalAuth = null;

  if (cfg.portal_enabled) {
    portalTokens = new PortalTokens({ file: cfg.portal_tokens_file, warn: (m) => log.warn(m) });
    try {
      portalTokens.load();
    } catch (err) {
      die('the portal access codes could not be loaded:', err.message);
      return;
    }
    portalAuth = new PortalAuth({
      config: cfg, tokens: portalTokens, audit, warn: (m) => log.warn(m),
    });
  }

  app.use('/api/admin', adminRoutes.build({
    cfg, auth, audit, privileged, enforcer, collector, portalTokens, portalAuth,
    settings, alerter,
  }));

  // Reads are behind the session too. Phase 5 could leave them open because it
  // had a start-up refusal saying so out loud; now that sign-in exists, "you can
  // read every user name and traffic total without it" would be a hole rather
  // than a documented choice. It does NOT touch the idle clock — a polling tab
  // must never keep an unattended session alive.
  function requireRead(req, res, next) {
    if (cfg.allow_unauthenticated) return next();
    if (!auth.resolve(req, { interactive: false })) {
      return res.status(401).json({ error: 'auth.required' });
    }
    return next();
  }

  app.get('/api/state', requireRead, (req, res) => {
    res.json(buildView({
      snapshot: collector.snapshot,
      collector,
      cfg,
      health: collector.health(),
    }));
  });

  // The catalog the browser needs before it can render anything is inlined into
  // the shell page, so the first paint is already in the viewer's language.
  // Fetching it afterwards would show a flash of key names, which is the
  // hardcoded-English problem wearing a different hat.
  app.get('/', (req, res) => {
    // The poll interval comes from the collector, which is what actually polls.
    // A page told 15s while the collector runs at 60s would count down to a
    // refresh that does not come.
    res.type('html').send(
      renderShell(req.locale, cfg, catalogs, { pollSeconds: collector.pollSeconds }));
  });

  app.use('/assets', express.static(path.join(__dirname, 'public'), {
    index: false,
    dotfiles: 'ignore',
    maxAge: 0,
    fallthrough: false,
  }));

  app.use((req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // Express's default error handler prints a stack trace into the response.
  // On a panel that is a description of the filesystem handed to whoever asked.
  app.use((err, req, res, _next) => {
    // A body express.json() could not parse, or one over the limit, is the
    // CLIENT's mistake and gets a 4xx. Reporting it as a 500 would make a
    // mistyped request look like a broken host, and send whoever debugs it
    // reading the wrong logs.
    if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
      log.warn(`bad request body on ${req.method} ${req.path}`, err.type);
      if (res.headersSent) return;
      res.status(err.type === 'entity.too.large' ? 413 : 400)
         .json({ ok: false, error: 'action.failed' });
      return;
    }
    log.error('request failed', err && err.stack ? err.stack : String(err));
    if (res.headersSent) return;
    res.status(500).json({ ok: false, error: 'action.failed' });
  });

  // ══════════════════════════════════════════════════════════════════════════
  // THE SELF-SERVE PORTAL — a second application, on a second socket
  // ══════════════════════════════════════════════════════════════════════════
  //
  // Not a sub-path of the app above, and not that app with a role check. Two
  // express instances, two listen() calls, and the admin router is attached to
  // exactly one of them.
  //
  // That is the whole of the phase's first acceptance criterion. "A portal
  // token cannot reach an admin route" is not a rule enforced by a guard that
  // could be got wrong — on the portal's socket there is no admin route to
  // reach, for any token, session, header or forgery. A role flag on shared
  // routes is exactly how a user reaches an admin endpoint, and there are no
  // shared routes.
  //
  // The two exist because the two audiences are in different places. The panel
  // binds where only the operator can get to it; the portal has to be reachable
  // by the people being served, who are by definition not on the tunnel yet —
  // fetching the configuration is how they get on it.
  //
  // ⚠ ONE PROCESS, TWO LISTENERS. They share a heap. A memory-safety or logic
  // compromise of one is a compromise of the other, and the honest reading is
  // that the portal's four routes are now part of the panel's attack surface.
  // That is a real cost and docs/security-model.md §6F states it rather than
  // burying it: the mitigations are that both are the same small dependency-free
  // codebase, that the portal's surface is seven routes with no user identifier
  // among them, and that everything privileged still goes through vpnctl.
  // Splitting them into two units is the alternative and is deferred, because a
  // second process would need either a second status poll or a second writer of
  // the traffic totals, and the totals are single-writer durable state.
  let portalApp = null;
  let portalServer = null;

  if (cfg.portal_enabled) {
    if (!cfg.portalBindIsLocal) {
      die(`portal_bind ${cfg.portal_bind} is not assigned to any interface on this host.`, [
        'listen() would fail with EADDRNOTAVAIL a moment from now; this is the same',
        'failure, said in time to be useful. Correct the address, or set',
        'portal_enabled=0 if this deployment has no self-serve users.',
      ]);
      return;
    }

    const missing = portalShell.missingAssets();
    if (missing.length) {
      // A missing asset renders a page that looks fine and does nothing, which
      // is the hardest kind of failure to report from a phone. Caught at
      // startup rather than at the first request.
      die('the portal is enabled but its assets are not where it expects them:', missing);
      return;
    }

    portalApp = express();
    portalApp.disable('x-powered-by');
    portalApp.set('etag', false);

    portalApp.use((req, res, next) => {
      // A tighter policy than the panel's on one point: this page is meant to
      // be reachable, so `noindex` and `no-referrer` are doing real work rather
      // than being belt and braces. A portal URL in a search index is a list of
      // somewhere worth probing.
      res.set({
        'Content-Security-Policy':
          "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
          "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; " +
          "frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'X-Robots-Tag': 'noindex, nofollow',
        'Cache-Control': 'no-store',
      });
      next();
    });

    portalApp.use((req, res, next) => {
      const fromCookie = readCookie(req.headers.cookie, LOCALE_COOKIE);
      req.locale = catalogs.negotiate(fromCookie, req.headers['accept-language']);
      next();
    });

    // The catalogs, so the language picker works without a reload. It is the
    // same handler the panel has, mounted on this app rather than shared: a
    // catalog is public text and there is nothing in it worth gating, but it
    // still has to be REGISTERED here, because nothing is shared between the
    // two applications by accident.
    portalApp.get('/api/i18n/:locale', (req, res) => {
      const wanted = String(req.params.locale || '').toLowerCase();
      if (!catalogs.has(wanted)) {
        res.status(404).json({ error: 'unknown_locale', available: cfg.locales });
        return;
      }
      res.json({ locale: wanted, strings: catalogs.catalog(wanted) });
    });

    portalApp.use('/api/portal', portalRoutes.build({
      cfg, portalAuth, audit, privileged, collector, catalogs,
    }));

    portalShell.mountAssets(portalApp);

    portalApp.get('/', (req, res) => {
      res.type('html').send(portalShell.render({ locale: req.locale, cfg, catalogs }));
    });

    portalApp.use((req, res) => {
      res.status(404).json({ error: 'not_found' });
    });

    portalApp.use((err, req, res, _next) => {
      if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
        log.warn(`bad portal request body on ${req.method} ${req.path}`, err.type);
        if (res.headersSent) return;
        res.status(err.type === 'entity.too.large' ? 413 : 400)
           .json({ ok: false, error: 'portal.failed' });
        return;
      }
      log.error('portal request failed', err && err.stack ? err.stack : String(err));
      if (res.headersSent) return;
      // No stack trace in the body. On an internet-facing socket that is a
      // description of the filesystem handed to whoever asked for it.
      res.status(500).json({ ok: false, error: 'portal.failed' });
    });
  }

  const server = app.listen(cfg.port, cfg.bind, () => {
    log.info(`VPN55 panel listening on ${cfg.bind}:${cfg.port}`);
    log.info(`status read: ${reader.statusCommandLine()}`);
    log.info(`write helper: ${privileged.commandLine()}`);
    log.info(`state: ${store.file}`);
    log.info(`audit: ${cfg.audit_file}  (the helper keeps its own, root-only)`);
    log.info(`locales: ${cfg.locales.join(', ')} (default ${cfg.default_locale})`);
    if (cfg.allow_unauthenticated) {
      log.warn('SIGN-IN IS OFF — every read and every write is open to this address');
    }
    collector.start();
    enforcer.start();
  });

  server.on('error', (err) => {
    die(`cannot listen on ${cfg.bind}:${cfg.port} — ${err.code || err.message}`);
    process.exit(1);
  });

  if (portalApp) {
    portalServer = portalApp.listen(cfg.portal_port, cfg.portal_bind, () => {
      log.info(`VPN55 portal listening on ${cfg.portal_bind}:${cfg.portal_port}`);
      log.info(`portal codes: ${cfg.portal_tokens_file}  (${portalTokens.count()} live)`);
      if (portalTokens.count() === 0) {
        // Not a warning. A portal with no codes is the correct state of a fresh
        // install and it answers 401 to everything; saying so once at startup is
        // what stops an operator concluding it is broken.
        log.info('no portal access codes exist yet — issue one with ' +
                 'node /usr/local/lib/vpn55/panel/scripts/portal.js issue <user>');
      }
      if (!cfg.portal_trust_proxy) {
        log.warn('portal_trust_proxy=0 — every portal client counts as the socket ' +
                 'address for rate limiting. Behind a reverse proxy that is ONE ' +
                 'bucket for everybody, which fails closed but throttles real users.');
      }
    });
    portalServer.on('error', (err) => {
      die(`cannot listen on ${cfg.portal_bind}:${cfg.portal_port} — ${err.code || err.message}`);
      process.exit(1);
    });
  }

  const shutdown = (signal) => {
    log.info(`${signal} — stopping`);
    collector.stop();
    enforcer.stop();
    auth.stop();
    if (portalAuth) portalAuth.stop();
    try {
      store.flush(true);
    } catch (err) {
      log.error('could not write state on shutdown', err.message);
    }
    if (portalServer) portalServer.close();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

function readCookie(header, name) {
  if (!header) return null;
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

/**
 * The shell page. It carries no sentence of its own — every visible string is a
 * catalog key resolved by the client script, and the catalog is inlined so the
 * first paint is already correct.
 *
 * Two strings are ALSO rendered server-side, into the markup rather than only
 * as a data-i18n key: the <title> and the <noscript>. Both are read before
 * app.js runs, or when it never runs at all — an empty <title> shows the URL in
 * the tab, and a body with no <noscript> is a blank page in no language. The
 * data-i18n attribute stays on the title so the language picker still reaches
 * it without a reload.
 */
function renderShell(locale, cfg, catalogs, { pollSeconds = null } = {}) {
  const boot = {
    locale,
    locales: cfg.locales,
    // Both of these are live values the settings screen can change without a
    // restart, so they come from the modules that own them rather than from the
    // frozen cfg. The fallbacks keep this function callable with three arguments
    // in a test that has no collector.
    defaultLocale: catalogs.defaultLocale || cfg.default_locale,
    cookieName: LOCALE_COOKIE,
    pollSeconds: pollSeconds === null ? cfg.poll_seconds : pollSeconds,
    strings: catalogs.catalog(locale),
  };
  // </script> inside JSON would close the tag early; the escape is the standard
  // one and is why this is not just JSON.stringify.
  const json = JSON.stringify(boot).replace(/</g, '\\u003c');

  return `<!doctype html>
<html lang="${esc(locale)}" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title data-i18n="app.title">${esc(catalogs.t(locale, 'app.title'))}</title>
<link rel="stylesheet" href="/assets/css/vendor/office-tools.css">
<link rel="stylesheet" href="/assets/css/panel.css">
<link rel="stylesheet" href="/assets/css/brand.css">
</head>
<body>
<noscript><p>${esc(catalogs.t(locale, 'app.noscript'))}</p></noscript>
<script id="boot" type="application/json">${json}</script>
<script src="/assets/js/theme.js"></script>
<script src="/assets/js/i18n.js"></script>
<script src="/assets/js/format.js"></script>
<script src="/assets/js/actions.js"></script>
<script src="/assets/js/app.js"></script>
</body>
</html>
`;
}

if (require.main === module) main();

module.exports = { renderShell, readCookie, main };
