'use strict';
//
// panel/lib/config.js — one place that turns `/etc/vpn55/panel.conf` into typed,
// validated values, with defaults that are safe when the file is absent.
//
// The format is the project's key=value settings format, the same one
// lib/core_fs.sh writes and reads: one setting per line, no quoting, no
// interpolation, `#` comments. Deliberately not JSON and deliberately not
// sourced as shell — a settings file that is sourced is a settings file that
// executes whatever gets written into it, and this one sits beside private keys.
//
// ── Two type traps this loader exists to avoid ────────────────────────────────
//
//  1. A STRING IS ALWAYS TRUTHY. The file is text, so a boolean arrives as the
//     five characters `false`, and `if (cfg.enforce_quota_revoke)` on that is
//     true. A security switch that turns ON when it is set to off is the worst
//     shape of bug there is: invisible, survives review, and does the thing the
//     operator explicitly asked it not to. Every boolean goes through asBool(),
//     which accepts a closed vocabulary and treats anything else as a mistake
//     to report rather than a value to guess at.
//
//  2. `key in DEFAULTS` WALKS THE PROTOTYPE CHAIN. `'constructor' in {}` is
//     true and so is `'toString'`, so a settings file containing
//     `constructor=…` would pass an `in` check and land somewhere surprising.
//     The defaults live on a null-prototype object and membership is tested
//     with Object.hasOwn.
//
// ── Refusing rather than warning ──────────────────────────────────────────────
// A wildcard bind address is a ConfigError, not a warning. The security model's
// central claim is that the panel is not reachable from the internet by default;
// a warning printed into a log nobody reads at 3am is not an enforcement of it.
// See §4 — an allowlist still lets a stranger complete the TLS handshake, so the
// binding is the control and it has to hold.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const log = require('./log');

const CONF_PATH = process.env.VPN55_PANEL_CONF || '/etc/vpn55/panel.conf';
const ROOT = path.join(__dirname, '..', '..');

class ConfigError extends Error {
  constructor(problems) {
    const list = [].concat(problems);
    super(list.join('\n'));
    this.name = 'ConfigError';
    this.problems = list;
  }
}

// Null-prototype: see trap 2.
const DEFAULTS = Object.assign(Object.create(null), {
  // ── Listener ──────────────────────────────────────────────────────────────
  // Loopback, because it is the only address every host definitely has. A real
  // deployment sets this to the tunnel interface's address; a wildcard is
  // refused outright.
  bind: '127.0.0.1',
  port: '8055',

  // Believe the proxy's client-address header (X-Real-IP, else the LAST
  // X-Forwarded-For hop — never the first; see lib/rate-limit.js).
  //
  // ON by default, matching portal_trust_proxy, and REFUSED below unless `bind`
  // is loopback. Those two facts are one decision: the default deployment is
  // loopback with the nginx vhost in front, and there OFF is not the safe
  // setting people assume. With it off, every request's socket address is
  // 127.0.0.1, so the whole internet shares ONE lockout bucket — five wrong
  // passwords from anyone who can reach the vhost locks the operator out of
  // their own panel, and 30 attempts refuse their correct password too. That is
  // a denial of service that ships in the default configuration.
  //
  // The loopback refusal is what makes ON safe: on a reachable address the
  // header is caller-controlled, so config.js declines the combination rather
  // than warning about it.
  trust_proxy: '1',

  // Phase 5 shipped with no sign-in, and refused to start until the operator
  // acknowledged that. Phase 6 added authentication, so the acknowledgement is
  // now the opposite switch: setting this to 1 turns sign-in OFF, and it is a
  // thing to do on a laptop while developing, never on a server.
  allow_unauthenticated: '0',

  // Refuse a sign-in for any administrator who has not enrolled a second factor.
  //
  // OFF by default, because turning it on before anybody has enrolled locks
  // every account out of the panel, and the fix is at the console. Turning it on
  // is the point at which TOTP stops being per-account and becomes policy:
  // without it, an account created before 2FA existed still signs in on a
  // password alone and nothing on screen says so.
  //
  // ⚠ It is deliberately NOT exposed in the settings screen — see EXPOSED below.
  // A control that can remove the requirement to hold a second factor, reachable
  // from a session that only needed one factor to open, is a bypass with a
  // checkbox in front of it.
  require_totp: '0',

  // ── State and reading ─────────────────────────────────────────────────────
  state_dir: '/var/lib/vpn55/panel',
  user_dir: '/etc/vpn55/users',
  poll_seconds: '15',
  event_limit: '500',
  log_level: 'info',

  // ── Reading the adapters ──────────────────────────────────────────────────
  // `vpn55.sh --status` is root-only and read-only: it prints every adapter's
  // status records and changes nothing. It is a SEPARATE sudo rule from the
  // helper, and the rule must pin the argument — `vpn55.sh` with no argument
  // is the interactive menu, which is full root. deploy/sudoers.d/vpn55-panel
  // gets this right; it is the single most important line in this deployment.
  installer: '/usr/local/lib/vpn55/vpn55.sh',
  status_timeout_ms: '20000',

  // ── The privileged helper ─────────────────────────────────────────────────
  helper: '/usr/local/lib/vpn55/helper/vpnctl',
  // Whether to reach root through sudo. Normally 1 — the panel runs
  // unprivileged. It is 0 only when something else already arranges the
  // privilege, never as a way of skipping it.
  use_sudo: '1',
  helper_timeout_ms: '60000',

  // ── i18n ──────────────────────────────────────────────────────────────────
  // Vietnamese first, and first in this list is the default. English is the
  // fallback and the key-authoring source.
  locales: 'vi,en,fr',
  default_locale: 'vi',

  // ── Sessions ──────────────────────────────────────────────────────────────
  // An absolute lifetime and a separate idle timeout. The absolute one is capped
  // hard in auth.js: a session token cannot be withdrawn from the client's side,
  // so "log in once, stay in forever" is a credential with no expiry wearing a
  // session's name.
  session_ttl_minutes: '720',
  session_idle_minutes: '30',

  // ── Login throttling ──────────────────────────────────────────────────────
  login_window_ms: '900000',      // 15 minutes
  login_max_failures: '5',        // per (username, IP)
  login_lock_ms: '900000',        // 15 minutes
  login_ip_max: '30',             // per IP, whatever username is tried

  // ── Quota and expiry enforcement ──────────────────────────────────────────
  enforce_enabled: '1',
  enforce_interval_seconds: '300',

  // Both default OFF, deliberately and with a cost that is stated rather than
  // hidden. Disabling a user is a reversible policy flag; revoking a credential
  // is not — the client key is gone and the person needs a new configuration.
  // An automated job that revoked on a monthly quota would burn every user's
  // config every month.
  //
  // The cost of OFF: a person already connected when they cross their quota
  // stays connected, because none of these protocols can suspend a credential
  // and later restore it. panel/lib/enforcement.js reports that in every run
  // rather than reporting an enforcement that did not happen.
  enforce_quota_revoke: '0',
  enforce_expiry_revoke: '0',

  // ── Alerting ──────────────────────────────────────────────────────────────
  //
  // Nothing on this host tells anybody when something has gone wrong. The
  // enforcement job already computes most of the conditions worth knowing about
  // and writes them into a summary nobody is watching; this turns that summary
  // into a message.
  //
  // OFF by default and inert with no URL: alerting is an outbound connection
  // from a host whose whole design is that it does not make any, so it is an
  // opt-in with an address the operator typed.
  alert_enabled: '0',

  // Where a message goes. http:// and https:// only, and NOT exposed in the
  // settings screen: this is the one setting that decides where data about this
  // host leaves it, and a session is not enough to repoint that.
  alert_webhook_url: '',

  // `json` posts {type, state, severity, at, host, data} — no names, no
  // addresses, no counts of anything that identifies a person.
  //
  // `telegram` posts {chat_id, text} to the Bot API's sendMessage, because
  // Telegram is already this project's announcement channel and a generic
  // webhook cannot produce that body. The text is rendered from the catalogs in
  // default_locale, so an alert is translated like everything else.
  alert_webhook_format: 'json',
  alert_telegram_chat_id: '',

  // ── The three layers that stop an alert storm ─────────────────────────────
  //
  // A flapping service is the normal way an alerting system destroys its own
  // usefulness: one restart at 3am produces forty messages, and the next person
  // to see the channel has already muted it.
  //
  //  1. Alert on a TRANSITION, never on a state. A condition that is still true
  //     an hour later is not news. (Not a setting — it is how alerts.js works.)
  //  2. CONFIRMATIONS: how many consecutive observations before a condition is
  //     believed. 2 kills a single bad poll without delaying a real outage by
  //     more than one interval.
  //  3. COOLDOWN: the shortest gap between two messages about the same
  //     condition, however many times it transitions. An hour.
  //
  // And a global ceiling under all three, because a bug in any of them is a
  // bug that sends messages.
  alert_confirmations: '2',
  alert_cooldown_seconds: '3600',
  alert_max_per_hour: '20',

  // How many consecutive failed status reads before the panel says it cannot
  // see the host. One failure is a slow box; three at the default poll interval
  // is 45 seconds of not being able to read anything.
  alert_status_failures: '3',

  // ── The self-serve portal (Phase 8) ───────────────────────────────────────
  //
  // A SEPARATE LISTENER, not a path on the admin one, and that is the whole
  // control. The admin app and the portal app are two express instances with
  // two `listen()` calls: an admin route is not registered on the portal's
  // socket at all, so there is no path from a portal request to an admin
  // handler for any session, token or header to unlock. A role flag on shared
  // routes is exactly how a user reaches an admin endpoint, and this is the
  // arrangement that makes that impossible rather than merely guarded.
  //
  // The two listeners exist because the two audiences are in different places.
  // The panel binds where only the operator can reach it. The portal is for the
  // people being served — who are, by definition, not on the tunnel yet, since
  // fetching the configuration is how they get on it.
  //
  // ON by default. It is inert until an operator issues somebody a code: with
  // no tokens, every request to it is one 401. Turning it off is for a pure
  // self-host deployment where the operator is the only user.
  portal_enabled: '1',

  // Loopback, with nginx in front terminating TLS — deploy/nginx/ assumes it.
  // A wildcard is refused here for the same reason it is on the panel: name the
  // address. Unlike the panel's, this address is ALLOWED to be public, because
  // being reachable is the point of it.
  portal_bind: '127.0.0.1',
  portal_port: '8056',

  // Believe X-Forwarded-For on the portal.
  //
  // ON by default, unlike the panel's — and it is refused unless portal_bind is
  // a loopback address. That pairing is the whole rule: the header is only
  // worth believing when nothing but a proxy on this host can reach the socket,
  // and binding to loopback is what guarantees that. A public bind with this on
  // hands every caller an unlimited supply of identities to spend the rate limit
  // from, so the two settings are checked together rather than separately.
  portal_trust_proxy: '1',

  // Portal sessions. Shorter than the panel's by default: this is a page
  // somebody opens on a phone to fetch a file, not a console left open.
  portal_session_ttl_minutes: '120',
  portal_session_idle_minutes: '20',

  // Redeeming an access code. The code is 256 bits of randomness, so this is
  // not a guessing control — it is there so an open portal cannot be used to
  // make this host do work. Generous accordingly.
  portal_window_ms: '900000',
  portal_ip_max: '60',

  // Fetching a configuration, per account per window. The only portal route
  // that costs a subprocess, so this is not about strangers — a session does
  // nothing to stop an authenticated caller in a loop making this host fork.
  // Generous: a real person switching between four files on three credentials
  // never meets it.
  portal_config_max: '60',

  // Rotations per account per window. Rotation issues a credential before it
  // revokes the old one, so a caller that could repeat it without limit could
  // fill the address pool from a phone. One a day covers a lost device; this
  // allows rather more than that.
  portal_rotate_window_ms: '3600000',
  portal_rotate_max: '3',
});

// ═════════════════════════════════════════════════════════════════════════════
// THE SETTINGS SCREEN'S ALLOWLIST
//
// Every key an administrator may change from the panel. It is an allowlist, not
// a denylist: a key added to DEFAULTS above is SSH-only until somebody adds it
// here on purpose, which is the right direction for a list that decides what a
// stolen session can reach.
//
// ── The rule a key is judged against ─────────────────────────────────────────
//
// A key belongs here if the worst an authenticated administrator can do with it
// is make the panel noisier, quieter, slower or stricter.
//
// A key stays SSH-only if changing it can:
//
//   (a) reduce authentication            allow_unauthenticated, require_totp
//   (b) change who can reach this process, or what it believes about a caller
//                                        bind, port, trust_proxy, portal_bind,
//                                        portal_port, portal_trust_proxy,
//                                        portal_enabled
//   (c) redirect where data goes         alert_webhook_url, alert_webhook_format,
//                                        alert_telegram_chat_id, alert_enabled
//   (d) move a path this panel reads or writes
//                                        state_dir, user_dir, installer, helper,
//                                        use_sudo, and the timeouts on both
//   (e) cause an irreversible action on somebody's credentials
//                                        enforce_quota_revoke, enforce_expiry_revoke
//
// Four of those deserve their reasoning written out rather than summarised:
//
//   allow_unauthenticated / require_totp — a screen that can switch off the
//     authentication the screen itself sits behind is a bypass with a checkbox
//     in front of it. Whoever holds a stolen session would use these first.
//
//   trust_proxy / portal_trust_proxy — these decide whether a caller-supplied
//     header names the caller. Flipping trust_proxy on a reachable bind hands
//     every attacker an endless supply of lockout identities AND the ability to
//     aim a lockout at the operator. It is the single most load-bearing pair in
//     the file and it is checked against `bind`, which is also not here.
//
//   helper / installer / use_sudo — the two programs this panel asks root to
//     run. The sudoers rule pins them, so repointing them here would fail rather
//     than escalate; a settings screen that can rewrite what we ask root to run
//     is still not a thing to build and then rely on sudoers to save.
//
//   enforce_quota_revoke / enforce_expiry_revoke — one checkbox that destroys
//     every over-quota user's configuration on the next run, irreversibly,
//     because the client key is already gone. Nothing in a web session should be
//     one click from that.
//
//   state_dir — moving it does not move the durable traffic totals. Every user's
//     lifetime usage would read as zero at the new path, every quota baseline
//     with it, and the old file would still be sitting there looking fine.
//
//   locales — the catalogs are loaded once at startup. A live change would ask
//     for a catalog that is not in memory, and the failure is a page of key names.
//
//   every portal_* key — the portal's limiters are the only thing between an
//     internet-facing socket and this host's fork budget, and they are built at
//     startup. They are tuning, so they would otherwise qualify; they are held
//     back because applying them live means rebuilding the limiters on the
//     public socket, and that is a bigger change than this screen is worth.
//
// ── Bounds ───────────────────────────────────────────────────────────────────
// The bounds here must not be WIDER than the ones load() applies below, or a
// value could pass this screen and then refuse to load. They do not have to be
// identical, and load() is protected from drift anyway: an overlay that makes
// the configuration unloadable is dropped, not fatal. See load().
const EXPOSED = Object.freeze(Object.assign(Object.create(null), {
  poll_seconds:             { type: 'int', min: 5, max: 3600, group: 'reading' },
  event_limit:              { type: 'int', min: 10, max: 100000, group: 'reading' },
  log_level:                { type: 'choice', choices: ['error', 'warn', 'info', 'debug'], group: 'reading' },
  default_locale:           { type: 'locale', group: 'reading' },

  session_ttl_minutes:      { type: 'int', min: 1, max: 1440, group: 'sessions' },
  session_idle_minutes:     { type: 'int', min: 1, max: 1440, group: 'sessions' },

  // Changing any of these REBUILDS the live lockout and per-IP counters, which
  // discards whatever they were holding. That is not a bypass — the counters
  // only ever restrain someone who is not signed in, and whoever changes this is
  // signed in — but it does mean an operator can clear a lockout by nudging a
  // number, and it is better that they know that than discover it.
  login_window_ms:          { type: 'int', min: 1000, max: 86400000, group: 'login' },
  login_max_failures:       { type: 'int', min: 1, max: 1000, group: 'login' },
  login_lock_ms:            { type: 'int', min: 1000, max: 86400000, group: 'login' },
  login_ip_max:             { type: 'int', min: 1, max: 10000, group: 'login' },

  // Whether the job runs and how often — not what it is allowed to do when it
  // finds something, which is (e) above.
  enforce_enabled:          { type: 'bool', group: 'enforcement' },
  enforce_interval_seconds: { type: 'int', min: 30, max: 86400, group: 'enforcement' },

  // Tuning only. Whether alerts happen at all, and where they go, are (c).
  //
  // The cooldown is capped at a day rather than left open, because an unbounded
  // cooldown is an off switch wearing a number, and the off switch is not here.
  alert_confirmations:      { type: 'int', min: 1, max: 10, group: 'alerts' },
  alert_cooldown_seconds:   { type: 'int', min: 60, max: 86400, group: 'alerts' },
  alert_max_per_hour:       { type: 'int', min: 1, max: 500, group: 'alerts' },
  alert_status_failures:    { type: 'int', min: 1, max: 100, group: 'alerts' },
}));

/**
 * Validate one settings-screen value against EXPOSED.
 *
 * Returns the NORMALISED string to store, or null. Normalised because the file
 * format is text and `true`, `yes` and `1` must not be three different stored
 * values for one boolean — the settings file is read back by this same loader
 * and compared against panel.conf, and a comparison of `1` with `true` would
 * report a key as overridden when it holds the same value.
 *
 * @param {string[]} [locales] the loaded locale list, for `default_locale`
 */
function normaliseExposed(key, value, { locales = [] } = {}) {
  if (!Object.hasOwn(EXPOSED, key)) return null;
  const spec = EXPOSED[key];

  if (spec.type === 'int') {
    const n = asInt(value, { min: spec.min, max: spec.max });
    return n === null ? null : String(n);
  }
  if (spec.type === 'bool') {
    const b = asBool(value);
    return b === null ? null : (b ? '1' : '0');
  }
  if (spec.type === 'choice') {
    const v = String(value ?? '').trim().toLowerCase();
    return spec.choices.includes(v) ? v : null;
  }
  if (spec.type === 'locale') {
    const v = String(value ?? '').trim().toLowerCase();
    return locales.includes(v) ? v : null;
  }
  return null;
}

function parseConf(text) {
  const out = Object.create(null);
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z0-9_]+$/.test(key)) continue;
    out[key] = line.slice(eq + 1).trim();
  }
  return out;
}

/**
 * A closed vocabulary; anything outside it is `null`, meaning "you wrote
 * something I do not understand" rather than a guess. The caller then reports
 * it, so a typo in a settings file becomes visible instead of becoming a silent
 * policy change.
 */
function asBool(value) {
  if (value === undefined || value === null) return null;
  const v = String(value).trim().toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes' || v === 'on') return true;
  if (v === '0' || v === 'false' || v === 'no' || v === 'off' || v === '') return false;
  return null;
}

function asInt(value, { min, max } = {}) {
  if (value === undefined || value === null) return null;
  const v = String(value).trim();
  if (!/^[0-9]+$/.test(v)) return null;
  const n = Number(v);
  if (!Number.isSafeInteger(n)) return null;
  if (min !== undefined && n < min) return null;
  if (max !== undefined && n > max) return null;
  return n;
}

/**
 * Loopback only — a narrower question than isPrivateAddress.
 *
 * It exists because `portal_trust_proxy` is answerable only for a socket
 * nothing but a local proxy can reach, and "private" is not that: 10.8.0.1 is
 * private and every peer on the tunnel can reach it.
 */
function isLoopbackAddress(addr) {
  const a = String(addr).split('%')[0];
  return a === '::1' || a === '0:0:0:0:0:0:0:1' || /^127\./.test(a);
}

/** RFC 1918, CGNAT, loopback, link-local, and the IPv6 equivalents. */
function isPrivateAddress(addr) {
  const a = String(addr);
  if (a === '::1' || a.startsWith('127.')) return true;
  if (/^10\./.test(a)) return true;
  if (/^192\.168\./.test(a)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(a)) return true;
  if (/^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./.test(a)) return true;   // CGNAT
  if (/^169\.254\./.test(a)) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(a)) return true;                              // ULA
  if (/^fe80:/i.test(a)) return true;
  return false;
}

/**
 * Is this address actually assigned to an interface here?
 *
 * Answered before listen() rather than after, so the failure is a sentence about
 * the tunnel interface being down instead of an EADDRNOTAVAIL a moment later.
 */
function isLocalAddress(addr) {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const iface of list || []) {
      // The zone suffix on a link-local address is not part of the address.
      if (String(iface.address).split('%')[0] === String(addr).split('%')[0]) return true;
    }
  }
  return false;
}

/**
 * @param {object}  [opts]
 * @param {string}  [opts.confPath]
 * @param {boolean} [opts.forListener=true]
 *   Whether the caller is about to open a socket.
 *
 *   The listener-arrangement checks — which `trust_proxy` goes with which
 *   `bind` — are fatal for server.js and meaningless for the console tools,
 *   which open nothing. Making them fatal for everything would be a deadlock:
 *   scripts/admin.js needs the config to find `admins_file`, so an operator
 *   whose panel.conf has the wrong arrangement would find the panel refusing to
 *   start AND the tool that resets the password refusing to run. That is the
 *   same "a prompt nobody can satisfy" failure the panel already refuses to
 *   create, arrived at from the other side.
 * @param {object|null} [opts.overlay]
 *   The settings-screen values to merge, or `{}` to ignore whatever is on disk.
 *   Undefined means "read the overlay file". Only load() passes this; see the
 *   note on the retry there.
 */
function loadWith({ confPath = CONF_PATH, forListener = true, overlay } = {}) {
  const problems = [];
  const notes = [];
  const overridden = [];

  let fileValues = Object.create(null);
  try {
    fileValues = parseConf(fs.readFileSync(confPath, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      problems.push(`cannot read ${confPath}: ${err.code || err.message}`);
    }
  }

  // ── The settings-screen overlay ───────────────────────────────────────────
  //
  // It lives in the state directory, which the panel owns outright and already
  // writes — the traffic totals, the audit log, the enforcement state and the
  // portal codes are all in there. /etc/vpn55/panel.conf stays root-owned and
  // is never written by this process, and `vpnctl` gains no verb for any of
  // this. That is how a settings screen reaches a root-owned file: it does not.
  //
  // ⚠ THE OVERLAY WINS over panel.conf. The alternative — the file wins, the
  // overlay only fills gaps — sounds safer and is unusable: panel.conf.example
  // ships almost every key set explicitly, so most controls on the screen would
  // silently do nothing. Instead the overlay wins, the screen SAYS which keys it
  // is overriding, and every one of them has a control that puts it back.
  //
  // The state directory has to be resolved before the overlay can be read, so it
  // is the one key that cannot be overridden from inside the overlay. It is not
  // in EXPOSED for a better reason anyway — see the list there.
  const stateDirRaw = Object.hasOwn(fileValues, 'state_dir')
    ? String(fileValues.state_dir).trim() : DEFAULTS.state_dir;
  const settingsFile = path.join(stateDirRaw, 'settings.json');

  let overlayValues = Object.create(null);
  if (overlay !== undefined) {
    overlayValues = overlay || Object.create(null);
  } else {
    try {
      const parsed = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
      if (parsed && typeof parsed === 'object' && parsed.settings
          && typeof parsed.settings === 'object') {
        overlayValues = Object.assign(Object.create(null), parsed.settings);
      } else if (parsed && typeof parsed === 'object') {
        notes.push(`${settingsFile} has no "settings" object — it was ignored`);
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        // Ignored, never fatal. This file is written by the panel through a
        // validator, so a broken one means it was hand-edited or predates a
        // bounds change — and neither is a reason to leave the operator with a
        // panel that will not start and a fix that needs SSH anyway.
        notes.push(`${settingsFile} is unreadable (${err.code || err.message}) — ` +
                   'the settings screen values were ignored, panel.conf is in effect');
      }
    }
  }

  // The locale list, resolved early: `default_locale` can only be validated
  // against it, and the overlay is merged before the main pass reads either.
  const localesForOverlay = String(
    Object.hasOwn(fileValues, 'locales') ? fileValues.locales : DEFAULTS.locales,
  ).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

  for (const key of Object.keys(overlayValues)) {
    if (!Object.hasOwn(EXPOSED, key)) {
      // Not a failure. A key that used to be exposed and no longer is has to
      // stop taking effect, and that is exactly what this does.
      notes.push(`${settingsFile}: "${key}" is not a setting the panel exposes — ignored`);
      continue;
    }
    const normalised = normaliseExposed(key, overlayValues[key], { locales: localesForOverlay });
    if (normalised === null) {
      notes.push(`${settingsFile}: "${key}=${overlayValues[key]}" is out of range — ` +
                 'ignored, and the value in panel.conf is in effect');
      continue;
    }
    fileValues[key] = normalised;
    overridden.push(key);
  }

  // Object.hasOwn, not `in`: see trap 2.
  const raw = (key) => (Object.hasOwn(fileValues, key) ? fileValues[key] : DEFAULTS[key]);

  const bool = (key) => {
    const parsed = asBool(raw(key));
    if (parsed !== null) return parsed;
    problems.push(`${key}="${raw(key)}" is not a boolean (use 1/0, true/false, yes/no, on/off)`);
    return asBool(DEFAULTS[key]) === true;
  };

  const int = (key, bounds) => {
    const parsed = asInt(raw(key), bounds);
    if (parsed !== null) return parsed;
    problems.push(`${key}="${raw(key)}" is not a whole number in range`);
    return asInt(DEFAULTS[key], bounds);
  };

  const str = (key) => String(raw(key) ?? '').trim();

  const bind = str('bind');
  // A wildcard is refused, not warned about. See the header.
  if (bind === '0.0.0.0' || bind === '::' || bind === '*' || bind === '') {
    problems.push(
      `bind="${bind}" listens on every interface. The panel binds to one private ` +
      'address — an IP allowlist still lets a stranger complete the TLS handshake ' +
      'and reach this code (docs/security-model.md §4). Name the tunnel interface address.',
    );
  }

  // The same question asked of the panel that config.js already asks of the
  // portal, and for the same reason: a client-address header is only worth
  // believing when nothing but a proxy on this host can reach the socket.
  const trustProxy = bool('trust_proxy');
  if (forListener && trustProxy && !isLoopbackAddress(bind)) {
    problems.push(
      `trust_proxy=1 with bind="${bind}" is refused. The proxy's client-address ` +
      'header is only worth believing when nothing but a proxy on this host can ' +
      'reach the socket, and only a loopback bind guarantees that. On a reachable ' +
      'address a caller sets the header themselves, and the login lockout is keyed ' +
      'on that value — which gives them both an endless supply of identities to ' +
      'guess from and the ability to aim a lockout at the operator. Either bind to ' +
      '127.0.0.1 and put nginx in front (deploy/nginx/vpn55-panel.conf), or set ' +
      'trust_proxy=0.',
    );
  }
  // The other half of the same trap, and the one that has no loud failure of its
  // own: OFF while behind a proxy is not "cautious", it is one shared bucket for
  // every caller. Reported as a problem so an operator meets it at install time.
  if (forListener && !trustProxy && isLoopbackAddress(bind)) {
    problems.push(
      `trust_proxy=0 with bind="${bind}" is refused. A loopback bind means a ` +
      'reverse proxy is the only thing that can reach this socket, so every ' +
      'request arrives from 127.0.0.1 and every caller shares ONE rate-limit and ' +
      'lockout bucket: anyone who can reach the vhost can lock the operator out ' +
      'of their own panel with five wrong passwords, repeatedly. Set trust_proxy=1 ' +
      '— the vhost sets X-Real-IP from $remote_addr and nothing else can reach ' +
      'this port. If there is genuinely no proxy in front, bind to the tunnel ' +
      'address instead of loopback.',
    );
  }

  const localeList = str('locales').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (localeList.length === 0) problems.push('locales is empty');
  const defaultLocale = str('default_locale').toLowerCase();
  if (localeList.length && !localeList.includes(defaultLocale)) {
    problems.push(`default_locale="${defaultLocale}" is not in locales="${localeList.join(',')}"`);
  }

  // ── The portal listener ─────────────────────────────────────────────────
  // Validated even when the portal is off, so turning it on later fails at the
  // config rather than at the listen(). A setting that is only checked when it
  // is used is a setting that is wrong for however long it is unused.
  const portalEnabled = bool('portal_enabled');
  const portalBind = str('portal_bind');
  const portalTrustProxy = bool('portal_trust_proxy');

  if (portalBind === '0.0.0.0' || portalBind === '::' || portalBind === '*' || portalBind === '') {
    problems.push(
      `portal_bind="${portalBind}" listens on every interface. Name one address. ` +
      'The recommended arrangement is loopback with the nginx vhost in front — ' +
      'see deploy/nginx/vpn55-portal.conf.',
    );
  }
  if (portalTrustProxy && !isLoopbackAddress(portalBind)) {
    problems.push(
      `portal_trust_proxy=1 with portal_bind="${portalBind}" is refused. ` +
      'X-Forwarded-For is only worth believing when nothing but a proxy on this ' +
      'host can reach the socket, and only a loopback bind guarantees that. On a ' +
      'reachable address the header is caller-controlled, so every rate limit ' +
      'keyed on the client address would have an endless supply of identities. ' +
      'Either bind to 127.0.0.1 and put nginx in front, or set portal_trust_proxy=0.',
    );
  }
  if (portalEnabled && portalBind === bind && str('portal_port') === str('port')) {
    problems.push(
      `portal_bind and portal_port are the same address and port as the panel's ` +
      `(${bind}:${str('port')}). They are two separate listeners on purpose: the ` +
      'admin routes are not registered on the portal socket at all, which is what ' +
      'makes "a portal token cannot reach an admin route" a property of the ' +
      'process rather than a check that could be got wrong. Give the portal its ' +
      'own port.',
    );
  }

  const logLevel = str('log_level').toLowerCase();
  if (!['error', 'warn', 'info', 'debug'].includes(logLevel)) {
    problems.push(`log_level="${logLevel}" must be error, warn, info or debug`);
  }

  // ── Alerting ────────────────────────────────────────────────────────────
  // Validated whether or not alerting is on, so turning it on later fails here
  // rather than at the first alert — which is the worst possible moment for a
  // configuration error to surface, because the thing that would have told you
  // about it is the thing that is broken.
  const alertEnabled = bool('alert_enabled');
  const alertUrl = str('alert_webhook_url');
  const alertFormat = str('alert_webhook_format').toLowerCase();
  const alertChatId = str('alert_telegram_chat_id');

  if (!['json', 'telegram'].includes(alertFormat)) {
    problems.push(`alert_webhook_format="${alertFormat}" must be json or telegram`);
  }
  if (alertUrl) {
    let parsedUrl = null;
    try { parsedUrl = new URL(alertUrl); } catch { parsedUrl = null; }
    if (!parsedUrl) {
      problems.push(`alert_webhook_url="${alertUrl}" is not a URL`);
    } else if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      // No file:, no unix:, nothing that turns "post an alert" into "read a
      // path". The alerter refuses the same thing again at send time — this is
      // the message an operator can act on, that one is the control.
      problems.push(`alert_webhook_url="${alertUrl}" must be http:// or https://`);
    }
  }
  if (alertEnabled && !alertUrl) {
    // A warning, not a refusal: an operator mid-way through setting alerting up
    // should not find the panel refusing to start. It is inert, and it says so.
    notes.push('alert_enabled=1 with no alert_webhook_url — nothing will be sent');
  }
  if (alertEnabled && alertFormat === 'telegram' && !alertChatId) {
    notes.push('alert_webhook_format=telegram with no alert_telegram_chat_id — ' +
               'the Bot API will refuse every message');
  }

  const stateDir = str('state_dir');
  if (!path.isAbsolute(stateDir)) problems.push(`state_dir="${stateDir}" must be an absolute path`);

  const userDir = str('user_dir');
  if (!path.isAbsolute(userDir)) problems.push(`user_dir="${userDir}" must be an absolute path`);

  // The two privileged programs. Both must be absolute: a relative path here
  // would be resolved against whatever directory systemd happened to start the
  // service in, and a sudo rule cannot pin a path that is not fixed.
  const installer = str('installer');
  if (!path.isAbsolute(installer)) problems.push(`installer="${installer}" must be an absolute path`);
  const helper = str('helper');
  if (!path.isAbsolute(helper)) problems.push(`helper="${helper}" must be an absolute path`);

  const cfg = {
    confPath,
    root: ROOT,

    bind,
    port: int('port', { min: 1, max: 65535 }),
    bindIsLocal: isLocalAddress(bind),
    bindIsPrivate: isPrivateAddress(bind),
    trust_proxy: trustProxy,
    allow_unauthenticated: bool('allow_unauthenticated'),
    require_totp: bool('require_totp'),

    state_dir: stateDir,
    user_dir: userDir,
    poll_seconds: int('poll_seconds', { min: 5, max: 3600 }),
    event_limit: int('event_limit', { min: 10, max: 100000 }),
    log_level: logLevel,

    installer,
    status_timeout_ms: int('status_timeout_ms', { min: 1000, max: 600000 }),

    helper,
    use_sudo: bool('use_sudo'),
    helper_timeout_ms: int('helper_timeout_ms', { min: 1000, max: 600000 }),

    locales: localeList,
    default_locale: defaultLocale,

    session_ttl_ms: int('session_ttl_minutes', { min: 1, max: 1440 }) * 60_000,
    session_idle_ms: int('session_idle_minutes', { min: 1, max: 1440 }) * 60_000,

    login_window_ms: int('login_window_ms', { min: 1000, max: 86_400_000 }),
    login_max_failures: int('login_max_failures', { min: 1, max: 1000 }),
    login_lock_ms: int('login_lock_ms', { min: 1000, max: 86_400_000 }),
    login_ip_max: int('login_ip_max', { min: 1, max: 10_000 }),

    enforce_enabled: bool('enforce_enabled'),
    enforce_interval_ms: int('enforce_interval_seconds', { min: 30, max: 86_400 }) * 1000,
    enforce_quota_revoke: bool('enforce_quota_revoke'),
    enforce_expiry_revoke: bool('enforce_expiry_revoke'),

    alert_enabled: alertEnabled,
    alert_webhook_url: alertUrl,
    alert_webhook_format: alertFormat,
    alert_telegram_chat_id: alertChatId,
    alert_confirmations: int('alert_confirmations', { min: 1, max: 10 }),
    alert_cooldown_ms: int('alert_cooldown_seconds', { min: 60, max: 86_400 }) * 1000,
    alert_max_per_hour: int('alert_max_per_hour', { min: 1, max: 500 }),
    alert_status_failures: int('alert_status_failures', { min: 1, max: 100 }),

    portal_enabled: portalEnabled,
    portal_bind: portalBind,
    portal_port: int('portal_port', { min: 1, max: 65535 }),
    portalBindIsLocal: isLocalAddress(portalBind),
    portalBindIsPrivate: isPrivateAddress(portalBind),
    portal_trust_proxy: portalTrustProxy,
    portal_session_ttl_ms: int('portal_session_ttl_minutes', { min: 1, max: 1440 }) * 60_000,
    portal_session_idle_ms: int('portal_session_idle_minutes', { min: 1, max: 1440 }) * 60_000,
    portal_window_ms: int('portal_window_ms', { min: 1000, max: 86_400_000 }),
    portal_ip_max: int('portal_ip_max', { min: 1, max: 10_000 }),
    portal_config_max: int('portal_config_max', { min: 1, max: 10_000 }),
    portal_rotate_window_ms: int('portal_rotate_window_ms', { min: 1000, max: 86_400_000 }),
    portal_rotate_max: int('portal_rotate_max', { min: 1, max: 1000 }),

    // Derived paths, so no other module has to know how they are composed.
    audit_file: path.join(stateDir, 'audit.log'),
    admins_file: path.join(stateDir, 'admins.json'),
    enforcement_file: path.join(stateDir, 'enforcement.json'),
    // Portal access tokens. In the state directory beside the traffic totals
    // and, like them, DURABLE: losing this file locks every user out of the
    // portal until the operator issues a fresh code to each of them. It is not
    // a cache, and it belongs in the same backup.
    portal_tokens_file: path.join(stateDir, 'portal-tokens.json'),

    // The settings screen's overlay. Panel-owned, in the directory the panel
    // already writes — see the merge above.
    settings_file: path.join(stateDir, 'settings.json'),

    // What the alerter has already said, so a restart does not re-announce every
    // condition that is still true. Small, and losing it costs one duplicate
    // message per condition rather than anything durable.
    alerts_file: path.join(stateDir, 'alerts.json'),

    // Which keys the settings screen is currently overriding panel.conf for.
    // The screen shows this per key; an operator who edits panel.conf and sees
    // no change needs to be told why, in the place they would look.
    overridden: Object.freeze(overridden.slice().sort()),

    notes,
  };

  if (problems.length) throw new ConfigError(problems);
  return sealed(cfg);
}

/**
 * loadWith, plus one guarantee: THE SETTINGS OVERLAY CAN NEVER STOP THE PANEL
 * STARTING.
 *
 * The overlay is written by the panel through normaliseExposed, so a value in it
 * should always be loadable. "Should always" is not a property, though — a later
 * release that narrows a bound, an operator editing the JSON by hand, a restore
 * of a state directory from a different version, and the panel refuses to start
 * over a file whose entire purpose was to save the operator an SSH session. The
 * unit would then restart every 10s forever.
 *
 * So a ConfigError with the overlay applied is retried once WITHOUT it. If the
 * configuration is bad on its own the original error is what gets reported —
 * blaming the overlay for a broken panel.conf would send whoever is debugging it
 * to the wrong file.
 */
function load(opts = {}) {
  try {
    return loadWith(opts);
  } catch (err) {
    if (!(err instanceof ConfigError) || opts.overlay !== undefined) throw err;

    let cfg;
    try {
      cfg = loadWith({ ...opts, overlay: {} });
    } catch {
      throw err;   // panel.conf itself is the problem; report that, not this.
    }

    log.error('the settings-screen overlay made the configuration unloadable, ' +
              'so it was IGNORED and panel.conf is in effect. The panel started; ' +
              'the settings screen did not take effect.');
    for (const line of err.problems) log.error(`  ${line}`);
    log.error(`  Delete ${cfg.settings_file} to clear it.`);
    return cfg;
  }
}

/**
 * Freeze, and make a read of a key that does not exist THROW.
 *
 * ── Trap 3, and it is the one that has actually bitten ────────────────────────
 * The two traps in the header are about a value arriving in the wrong type. This
 * one is about the key: `config.pollSeconds` on an object that exports
 * `poll_seconds` is not an error in JavaScript, it is `undefined`. Every use of
 * it then fails in its own way and none of them mention the config —
 * `setTimeout(fn, undefined)` fires immediately, so a helper timeout of ten
 * minutes becomes zero; a boolean read as undefined is falsy, so `use_sudo`
 * silently stops using sudo; a path read as undefined becomes the string
 * "undefined" in a join. A whole session's modules were wired to camelCase names
 * this file has never exported, and the tree simply did not run, with no line
 * anywhere naming the cause.
 *
 * So an unknown STRING key throws, naming itself and the nearest real key.
 * Symbols and inherited members pass through untouched: util.inspect, spread,
 * JSON.stringify and `await` all probe for members that are legitimately absent,
 * and a config object that exploded when logged would be worse than the bug.
 */
// Members the language and the runtime probe for on any object, expecting the
// absence to be an answer. JSON.stringify asks for toJSON; awaiting or resolving
// anything asks for then; util.inspect asks for inspect. Throwing at those turns
// "log the config" into a crash, which is a worse bug than the one being caught.
const PROBED = new Set(['then', 'catch', 'finally', 'toJSON', 'inspect']);

function sealed(cfg) {
  const frozen = Object.freeze(cfg);
  return new Proxy(frozen, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && !PROBED.has(prop) && !(prop in target)) {
        const near = Object.keys(target)
          .filter((k) => k.replace(/_/g, '').toLowerCase() === prop.replace(/_/g, '').toLowerCase());
        throw new TypeError(
          `config has no setting "${prop}"` +
          (near.length ? ` — did you mean "${near[0]}"? (settings use snake_case, ` +
                         'matching the key names in panel.conf so an error message ' +
                         'names the same thing the operator typed)'
                       : ' — check panel/lib/config.js for the list'));
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

module.exports = {
  load, loadWith, ConfigError, parseConf, asBool, asInt,
  isPrivateAddress, isLoopbackAddress, isLocalAddress,
  DEFAULTS, EXPOSED, normaliseExposed, CONF_PATH,
};
