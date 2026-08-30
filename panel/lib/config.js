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

  // Trust the first X-Forwarded-For hop. OFF by default, and that default is
  // load-bearing rather than cautious: the login lockout is keyed on the client
  // IP, so a caller who can set that header freely has an endless supply of
  // "different" clients and is never locked out. Turn it on only when a reverse
  // proxy on this host is the sole way in, which is the only arrangement in
  // which the header means anything at all.
  trust_proxy: '0',

  // Phase 5 shipped with no sign-in, and refused to start until the operator
  // acknowledged that. Phase 6 added authentication, so the acknowledgement is
  // now the opposite switch: setting this to 1 turns sign-in OFF, and it is a
  // thing to do on a laptop while developing, never on a server.
  allow_unauthenticated: '0',

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

function load({ confPath = CONF_PATH } = {}) {
  const problems = [];
  const notes = [];

  let fileValues = Object.create(null);
  try {
    fileValues = parseConf(fs.readFileSync(confPath, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      problems.push(`cannot read ${confPath}: ${err.code || err.message}`);
    }
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
    trust_proxy: bool('trust_proxy'),
    allow_unauthenticated: bool('allow_unauthenticated'),

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

    notes,
  };

  if (problems.length) throw new ConfigError(problems);
  return sealed(cfg);
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
  load, ConfigError, parseConf, asBool, asInt,
  isPrivateAddress, isLoopbackAddress, isLocalAddress, DEFAULTS, CONF_PATH,
};
