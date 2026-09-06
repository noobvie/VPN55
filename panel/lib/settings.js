'use strict';
//
// panel/lib/settings.js — the settings screen's half that touches disk.
//
// `/etc/vpn55/panel.conf` is root-owned, mode 0640, and the panel only ever
// reads it. That does not change here, and no verb is added to `helper/vpnctl`.
//
// ── How a write reaches a root-owned file ────────────────────────────────────
//
// It does not. The values an operator changes on screen are written to
// `<state_dir>/settings.json` — the directory the panel already owns outright
// and already writes: the traffic totals, the audit log, the enforcement state
// and the portal access codes all live there. `docs/security-model.md` §3
// already lists that directory as the panel's, so this adds a sixth file to a
// place with an established owner rather than a new privilege.
//
// config.js merges that file over panel.conf at load, restricted to the keys in
// its own EXPOSED allowlist. The overlay WINS over the file, which is the
// surprising half and is the only choice that produces a usable screen — see the
// comment at the merge. The screen then says, per key, whether the value it is
// showing came from here or from panel.conf, and every overridden key has a
// control that puts it back.
//
// ── The allowlist is in config.js, not here ──────────────────────────────────
//
// Next to DEFAULTS, where the whole key list and the reasoning for each key
// already lives. A reviewer asking "can a stolen session change this?" reads one
// file, and a key added to DEFAULTS is SSH-only until somebody deliberately adds
// it to EXPOSED — which is the right direction for that mistake to fall.
//
// ── Applying a change ────────────────────────────────────────────────────────
//
// Every exposed key takes effect NOW, without a restart. That is not a nicety:
// the panel cannot restart itself — `service-restart` takes an adapter tag, and
// the panel's own unit is not an adapter — so a settings screen whose changes
// needed a restart would be a settings screen that needs an SSH session, which
// is the thing it was built to avoid.
//
// So each owning module has a setter and the value lives THERE, not in a mutable
// copy of cfg. cfg stays frozen and stays the record of what was loaded at
// start-up; asking a module for its current interval is the only way to get an
// answer that is true. A second mutable config object would be a second opinion
// about what the panel is doing, which is the drift this whole codebase is built
// to avoid.

const fs = require('node:fs');
const path = require('node:path');

const log = require('./log');
const { EXPOSED, normaliseExposed, parseConf, DEFAULTS } = require('./config');

class Settings {
  /**
   * @param {object} deps
   * @param {object} deps.cfg   the configuration as loaded at start-up
   */
  constructor({ cfg }) {
    this.cfg = cfg;
    this.file = cfg.settings_file;
    this.confPath = cfg.confPath;
    this.values = this._load();
    this.targets = null;
  }

  /**
   * Wire the modules that own a live value.
   *
   * Called once by server.js. Every module is optional so the console tools and
   * the tests can construct this without a running panel.
   */
  bind(targets) {
    this.targets = targets || null;
    return this;
  }

  _load() {
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') {
        // config.js has already reported this and started anyway. Repeating the
        // detail here would be the same sentence twice in one start-up log.
        log.warn(`settings overlay ${this.file} is unreadable — starting with none`);
      }
      return Object.create(null);
    }
    const settings = (parsed && typeof parsed === 'object' && parsed.settings
                      && typeof parsed.settings === 'object') ? parsed.settings : {};
    return Object.assign(Object.create(null), settings);
  }

  _save() {
    const tmp = `${this.file}.tmp`;
    const body = JSON.stringify({ settings: this.values }, null, 2);
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o750 });
      // Mode set on creation rather than afterwards: a file that exists for even
      // a moment at the umask default is a file somebody could have opened.
      fs.writeFileSync(tmp, `${body}\n`, { mode: 0o600 });
      // Renamed over rather than written in place, so a reader never catches the
      // middle of a write and a failed write cannot truncate what is there.
      fs.renameSync(tmp, this.file);
    } catch (err) {
      try { fs.unlinkSync(tmp); } catch { /* the temp file may not exist */ }
      throw new Error(`cannot write ${this.file}: ${err.code || err.message}`);
    }
  }

  /** What panel.conf says, re-read rather than remembered. */
  _fileValues() {
    try {
      return parseConf(fs.readFileSync(this.confPath, 'utf8'));
    } catch {
      return Object.create(null);
    }
  }

  /**
   * Every exposed key, with where its value came from.
   *
   * `source` is the whole point of this response. An operator who edits
   * panel.conf and sees nothing change needs to be told that this screen is
   * overriding it, in the place they are looking, not in a log.
   */
  list() {
    const fileValues = this._fileValues();
    const rows = [];
    for (const key of Object.keys(EXPOSED)) {
      const spec = EXPOSED[key];
      const overridden = Object.hasOwn(this.values, key);
      const inFile = Object.hasOwn(fileValues, key);
      rows.push({
        key,
        group: spec.group,
        type: spec.type,
        min: spec.min ?? null,
        max: spec.max ?? null,
        choices: spec.type === 'locale' ? this.cfg.locales.slice() : (spec.choices || null),
        value: this.effective(key, fileValues),
        source: overridden ? 'panel' : (inFile ? 'file' : 'default'),
        fileValue: inFile ? String(fileValues[key]) : null,
        defaultValue: String(DEFAULTS[key]),
      });
    }
    return rows;
  }

  /** Overlay, else panel.conf, else the built-in default. The same order config.js uses. */
  effective(key, fileValues = null) {
    const file = fileValues || this._fileValues();
    if (Object.hasOwn(this.values, key)) return String(this.values[key]);
    if (Object.hasOwn(file, key)) return String(file[key]);
    return String(DEFAULTS[key]);
  }

  /**
   * Change one key.
   *
   * Validated against EXPOSED before it is stored, so the file the loader reads
   * back should never contain a value the loader would refuse. "Should never" is
   * not load-bearing — config.js drops an unloadable overlay rather than
   * refusing to start — but a value rejected here is a 400 the operator can see
   * and correct, and a value rejected there is a line in a log after a restart.
   *
   * @returns {{key: string, value: string}}
   * @throws {Error} with `.code = 'unknown' | 'invalid' | 'write'`
   */
  set(key, value) {
    if (!Object.hasOwn(EXPOSED, key)) {
      const err = new Error(`"${key}" is not a setting this panel exposes`);
      err.code = 'unknown';
      throw err;
    }
    const normalised = normaliseExposed(key, value, { locales: this.cfg.locales });
    if (normalised === null) {
      const err = new Error(`"${key}" cannot take that value`);
      err.code = 'invalid';
      throw err;
    }

    const before = this.values[key];
    this.values[key] = normalised;
    try {
      this._save();
    } catch (saveErr) {
      // Put it back. A value applied to a running module but not on disk would
      // survive until the next restart and then silently revert, which is the
      // worst of both — the operator sees it working and finds it undone a week
      // later with nothing to explain it.
      if (before === undefined) delete this.values[key]; else this.values[key] = before;
      const err = new Error(saveErr.message);
      err.code = 'write';
      throw err;
    }

    this.apply(key, normalised);
    return { key, value: normalised };
  }

  /**
   * Stop overriding one key: whatever panel.conf says takes effect again, or the
   * built-in default if it says nothing.
   *
   * This is what makes the overlay-wins precedence honest. Without it, a value
   * set once here would shadow the file forever and the only way back would be
   * to delete a JSON file over SSH — which is the situation this screen exists
   * to remove.
   */
  clear(key) {
    if (!Object.hasOwn(EXPOSED, key)) {
      const err = new Error(`"${key}" is not a setting this panel exposes`);
      err.code = 'unknown';
      throw err;
    }
    if (!Object.hasOwn(this.values, key)) return { key, value: this.effective(key) };

    const before = this.values[key];
    delete this.values[key];
    try {
      this._save();
    } catch (saveErr) {
      this.values[key] = before;
      const err = new Error(saveErr.message);
      err.code = 'write';
      throw err;
    }

    const restored = this.effective(key);
    this.apply(key, restored);
    return { key, value: restored };
  }

  /**
   * Push every exposed key into its owning module.
   *
   * Called once at start-up so the modules and this file agree from the first
   * request, rather than agreeing only after somebody happens to change
   * something. Without it, an overlay value would be in effect for the loader
   * (config.js merged it) and not for a module that read cfg once — the two
   * would disagree and the screen would show the value that was not being used.
   */
  applyAll() {
    for (const key of Object.keys(EXPOSED)) this.apply(key, this.effective(key));
  }

  /**
   * One key, into the module that owns it.
   *
   * A key with no target here is a key that would silently do nothing, so the
   * default branch says so out loud rather than returning quietly. That is the
   * failure this switch is most likely to grow: somebody adds a key to EXPOSED,
   * the screen shows it, it saves, and it never takes effect.
   */
  apply(key, value) {
    const T = this.targets;
    if (!T) return;

    switch (key) {
      case 'log_level':
        log.setLevel(value);
        return;

      case 'poll_seconds':
        if (T.collector) T.collector.setPollSeconds(Number(value));
        return;

      case 'event_limit':
        if (T.collector) T.collector.setEventLimit(Number(value));
        return;

      case 'default_locale':
        if (T.catalogs) T.catalogs.setDefault(value);
        return;

      case 'session_ttl_minutes':
      case 'session_idle_minutes':
        if (T.auth) {
          T.auth.setSessionTimeouts({
            ttlMs: Number(this.effective('session_ttl_minutes')) * 60_000,
            idleMs: Number(this.effective('session_idle_minutes')) * 60_000,
          });
        }
        return;

      // All four rebuild the same two counters, so they are applied together
      // rather than one at a time — applying them singly would rebuild the
      // limiter four times on a screen that saves four fields.
      case 'login_window_ms':
      case 'login_max_failures':
      case 'login_lock_ms':
      case 'login_ip_max':
        if (T.auth) {
          T.auth.setLoginLimits({
            windowMs: Number(this.effective('login_window_ms')),
            maxFailures: Number(this.effective('login_max_failures')),
            lockMs: Number(this.effective('login_lock_ms')),
            ipMax: Number(this.effective('login_ip_max')),
          });
        }
        return;

      case 'enforce_enabled':
        if (T.enforcer) T.enforcer.setEnabled(value === '1');
        return;

      case 'enforce_interval_seconds':
        if (T.enforcer) T.enforcer.setIntervalMs(Number(value) * 1000);
        return;

      case 'alert_confirmations':
      case 'alert_cooldown_seconds':
      case 'alert_max_per_hour':
      case 'alert_status_failures':
        if (T.alerter) {
          T.alerter.configure({
            confirmations: Number(this.effective('alert_confirmations')),
            cooldownMs: Number(this.effective('alert_cooldown_seconds')) * 1000,
            maxPerHour: Number(this.effective('alert_max_per_hour')),
            statusFailures: Number(this.effective('alert_status_failures')),
          });
        }
        return;

      default:
        log.warnOnce(`settings-unapplied-${key}`,
          `"${key}" is in the settings allowlist but nothing applies it — changing ` +
          'it on screen saves the value and has no effect until the panel restarts. ' +
          'Add a case to settings.js:apply().');
    }
  }
}

module.exports = { Settings };
