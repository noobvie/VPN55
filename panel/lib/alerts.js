'use strict';
//
// panel/lib/alerts.js — the smallest thing that tells somebody.
//
// Before this, nothing on the host notified anyone of anything. The enforcement
// job already computed most of the conditions worth knowing about and wrote them
// into a summary object that only exists if somebody opens the panel — which is
// the one thing they are not doing at the moment it matters.
//
// ═════════════════════════════════════════════════════════════════════════════
// WHAT IT SENDS. Five conditions, and no more, because a list nobody has pruned
// is a channel nobody reads.
//
//   status.unreadable        the status read has failed N times running. The
//                            panel cannot see the host at all; every other
//                            number on this list is unknowable while it is true.
//   enforce.still_connected  accounts this job disabled are still carrying
//                            traffic. This is the honest measure of what
//                            flag-only enforcement did not achieve.
//   enforce.quota_skipped    accounts with a quota that could not be checked,
//                            because there is no usage reading for them. Quota
//                            enforcement is silently not happening for those.
//   enforce.baselines_reset  a lifetime total went BACKWARDS, so the durable
//                            state was lost or restored from an older copy.
//                            This is the one that means "your backup is being
//                            used and nobody said so".
//   auth.locked_out          a login lockout tripped. Somebody is guessing.
//
// Three of those are LEVELS: they are true or false at every observation, they
// stay true, and they resolve. Two are EDGES: they happen, and there is nothing
// to resolve.
//
// ⚠ Which of the two a condition is decides whether it can ever be sent at all,
// and it is not obvious from the name. `baselines_reset` reads like a level and
// is an edge: a baseline is re-taken by ONE run and the next run finds nothing
// to re-take, so as a level it would need `confirmations` consecutive runs to
// agree and would therefore never fire — a monitoring rule that is silent for
// exactly the event it was written for. `quota_skipped` reads like an edge and
// is a level: an account with no usage reading still has none an hour later.
// ═════════════════════════════════════════════════════════════════════════════
//
// ── What it deliberately does not send ───────────────────────────────────────
//
// NO NAMES. Not a VPN user's, not an administrator's, not an IP address. An
// alert carries a type and a count. The destination is a URL in a settings file
// that may well be a third-party chat service, and it is the least trusted place
// anything about this host ends up; the panel's own audit log holds the whole
// record and is one SSH session away. "Three accounts are still connected" is
// the entire actionable content of "three accounts are still connected"; the
// three names add nothing except somewhere for them to leak from.
//
// ── The three layers against an alert storm ──────────────────────────────────
//
// A flapping service is the normal way an alerting system destroys its own
// usefulness. One restart at 3am produces forty messages and the channel is
// muted by morning, which is worse than never having built this.
//
//  1. TRANSITION, NOT STATE. A condition that was true last run and is still
//     true is not news. Only a change of state sends anything.
//  2. CONFIRMATION. A condition must be observed `confirmations` times running
//     before it is believed to have changed — in BOTH directions, so a single
//     good poll in the middle of an outage does not send a spurious all-clear
//     either. The cost is one poll interval of latency.
//  3. COOLDOWN. Even a genuine transition is not sent if the same key sent
//     something within `cooldownMs`. Under that, a global ceiling per hour,
//     because a bug in either of the two above is a bug that sends messages.
//
// State is persisted, because without it a panel in a restart loop re-announces
// every condition on every start, which is precisely the storm this is built to
// prevent — arriving from the direction nobody tests.
//
// ── Sending never affects anything else ──────────────────────────────────────
//
// Every send is fire-and-forget with its own timeout, and a failure is logged
// once and dropped. An alerter that could delay a poll, or throw into an
// enforcement run, would be a monitoring system that causes outages.

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const log = require('./log');

const SEND_TIMEOUT_MS = 10_000;

// Level conditions resolve; edge conditions do not. See the warning in the
// header for why baselines_reset is on the second list and not the first.
const LEVEL_TYPES = Object.freeze([
  'status.unreadable',
  'enforce.still_connected',
  'enforce.quota_skipped',
]);
const EDGE_TYPES = Object.freeze([
  'enforce.baselines_reset',
  'auth.locked_out',
]);

const SEVERITY = Object.freeze({
  'status.unreadable': 'crit',
  'enforce.still_connected': 'warn',
  'enforce.quota_skipped': 'warn',
  'enforce.baselines_reset': 'crit',
  'auth.locked_out': 'warn',
});

class Alerter {
  /**
   * @param {object} deps
   * @param {object} deps.cfg
   * @param {object} deps.catalogs   for the Telegram text, rendered in default_locale
   * @param {function} [deps.send]   injected transport, for tests
   */
  constructor({ cfg, catalogs, send = null }) {
    this.cfg = cfg;
    this.catalogs = catalogs;
    this.file = cfg.alerts_file;
    this._send = send;

    // Live tuning. These four come from the settings screen, so they are held
    // here rather than read from the frozen cfg on every observation.
    this.enabled = cfg.alert_enabled;
    this.confirmations = cfg.alert_confirmations;
    this.cooldownMs = cfg.alert_cooldown_ms;
    this.maxPerHour = cfg.alert_max_per_hour;
    this.statusFailures = cfg.alert_status_failures;

    const loaded = this._load();
    this.keys = loaded.keys;      // type -> { firing, lastFiredAt, pending }
    this.sent = loaded.sent;      // epoch ms of recent sends, for the ceiling
    this.lastError = null;

    // The confirmation streak is IN MEMORY and deliberately not persisted.
    //
    // Persisting it would mean a file write on every poll — every fifteen
    // seconds, for a number whose only job is to be forgotten. Losing it across
    // a restart costs `confirmations` more observations before the next
    // transition, which is a short delay in the safe direction. What must
    // survive a restart is which conditions are ALREADY announced, and that is
    // `firing` above; without it a panel in a restart loop re-announces
    // everything on every start, which is the storm this file exists to prevent,
    // arriving from the direction nobody tests.
    this.streaks = new Map();     // type -> signed count of agreeing observations
  }

  configure({ confirmations, cooldownMs, maxPerHour, statusFailures } = {}) {
    if (Number.isFinite(confirmations)) this.confirmations = confirmations;
    if (Number.isFinite(cooldownMs)) this.cooldownMs = cooldownMs;
    if (Number.isFinite(maxPerHour)) this.maxPerHour = maxPerHour;
    if (Number.isFinite(statusFailures)) this.statusFailures = statusFailures;
  }

  /** Is there anywhere to send to at all? */
  get active() {
    return Boolean(this.enabled && this.cfg.alert_webhook_url);
  }

  // ── Persisted state ───────────────────────────────────────────────────────

  _load() {
    const empty = { keys: Object.create(null), sent: [] };
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') {
        log.warn(`cannot read ${this.file}`, err.code || err.message);
      }
      return empty;
    }
    if (!parsed || typeof parsed !== 'object') return empty;
    return {
      // Null-prototype: a type is a string from this file and `__proto__` must
      // look up nothing rather than find a function.
      keys: (parsed.keys && typeof parsed.keys === 'object')
        ? Object.assign(Object.create(null), parsed.keys) : Object.create(null),
      sent: Array.isArray(parsed.sent) ? parsed.sent.filter((n) => Number.isFinite(n)) : [],
    };
  }

  _save() {
    const tmp = `${this.file}.tmp`;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o750 });
      fs.writeFileSync(tmp, JSON.stringify({ keys: this.keys, sent: this.sent }, null, 2),
                       { mode: 0o600 });
      fs.renameSync(tmp, this.file);
    } catch (err) {
      log.warnOnce('alerts-save', `cannot write ${this.file}: ${err.code || err.message}`);
      try { fs.unlinkSync(tmp); } catch { /* the temp file may not exist */ }
    }
  }

  _slot(type) {
    if (!Object.hasOwn(this.keys, type)) {
      this.keys[type] = { firing: false, lastFiredAt: 0, pending: 0 };
    }
    const slot = this.keys[type];
    // A slot restored from a file written by another version may be missing a
    // field. Filled in rather than trusted, because the alternative is NaN
    // arithmetic on lastFiredAt, which compares false against everything and
    // silently disables the cooldown.
    if (typeof slot.firing !== 'boolean') slot.firing = false;
    if (!Number.isFinite(slot.lastFiredAt)) slot.lastFiredAt = 0;
    if (!Number.isFinite(slot.pending)) slot.pending = 0;
    return slot;
  }

  // ── Layer 1 and 2: transition, confirmed ──────────────────────────────────

  /**
   * One observation of a level condition.
   *
   * Called on EVERY poll or run, whether or not the condition holds — a level
   * that is only reported when it is true can never resolve.
   */
  observe(type, active, data = {}) {
    if (!LEVEL_TYPES.includes(type)) {
      log.warnOnce(`alert-type-${type}`, `unknown alert type "${type}" — ignored`);
      return;
    }
    const slot = this._slot(type);
    const now = Boolean(active);

    // The streak counts consecutive observations that AGREE WITH EACH OTHER,
    // not observations that disagree with the firing state. That is what makes
    // the confirmation work in both directions: an outage needs N bad readings
    // before it is announced and N good ones before it is called over, so a
    // single flap either way is absorbed rather than sent.
    const previous = this.streaks.get(type);
    const run = (previous && previous.active === now) ? previous.count + 1 : 1;
    this.streaks.set(type, { active: now, count: run });

    if (run < this.confirmations) return;   // not believed yet
    if (now === slot.firing) return;        // believed, and already the state we hold

    slot.firing = now;
    this._maybeSend(type, now ? 'firing' : 'resolved', data);
    this._save();
  }

  /**
   * One occurrence of an edge condition.
   *
   * There is nothing to confirm — it either happened or it did not — so only the
   * cooldown and the ceiling apply.
   *
   * `data.count` is an INCREMENT, not a total, and it accumulates across a
   * cooldown window. A message then says how many happened rather than arriving
   * once for the first and hiding the other forty; the caller passes the number
   * of things (baselines re-taken), or nothing for one occurrence (a lockout).
   */
  event(type, data = {}) {
    if (!EDGE_TYPES.includes(type)) {
      log.warnOnce(`alert-type-${type}`, `unknown alert type "${type}" — ignored`);
      return;
    }
    const slot = this._slot(type);
    const increment = Number.isFinite(data.count) && data.count > 0 ? Math.floor(data.count) : 1;
    slot.pending += increment;

    const now = Date.now();
    if (slot.lastFiredAt && now - slot.lastFiredAt < this.cooldownMs) { this._save(); return; }

    const count = slot.pending;
    slot.pending = 0;
    this._maybeSend(type, 'firing', { ...data, count });
    this._save();
  }

  // ── Layer 3: cooldown, then the ceiling ───────────────────────────────────

  _maybeSend(type, state, data) {
    if (!this.active) return;
    const slot = this._slot(type);
    const now = Date.now();

    // A resolve is not held back by the cooldown that its own firing message
    // started. An alert that fires and then never says it is over is how a
    // channel fills with conditions nobody can tell are stale.
    if (state === 'firing' && slot.lastFiredAt && now - slot.lastFiredAt < this.cooldownMs) {
      log.debug(`alert ${type} suppressed — within cooldown`);
      return;
    }

    this.sent = this.sent.filter((at) => now - at < 3_600_000);
    if (this.sent.length >= this.maxPerHour) {
      log.warnOnce('alert-ceiling',
        `the hourly alert ceiling (${this.maxPerHour}) was reached — further alerts ` +
        'this hour are dropped. This is a backstop; if it is being hit, the ' +
        'confirmation or cooldown setting is wrong for this host.');
      return;
    }

    if (state === 'firing') slot.lastFiredAt = now;
    this.sent.push(now);

    const payload = {
      source: 'vpn55-panel',
      host: os.hostname(),
      type,
      state,
      severity: SEVERITY[type] || 'warn',
      at: Math.floor(now / 1000),
      data,
    };
    this.deliver(payload).catch((err) => {
      this.lastError = { at: Math.floor(Date.now() / 1000), message: err.message };
      log.warn(`could not deliver alert ${type}`, err.message);
    });
  }

  // ── The transport ─────────────────────────────────────────────────────────

  /**
   * The two shapes.
   *
   * `json` posts the payload as it stands — one line in a receiving script.
   * `telegram` posts what the Bot API accepts, because a generic webhook body
   * cannot be one: sendMessage wants {chat_id, text} and nothing else will do.
   * The text is rendered through the catalogs in default_locale, so an alert is
   * translated like every other string this project emits — an English sentence
   * built here would be the only one in the panel.
   */
  async deliver(payload) {
    if (this._send) return this._send(payload);

    const url = this.cfg.alert_webhook_url;
    let body;
    if (this.cfg.alert_webhook_format === 'telegram') {
      body = {
        chat_id: this.cfg.alert_telegram_chat_id,
        text: this.renderText(payload),
        disable_web_page_preview: true,
      };
    } else {
      body = payload;
    }
    return postJson(url, body);
  }

  /**
   * Title and body from the catalogs, in the configured default locale.
   *
   * A resolve gets its OWN title as well as its own body — `alert.<type>.clear.*`
   * rather than the firing title with a different sentence under it. Reusing the
   * title would send "this host cannot be read" as the heading of the message
   * saying it can, which is the sort of thing somebody reads at 3am and acts on.
   */
  renderText(payload) {
    const locale = this.catalogs ? this.catalogs.defaultLocale : 'en';
    const t = (key, vars) => (this.catalogs ? this.catalogs.t(locale, key, vars) : key);
    // ⚠ The literal `'alert.'` must sit INSIDE the t() call, not in a variable
    // the call then uses. check-i18n-usage.mjs claims a prefix with
    //
    //     \b(?:t|tOr|T|has)\(\s*['"]([A-Za-z0-9_.-]*\.)['"]\s*\+
    //
    // — the literal has to be the first thing after the paren. This was written
    // as `const base = 'alert.' + …` with a comment claiming the claim worked;
    // it never matched, and all sixteen live keys stayed in the "never looked
    // up" list, which is exactly the noise that hides a genuinely dead key.
    const suffix = payload.type + (payload.state === 'resolved' ? '.clear' : '');
    const vars = { host: payload.host, count: String(payload.data.count ?? 0) };
    return `${t('alert.' + suffix + '.title', vars)}\n${t('alert.' + suffix + '.body', vars)}\n${payload.host}`;
  }

  /** What the panel shows about its own alerting. No URL — that is a secret. */
  status() {
    return {
      enabled: this.enabled,
      configured: Boolean(this.cfg.alert_webhook_url),
      format: this.cfg.alert_webhook_format,
      confirmations: this.confirmations,
      cooldownSeconds: Math.floor(this.cooldownMs / 1000),
      maxPerHour: this.maxPerHour,
      statusFailures: this.statusFailures,
      sentLastHour: this.sent.filter((at) => Date.now() - at < 3_600_000).length,
      firing: Object.keys(this.keys).filter((k) => this.keys[k].firing),
      lastError: this.lastError,
    };
  }
}

/**
 * POST one JSON body.
 *
 * ⚠ The protocol is checked HERE as well as in config.js. config.js gives the
 * operator a readable message at start-up; this is the control, because a value
 * can also arrive from a settings file written by a future version, and a
 * transport that would follow `file:` on request is a file reader with a URL
 * parameter.
 *
 * There is no retry. A webhook that failed once will usually fail twice, the
 * second attempt lands in the same channel a minute later, and the condition is
 * still true at the next observation anyway — which is a retry with a cooldown
 * in front of it, arrived at honestly.
 */
function postJson(url, body) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch { reject(new Error('alert_webhook_url is not a URL')); return; }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      reject(new Error(`alert_webhook_url must be http or https, not ${parsed.protocol}`));
      return;
    }

    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(parsed, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': String(payload.length),
        'User-Agent': 'vpn55-panel',
      },
      timeout: SEND_TIMEOUT_MS,
    }, (res) => {
      // The body is drained and discarded. Not reading it leaves the socket
      // open until the timeout, and keeping it would mean holding whatever a
      // webhook chose to return in a process that has no use for it.
      res.resume();
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve();
        else reject(new Error(`the webhook answered HTTP ${res.statusCode}`));
      });
    });

    req.on('timeout', () => { req.destroy(new Error('the webhook did not answer in time')); });
    req.on('error', reject);
    req.end(payload);
  });
}

module.exports = { Alerter, postJson, LEVEL_TYPES, EDGE_TYPES, SEVERITY };
